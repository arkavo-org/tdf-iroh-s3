//! Which blobs the node serves, and the deletion of refused ones.
//!
//! The node serves a blob only once it is known to be a valid TDF: this
//! process validated it, or S3 holds `blobs/<hash>`, which only ingest
//! writes and only after validating. Everything else in the store is
//! withheld: get, get_many and observe of it are refused. That covers a
//! push in transit, a push that failed, and anything left in the store by
//! a crash or by builds that did not validate before storing. S3's answer
//! is asked once per hash and remembered.
//!
//! A push of a hash the node does not already hold (validated, or in S3)
//! is *tracked*: *pending* from the moment the node accepts it until
//! ingest validates it. A tracked push that does not validate (too large,
//! not a TDF, incomplete, or ingest gave up before validating) is
//! *refused*, and so is a stored blob a fetch found complete but absent
//! from S3. A refusal never touches content the node holds: a push of a
//! held hash is not tracked, a hash that any push validates is never
//! refused afterwards, and validation lifts an earlier refusal of it.
//! Before deleting, the collector also asks S3, and an ingested hash is
//! kept.
//!
//! iroh-blobs deletes blobs only through its garbage collector (its
//! `delete` is crate-private), which removes every blob that nothing
//! protects. The node configures it with [`Quarantine::gc_config`]: a run
//! happens only while some blob is refused, and it protects every stored
//! blob except the refused ones confirmed absent from S3, plus every
//! pending push and every validated hash. So it deletes exactly those
//! refused blobs, never a blob in transit or one served today. Refused
//! hashes are kept in `<data_dir>/refused-blobs`, one per line, until the
//! collector has removed them. A refusal lost to a crash before it was
//! saved leaves the blob on disk, still withheld, until a fetch or a push
//! refuses it again.
//!
//! One window remains: a push that starts between the protect callback and
//! the collector's sweep, and writes nothing in that time, can lose its
//! partial data. Its ingest then finds it incomplete and refuses it; the
//! publisher sees `GET /blobs` answer 404 and pushes again. Runs happen
//! only while a refused blob waits for deletion.

use anyhow::Context;
use futures::StreamExt;
use iroh_blobs::Hash;
use iroh_blobs::api::Store;
use iroh_blobs::store::{GcConfig, ProtectOutcome};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::store::s3::S3Client;

/// S3 lookups (`blobs/<hash>` HEADs) in flight at once, across fetches,
/// pushes and the collector.
const S3_LOOKUPS: usize = 16;

/// Whether the node may serve a hash, as far as it knows without asking S3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serve {
    Yes,
    No,
    /// Not seen yet: [`Quarantine::check_stored`] decides.
    Ask,
}

pub struct Quarantine {
    /// Tracked pushes not yet validated, with how many of each are in
    /// flight.
    pending: Mutex<HashMap<Hash, usize>>,
    /// Refused blobs still in the store.
    refused: Mutex<HashSet<Hash>>,
    /// Hashes this process validated, or found in S3: served, and never
    /// refused.
    validated: Mutex<HashSet<Hash>>,
    /// Bounds concurrent S3 lookups.
    lookups: Semaphore,
    /// Where `refused` is kept across restarts.
    file: PathBuf,
    /// Serializes writes of `file`, so the last one written is the newest.
    write_lock: tokio::sync::Mutex<()>,
    /// The store and S3, once loaded (the collector is configured before).
    attached: OnceLock<(Store, Arc<S3Client>)>,
    /// The node's runtime. The collector runs on the store's own runtime,
    /// which has no IO driver, so its S3 checks run here instead.
    runtime: tokio::runtime::Handle,
}

impl Quarantine {
    /// Load the refused hashes kept in `<data_dir>/refused-blobs`.
    pub async fn load(data_dir: &Path) -> anyhow::Result<Arc<Self>> {
        let file = data_dir.join("refused-blobs");
        let refused = match tokio::fs::read_to_string(&file).await {
            Ok(text) => text
                .lines()
                .filter_map(|line| line.trim().parse::<Hash>().ok())
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to read {}", file.display()));
            }
        };
        if !refused.is_empty() {
            info!(count = refused.len(), "Refused blobs waiting for deletion");
        }
        Ok(Arc::new(Self {
            pending: Mutex::default(),
            refused: Mutex::new(refused),
            validated: Mutex::default(),
            lookups: Semaphore::new(S3_LOOKUPS),
            file,
            write_lock: tokio::sync::Mutex::new(()),
            attached: OnceLock::new(),
            runtime: tokio::runtime::Handle::current(),
        }))
    }

    /// Give the quarantine the store it deletes from, and S3 to confirm a
    /// refused hash was never ingested before deleting it.
    pub fn attach(&self, store: Store, s3: Arc<S3Client>) {
        let _ = self.attached.set((store, s3));
    }

    /// The garbage collector configuration that deletes refused blobs,
    /// checking every `interval`.
    pub fn gc_config(self: &Arc<Self>, interval: Duration) -> GcConfig {
        let quarantine = Arc::clone(self);
        GcConfig {
            interval,
            add_protected: Some(Arc::new(move |live: &mut HashSet<Hash>| {
                let quarantine = Arc::clone(&quarantine);
                Box::pin(async move {
                    // The callback's future must be Sync; store and S3
                    // requests are not, so they run in a task of their own,
                    // on the node's runtime (S3 needs its IO driver).
                    let runtime = quarantine.runtime.clone();
                    match runtime
                        .spawn(async move { quarantine.keep_set().await })
                        .await
                    {
                        Ok(Some(keep)) => {
                            live.extend(keep);
                            ProtectOutcome::Continue
                        }
                        Ok(None) => ProtectOutcome::Abort,
                        Err(e) => {
                            warn!(error = %e, "Garbage collection protect task failed");
                            ProtectOutcome::Abort
                        }
                    }
                })
            })),
        }
    }

    /// A push the node accepted. Tracked (withheld until
    /// [`PendingPush::validated`], refused if dropped before that) unless
    /// the node already holds the hash: validated, or in S3. When S3 cannot
    /// answer, the push is tracked.
    pub async fn track(self: &Arc<Self>, hash: Hash) -> PendingPush {
        let already_held = self.is_validated(&hash) || self.ingested(hash).await == Some(true);
        if !already_held {
            *lock(&self.pending).entry(hash).or_default() += 1;
        }
        PendingPush {
            quarantine: Arc::clone(self),
            hash,
            tracked: !already_held,
            validated: false,
        }
    }

    /// Whether the node may serve `hash`, without waiting on S3.
    pub fn serve(&self, hash: &Hash) -> Serve {
        if self.is_validated(hash) {
            Serve::Yes
        } else if lock(&self.pending).contains_key(hash) || self.is_refused(hash) {
            Serve::No
        } else {
            Serve::Ask
        }
    }

    /// Decide a hash [`Self::serve`] answered [`Serve::Ask`] for: served
    /// when the store holds it complete and S3 holds it (remembered as
    /// validated). A stored blob that S3 lacks did not validate: it is
    /// refused, and deleted. A hash the store lacks is not served, nor is
    /// any hash while S3 cannot answer.
    pub async fn check_stored(self: &Arc<Self>, hash: Hash) -> bool {
        if self.serve(&hash) != Serve::Ask {
            return self.serve(&hash) == Serve::Yes;
        }
        let Some((store, _)) = self.attached.get() else {
            return false;
        };
        let stored = match store.observe(hash).await {
            Ok(bitfield) => bitfield,
            Err(_) => return false,
        };
        if !stored.is_complete() {
            if stored.size() > 0 {
                // Left by a push that never finished.
                self.refuse(hash);
            }
            return false;
        }
        match self.ingested(hash).await {
            Some(true) => true,
            Some(false) => {
                warn!(%hash, "Stored blob was never ingested; refusing it");
                self.refuse(hash);
                false
            }
            None => false,
        }
    }

    /// Whether S3 holds `blobs/<hash>`; `None` when it cannot answer. A
    /// hash it holds is remembered as validated.
    async fn ingested(self: &Arc<Self>, hash: Hash) -> Option<bool> {
        let (_, s3) = self.attached.get()?;
        let _permit = self.lookups.acquire().await.ok()?;
        match s3.blob_size(&hash.to_hex()).await {
            Ok(Some(_)) => {
                self.mark_validated(hash);
                Some(true)
            }
            Ok(None) => Some(false),
            Err(e) => {
                warn!(%hash, error = %e, "Ingest lookup failed");
                None
            }
        }
    }

    /// Whether `hash` is refused and waiting for deletion.
    pub fn is_refused(&self, hash: &Hash) -> bool {
        lock(&self.refused).contains(hash)
    }

    /// Whether this process validated `hash`, or found it in S3.
    pub fn is_validated(&self, hash: &Hash) -> bool {
        lock(&self.validated).contains(hash)
    }

    fn settle(&self, hash: Hash) {
        let mut pending = lock(&self.pending);
        if let Some(n) = pending.get_mut(&hash) {
            *n -= 1;
            if *n == 0 {
                pending.remove(&hash);
            }
        }
    }

    /// `hash` validated: it is never refused, and an earlier refusal of it
    /// is lifted.
    fn mark_validated(self: &Arc<Self>, hash: Hash) {
        lock(&self.validated).insert(hash);
        if lock(&self.refused).remove(&hash) {
            info!(%hash, "Refusal lifted: another push of this blob validated");
            self.spawn_persist();
        }
    }

    fn refuse(self: &Arc<Self>, hash: Hash) {
        // mark_validated adds to `validated` before it removes from
        // `refused`, so checking `validated` again after inserting catches a
        // validation that ran in between.
        if self.is_validated(&hash) {
            return;
        }
        info!(%hash, "Pushed blob refused; it will be deleted");
        lock(&self.refused).insert(hash);
        if self.is_validated(&hash) {
            lock(&self.refused).remove(&hash);
            return;
        }
        self.spawn_persist();
    }

    fn spawn_persist(self: &Arc<Self>) {
        let quarantine = Arc::clone(self);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move { quarantine.persist().await });
            }
            Err(_) => quarantine.persist_blocking(),
        }
    }

    /// The hashes this collector run must keep: every stored blob except
    /// the refused ones S3 confirms were never ingested, every pending push
    /// (seen before or after the listing) and every validated hash. `None`
    /// skips the run, when there is nothing to delete or the store cannot
    /// be listed.
    async fn keep_set(self: &Arc<Self>) -> Option<HashSet<Hash>> {
        if lock(&self.refused).is_empty() {
            return None;
        }
        let (store, s3) = self.attached.get()?.clone();
        // Before listing: a push accepted from here on is pending at the
        // end, or settled (validated, or refused).
        let mut keep: HashSet<Hash> = lock(&self.pending).keys().copied().collect();
        // Commit pending writes first, so the listing includes a blob
        // refused a moment ago; otherwise it would be pruned below before it
        // was ever deleted.
        if let Err(e) = store.sync_db().await {
            warn!(error = %e, "Store sync before garbage collection failed");
            return None;
        }
        let stored: HashSet<Hash> = match store.blobs().list().hashes().await {
            Ok(hashes) => hashes.into_iter().collect(),
            Err(e) => {
                warn!(error = %e, "Listing blobs for garbage collection failed");
                return None;
            }
        };

        // A refused hash no longer stored has been deleted.
        let (pruned, refused) = {
            let mut refused = lock(&self.refused);
            let before = refused.len();
            refused.retain(|h| stored.contains(h));
            (before - refused.len(), refused.clone())
        };
        if pruned > 0 {
            info!(count = pruned, "Refused blobs deleted from the store");
            self.persist().await;
        }

        // Delete only what S3 confirms was never ingested. An ingested
        // blob validated (perhaps before a restart): lift its refusal. When
        // S3 cannot answer, keep the blob this run.
        let mut doomed = HashSet::new();
        let mut lookups = futures::stream::iter(refused)
            .map(|hash| {
                let s3 = Arc::clone(&s3);
                async move { (hash, s3.blob_size(&hash.to_hex()).await) }
            })
            .buffer_unordered(S3_LOOKUPS);
        while let Some((hash, found)) = lookups.next().await {
            match found {
                Ok(None) => {
                    doomed.insert(hash);
                }
                Ok(Some(_)) => self.mark_validated(hash),
                Err(e) => {
                    warn!(%hash, error = %e, "Ingest check failed; keeping the refused blob for now")
                }
            }
        }

        // A push of a hash may have started, or validated, meanwhile.
        keep.extend(lock(&self.pending).keys().copied());
        keep.extend(lock(&self.validated).iter().copied());
        doomed.retain(|h| !keep.contains(h));
        if doomed.is_empty() {
            return None;
        }

        debug!(
            doomed = doomed.len(),
            stored = stored.len(),
            "Garbage collection deletes refused blobs"
        );
        keep.extend(stored.difference(&doomed).copied());
        Some(keep)
    }

    /// Write the refused hashes to `file`, replacing it atomically.
    async fn persist(&self) {
        let _guard = self.write_lock.lock().await;
        let text = self.render();
        let tmp = self.file.with_extension("tmp");
        let result = async {
            tokio::fs::write(&tmp, text).await?;
            tokio::fs::rename(&tmp, &self.file).await
        }
        .await;
        if let Err(e) = result {
            warn!(file = %self.file.display(), error = %e, "Failed to save refused blobs");
        }
    }

    fn persist_blocking(&self) {
        let tmp = self.file.with_extension("tmp");
        let result =
            std::fs::write(&tmp, self.render()).and_then(|()| std::fs::rename(&tmp, &self.file));
        if let Err(e) = result {
            warn!(file = %self.file.display(), error = %e, "Failed to save refused blobs");
        }
    }

    fn render(&self) -> String {
        lock(&self.refused)
            .iter()
            .map(|h| format!("{}\n", h.to_hex()))
            .collect()
    }
}

/// A push being ingested. Dropping a tracked one before [`Self::validated`]
/// refuses the blob: only a blob that validated is ever served. Dropping an
/// untracked one (a re-push of a blob the node holds) changes nothing.
pub struct PendingPush {
    quarantine: Arc<Quarantine>,
    hash: Hash,
    tracked: bool,
    validated: bool,
}

impl PendingPush {
    /// Whether this push decides the blob's fate (the node did not hold it).
    pub fn is_tracked(&self) -> bool {
        self.tracked
    }

    /// The blob validated: it may be served, and is never refused.
    pub fn validated(mut self) {
        self.validated = true;
        self.quarantine.mark_validated(self.hash);
        if self.tracked {
            self.quarantine.settle(self.hash);
        }
    }
}

impl Drop for PendingPush {
    fn drop(&mut self) {
        if self.tracked && !self.validated {
            self.quarantine.refuse(self.hash);
            self.quarantine.settle(self.hash);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_blobs::store::fs::FsStore;

    fn hash(n: u8) -> Hash {
        Hash::new([n])
    }

    /// A loopback S3 that answers `HEAD blobs/<hash>` for the hashes in
    /// `ingested`, and 404 for any other.
    #[derive(Clone, Default)]
    struct FakeS3 {
        ingested: Arc<Mutex<HashSet<Hash>>>,
    }

    impl FakeS3 {
        async fn start(&self) -> String {
            use axum::http::{StatusCode, Uri, header};
            use axum::response::IntoResponse;
            let ingested = Arc::clone(&self.ingested);
            let app = axum::Router::new().fallback(move |uri: Uri| {
                let ingested = Arc::clone(&ingested);
                async move {
                    let found = uri
                        .path()
                        .rsplit_once("/blobs/")
                        .and_then(|(_, hex)| hex.parse::<Hash>().ok())
                        .is_some_and(|h| lock(&ingested).contains(&h));
                    if found {
                        (StatusCode::OK, [(header::CONTENT_LENGTH, "1")]).into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.ok() });
            url
        }

        fn ingest(&self, hash: Hash) {
            lock(&self.ingested).insert(hash);
        }
    }

    /// A quarantine attached to a fresh store and a [`FakeS3`].
    async fn attached() -> (Arc<Quarantine>, FsStore, FakeS3, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::load(dir.path()).await.unwrap();
        let store = FsStore::load(dir.path().join("store")).await.unwrap();
        let s3 = FakeS3::default();
        let url = s3.start().await;
        q.attach(
            store.clone().into(),
            Arc::new(S3Client::for_endpoint("b", &url)),
        );
        (q, store, s3, dir)
    }

    /// Add `data` to the store untagged, as a push leaves it.
    async fn stored(store: &FsStore, data: &[u8]) -> Hash {
        let tag = store.add_slice(data).temp_tag().await.unwrap();
        tag.hash()
    }

    #[tokio::test]
    async fn a_new_push_is_withheld_until_it_validates() {
        let (q, store, _s3, _dir) = attached().await;
        let push = q.track(hash(1)).await;
        assert!(push.is_tracked());
        assert_eq!(q.serve(&hash(1)), Serve::No);
        push.validated();
        assert_eq!(q.serve(&hash(1)), Serve::Yes);
        assert!(!q.is_refused(&hash(1)));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_new_push_dropped_before_validating_is_refused_and_remembered() {
        let (q, store, _s3, dir) = attached().await;
        drop(q.track(hash(2)).await);
        assert!(q.is_refused(&hash(2)));
        assert_eq!(q.serve(&hash(2)), Serve::No);

        // Saved, so a restart still withholds and deletes it.
        for _ in 0..50 {
            if dir.path().join("refused-blobs").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let again = Quarantine::load(dir.path()).await.unwrap();
        assert!(again.is_refused(&hash(2)));
        store.shutdown().await.unwrap();
    }

    /// A push of a blob the node holds (ingested, or validated in this
    /// process) decides nothing: dropping it unvalidated (an aborted or
    /// failed re-push) neither withholds nor refuses the blob.
    #[tokio::test]
    async fn a_re_push_of_a_held_blob_cannot_condemn_it() {
        let (q, store, s3, _dir) = attached().await;
        let held = hash(3);
        s3.ingest(held);
        let push = q.track(held).await;
        assert!(!push.is_tracked());
        assert_eq!(q.serve(&held), Serve::Yes, "an ingested hash is served");
        drop(push);
        assert!(!q.is_refused(&held));
        assert_eq!(q.serve(&held), Serve::Yes);

        // Also when the blob validated earlier in this process.
        let other = hash(4);
        q.track(other).await.validated();
        let push = q.track(other).await;
        assert!(!push.is_tracked());
        drop(push);
        assert!(!q.is_refused(&other));
        store.shutdown().await.unwrap();
    }

    /// A blob complete in the store is not held unless it validated: a
    /// failed push of it refuses it.
    #[tokio::test]
    async fn a_stored_blob_that_never_validated_is_not_held() {
        let (q, store, _s3, _dir) = attached().await;
        let leftover = stored(&store, &[7u8; 40_000]).await;
        let push = q.track(leftover).await;
        assert!(push.is_tracked());
        drop(push);
        assert!(q.is_refused(&leftover));
        store.shutdown().await.unwrap();
    }

    /// Two pushes of one new blob: whichever order they end in, one that
    /// validates keeps the blob, and it is served from then on.
    #[tokio::test]
    async fn a_failed_push_racing_a_good_one_cannot_condemn_it() {
        let (q, store, _s3, _dir) = attached().await;

        // The failed push ends first: refused, then lifted by the good one.
        let good = q.track(hash(5)).await;
        let bad = q.track(hash(5)).await;
        drop(bad);
        assert_eq!(
            q.serve(&hash(5)),
            Serve::No,
            "withheld while the good push runs"
        );
        good.validated();
        assert!(!q.is_refused(&hash(5)));
        assert_eq!(q.serve(&hash(5)), Serve::Yes);

        // The good push ends first: served at once, though the other push
        // is still in flight, and that one cannot refuse it.
        let good = q.track(hash(6)).await;
        let stalled = q.track(hash(6)).await;
        good.validated();
        assert_eq!(
            q.serve(&hash(6)),
            Serve::Yes,
            "a stalled push does not withhold"
        );
        drop(stalled);
        assert!(!q.is_refused(&hash(6)));
        assert_eq!(q.serve(&hash(6)), Serve::Yes);
        store.shutdown().await.unwrap();
    }

    /// A refused blob pushed again stays refused unless this push validates.
    #[tokio::test]
    async fn a_refused_blob_stays_refused_unless_a_push_validates() {
        let (q, store, _s3, _dir) = attached().await;
        drop(q.track(hash(7)).await);
        let again = q.track(hash(7)).await;
        assert!(again.is_tracked(), "a refused hash is not held");
        drop(again);
        assert!(q.is_refused(&hash(7)));

        q.track(hash(7)).await.validated();
        assert!(!q.is_refused(&hash(7)));
        store.shutdown().await.unwrap();
    }

    /// A hash first seen in a fetch: served when stored complete and
    /// ingested; refused, for deletion, when stored but never ingested;
    /// not served, and not refused, when the store lacks it.
    #[tokio::test]
    async fn a_fetch_of_an_unseen_hash_asks_the_store_and_s3() {
        let (q, store, s3, _dir) = attached().await;
        let ingested = stored(&store, &[1u8; 40_000]).await;
        s3.ingest(ingested);
        let never = stored(&store, &[2u8; 40_000]).await;
        let absent = hash(8);
        store.sync_db().await.unwrap();

        for h in [ingested, never, absent] {
            assert_eq!(q.serve(&h), Serve::Ask);
        }
        assert!(q.check_stored(ingested).await);
        assert_eq!(q.serve(&ingested), Serve::Yes, "remembered");

        assert!(!q.check_stored(never).await);
        assert!(q.is_refused(&never));
        assert_eq!(q.serve(&never), Serve::No, "remembered");

        assert!(!q.check_stored(absent).await);
        assert!(!q.is_refused(&absent));
        store.shutdown().await.unwrap();
    }

    /// The collector keeps every pending push and every validated hash,
    /// including those the store listing missed (a push that landed while
    /// the collector waited on S3), and deletes only refused blobs S3 lacks.
    #[tokio::test]
    async fn the_collector_keeps_pending_and_validated_hashes() {
        let (q, store, s3, _dir) = attached().await;
        let refused = stored(&store, &[3u8; 40_000]).await;
        let kept = stored(&store, &[4u8; 40_000]).await;
        let lifted = stored(&store, &[5u8; 40_000]).await;
        drop(q.track(refused).await);
        drop(q.track(lifted).await);
        s3.ingest(lifted);
        let pending = q.track(hash(9)).await;
        q.track(hash(10)).await.validated();

        let keep = q.keep_set().await.expect("a refused blob to delete");
        assert!(!keep.contains(&refused));
        for h in [kept, lifted, hash(9), hash(10)] {
            assert!(keep.contains(&h), "{h} kept");
        }
        assert!(!q.is_refused(&lifted), "an ingested hash is lifted");
        drop(pending);
        store.shutdown().await.unwrap();
    }
}
