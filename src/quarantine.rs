//! Which blobs the node serves, and the deletion of refused ones.
//!
//! The node serves a blob only once it is *validated*: known to be a valid
//! TDF and complete in the local store. A hash becomes validated when this
//! process validates it, or when the store holds it complete and S3 holds
//! `blobs/<hash>` (which only ingest writes, after validating). Everything
//! else in the store is withheld: get, get_many and observe of it are
//! refused. That covers a push in transit, a push that failed, and anything
//! a crash or earlier builds left in the store. The validated set is a
//! bounded cache ([`VALIDATED_CAPACITY`]); S3 and the store answer for a
//! hash it has dropped.
//!
//! A stored blob that is not known valid is *recovered* the first time a
//! fetch finds it: ingested again (validated, then uploaded), as if just
//! pushed. A good TDF whose upload failed is uploaded then, and served; one
//! that does not validate, or an incomplete leftover, is refused.
//!
//! A push of a hash the node does not hold (validated, or complete in the
//! store and in S3) is *tracked*, as is a recovery: *pending* from the
//! moment the node accepts it until ingest validates it. Of the pending
//! pushes of a hash, the last to end without validating refuses it, unless
//! another validated it; a push that ends while another is pending leaves
//! the decision to that one. So a failed push racing a good one, or a fetch
//! racing a push, never condemns a blob, and a hash any push validates is
//! never refused afterwards (validation lifts an earlier refusal). A push
//! that fails for the node's own reasons (it could not read the store,
//! export or read the blob, or the node is shutting down) is released
//! without refusing it; a fetch recovers a released blob again only after
//! [`RECOVERY_COOLDOWN`].
//!
//! iroh-blobs deletes blobs only through its garbage collector (its
//! `delete` is crate-private), which removes every blob that nothing
//! protects. The node configures it with [`Quarantine::gc_config`]: a run
//! happens only while some blob is refused, and it protects every stored
//! blob except the refused ones it may delete (incomplete, or complete but
//! absent from S3), plus every pending push and every hash validated or
//! released during the run. So it deletes exactly those refused blobs, never a blob in
//! transit or one served today. Refused hashes are kept in
//! `<data_dir>/refused-blobs`, one per line, until the collector has
//! removed them. A refusal lost to a crash before it was saved leaves the
//! blob on disk, still withheld, until a fetch recovers it.
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
pub const S3_LOOKUPS: usize = 16;

/// Most hashes remembered as validated. A forgotten hash costs one S3
/// lookup the next time it is fetched or pushed.
pub const VALIDATED_CAPACITY: usize = 200_000;

/// How long after a released ingest a fetch may recover the blob again.
pub const RECOVERY_COOLDOWN: Duration = Duration::from_secs(60);

/// Most released hashes remembered for [`RECOVERY_COOLDOWN`].
const RELEASED_CAPACITY: usize = 10_000;

/// Whether the node may serve a hash, as far as memory knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serve {
    Yes,
    No,
    /// Not known: [`Quarantine::check_stored`] decides.
    Ask,
}

/// What [`Quarantine::check_stored`] found for a hash.
pub enum Stored {
    /// Validated: served.
    Serve,
    /// The store holds none of it: there is nothing to serve.
    Absent,
    /// A push of it is pending, or it is refused.
    Withheld,
    /// S3 could not answer: not served this time.
    Unknown,
    /// Stored, but not known valid. The caller ingests it with this tracked
    /// push: served once it validates, refused if it does not.
    Recover(PendingPush),
}

pub struct Quarantine {
    /// Tracked pushes not yet validated, with how many of each are in
    /// flight.
    pending: Mutex<HashMap<Hash, usize>>,
    /// Refused blobs still in the store.
    refused: Mutex<HashSet<Hash>>,
    /// Hashes known valid and complete in the store: served, and never
    /// refused.
    validated: Mutex<Validated>,
    /// Bounds concurrent S3 lookups.
    lookups: Semaphore,
    /// Hashes whose ingest was released (the node's own failure), and when:
    /// a fetch does not recover one again until [`RECOVERY_COOLDOWN`] has
    /// passed.
    released: Mutex<HashMap<Hash, std::time::Instant>>,
    /// Set once the node shuts down: a push ended by the shutdown is
    /// released, not refused.
    closing: std::sync::atomic::AtomicBool,
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

/// The validated hashes, in two generations: a hash is added to `current`,
/// and when `current` reaches half of [`VALIDATED_CAPACITY`] it becomes
/// `previous` (dropping the old `previous`). A hit in `previous` moves the
/// hash back to `current`, so hashes in use stay.
#[derive(Default)]
struct Validated {
    current: HashSet<Hash>,
    previous: HashSet<Hash>,
    /// While the collector runs, the hashes validated or released since it
    /// started: it may not have listed them.
    during_collection: Option<HashSet<Hash>>,
}

impl Validated {
    fn contains(&mut self, hash: &Hash) -> bool {
        if self.current.contains(hash) {
            return true;
        }
        if self.previous.remove(hash) {
            self.add(*hash);
            return true;
        }
        false
    }

    fn insert(&mut self, hash: Hash) {
        self.protect(hash);
        self.add(hash);
    }

    /// Keep `hash` from the running collection, if one runs.
    fn protect(&mut self, hash: Hash) {
        if let Some(during) = &mut self.during_collection {
            during.insert(hash);
        }
    }

    fn add(&mut self, hash: Hash) {
        if self.current.insert(hash) && self.current.len() >= VALIDATED_CAPACITY / 2 {
            self.previous = std::mem::take(&mut self.current);
        }
    }
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
            released: Mutex::default(),
            closing: std::sync::atomic::AtomicBool::new(false),
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
    /// [`PendingPush::validated`]) unless the node already holds the hash:
    /// validated, or complete in the store and in S3. When S3 cannot
    /// answer, the push is tracked.
    pub async fn track(self: &Arc<Self>, hash: Hash) -> PendingPush {
        if self.is_validated(&hash) {
            return PendingPush::new(self, hash, false);
        }
        // Pending while the store and S3 are asked, so no fetch is approved
        // for the hash meanwhile.
        *lock(&self.pending).entry(hash).or_default() += 1;
        let held = self.complete_and_ingested(hash).await == Some(true);
        if held {
            self.settle(hash);
        }
        PendingPush::new(self, hash, !held)
    }

    /// Whether the node may serve `hash`, from memory alone.
    pub fn serve(&self, hash: &Hash) -> Serve {
        if self.is_validated(hash) {
            Serve::Yes
        } else if lock(&self.pending).contains_key(hash) || self.is_refused(hash) {
            Serve::No
        } else {
            Serve::Ask
        }
    }

    /// Look `hash` up in the store, and in S3 when the store holds it
    /// complete. A complete blob S3 holds becomes validated. A stored blob
    /// S3 lacks, or an incomplete one, is returned for recovery, unless a
    /// push of it is pending (that push decides) or its last ingest was
    /// released within [`RECOVERY_COOLDOWN`].
    pub async fn check_stored(self: &Arc<Self>, hash: Hash) -> Stored {
        match self.serve(&hash) {
            Serve::Yes => return Stored::Serve,
            Serve::No => return Stored::Withheld,
            Serve::Ask => {}
        }
        let Some((store, _)) = self.attached.get() else {
            return Stored::Unknown;
        };
        let bitfield = match store.observe(hash).await {
            Ok(bitfield) => bitfield,
            Err(e) => {
                warn!(%hash, error = %e, "Store lookup failed");
                return Stored::Unknown;
            }
        };
        if bitfield.ranges.is_empty() {
            return Stored::Absent;
        }
        if bitfield.is_complete() {
            match self.lookup(hash).await {
                Ok(Some(_)) => {
                    self.mark_validated(hash);
                    return Stored::Serve;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(%hash, error = %e, "Ingest lookup failed");
                    return Stored::Unknown;
                }
            }
        }
        if self.recently_released(&hash) {
            return Stored::Withheld;
        }
        match self.track_if_idle(hash) {
            Some(recovery) => Stored::Recover(recovery),
            None => Stored::Withheld,
        }
    }

    fn recently_released(&self, hash: &Hash) -> bool {
        let mut released = lock(&self.released);
        match released.get(hash) {
            Some(at) if at.elapsed() < RECOVERY_COOLDOWN => true,
            Some(_) => {
                released.remove(hash);
                false
            }
            None => false,
        }
    }

    fn note_released(&self, hash: Hash) {
        let mut released = lock(&self.released);
        if released.len() >= RELEASED_CAPACITY {
            released.retain(|_, at| at.elapsed() < RECOVERY_COOLDOWN);
            if released.len() >= RELEASED_CAPACITY {
                released.clear();
            }
        }
        released.insert(hash, std::time::Instant::now());
    }

    /// The node is shutting down: a push ended from here on is released,
    /// not refused, since the shutdown ended it, not the blob.
    pub fn close(&self) {
        self.closing
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// `Some(true)` when the store holds `hash` complete and S3 holds it
    /// (it becomes validated); `None` when either cannot answer.
    async fn complete_and_ingested(self: &Arc<Self>, hash: Hash) -> Option<bool> {
        let (store, _) = self.attached.get()?;
        if !store.observe(hash).await.ok()?.is_complete() {
            return Some(false);
        }
        match self.lookup(hash).await {
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

    /// S3's `blobs/<hash>` size, or `None` when absent; at most
    /// [`S3_LOOKUPS`] at once.
    async fn lookup(&self, hash: Hash) -> anyhow::Result<Option<u64>> {
        let (_, s3) = self.attached.get().context("S3 not attached")?;
        let _permit = self.lookups.acquire().await?;
        s3.blob_size(&hash.to_hex()).await
    }

    /// A tracked push of `hash` for recovery, unless one is pending.
    fn track_if_idle(self: &Arc<Self>, hash: Hash) -> Option<PendingPush> {
        let mut pending = lock(&self.pending);
        if pending.contains_key(&hash) {
            return None;
        }
        pending.insert(hash, 1);
        Some(PendingPush::new(self, hash, true))
    }

    /// Whether `hash` is refused and waiting for deletion.
    pub fn is_refused(&self, hash: &Hash) -> bool {
        lock(&self.refused).contains(hash)
    }

    /// Whether `hash` is known valid and complete in the store (and still
    /// remembered).
    pub fn is_validated(&self, hash: &Hash) -> bool {
        lock(&self.validated).contains(hash)
    }

    /// A tracked push of `hash` ended, validated or released.
    fn settle(&self, hash: Hash) {
        let mut pending = lock(&self.pending);
        if let Some(n) = pending.get_mut(&hash) {
            *n -= 1;
            if *n == 0 {
                pending.remove(&hash);
            }
        }
    }

    /// A tracked push of `hash` ended without validating. The last pending
    /// push refuses the hash, unless it validated meanwhile.
    fn end_unvalidated(self: &Arc<Self>, hash: Hash) {
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            self.settle(hash);
            return;
        }
        let refused = {
            let mut pending = lock(&self.pending);
            let last = match pending.get_mut(&hash) {
                Some(n) if *n > 1 => {
                    *n -= 1;
                    false
                }
                Some(_) => {
                    pending.remove(&hash);
                    true
                }
                None => false,
            };
            // mark_validated adds to `validated` before it removes from
            // `refused`, so checking `validated` again after inserting
            // catches a validation that ran in between.
            last && !self.is_validated(&hash) && {
                lock(&self.refused).insert(hash);
                if self.is_validated(&hash) {
                    lock(&self.refused).remove(&hash);
                    false
                } else {
                    true
                }
            }
        };
        if refused {
            info!(%hash, "Pushed blob refused; it will be deleted");
            self.spawn_persist();
        }
    }

    /// `hash` is known valid and complete in the store: it is served, never
    /// refused, and an earlier refusal of it is lifted.
    fn mark_validated(self: &Arc<Self>, hash: Hash) {
        lock(&self.validated).insert(hash);
        if lock(&self.refused).remove(&hash) {
            info!(%hash, "Refusal lifted: the blob validated");
            self.spawn_persist();
        }
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
    /// the refused ones it may delete, every pending push (seen before or
    /// after the listing) and every hash validated or released during the
    /// run. `None`
    /// skips the run, when there is nothing to delete or the store cannot
    /// be listed.
    async fn keep_set(self: &Arc<Self>) -> Option<HashSet<Hash>> {
        if lock(&self.refused).is_empty() {
            return None;
        }
        lock(&self.validated).during_collection = Some(HashSet::new());
        let plan = self.plan_collection().await;
        // Pending pushes before validations: a push that validates after
        // this read is recorded as validated during the run.
        let pending: Vec<Hash> = lock(&self.pending).keys().copied().collect();
        let during = lock(&self.validated)
            .during_collection
            .take()
            .unwrap_or_default();
        let (stored, mut doomed, mut keep) = plan?;
        keep.extend(pending);
        keep.extend(during);
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

    /// The stored hashes, the refused ones to delete, and the pending
    /// pushes seen before listing the store.
    async fn plan_collection(
        self: &Arc<Self>,
    ) -> Option<(HashSet<Hash>, HashSet<Hash>, HashSet<Hash>)> {
        let (store, _) = self.attached.get()?.clone();
        // Before listing: a push accepted from here on is pending at the
        // end, or settled.
        let keep: HashSet<Hash> = lock(&self.pending).keys().copied().collect();
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

        let mut doomed = HashSet::new();
        let mut fates = futures::stream::iter(refused)
            .map(|hash| {
                let quarantine = Arc::clone(self);
                let store = store.clone();
                async move { (hash, quarantine.may_delete(&store, hash).await) }
            })
            .buffer_unordered(S3_LOOKUPS);
        while let Some((hash, delete)) = fates.next().await {
            if delete {
                doomed.insert(hash);
            }
        }
        Some((stored, doomed, keep))
    }

    /// Whether the collector may delete refused `hash`: incomplete in the
    /// store, or complete but absent from S3. A complete blob S3 holds
    /// validated (perhaps before a restart): its refusal is lifted. When
    /// the store or S3 cannot answer, the blob is kept this run.
    async fn may_delete(self: &Arc<Self>, store: &Store, hash: Hash) -> bool {
        match store.observe(hash).await {
            Ok(bitfield) if bitfield.is_complete() => {}
            Ok(_) => return true,
            Err(e) => {
                warn!(%hash, error = %e, "Store lookup failed; keeping the refused blob for now");
                return false;
            }
        }
        match self.lookup(hash).await {
            Ok(None) => true,
            Ok(Some(_)) => {
                self.mark_validated(hash);
                false
            }
            Err(e) => {
                warn!(%hash, error = %e, "Ingest check failed; keeping the refused blob for now");
                false
            }
        }
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

/// A push, or a recovery, being ingested. Dropping a tracked one before
/// [`Self::validated`] or [`Self::release`] ends it unvalidated: the last
/// pending push of a hash to end that way refuses it. Dropping an untracked
/// one (a re-push of a blob the node holds) changes nothing.
pub struct PendingPush {
    quarantine: Arc<Quarantine>,
    hash: Hash,
    tracked: bool,
    settled: bool,
}

impl PendingPush {
    fn new(quarantine: &Arc<Quarantine>, hash: Hash, tracked: bool) -> Self {
        Self {
            quarantine: Arc::clone(quarantine),
            hash,
            tracked,
            settled: false,
        }
    }

    /// Whether this push decides the blob's fate (the node did not hold it).
    pub fn is_tracked(&self) -> bool {
        self.tracked
    }

    /// The blob validated: it is served, and never refused.
    pub fn validated(mut self) {
        self.settled = true;
        self.quarantine.mark_validated(self.hash);
        if self.tracked {
            self.quarantine.settle(self.hash);
        }
    }

    /// The node could not finish checking the blob (for its own reasons,
    /// not the blob's): end the push without refusing it. The blob stays
    /// withheld until a later push, or a fetch after
    /// [`RECOVERY_COOLDOWN`], checks it again.
    pub fn release(mut self) {
        self.settled = true;
        if self.tracked {
            // Kept from a running collection, which may not have listed it.
            lock(&self.quarantine.validated).protect(self.hash);
            self.quarantine.note_released(self.hash);
            self.quarantine.settle(self.hash);
        }
    }
}

impl Drop for PendingPush {
    fn drop(&mut self) {
        if self.tracked && !self.settled {
            self.quarantine.end_unvalidated(self.hash);
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
    /// `ingested`, and 404 for any other, after `delay`.
    #[derive(Clone, Default)]
    struct FakeS3 {
        ingested: Arc<Mutex<HashSet<Hash>>>,
        delay: Arc<Mutex<Duration>>,
    }

    impl FakeS3 {
        async fn start(&self) -> String {
            use axum::http::{StatusCode, Uri, header};
            use axum::response::IntoResponse;
            let s3 = self.clone();
            let app = axum::Router::new().fallback(move |uri: Uri| {
                let s3 = s3.clone();
                async move {
                    let delay = *lock(&s3.delay);
                    tokio::time::sleep(delay).await;
                    let found = uri
                        .path()
                        .rsplit_once("/blobs/")
                        .and_then(|(_, hex)| hex.parse::<Hash>().ok())
                        .is_some_and(|h| lock(&s3.ingested).contains(&h));
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

    /// A push of a blob the node holds (complete in the store and ingested,
    /// or validated in this process) decides nothing: dropping it
    /// unvalidated (an aborted or failed re-push) neither withholds nor
    /// refuses the blob.
    #[tokio::test]
    async fn a_re_push_of_a_held_blob_cannot_condemn_it() {
        let (q, store, s3, _dir) = attached().await;
        let held = stored(&store, &[3u8; 40_000]).await;
        s3.ingest(held);
        let push = q.track(held).await;
        assert!(!push.is_tracked());
        assert_eq!(
            q.serve(&held),
            Serve::Yes,
            "a stored, ingested hash is served"
        );
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

    /// A hash S3 holds but the store lacks is not held: its push is tracked
    /// like a new one, and a failed push refuses the partial data.
    #[tokio::test]
    async fn an_ingested_hash_the_store_lacks_is_not_held() {
        let (q, store, s3, _dir) = attached().await;
        s3.ingest(hash(5));
        let push = q.track(hash(5)).await;
        assert!(push.is_tracked());
        assert_eq!(q.serve(&hash(5)), Serve::No);
        drop(push);
        assert!(q.is_refused(&hash(5)));
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

    /// Of the pending pushes of a hash, the last to end decides: one that
    /// fails while another is pending refuses nothing, and one that
    /// validates keeps the blob whatever the others do.
    #[tokio::test]
    async fn the_last_pending_push_decides() {
        let (q, store, _s3, _dir) = attached().await;

        // The failed push ends first: nothing refused while the other runs.
        let good = q.track(hash(6)).await;
        let bad = q.track(hash(6)).await;
        drop(bad);
        assert!(!q.is_refused(&hash(6)), "the other push decides");
        assert_eq!(q.serve(&hash(6)), Serve::No, "withheld while it runs");
        good.validated();
        assert!(!q.is_refused(&hash(6)));
        assert_eq!(q.serve(&hash(6)), Serve::Yes);

        // The good push ends first: served at once, though the other push
        // is still in flight, and that one cannot refuse it.
        let good = q.track(hash(7)).await;
        let stalled = q.track(hash(7)).await;
        good.validated();
        assert_eq!(
            q.serve(&hash(7)),
            Serve::Yes,
            "a stalled push does not withhold"
        );
        drop(stalled);
        assert!(!q.is_refused(&hash(7)));

        // Both fail: the second refuses.
        let first = q.track(hash(8)).await;
        let second = q.track(hash(8)).await;
        drop(first);
        assert!(!q.is_refused(&hash(8)));
        drop(second);
        assert!(q.is_refused(&hash(8)));
        store.shutdown().await.unwrap();
    }

    /// A push the node could not finish checking is released: not refused,
    /// still not served.
    #[tokio::test]
    async fn a_released_push_refuses_nothing() {
        let (q, store, _s3, _dir) = attached().await;
        q.track(hash(9)).await.release();
        assert!(!q.is_refused(&hash(9)));
        assert_eq!(q.serve(&hash(9)), Serve::Ask);
        store.shutdown().await.unwrap();
    }

    /// A refused blob pushed again stays refused unless this push validates.
    #[tokio::test]
    async fn a_refused_blob_stays_refused_unless_a_push_validates() {
        let (q, store, _s3, _dir) = attached().await;
        drop(q.track(hash(10)).await);
        let again = q.track(hash(10)).await;
        assert!(again.is_tracked(), "a refused hash is not held");
        drop(again);
        assert!(q.is_refused(&hash(10)));

        q.track(hash(10)).await.validated();
        assert!(!q.is_refused(&hash(10)));
        store.shutdown().await.unwrap();
    }

    /// A hash first seen in a fetch: served when stored complete and
    /// ingested; recovered (a tracked push to ingest again) when stored but
    /// not ingested, or incomplete; absent when the store lacks it.
    #[tokio::test]
    async fn a_fetch_of_an_unseen_hash_asks_the_store_and_s3() {
        let (q, store, s3, _dir) = attached().await;
        let ingested = stored(&store, &[1u8; 40_000]).await;
        s3.ingest(ingested);
        let never = stored(&store, &[2u8; 40_000]).await;
        let absent = hash(11);
        store.sync_db().await.unwrap();

        for h in [ingested, never, absent] {
            assert_eq!(q.serve(&h), Serve::Ask);
        }
        assert!(matches!(q.check_stored(ingested).await, Stored::Serve));
        assert_eq!(q.serve(&ingested), Serve::Yes, "remembered");

        let Stored::Recover(recovery) = q.check_stored(never).await else {
            panic!("a stored blob S3 lacks is recovered");
        };
        assert!(recovery.is_tracked());
        assert!(
            matches!(q.check_stored(never).await, Stored::Withheld),
            "one recovery at a time"
        );
        drop(recovery);
        assert!(q.is_refused(&never), "a recovery that fails refuses");

        assert!(matches!(q.check_stored(absent).await, Stored::Absent));
        assert!(!q.is_refused(&absent));
        store.shutdown().await.unwrap();
    }

    /// The collector deletes a refused blob that is incomplete, or complete
    /// but absent from S3; lifts one S3 holds; and keeps every pending push
    /// and every hash validated or released while it waits on S3, though the
    /// store listing missed them.
    #[tokio::test]
    async fn the_collector_keeps_pending_and_freshly_validated_hashes() {
        let (q, store, s3, _dir) = attached().await;
        let refused = stored(&store, &[3u8; 40_000]).await;
        let kept = stored(&store, &[4u8; 40_000]).await;
        let lifted = stored(&store, &[5u8; 40_000]).await;
        drop(q.track(refused).await);
        drop(q.track(lifted).await);
        s3.ingest(lifted);
        let pending = q.track(hash(12)).await;
        store.sync_db().await.unwrap();

        // S3 answers slowly; one push validates meanwhile, and another is
        // released after a failure of the node's own.
        *lock(&s3.delay) = Duration::from_millis(300);
        let (keep, ()) = tokio::join!(q.keep_set(), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            q.track(hash(13)).await.validated();
            q.track(hash(14)).await.release();
        });
        let keep = keep.expect("a refused blob to delete");
        assert!(!keep.contains(&refused));
        for h in [kept, lifted, hash(12), hash(13), hash(14)] {
            assert!(keep.contains(&h), "{h} kept");
        }
        assert!(!q.is_refused(&lifted), "an ingested hash is lifted");
        assert!(lock(&q.validated).during_collection.is_none());
        drop(pending);
        store.shutdown().await.unwrap();
    }

    /// While a push waits on S3 to learn whether the node holds its hash,
    /// the hash is pending: no fetch is approved for it meanwhile.
    #[tokio::test]
    async fn a_push_is_pending_while_it_asks_s3() {
        let (q, store, s3, _dir) = attached().await;
        let held = stored(&store, &[6u8; 40_000]).await;
        s3.ingest(held);
        *lock(&s3.delay) = Duration::from_millis(300);
        let (push, ()) = tokio::join!(q.track(held), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(q.serve(&held), Serve::No, "pending while S3 answers");
        });
        assert!(
            !push.is_tracked(),
            "held: S3 has it, the store has it whole"
        );
        assert_eq!(q.serve(&held), Serve::Yes);
        drop(push);
        assert!(!q.is_refused(&held));
        store.shutdown().await.unwrap();
    }

    /// Once the node shuts down, a push it ends is released, not refused.
    #[tokio::test]
    async fn a_push_ended_by_shutdown_is_not_refused() {
        let (q, store, _s3, _dir) = attached().await;
        let push = q.track(hash(15)).await;
        q.close();
        drop(push);
        assert!(!q.is_refused(&hash(15)));
        assert_eq!(q.serve(&hash(15)), Serve::Ask);
        store.shutdown().await.unwrap();
    }

    /// A blob whose ingest was released is not recovered again by fetches
    /// until the cooldown passes.
    #[tokio::test]
    async fn a_released_blob_is_not_recovered_at_once() {
        let (q, store, _s3, _dir) = attached().await;
        let blob = stored(&store, &[8u8; 40_000]).await;
        store.sync_db().await.unwrap();
        let Stored::Recover(recovery) = q.check_stored(blob).await else {
            panic!("recovered");
        };
        recovery.release();
        assert!(matches!(q.check_stored(blob).await, Stored::Withheld));
        assert!(!q.is_refused(&blob));
        store.shutdown().await.unwrap();
    }

    /// The validated set keeps at most VALIDATED_CAPACITY hashes, dropping
    /// the oldest generation; a hash in use moves to the newest.
    #[test]
    fn the_validated_set_is_bounded() {
        let mut v = Validated::default();
        let h = |i: usize| Hash::new(i.to_le_bytes());
        v.insert(h(0));
        v.insert(h(1));
        for i in 2..VALIDATED_CAPACITY / 2 + 1 {
            v.insert(h(i));
        }
        // h(0) and h(1) are in the older generation now; using h(1) keeps it.
        assert!(v.contains(&h(1)));
        for i in VALIDATED_CAPACITY..VALIDATED_CAPACITY * 3 / 2 {
            v.insert(h(i));
        }
        assert!(!v.contains(&h(0)), "the oldest are dropped");
        assert!(v.contains(&h(1)), "a hash in use stays");
        assert!(v.current.len() + v.previous.len() <= VALIDATED_CAPACITY);
    }
}
