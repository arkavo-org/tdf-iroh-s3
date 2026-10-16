//! Pushed blobs the node withholds, and the deletion of refused ones.
//!
//! A push of a hash the node does not already hold is *tracked*: it is
//! *pending* from the moment the node accepts it until ingest validates it.
//! A tracked push that does not validate (too large, not a TDF, incomplete,
//! or ingest gave up before validating) is *refused*. The node serves
//! neither: get, get_many and observe of a withheld hash are refused.
//!
//! A refusal never touches content the node already accepted. A push is
//! not tracked when its hash was already complete in the store and not
//! refused, or validated earlier by this process: re-pushing it cannot
//! change it (the store verifies every chunk against the hash), so a
//! re-push that aborts or fails changes nothing. A hash that any push
//! validates is never refused afterwards, and validation lifts an earlier
//! refusal of it, so a failed push racing a good one cannot condemn it.
//! Before deleting, the collector also asks S3: a hash with an ingested
//! `blobs/<hash>` is a validated TDF and is kept.
//!
//! iroh-blobs deletes blobs only through its garbage collector (its
//! `delete` is crate-private), which removes every blob that nothing
//! protects. The node configures it with [`Quarantine::gc_config`]: a run
//! happens only while some blob is refused, and it protects every stored
//! blob except the refused ones confirmed absent from S3, plus every
//! pending push. So it deletes exactly those refused blobs, never a blob
//! in transit or one served today. Refused hashes are kept in
//! `<data_dir>/refused-blobs`, one per line, until the collector has
//! removed them, so a restart does not forget them.
//!
//! One window remains: a push that starts between the protect callback and
//! the collector's sweep, and writes nothing in that time, can lose its
//! partial data. Its ingest then finds it incomplete and refuses it; the
//! publisher sees `GET /blobs` answer 404 and pushes again. Runs happen
//! only while a refused blob waits for deletion.

use anyhow::Context;
use iroh_blobs::Hash;
use iroh_blobs::api::Store;
use iroh_blobs::store::{GcConfig, ProtectOutcome};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::store::s3::S3Client;

pub struct Quarantine {
    /// Tracked pushes not yet validated, with how many of each are in
    /// flight.
    pending: Mutex<HashMap<Hash, usize>>,
    /// Refused blobs still in the store.
    refused: Mutex<HashSet<Hash>>,
    /// Hashes some push validated in this process. Never refused.
    validated: Mutex<HashSet<Hash>>,
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
    /// the node already holds the hash: complete in the store and not
    /// refused, or validated by this process.
    pub async fn track(self: &Arc<Self>, hash: Hash) -> PendingPush {
        let refused = self.is_refused(&hash);
        let already_held = !refused
            && (self.is_validated(&hash)
                || match self.attached.get() {
                    Some((store, _)) => store
                        .observe(hash)
                        .await
                        .is_ok_and(|bitfield| bitfield.is_complete()),
                    None => false,
                });
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

    /// Whether the node must not serve `hash`.
    pub fn is_withheld(&self, hash: &Hash) -> bool {
        lock(&self.pending).contains_key(hash) || lock(&self.refused).contains(hash)
    }

    /// Whether `hash` is refused and waiting for deletion.
    pub fn is_refused(&self, hash: &Hash) -> bool {
        lock(&self.refused).contains(hash)
    }

    fn is_validated(&self, hash: &Hash) -> bool {
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
    /// the refused ones S3 confirms were never ingested, and every pending
    /// push. `None` skips the run, when there is nothing to delete or the
    /// store cannot be listed.
    async fn keep_set(self: &Arc<Self>) -> Option<HashSet<Hash>> {
        if lock(&self.refused).is_empty() {
            return None;
        }
        let (store, s3) = self.attached.get()?.clone();
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
        for hash in refused {
            match s3.blob_size(&hash.to_hex()).await {
                Ok(None) => {
                    doomed.insert(hash);
                }
                Ok(Some(_)) => self.mark_validated(hash),
                Err(e) => {
                    warn!(%hash, error = %e, "Ingest check failed; keeping the refused blob for now")
                }
            }
        }
        // A push of the hash may have started meanwhile.
        let pending = lock(&self.pending).keys().copied().collect::<Vec<_>>();
        for hash in &pending {
            doomed.remove(hash);
        }
        if doomed.is_empty() {
            return None;
        }

        debug!(
            doomed = doomed.len(),
            stored = stored.len(),
            "Garbage collection deletes refused blobs"
        );
        let mut keep: HashSet<Hash> = stored.difference(&doomed).copied().collect();
        keep.extend(pending);
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

    /// A quarantine attached to a fresh store (S3 is a mock: it is only
    /// asked when the collector runs, which these tests do not do).
    async fn attached() -> (Arc<Quarantine>, FsStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::load(dir.path()).await.unwrap();
        let store = FsStore::load(dir.path().join("store")).await.unwrap();
        q.attach(
            store.clone().into(),
            Arc::new(S3Client::new_mock("b", "us-east-1", "")),
        );
        (q, store, dir)
    }

    #[tokio::test]
    async fn a_new_push_is_withheld_until_it_validates() {
        let (q, store, _dir) = attached().await;
        let push = q.track(hash(1)).await;
        assert!(push.is_tracked());
        assert!(q.is_withheld(&hash(1)));
        push.validated();
        assert!(!q.is_withheld(&hash(1)));
        assert!(!q.is_refused(&hash(1)));
        store.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn a_new_push_dropped_before_validating_is_refused_and_remembered() {
        let (q, store, dir) = attached().await;
        drop(q.track(hash(2)).await);
        assert!(q.is_refused(&hash(2)));
        assert!(q.is_withheld(&hash(2)));

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

    /// A push of a blob the store already holds decides nothing: dropping
    /// it unvalidated (an aborted or failed re-push) neither withholds nor
    /// refuses the blob.
    #[tokio::test]
    async fn a_re_push_of_a_held_blob_cannot_condemn_it() {
        let (q, store, _dir) = attached().await;
        let held = store.add_slice(vec![9u8; 40_000]).await.unwrap().hash;

        let push = q.track(held).await;
        assert!(!push.is_tracked());
        assert!(!q.is_withheld(&held), "a re-push does not withhold");
        drop(push);
        assert!(!q.is_refused(&held));
        assert!(!q.is_withheld(&held));

        // Also when the blob validated earlier in this process.
        let other = hash(3);
        q.track(other).await.validated();
        let push = q.track(other).await;
        assert!(!push.is_tracked());
        drop(push);
        assert!(!q.is_refused(&other));
        store.shutdown().await.unwrap();
    }

    /// Two pushes of one new blob: whichever order they end in, one that
    /// validates keeps the blob.
    #[tokio::test]
    async fn a_failed_push_racing_a_good_one_cannot_condemn_it() {
        let (q, store, _dir) = attached().await;

        // The failed push ends first: refused, then lifted by the good one.
        let good = q.track(hash(4)).await;
        let bad = q.track(hash(4)).await;
        drop(bad);
        assert!(q.is_withheld(&hash(4)), "withheld while the good push runs");
        good.validated();
        assert!(!q.is_refused(&hash(4)));
        assert!(!q.is_withheld(&hash(4)));

        // The good push ends first: the failed one cannot refuse it.
        let good = q.track(hash(5)).await;
        let bad = q.track(hash(5)).await;
        good.validated();
        drop(bad);
        assert!(!q.is_refused(&hash(5)));
        assert!(!q.is_withheld(&hash(5)));
        store.shutdown().await.unwrap();
    }

    /// A refused blob pushed again stays refused unless this push validates.
    #[tokio::test]
    async fn a_refused_blob_stays_refused_unless_a_push_validates() {
        let (q, store, _dir) = attached().await;
        drop(q.track(hash(6)).await);
        let again = q.track(hash(6)).await;
        assert!(again.is_tracked(), "a refused hash is not held");
        drop(again);
        assert!(q.is_refused(&hash(6)));

        q.track(hash(6)).await.validated();
        assert!(!q.is_refused(&hash(6)));
        store.shutdown().await.unwrap();
    }
}
