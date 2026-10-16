//! Pushed blobs the node withholds, and the deletion of refused ones.
//!
//! A push is *pending* from the moment the node accepts it until ingest
//! validates it. A push that does not validate (too large, not a TDF,
//! incomplete, or ingest gave up before validating) is *refused*. The node
//! serves neither: get, get_many and observe of a withheld hash are refused.
//!
//! iroh-blobs deletes blobs only through its garbage collector (its
//! `delete` is crate-private), which removes every blob that nothing
//! protects. The node configures it with [`Quarantine::gc_config`]: a run
//! happens only while some blob is refused, and it protects every stored
//! blob except the refused ones, plus every pending push. So it deletes
//! exactly the refused blobs, and never a blob in transit or one served
//! today. Refused hashes are kept in `<data_dir>/refused-blobs`, one per
//! line, until the collector has removed them, so a restart does not
//! forget them.
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

pub struct Quarantine {
    /// Accepted pushes not yet validated, with how many of each are in
    /// flight.
    pending: Mutex<HashMap<Hash, usize>>,
    /// Refused blobs still in the store.
    refused: Mutex<HashSet<Hash>>,
    /// Where `refused` is kept across restarts.
    file: PathBuf,
    /// Serializes writes of `file`, so the last one written is the newest.
    write_lock: tokio::sync::Mutex<()>,
    /// The store, once loaded (the collector is configured before).
    store: OnceLock<Store>,
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
            file,
            write_lock: tokio::sync::Mutex::new(()),
            store: OnceLock::new(),
        }))
    }

    /// Give the collector the store it deletes from.
    pub fn attach(&self, store: Store) {
        let _ = self.store.set(store);
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
                    // The callback's future must be Sync; store requests
                    // are not, so they run in a task of their own.
                    match tokio::spawn(async move { quarantine.keep_set().await }).await {
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

    /// A push the node accepted. Withheld until [`PendingPush::validated`];
    /// refused if dropped before that.
    pub fn pushed(self: &Arc<Self>, hash: Hash) -> PendingPush {
        *lock(&self.pending).entry(hash).or_default() += 1;
        // Pushed again: this push decides now. Saved, so a restart does not
        // delete it if it validates.
        if lock(&self.refused).remove(&hash) {
            self.spawn_persist();
        }
        PendingPush {
            quarantine: Arc::clone(self),
            hash,
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

    fn settle(&self, hash: Hash) {
        let mut pending = lock(&self.pending);
        if let Some(n) = pending.get_mut(&hash) {
            *n -= 1;
            if *n == 0 {
                pending.remove(&hash);
            }
        }
    }

    fn refuse(self: &Arc<Self>, hash: Hash) {
        lock(&self.refused).insert(hash);
        self.settle(hash);
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
    /// the refused ones, and every pending push. `None` skips the run, when
    /// nothing is refused or the store cannot be listed.
    async fn keep_set(&self) -> Option<HashSet<Hash>> {
        if lock(&self.refused).is_empty() {
            return None;
        }
        let store = self.store.get()?.clone();
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
        if refused.is_empty() {
            return None;
        }

        debug!(
            refused = refused.len(),
            stored = stored.len(),
            "Garbage collection deletes refused blobs"
        );
        let mut keep: HashSet<Hash> = stored.difference(&refused).copied().collect();
        keep.extend(lock(&self.pending).keys().copied());
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

/// A push being ingested. Dropping it before [`Self::validated`] refuses
/// the blob: only a blob that validated is ever served.
pub struct PendingPush {
    quarantine: Arc<Quarantine>,
    hash: Hash,
    validated: bool,
}

impl PendingPush {
    /// The blob validated: it may be served.
    pub fn validated(mut self) {
        self.validated = true;
        self.quarantine.settle(self.hash);
    }
}

impl Drop for PendingPush {
    fn drop(&mut self) {
        if !self.validated {
            info!(hash = %self.hash, "Pushed blob refused; it will be deleted");
            self.quarantine.refuse(self.hash);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> Hash {
        Hash::new([n])
    }

    #[tokio::test]
    async fn a_push_is_withheld_until_it_validates() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::load(dir.path()).await.unwrap();
        let push = q.pushed(hash(1));
        assert!(q.is_withheld(&hash(1)));
        push.validated();
        assert!(!q.is_withheld(&hash(1)));
        assert!(!q.is_refused(&hash(1)));
    }

    #[tokio::test]
    async fn a_push_dropped_before_validating_is_refused_and_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::load(dir.path()).await.unwrap();
        drop(q.pushed(hash(2)));
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

        // Pushed again: pending, no longer refused, until it decides.
        let push = again.pushed(hash(2));
        assert!(!again.is_refused(&hash(2)));
        assert!(again.is_withheld(&hash(2)));
        push.validated();
        assert!(!again.is_withheld(&hash(2)));
    }

    #[tokio::test]
    async fn concurrent_pushes_of_one_hash_settle_separately() {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::load(dir.path()).await.unwrap();
        let a = q.pushed(hash(3));
        let b = q.pushed(hash(3));
        a.validated();
        assert!(q.is_withheld(&hash(3)), "the second push is still pending");
        b.validated();
        assert!(!q.is_withheld(&hash(3)));
    }
}
