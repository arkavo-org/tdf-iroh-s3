//! The node's local store as push staging.
//!
//! Fetches are served from S3 ([`crate::s3_serve`]); the local store only
//! holds a push while it arrives and is ingested. A push is *pending* from
//! the moment the node accepts it until ingest is done with it: exported
//! for validation and uploaded, refused, or abandoned. Nothing in the store
//! is ever served, so nothing in it needs withholding.
//!
//! Every blob in the store that no pending push needs is deleted by the
//! store's garbage collector (iroh-blobs' only deletion), configured with
//! [`Staging::gc_config`]: a run protects exactly the pending pushes, read
//! before and after listing the store, and iroh-blobs itself protects
//! anything written once the run has started. So disk holds the pushes in
//! flight and, for up to one collector interval, the copies of pushes
//! already ingested. A push that starts and writes all its data between
//! the last read and the collector's start can lose it; its ingest then
//! finds the blob incomplete, and the publisher pushes again.
//!
//! The collector is the only cleanup, and iroh-blobs ends its loop for good
//! after a run fails. Each run starts with the protect callback, so
//! [`Staging::collector_stopped`] notices when the callback stops being
//! called; the node then restarts (once no push is pending) to get a fresh
//! collector, rather than letting staged pushes fill the disk.

use iroh_blobs::Hash;
use iroh_blobs::api::Store;
use iroh_blobs::store::{GcConfig, ProtectOutcome};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing::{debug, error, warn};

pub struct Staging {
    /// Pushes not yet ingested, with how many of each are in flight.
    pending: Mutex<HashMap<Hash, usize>>,
    /// The store, once loaded (the collector is configured before).
    store: OnceLock<Store>,
    /// The node's runtime: the collector runs on the store's own runtime,
    /// so its store requests run here instead.
    runtime: tokio::runtime::Handle,
    /// When the collector last started a run (called the protect callback).
    last_run: Mutex<tokio::time::Instant>,
}

/// How long [`Staging::collector_stopped`] waits for pending pushes to end
/// before it reports anyway.
const DRAIN_LIMIT: Duration = Duration::from_secs(15 * 60);

impl Staging {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: Mutex::default(),
            store: OnceLock::new(),
            runtime: tokio::runtime::Handle::current(),
            last_run: Mutex::new(tokio::time::Instant::now()),
        })
    }

    /// Give staging the store its collector deletes from.
    pub fn attach(&self, store: Store) {
        let _ = self.store.set(store);
    }

    /// The garbage collector configuration that deletes every blob no
    /// pending push needs, checking every `interval`.
    pub fn gc_config(self: &Arc<Self>, interval: Duration) -> GcConfig {
        let staging = Arc::clone(self);
        GcConfig {
            interval,
            add_protected: Some(Arc::new(move |live: &mut HashSet<Hash>| {
                let staging = Arc::clone(&staging);
                *lock(&staging.last_run) = tokio::time::Instant::now();
                Box::pin(async move {
                    // The callback's future must be Sync; store requests are
                    // not, so they run in a task of their own.
                    let runtime = staging.runtime.clone();
                    match runtime.spawn(async move { staging.keep_set().await }).await {
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

    /// Resolves once the collector has not started a run for `dead_after`,
    /// checking every `poll`, and then no push is pending (or
    /// [`DRAIN_LIMIT`] passed), so a restart cuts off no push.
    pub async fn collector_stopped(&self, dead_after: Duration, poll: Duration) {
        while lock(&self.last_run).elapsed() < dead_after {
            tokio::time::sleep(poll).await;
        }
        error!(
            ?dead_after,
            "The store's garbage collector stopped; staged pushes are no longer deleted"
        );
        let deadline = tokio::time::Instant::now() + DRAIN_LIMIT;
        while !lock(&self.pending).is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(poll).await;
        }
    }

    /// A push the node accepted: pending until the returned guard drops.
    pub fn track(self: &Arc<Self>, hash: Hash) -> PendingPush {
        *lock(&self.pending).entry(hash).or_default() += 1;
        PendingPush {
            staging: Arc::clone(self),
            hash,
        }
    }

    /// Whether a push of `hash` is pending.
    pub fn is_pending(&self, hash: &Hash) -> bool {
        lock(&self.pending).contains_key(hash)
    }

    /// The hashes this collector run keeps: the pending pushes, read before
    /// and after listing the store. `None` skips the run, when every stored
    /// blob is pending or the store cannot be listed.
    async fn keep_set(&self) -> Option<HashSet<Hash>> {
        let store = self.store.get()?.clone();
        let mut keep: HashSet<Hash> = lock(&self.pending).keys().copied().collect();
        if let Err(e) = store.sync_db().await {
            warn!(error = %e, "Store sync before garbage collection failed");
            return None;
        }
        let stored: Vec<Hash> = match store.blobs().list().hashes().await {
            Ok(hashes) => hashes,
            Err(e) => {
                warn!(error = %e, "Listing blobs for garbage collection failed");
                return None;
            }
        };
        keep.extend(lock(&self.pending).keys().copied());
        let doomed = stored.iter().filter(|h| !keep.contains(*h)).count();
        if doomed == 0 {
            return None;
        }
        debug!(
            doomed,
            stored = stored.len(),
            "Garbage collection deletes staged blobs no push needs"
        );
        Some(keep)
    }
}

/// A push being received or ingested; dropping it ends it.
pub struct PendingPush {
    staging: Arc<Staging>,
    hash: Hash,
}

impl Drop for PendingPush {
    fn drop(&mut self) {
        let mut pending = lock(&self.staging.pending);
        if let Some(n) = pending.get_mut(&self.hash) {
            *n -= 1;
            if *n == 0 {
                pending.remove(&self.hash);
            }
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

    async fn staged() -> (Arc<Staging>, FsStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let staging = Staging::new();
        let store = FsStore::load(dir.path().join("store")).await.unwrap();
        staging.attach(store.clone().into());
        (staging, store, dir)
    }

    async fn stored(store: &FsStore, data: &[u8]) -> Hash {
        store.add_slice(data).temp_tag().await.unwrap().hash()
    }

    /// A pending push is kept; every other stored blob is collected; with
    /// nothing to collect the run is skipped.
    #[tokio::test]
    async fn the_collector_keeps_only_pending_pushes() {
        let (staging, store, _dir) = staged().await;
        assert!(staging.keep_set().await.is_none(), "an empty store");

        let pushed = stored(&store, &[1u8; 40_000]).await;
        let done = stored(&store, &[2u8; 40_000]).await;
        let push = staging.track(pushed);
        let keep = staging.keep_set().await.expect("a blob to collect");
        assert!(keep.contains(&pushed));
        assert!(!keep.contains(&done));

        drop(push);
        assert!(!staging.is_pending(&pushed));
        let keep = staging.keep_set().await.expect("both collected");
        assert!(keep.is_empty());
        store.shutdown().await.unwrap();
    }

    /// Each collector run calls the protect callback, which counts as a
    /// sign of life; without one for `dead_after`, the collector is
    /// reported stopped, but only once no push is pending.
    #[tokio::test]
    async fn a_silent_collector_is_reported_once_pushes_end() {
        let (staging, store, _dir) = staged().await;
        let (dead_after, poll) = (Duration::from_millis(300), Duration::from_millis(10));
        let protect = staging
            .gc_config(Duration::from_secs(60))
            .add_protected
            .unwrap();
        let start = tokio::time::Instant::now();
        let watch = staging.collector_stopped(dead_after, poll);
        tokio::pin!(watch);
        // Runs keep it alive.
        for _ in 0..5 {
            tokio::select! {
                () = &mut watch => panic!("reported while the collector runs"),
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            protect(&mut HashSet::new()).await;
        }
        // Then silence, with a push pending: not reported until it ends.
        let push = staging.track(Hash::new(b"in flight"));
        tokio::select! {
            () = &mut watch => panic!("reported while a push is pending"),
            () = tokio::time::sleep(dead_after * 2) => {}
        }
        drop(push);
        tokio::time::timeout(Duration::from_secs(5), watch)
            .await
            .expect("reported once the push ended");
        assert!(start.elapsed() >= Duration::from_millis(500) + dead_after);
        store.shutdown().await.unwrap();
    }

    /// Two pushes of one hash: pending until both end.
    #[tokio::test]
    async fn a_hash_is_pending_until_its_last_push_ends() {
        let (staging, store, _dir) = staged().await;
        let hash = Hash::new(b"x");
        let first = staging.track(hash);
        let second = staging.track(hash);
        drop(first);
        assert!(staging.is_pending(&hash));
        drop(second);
        assert!(!staging.is_pending(&hash));
        store.shutdown().await.unwrap();
    }
}
