//! The bucket as the offline commands (`claim-owners`, `release-owner`,
//! the deletion sweep) see it: current objects, and every version and
//! delete marker of them. `S3Client` implements it (`store/s3.rs`);
//! `mem::MemObjects` is a versioned in-memory one for unit tests.
//!
//! Keys are relative to the `[s3] prefix`.

use bytes::Bytes;
use std::future::Future;

/// A current object and when its current version was written (Unix
/// seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub key: String,
    pub modified: i64,
}

/// One version of a key, or one delete marker, and when it was written
/// (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub key: String,
    pub version_id: String,
    pub delete_marker: bool,
    pub modified: i64,
}

/// A versioned object store.
pub trait ObjectStore: Send + Sync + 'static {
    /// Every current object whose key starts with `prefix`, in key order.
    /// A key whose newest version is a delete marker has no current object.
    fn list(&self, prefix: &str) -> impl Future<Output = anyhow::Result<Vec<ObjectInfo>>> + Send;

    /// Every version and delete marker of every key that starts with
    /// `prefix`, current or not, in key order. A prefix is not a key:
    /// `blobs/aa` also lists `blobs/aab…`.
    fn list_versions(
        &self,
        prefix: &str,
    ) -> impl Future<Output = anyhow::Result<Vec<VersionInfo>>> + Send;

    /// The current object's body, or `None` (no object, or a delete marker).
    fn get(&self, key: &str) -> impl Future<Output = anyhow::Result<Option<Bytes>>> + Send;

    /// Whether `key` has a current object, and its `owner` metadata
    /// (`x-amz-meta-owner`): `None` for no object, `Some(None)` for an
    /// object stored without it.
    fn head_owner(
        &self,
        key: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Option<String>>>> + Send;

    /// Write a new version of `key`.
    fn put(&self, key: &str, body: Bytes) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Write `key` only if it has no current object (`If-None-Match: *`).
    /// `false` when one exists; nothing is written then. `Err` when a
    /// concurrent conditional write to the key is still in progress after
    /// the retries (S3's 409): whether one exists is unknown.
    fn create(&self, key: &str, body: Bytes) -> impl Future<Output = anyhow::Result<bool>> + Send;

    /// Delete every version and every delete marker of exactly `key`, and
    /// return how many there were. Keys that only start with `key` are
    /// untouched. With no write in between, `create` on `key` then
    /// succeeds.
    fn delete_all_versions(&self, key: &str) -> impl Future<Output = anyhow::Result<usize>> + Send;

    /// Delete exactly the versions and delete markers of `key` that
    /// `version_ids` names, the current one last, and return how many
    /// there were. Any other version stays, one written since the caller
    /// listed `key` included; a named one already gone is skipped. Keys
    /// that only start with `key` are untouched.
    fn delete_versions(
        &self,
        key: &str,
        version_ids: &[String],
    ) -> impl Future<Output = anyhow::Result<usize>> + Send;
}

#[cfg(test)]
pub(crate) mod mem {
    use super::*;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    /// The calls a [`MemObjects::fail_on`] injection fails.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Op {
        /// `get` and `head_owner` of the key.
        Get,
        /// `put` and `create` of the key.
        Put,
        /// `delete_all_versions` and `delete_versions` of the key.
        Delete,
        /// `list` and `list_versions` of any prefix of the key, so of any
        /// listing that would include it.
        List,
    }

    type Hook = Box<dyn FnOnce(&MemObjects) + Send>;

    /// A versioned bucket in memory, as S3 versioning behaves: every write
    /// adds a version, a plain delete adds a delete marker, and a key whose
    /// newest version is a marker has no current object.
    #[derive(Default)]
    pub struct MemObjects {
        state: Mutex<State>,
    }

    #[derive(Default)]
    struct State {
        now: i64,
        /// Version IDs are never reused, also after a key's versions go.
        next_version: u64,
        /// Each key's versions, oldest first.
        keys: BTreeMap<String, Vec<Version>>,
        failures: Vec<(String, Op)>,
        deletes: Vec<String>,
        hooks: HashMap<String, Hook>,
        get_hooks: HashMap<String, Hook>,
    }

    struct Version {
        id: String,
        /// `None`: a delete marker.
        body: Option<Bytes>,
        owner: Option<String>,
        modified: i64,
    }

    impl State {
        fn add(&mut self, key: &str, body: Option<Bytes>, owner: Option<String>) {
            self.next_version += 1;
            let version = Version {
                id: format!("v{}", self.next_version),
                body,
                owner,
                modified: self.now,
            };
            self.keys.entry(key.to_string()).or_default().push(version);
        }

        /// The current object: the newest version, unless it is a marker.
        fn current(&self, key: &str) -> Option<&Version> {
            self.keys
                .get(key)
                .and_then(|versions| versions.last())
                .filter(|v| v.body.is_some())
        }

        /// Fail with the first injection of `op` whose key `matches`, and
        /// use it up.
        fn injected(&mut self, op: Op, matches: impl Fn(&str) -> bool) -> anyhow::Result<()> {
            match self
                .failures
                .iter()
                .position(|(key, o)| *o == op && matches(key))
            {
                Some(i) => {
                    let (key, _) = self.failures.remove(i);
                    anyhow::bail!("injected {op:?} failure on {key}")
                }
                None => Ok(()),
            }
        }
    }

    impl MemObjects {
        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.state.lock().unwrap()
        }

        /// Stamp later writes (and delete markers) with `now`.
        pub fn set_now(&self, now: i64) {
            self.state().now = now;
        }

        /// The time later writes are stamped with.
        pub fn now(&self) -> i64 {
            self.state().now
        }

        /// Make the next call of `op` on `key` fail, once (see [`Op`]).
        pub fn fail_on(&self, key: &str, op: Op) {
            self.state().failures.push((key.to_string(), op));
        }

        /// A plain `DeleteObject`: adds a delete marker to `key`.
        pub fn delete_current(&self, key: &str) {
            self.state().add(key, None, None);
        }

        /// The keys of every `delete_all_versions` and `delete_versions`
        /// call that succeeded, in order, one entry per call, also for one
        /// that deleted nothing.
        pub fn deletes(&self) -> Vec<String> {
            self.state().deletes.clone()
        }

        /// Run `f` once, just before the first `delete_all_versions` or
        /// `delete_versions` of `key` (before an injected `Op::Delete`
        /// failure is checked). `f` can write through `insert`: no lock is
        /// held while it runs.
        pub fn on_before_delete(&self, key: &str, f: impl FnOnce(&MemObjects) + Send + 'static) {
            self.state().hooks.insert(key.to_string(), Box::new(f));
        }

        /// Run `f` once, just before the next `get` of `key` (before an
        /// injected `Op::Get` failure is checked): a write landing during a
        /// read of the bucket, armed from another hook once the reads
        /// before it are done. `f` can write through `insert`.
        pub fn on_before_get(&self, key: &str, f: impl FnOnce(&MemObjects) + Send + 'static) {
            self.state().get_hooks.insert(key.to_string(), Box::new(f));
        }

        /// A put, synchronously, with no injected failure: for seeding and
        /// for hooks.
        pub fn insert(&self, key: &str, body: impl Into<Bytes>) {
            self.state().add(key, Some(body.into()), None);
        }

        /// [`insert`](Self::insert) with `owner` metadata, as a catalog
        /// document is stored.
        pub fn insert_with_owner(&self, key: &str, body: impl Into<Bytes>, owner: &str) {
            self.state()
                .add(key, Some(body.into()), Some(owner.to_string()));
        }
    }

    impl ObjectStore for MemObjects {
        async fn list(&self, prefix: &str) -> anyhow::Result<Vec<ObjectInfo>> {
            let mut state = self.state();
            state.injected(Op::List, |key| key.starts_with(prefix))?;
            Ok(state
                .keys
                .keys()
                .filter(|key| key.starts_with(prefix))
                .filter_map(|key| {
                    let current = state.current(key)?;
                    Some(ObjectInfo {
                        key: key.clone(),
                        modified: current.modified,
                    })
                })
                .collect())
        }

        /// In key order, each key's versions newest first, as S3 lists them.
        async fn list_versions(&self, prefix: &str) -> anyhow::Result<Vec<VersionInfo>> {
            let mut state = self.state();
            state.injected(Op::List, |key| key.starts_with(prefix))?;
            Ok(state
                .keys
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .flat_map(|(key, versions)| {
                    versions.iter().rev().map(|v| VersionInfo {
                        key: key.clone(),
                        version_id: v.id.clone(),
                        delete_marker: v.body.is_none(),
                        modified: v.modified,
                    })
                })
                .collect())
        }

        async fn get(&self, key: &str) -> anyhow::Result<Option<Bytes>> {
            // Taken out first: the hook writes through `self`, which locks.
            let hook = self.state().get_hooks.remove(key);
            if let Some(hook) = hook {
                hook(self);
            }
            let mut state = self.state();
            state.injected(Op::Get, |k| k == key)?;
            Ok(state.current(key).and_then(|v| v.body.clone()))
        }

        async fn head_owner(&self, key: &str) -> anyhow::Result<Option<Option<String>>> {
            let mut state = self.state();
            state.injected(Op::Get, |k| k == key)?;
            Ok(state.current(key).map(|v| v.owner.clone()))
        }

        async fn put(&self, key: &str, body: Bytes) -> anyhow::Result<()> {
            let mut state = self.state();
            state.injected(Op::Put, |k| k == key)?;
            state.add(key, Some(body), None);
            Ok(())
        }

        async fn create(&self, key: &str, body: Bytes) -> anyhow::Result<bool> {
            let mut state = self.state();
            state.injected(Op::Put, |k| k == key)?;
            if state.current(key).is_some() {
                return Ok(false);
            }
            state.add(key, Some(body), None);
            Ok(true)
        }

        async fn delete_all_versions(&self, key: &str) -> anyhow::Result<usize> {
            let mut state = self.before_delete(key)?;
            let deleted = state.keys.remove(key).map_or(0, |versions| versions.len());
            state.deletes.push(key.to_string());
            Ok(deleted)
        }

        async fn delete_versions(
            &self,
            key: &str,
            version_ids: &[String],
        ) -> anyhow::Result<usize> {
            let mut state = self.before_delete(key)?;
            let mut deleted = 0;
            if let Some(versions) = state.keys.get_mut(key) {
                let before = versions.len();
                versions.retain(|v| !version_ids.contains(&v.id));
                deleted = before - versions.len();
                if versions.is_empty() {
                    state.keys.remove(key);
                }
            }
            state.deletes.push(key.to_string());
            Ok(deleted)
        }
    }

    impl MemObjects {
        /// Run `key`'s [`on_before_delete`](Self::on_before_delete) hook,
        /// then fail with an injected `Op::Delete`, or lock for the delete.
        fn before_delete(&self, key: &str) -> anyhow::Result<std::sync::MutexGuard<'_, State>> {
            // Taken out first: the hook writes through `self`, which locks.
            let hook = self.state().hooks.remove(key);
            if let Some(hook) = hook {
                hook(self);
            }
            let mut state = self.state();
            state.injected(Op::Delete, |k| k == key)?;
            Ok(state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mem::{MemObjects, Op};
    use super::*;

    fn b(s: &'static str) -> Bytes {
        Bytes::from_static(s.as_bytes())
    }

    #[tokio::test]
    async fn create_after_every_version_is_deleted_succeeds() {
        let m = MemObjects::default();
        assert!(m.create("k", b("one")).await.unwrap());
        assert!(!m.create("k", b("again")).await.unwrap());
        m.put("k", b("two")).await.unwrap();
        assert_eq!(m.list_versions("k").await.unwrap().len(), 2);

        assert_eq!(m.delete_all_versions("k").await.unwrap(), 2);
        assert!(m.list_versions("k").await.unwrap().is_empty());
        assert_eq!(m.get("k").await.unwrap(), None);
        assert!(m.create("k", b("three")).await.unwrap());
        assert_eq!(m.get("k").await.unwrap(), Some(b("three")));
    }

    #[tokio::test]
    async fn delete_all_versions_removes_delete_markers() {
        let m = MemObjects::default();
        m.put("k", b("one")).await.unwrap();
        m.delete_current("k");
        let versions = m.list_versions("k").await.unwrap();
        assert_eq!(versions.len(), 2);
        // Newest first, as S3 lists them: the marker, then the object.
        assert!(versions[0].delete_marker);
        assert!(!versions[1].delete_marker);

        assert_eq!(m.delete_all_versions("k").await.unwrap(), 2);
        assert!(m.list_versions("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_versions_deletes_only_the_named_versions() {
        let m = MemObjects::default();
        m.put("k", b("one")).await.unwrap();
        m.delete_current("k");
        m.put("kk", b("longer")).await.unwrap();
        let ids = |versions: Vec<VersionInfo>| -> Vec<String> {
            versions
                .into_iter()
                .filter(|v| v.key == "k")
                .map(|v| v.version_id)
                .collect()
        };
        let listed = ids(m.list_versions("k").await.unwrap());
        m.on_before_delete("k", |m| m.insert("k", b("written meanwhile")));

        // The version and the marker; not the hook's write, nor `kk`.
        assert_eq!(m.delete_versions("k", &listed).await.unwrap(), 2);
        assert_eq!(m.get("k").await.unwrap(), Some(b("written meanwhile")));
        assert_eq!(m.get("kk").await.unwrap(), Some(b("longer")));
        // Named again: gone already.
        assert_eq!(m.delete_versions("k", &listed).await.unwrap(), 0);
        let rest = ids(m.list_versions("k").await.unwrap());
        assert_eq!(m.delete_versions("k", &rest).await.unwrap(), 1);
        assert!(
            m.list_versions("k")
                .await
                .unwrap()
                .iter()
                .all(|v| v.key == "kk")
        );
        assert_eq!(m.deletes(), ["k", "k", "k"]);

        m.fail_on("kk", Op::Delete);
        assert!(m.delete_versions("kk", &[]).await.is_err());
        assert_eq!(m.deletes().len(), 3, "a failed delete is not recorded");
    }

    #[tokio::test]
    async fn list_versions_matches_only_the_prefix() {
        let m = MemObjects::default();
        m.put("blobs/aa", b("1")).await.unwrap();
        m.put("blobs/aa", b("2")).await.unwrap();
        m.put("blobs/ab", b("3")).await.unwrap();
        m.put("manifests/aa", b("4")).await.unwrap();

        let versions = m.list_versions("blobs/aa").await.unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|v| v.key == "blobs/aa"));
        assert_ne!(versions[0].version_id, versions[1].version_id);

        let keys: Vec<String> = m
            .list_versions("blobs/")
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.key)
            .collect();
        assert_eq!(keys, ["blobs/aa", "blobs/aa", "blobs/ab"]);
    }

    #[tokio::test]
    async fn delete_all_versions_spares_longer_keys() {
        let m = MemObjects::default();
        m.put("blobs/aa", b("1")).await.unwrap();
        m.put("blobs/aab", b("2")).await.unwrap();

        assert_eq!(m.delete_all_versions("blobs/aa").await.unwrap(), 1);
        let left = m.list_versions("blobs/").await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, "blobs/aab");
        // A key with no versions deletes nothing.
        assert_eq!(m.delete_all_versions("blobs/zz").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn list_returns_current_objects_with_their_write_time() {
        let m = MemObjects::default();
        m.set_now(100);
        m.put("p/a", b("a")).await.unwrap();
        m.put("p/gone", b("g")).await.unwrap();
        m.set_now(200);
        m.delete_current("p/gone");
        m.put("p/b", b("b")).await.unwrap();
        m.put("q/c", b("c")).await.unwrap();

        assert_eq!(
            m.list("p/").await.unwrap(),
            [
                ObjectInfo {
                    key: "p/a".into(),
                    modified: 100
                },
                ObjectInfo {
                    key: "p/b".into(),
                    modified: 200
                },
            ]
        );
        // The marker is a version, stamped with the time it was written.
        let gone = m.list_versions("p/gone").await.unwrap();
        assert_eq!(
            gone.iter()
                .map(|v| (v.delete_marker, v.modified))
                .collect::<Vec<_>>(),
            [(true, 200), (false, 100)]
        );
    }

    #[tokio::test]
    async fn a_delete_marker_hides_the_object_until_it_is_written_again() {
        let m = MemObjects::default();
        m.put("k", b("one")).await.unwrap();
        m.delete_current("k");
        assert_eq!(m.get("k").await.unwrap(), None);
        assert_eq!(m.head_owner("k").await.unwrap(), None);
        assert!(m.create("k", b("two")).await.unwrap());
        assert_eq!(m.get("k").await.unwrap(), Some(b("two")));
        assert_eq!(m.list_versions("k").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn head_owner_reads_the_owner_metadata() {
        let m = MemObjects::default();
        m.insert_with_owner("catalog-documents/h", b("doc"), "u1");
        m.insert("catalog-documents/plain", b("doc"));
        assert_eq!(
            m.head_owner("catalog-documents/h").await.unwrap(),
            Some(Some("u1".to_string()))
        );
        assert_eq!(
            m.head_owner("catalog-documents/plain").await.unwrap(),
            Some(None)
        );
        assert_eq!(m.head_owner("catalog-documents/none").await.unwrap(), None);
        // The current version's metadata counts: a later put has none.
        m.put("catalog-documents/h", b("doc")).await.unwrap();
        assert_eq!(
            m.head_owner("catalog-documents/h").await.unwrap(),
            Some(None)
        );
    }

    #[tokio::test]
    async fn fail_on_fails_one_matching_call() {
        let m = MemObjects::default();
        m.insert("blobs/aa", b("1"));

        m.fail_on("blobs/aa", Op::Get);
        assert!(m.get("blobs/zz").await.is_ok(), "another key is unaffected");
        assert!(m.head_owner("blobs/aa").await.is_err());
        assert!(m.get("blobs/aa").await.is_ok(), "one failure only");

        m.fail_on("blobs/aa", Op::Put);
        assert!(m.create("blobs/aa", b("2")).await.is_err());
        m.put("blobs/aa", b("2")).await.unwrap();

        m.fail_on("blobs/aa", Op::Delete);
        assert!(m.delete_all_versions("blobs/aa").await.is_err());
        assert_eq!(m.list_versions("blobs/aa").await.unwrap().len(), 2);
        assert!(m.deletes().is_empty(), "a failed delete is not recorded");

        m.fail_on("blobs/aa", Op::List);
        assert!(m.list("manifests/").await.is_ok(), "a listing without it");
        assert!(m.list("blobs/").await.is_err());
        assert!(m.list_versions("").await.is_ok());
        m.fail_on("blobs/aa", Op::List);
        assert!(m.list_versions("blobs/aa").await.is_err());

        assert_eq!(m.delete_all_versions("blobs/aa").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn deletes_records_each_delete_in_order() {
        let m = MemObjects::default();
        m.insert("b", b("1"));
        m.insert("a", b("1"));
        m.delete_current("a");
        m.delete_all_versions("b").await.unwrap();
        m.delete_all_versions("a").await.unwrap();
        m.delete_all_versions("never-written").await.unwrap();
        assert_eq!(m.deletes(), ["b", "a", "never-written"]);
    }

    #[tokio::test]
    async fn on_before_get_runs_once_before_the_next_get() {
        let m = MemObjects::default();
        m.insert("k", b("one"));
        m.on_before_get("k", |m| m.insert("k", b("written meanwhile")));
        assert_eq!(m.get("k").await.unwrap(), Some(b("written meanwhile")));
        m.insert("k", b("again"));
        assert_eq!(m.get("k").await.unwrap(), Some(b("again")), "once");
    }

    #[tokio::test]
    async fn on_before_delete_runs_once_before_the_first_delete() {
        let m = MemObjects::default();
        m.insert("blobs/aa", b("1"));
        m.on_before_delete("blobs/aa", |m| {
            m.insert("blobs/aa", b("written meanwhile"));
            m.insert("catalog-pointers/u1", b("pointer"));
        });

        // The hook's write lands before the delete, so it is deleted too.
        assert_eq!(m.delete_all_versions("blobs/aa").await.unwrap(), 2);
        assert_eq!(
            m.get("catalog-pointers/u1").await.unwrap(),
            Some(b("pointer"))
        );

        m.insert("blobs/aa", b("again"));
        assert_eq!(m.delete_all_versions("blobs/aa").await.unwrap(), 1);
        assert_eq!(
            m.list_versions("catalog-pointers/u1").await.unwrap().len(),
            1,
            "the hook ran once"
        );
    }
}
