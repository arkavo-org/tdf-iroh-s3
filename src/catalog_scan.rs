//! Every catalog the bucket holds, read strictly, for the offline commands
//! (`claim-owners`, and the deletion sweep): each signed pointer at
//! `catalog-pointers/<sub>` and each index record at
//! `catalog-indexes/<hash>`. Anything listed that can't be read or parsed
//! fails the scan, so a command never decides on part of the bucket, and
//! so does a `/2` pointer whose index record is missing or no longer
//! hashes to the `indexHash` it signed.

use anyhow::Context;
use std::collections::{BTreeSet, HashMap};

use crate::catalogs_v2_api::{IndexRecord, stored_pointer};
use crate::creator_catalog::{index_hash, is_lower_hex_hash, parse_index};
use crate::moderation::{canonical_subject, valid_subject};
use crate::object_store::{ObjectInfo, ObjectStore, bodies, parsed};

/// Where the signed pointers live: `catalog-pointers/<sub>`.
pub const POINTERS: &str = "catalog-pointers/";
/// Where the index records live: `catalog-indexes/<catalog hash>`.
pub const INDEXES: &str = "catalog-indexes/";

/// A stored pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedPointer {
    /// `catalog-pointers/<sub>`, `<sub>` byte for byte as the publisher's
    /// token named it.
    pub key: String,
    /// The key's `<sub>`, canonical (`moderation::canonical_subject`).
    pub subject: String,
    pub seq: u64,
    pub catalog_hash: String,
    /// The pointer's `indexHash`: `Some` for `/2`, `None` for `/1`.
    pub index_hash: Option<String>,
    /// Lowercase hex SHA-256 of the signed pointer bytes.
    pub digest: String,
}

/// An index record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedIndex {
    /// The publisher's `sub`, as the record names it.
    pub owner: String,
    /// The payload hashes its entries list.
    pub hashes: BTreeSet<String>,
}

/// What [`scan`] read.
#[derive(Debug, Default)]
pub struct Catalogs {
    /// Every pointer, in key order.
    pub pointers: Vec<ScannedPointer>,
    /// Every index record, current or superseded, by catalog hash.
    pub indexes: HashMap<String, ScannedIndex>,
}

impl Catalogs {
    /// The payload hashes of `p`'s live index: the index record of the
    /// catalog it names. `None` for a pointer at a catalog from before
    /// envelopes (always `/1`), which has no index record and which `GET`
    /// never serves.
    pub fn live_hashes(&self, p: &ScannedPointer) -> Option<&BTreeSet<String>> {
        self.indexes.get(&p.catalog_hash).map(|index| &index.hashes)
    }
}

/// Read every pointer, then every index record, 16 reads at a time
/// ([`bodies`], [`parsed`]: each index record parsed as its read ends).
/// `Err` if any of them can't be read or parsed, or
/// vanishes between the listing and its read, or if a `/2` pointer's index
/// record is missing or doesn't hash to its `indexHash`. The first error
/// ends the scan.
///
/// The two never overlap: every pointer is listed and read before the
/// index records are listed. A publish writes its index record before its
/// pointer, so the index listing that follows holds the record of every
/// `/2` pointer read, and a publish in flight cannot look like a `/2`
/// pointer without its index.
pub async fn scan<O: ObjectStore>(store: &O) -> anyhow::Result<Catalogs> {
    // Every pointer read has finished once this returns, before the index
    // listing below starts.
    let pointer_bodies = bodies(store, POINTERS).await?;
    let mut pointers = Vec::new();
    for (ObjectInfo { key, .. }, body) in pointer_bodies {
        let sub = name(&key, POINTERS)?;
        anyhow::ensure!(valid_subject(sub), "{key}: not a subject");
        let pointer = stored_pointer(&body).with_context(|| format!("{key} unreadable"))?;
        pointers.push(ScannedPointer {
            subject: canonical_subject(sub).to_string(),
            seq: pointer.seq,
            catalog_hash: pointer.catalog_hash,
            index_hash: pointer.index_hash,
            digest: pointer.digest,
            key,
        });
    }

    let mut indexes = HashMap::new();
    // Each record's canonical index hash, by catalog hash.
    let mut canonical = HashMap::new();
    // Each record is parsed as its read ends, so the scan holds what it
    // keeps of each, never every body at once.
    let records = parsed(store, INDEXES, |ObjectInfo { key, .. }, body| {
        let hash = name(&key, INDEXES)?;
        anyhow::ensure!(is_lower_hex_hash(hash), "{key}: not a catalog hash");
        let record: IndexRecord =
            serde_json::from_slice(&body).with_context(|| format!("{key} unreadable"))?;
        let entries = parse_index(record.entries)
            .map_err(|why| anyhow::anyhow!("{key} unreadable: invalid index: {why}"))?;
        let canonical = index_hash(&entries);
        let index = ScannedIndex {
            owner: record.owner,
            hashes: entries.into_iter().map(|e| e.payload_hash).collect(),
        };
        Ok((hash.to_string(), canonical, index))
    })
    .await?;
    for (hash, index_hash, index) in records {
        canonical.insert(hash.clone(), index_hash);
        indexes.insert(hash, index);
    }

    // A `/2` pointer's live index is the one it signed. Its index record is
    // written once, before the pointer, so a missing one is a fault too.
    // Pointers are listed and read before index records are listed, so a
    // publish in flight cannot look like one. A `/1` with no index record
    // is a pointer from before envelopes.
    for p in &pointers {
        let (key, hash) = (&p.key, &p.catalog_hash);
        match (&p.index_hash, canonical.get(hash)) {
            (Some(claimed), Some(actual)) => anyhow::ensure!(
                claimed == actual,
                "{key}: indexHash {claimed} does not match the index of catalog {hash} ({actual})"
            ),
            (Some(claimed), None) => anyhow::bail!(
                "{key}: indexHash {claimed} names catalog {hash}, which has no index record"
            ),
            (None, _) => {}
        }
    }
    Ok(Catalogs { pointers, indexes })
}

/// The part of a listed `key` after `prefix`.
fn name<'a>(key: &'a str, prefix: &str) -> anyhow::Result<&'a str> {
    key.strip_prefix(prefix)
        .with_context(|| format!("{key} listed under {prefix}"))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::catalog_v2::test_support::bundle;
    use crate::catalogs_v2_api::IndexRecord;
    use crate::creator_catalog::index_hash;
    use crate::creator_catalog::test_support::entry;
    use crate::object_store::mem::MemObjects;

    /// Store `sub`'s catalog `document` as a publish does: its index
    /// record, with one entry per payload hash, then a `/1` pointer at it.
    pub fn publish(store: &MemObjects, sub: &str, seq: u64, document: &[u8], payloads: &[&str]) {
        store_catalog(store, sub, seq, document, payloads, false);
    }

    /// As [`publish`], with a `/2` pointer whose `indexHash` is its
    /// index's. Returns that `indexHash`.
    pub fn publish_2(
        store: &MemObjects,
        sub: &str,
        seq: u64,
        document: &[u8],
        payloads: &[&str],
    ) -> String {
        store_catalog(store, sub, seq, document, payloads, true)
    }

    /// The index record of `sub`'s catalog listing `payloads`.
    pub fn index_record(sub: &str, payloads: &[&str]) -> IndexRecord {
        IndexRecord {
            owner: sub.to_string(),
            attribute: "https://patreon.arkavo.com/attr/campaign/value/1".to_string(),
            entries: payloads
                .iter()
                .enumerate()
                .map(|(i, payload)| entry(&format!("rec-{i}"), payload))
                .collect(),
        }
    }

    fn store_catalog(
        store: &MemObjects,
        sub: &str,
        seq: u64,
        document: &[u8],
        payloads: &[&str],
        signs_index: bool,
    ) -> String {
        let record = index_record(sub, payloads);
        let signed = index_hash(&parse_index(record.entries.clone()).unwrap());
        store.insert(
            &format!("{INDEXES}{}", blake3::hash(document).to_hex()),
            serde_json::to_vec(&record).unwrap(),
        );
        let index_hash = signs_index.then_some(signed.as_str());
        store.insert(
            &format!("{POINTERS}{sub}"),
            serde_json::to_vec(&bundle(sub, seq, document, index_hash)).unwrap(),
        );
        signed
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{self, publish, publish_2};
    use super::*;
    use crate::catalog_v2::test_support::pointer_bytes;
    use crate::object_store::mem::MemObjects;
    use crate::object_store::{READS_AT_ONCE, VersionInfo};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    const U: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    #[tokio::test]
    async fn scan_reads_pointers_and_indexes_strictly() {
        let m = MemObjects::default();
        let arkavo = format!("arkavo:{U}");
        publish(&m, &arkavo, 3, b"doc-1", &[&h("aa"), &h("bb")]);
        publish(&m, "u2", 1, b"doc-2", &[&h("bb")]);

        let catalogs = scan(&m).await.unwrap();
        assert_eq!(catalogs.pointers.len(), 2);
        let (first, second) = (&catalogs.pointers[0], &catalogs.pointers[1]);
        assert_eq!(first.key, format!("catalog-pointers/{arkavo}"));
        assert_eq!(first.subject, U, "canonical");
        assert_eq!(first.seq, 3);
        assert_eq!(first.catalog_hash, blake3::hash(b"doc-1").to_hex().as_str());
        assert_eq!(first.index_hash, None);
        assert_eq!(
            first.digest,
            hex::encode(Sha256::digest(pointer_bytes(&arkavo, 3, b"doc-1", None)))
        );
        assert_eq!(second.key, "catalog-pointers/u2");
        assert_eq!(second.subject, "u2");
        assert_eq!(
            second.digest,
            hex::encode(Sha256::digest(pointer_bytes("u2", 1, b"doc-2", None)))
        );

        assert_eq!(
            catalogs.live_hashes(first),
            Some(&BTreeSet::from([h("aa"), h("bb")]))
        );
        assert_eq!(
            catalogs.live_hashes(second),
            Some(&BTreeSet::from([h("bb")]))
        );
        assert_eq!(catalogs.indexes.len(), 2);
        let index = &catalogs.indexes[blake3::hash(b"doc-1").to_hex().as_str()];
        assert_eq!(index.owner, arkavo, "as recorded");

        // A pointer at a catalog with no index record has no live index.
        let pre_envelope = MemObjects::default();
        pre_envelope.insert(
            "catalog-pointers/u3",
            serde_json::to_vec(&crate::catalog_v2::test_support::bundle(
                "u3", 1, b"old", None,
            ))
            .unwrap(),
        );
        let catalogs = scan(&pre_envelope).await.unwrap();
        assert_eq!(catalogs.live_hashes(&catalogs.pointers[0]), None);

        // Anything unreadable fails the scan.
        let garbage_pointer = MemObjects::default();
        publish(&garbage_pointer, "u1", 1, b"doc", &[&h("aa")]);
        garbage_pointer.insert("catalog-pointers/u3", "not a bundle");
        assert!(scan(&garbage_pointer).await.is_err());

        let garbage_index = MemObjects::default();
        publish(&garbage_index, "u1", 1, b"doc", &[&h("aa")]);
        garbage_index.insert(&format!("catalog-indexes/{}", h("cc")), "{}");
        assert!(scan(&garbage_index).await.is_err());

        let bad_entries = MemObjects::default();
        let record = serde_json::json!({
            "owner": "u1",
            "attribute": "a",
            "entries": [{"contentID": "rec", "version": 1, "payloadHash": "AA", "payloadSize": 1}],
        });
        bad_entries.insert(
            &format!("catalog-indexes/{}", h("cc")),
            serde_json::to_vec(&record).unwrap(),
        );
        assert!(scan(&bad_entries).await.is_err());

        let not_a_hash = MemObjects::default();
        publish(&not_a_hash, "u1", 1, b"doc", &[&h("aa")]);
        let copy = not_a_hash
            .get(&format!(
                "catalog-indexes/{}",
                blake3::hash(b"doc").to_hex()
            ))
            .await
            .unwrap()
            .unwrap();
        not_a_hash.insert("catalog-indexes/not-a-hash", copy);
        assert!(scan(&not_a_hash).await.is_err());
    }

    /// A `/2` pointer signs its index: a live index record that no longer
    /// hashes to its `indexHash`, or none at all, fails the scan.
    #[tokio::test]
    async fn scan_refuses_a_2_pointer_whose_index_does_not_match() {
        let m = MemObjects::default();
        let signed = publish_2(&m, "u1", 2, b"doc", &[&h("aa"), &h("bb")]);
        publish(&m, "u2", 1, b"doc-2", &[&h("cc")]);
        let catalogs = scan(&m).await.unwrap();
        let p = &catalogs.pointers[0];
        assert_eq!(p.key, "catalog-pointers/u1");
        assert_eq!(p.index_hash.as_deref(), Some(signed.as_str()));
        assert_eq!(
            p.digest,
            hex::encode(Sha256::digest(pointer_bytes(
                "u1",
                2,
                b"doc",
                Some(&signed)
            )))
        );
        assert_eq!(catalogs.pointers[1].index_hash, None, "/1");

        // The record rewritten with another entry list.
        m.insert(
            &format!("catalog-indexes/{}", blake3::hash(b"doc").to_hex()),
            serde_json::to_vec(&test_support::index_record("u1", &[&h("aa")])).unwrap(),
        );
        let err = scan(&m).await.unwrap_err().to_string();
        assert!(err.contains("catalog-pointers/u1"), "{err}");
        assert!(err.contains("indexHash"), "{err}");

        // A `/2` pointer exists only after its write-once index record, so
        // one at a catalog with no index record is a fault, not a pointer
        // from before envelopes (those are `/1`).
        let missing = MemObjects::default();
        publish(&missing, "u2", 1, b"doc-2", &[&h("cc")]);
        missing.insert(
            "catalog-pointers/u3",
            serde_json::to_vec(&crate::catalog_v2::test_support::bundle(
                "u3",
                1,
                b"old",
                Some(&signed),
            ))
            .unwrap(),
        );
        let err = scan(&missing).await.unwrap_err().to_string();
        assert!(err.contains("catalog-pointers/u3"), "{err}");
        assert!(err.contains("no index record"), "{err}");
    }

    /// A publish creates its index record before the envelope and the
    /// pointer, so one whose envelope write failed leaves a record no
    /// pointer names: read like any other, and no pointer's live index.
    #[tokio::test]
    async fn an_index_record_no_pointer_names_is_no_fault() {
        let m = MemObjects::default();
        publish_2(&m, "u1", 1, b"doc", &[&h("aa")]);
        let orphan = blake3::hash(b"never written").to_hex().to_string();
        m.insert(
            &format!("{INDEXES}{orphan}"),
            serde_json::to_vec(&test_support::index_record("u2", &[&h("bb")])).unwrap(),
        );
        let catalogs = scan(&m).await.unwrap();
        assert_eq!(catalogs.pointers.len(), 1);
        assert_eq!(
            catalogs.live_hashes(&catalogs.pointers[0]),
            Some(&BTreeSet::from([h("aa")]))
        );
        assert_eq!(catalogs.indexes[&orphan].owner, "u2");
    }

    /// [`MemObjects`] whose reads finish out of order: each `get` gives way
    /// a number of times its key decides before it reads. It logs each
    /// listing as it starts and each read as it ends, and counts the reads
    /// in flight.
    #[derive(Default)]
    struct Scrambled {
        inner: MemObjects,
        log: std::sync::Mutex<Vec<Event>>,
        in_flight: AtomicUsize,
        most_in_flight: AtomicUsize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Listed(String),
        Read(String),
    }

    impl Scrambled {
        fn log(&self) -> Vec<Event> {
            self.log.lock().unwrap().clone()
        }

        /// The keys under `prefix`, in the order their reads ended.
        fn reads(&self, prefix: &str) -> Vec<String> {
            self.log()
                .into_iter()
                .filter_map(|e| match e {
                    Event::Read(key) if key.starts_with(prefix) => Some(key),
                    _ => None,
                })
                .collect()
        }
    }

    impl ObjectStore for Scrambled {
        async fn list(&self, prefix: &str) -> anyhow::Result<Vec<ObjectInfo>> {
            self.log
                .lock()
                .unwrap()
                .push(Event::Listed(prefix.to_string()));
            self.inner.list(prefix).await
        }

        async fn get(&self, key: &str) -> anyhow::Result<Option<bytes::Bytes>> {
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.most_in_flight.fetch_max(now, SeqCst);
            for _ in 0..blake3::hash(key.as_bytes()).as_bytes()[0] % 8 + 1 {
                tokio::task::yield_now().await;
            }
            let body = self.inner.get(key).await;
            self.in_flight.fetch_sub(1, SeqCst);
            self.log.lock().unwrap().push(Event::Read(key.to_string()));
            body
        }

        async fn list_versions(&self, prefix: &str) -> anyhow::Result<Vec<VersionInfo>> {
            self.inner.list_versions(prefix).await
        }

        async fn head_owner(&self, key: &str) -> anyhow::Result<Option<Option<String>>> {
            self.inner.head_owner(key).await
        }

        async fn put(&self, key: &str, body: bytes::Bytes) -> anyhow::Result<()> {
            self.inner.put(key, body).await
        }

        async fn create(&self, key: &str, body: bytes::Bytes) -> anyhow::Result<bool> {
            self.inner.create(key, body).await
        }

        async fn delete_all_versions(&self, key: &str) -> anyhow::Result<usize> {
            self.inner.delete_all_versions(key).await
        }

        async fn delete_versions(
            &self,
            key: &str,
            version_ids: &[String],
        ) -> anyhow::Result<usize> {
            self.inner.delete_versions(key, version_ids).await
        }
    }

    /// More pointers and index records than are read at once: subject
    /// `u<i>`'s catalog `doc-<i>`, at seq `i + 1`, lists payload `i`; every
    /// other pointer is `/2`.
    const MANY: usize = 40;

    fn doc(i: usize) -> Vec<u8> {
        format!("doc-{i}").into_bytes()
    }

    fn payload(i: usize) -> String {
        format!("{i:064x}")
    }

    fn many(m: &MemObjects) {
        for i in 0..MANY {
            let (sub, seq) = (format!("u{i:02}"), i as u64 + 1);
            if i % 2 == 0 {
                publish_2(m, &sub, seq, &doc(i), &[&payload(i)]);
            } else {
                publish(m, &sub, seq, &doc(i), &[&payload(i)]);
            }
        }
    }

    /// Reads that finish in any order give what reads in listing order
    /// give: each body with its own key, pointers in key order.
    #[tokio::test]
    async fn results_do_not_depend_on_completion_order() {
        let scrambled = Scrambled::default();
        many(&scrambled.inner);

        let in_order = scan(&scrambled.inner).await.unwrap();
        let catalogs = scan(&scrambled).await.unwrap();
        assert_eq!(catalogs.pointers, in_order.pointers);
        assert_eq!(catalogs.indexes, in_order.indexes);

        assert_eq!(catalogs.pointers.len(), MANY);
        assert_eq!(catalogs.indexes.len(), MANY);
        for (i, p) in catalogs.pointers.iter().enumerate() {
            assert_eq!(p.key, format!("{POINTERS}u{i:02}"));
            assert_eq!(p.seq, i as u64 + 1, "{}", p.key);
            assert_eq!(p.catalog_hash, blake3::hash(&doc(i)).to_hex().as_str());
            assert_eq!(p.index_hash.is_some(), i % 2 == 0, "{}", p.key);
            assert_eq!(
                catalogs.live_hashes(p),
                Some(&BTreeSet::from([payload(i)])),
                "{}",
                p.key
            );
            assert_eq!(catalogs.indexes[&p.catalog_hash].owner, format!("u{i:02}"));
        }

        // The premise: the reads ran up to 16 at once, never more, and
        // finished out of listing order.
        assert_eq!(scrambled.most_in_flight.load(SeqCst), READS_AT_ONCE);
        for prefix in [POINTERS, INDEXES] {
            let ended = scrambled.reads(prefix);
            let mut listed = ended.clone();
            listed.sort();
            assert_eq!(ended.len(), MANY, "{prefix}");
            assert_ne!(ended, listed, "{prefix} read in listing order");
        }
    }

    /// Every pointer is read before the index records are listed, so a
    /// publish that lands during the pointer reads (index record first,
    /// then pointer) is read whole: the `/2` pointer it wrote finds the
    /// index record it signed.
    #[tokio::test]
    async fn the_index_listing_waits_for_every_pointer_read() {
        let scrambled = Scrambled::default();
        many(&scrambled.inner);
        for i in 0..MANY {
            let sub = format!("u{i:02}");
            let key = format!("{POINTERS}{sub}");
            scrambled.inner.on_before_get(&key, move |m| {
                publish_2(m, &sub, 100 + i as u64, &doc(100 + i), &[&payload(100 + i)]);
            });
        }

        let catalogs = scan(&scrambled).await.unwrap();
        for (i, p) in catalogs.pointers.iter().enumerate() {
            assert_eq!(p.seq, 100 + i as u64, "{}", p.key);
            assert_eq!(
                catalogs.live_hashes(p),
                Some(&BTreeSet::from([payload(100 + i)])),
                "{}",
                p.key
            );
        }

        let log = scrambled.log();
        let listing = log
            .iter()
            .position(|e| *e == Event::Listed(INDEXES.to_string()))
            .unwrap();
        let last_pointer = log
            .iter()
            .rposition(|e| matches!(e, Event::Read(key) if key.starts_with(POINTERS)))
            .unwrap();
        assert!(last_pointer < listing, "{log:?}");
    }

    /// Each index record is parsed as its read ends, inside the read
    /// stream, so the scan holds parsed records and never every body at
    /// once: a malformed record first in listing order ends the scan
    /// before the records after it have all been read.
    #[tokio::test]
    async fn index_records_are_parsed_as_they_are_read() {
        let scrambled = Scrambled::default();
        many(&scrambled.inner);
        let first = format!("{INDEXES}{}", "0".repeat(64));
        scrambled.inner.insert(&first, "not an index record");

        let err = scan(&scrambled).await.unwrap_err();
        assert!(format!("{err:#}").contains(&first), "{err:#}");
        let read = scrambled.reads(INDEXES).len();
        assert!(
            read <= READS_AT_ONCE,
            "{read} of {} index records read",
            MANY + 1
        );
    }

    #[tokio::test]
    async fn a_failed_read_fails_the_scan() {
        use crate::object_store::mem::Op;
        let m = MemObjects::default();
        publish(&m, "u1", 1, b"doc", &[&h("aa")]);
        m.fail_on("catalog-pointers/u1", Op::Get);
        assert!(scan(&m).await.is_err());
        m.fail_on(
            &format!("catalog-indexes/{}", blake3::hash(b"doc").to_hex()),
            Op::List,
        );
        assert!(scan(&m).await.is_err());
        assert!(scan(&m).await.is_ok(), "each injection fails one call");
    }
}
