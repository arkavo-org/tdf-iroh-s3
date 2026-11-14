//! Every catalog the bucket holds, read strictly, for the offline commands
//! (`claim-owners`, and the deletion sweep): each signed pointer at
//! `catalog-pointers/<sub>` and each index record at
//! `catalog-indexes/<hash>`. Anything listed that can't be read or parsed
//! fails the scan, so a command never decides on part of the bucket, and
//! so does a `/2` pointer whose index record no longer hashes to the
//! `indexHash` it signed.

use anyhow::Context;
use std::collections::{BTreeSet, HashMap};

use crate::catalogs_v2_api::{IndexRecord, stored_pointer};
use crate::creator_catalog::{index_hash, is_lower_hex_hash, parse_index};
use crate::moderation::{canonical_subject, valid_subject};
use crate::object_store::ObjectStore;

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
    /// envelopes, which has no index record and which `GET` never serves.
    pub fn live_hashes(&self, p: &ScannedPointer) -> Option<&BTreeSet<String>> {
        self.indexes.get(&p.catalog_hash).map(|index| &index.hashes)
    }
}

/// Read every pointer and every index record. `Err` if any of them can't
/// be read or parsed, or vanishes between the listing and its read, or if
/// a `/2` pointer's index record doesn't hash to its `indexHash`.
pub async fn scan<O: ObjectStore>(store: &O) -> anyhow::Result<Catalogs> {
    let mut pointers = Vec::new();
    for listed in store.list(POINTERS).await? {
        let key = listed.key;
        let sub = name(&key, POINTERS)?;
        anyhow::ensure!(valid_subject(sub), "{key}: not a subject");
        let body = read(store, &key).await?;
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
    for listed in store.list(INDEXES).await? {
        let key = listed.key;
        let hash = name(&key, INDEXES)?;
        anyhow::ensure!(is_lower_hex_hash(hash), "{key}: not a catalog hash");
        let body = read(store, &key).await?;
        let record: IndexRecord =
            serde_json::from_slice(&body).with_context(|| format!("{key} unreadable"))?;
        let entries = parse_index(record.entries)
            .map_err(|why| anyhow::anyhow!("{key} unreadable: invalid index: {why}"))?;
        canonical.insert(hash.to_string(), index_hash(&entries));
        indexes.insert(
            hash.to_string(),
            ScannedIndex {
                owner: record.owner,
                hashes: entries.into_iter().map(|e| e.payload_hash).collect(),
            },
        );
    }

    // A `/2` pointer's live index is the one it signed. One with no index
    // record is from before envelopes, as a `/1` would be.
    for p in &pointers {
        if let (Some(claimed), Some(actual)) = (&p.index_hash, canonical.get(&p.catalog_hash)) {
            anyhow::ensure!(
                claimed == actual,
                "{}: indexHash {claimed} does not match the index of catalog {} ({actual})",
                p.key,
                p.catalog_hash
            );
        }
    }
    Ok(Catalogs { pointers, indexes })
}

/// The part of a listed `key` after `prefix`.
fn name<'a>(key: &'a str, prefix: &str) -> anyhow::Result<&'a str> {
    key.strip_prefix(prefix)
        .with_context(|| format!("{key} listed under {prefix}"))
}

/// A listed object's body; one deleted since the listing is an error.
async fn read<O: ObjectStore>(store: &O, key: &str) -> anyhow::Result<bytes::Bytes> {
    store
        .get(key)
        .await?
        .with_context(|| format!("{key} vanished during the scan"))
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
    use sha2::{Digest, Sha256};

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
    /// hashes to its `indexHash` fails the scan.
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

        // A `/2` pointer at a catalog with no index record is a pointer
        // from before envelopes, as for `/1`.
        let pre_envelope = MemObjects::default();
        pre_envelope.insert(
            "catalog-pointers/u3",
            serde_json::to_vec(&crate::catalog_v2::test_support::bundle(
                "u3",
                1,
                b"old",
                Some(&signed),
            ))
            .unwrap(),
        );
        let catalogs = scan(&pre_envelope).await.unwrap();
        assert_eq!(catalogs.live_hashes(&catalogs.pointers[0]), None);
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
