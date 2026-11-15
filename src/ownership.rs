//! Who owns a recording: `moderation/publishers/<hash>`, written once by
//! the first account to push the hash and never overwritten.
//!
//! Two operator commands write it outside ingest: `claim-owners` (the
//! backfill before ownership is enforced) and `release-owner` (frees a
//! recording whose owner's account was deleted).

use anyhow::Context;
use bytes::Bytes;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use tracing::warn;

use crate::creator_catalog::{is_lower_hex_hash, object_from_slice};
use crate::moderation::{canonical_subject, valid_subject};
use crate::object_store::ObjectStore;
use crate::store::s3::S3Client;

pub use crate::moderation::BlobOwner;

/// `moderation/publishers/<hash>`: the recording's owner record.
pub const PUBLISHERS: &str = "publishers";

/// Whose a recording is, as `GET /publish/recordings/{hash}` tells the
/// caller. It never names another account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OwnerView {
    /// The caller's subject owns it (compared canonically).
    #[serde(rename = "you")]
    You,
    /// Another account owns it.
    #[serde(rename = "another account")]
    Another,
    /// It has no owner record: the next push claims it.
    #[serde(rename = "none")]
    None,
}

/// Read the owner record stored under `hash`, strictly: it must be the
/// record's JSON, name `hash` itself and carry a valid subject.
pub fn parse_owner(hash: &str, bytes: &[u8]) -> anyhow::Result<BlobOwner> {
    let owner: BlobOwner =
        object_from_slice(bytes).with_context(|| format!("owner record {hash} unreadable"))?;
    anyhow::ensure!(owner.hash == hash, "owner record {hash} names another hash");
    anyhow::ensure!(
        valid_subject(&owner.subject),
        "owner record {hash} has an invalid subject"
    );
    Ok(owner)
}

/// Where owner records live. Object-safe, so the gate needs no type
/// parameter. `S3Client` in production.
pub trait OwnerStore: Send + Sync + 'static {
    /// The record's bytes, or `None` when the hash has no owner.
    fn get_owner<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>>;

    /// Create the record only if none exists. `false`: one already does,
    /// and it is left as it was.
    fn create_owner<'a>(
        &'a self,
        hash: &'a str,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>;
}

/// The `endpointId` of the owner records `claim-owners` creates.
pub const CLAIM_ENDPOINT: &str = "claim-owners";

/// What `claim-owners` found (or, with `write`, did).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClaimReport {
    /// Listed hashes whose owner record names their only lister.
    pub owned: usize,
    /// `(hash, canonical subject)`: each record created, or that a dry run
    /// would create, in hash order.
    pub claimed: Vec<(String, String)>,
    /// In hash order. Nothing is written for them.
    pub conflicts: Vec<Conflict>,
}

/// A listed hash `claim-owners` can't settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub hash: String,
    /// The canonical subjects whose live index lists it, sorted.
    pub listers: Vec<String>,
    /// The subject its owner record names, if it has one.
    pub owner: Option<String>,
}

/// What `release-owner` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Released {
    /// The record named the subject; this many versions and delete markers
    /// were deleted.
    Deleted(usize),
    /// The record names this other subject, and is kept.
    NotOwner(String),
    /// The hash has no owner record.
    NoRecord,
}

/// `moderation/publishers/<hash>`, relative to the `[s3] prefix`.
fn owner_key(hash: &str) -> String {
    format!("moderation/{PUBLISHERS}/{hash}")
}

/// `claim-owners`: before ownership is enforced, give every payload hash a
/// live index lists an owner record, so existing catalogs keep publishing.
/// For each listed hash:
/// - a record naming its only lister: owned, nothing to do;
/// - no record and one lister: claimed for that lister (canonical), with
///   `endpointId` [`CLAIM_ENDPOINT`];
/// - more than one lister, or a record naming a subject that isn't the
///   only lister: a conflict, nothing written.
///
/// Listers are pointer subjects, compared canonically. Every owner record
/// is read and parsed before anything is written, and one that can't be is
/// `Err`. Without `write` nothing is written. A create that finds a record
/// already there (a push claimed the hash meanwhile) is not reported as
/// claimed; the next run reads that record.
pub async fn claim_owners<O: ObjectStore>(
    store: &O,
    write: bool,
    now: i64,
) -> anyhow::Result<ClaimReport> {
    let catalogs = crate::catalog_scan::scan(store).await?;
    let mut listed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pointer in &catalogs.pointers {
        for hash in catalogs.live_hashes(pointer).into_iter().flatten() {
            listed
                .entry(hash.clone())
                .or_default()
                .insert(pointer.subject.clone());
        }
    }

    let mut report = ClaimReport::default();
    let mut claims = Vec::new();
    for (hash, listers) in listed {
        let owner = match store.get(&owner_key(&hash)).await? {
            Some(body) => Some(parse_owner(&hash, &body)?.subject),
            None => None,
        };
        let only = match listers.len() {
            1 => listers.first().cloned(),
            _ => None,
        };
        match (only, owner) {
            (Some(lister), None) => claims.push((hash, lister)),
            (Some(lister), Some(owner)) if canonical_subject(&owner) == lister => {
                report.owned += 1;
            }
            (_, owner) => report.conflicts.push(Conflict {
                hash,
                listers: listers.into_iter().collect(),
                owner,
            }),
        }
    }

    for (hash, subject) in claims {
        if write {
            let record = BlobOwner {
                hash: hash.clone(),
                subject: subject.clone(),
                endpoint_id: CLAIM_ENDPOINT.to_string(),
                at: now,
            };
            let body = Bytes::from(serde_json::to_vec(&record).expect("owner serializes"));
            if !store.create(&owner_key(&hash), body).await? {
                warn!(%hash, %subject, "Owner record appeared meanwhile; not claimed. Run claim-owners again");
                continue;
            }
        }
        report.claimed.push((hash, subject));
    }
    Ok(report)
}

/// `release-owner`: delete `hash`'s owner record, every version and delete
/// marker, only if it names `subject` (compared canonically), so the next
/// push claims the recording. A record that can't be parsed is `Err` and
/// kept.
pub async fn release_owner<O: ObjectStore>(
    store: &O,
    hash: &str,
    subject: &str,
) -> anyhow::Result<Released> {
    anyhow::ensure!(
        is_lower_hex_hash(hash),
        "invalid hash: must be 64 lowercase hex characters"
    );
    anyhow::ensure!(valid_subject(subject), "invalid subject");
    let key = owner_key(hash);
    let Some(body) = store.get(&key).await? else {
        return Ok(Released::NoRecord);
    };
    let owner = parse_owner(hash, &body)?;
    if canonical_subject(&owner.subject) != canonical_subject(subject) {
        return Ok(Released::NotOwner(owner.subject));
    }
    Ok(Released::Deleted(store.delete_all_versions(&key).await?))
}

impl OwnerStore for S3Client {
    fn get_owner<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>> {
        Box::pin(self.get_moderation_record(PUBLISHERS, hash))
    }

    fn create_owner<'a>(
        &'a self,
        hash: &'a str,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
        Box::pin(self.create_moderation_record(PUBLISHERS, hash, body))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Owner records keyed by hash. With `down` set every call fails; with
    /// `hang` set `get_owner` never resolves; with `delay` set it answers
    /// that much later.
    #[derive(Default)]
    pub struct MemOwners {
        pub records: Mutex<HashMap<String, Bytes>>,
        pub down: AtomicBool,
        pub hang: AtomicBool,
        pub delay: Mutex<Duration>,
    }

    impl OwnerStore for MemOwners {
        fn get_owner<'a>(
            &'a self,
            hash: &'a str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>> {
            Box::pin(async move {
                if self.hang.load(Ordering::Relaxed) {
                    std::future::pending::<()>().await;
                }
                let delay = *self.delay.lock().unwrap();
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                anyhow::ensure!(!self.down.load(Ordering::Relaxed), "down");
                Ok(self.records.lock().unwrap().get(hash).cloned())
            })
        }

        fn create_owner<'a>(
            &'a self,
            hash: &'a str,
            body: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
            Box::pin(async move {
                anyhow::ensure!(!self.down.load(Ordering::Relaxed), "down");
                match self.records.lock().unwrap().entry(hash.to_string()) {
                    Entry::Occupied(_) => Ok(false),
                    Entry::Vacant(slot) => {
                        slot.insert(body);
                        Ok(true)
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemOwners;
    use super::*;

    const H: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

    #[test]
    fn parse_owner_is_strict() {
        let good = format!(r#"{{"hash":"{H}","subject":"u1","endpointId":"e","at":1}}"#);
        let owner = parse_owner(H, good.as_bytes()).unwrap();
        assert_eq!(owner.hash, H);
        assert_eq!(owner.subject, "u1");
        assert_eq!(owner.endpoint_id, "e");
        assert_eq!(owner.at, 1);

        let other = "cd".repeat(32);
        let wrong_hash = format!(r#"{{"hash":"{other}","subject":"u1","endpointId":"e","at":1}}"#);
        assert!(parse_owner(H, wrong_hash.as_bytes()).is_err());

        let bad_subject = format!(r#"{{"hash":"{H}","subject":"a/b","endpointId":"e","at":1}}"#);
        assert!(parse_owner(H, bad_subject.as_bytes()).is_err());

        assert!(parse_owner(H, b"not json").is_err());

        let no_at = format!(r#"{{"hash":"{H}","subject":"u1","endpointId":"e"}}"#);
        assert!(parse_owner(H, no_at.as_bytes()).is_err());

        // The same values as an array: a derived struct reads it, the
        // record must be an object.
        let array = crate::creator_catalog::test_support::array_form(good.as_bytes());
        let why = parse_owner(H, &array).unwrap_err();
        assert!(
            format!("{why:#}").contains("expected a JSON object"),
            "{why:#}"
        );
    }

    #[test]
    fn owner_view_serializes_as_the_wire_strings() {
        for (view, wire) in [
            (OwnerView::You, "you"),
            (OwnerView::Another, "another account"),
            (OwnerView::None, "none"),
        ] {
            assert_eq!(serde_json::to_value(view).unwrap(), wire);
        }
    }

    mod offline {
        use super::super::*;
        use crate::catalog_scan::test_support::publish;
        use crate::object_store::mem::MemObjects;

        const NOW: i64 = 1_800_000_000;
        const U: &str = "550e8400-e29b-41d4-a716-446655440000";

        fn h(byte: &str) -> String {
            byte.repeat(32)
        }

        fn key(hash: &str) -> String {
            format!("moderation/publishers/{hash}")
        }

        /// An owner record naming `subject`, as ingest writes it.
        fn record(hash: &str, subject: &str) -> Vec<u8> {
            serde_json::to_vec(&BlobOwner {
                hash: hash.to_string(),
                subject: subject.to_string(),
                endpoint_id: "e".to_string(),
                at: 1,
            })
            .unwrap()
        }

        async fn owner(m: &MemObjects, hash: &str) -> Option<BlobOwner> {
            let body = m.get(&key(hash)).await.unwrap()?;
            Some(parse_owner(hash, &body).unwrap())
        }

        async fn owner_writes(m: &MemObjects) -> usize {
            m.list_versions("moderation/").await.unwrap().len()
        }

        #[tokio::test]
        async fn claim_owners_creates_a_record_for_the_only_lister() {
            let m = MemObjects::default();
            publish(&m, "u1", 1, b"doc-u1", &[&h("aa")]);

            let dry = claim_owners(&m, false, NOW).await.unwrap();
            assert_eq!(dry.claimed, [(h("aa"), "u1".to_string())]);
            assert_eq!((dry.owned, dry.conflicts.len()), (0, 0));
            assert_eq!(owner_writes(&m).await, 0, "a dry run writes nothing");

            let wet = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(wet, dry);
            let created = owner(&m, &h("aa")).await.unwrap();
            assert_eq!(created.subject, "u1");
            assert_eq!(created.endpoint_id, "claim-owners");
            assert_eq!(created.at, NOW);

            let again = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(again.owned, 1);
            assert!(again.claimed.is_empty() && again.conflicts.is_empty());
            assert_eq!(owner_writes(&m).await, 1);
        }

        #[tokio::test]
        async fn two_pointer_keys_of_one_subject_are_one_lister() {
            let m = MemObjects::default();
            publish(&m, &format!("arkavo:{U}"), 1, b"doc-a", &[&h("aa")]);
            publish(&m, U, 1, b"doc-b", &[&h("aa")]);

            let report = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(report.claimed, [(h("aa"), U.to_string())]);
            assert!(report.conflicts.is_empty());
            assert_eq!(owner(&m, &h("aa")).await.unwrap().subject, U, "canonical");
        }

        #[tokio::test]
        async fn two_listers_are_a_conflict() {
            let m = MemObjects::default();
            publish(&m, "u2", 1, b"doc-u2", &[&h("aa")]);
            publish(&m, "u1", 1, b"doc-u1", &[&h("aa"), &h("bb")]);

            let report = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(
                report.conflicts,
                [Conflict {
                    hash: h("aa"),
                    listers: vec!["u1".to_string(), "u2".to_string()],
                    owner: None,
                }]
            );
            assert!(
                owner(&m, &h("aa")).await.is_none(),
                "nothing written for it"
            );
            // A conflict holds back only its own hash.
            assert_eq!(report.claimed, [(h("bb"), "u1".to_string())]);
            assert_eq!(owner_writes(&m).await, 1);
        }

        #[tokio::test]
        async fn an_owner_who_does_not_list_it_is_a_conflict() {
            let m = MemObjects::default();
            m.insert(&key(&h("aa")), record(&h("aa"), "u2"));
            publish(&m, "u1", 1, b"doc-u1", &[&h("aa")]);

            let report = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(
                report.conflicts,
                [Conflict {
                    hash: h("aa"),
                    listers: vec!["u1".to_string()],
                    owner: Some("u2".to_string()),
                }]
            );
            assert!(report.claimed.is_empty());
            assert_eq!(owner(&m, &h("aa")).await.unwrap().subject, "u2");
            assert_eq!(owner_writes(&m).await, 1, "the record is kept as it was");

            // An owner among several listers is a conflict too.
            publish(&m, "u2", 1, b"doc-u2", &[&h("aa")]);
            let report = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(report.conflicts[0].listers, ["u1", "u2"]);
            assert_eq!(report.conflicts[0].owner.as_deref(), Some("u2"));
        }

        #[tokio::test]
        async fn an_owner_who_lists_it_is_owned() {
            let m = MemObjects::default();
            m.insert(&key(&h("aa")), record(&h("aa"), U));
            publish(&m, &format!("arkavo:{U}"), 1, b"doc", &[&h("aa")]);

            let report = claim_owners(&m, true, NOW).await.unwrap();
            assert_eq!(report.owned, 1);
            assert!(report.claimed.is_empty() && report.conflicts.is_empty());
            assert_eq!(owner_writes(&m).await, 1);
        }

        #[tokio::test]
        async fn an_unreadable_owner_record_fails_the_claim_before_any_write() {
            let m = MemObjects::default();
            // `aa` would be claimed, and comes first.
            publish(&m, "u1", 1, b"doc", &[&h("aa"), &h("bb")]);
            m.insert(&key(&h("bb")), "not a record");
            assert!(claim_owners(&m, true, NOW).await.is_err());
            assert!(owner(&m, &h("aa")).await.is_none());

            // So does a record that names another hash.
            let m = MemObjects::default();
            publish(&m, "u1", 1, b"doc", &[&h("aa"), &h("bb")]);
            m.insert(&key(&h("bb")), record(&h("cc"), "u1"));
            assert!(claim_owners(&m, true, NOW).await.is_err());
            assert!(owner(&m, &h("aa")).await.is_none());
        }

        #[tokio::test]
        async fn hashes_no_live_index_lists_are_left() {
            let m = MemObjects::default();
            // A superseded index record, and a pointer at another catalog.
            publish(&m, "u1", 1, b"old", &[&h("aa")]);
            publish(&m, "u1", 2, b"new", &[&h("bb")]);
            let report = claim_owners(&m, false, NOW).await.unwrap();
            assert_eq!(report.claimed, [(h("bb"), "u1".to_string())]);
        }

        #[tokio::test]
        async fn release_owner_deletes_only_the_named_subjects_record() {
            let m = MemObjects::default();
            let k = key(&h("aa"));
            // Versions earlier deletes and writes left behind.
            m.insert(&k, record(&h("aa"), "u0"));
            m.delete_current(&k);
            m.insert(&k, record(&h("aa"), U));

            assert_eq!(
                release_owner(&m, &h("aa"), "u1").await.unwrap(),
                Released::NotOwner(U.to_string())
            );
            assert_eq!(owner(&m, &h("aa")).await.unwrap().subject, U, "kept");

            assert_eq!(
                release_owner(&m, &h("aa"), &format!("arkavo:{U}"))
                    .await
                    .unwrap(),
                Released::Deleted(3)
            );
            assert!(m.list_versions(&k).await.unwrap().is_empty());

            assert_eq!(
                release_owner(&m, &h("aa"), U).await.unwrap(),
                Released::NoRecord
            );

            // An unreadable record is never deleted.
            m.insert(&k, "not a record");
            assert!(release_owner(&m, &h("aa"), U).await.is_err());
            assert_eq!(m.list_versions(&k).await.unwrap().len(), 1);

            // Nor is a hash or subject that couldn't be a key.
            assert!(release_owner(&m, &"AA".repeat(32), U).await.is_err());
            assert!(release_owner(&m, &h("aa"), "a/b").await.is_err());
        }
    }

    #[tokio::test]
    async fn create_owner_never_overwrites() {
        let mem = MemOwners::default();
        let owners: &dyn OwnerStore = &mem;
        let first = Bytes::from_static(b"first");
        let second = Bytes::from_static(b"second");
        assert!(owners.create_owner(H, first.clone()).await.unwrap());
        assert!(!owners.create_owner(H, second).await.unwrap());
        assert_eq!(owners.get_owner(H).await.unwrap(), Some(first));
    }
}
