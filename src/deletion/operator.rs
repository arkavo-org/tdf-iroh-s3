//! `request-deletion` (spec 3.3): an operator asks the sweep to delete
//! what the publish path can't request.
//!
//! - [`request_hashes`] (`--hash`): moderation-blocked recordings, which
//!   the sweep otherwise keeps while their block stands (decision 3).
//!   Writes `operator/<sub>/<hash>`, scope `hash`.
//! - [`request_all`] (`--all`): everything an account published, for a
//!   creator who can't publish an empty catalog (decision 6). Its
//!   precondition is the account's active catalog block. Writes a
//!   scope-`subject` `operator/<sub>/<hash>` for every hash in a live index
//!   of the account's pointers and every hash its owner records name, then
//!   `subjects/<sub>`, which deletes its pointers. That is its whole
//!   coverage: anything else needs `--hash`.
//!
//! Both read the bucket strictly first ([`snapshot::read`]) and check every
//! precondition before they write anything, so an unreadable record or an
//! unmet precondition writes nothing. Subjects in keys and bodies are
//! canonical, and each record is one the next sweep reads back.

use anyhow::Context;
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};

use super::snapshot::{self, Snapshot};
use super::{OperatorRequest, Scope, State, SubjectRequest, operator_key, subject_key};
use crate::creator_catalog::is_lower_hex_hash;
use crate::moderation::{canonical_subject, valid_subject};
use crate::object_store::ObjectStore;

/// What `request-deletion` did at one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// There was no request: a pending one is written.
    Requested,
    /// There was a tombstone (`deleted`): the operator asks again, so a
    /// new pending request replaces it.
    Renewed,
    /// There was a pending operator request of the other scope, one that
    /// can't delete the hash while the requested one can: scope `subject`
    /// keeps a blocked hash, and scope `hash` keeps one whose block was
    /// lifted. The requested scope replaces it.
    Rescoped,
    /// There was a pending request, and it is left as it was.
    Exists,
}

/// One key `request-deletion` wrote, or found pending and left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requested {
    pub key: String,
    pub outcome: Outcome,
}

/// `request-deletion --subject <subject> --hash <hash>...`: a scope-`hash`
/// request for each hash, deduplicated, in hash order. `Err`, with nothing
/// written, if the subject, a hash or the reason is invalid, if anything
/// in the bucket is unreadable, or if a hash has no active block (the
/// first such, in the order given).
pub async fn request_hashes<O: ObjectStore>(
    store: &O,
    subject: &str,
    hashes: &[String],
    reason: &str,
    now: i64,
) -> anyhow::Result<Vec<Requested>> {
    let sub = canonical(subject)?;
    let reason = given(reason)?;
    anyhow::ensure!(!hashes.is_empty(), "no hash given");
    for hash in hashes {
        anyhow::ensure!(
            is_lower_hex_hash(hash),
            "invalid hash {hash}: must be 64 lowercase hex characters"
        );
    }
    let snapshot = snapshot::read(store).await?;
    let blocked = &snapshot.moderation.blocked;
    if let Some(hash) = hashes.iter().find(|hash| !blocked.contains(*hash)) {
        anyhow::bail!("{hash} has no active block: --hash deletes only blocked content");
    }
    let mut out = Vec::new();
    for hash in hashes.iter().collect::<BTreeSet<_>>() {
        out.push(request_one(store, &snapshot, sub, hash, Scope::Hash, reason, now).await?);
    }
    Ok(out)
}

/// `request-deletion --subject <subject> --all`: a scope-`subject` request
/// for every hash in the live index of each pointer whose subject is
/// canonically `subject`, and every hash whose owner record names it,
/// deduplicated, in hash order; then `subjects/<sub>`, last. `Err`, with
/// nothing written, if the subject or the reason is invalid, if anything
/// in the bucket is unreadable, or if the subject has no active catalog
/// block.
pub async fn request_all<O: ObjectStore>(
    store: &O,
    subject: &str,
    reason: &str,
    now: i64,
) -> anyhow::Result<Vec<Requested>> {
    let sub = canonical(subject)?;
    let reason = given(reason)?;
    let snapshot = snapshot::read(store).await?;
    anyhow::ensure!(
        snapshot.moderation.catalog_blocked.contains(sub),
        "{sub} has no active catalog block: --all needs one"
    );
    let catalogs = &snapshot.catalogs;
    let mut hashes = BTreeSet::new();
    for pointer in catalogs.pointers.iter().filter(|p| p.subject == sub) {
        hashes.extend(catalogs.live_hashes(pointer).into_iter().flatten());
    }
    // Owner records' subjects are canonical in the snapshot.
    hashes.extend(
        snapshot
            .owners
            .iter()
            .filter(|(_, owner)| *owner == sub)
            .map(|(hash, _)| hash),
    );
    let mut out = Vec::new();
    for hash in hashes {
        out.push(request_one(store, &snapshot, sub, hash, Scope::Subject, reason, now).await?);
    }

    let key = subject_key(sub);
    let outcome = match snapshot.requests.subjects.get(sub) {
        None => Outcome::Requested,
        Some(r) if r.state == State::Deleted => Outcome::Renewed,
        Some(_) => Outcome::Exists,
    };
    let record = SubjectRequest {
        subject: sub.to_string(),
        requested_at: now,
        reason: reason.to_string(),
        state: State::Pending,
        deleted_at: None,
    };
    out.push(write(store, key, outcome, &record).await?);
    Ok(out)
}

/// `operator/<sub>/<hash>` at `scope`, unless a pending request there is
/// left ([`Outcome`]).
async fn request_one<O: ObjectStore>(
    store: &O,
    snapshot: &Snapshot,
    sub: &str,
    hash: &str,
    scope: Scope,
    reason: &str,
    now: i64,
) -> anyhow::Result<Requested> {
    let key = operator_key(sub, hash);
    let existing = snapshot
        .requests
        .operator
        .get(&(sub.to_string(), hash.to_string()));
    let outcome = match existing {
        None => Outcome::Requested,
        Some(r) if r.state == State::Deleted => Outcome::Renewed,
        Some(r) if r.scope != scope && !deletes(r.scope, hash, &snapshot.moderation.blocked) => {
            Outcome::Rescoped
        }
        Some(_) => Outcome::Exists,
    };
    let record = OperatorRequest {
        hash: hash.to_string(),
        subject: sub.to_string(),
        requested_at: now,
        reason: reason.to_string(),
        scope,
        state: State::Pending,
        deleted_at: None,
    };
    write(store, key, outcome, &record).await
}

/// Whether a request of `scope` can delete `hash` with the blocks as they
/// stand (`due.rs`): scope `hash` only while it is blocked, scope
/// `subject` only while it isn't.
fn deletes(scope: Scope, hash: &str, blocked: &HashSet<String>) -> bool {
    match scope {
        Scope::Hash => blocked.contains(hash),
        Scope::Subject => !blocked.contains(hash),
    }
}

/// Write `record` at `key` as `outcome` says: a new key only if it is
/// still absent (one that appeared since the read is left, as `Exists`),
/// a replaced one over what is there, and an `Exists` not at all.
async fn write<O: ObjectStore, T: Serialize>(
    store: &O,
    key: String,
    outcome: Outcome,
    record: &T,
) -> anyhow::Result<Requested> {
    let body = || Bytes::from(serde_json::to_vec(record).expect("request serializes"));
    let outcome = match outcome {
        Outcome::Exists => Outcome::Exists,
        Outcome::Requested => {
            let created = store
                .create(&key, body())
                .await
                .with_context(|| format!("writing {key} failed"))?;
            if created {
                Outcome::Requested
            } else {
                Outcome::Exists
            }
        }
        Outcome::Renewed | Outcome::Rescoped => {
            store
                .put(&key, body())
                .await
                .with_context(|| format!("writing {key} failed"))?;
            outcome
        }
    };
    Ok(Requested { key, outcome })
}

/// `subject`'s canonical form, which request keys carry. It must be a
/// subject whose canonical form is one too, as the sweep's strict read
/// requires of a request key (`arkavo:` alone, or `arkavo:arkavo:<id>`,
/// is not).
fn canonical(subject: &str) -> anyhow::Result<&str> {
    let sub = canonical_subject(subject);
    anyhow::ensure!(
        valid_subject(subject) && valid_subject(sub) && canonical_subject(sub) == sub,
        "invalid subject {subject}"
    );
    Ok(sub)
}

/// The reason, trimmed; empty is refused.
fn given(reason: &str) -> anyhow::Result<&str> {
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "--reason must not be empty");
    Ok(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_scan::test_support::{publish, publish_2};
    use crate::deletion::snapshot;
    use crate::deletion::{
        OperatorRequest, Scope, State, SubjectRequest, operator_key, subject_key,
    };
    use crate::object_store::mem::MemObjects;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    const U: &str = "550e8400-e29b-41d4-a716-446655440000";
    const U2: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const WHY: &str = "court order 7";

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    fn put(m: &MemObjects, key: &str, body: serde_json::Value) {
        m.insert(key, serde_json::to_vec(&body).unwrap());
    }

    fn block(m: &MemObjects, hash: &str, lifted_at: Option<i64>) {
        put(
            m,
            &format!("moderation/blocks/{hash}"),
            json!({"hash": hash, "reason": "r", "by": "op", "at": 1, "liftedAt": lifted_at}),
        );
    }

    fn catalog_block(m: &MemObjects, subject: &str, lifted_at: Option<i64>) {
        put(
            m,
            &format!("moderation/catalog-blocks/{subject}"),
            json!({"subject": subject, "reason": "r", "by": "op", "at": 1, "liftedAt": lifted_at}),
        );
    }

    fn owner(m: &MemObjects, hash: &str, subject: &str) {
        put(
            m,
            &format!("moderation/publishers/{hash}"),
            json!({"hash": hash, "subject": subject, "endpointId": "e", "at": 1}),
        );
    }

    fn requested(key: String) -> Requested {
        Requested {
            key,
            outcome: Outcome::Requested,
        }
    }

    fn keys(out: &[Requested]) -> Vec<String> {
        out.iter().map(|r| r.key.clone()).collect()
    }

    /// Every version under `deletion-requests/`: nothing written means none.
    async fn request_writes(m: &MemObjects) -> usize {
        m.list_versions("deletion-requests/").await.unwrap().len()
    }

    /// What the next sweep reads back: every record written must pass its
    /// strict read, or every later run aborts.
    async fn read_back(m: &MemObjects) -> snapshot::Requests {
        snapshot::read(m).await.unwrap().requests
    }

    fn operator(sub: &str, hash: &str, scope: Scope) -> OperatorRequest {
        OperatorRequest {
            hash: hash.to_string(),
            subject: sub.to_string(),
            requested_at: NOW,
            reason: WHY.to_string(),
            scope,
            state: State::Pending,
            deleted_at: None,
        }
    }

    fn subject(sub: &str) -> SubjectRequest {
        SubjectRequest {
            subject: sub.to_string(),
            requested_at: NOW,
            reason: WHY.to_string(),
            state: State::Pending,
            deleted_at: None,
        }
    }

    fn store_operator(m: &MemObjects, r: &OperatorRequest) {
        m.insert(
            &operator_key(&r.subject, &r.hash),
            serde_json::to_vec(r).unwrap(),
        );
    }

    #[tokio::test]
    async fn hash_requests_need_an_active_block() {
        let m = MemObjects::default();
        block(&m, &h("a1"), None);
        // A lifted block is no block.
        block(&m, &h("a2"), Some(5));
        let hashes = [h("a1"), h("a2")];

        let err = request_hashes(&m, U, &hashes, WHY, NOW)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(&h("a2")), "{err}");
        assert!(!err.contains(&h("a1")), "names the first unblocked: {err}");
        assert_eq!(request_writes(&m).await, 0, "nothing written");

        block(&m, &h("a2"), None);
        let out = request_hashes(&m, U, &hashes, WHY, NOW).await.unwrap();
        assert_eq!(
            out,
            [
                requested(operator_key(U, &h("a1"))),
                requested(operator_key(U, &h("a2")))
            ]
        );
        let back = read_back(&m).await;
        assert_eq!(back.operator.len(), 2);
        for hash in &hashes {
            assert_eq!(
                back.operator[&(U.to_string(), hash.clone())],
                operator(U, hash, Scope::Hash)
            );
        }
        assert!(back.subjects.is_empty());
    }

    #[tokio::test]
    async fn arguments_the_sweep_could_not_read_back_are_refused() {
        let m = MemObjects::default();
        block(&m, &h("a1"), None);
        catalog_block(&m, U, None);
        let ok = [h("a1")];
        let refused = |result: anyhow::Result<Vec<Requested>>, why: &str| {
            let err = result.unwrap_err().to_string();
            assert!(err.contains(why), "{err}, not {why}");
        };
        for (sub, hashes, reason, why) in [
            (U, vec!["A1".repeat(32)], WHY, "invalid hash"),
            (U, vec!["a1".repeat(31)], WHY, "invalid hash"),
            (U, vec![], WHY, "no hash"),
            ("a/b", ok.to_vec(), WHY, "invalid subject"),
            ("arkavo:", ok.to_vec(), WHY, "invalid subject"),
            ("arkavo:arkavo:u1", ok.to_vec(), WHY, "invalid subject"),
            (U, ok.to_vec(), "", "--reason"),
            (U, ok.to_vec(), "  \t", "--reason"),
        ] {
            refused(request_hashes(&m, sub, &hashes, reason, NOW).await, why);
        }
        for (sub, reason, why) in [
            ("a/b", WHY, "invalid subject"),
            ("arkavo:", WHY, "invalid subject"),
            ("arkavo:arkavo:u1", WHY, "invalid subject"),
            (U, " ", "--reason"),
        ] {
            refused(request_all(&m, sub, reason, NOW).await, why);
        }
        assert_eq!(request_writes(&m).await, 0, "nothing written");
    }

    #[tokio::test]
    async fn all_needs_an_active_catalog_block() {
        let m = MemObjects::default();
        publish_2(&m, U, 1, b"doc", &[&h("a1")]);
        assert!(request_all(&m, U, WHY, NOW).await.is_err(), "no block");

        // A lifted catalog block, or a hideCatalog suspension, is not one.
        catalog_block(&m, U, Some(5));
        put(
            &m,
            &format!("moderation/suspensions/{U}"),
            json!({"subject": U, "reason": "r", "hideCatalog": true, "by": "op", "at": 1}),
        );
        assert!(request_all(&m, U, WHY, NOW).await.is_err(), "lifted");
        // Another account's block isn't this one's.
        catalog_block(&m, U2, None);
        assert!(request_all(&m, U, WHY, NOW).await.is_err(), "another's");
        assert_eq!(request_writes(&m).await, 0, "nothing written");

        catalog_block(&m, U, None);
        let out = request_all(&m, U, WHY, NOW).await.unwrap();
        assert_eq!(
            out,
            [
                requested(operator_key(U, &h("a1"))),
                requested(subject_key(U))
            ]
        );
    }

    #[tokio::test]
    async fn all_covers_live_indexes_and_owner_records() {
        let m = MemObjects::default();
        let arkavo = format!("arkavo:{U}");
        // Both pointer keys of one account, one of them `/1`, and a
        // superseded index of the account, no longer live.
        publish_2(&m, &arkavo, 2, b"doc-a", &[&h("a2"), &h("a1")]);
        publish(&m, U, 1, b"doc-old", &[&h("e1")]);
        publish(&m, U, 2, b"doc-b", &[&h("a2"), &h("b1")]);
        // An owner record for a hash no live index lists.
        owner(&m, &h("c3"), U);
        owner(&m, &h("c4"), &arkavo);
        // Another account's recording, listed and owned.
        publish_2(&m, U2, 1, b"doc-u2", &[&h("d1")]);
        owner(&m, &h("d1"), U2);
        catalog_block(&m, U, None);

        let out = request_all(&m, U, WHY, NOW).await.unwrap();
        let mut expected: Vec<String> = ["a1", "a2", "b1", "c3", "c4"]
            .iter()
            .map(|b| operator_key(U, &h(b)))
            .collect();
        expected.push(subject_key(U));
        assert_eq!(keys(&out), expected, "deduped, sorted, subject last");
        assert!(out.iter().all(|r| r.outcome == Outcome::Requested));

        // `subjects/<sub>` is written after every `operator/` record.
        let versions = m.list_versions("deletion-requests/").await.unwrap();
        let order = |key: &str| {
            let v = versions.iter().find(|v| v.key == key).unwrap();
            v.version_id[1..].parse::<u64>().unwrap()
        };
        let last = order(&subject_key(U));
        assert!(expected[..5].iter().all(|k| order(k) < last));

        let back = read_back(&m).await;
        for b in ["a1", "a2", "b1", "c3", "c4"] {
            assert_eq!(
                back.operator[&(U.to_string(), h(b))],
                operator(U, &h(b), Scope::Subject)
            );
        }
        assert_eq!(back.operator.len(), 5);
        assert_eq!(back.subjects[U], subject(U));
    }

    #[tokio::test]
    async fn subjects_in_keys_are_canonical() {
        let m = MemObjects::default();
        let arkavo = format!("arkavo:{U}");
        block(&m, &h("a1"), None);
        catalog_block(&m, U, None);
        owner(&m, &h("a2"), U);

        let out = request_hashes(&m, &arkavo, &[h("a1")], WHY, NOW)
            .await
            .unwrap();
        assert_eq!(out, [requested(operator_key(U, &h("a1")))]);
        let out = request_all(&m, &arkavo, WHY, NOW).await.unwrap();
        assert_eq!(
            keys(&out),
            [operator_key(U, &h("a2")), subject_key(U)],
            "a1 is the hash request's; a2 is owned"
        );

        let back = read_back(&m).await;
        assert_eq!(
            back.operator[&(U.to_string(), h("a1"))],
            operator(U, &h("a1"), Scope::Hash)
        );
        assert_eq!(
            back.operator[&(U.to_string(), h("a2"))],
            operator(U, &h("a2"), Scope::Subject)
        );
        assert_eq!(back.subjects[U], subject(U));
        assert!(
            m.list("deletion-requests/")
                .await
                .unwrap()
                .iter()
                .all(|o| !o.key.contains("arkavo:")),
            "no key carries arkavo:"
        );
    }

    #[tokio::test]
    async fn a_pending_request_is_left_and_a_deleted_one_renewed() {
        let m = MemObjects::default();
        block(&m, &h("a1"), None);
        block(&m, &h("a2"), None);
        let pending = OperatorRequest {
            requested_at: 7,
            reason: "first".into(),
            ..operator(U, &h("a1"), Scope::Hash)
        };
        store_operator(&m, &pending);
        store_operator(
            &m,
            &OperatorRequest {
                requested_at: 7,
                reason: "first".into(),
                state: State::Deleted,
                deleted_at: Some(9),
                ..operator(U, &h("a2"), Scope::Hash)
            },
        );

        let out = request_hashes(&m, U, &[h("a2"), h("a1")], WHY, NOW)
            .await
            .unwrap();
        assert_eq!(
            out,
            [
                Requested {
                    key: operator_key(U, &h("a1")),
                    outcome: Outcome::Exists,
                },
                Requested {
                    key: operator_key(U, &h("a2")),
                    outcome: Outcome::Renewed,
                },
            ]
        );
        let back = read_back(&m).await;
        assert_eq!(back.operator[&(U.to_string(), h("a1"))], pending, "left");
        assert_eq!(
            back.operator[&(U.to_string(), h("a2"))],
            operator(U, &h("a2"), Scope::Hash),
            "a new pending request"
        );
        assert_eq!(
            m.list_versions(&operator_key(U, &h("a1")))
                .await
                .unwrap()
                .len(),
            1,
            "not rewritten"
        );

        // The same for `subjects/<sub>`.
        catalog_block(&m, U, None);
        let first = SubjectRequest {
            requested_at: 7,
            ..subject(U)
        };
        m.insert(&subject_key(U), serde_json::to_vec(&first).unwrap());
        let out = request_all(&m, U, WHY, NOW).await.unwrap();
        assert_eq!(
            out.last().unwrap(),
            &Requested {
                key: subject_key(U),
                outcome: Outcome::Exists,
            }
        );
        assert_eq!(read_back(&m).await.subjects[U], first);

        let tombstone = SubjectRequest {
            state: State::Deleted,
            deleted_at: Some(9),
            ..first
        };
        m.insert(&subject_key(U), serde_json::to_vec(&tombstone).unwrap());
        let out = request_all(&m, U, WHY, NOW).await.unwrap();
        assert_eq!(out.last().unwrap().outcome, Outcome::Renewed);
        assert_eq!(read_back(&m).await.subjects[U], subject(U));
    }

    /// One key holds one operator request, of either scope. A pending one
    /// of the other scope is rewritten when its own scope can't delete the
    /// hash and the requested one can: scope `subject` keeps a blocked
    /// hash (moderation's exception), and scope `hash` keeps one whose
    /// block was lifted.
    #[tokio::test]
    async fn a_pending_request_of_the_scope_that_cannot_delete_is_rewritten() {
        let m = MemObjects::default();
        catalog_block(&m, U, None);
        owner(&m, &h("a1"), U);
        owner(&m, &h("a2"), U);
        owner(&m, &h("a3"), U);
        // `--all` first: scope `subject` for every owned hash.
        request_all(&m, U, WHY, NOW).await.unwrap();

        // a1 is blocked: `--hash` makes it scope `hash`, which deletes it.
        block(&m, &h("a1"), None);
        let out = request_hashes(&m, U, &[h("a1")], "takedown", NOW + 1)
            .await
            .unwrap();
        assert_eq!(
            out,
            [Requested {
                key: operator_key(U, &h("a1")),
                outcome: Outcome::Rescoped,
            }]
        );
        let back = read_back(&m).await;
        assert_eq!(
            back.operator[&(U.to_string(), h("a1"))],
            OperatorRequest {
                requested_at: NOW + 1,
                reason: "takedown".into(),
                ..operator(U, &h("a1"), Scope::Hash)
            }
        );

        // `--all` again: a1's scope `hash` still deletes it, so it stays.
        // a2 gets a scope-`hash` request whose block is then lifted:
        // `--all` makes it scope `subject` again.
        block(&m, &h("a2"), None);
        request_hashes(&m, U, &[h("a2")], "takedown", NOW + 1)
            .await
            .unwrap();
        block(&m, &h("a2"), Some(NOW + 2));
        let out = request_all(&m, U, WHY, NOW + 3).await.unwrap();
        let outcome = |b: &str| {
            out.iter()
                .find(|r| r.key == operator_key(U, &h(b)))
                .unwrap()
                .outcome
        };
        assert_eq!(outcome("a1"), Outcome::Exists);
        assert_eq!(outcome("a2"), Outcome::Rescoped);
        assert_eq!(outcome("a3"), Outcome::Exists);
        let back = read_back(&m).await;
        assert_eq!(back.operator[&(U.to_string(), h("a1"))].scope, Scope::Hash);
        assert_eq!(
            back.operator[&(U.to_string(), h("a2"))],
            OperatorRequest {
                requested_at: NOW + 3,
                ..operator(U, &h("a2"), Scope::Subject)
            }
        );
        assert_eq!(back.operator[&(U.to_string(), h("a3"))].requested_at, NOW);
    }

    #[tokio::test]
    async fn an_unreadable_record_writes_nothing() {
        let m = MemObjects::default();
        block(&m, &h("a1"), None);
        catalog_block(&m, U, None);
        owner(&m, &h("a1"), U);
        let bad = operator_key(U2, &h("b1"));
        m.insert(&bad, "not a request");
        for result in [
            request_hashes(&m, U, &[h("a1")], WHY, NOW).await,
            request_all(&m, U, WHY, NOW).await,
        ] {
            let err = format!("{:#}", result.unwrap_err());
            assert!(err.contains(&bad), "names the record: {err}");
        }
        assert_eq!(request_writes(&m).await, 1, "only the unreadable one");
    }

    #[tokio::test]
    async fn duplicate_hashes_are_one_request() {
        let m = MemObjects::default();
        block(&m, &h("a2"), None);
        block(&m, &h("a1"), None);
        let out = request_hashes(&m, U, &[h("a2"), h("a1"), h("a2")], WHY, NOW)
            .await
            .unwrap();
        assert_eq!(
            keys(&out),
            [operator_key(U, &h("a1")), operator_key(U, &h("a2"))]
        );
        assert_eq!(request_writes(&m).await, 2);
    }
}
