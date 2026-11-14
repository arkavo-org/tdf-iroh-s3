//! The sweep's strict read (spec 3.4 step 1): every pointer, index record,
//! transition and deletion request, and the moderation records the sweep
//! decides on (suspensions, blocks, catalog blocks and owner records).
//! Unlike the node's moderation loader, which skips what it can't parse,
//! anything listed that can't be read or parsed, whose key isn't the
//! layout, or whose body names something other than its key, fails the
//! read with an error naming the key. So the sweep never decides on part
//! of the bucket, and writes nothing. Publish sessions and audit records
//! are never read.

use anyhow::Context;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::{
    ENVELOPE_OBJECTS, ENVELOPES, EnvelopeRequest, OPERATOR, OperatorRequest, RECORDINGS,
    RecordingRequest, SUBJECTS, State, SubjectRequest, TRANSITIONS, Transition, transition_name,
};
use crate::catalog_scan::{self, Catalogs};
use crate::creator_catalog::{is_lower_hex_hash, object_from_slice};
use crate::moderation::{
    BLOCKS, Block, CATALOG_BLOCKS, CatalogBlock, SUSPENSIONS, Suspension, canonical_subject,
    valid_subject,
};
use crate::object_store::{ObjectInfo, ObjectStore, bodies};
use crate::ownership::{PUBLISHERS, parse_owner};

/// Everything the sweep decides on, as one run read it.
#[derive(Debug, Default)]
pub struct Snapshot {
    /// Every pointer and every index record.
    pub catalogs: Catalogs,
    /// Every transition, by its full key: `catalog-transitions/<sub>/<name>`
    /// ([`super::transition_key`]), `<sub>` the pointer key's.
    pub transitions: BTreeMap<String, Transition>,
    pub requests: Requests,
    /// When each request record's current version was written, by its
    /// full key (`deletion-requests/...`): S3's `LastModified`, Unix
    /// seconds. A tombstone's is when its item was deleted, on S3's clock,
    /// which tombstone verification measures from (spec 3.4 step 7).
    pub request_written: BTreeMap<String, i64>,
    pub moderation: ModerationView,
    /// Each owner record (`moderation/publishers/<hash>`): hash → its
    /// subject, canonical.
    pub owners: HashMap<String, String>,
    /// Every catalog hash with an object under `catalog-documents/`,
    /// `catalog-outboards/` or `catalog-indexes/`.
    pub envelope_objects: BTreeSet<String>,
}

/// Every deletion request, by the names in its key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Requests {
    /// `recordings/<sub>/<hash>`, by `(sub, hash)`; `sub` canonical.
    pub recordings: BTreeMap<(String, String), RecordingRequest>,
    /// `envelopes/<hash>`, by hash.
    pub envelopes: BTreeMap<String, EnvelopeRequest>,
    /// `operator/<sub>/<hash>`, by `(sub, hash)`; `sub` canonical.
    pub operator: BTreeMap<(String, String), OperatorRequest>,
    /// `subjects/<sub>`, by `sub`, canonical.
    pub subjects: BTreeMap<String, SubjectRequest>,
}

/// The moderation records the sweep decides on. Only active records
/// (no `liftedAt`) count; a lifted record stays stored with `liftedAt` set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModerationView {
    /// Hashes with an active block, lowercase.
    pub blocked: HashSet<String>,
    /// Canonical subjects with an active catalog block.
    pub catalog_blocked: HashSet<String>,
    /// Canonical subjects whose catalog is hidden: an active catalog block,
    /// or an active suspension with `hideCatalog`.
    pub hidden: HashSet<String>,
    /// Canonical subjects with an active suspension, `hideCatalog` or not.
    pub suspended: HashSet<String>,
}

/// Read everything the sweep decides on, strictly (see the module doc).
/// `Err` names the first key that is unreadable, malformed, or vanished
/// between its listing and its read; [`catalog_scan::scan`]'s rules apply
/// to pointers and index records.
pub async fn read<O: ObjectStore>(store: &O) -> anyhow::Result<Snapshot> {
    // The order matters, because a publish writes its index record, its
    // transition, its document and outboard, and only then its pointer:
    // whatever a pointer names was written before it.
    // - pointers before transitions, so the transition of every pointer
    //   read is listed too. The other way round, a publish landing between
    //   the two reads would leave its pointer's walk with no first step,
    //   and the older transitions it reaches would look unreachable;
    // - pointers before index records (`catalog_scan::scan`), so every `/2`
    //   pointer read finds the index record it signed;
    // - envelope objects before pointers, so a publish in flight lists an
    //   envelope object (its index record is the first) that no pointer
    //   read names only when its writes span the pointer read.
    let envelope_objects = envelope_objects(store).await?;
    let catalogs = catalog_scan::scan(store).await?;
    let transitions = transitions(store).await?;
    let (requests, request_written) = requests(store).await?;
    let moderation = moderation(store).await?;
    let owners = owners(store).await?;
    Ok(Snapshot {
        catalogs,
        transitions,
        requests,
        request_written,
        moderation,
        owners,
        envelope_objects,
    })
}

async fn envelope_objects<O: ObjectStore>(store: &O) -> anyhow::Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    for prefix in ENVELOPE_OBJECTS {
        for listed in store
            .list(prefix)
            .await
            .with_context(|| format!("listing {prefix} failed"))?
        {
            let key = listed.key;
            let hash = names(&key, prefix)
                .and_then(|[name]| lower_hex(name))
                .with_context(|| format!("{key} unreadable"))?;
            hashes.insert(hash.to_string());
        }
    }
    Ok(hashes)
}

async fn transitions<O: ObjectStore>(store: &O) -> anyhow::Result<BTreeMap<String, Transition>> {
    let mut transitions = BTreeMap::new();
    for (ObjectInfo { key, .. }, body) in bodies(store, TRANSITIONS).await? {
        let transition = transition(&key, &body).with_context(|| format!("{key} unreadable"))?;
        transitions.insert(key, transition);
    }
    Ok(transitions)
}

/// A transition, named for its own subject (byte for byte), `seq` and
/// pointer digest, with lowercase hex hashes throughout.
fn transition(key: &str, body: &[u8]) -> anyhow::Result<Transition> {
    let [sub, name] = names(key, TRANSITIONS)?;
    anyhow::ensure!(valid_subject(sub), "{sub} is not a subject");
    let t: Transition = object_from_slice(body)?;
    same("subject", &t.subject, sub)?;
    same("name", &transition_name(t.seq, &t.pointer), name)?;
    let base = t.base.iter().flat_map(|b| [&b.catalog_hash, &b.pointer]);
    for hash in [&t.catalog_hash, &t.pointer]
        .into_iter()
        .chain(base)
        .chain(&t.dropped)
        .chain(&t.added)
    {
        lower_hex(hash)?;
    }
    Ok(t)
}

/// Every request, and when each record was written, by key.
async fn requests<O: ObjectStore>(store: &O) -> anyhow::Result<(Requests, BTreeMap<String, i64>)> {
    let mut requests = Requests::default();
    let mut written = BTreeMap::new();
    for (ObjectInfo { key, modified }, body) in bodies(store, RECORDINGS).await? {
        let (names, request) =
            recording(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.recordings.insert(names, request);
        written.insert(key, modified);
    }
    for (ObjectInfo { key, modified }, body) in bodies(store, ENVELOPES).await? {
        let (hash, request) = envelope(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.envelopes.insert(hash, request);
        written.insert(key, modified);
    }
    for (ObjectInfo { key, modified }, body) in bodies(store, OPERATOR).await? {
        let (names, request) =
            operator(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.operator.insert(names, request);
        written.insert(key, modified);
    }
    for (ObjectInfo { key, modified }, body) in bodies(store, SUBJECTS).await? {
        let (sub, request) = subject(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.subjects.insert(sub, request);
        written.insert(key, modified);
    }
    Ok((requests, written))
}

fn recording(key: &str, body: &[u8]) -> anyhow::Result<((String, String), RecordingRequest)> {
    let [sub, hash] = names(key, RECORDINGS)?;
    let (sub, hash) = (canonical(sub)?, lower_hex(hash)?);
    let r: RecordingRequest = object_from_slice(body)?;
    same("subject", &r.subject, sub)?;
    same("hash", &r.hash, hash)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok(((sub.to_string(), hash.to_string()), r))
}

fn envelope(key: &str, body: &[u8]) -> anyhow::Result<(String, EnvelopeRequest)> {
    let [hash] = names(key, ENVELOPES)?;
    let hash = lower_hex(hash)?;
    let r: EnvelopeRequest = object_from_slice(body)?;
    same("hash", &r.hash, hash)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok((hash.to_string(), r))
}

fn operator(key: &str, body: &[u8]) -> anyhow::Result<((String, String), OperatorRequest)> {
    let [sub, hash] = names(key, OPERATOR)?;
    let (sub, hash) = (canonical(sub)?, lower_hex(hash)?);
    let r: OperatorRequest = object_from_slice(body)?;
    same("subject", &r.subject, sub)?;
    same("hash", &r.hash, hash)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok(((sub.to_string(), hash.to_string()), r))
}

fn subject(key: &str, body: &[u8]) -> anyhow::Result<(String, SubjectRequest)> {
    let [sub] = names(key, SUBJECTS)?;
    let sub = canonical(sub)?;
    let r: SubjectRequest = object_from_slice(body)?;
    same("subject", &r.subject, sub)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok((sub.to_string(), r))
}

/// Suspensions, blocks and catalog blocks, through the node's own record
/// types; active ones make the view. Their keys are what the node writes:
/// a suspension's and a catalog block's a canonical subject, a block's a
/// lowercase hash. Any other key fails the read: the node looks records
/// up by canonical subject and lowercase hash, so one named otherwise has
/// no effect there, and the sweep must not decide on it either.
async fn moderation<O: ObjectStore>(store: &O) -> anyhow::Result<ModerationView> {
    let mut view = ModerationView::default();
    for (ObjectInfo { key, .. }, body) in bodies(store, &moderation_prefix(SUSPENSIONS)).await? {
        let s = moderation_record::<Suspension>(&key, &body, SUSPENSIONS, SUBJECT, |s| &s.subject)?;
        // Active as the publish gate has it (`Moderation::reload`): no
        // `liftedAt`. A suspension has no expiry.
        if s.lifted_at.is_none() {
            if s.hide_catalog {
                view.hidden.insert(s.subject.clone());
            }
            view.suspended.insert(s.subject);
        }
    }
    for (ObjectInfo { key, .. }, body) in bodies(store, &moderation_prefix(BLOCKS)).await? {
        let b = moderation_record::<Block>(&key, &body, BLOCKS, HASH, |b| &b.hash)?;
        if b.lifted_at.is_none() {
            view.blocked.insert(b.hash);
        }
    }
    for (ObjectInfo { key, .. }, body) in bodies(store, &moderation_prefix(CATALOG_BLOCKS)).await? {
        let b = moderation_record::<CatalogBlock>(&key, &body, CATALOG_BLOCKS, SUBJECT, |b| {
            &b.subject
        })?;
        if b.lifted_at.is_none() {
            view.catalog_blocked.insert(b.subject.clone());
            view.hidden.insert(b.subject);
        }
    }
    Ok(view)
}

/// A moderation key's name: what the body names it, and how it must read.
type Name = (&'static str, fn(&str) -> anyhow::Result<&str>);
const SUBJECT: Name = ("subject", canonical);
const HASH: Name = ("hash", lower_hex);

/// `moderation/<kind>/<name>`, with `name` as `valid` has it (a canonical
/// subject, a lowercase hash), whose body's `what` (`name_of`) is `name`.
fn moderation_record<T: DeserializeOwned>(
    key: &str,
    body: &[u8],
    kind: &str,
    (what, valid): Name,
    name_of: fn(&T) -> &String,
) -> anyhow::Result<T> {
    let parse = || {
        let [name] = names(key, &moderation_prefix(kind))?;
        let name = valid(name)?;
        let record: T = object_from_slice(body)?;
        same(what, name_of(&record), name)?;
        anyhow::Ok(record)
    };
    parse().with_context(|| format!("{key} unreadable"))
}

/// Owner records, through [`parse_owner`]: hash → canonical subject.
async fn owners<O: ObjectStore>(store: &O) -> anyhow::Result<HashMap<String, String>> {
    let mut owners = HashMap::new();
    for (ObjectInfo { key, .. }, body) in bodies(store, &moderation_prefix(PUBLISHERS)).await? {
        let parse = || {
            let [hash] = names(&key, &moderation_prefix(PUBLISHERS))?;
            let owner = parse_owner(lower_hex(hash)?, &body)?;
            anyhow::Ok((owner.hash, canonical_subject(&owner.subject).to_string()))
        };
        let (hash, subject) = parse().with_context(|| format!("{key} unreadable"))?;
        owners.insert(hash, subject);
    }
    Ok(owners)
}

fn moderation_prefix(kind: &str) -> String {
    format!("moderation/{kind}/")
}

/// The `N` names after `prefix` in a listed `key`: exactly `N`, none empty.
fn names<'a, const N: usize>(key: &'a str, prefix: &str) -> anyhow::Result<[&'a str; N]> {
    let rest = key
        .strip_prefix(prefix)
        .with_context(|| format!("listed under {prefix}"))?;
    let names: [&str; N] = rest
        .split('/')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| anyhow::anyhow!("not {N} names after {prefix}"))?;
    anyhow::ensure!(
        names.iter().all(|name| !name.is_empty()),
        "an empty name after {prefix}"
    );
    Ok(names)
}

/// A request key's subject: valid, and already canonical.
fn canonical(sub: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(
        valid_subject(sub) && canonical_subject(sub) == sub,
        "{sub} is not a canonical subject"
    );
    Ok(sub)
}

fn lower_hex(hash: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(
        is_lower_hex_hash(hash),
        "{hash} is not 64 lowercase hex characters"
    );
    Ok(hash)
}

/// The body's `what` is the key's.
fn same(what: &str, body: &str, key: &str) -> anyhow::Result<()> {
    anyhow::ensure!(body == key, "its {what} {body} is not the key's {key}");
    Ok(())
}

/// A tombstone carries `deletedAt`: re-folding a drop over it (call 9)
/// needs it. Verifying it (spec 3.4 step 7) measures from the record's
/// own write time instead ([`Snapshot::request_written`]).
fn tombstone_dated(state: State, deleted_at: Option<i64>) -> anyhow::Result<()> {
    anyhow::ensure!(
        state != State::Deleted || deleted_at.is_some(),
        "deleted without deletedAt"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_scan::test_support::publish_2;
    use crate::deletion::{
        Transition, envelope_key, operator_key, recording_key, subject_key, transition_key,
        transition_name,
    };
    use crate::object_store::mem::{MemObjects, Op};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    const U: &str = "550e8400-e29b-41d4-a716-446655440000";
    const U2: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    fn put(m: &MemObjects, key: &str, body: serde_json::Value) {
        m.insert(key, serde_json::to_vec(&body).unwrap());
    }

    fn transition(subject: &str, seq: u64, digest: &str) -> Transition {
        Transition {
            subject: subject.into(),
            seq,
            catalog_hash: h("c0"),
            pointer: digest.into(),
            base: None,
            at: 10,
            dropped: vec![h("aa")],
            added: vec![h("ab")],
        }
    }

    fn suspension(subject: &str, hide_catalog: bool, lifted_at: Option<i64>) -> serde_json::Value {
        json!({"subject": subject, "reason": "r", "hideCatalog": hide_catalog, "by": "op",
               "at": 1, "liftedAt": lifted_at})
    }

    fn block(hash: &str, lifted_at: Option<i64>) -> serde_json::Value {
        json!({"hash": hash, "reason": "r", "by": "op", "at": 1, "liftedAt": lifted_at})
    }

    fn catalog_block(subject: &str, lifted_at: Option<i64>) -> serde_json::Value {
        json!({"subject": subject, "reason": "r", "by": "op", "at": 1, "liftedAt": lifted_at})
    }

    fn owner(hash: &str, subject: &str) -> serde_json::Value {
        json!({"hash": hash, "subject": subject, "endpointId": "e", "at": 1})
    }

    fn doc() -> String {
        blake3::hash(b"doc").to_hex().to_string()
    }

    /// A bucket holding a readable record of every kind the snapshot reads.
    fn populated() -> MemObjects {
        let m = MemObjects::default();
        let arkavo = format!("arkavo:{U}");
        publish_2(&m, &arkavo, 2, b"doc", &[&h("aa")]);
        m.insert_with_owner(&format!("catalog-documents/{}", doc()), "doc", &arkavo);
        m.insert(&format!("catalog-outboards/{}", h("e1")), "");

        let name = transition_name(2, &h("d2"));
        m.insert(
            &transition_key(&arkavo, &name),
            serde_json::to_vec(&transition(&arkavo, 2, &h("d2"))).unwrap(),
        );

        // The requests are written at 7.
        m.set_now(7);
        put(
            &m,
            &recording_key(U, &h("aa")),
            json!({"hash": h("aa"), "subject": U, "requestedAt": 10, "seq": 2,
                   "state": "pending"}),
        );
        put(
            &m,
            &envelope_key(&h("e1")),
            json!({"hash": h("e1"), "supersededAt": 10, "source": "observed",
                   "state": "pending"}),
        );
        put(
            &m,
            &operator_key("u2", &h("b1")),
            json!({"hash": h("b1"), "subject": "u2", "requestedAt": 10, "reason": "r",
                   "scope": "hash", "state": "deleted", "deletedAt": 20}),
        );
        put(
            &m,
            &subject_key("c1"),
            json!({"subject": "c1", "requestedAt": 10, "reason": "r", "state": "pending"}),
        );

        put(
            &m,
            "moderation/suspensions/s1",
            suspension("s1", true, None),
        );
        put(
            &m,
            "moderation/suspensions/s2",
            suspension("s2", false, None),
        );
        put(
            &m,
            "moderation/suspensions/s3",
            suspension("s3", true, Some(5)),
        );
        put(
            &m,
            &format!("moderation/suspensions/{U2}"),
            suspension(U2, true, None),
        );
        put(
            &m,
            &format!("moderation/blocks/{}", h("b1")),
            block(&h("b1"), None),
        );
        put(
            &m,
            &format!("moderation/blocks/{}", h("b2")),
            block(&h("b2"), Some(5)),
        );
        put(
            &m,
            "moderation/catalog-blocks/c1",
            catalog_block("c1", None),
        );
        put(
            &m,
            "moderation/catalog-blocks/c2",
            catalog_block("c2", Some(5)),
        );
        put(
            &m,
            &format!("moderation/publishers/{}", h("aa")),
            owner(&h("aa"), &arkavo),
        );
        m
    }

    #[tokio::test]
    async fn read_builds_the_view() {
        let snapshot = read(&populated()).await.unwrap();
        let view = &snapshot.moderation;
        assert_eq!(view.blocked, HashSet::from([h("b1")]), "active blocks only");
        assert_eq!(view.catalog_blocked, HashSet::from(["c1".to_string()]));
        assert_eq!(
            view.hidden,
            HashSet::from(["c1".to_string(), "s1".to_string(), U2.to_string()]),
            "active catalog blocks and hideCatalog suspensions"
        );
        assert_eq!(
            view.suspended,
            HashSet::from(["s1".to_string(), "s2".to_string(), U2.to_string()]),
            "active suspensions, hideCatalog or not"
        );

        assert_eq!(
            snapshot.owners,
            HashMap::from([(h("aa"), U.to_string())]),
            "canonical"
        );
        assert_eq!(snapshot.envelope_objects, BTreeSet::from([doc(), h("e1")]));

        let arkavo = format!("arkavo:{U}");
        let key = transition_key(&arkavo, &transition_name(2, &h("d2")));
        assert_eq!(
            snapshot.transitions.keys().collect::<Vec<_>>(),
            [&key],
            "keyed by the full key"
        );
        assert_eq!(snapshot.transitions[&key], transition(&arkavo, 2, &h("d2")));

        let requests = &snapshot.requests;
        assert_eq!(
            requests.recordings.keys().collect::<Vec<_>>(),
            [&(U.to_string(), h("aa"))]
        );
        assert_eq!(requests.recordings[&(U.to_string(), h("aa"))].seq, 2);
        assert_eq!(requests.envelopes.keys().collect::<Vec<_>>(), [&h("e1")]);
        assert_eq!(
            requests.operator.keys().collect::<Vec<_>>(),
            [&("u2".to_string(), h("b1"))]
        );
        assert_eq!(
            requests.operator[&("u2".to_string(), h("b1"))].deleted_at,
            Some(20)
        );
        assert_eq!(requests.subjects.keys().collect::<Vec<_>>(), ["c1"]);
        assert_eq!(
            snapshot.request_written,
            BTreeMap::from([
                (recording_key(U, &h("aa")), 7),
                (envelope_key(&h("e1")), 7),
                (operator_key("u2", &h("b1")), 7),
                (subject_key("c1"), 7),
            ]),
            "each request record's write time, by key"
        );

        assert_eq!(snapshot.catalogs.pointers.len(), 1);
        assert_eq!(snapshot.catalogs.pointers[0].subject, U);
    }

    #[tokio::test]
    async fn read_aborts_on_anything_unreadable() {
        assert!(read(&populated()).await.is_ok());
        let keys = [
            transition_key("u1", &transition_name(1, &h("d1"))),
            recording_key("u1", &h("aa")),
            envelope_key(&h("aa")),
            operator_key("u1", &h("aa")),
            subject_key("u1"),
            "moderation/suspensions/u1".to_string(),
            format!("moderation/blocks/{}", h("aa")),
            "moderation/catalog-blocks/u1".to_string(),
            format!("moderation/publishers/{}", h("ab")),
            "catalog-pointers/u1".to_string(),
        ];
        for key in keys {
            for body in ["not json", "{}"] {
                let m = populated();
                m.insert(&key, body);
                let err = read(&m).await.expect_err(&key).to_string();
                assert!(err.contains(&key), "{key} ({body}): {err}");
            }
        }
    }

    /// Every record the snapshot reads is a JSON object: the same values as
    /// an array, which a derived struct also reads, are unreadable.
    #[tokio::test]
    async fn read_refuses_records_as_arrays() {
        use crate::creator_catalog::test_support::array_form;
        use crate::deletion::{
            EnvelopeRequest, OperatorRequest, RecordingRequest, Scope, Source, State,
            SubjectRequest, TransitionBase,
        };
        use crate::moderation::{BlobOwner, Block, CatalogBlock, Suspension};
        let arkavo = format!("arkavo:{U}");
        let transition_at = transition_key(&arkavo, &transition_name(2, &h("d2")));
        let mut based = transition(&arkavo, 2, &h("d2"));
        based.base = Some(TransitionBase {
            seq: 1,
            catalog_hash: h("c0"),
            pointer: h("d1"),
        });
        let cases: Vec<(String, Vec<u8>)> = vec![
            (
                transition_at.clone(),
                serde_json::to_vec(&transition(&arkavo, 2, &h("d2"))).unwrap(),
            ),
            (transition_at.clone(), serde_json::to_vec(&based).unwrap()),
            (
                recording_key(U, &h("aa")),
                serde_json::to_vec(&RecordingRequest {
                    hash: h("aa"),
                    subject: U.into(),
                    requested_at: 10,
                    seq: 2,
                    state: State::Pending,
                    deleted_at: None,
                })
                .unwrap(),
            ),
            (
                envelope_key(&h("e1")),
                serde_json::to_vec(&EnvelopeRequest {
                    hash: h("e1"),
                    owner: Some(arkavo.clone()),
                    superseded_at: 10,
                    source: Source::Observed,
                    state: State::Pending,
                    deleted_at: None,
                })
                .unwrap(),
            ),
            (
                operator_key("u2", &h("b1")),
                serde_json::to_vec(&OperatorRequest {
                    hash: h("b1"),
                    subject: "u2".into(),
                    requested_at: 10,
                    reason: "r".into(),
                    scope: Scope::Hash,
                    state: State::Deleted,
                    deleted_at: Some(20),
                })
                .unwrap(),
            ),
            (
                subject_key("c1"),
                serde_json::to_vec(&SubjectRequest {
                    subject: "c1".into(),
                    requested_at: 10,
                    reason: "r".into(),
                    state: State::Pending,
                    deleted_at: None,
                })
                .unwrap(),
            ),
            (
                "moderation/suspensions/s1".into(),
                serde_json::to_vec(&Suspension {
                    subject: "s1".into(),
                    reason: "r".into(),
                    report_id: None,
                    hide_catalog: true,
                    by: "op".into(),
                    at: 1,
                    lifted_by: None,
                    lifted_at: None,
                })
                .unwrap(),
            ),
            (
                format!("moderation/blocks/{}", h("b1")),
                serde_json::to_vec(&Block {
                    hash: h("b1"),
                    reason: "r".into(),
                    report_id: None,
                    by: "op".into(),
                    at: 1,
                    lifted_by: None,
                    lifted_at: None,
                })
                .unwrap(),
            ),
            (
                "moderation/catalog-blocks/c1".into(),
                serde_json::to_vec(&CatalogBlock {
                    subject: "c1".into(),
                    reason: "r".into(),
                    report_id: None,
                    by: "op".into(),
                    at: 1,
                    lifted_by: None,
                    lifted_at: None,
                })
                .unwrap(),
            ),
            (
                format!("moderation/publishers/{}", h("aa")),
                serde_json::to_vec(&BlobOwner {
                    hash: h("aa"),
                    subject: arkavo.clone(),
                    endpoint_id: "e".into(),
                    at: 1,
                })
                .unwrap(),
            ),
        ];
        for (key, good) in cases {
            let m = populated();
            m.insert(&key, good.clone());
            read(&m)
                .await
                .unwrap_or_else(|e| panic!("{key} as an object: {e:#}"));
            m.insert(&key, array_form(&good));
            let e = read(&m).await.expect_err(&key);
            assert!(
                format!("{e:#}").contains("expected a JSON object"),
                "{key}: {e:#}"
            );
        }

        // A transition's base, inside an object.
        let mut nested = serde_json::to_value(&based).unwrap();
        nested["base"] = json!([1, h("c0"), h("d1")]);
        let m = populated();
        m.insert(&transition_at, serde_json::to_vec(&nested).unwrap());
        let e = read(&m).await.expect_err("base as an array");
        assert!(format!("{e:#}").contains("expected a JSON object"), "{e:#}");
    }

    /// Keys that aren't the layout, and records that can't be what they
    /// claim, are unreadable too.
    #[tokio::test]
    async fn read_refuses_malformed_keys_and_records() {
        let arkavo = format!("arkavo:{U}");
        let pending = |subject: &str, hash: &str| {
            json!({"hash": hash, "subject": subject, "requestedAt": 1, "seq": 1,
                   "state": "pending"})
        };
        let mut uppercase = transition("u1", 1, &h("d1"));
        uppercase.dropped = vec![h("AA")];
        let cases: Vec<(String, serde_json::Value)> = vec![
            // Request keys carry canonical subjects.
            (recording_key(&arkavo, &h("aa")), pending(&arkavo, &h("aa"))),
            (
                operator_key(&arkavo, &h("aa")),
                json!({"hash": h("aa"), "subject": arkavo, "requestedAt": 1, "reason": "r",
                       "scope": "hash", "state": "pending"}),
            ),
            (
                subject_key(&arkavo),
                json!({"subject": arkavo, "requestedAt": 1, "reason": "r",
                       "state": "pending"}),
            ),
            // Hashes in keys are lowercase hex.
            (
                envelope_key("not-a-hash"),
                json!({"hash": "not-a-hash", "supersededAt": 1, "source": "observed",
                       "state": "pending"}),
            ),
            (recording_key("u1", &h("AA")), pending("u1", &h("AA"))),
            // Exactly the layout's names.
            (
                format!("{}/extra", subject_key("u1")),
                json!({"subject": "u1", "requestedAt": 1, "reason": "r", "state": "pending"}),
            ),
            (
                "deletion-requests/recordings/u1".to_string(),
                pending("u1", &h("aa")),
            ),
            // A deleted record says when.
            (
                recording_key("u1", &h("aa")),
                json!({"hash": h("aa"), "subject": "u1", "requestedAt": 1, "seq": 1,
                       "state": "deleted"}),
            ),
            (
                envelope_key(&h("aa")),
                json!({"hash": h("aa"), "supersededAt": 1, "source": "observed",
                       "state": "deleted"}),
            ),
            (
                operator_key("u1", &h("aa")),
                json!({"hash": h("aa"), "subject": "u1", "requestedAt": 1, "reason": "r",
                       "scope": "subject", "state": "deleted"}),
            ),
            (
                subject_key("u1"),
                json!({"subject": "u1", "requestedAt": 1, "reason": "r", "state": "deleted"}),
            ),
            // A transition is named for its own subject, seq and pointer, and
            // carries lowercase hashes.
            (
                "catalog-transitions/u1".to_string(),
                serde_json::to_value(transition("u1", 1, &h("d1"))).unwrap(),
            ),
            (
                transition_key("u1", &transition_name(9, &h("d1"))),
                serde_json::to_value(transition("u1", 1, &h("d1"))).unwrap(),
            ),
            (
                transition_key("u1", &transition_name(1, &h("d1"))),
                serde_json::to_value(transition("u2", 1, &h("d1"))).unwrap(),
            ),
            (
                transition_key("u1", &transition_name(1, &h("d1"))),
                serde_json::to_value(uppercase).unwrap(),
            ),
            // Moderation keys are canonical subjects and lowercase hashes,
            // even when the body names exactly what the key names.
            (
                format!("moderation/suspensions/{arkavo}"),
                suspension(&arkavo, true, None),
            ),
            (
                format!("moderation/catalog-blocks/{arkavo}"),
                catalog_block(&arkavo, None),
            ),
            (
                "moderation/suspensions/a..b".to_string(),
                suspension("a..b", true, None),
            ),
            (
                format!("moderation/blocks/{}", h("B3")),
                block(&h("B3"), None),
            ),
            (
                "moderation/blocks/not-a-hash".to_string(),
                block("not-a-hash", None),
            ),
            (
                format!("moderation/blocks/{}", h("b")),
                block(&h("b"), None),
            ),
            // A moderation record names what its key names.
            (
                "moderation/suspensions/u1".to_string(),
                suspension("u2", true, None),
            ),
            (
                format!("moderation/blocks/{}", h("aa")),
                block(&h("ab"), None),
            ),
            (
                "moderation/catalog-blocks/u1".to_string(),
                catalog_block("u2", None),
            ),
            (
                format!("moderation/publishers/{}", h("ab")),
                owner(&h("ac"), "u1"),
            ),
            (
                "moderation/publishers/not-a-hash".to_string(),
                owner("not-a-hash", "u1"),
            ),
            // No empty names, as a console folder marker would have.
            (
                "moderation/catalog-blocks/".to_string(),
                catalog_block("", None),
            ),
            // Envelope objects are listed only, by catalog hash.
            (format!("catalog-documents/{}", "not-a-hash"), json!({})),
            (format!("catalog-outboards/{}", h("AB")), json!({})),
        ];
        for (key, body) in cases {
            let m = populated();
            put(&m, &key, body);
            let err = read(&m).await.expect_err(&key).to_string();
            assert!(err.contains(&key), "{key}: {err}");
        }
    }

    #[tokio::test]
    async fn a_request_key_must_match_its_body() {
        let cases = [
            (
                recording_key("u1", &h("aa")),
                json!({"hash": h("aa"), "subject": "u2", "requestedAt": 1, "seq": 1,
                       "state": "pending"}),
            ),
            (
                recording_key("u1", &h("aa")),
                json!({"hash": h("ab"), "subject": "u1", "requestedAt": 1, "seq": 1,
                       "state": "pending"}),
            ),
            (
                envelope_key(&h("aa")),
                json!({"hash": h("ab"), "supersededAt": 1, "source": "observed",
                       "state": "pending"}),
            ),
            (
                operator_key("u1", &h("aa")),
                json!({"hash": h("aa"), "subject": "u2", "requestedAt": 1, "reason": "r",
                       "scope": "hash", "state": "pending"}),
            ),
            (
                operator_key("u1", &h("aa")),
                json!({"hash": h("ab"), "subject": "u1", "requestedAt": 1, "reason": "r",
                       "scope": "hash", "state": "pending"}),
            ),
            (
                subject_key("u1"),
                json!({"subject": "u2", "requestedAt": 1, "reason": "r", "state": "pending"}),
            ),
        ];
        for (key, body) in cases {
            let m = populated();
            put(&m, &key, body);
            let err = read(&m).await.expect_err(&key).to_string();
            assert!(err.contains(&key), "{key}: {err}");
        }
    }

    #[tokio::test]
    async fn read_does_not_read_sessions_or_audit() {
        let m = populated();
        let session = "moderation/sessions/endpoint";
        let audit = format!("moderation/audit/blocks/{}/00000000000000000001", h("b1"));
        for key in [session, audit.as_str()] {
            m.insert(key, "garbage");
            m.fail_on(key, Op::List);
            m.fail_on(key, Op::Get);
        }
        read(&m).await.unwrap();
    }

    #[tokio::test]
    async fn a_failed_read_aborts() {
        let key = recording_key(U, &h("aa"));
        let m = populated();
        m.fail_on(&key, Op::Get);
        let err = read(&m).await.unwrap_err().to_string();
        assert!(err.contains(&key), "{err}");

        for key in [
            subject_key("c1"),
            format!("moderation/publishers/{}", h("aa")),
            format!("catalog-outboards/{}", h("e1")),
            transition_key(&format!("arkavo:{U}"), &transition_name(2, &h("d2"))),
        ] {
            let m = populated();
            m.fail_on(&key, Op::List);
            assert!(read(&m).await.is_err(), "{key}");
        }
    }
}
