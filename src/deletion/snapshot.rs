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
use bytes::Bytes;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::{
    ENVELOPES, EnvelopeRequest, OPERATOR, OperatorRequest, RECORDINGS, RecordingRequest, SUBJECTS,
    State, SubjectRequest, TRANSITIONS, Transition, transition_name,
};
use crate::catalog_scan::{self, Catalogs};
use crate::creator_catalog::is_lower_hex_hash;
use crate::moderation::{
    BLOCKS, Block, CATALOG_BLOCKS, CatalogBlock, SUSPENSIONS, Suspension, canonical_subject,
    valid_subject,
};
use crate::object_store::ObjectStore;
use crate::ownership::{PUBLISHERS, parse_owner};

/// Where a catalog envelope's objects live, each keyed by its catalog
/// hash. Only listed: [`Snapshot::envelope_objects`].
const ENVELOPE_OBJECTS: [&str; 3] = [
    "catalog-documents/",
    "catalog-outboards/",
    catalog_scan::INDEXES,
];

/// Everything the sweep decides on, as one run read it.
#[derive(Debug, Default)]
pub struct Snapshot {
    /// Every pointer and every index record.
    pub catalogs: Catalogs,
    /// Every transition, by its full key: `catalog-transitions/<sub>/<name>`
    /// ([`super::transition_key`]), `<sub>` the pointer key's.
    pub transitions: BTreeMap<String, Transition>,
    pub requests: Requests,
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
}

/// Read everything the sweep decides on, strictly (see the module doc).
/// `Err` names the first key that is unreadable, malformed, or vanished
/// between its listing and its read; [`catalog_scan::scan`]'s rules apply
/// to pointers and index records.
pub async fn read<O: ObjectStore>(store: &O) -> anyhow::Result<Snapshot> {
    // The order matters, because a publish writes its transition, then its
    // document, outboard and index, then its pointer:
    // - pointers before transitions, so the transition of every pointer
    //   read is listed too. The other way round, a publish landing between
    //   the two reads would leave its pointer's walk with no first step,
    //   and the older transitions it reaches would look unreachable;
    // - envelope objects before pointers, so only a publish whose writes
    //   span the pointer read lists a document no pointer read names.
    let envelope_objects = envelope_objects(store).await?;
    let catalogs = catalog_scan::scan(store).await?;
    let transitions = transitions(store).await?;
    let requests = requests(store).await?;
    let moderation = moderation(store).await?;
    let owners = owners(store).await?;
    Ok(Snapshot {
        catalogs,
        transitions,
        requests,
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
    for (key, body) in bodies(store, TRANSITIONS).await? {
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
    let t: Transition = serde_json::from_slice(body)?;
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

async fn requests<O: ObjectStore>(store: &O) -> anyhow::Result<Requests> {
    let mut requests = Requests::default();
    for (key, body) in bodies(store, RECORDINGS).await? {
        let (names, request) =
            recording(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.recordings.insert(names, request);
    }
    for (key, body) in bodies(store, ENVELOPES).await? {
        let (hash, request) = envelope(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.envelopes.insert(hash, request);
    }
    for (key, body) in bodies(store, OPERATOR).await? {
        let (names, request) =
            operator(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.operator.insert(names, request);
    }
    for (key, body) in bodies(store, SUBJECTS).await? {
        let (sub, request) = subject(&key, &body).with_context(|| format!("{key} unreadable"))?;
        requests.subjects.insert(sub, request);
    }
    Ok(requests)
}

fn recording(key: &str, body: &[u8]) -> anyhow::Result<((String, String), RecordingRequest)> {
    let [sub, hash] = names(key, RECORDINGS)?;
    let (sub, hash) = (canonical(sub)?, lower_hex(hash)?);
    let r: RecordingRequest = serde_json::from_slice(body)?;
    same("subject", &r.subject, sub)?;
    same("hash", &r.hash, hash)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok(((sub.to_string(), hash.to_string()), r))
}

fn envelope(key: &str, body: &[u8]) -> anyhow::Result<(String, EnvelopeRequest)> {
    let [hash] = names(key, ENVELOPES)?;
    let hash = lower_hex(hash)?;
    let r: EnvelopeRequest = serde_json::from_slice(body)?;
    same("hash", &r.hash, hash)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok((hash.to_string(), r))
}

fn operator(key: &str, body: &[u8]) -> anyhow::Result<((String, String), OperatorRequest)> {
    let [sub, hash] = names(key, OPERATOR)?;
    let (sub, hash) = (canonical(sub)?, lower_hex(hash)?);
    let r: OperatorRequest = serde_json::from_slice(body)?;
    same("subject", &r.subject, sub)?;
    same("hash", &r.hash, hash)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok(((sub.to_string(), hash.to_string()), r))
}

fn subject(key: &str, body: &[u8]) -> anyhow::Result<(String, SubjectRequest)> {
    let [sub] = names(key, SUBJECTS)?;
    let sub = canonical(sub)?;
    let r: SubjectRequest = serde_json::from_slice(body)?;
    same("subject", &r.subject, sub)?;
    tombstone_dated(r.state, r.deleted_at)?;
    Ok((sub.to_string(), r))
}

/// Suspensions, blocks and catalog blocks, through the node's own record
/// types; active ones make the view.
async fn moderation<O: ObjectStore>(store: &O) -> anyhow::Result<ModerationView> {
    let mut view = ModerationView::default();
    for (key, body) in bodies(store, &moderation_prefix(SUSPENSIONS)).await? {
        let s =
            moderation_record::<Suspension>(&key, &body, SUSPENSIONS, "subject", |s| &s.subject)?;
        if s.lifted_at.is_none() && s.hide_catalog {
            view.hidden
                .insert(canonical_subject(&s.subject).to_string());
        }
    }
    for (key, body) in bodies(store, &moderation_prefix(BLOCKS)).await? {
        let b = moderation_record::<Block>(&key, &body, BLOCKS, "hash", |b| &b.hash)?;
        if b.lifted_at.is_none() {
            view.blocked.insert(b.hash.to_ascii_lowercase());
        }
    }
    for (key, body) in bodies(store, &moderation_prefix(CATALOG_BLOCKS)).await? {
        let b = moderation_record::<CatalogBlock>(&key, &body, CATALOG_BLOCKS, "subject", |b| {
            &b.subject
        })?;
        if b.lifted_at.is_none() {
            let subject = canonical_subject(&b.subject).to_string();
            view.catalog_blocked.insert(subject.clone());
            view.hidden.insert(subject);
        }
    }
    Ok(view)
}

/// `moderation/<kind>/<name>`, whose body's `what` (`name_of`) is `name`.
fn moderation_record<T: DeserializeOwned>(
    key: &str,
    body: &[u8],
    kind: &str,
    what: &str,
    name_of: fn(&T) -> &String,
) -> anyhow::Result<T> {
    let parse = || {
        let [name] = names(key, &moderation_prefix(kind))?;
        let record: T = serde_json::from_slice(body)?;
        same(what, name_of(&record), name)?;
        anyhow::Ok(record)
    };
    parse().with_context(|| format!("{key} unreadable"))
}

/// Owner records, through [`parse_owner`]: hash → canonical subject.
async fn owners<O: ObjectStore>(store: &O) -> anyhow::Result<HashMap<String, String>> {
    let mut owners = HashMap::new();
    for (key, body) in bodies(store, &moderation_prefix(PUBLISHERS)).await? {
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

/// Every object listed under `prefix`, with its body. A read that fails,
/// or finds the object gone since the listing, names the key.
async fn bodies<O: ObjectStore>(store: &O, prefix: &str) -> anyhow::Result<Vec<(String, Bytes)>> {
    let mut out = Vec::new();
    for listed in store
        .list(prefix)
        .await
        .with_context(|| format!("listing {prefix} failed"))?
    {
        let key = listed.key;
        let body = store
            .get(&key)
            .await
            .with_context(|| format!("{key} unreadable"))?
            .with_context(|| format!("{key} vanished during the read"))?;
        out.push((key, body));
    }
    Ok(out)
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

/// A tombstone carries `deletedAt`: verifying it (spec 3.4 step 7) and
/// re-folding a drop over it (call 9) both need it.
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
    use std::collections::{BTreeSet, HashMap, HashSet};

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
        let arkavo_2 = format!("arkavo:{U2}");
        put(
            &m,
            &format!("moderation/suspensions/{arkavo_2}"),
            suspension(&arkavo_2, true, None),
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
            &format!("moderation/blocks/{}", h("B3")),
            block(&h("B3"), None),
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
        assert_eq!(
            view.blocked,
            HashSet::from([h("b1"), h("b3")]),
            "active blocks only, lowercase"
        );
        assert_eq!(view.catalog_blocked, HashSet::from(["c1".to_string()]));
        assert_eq!(
            view.hidden,
            HashSet::from(["c1".to_string(), "s1".to_string(), U2.to_string()]),
            "active catalog blocks and hideCatalog suspensions, canonical"
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
