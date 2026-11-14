//! `sweep-deletions` (spec 3.4): delete what owners and operators asked
//! to delete, every version, once it is due.
//!
//! A run reads everything strictly ([`snapshot::read`]), folds the
//! committed transitions ([`fold::fold`]), observes untracked envelopes
//! and decides what is due ([`due`]), all before it writes anything: any
//! unreadable record aborts the run with nothing written. A dry run stops
//! there and reports what it would delete.
//!
//! With `delete`, it then writes, in this order:
//! 1. the requests the fold changed, then deletes the requests it
//!    cancelled, the transitions it folded (oldest first) and the lost
//!    ones. A failure here aborts the run; the transitions stay, so the
//!    next run folds them again;
//! 2. the observed envelopes' requests;
//! 3. each due item: subjects (their pointers), then recordings, then
//!    envelopes, so a subject's pointer goes before its envelope.
//!    Immediately before each, the run reads everything again and decides
//!    again: an item no longer due is kept, and so is an envelope a stored
//!    pointer still names (its subject's pointer delete failed); one whose
//!    requester's catalog moved since the first read is deferred to the
//!    next run, which folds the new transitions first. A failure leaves
//!    the item pending, and the run goes on.
//!
//! Never delete what the owner didn't ask to delete; never act on
//! unreadable state; a dry run writes nothing.

use anyhow::Context;
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::due::{self, Decision, Item, View};
use super::fold::{self, Fold};
use super::snapshot::{self, Requests, Snapshot};
use super::{
    EnvelopeRequest, State, TRANSITIONS, envelope_key, operator_key, recording_key, subject_key,
};
use crate::catalog_scan::{Catalogs, INDEXES};
use crate::moderation::{canonical_subject, valid_subject};
use crate::object_store::ObjectStore;

/// Where a catalog document lives, with its `owner` metadata.
const DOCUMENTS: &str = "catalog-documents/";

/// A recording's objects, deleted in this order: the blob first, so
/// nothing is served once anything is gone, and its owner record last
/// (ownership ends, spec decision 10).
const RECORDING_OBJECTS: [&str; 4] = [
    "blobs/",
    "outboards/",
    "manifests/",
    "moderation/publishers/",
];

/// An envelope's objects, deleted in this order.
const ENVELOPE_OBJECTS: [&str; 3] = [DOCUMENTS, "catalog-outboards/", INDEXES];

/// Why an item due at the first read is kept when the fresh decision
/// names no reason for it.
const NO_LONGER_DUE: &str = "no longer due";

/// Why a due envelope is kept at its re-check: a stored pointer names it.
const POINTER_NAMES_IT: &str = "a pointer still names it";

/// What a run did, or in a dry run would do. [`fmt::Display`] prints
/// [`lines`](Self::lines), then `N deleted, N kept, N deferred, N failed`
/// (`N would delete` in a dry run).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// In order: one line per due item, in the order the run takes them
    /// (`deleted <id>`, `would delete <id>`, `kept <id>: <why>`,
    /// `deferred <id>: catalog changed`, `failed <id>: <error>`); then
    /// `kept <id>: <why>` for each pending request not due, and for each
    /// transition the fold keeps; then each deleted recording a catalog
    /// lists and each deleted envelope a pointer names (spec 3.4 step 8).
    /// `<id>` is [`Item::id`]: `<kind> <name>`.
    pub lines: Vec<String>,
    /// Items deleted (in a dry run: that would be).
    pub deleted: usize,
    pub kept: usize,
    pub deferred: usize,
    /// Items that failed. Any makes `sweep-deletions` exit nonzero.
    pub failures: usize,
    pub dry_run: bool,
}

impl Report {
    fn deleted(&mut self, id: &str) {
        let verb = if self.dry_run {
            "would delete"
        } else {
            "deleted"
        };
        self.lines.push(format!("{verb} {id}"));
        self.deleted += 1;
    }

    fn kept(&mut self, id: &str, why: &str) {
        self.lines.push(format!("kept {id}: {why}"));
        self.kept += 1;
    }

    fn deferred(&mut self, id: &str) {
        self.lines.push(format!("deferred {id}: catalog changed"));
        self.deferred += 1;
    }

    fn failed(&mut self, id: &str, error: &anyhow::Error) {
        self.lines.push(format!("failed {id}: {error:#}"));
        self.failures += 1;
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        let verb = if self.dry_run {
            "would delete"
        } else {
            "deleted"
        };
        write!(
            f,
            "{} {verb}, {} kept, {} deferred, {} failed",
            self.deleted, self.kept, self.deferred, self.failures
        )
    }
}

/// Run the sweep (see the module doc): with `delete`, write and delete;
/// without, report only. `now` is Unix seconds. `Err` when anything read
/// is unreadable (before anything is written, or at an item's re-check),
/// or when a fold or observe write fails; a failed item is reported
/// instead, in [`Report::failures`].
pub async fn sweep<O: ObjectStore>(store: &O, delete: bool, now: i64) -> anyhow::Result<Report> {
    // Read and decide. Nothing is written before all of this has read.
    let snapshot = snapshot::read(store).await?;
    let fold = fold::fold(&snapshot, now);
    let view = due::view(&snapshot.catalogs, &fold.requests, &snapshot.moderation);
    let observed = observe(store, &snapshot, &fold.requests, &view, now).await?;
    let mut requests = fold.requests.clone();
    for r in &observed {
        requests.envelopes.insert(r.hash.clone(), r.clone());
    }
    let decision = due::due(&snapshot, &requests, &view, now);

    let mut report = Report {
        dry_run: !delete,
        ..Report::default()
    };
    let items = in_deletion_order(&decision.due);
    if delete {
        write_fold(store, &snapshot.requests, &fold).await?;
        for r in &observed {
            put_json(store, &envelope_key(&r.hash), r).await?;
        }
        let mut baseline = Pointers::of(&snapshot.catalogs);
        for item in items {
            take(store, item, &mut baseline, now, &mut report).await?;
        }
    } else {
        for item in items {
            report.deleted(&item.id());
        }
    }
    verify_tombstones(store, delete, now, &mut report).await?;

    for (id, why) in &decision.kept {
        report.kept(id, why);
    }
    for (key, why) in &fold.kept {
        let name = key.strip_prefix(TRANSITIONS).unwrap_or(key);
        report.kept(&format!("transition {name}"), why);
    }
    // Spec 3.4 step 8, against what the bucket holds now.
    if delete {
        let last = snapshot::read(store)
            .await
            .context("the final read failed")?;
        let view = due::view(&last.catalogs, &last.requests, &last.moderation);
        report
            .lines
            .extend(listed_tombstones(&last.requests, &view));
    } else {
        report.lines.extend(listed_tombstones(&requests, &view));
    }
    Ok(report)
}

/// Spec 3.4 step 4: [`due::observe`], each request's `owner` read from its
/// document's `owner` metadata, canonical. Only reads.
async fn observe<O: ObjectStore>(
    store: &O,
    snapshot: &Snapshot,
    requests: &Requests,
    view: &View,
    now: i64,
) -> anyhow::Result<Vec<EnvelopeRequest>> {
    let mut observed = due::observe(snapshot, requests, view, now);
    for r in &mut observed {
        let key = format!("{DOCUMENTS}{}", r.hash);
        let owner = store
            .head_owner(&key)
            .await
            .with_context(|| format!("{key} unreadable"))?;
        if let Some(Some(owner)) = owner {
            anyhow::ensure!(
                valid_subject(&owner),
                "{key} unreadable: its owner {owner:?} is not a subject"
            );
            r.owner = Some(canonical_subject(&owner).to_string());
        }
    }
    Ok(observed)
}

/// Write what the fold decided: each request that differs from what was
/// read, then delete the cancelled requests, the folded transitions in
/// the order folded (oldest first), and the lost ones. Every write comes
/// before any transition is deleted, so a failure leaves them all for the
/// next run to fold again.
async fn write_fold<O: ObjectStore>(
    store: &O,
    stored: &Requests,
    fold: &Fold,
) -> anyhow::Result<()> {
    let new = &fold.requests;
    for (names @ (sub, hash), r) in &new.recordings {
        if stored.recordings.get(names) != Some(r) {
            put_json(store, &recording_key(sub, hash), r).await?;
        }
    }
    for (hash, r) in &new.envelopes {
        if stored.envelopes.get(hash) != Some(r) {
            put_json(store, &envelope_key(hash), r).await?;
        }
    }
    for (names @ (sub, hash), r) in &new.operator {
        if stored.operator.get(names) != Some(r) {
            put_json(store, &operator_key(sub, hash), r).await?;
        }
    }
    for (sub, r) in &new.subjects {
        if stored.subjects.get(sub) != Some(r) {
            put_json(store, &subject_key(sub), r).await?;
        }
    }
    let cancelled = fold
        .cancelled
        .iter()
        .map(|(sub, hash)| recording_key(sub, hash));
    for key in cancelled
        .chain(fold.folded.iter().cloned())
        .chain(fold.lost.iter().cloned())
    {
        delete_versions(store, &key).await?;
    }
    Ok(())
}

/// Subjects, then recordings, then envelopes, each by [`Item::id`]: a
/// subject's pointers go before its envelopes.
fn in_deletion_order(due: &[Item]) -> Vec<&Item> {
    let rank = |item: &Item| match item {
        Item::Subject(_) => 0,
        Item::Recording { .. } => 1,
        Item::Envelope(_) => 2,
    };
    let mut items: Vec<&Item> = due.iter().collect();
    items.sort_by_cached_key(|item| (rank(item), item.id()));
    items
}

/// Each pointer as the first read saw it, less those this run deleted
/// since: `key → (canonical subject, seq, catalog hash)`.
struct Pointers(BTreeMap<String, (String, u64, String)>);

impl Pointers {
    fn of(catalogs: &Catalogs) -> Self {
        Pointers(
            catalogs
                .pointers
                .iter()
                .map(|p| {
                    let pointer = (
                        canonical_subject(&p.subject).to_string(),
                        p.seq,
                        p.catalog_hash.clone(),
                    );
                    (p.key.clone(), pointer)
                })
                .collect(),
        )
    }

    /// `subject`'s pointers, `key → (seq, catalog hash)`.
    fn of_subject(&self, subject: &str) -> BTreeMap<&str, (u64, &str)> {
        self.0
            .iter()
            .filter(|(_, (sub, ..))| sub == subject)
            .map(|(key, (_, seq, hash))| (key.as_str(), (*seq, hash.as_str())))
            .collect()
    }

    /// Whether any pointer of `subject` (canonical) in `now` differs from
    /// this one in seq or catalog hash, or is new, or is gone.
    fn moved(&self, subject: &str, now: &Pointers) -> bool {
        self.of_subject(subject) != now.of_subject(subject)
    }

    /// This run deleted `key`: no change of its subject's catalog.
    fn forget(&mut self, key: &str) {
        self.0.remove(key);
    }
}

/// Take one due item (spec 3.4 step 6): re-check it on a fresh read, then
/// delete it, or report why not. `Err` only when the fresh read fails.
async fn take<O: ObjectStore>(
    store: &O,
    item: &Item,
    baseline: &mut Pointers,
    now: i64,
    report: &mut Report,
) -> anyhow::Result<()> {
    let id = item.id();
    match recheck(store, item, baseline, now)
        .await
        .with_context(|| format!("re-checking {id}"))?
    {
        Recheck::Kept(why) => report.kept(&id, &why),
        Recheck::Deferred => report.deferred(&id),
        Recheck::Due { item, fresh, view } => {
            match delete_item(store, &item, &fresh, &view, baseline, now).await {
                Ok(()) => report.deleted(&id),
                Err(e) => report.failed(&id, &e),
            }
        }
    }
    Ok(())
}

/// What an item's re-check found.
enum Recheck {
    /// No longer due, with why.
    Kept(String),
    /// Due, but its requester's catalog moved since the first read.
    Deferred,
    /// Due still: the item as the fresh decision names it, and what that
    /// decision read.
    Due {
        item: Item,
        fresh: Box<Snapshot>,
        view: View,
    },
}

/// Read everything again and decide again (the requests this run wrote
/// are in the fresh read; transitions published since are not folded, but
/// they moved a pointer, which defers the item). Kept when the fresh
/// decision doesn't have it due; deferred when a pointer of its requester
/// moved. `Err` when the read fails.
async fn recheck<O: ObjectStore>(
    store: &O,
    item: &Item,
    baseline: &Pointers,
    now: i64,
) -> anyhow::Result<Recheck> {
    let fresh = snapshot::read(store).await?;
    let view = due::view(&fresh.catalogs, &fresh.requests, &fresh.moderation);
    let decision = due::due(&fresh, &fresh.requests, &view, now);
    let id = item.id();
    let Some(item) = decision.due.iter().find(|i| i.id() == id).cloned() else {
        return Ok(Recheck::Kept(kept_reason(&decision, item)));
    };
    // An envelope any stored pointer names stays, even one in `S` (a
    // subject being deleted, whose pointers are outside `C`): its pointer
    // delete may have failed this run. Deleting the index record a `/2`
    // pointer names would make every later strict read fail ("no index
    // record"), this run's final read and every sweep and `claim-owners`
    // after it. The next run retries the subject first.
    if let Item::Envelope(hash) = &item
        && fresh
            .catalogs
            .pointers
            .iter()
            .any(|p| &p.catalog_hash == hash)
    {
        return Ok(Recheck::Kept(POINTER_NAMES_IT.to_string()));
    }
    let current = Pointers::of(&fresh.catalogs);
    if requesters(&item, &fresh)
        .iter()
        .any(|subject| baseline.moved(subject, &current))
    {
        return Ok(Recheck::Deferred);
    }
    Ok(Recheck::Due {
        item,
        fresh: Box::new(fresh),
        view,
    })
}

/// Why the fresh decision keeps `item`: for a recording, the first kept
/// request for its hash, of any subject.
fn kept_reason(decision: &Decision, item: &Item) -> String {
    let matches = |id: &str| match item {
        Item::Recording { hash, .. } => {
            (id.starts_with("recording ") || id.starts_with("operator "))
                && id.ends_with(&format!("/{hash}"))
        }
        other => id == other.id(),
    };
    decision
        .kept
        .iter()
        .find(|(id, _)| matches(id))
        .map_or(NO_LONGER_DUE, |(_, why)| why.as_str())
        .to_string()
}

/// The canonical subjects whose catalogs an item answers to: a recording's
/// requesters (the subjects of its request keys), the subject itself, an
/// envelope's owner (none when unknown).
fn requesters(item: &Item, fresh: &Snapshot) -> BTreeSet<String> {
    match item {
        Item::Recording { hash, requests } => {
            let recordings = fresh
                .requests
                .recordings
                .keys()
                .filter(|(sub, h)| h == hash && requests.contains(&recording_key(sub, h)));
            let operator = fresh
                .requests
                .operator
                .keys()
                .filter(|(sub, h)| h == hash && requests.contains(&operator_key(sub, h)));
            recordings
                .chain(operator)
                .map(|(sub, _)| canonical_subject(sub).to_string())
                .collect()
        }
        Item::Subject(sub) => BTreeSet::from([canonical_subject(sub).to_string()]),
        Item::Envelope(hash) => fresh
            .requests
            .envelopes
            .get(hash)
            .and_then(|r| due::envelope_owner(r, &fresh.catalogs))
            .map(str::to_string)
            .into_iter()
            .collect(),
    }
}

/// Delete every version of each of the item's objects, in order, then
/// mark its requests `deleted` at `now`: the fresh records, so nothing
/// cancelled meanwhile comes back. A subject's objects are its pointers
/// in the fresh `S`. The first failure stops the item.
async fn delete_item<O: ObjectStore>(
    store: &O,
    item: &Item,
    fresh: &Snapshot,
    view: &View,
    baseline: &mut Pointers,
    now: i64,
) -> anyhow::Result<()> {
    let requests = &fresh.requests;
    match item {
        Item::Recording {
            hash,
            requests: keys,
        } => {
            for prefix in RECORDING_OBJECTS {
                delete_versions(store, &format!("{prefix}{hash}")).await?;
            }
            for ((sub, h), r) in &requests.recordings {
                let key = recording_key(sub, h);
                if h == hash && keys.contains(&key) {
                    let mut r = r.clone();
                    (r.state, r.deleted_at) = (State::Deleted, Some(now));
                    put_json(store, &key, &r).await?;
                }
            }
            for ((sub, h), r) in &requests.operator {
                let key = operator_key(sub, h);
                if h == hash && keys.contains(&key) {
                    let mut r = r.clone();
                    (r.state, r.deleted_at) = (State::Deleted, Some(now));
                    put_json(store, &key, &r).await?;
                }
            }
        }
        Item::Subject(sub) => {
            for p in &fresh.catalogs.pointers {
                if view.s.contains(&p.key) && canonical_subject(&p.subject) == sub {
                    delete_versions(store, &p.key).await?;
                    baseline.forget(&p.key);
                }
            }
            let mut r = requests
                .subjects
                .get(sub)
                .with_context(|| format!("{} vanished", subject_key(sub)))?
                .clone();
            (r.state, r.deleted_at) = (State::Deleted, Some(now));
            put_json(store, &subject_key(sub), &r).await?;
        }
        Item::Envelope(hash) => {
            for prefix in ENVELOPE_OBJECTS {
                delete_versions(store, &format!("{prefix}{hash}")).await?;
            }
            let mut r = requests
                .envelopes
                .get(hash)
                .with_context(|| format!("{} vanished", envelope_key(hash)))?
                .clone();
            (r.state, r.deleted_at) = (State::Deleted, Some(now));
            put_json(store, &envelope_key(hash), &r).await?;
        }
    }
    Ok(())
}

/// Spec 3.4 step 7, Task 17: verify each tombstone at least
/// [`super::VERIFY_AFTER`] old, and forget it once every object it covers
/// is still gone. Not yet: it does nothing, so tombstones stay.
async fn verify_tombstones<O: ObjectStore>(
    _store: &O,
    _delete: bool,
    _now: i64,
    _report: &mut Report,
) -> anyhow::Result<()> {
    Ok(())
}

/// Spec 3.4 step 8: each recording a tombstone covers that a catalog
/// lists (`L`), and each envelope a tombstone covers that a pointer names
/// (`C`). Reported only: the sweep never acts on them.
fn listed_tombstones(requests: &Requests, view: &View) -> Vec<String> {
    let recordings: BTreeSet<&String> = requests
        .recordings
        .values()
        .map(|r| (r.state, &r.hash))
        .chain(requests.operator.values().map(|r| (r.state, &r.hash)))
        .filter(|(state, hash)| *state == State::Deleted && view.l.contains(*hash))
        .map(|(_, hash)| hash)
        .collect();
    let envelopes: BTreeSet<&String> = requests
        .envelopes
        .values()
        .filter(|r| r.state == State::Deleted && view.c.contains(&r.hash))
        .map(|r| &r.hash)
        .collect();
    let recordings = recordings
        .into_iter()
        .map(|hash| format!("deleted recording {hash} is listed again"));
    let envelopes = envelopes
        .into_iter()
        .map(|hash| format!("deleted envelope {hash} is current again"));
    recordings.chain(envelopes).collect()
}

async fn put_json<O: ObjectStore>(
    store: &O,
    key: &str,
    record: &impl Serialize,
) -> anyhow::Result<()> {
    let body = Bytes::from(serde_json::to_vec(record)?);
    store
        .put(key, body)
        .await
        .with_context(|| format!("writing {key} failed"))
}

async fn delete_versions<O: ObjectStore>(store: &O, key: &str) -> anyhow::Result<()> {
    store
        .delete_all_versions(key)
        .await
        .with_context(|| format!("deleting {key} failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_scan::test_support::{index_record, publish_2};
    use crate::catalog_v2::test_support::pointer_bytes;
    use crate::deletion::{
        EnvelopeRequest, GRACE, OperatorRequest, RecordingRequest, Scope, Source, State,
        SubjectRequest, Transition, TransitionBase, envelope_key, operator_key, recording_key,
        subject_key, transition_key, transition_name,
    };
    use crate::object_store::VersionInfo;
    use crate::object_store::mem::{MemObjects, Op};
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const U: &str = "550e8400-e29b-41d4-a716-446655440000";
    const U2: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const NOW: i64 = 1_000_000_000;

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    fn arkavo(uuid: &str) -> String {
        format!("arkavo:{uuid}")
    }

    /// The catalog hash of envelope `doc`.
    fn catalog(doc: &[u8]) -> String {
        blake3::hash(doc).to_hex().to_string()
    }

    fn put(m: &MemObjects, key: &str, body: impl Serialize) {
        m.insert(key, serde_json::to_vec(&body).unwrap());
    }

    async fn record<T: DeserializeOwned>(m: &MemObjects, key: &str) -> T {
        let body = m.get(key).await.unwrap().unwrap_or_else(|| panic!("{key}"));
        serde_json::from_slice(&body).unwrap()
    }

    async fn versions(m: &MemObjects) -> Vec<VersionInfo> {
        m.list_versions("").await.unwrap()
    }

    async fn gone(m: &MemObjects, key: &str) -> bool {
        m.list_versions(key)
            .await
            .unwrap()
            .iter()
            .all(|v| v.key != key)
    }

    /// A recording's keys, in the order the sweep deletes them.
    fn recording_keys(hash: &str) -> [String; 4] {
        [
            format!("blobs/{hash}"),
            format!("outboards/{hash}"),
            format!("manifests/{hash}"),
            format!("moderation/publishers/{hash}"),
        ]
    }

    /// An envelope's keys, in the order the sweep deletes them.
    fn envelope_keys(hash: &str) -> [String; 3] {
        [
            format!("catalog-documents/{hash}"),
            format!("catalog-outboards/{hash}"),
            format!("catalog-indexes/{hash}"),
        ]
    }

    /// Recording `hash` as ingest stores it, owned by `owner`: its blob
    /// (written twice, so two versions), outboard, manifest and owner
    /// record.
    fn recording(m: &MemObjects, hash: &str, owner: &str) {
        m.insert(&format!("blobs/{hash}"), "blob 1");
        m.insert(&format!("blobs/{hash}"), "blob 2");
        m.insert(&format!("outboards/{hash}"), "outboard");
        m.insert(&format!("manifests/{hash}"), "{}");
        put(
            m,
            &format!("moderation/publishers/{hash}"),
            json!({"hash": hash, "subject": owner, "endpointId": "e", "at": 1}),
        );
    }

    /// `recordings/<sub>/<hash>`, pending since `requested_at`.
    fn request(m: &MemObjects, sub: &str, hash: &str, requested_at: i64) {
        put(
            m,
            &recording_key(sub, hash),
            RecordingRequest {
                hash: hash.into(),
                subject: sub.into(),
                requested_at,
                seq: 1,
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    /// Envelope `doc` as a publish by `owner` stores it: the document
    /// (with its owner metadata), its outboard and its (empty) index
    /// record. Returns its catalog hash.
    fn envelope(m: &MemObjects, owner: &str, doc: &[u8]) -> String {
        let hash = catalog(doc);
        m.insert_with_owner(&format!("catalog-documents/{hash}"), doc.to_vec(), owner);
        m.insert(&format!("catalog-outboards/{hash}"), "outboard");
        put(
            m,
            &format!("catalog-indexes/{hash}"),
            index_record(owner, &[]),
        );
        hash
    }

    fn envelope_request(m: &MemObjects, hash: &str, owner: &str, superseded_at: i64) {
        put(
            m,
            &envelope_key(hash),
            EnvelopeRequest {
                hash: hash.into(),
                owner: Some(owner.into()),
                superseded_at,
                source: Source::Transition,
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    fn catalog_block(m: &MemObjects, sub: &str) {
        put(
            m,
            &format!("moderation/catalog-blocks/{sub}"),
            json!({"subject": sub, "reason": "r", "by": "op", "at": 1}),
        );
    }

    fn subject_request(m: &MemObjects, sub: &str) {
        put(
            m,
            &subject_key(sub),
            SubjectRequest {
                subject: sub.into(),
                requested_at: NOW,
                reason: "account closed".into(),
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    /// A publish as the node stores it: its transition key, and the
    /// `base` the next publish names.
    struct Published {
        key: String,
        base: TransitionBase,
    }

    /// `sub`'s publish `seq` of envelope `doc` listing `payloads`, at
    /// `at`, over `base`: its index record, `/2` pointer and transition.
    #[allow(clippy::too_many_arguments)]
    fn publish(
        m: &MemObjects,
        sub: &str,
        seq: u64,
        doc: &[u8],
        payloads: &[&str],
        base: Option<&Published>,
        at: i64,
        dropped: &[&str],
        added: &[&str],
    ) -> Published {
        let index_hash = publish_2(m, sub, seq, doc, payloads);
        let pointer = hex::encode(Sha256::digest(pointer_bytes(
            sub,
            seq,
            doc,
            Some(&index_hash),
        )));
        let key = transition_key(sub, &transition_name(seq, &pointer));
        let strings = |hashes: &[&str]| hashes.iter().map(|s| s.to_string()).collect();
        put(
            m,
            &key,
            Transition {
                subject: sub.into(),
                seq,
                catalog_hash: catalog(doc),
                pointer: pointer.clone(),
                base: base.map(|b| b.base.clone()),
                at,
                dropped: strings(dropped),
                added: strings(added),
            },
        );
        Published {
            key,
            base: TransitionBase {
                seq,
                catalog_hash: catalog(doc),
                pointer,
            },
        }
    }

    /// `U` listed recording `hash` (publish 1, envelope `doc-1`) and
    /// dropped it a grace period ago (publish 2, `doc-2`): once folded,
    /// the recording and envelope `doc-1` are due.
    fn dropped(m: &MemObjects, hash: &str) -> [Published; 2] {
        recording(m, hash, U);
        let first = publish(
            m,
            U,
            1,
            b"doc-1",
            &[hash],
            None,
            NOW - 2 * GRACE,
            &[],
            &[hash],
        );
        let second = publish(
            m,
            U,
            2,
            b"doc-2",
            &[],
            Some(&first),
            NOW - GRACE,
            &[hash],
            &[],
        );
        [first, second]
    }

    fn has(report: &Report, line: &str) -> bool {
        report.lines.iter().any(|l| l == line)
    }

    #[tokio::test]
    async fn a_dry_run_changes_nothing() {
        let m = MemObjects::default();
        let (p, q) = (h("a1"), h("a2"));
        // Folding writes a request and an envelope request, and deletes
        // two transitions.
        dropped(&m, &p);
        // A stored request, due.
        recording(&m, &q, U);
        request(&m, U, &q, NOW - GRACE);
        // An envelope no pointer names: observing it writes a request.
        let e = envelope(&m, U, b"doc-0");
        let before = versions(&m).await;

        let report = sweep(&m, false, NOW).await.unwrap();
        assert!(
            has(&report, &format!("would delete recording {p}")),
            "{report}"
        );
        assert!(
            has(&report, &format!("would delete recording {q}")),
            "{report}"
        );
        assert!(
            has(
                &report,
                &format!("would delete envelope {}", catalog(b"doc-1"))
            ),
            "{report}"
        );
        assert!(
            has(&report, &format!("kept envelope {e}: within grace")),
            "{report}"
        );
        assert_eq!(
            report.to_string().lines().last(),
            Some("3 would delete, 1 kept, 0 deferred, 0 failed")
        );
        assert_eq!(report.failures, 0);
        assert_eq!(versions(&m).await, before, "every object and version");
        assert!(m.deletes().is_empty());
    }

    #[tokio::test]
    async fn a_due_recording_loses_every_version_in_order() {
        let m = MemObjects::default();
        let p = h("a1");
        recording(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("deleted recording {p}\n1 deleted, 0 kept, 0 deferred, 0 failed")
        );
        assert_eq!(m.deletes(), recording_keys(&p));
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Deleted);
        assert_eq!(r.deleted_at, Some(NOW));
        assert_eq!(r.requested_at, NOW - GRACE, "otherwise unchanged");
    }

    #[tokio::test]
    async fn a_due_envelope_is_deleted() {
        let m = MemObjects::default();
        publish_2(&m, U, 2, b"doc-2", &[]);
        let e = envelope(&m, U, b"doc-1");
        envelope_request(&m, &e, U, NOW - GRACE);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted envelope {e}")), "{report}");
        assert_eq!(report.failures, 0);
        assert_eq!(m.deletes(), envelope_keys(&e));
        for key in envelope_keys(&e) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
        assert_eq!(r.state, State::Deleted);
        assert_eq!(r.deleted_at, Some(NOW));
        // The current envelope stays.
        assert!(!gone(&m, &format!("catalog-indexes/{}", catalog(b"doc-2"))).await);
    }

    #[tokio::test]
    async fn a_due_subject_loses_its_pointers() {
        let m = MemObjects::default();
        // Both pointer keys of `U`, and another account's.
        publish_2(&m, &arkavo(U), 1, b"doc-a", &[]);
        publish_2(&m, U, 1, b"doc-b", &[]);
        publish_2(&m, U2, 1, b"doc-c", &[]);
        catalog_block(&m, U);
        subject_request(&m, U);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted subject {U}")), "{report}");
        assert_eq!(report.failures, 0);
        let (bare, prefixed) = (
            format!("catalog-pointers/{U}"),
            format!("catalog-pointers/{}", arkavo(U)),
        );
        assert_eq!(m.deletes(), [bare.clone(), prefixed.clone()]);
        assert!(gone(&m, &bare).await && gone(&m, &prefixed).await);
        assert!(!gone(&m, &format!("catalog-pointers/{U2}")).await);
        let r: SubjectRequest = record(&m, &subject_key(U)).await;
        assert_eq!(r.state, State::Deleted);
        assert_eq!(r.deleted_at, Some(NOW));
    }

    #[tokio::test]
    async fn a_relisted_recording_is_dropped_at_the_recheck() {
        let m = MemObjects::default();
        let p = h("a1");
        let [_, second] = dropped(&m, &p);
        // Once the run has decided, another catalog lists it.
        let listed = p.clone();
        m.on_before_delete(&second.key, move |m| {
            publish_2(m, U2, 1, b"other", &[&listed]);
        });

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(
            has(&report, &format!("kept recording {p}: still listed")),
            "{report}"
        );
        for key in recording_keys(&p) {
            assert!(!m.deletes().contains(&key), "{key}");
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Pending);
    }

    #[tokio::test]
    async fn a_moved_pointer_defers_the_item() {
        let m = MemObjects::default();
        let p = h("a1");
        let [_, second] = dropped(&m, &p);
        // Once the run has decided, `U` publishes again.
        m.on_before_delete(&second.key, |m| {
            publish_2(m, U, 3, b"doc-3", &[]);
        });

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(
            has(&report, &format!("deferred recording {p}: catalog changed")),
            "{report}"
        );
        assert!(
            has(
                &report,
                &format!("deferred envelope {}: catalog changed", catalog(b"doc-1"))
            ),
            "its owner's catalog moved too: {report}"
        );
        assert_eq!(report.deferred, 2);
        assert_eq!(report.failures, 0);
        for key in recording_keys(&p) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Pending);
    }

    #[tokio::test]
    async fn a_failed_delete_leaves_the_item_pending() {
        let m = MemObjects::default();
        let (p, q) = (h("a1"), h("a2"));
        for hash in [&p, &q] {
            recording(&m, hash, U);
            request(&m, U, hash, NOW - GRACE);
        }
        m.fail_on(&format!("outboards/{p}"), Op::Delete);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 1);
        let failed = format!("failed recording {p}: ");
        assert!(
            report
                .lines
                .iter()
                .any(|l| l.starts_with(&failed) && l.contains(&format!("outboards/{p}"))),
            "{report}"
        );
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Pending);
        assert!(m.get(&format!("manifests/{p}")).await.unwrap().is_some());

        // The run went on to the next item.
        assert!(has(&report, &format!("deleted recording {q}")), "{report}");
        let r: RecordingRequest = record(&m, &recording_key(U, &q)).await;
        assert_eq!(r.state, State::Deleted);
        assert_eq!(
            report.to_string().lines().last(),
            Some("1 deleted, 0 kept, 0 deferred, 1 failed")
        );
    }

    #[tokio::test]
    async fn an_unreadable_record_aborts_before_any_write() {
        let m = MemObjects::default();
        dropped(&m, &h("a1"));
        recording(&m, &h("a2"), U);
        request(&m, U, &h("a2"), NOW - GRACE);
        let garbage = "deletion-requests/subjects/u9";
        m.insert(garbage, "not json");
        let before = versions(&m).await;

        let err = sweep(&m, true, NOW).await.unwrap_err();
        assert!(format!("{err:#}").contains(garbage), "{err:#}");
        assert_eq!(versions(&m).await, before);
        assert!(m.deletes().is_empty());
    }

    /// The document's owner is read before anything is written, so a
    /// failed read of it aborts with nothing written either.
    #[tokio::test]
    async fn an_unreadable_document_owner_aborts_before_any_write() {
        let m = MemObjects::default();
        dropped(&m, &h("a1"));
        let e = envelope(&m, U, b"doc-0");
        m.fail_on(&format!("catalog-documents/{e}"), Op::Get);
        let before = versions(&m).await;

        assert!(sweep(&m, true, NOW).await.is_err());
        assert_eq!(versions(&m).await, before);
        assert!(m.deletes().is_empty());
    }

    #[tokio::test]
    async fn transitions_are_deleted_only_after_their_requests_are_written() {
        let m = MemObjects::default();
        let p = h("a1");
        let [first, second] = dropped(&m, &p);
        m.fail_on(&recording_key(U, &p), Op::Put);

        let err = sweep(&m, true, NOW).await.unwrap_err();
        assert!(
            format!("{err:#}").contains(&recording_key(U, &p)),
            "{err:#}"
        );
        for t in [first, second] {
            assert!(m.get(&t.key).await.unwrap().is_some(), "{}", t.key);
        }
        assert!(m.deletes().is_empty());
        for key in recording_keys(&p) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
    }

    /// The fold's writes, in order: changed requests, then the cancelled
    /// ones deleted, then the folded transitions oldest first, then the
    /// lost ones. Unreachable transitions it keeps are reported.
    #[tokio::test]
    async fn the_fold_is_written_then_its_transitions_deleted() {
        let m = MemObjects::default();
        let (p, r) = (h("a1"), h("a3"));
        // A stored request for `r`, which publish 2 lists again.
        request(&m, U, &r, NOW - 500);
        let first = publish(&m, U, 1, b"doc-1", &[&p], None, NOW - 100, &[], &[&p]);
        let second = publish(
            &m,
            U,
            2,
            b"doc-2",
            &[&r],
            Some(&first),
            NOW - 50,
            &[&p],
            &[&r],
        );
        // A publish of `U` that lost the pointer race, older than grace...
        let lost = Transition {
            subject: U.into(),
            seq: 2,
            catalog_hash: catalog(b"lost"),
            pointer: h("ee"),
            base: Some(first.base.clone()),
            at: NOW - 2 * GRACE,
            dropped: vec![p.clone()],
            added: vec![],
        };
        let lost_key = transition_key(U, &transition_name(2, &h("ee")));
        put(&m, &lost_key, &lost);
        // ...and one that may still be in flight.
        let young_name = transition_name(3, &h("ef"));
        let young_key = transition_key(U, &young_name);
        put(
            &m,
            &young_key,
            Transition {
                seq: 3,
                pointer: h("ef"),
                at: NOW,
                ..lost
            },
        );

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 0, "{report}");
        assert_eq!(
            m.deletes(),
            [recording_key(U, &r), first.key, second.key, lost_key]
        );
        assert!(gone(&m, &recording_key(U, &r)).await);
        assert!(m.get(&young_key).await.unwrap().is_some());
        let dropped: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(
            dropped,
            RecordingRequest {
                hash: p.clone(),
                subject: U.into(),
                requested_at: NOW - 50,
                seq: 2,
                state: State::Pending,
                deleted_at: None,
            }
        );
        let superseded: EnvelopeRequest = record(&m, &envelope_key(&catalog(b"doc-1"))).await;
        assert_eq!(
            superseded,
            EnvelopeRequest {
                hash: catalog(b"doc-1"),
                owner: Some(U.into()),
                superseded_at: NOW - 50,
                source: Source::Transition,
                state: State::Pending,
                deleted_at: None,
            }
        );
        assert!(
            has(&report, &format!("kept recording {U}/{p}: within grace")),
            "{report}"
        );
        assert!(
            has(
                &report,
                &format!("kept transition {U}/{young_name}: younger than grace")
            ),
            "{report}"
        );
    }

    #[tokio::test]
    async fn an_observed_envelope_takes_its_documents_owner() {
        let m = MemObjects::default();
        let e1 = envelope(&m, &arkavo(U), b"doc-1");
        // Only an outboard left: no document to name an owner.
        let e2 = h("e2");
        m.insert(&format!("catalog-outboards/{e2}"), "outboard");

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 0, "{report}");
        let observed = |hash: &str, owner: Option<&str>| EnvelopeRequest {
            hash: hash.into(),
            owner: owner.map(str::to_string),
            superseded_at: NOW,
            source: Source::Observed,
            state: State::Pending,
            deleted_at: None,
        };
        assert_eq!(
            record::<EnvelopeRequest>(&m, &envelope_key(&e1)).await,
            observed(&e1, Some(U)),
            "canonical"
        );
        assert_eq!(
            record::<EnvelopeRequest>(&m, &envelope_key(&e2)).await,
            observed(&e2, None)
        );
    }

    /// A subject's pointers go first, then recordings, then envelopes.
    /// Deleting the subject's own pointers is no catalog change: its
    /// recordings and envelopes are deleted in the same run.
    #[tokio::test]
    async fn items_go_subject_then_recording_then_envelope() {
        let m = MemObjects::default();
        let p = h("a1");
        recording(&m, &p, U);
        publish_2(&m, U, 1, b"doc-u", &[&p]);
        catalog_block(&m, U);
        subject_request(&m, U);
        put(
            &m,
            &operator_key(U, &p),
            OperatorRequest {
                hash: p.clone(),
                subject: U.into(),
                requested_at: NOW,
                reason: "account closed".into(),
                scope: Scope::Subject,
                state: State::Pending,
                deleted_at: None,
            },
        );
        let e = envelope(&m, U, b"doc-old");
        envelope_request(&m, &e, U, NOW - GRACE);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 0, "{report}");
        assert_eq!(report.deferred, 0, "{report}");
        let mut expected = vec![format!("catalog-pointers/{U}")];
        expected.extend(recording_keys(&p));
        expected.extend(envelope_keys(&e));
        assert_eq!(m.deletes(), expected);
        let lines: Vec<&str> = report
            .lines
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("deleted "))
            .collect();
        assert_eq!(
            lines,
            [
                format!("deleted subject {U}"),
                format!("deleted recording {p}"),
                format!("deleted envelope {e}"),
            ]
        );
        let r: OperatorRequest = record(&m, &operator_key(U, &p)).await;
        assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(NOW)));
    }

    /// A subject whose pointer delete fails keeps the envelope that pointer
    /// names, though that envelope is due in the same run (its pointer is in
    /// `S`, so not in `C`): deleting the index record of a live `/2` pointer
    /// would make every later strict read fail. The next run retries the
    /// subject first.
    #[tokio::test]
    async fn an_envelope_a_pointer_still_names_is_kept() {
        let m = MemObjects::default();
        publish_2(&m, U, 1, b"doc-u", &[]);
        let e = catalog(b"doc-u");
        m.insert_with_owner(&format!("catalog-documents/{e}"), "doc-u", U);
        m.insert(&format!("catalog-outboards/{e}"), "outboard");
        catalog_block(&m, U);
        subject_request(&m, U);
        // Observed on an earlier run, a grace period ago.
        put(
            &m,
            &envelope_key(&e),
            EnvelopeRequest {
                hash: e.clone(),
                owner: Some(U.into()),
                superseded_at: NOW - GRACE,
                source: Source::Observed,
                state: State::Pending,
                deleted_at: None,
            },
        );
        let pointer = format!("catalog-pointers/{U}");
        m.fail_on(&pointer, Op::Delete);

        let report = sweep(&m, true, NOW).await.unwrap();
        let failed = report
            .lines
            .iter()
            .position(|l| l.starts_with(&format!("failed subject {U}: ")))
            .unwrap_or_else(|| panic!("{report}"));
        let kept = report
            .lines
            .iter()
            .position(|l| *l == format!("kept envelope {e}: a pointer still names it"))
            .unwrap_or_else(|| panic!("{report}"));
        assert!(failed < kept, "{report}");
        assert_eq!(report.failures, 1);
        assert_eq!(report.deleted, 0, "{report}");
        for key in envelope_keys(&e) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
        assert!(m.get(&pointer).await.unwrap().is_some());
        let r: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
        assert_eq!(r.state, State::Pending);
        snapshot::read(&m).await.unwrap();
    }

    /// Deletion is per hash: a recording due under one request marks every
    /// pending request for it deleted, of any subject, due on its own or
    /// not. The block that made it due is kept.
    #[tokio::test]
    async fn a_deleted_recording_marks_every_request_for_it() {
        let m = MemObjects::default();
        let p = h("a1");
        recording(&m, &p, U);
        // Within grace on its own.
        request(&m, U, &p, NOW);
        let block = format!("moderation/blocks/{p}");
        put(
            &m,
            &block,
            json!({"hash": p, "reason": "r", "by": "op", "at": 1}),
        );
        put(
            &m,
            &operator_key(U2, &p),
            OperatorRequest {
                hash: p.clone(),
                subject: U2.into(),
                requested_at: NOW,
                reason: "court order".into(),
                scope: Scope::Hash,
                state: State::Pending,
                deleted_at: None,
            },
        );

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("deleted recording {p}\n1 deleted, 0 kept, 0 deferred, 0 failed")
        );
        assert_eq!(m.deletes(), recording_keys(&p));
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(NOW)));
        let r: OperatorRequest = record(&m, &operator_key(U2, &p)).await;
        assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(NOW)));
        assert!(m.get(&block).await.unwrap().is_some(), "the block stays");
    }

    /// Spec 3.4 step 8: a recording deleted while a catalog lists it is
    /// reported, not acted on.
    #[tokio::test]
    async fn a_deleted_recording_listed_again_is_reported() {
        let m = MemObjects::default();
        let p = h("a1");
        recording(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        // Listed after its re-check, just before its delete.
        let listed = p.clone();
        m.on_before_delete(&format!("blobs/{p}"), move |m| {
            publish_2(m, U2, 1, b"other", &[&listed]);
        });

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted recording {p}")), "{report}");
        assert!(
            has(&report, &format!("deleted recording {p} is listed again")),
            "{report}"
        );
        assert_eq!(report.failures, 0);
    }

    #[tokio::test]
    async fn a_failed_recheck_aborts() {
        let m = MemObjects::default();
        let p = h("a1");
        let [_, second] = dropped(&m, &p);
        let key = recording_key(U, &p);
        m.on_before_delete(&second.key, move |m| m.fail_on(&key, Op::Get));

        let err = sweep(&m, true, NOW).await.unwrap_err();
        assert!(
            format!("{err:#}").contains(&recording_key(U, &p)),
            "{err:#}"
        );
        for key in recording_keys(&p) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
    }
}
