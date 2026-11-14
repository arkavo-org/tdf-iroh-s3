//! `sweep-deletions` (spec 3.4): delete what owners and operators asked
//! to delete, every version, once it is due.
//!
//! A run reads everything strictly ([`snapshot::read`]), folds the
//! committed transitions ([`fold::fold`]), observes untracked envelopes
//! and decides what is due ([`due`]), all before it writes anything: any
//! unreadable record aborts the run with nothing written. A dry run stops
//! there and reports what it would delete, having listed each due
//! recording's pushed objects for its push check (below), a read.
//!
//! With `delete`, it then writes, in this order:
//! 1. the requests the fold changed, then deletes the requests it
//!    cancelled, the transitions it folded (oldest first) and the lost
//!    ones. A failure here aborts the run; the transitions stay, so the
//!    next run folds them again;
//! 2. the observed envelopes' requests;
//! 3. each due item: subjects (their pointers), then recordings, then
//!    envelopes, so a subject's pointer goes before its envelope.
//!    Immediately before each, the run lists the item's versions, then
//!    reads everything again and decides again ([`take`]): an item no
//!    longer due is kept, and so is an envelope a stored pointer still
//!    names (its subject's pointer delete failed); one whose requester's
//!    catalog moved since the first read is deferred to the next run,
//!    which folds the new transitions first. A recording pushed again
//!    after the drops that have it due (its pushed objects listed again
//!    after the read) isn't deleted: every pending `recordings/` request
//!    of the hash older than the push restarts its grace from the push
//!    ([`pushed_again`]). Only a listing cancels a drop. Otherwise it
//!    deletes exactly the versions it listed, never one written since. A
//!    failure leaves the item pending, and the run goes on.
//!
//! Then, in both modes, it verifies each tombstone at least
//! [`VERIFY_AFTER`] old ([`verify_tombstones`], spec 3.4 step 7): it
//! forgets one whose objects stay gone, or came back fresh or listed, and
//! deletes again exactly the versions it listed, before its fresh read,
//! that an in-flight write brought back.
//!
//! A run that aborts part way ([`Aborted`]) still reports what it did
//! until then.
//!
//! Never delete what the owner didn't ask to delete; never leave a deleted
//! object to come back; never act on unreadable state; a dry run writes
//! nothing.

use anyhow::Context;
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::due::{self, Decision, Item, View};
use super::fold::{self, Fold};
use super::snapshot::{self, ModerationView, Requests, Snapshot};
use super::{
    EnvelopeRequest, RecordingRequest, State, TRANSITIONS, VERIFY_AFTER, envelope_key,
    operator_key, recording_key, subject_key,
};
use crate::catalog_scan::{Catalogs, INDEXES, POINTERS};
use crate::moderation::{canonical_subject, valid_subject};
use crate::object_store::{ObjectStore, VersionInfo};

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

/// The objects of a recording a new push writes, and of an envelope a new
/// publish writes: what makes a tombstone fresh (spec 3.4 step 7, rule 1),
/// and what shows a recording pushed again since its drop
/// ([`newest_push`]). Never an outboard: the node writes one itself when
/// it serves a blob or envelope that lacks it.
const PUSHED_OBJECTS: [&str; 3] = ["blobs/", "manifests/", "moderation/publishers/"];
const PUBLISHED_OBJECTS: [&str; 2] = [DOCUMENTS, INDEXES];

/// Why an item due at the first read is kept when the fresh decision
/// names no reason for it.
const NO_LONGER_DUE: &str = "no longer due";

/// Why a due envelope is kept at its re-check: a stored pointer names it.
const POINTER_NAMES_IT: &str = "a pointer still names it";

/// Why an item is deferred: its requester's catalog moved.
const CATALOG_CHANGED: &str = "catalog changed";

/// Why a tombstone is forgotten with its objects kept (spec 3.4 step 7):
/// one was written more than [`VERIFY_AFTER`] after the delete; the
/// recording is listed; the envelope is current.
const FRESH: &str = "fresh";
const LISTED_AGAIN: &str = "listed again";
const CURRENT_AGAIN: &str = "current again";

/// What a failed final read (spec 3.4 step 8) reports as failed.
const FINAL_READ: &str = "final read";

/// Why a transition no pointer reaches is deleted unfolded.
const LOST: &str = "lost its publish";

/// Why a subject's tombstone is kept: an envelope request of that owner is
/// pending, and the tombstone releases it while the owner's catalog block
/// stands (`due::everything_requested`).
const ENVELOPES_PENDING: &str = "envelopes pending";

/// What a run did, or in a dry run would do. [`fmt::Display`] prints
/// [`lines`](Self::lines), then `N deleted, N kept, N deferred, N failed`
/// (`N would delete` in a dry run).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// In order: `deleted transition <sub>/<name>: lost its publish`
    /// (`would delete …` in a dry run) for each transition that lost its
    /// publish, not counted; then one line per due item, in the order the
    /// run takes them (`deleted <id>`, `would delete <id>`, `kept <id>:
    /// <why>`, `pushed again <id>` (in a dry run too), `deferred <id>:
    /// catalog changed`, `failed <id>: <error>`);
    /// then one line per tombstoned item verified, in the same order (`verified
    /// <id>`, `fresh <id>`, `listed again <id>`, `current again <id>`,
    /// `recreated <id>`, `kept <id>: <why>`, `failed <id>: <error>`; in a
    /// dry run `would verify <id>`, `would forget <id>: <why>`, `would
    /// delete again <id>`); then `kept <id>: <why>` for each pending
    /// request not due, and for each transition the fold keeps; then each
    /// deleted recording a catalog lists and each deleted envelope a
    /// pointer names (spec 3.4 step 8), or `failed final read: <error>`.
    /// `<id>` is [`Item::id`]: `<kind> <name>`.
    pub lines: Vec<String>,
    /// Items deleted, and tombstoned items deleted again (in a dry run:
    /// that would be).
    pub deleted: usize,
    /// Items, tombstoned items, requests and transitions kept, a recording
    /// pushed again among them.
    pub kept: usize,
    pub deferred: usize,
    /// Items that failed, and a failed final read. Any makes
    /// `sweep-deletions` exit nonzero.
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

    /// A due recording pushed again since the drops that had it due
    /// ([`pushed_again`]): kept, and the grace of those drops restarted
    /// from the push (in a dry run: would be). The same line in both
    /// modes.
    fn pushed_again(&mut self, id: &str) {
        self.lines.push(format!("pushed again {id}"));
        self.kept += 1;
    }

    fn deferred(&mut self, id: &str) {
        self.lines.push(format!("deferred {id}: {CATALOG_CHANGED}"));
        self.deferred += 1;
    }

    fn failed(&mut self, id: &str, error: &anyhow::Error) {
        self.lines.push(format!("failed {id}: {error:#}"));
        self.failures += 1;
    }

    /// A transition that lost its publish, deleted unfolded: a line, not
    /// counted (it is no item).
    fn lost(&mut self, key: &str) {
        let verb = if self.dry_run {
            "would delete"
        } else {
            "deleted"
        };
        let name = key.strip_prefix(TRANSITIONS).unwrap_or(key);
        self.lines.push(format!("{verb} transition {name}: {LOST}"));
    }

    /// A tombstone whose objects stayed gone, removed.
    fn verified(&mut self, id: &str) {
        self.lines.push(if self.dry_run {
            format!("would verify {id}")
        } else {
            format!("verified {id}")
        });
    }

    /// A tombstone removed with its objects kept, for `why`.
    fn forgot(&mut self, id: &str, why: &str) {
        self.lines.push(if self.dry_run {
            format!("would forget {id}: {why}")
        } else {
            format!("{why} {id}")
        });
    }

    /// A tombstoned item's objects, written back in flight, deleted again.
    fn recreated(&mut self, id: &str) {
        self.lines.push(if self.dry_run {
            format!("would delete again {id}")
        } else {
            format!("recreated {id}")
        });
        self.deleted += 1;
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

/// A run that stopped part way.
#[derive(Debug)]
pub struct Aborted {
    /// What the run did before it stopped: its [`Report::lines`] so far,
    /// and their counts. Empty when the first read stopped it, before
    /// anything was written.
    pub report: Report,
    /// Why it stopped.
    pub error: anyhow::Error,
}

/// Run the sweep (see the module doc): with `delete`, write and delete;
/// without, report only. `now` is Unix seconds. [`Aborted`] when anything
/// read or listed is unreadable (before anything is written, at an item's
/// re-check, or at the tombstones' verification), or when a fold or
/// observe write fails, with what the run did until then; a failed item is
/// reported instead, in [`Report::failures`], and so is a failed final
/// read.
pub async fn sweep<O: ObjectStore>(store: &O, delete: bool, now: i64) -> Result<Report, Aborted> {
    let mut report = Report {
        dry_run: !delete,
        ..Report::default()
    };
    match run(store, delete, now, &mut report).await {
        Ok(()) => Ok(report),
        Err(error) => Err(Aborted { report, error }),
    }
}

/// [`sweep`], each line into `report` as it happens.
async fn run<O: ObjectStore>(
    store: &O,
    delete: bool,
    now: i64,
    report: &mut Report,
) -> anyhow::Result<()> {
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

    let items = in_deletion_order(&decision.due);
    let mut baseline = Pointers::of(&snapshot.catalogs);
    if delete {
        write_fold(store, &snapshot.requests, &fold).await?;
        for key in &fold.lost {
            delete_record(store, key).await?;
            report.lost(key);
        }
        for r in &observed {
            put_json(store, &envelope_key(&r.hash), r).await?;
        }
        for item in items {
            take(store, item, &mut baseline, now, report).await?;
        }
    } else {
        for key in &fold.lost {
            report.lost(key);
        }
        // Step 6 without its re-read: a recording's push check, on a
        // listing of its pushed objects. Reads only: no grace restarts.
        for item in items {
            let id = item.id();
            let mut pushed = false;
            if let Item::Recording { hash, .. } = item {
                let listed = list_keys(store, pushed_keys(hash))
                    .await
                    .with_context(|| format!("checking {id}"))?;
                let last = newest_push(&listed.versions);
                pushed = pushed_again(item, &snapshot, &requests, &view, last, now).is_some();
            }
            if pushed {
                report.pushed_again(&id);
            } else {
                report.deleted(&id);
            }
        }
    }
    verify_tombstones(
        store,
        delete,
        (&requests, &snapshot.request_written),
        &mut baseline,
        now,
        report,
    )
    .await?;

    for (id, why) in &decision.kept {
        report.kept(id, why);
    }
    for (key, why) in &fold.kept {
        let name = key.strip_prefix(TRANSITIONS).unwrap_or(key);
        report.kept(&format!("transition {name}"), why);
    }
    // Spec 3.4 step 8, against what the bucket holds now. Every delete
    // is done by then: a failed read is a failure, not an abort.
    if delete {
        match snapshot::read(store).await {
            Ok(last) => {
                let view = due::view(&last.catalogs, &last.requests, &last.moderation);
                report
                    .lines
                    .extend(listed_tombstones(&last.requests, &view));
            }
            Err(e) => report.failed(FINAL_READ, &e),
        }
    } else {
        report.lines.extend(listed_tombstones(&requests, &view));
    }
    Ok(())
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
/// read, then delete the cancelled requests and the folded transitions in
/// the order folded (oldest first). Every write comes before any
/// transition is deleted, so a failure leaves them all for the next run
/// to fold again. The lost transitions are the caller's, each reported as
/// it goes.
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
    for key in cancelled.chain(fold.folded.iter().cloned()) {
        delete_record(store, &key).await?;
    }
    Ok(())
}

/// Subjects, then recordings, then envelopes, each by [`Item::id`]: a
/// subject's pointers go before its envelopes.
fn in_deletion_order(due: &[Item]) -> Vec<&Item> {
    let mut items: Vec<&Item> = due.iter().collect();
    items.sort_by_cached_key(|item| deletion_order(item));
    items
}

/// The sort key of [`in_deletion_order`].
fn deletion_order(item: &Item) -> (u8, String) {
    let rank = match item {
        Item::Subject(_) => 0,
        Item::Recording { .. } => 1,
        Item::Envelope(_) => 2,
    };
    (rank, item.id())
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

/// Take one due item (spec 3.4 step 6): list its versions, re-check it on
/// a fresh read, check a recording wasn't pushed again since its drops
/// ([`pushed_again`]: restart their grace), then delete exactly the listed
/// versions, or report why not. `Err` only when the fresh read or a
/// listing fails.
///
/// The versions are listed before the fresh read, so everything the delete
/// removes existed when that read judged the item; a version written after
/// the listing survives on every path. That alone would let a push landing
/// during the fresh read go unjudged: it survives the delete but predates
/// the tombstone, and verification would delete it again as an in-flight
/// write. So a recording's pushed objects are listed again after the read,
/// for the push check only (the delete still takes the first listing): a
/// push up to that second listing restarts the grace.
async fn take<O: ObjectStore>(
    store: &O,
    item: &Item,
    baseline: &mut Pointers,
    now: i64,
    report: &mut Report,
) -> anyhow::Result<()> {
    let id = item.id();
    let listed = list_keys(store, candidate_keys(item))
        .await
        .with_context(|| format!("re-checking {id}"))?;
    let (item, fresh, view) = match recheck(store, item, baseline, now)
        .await
        .with_context(|| format!("re-checking {id}"))?
    {
        Recheck::Kept(why) => {
            report.kept(&id, &why);
            return Ok(());
        }
        Recheck::Deferred => {
            report.deferred(&id);
            return Ok(());
        }
        Recheck::Due { item, fresh, view } => (item, fresh, view),
    };
    let listed = Listed {
        keys: due_keys(&item, &fresh, &view),
        versions: listed.versions,
    };
    if let Item::Recording { hash, .. } = &item {
        let since = list_keys(store, pushed_keys(hash))
            .await
            .with_context(|| format!("re-checking {id}"))?;
        let pushed = newest_push(listed.versions.iter().chain(&since.versions));
        if let Some(moved) = pushed_again(&item, &fresh, &fresh.requests, &view, pushed, now) {
            match restart(store, &moved).await {
                Ok(()) => report.pushed_again(&id),
                Err(e) => report.failed(&id, &e),
            }
            return Ok(());
        }
    }
    match delete_item(store, &item, &fresh, &listed, baseline, now).await {
        Ok(()) => report.deleted(&id),
        Err(e) => report.failed(&id, &e),
    }
    Ok(())
}

/// What a delete may remove: an item's keys, in the order they are
/// deleted, and every version and delete marker of them as listed.
struct Listed {
    keys: Vec<String>,
    versions: Vec<VersionInfo>,
}

impl Listed {
    /// Delete exactly the listed versions, key by key in order; one
    /// written since the listing stays. A key with none listed deletes
    /// nothing. The first failure stops it.
    async fn delete<O: ObjectStore>(
        &self,
        store: &O,
        baseline: &mut Pointers,
    ) -> anyhow::Result<()> {
        for key in &self.keys {
            let ids: Vec<String> = self
                .versions
                .iter()
                .filter(|v| &v.key == key)
                .map(|v| v.version_id.clone())
                .collect();
            store
                .delete_versions(key, &ids)
                .await
                .with_context(|| format!("deleting {key} failed"))?;
            // A pointer this run deleted is no catalog change.
            baseline.forget(key);
        }
        Ok(())
    }
}

/// Every version and delete marker of exactly `keys`.
async fn list_keys<O: ObjectStore>(store: &O, keys: Vec<String>) -> anyhow::Result<Listed> {
    let mut versions = Vec::new();
    for key in &keys {
        let listed = list_versions(store, key).await?;
        versions.extend(listed.into_iter().filter(|v| &v.key == key));
    }
    Ok(Listed { keys, versions })
}

/// Every key a due item may delete, known before the fresh read: a
/// recording's and an envelope's objects, a subject's pointer keys in
/// both forms (`<sub>`, `arkavo:<sub>`) that are canonically it.
fn candidate_keys(item: &Item) -> Vec<String> {
    match item {
        Item::Subject(sub) => [sub.clone(), format!("arkavo:{sub}")]
            .into_iter()
            .map(|name| format!("{POINTERS}{name}"))
            .filter(|key| pointer_subject(key) == Some(sub.as_str()))
            .collect(),
        item => object_keys(item),
    }
}

/// A due item's keys, in the order they are deleted: a recording's and an
/// envelope's objects, a subject's pointers in the fresh `S`.
fn due_keys(item: &Item, fresh: &Snapshot, view: &View) -> Vec<String> {
    match item {
        Item::Subject(sub) => fresh
            .catalogs
            .pointers
            .iter()
            .filter(|p| view.s.contains(&p.key) && canonical_subject(&p.subject) == sub)
            .map(|p| p.key.clone())
            .collect(),
        item => object_keys(item),
    }
}

/// A recording's objects a push writes ([`PUSHED_OBJECTS`]).
fn pushed_keys(hash: &str) -> Vec<String> {
    PUSHED_OBJECTS
        .iter()
        .map(|p| format!("{p}{hash}"))
        .collect()
}

/// When a recording was last pushed, as far as `versions` show: the newest
/// write of a version of a pushed object ([`PUSHED_OBJECTS`]; never an
/// outboard, nor a delete marker). `None` when they show none.
fn newest_push<'a>(versions: impl IntoIterator<Item = &'a VersionInfo>) -> Option<i64> {
    versions
        .into_iter()
        .filter(|v| !v.delete_marker && PUSHED_OBJECTS.iter().any(|p| v.key.starts_with(p)))
        .map(|v| v.modified)
        .max()
}

/// The `recordings/` requests of `item`, due on `snapshot` and `requests`,
/// that a push since restarts, with their keys, when nothing else has the
/// item due without them. A push after a drop doesn't cancel it (only a
/// listing does, through the fold's `added`): it restarts its grace. So
/// every pending `recordings/` request of the hash whose `requestedAt` is
/// older than `pushed` ([`newest_push`]) moves forward to it, never back,
/// and the recording isn't deleted this run: each falls due a grace after
/// the push. `None` for any other item, with no push, when none is older,
/// or when another request still has the hash due without them: an
/// operator's, whose own rules hold whatever a push does (scope `subject`
/// while the catalog block stands; scope `hash` while the block does, and
/// the node refuses a blocked hash's push).
///
/// Step 6 only, not the tombstones' verification: every write that
/// recreates a deleted recording is after its drop, and one within the
/// hour after the tombstone is an in-flight write, deleted again.
fn pushed_again(
    item: &Item,
    snapshot: &Snapshot,
    requests: &Requests,
    view: &View,
    pushed: Option<i64>,
    now: i64,
) -> Option<Vec<(String, RecordingRequest)>> {
    let Item::Recording {
        hash,
        requests: keys,
    } = item
    else {
        return None;
    };
    let pushed = pushed?;
    let moved: Vec<(String, RecordingRequest)> = requests
        .recordings
        .iter()
        .filter(|((sub, h), r)| {
            h == hash && keys.contains(&recording_key(sub, h)) && pushed > r.requested_at
        })
        .map(|((sub, h), r)| {
            let mut r = r.clone();
            r.requested_at = pushed;
            (recording_key(sub, h), r)
        })
        .collect();
    if moved.is_empty() {
        return None;
    }
    let mut rest = requests.clone();
    rest.recordings
        .retain(|(sub, h), _| !moved.iter().any(|(key, _)| *key == recording_key(sub, h)));
    let id = item.id();
    if due::due(snapshot, &rest, view, now)
        .due
        .iter()
        .any(|i| i.id() == id)
    {
        return None;
    }
    Some(moved)
}

/// Write the requests a push restarted ([`pushed_again`]).
async fn restart<O: ObjectStore>(
    store: &O,
    moved: &[(String, RecordingRequest)],
) -> anyhow::Result<()> {
    for (key, r) in moved {
        put_json(store, key, r).await?;
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
    Ok(match held(&item, &fresh, baseline) {
        Some(Hold::PointerNamesIt) => Recheck::Kept(POINTER_NAMES_IT.to_string()),
        Some(Hold::Moved) => Recheck::Deferred,
        None => Recheck::Due {
            item,
            fresh: Box::new(fresh),
            view,
        },
    })
}

/// Why an item the fresh decision has due waits all the same.
enum Hold {
    /// An envelope a stored pointer names: kept.
    PointerNamesIt,
    /// Its requester's catalog moved since the first read: deferred.
    Moved,
}

/// Whether `item`, due on `fresh`, waits all the same (see [`Hold`]).
fn held(item: &Item, fresh: &Snapshot, baseline: &Pointers) -> Option<Hold> {
    // An envelope any stored pointer names stays, even one in `S` (a
    // subject being deleted, whose pointers are outside `C`): its pointer
    // delete may have failed this run. Deleting the index record a `/2`
    // pointer names would make every later strict read fail ("no index
    // record"), this run's final read and every sweep and `claim-owners`
    // after it. The next run retries the subject first.
    if let Item::Envelope(hash) = item
        && fresh
            .catalogs
            .pointers
            .iter()
            .any(|p| &p.catalog_hash == hash)
    {
        return Some(Hold::PointerNamesIt);
    }
    let current = Pointers::of(&fresh.catalogs);
    requesters(item, fresh)
        .iter()
        .any(|subject| baseline.moved(subject, &current))
        .then_some(Hold::Moved)
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

/// Delete exactly the `listed` versions of the item's objects, key by key
/// in order ([`due_keys`]), then mark its requests `deleted` at `now`: the
/// fresh records, so nothing cancelled meanwhile comes back. The first
/// failure stops the item.
async fn delete_item<O: ObjectStore>(
    store: &O,
    item: &Item,
    fresh: &Snapshot,
    listed: &Listed,
    baseline: &mut Pointers,
    now: i64,
) -> anyhow::Result<()> {
    listed.delete(store, baseline).await?;
    let requests = &fresh.requests;
    match item {
        Item::Recording {
            hash,
            requests: keys,
        } => {
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
            let mut r = requests
                .subjects
                .get(sub)
                .with_context(|| format!("{} vanished", subject_key(sub)))?
                .clone();
            (r.state, r.deleted_at) = (State::Deleted, Some(now));
            put_json(store, &subject_key(sub), &r).await?;
        }
        Item::Envelope(hash) => {
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

/// Spec 3.4 step 7: verify each tombstoned item whose newest tombstone is
/// at least [`VERIFY_AFTER`] old (any in-flight push, backfill or publish
/// has finished by then), in [`in_deletion_order`]. A tombstone's age, and
/// the delete it measures from, is its record's own write time (S3's
/// `LastModified`), not its `deletedAt`: that is the run's start, on the
/// operator's clock, and a long run deletes items well after it. Its
/// objects are the versions of its keys that aren't delete markers: a
/// recording's [`RECORDING_OBJECTS`], an envelope's [`ENVELOPE_OBJECTS`],
/// a subject's pointer keys (both forms of it). In the spec's order:
/// 1. one a new push or publish writes ([`PUSHED_OBJECTS`],
///    [`PUBLISHED_OBJECTS`], a pointer) written more than [`VERIFY_AFTER`]
///    after the delete is fresh: forget the tombstones, keep everything;
/// 2. a recording in `L`, or an envelope in `C`: forget them, keep the
///    objects. `L` and `C` leave out a deleted subject's late pointers
///    ([`late_pointers`]);
/// 3. any other object came back in flight: re-check the item on a fresh
///    read as step 6 does ([`deletable_again`]; a push after the drop
///    doesn't hold it here, owner record or not), then delete again
///    exactly the versions and markers listed here, before that read
///    ([`again`]), keeping the tombstones; or keep everything, and say
///    why;
/// 4. no object: forget them.
///
/// A subject's tombstone is not forgotten while an envelope request of
/// that owner is pending and the owner's catalog block stands: it releases
/// those envelopes from a hidden catalog then (`due::everything_requested`).
/// With the block lifted it releases nothing, and goes.
///
/// It reads the bucket again first: with `delete`, the requests and their
/// write times too; in a dry run, which wrote nothing, it takes
/// `unwritten` (the folded and observed requests, and the first read's
/// write times) instead, and changes nothing. A recording's tombstones
/// (`recordings/` and `operator/`, of any subject) are verified together,
/// by hash. `Err` when a read fails; a failed delete is reported and the
/// run goes on.
async fn verify_tombstones<O: ObjectStore>(
    store: &O,
    delete: bool,
    unwritten: (&Requests, &BTreeMap<String, i64>),
    baseline: &mut Pointers,
    now: i64,
    report: &mut Report,
) -> anyhow::Result<()> {
    let read = snapshot::read(store)
        .await
        .context("the verify read failed")?;
    let (requests, written) = if delete {
        (&read.requests, &read.request_written)
    } else {
        unwritten
    };
    // For rule 2 only. A pointer rule 3 deletes again (now, or once its
    // subject's tombstone is old enough) lists and names nothing: were its
    // recordings and envelope forgotten here, their objects would outlive
    // it with no request left to delete them.
    let late = late_pointers(store, requests, written, &read.moderation).await?;
    let view = due::view_except(&read.catalogs, requests, &read.moderation, &late);
    let mut groups: Vec<Tombstones> = tombstones(requests, written)
        .into_iter()
        .filter(|t| {
            t.written
                .is_some_and(|w| w.saturating_add(VERIFY_AFTER) <= now)
        })
        .collect();
    groups.sort_by_cached_key(|t| deletion_order(&t.item));

    for group in &groups {
        let id = group.item.id();
        let listed = tombstoned(store, &group.item)
            .await
            .with_context(|| format!("verifying {id}"))?;
        let objects: Vec<&VersionInfo> = listed
            .versions
            .iter()
            .filter(|v| !v.delete_marker)
            .collect();
        let written_by = group
            .written
            .unwrap_or(i64::MAX)
            .saturating_add(VERIFY_AFTER);
        let fresh = objects
            .iter()
            .any(|v| v.modified > written_by && pushed_or_published(&group.item, &v.key));
        let forget = if fresh {
            Some(FRESH)
        } else {
            match &group.item {
                Item::Recording { hash, .. } if view.l.contains(hash) => Some(LISTED_AGAIN),
                Item::Envelope(hash) if view.c.contains(hash) => Some(CURRENT_AGAIN),
                _ if objects.is_empty() => None,
                _ => {
                    again(
                        store, delete, group, &listed, &read, requests, baseline, now, report,
                    )
                    .await?;
                    continue;
                }
            }
        };
        // A subject has no rule 2: this holds rules 1 and 4.
        if let Item::Subject(sub) = &group.item
            && read.moderation.catalog_blocked.contains(sub)
            && envelopes_pending(requests, &read.catalogs, sub)
        {
            report.kept(&id, ENVELOPES_PENDING);
            continue;
        }
        if delete && let Err(e) = remove(store, group).await {
            report.failed(&id, &e);
            continue;
        }
        match forget {
            Some(why) => report.forgot(&id, why),
            None => report.verified(&id),
        }
    }
    Ok(())
}

/// One item's tombstones, verified together.
struct Tombstones {
    /// What they cover. A recording's `requests` are their keys.
    item: Item,
    tombstones: Vec<Tombstone>,
    /// When the newest of their records was written (S3's clock); `None`
    /// when one's write time is unknown, and then the item waits.
    written: Option<i64>,
}

/// One tombstone, by the names in its request key.
enum Tombstone {
    Recording(String, String),
    Operator(String, String),
    Envelope(String),
    Subject(String),
}

impl Tombstone {
    fn key(&self) -> String {
        match self {
            Tombstone::Recording(sub, hash) => recording_key(sub, hash),
            Tombstone::Operator(sub, hash) => operator_key(sub, hash),
            Tombstone::Envelope(hash) => envelope_key(hash),
            Tombstone::Subject(sub) => subject_key(sub),
        }
    }

    /// How [`Decision::kept`] names its request.
    fn id(&self) -> String {
        match self {
            Tombstone::Recording(sub, hash) => format!("recording {sub}/{hash}"),
            Tombstone::Operator(sub, hash) => format!("operator {sub}/{hash}"),
            Tombstone::Envelope(hash) => format!("envelope {hash}"),
            Tombstone::Subject(sub) => format!("subject {sub}"),
        }
    }

    /// Make its request in `requests` pending again.
    fn revive(&self, requests: &mut Requests) {
        let names = |sub: &String, hash: &String| (sub.clone(), hash.clone());
        let request = match self {
            Tombstone::Recording(sub, hash) => requests
                .recordings
                .get_mut(&names(sub, hash))
                .map(|r| (&mut r.state, &mut r.deleted_at)),
            Tombstone::Operator(sub, hash) => requests
                .operator
                .get_mut(&names(sub, hash))
                .map(|r| (&mut r.state, &mut r.deleted_at)),
            Tombstone::Envelope(hash) => requests
                .envelopes
                .get_mut(hash)
                .map(|r| (&mut r.state, &mut r.deleted_at)),
            Tombstone::Subject(sub) => requests
                .subjects
                .get_mut(sub)
                .map(|r| (&mut r.state, &mut r.deleted_at)),
        };
        if let Some((state, deleted_at)) = request {
            (*state, *deleted_at) = (State::Pending, None);
        }
    }
}

/// Every tombstone in `requests`, by item: a recording's by hash, of any
/// subject and either kind. `written` holds each record's write time, by
/// key.
fn tombstones(requests: &Requests, written: &BTreeMap<String, i64>) -> Vec<Tombstones> {
    let mut recordings: BTreeMap<&String, Vec<Tombstone>> = BTreeMap::new();
    for ((sub, hash), r) in &requests.recordings {
        if r.state == State::Deleted {
            let t = Tombstone::Recording(sub.clone(), hash.clone());
            recordings.entry(hash).or_default().push(t);
        }
    }
    for ((sub, hash), r) in &requests.operator {
        if r.state == State::Deleted {
            let t = Tombstone::Operator(sub.clone(), hash.clone());
            recordings.entry(hash).or_default().push(t);
        }
    }
    let group = |item: Item, tombstones: Vec<Tombstone>| Tombstones {
        item,
        written: tombstones
            .iter()
            .map(|t| written.get(&t.key()).copied())
            .collect::<Option<Vec<i64>>>()
            .and_then(|times| times.into_iter().max()),
        tombstones,
    };
    let mut out = Vec::new();
    for (hash, tombstones) in recordings {
        let mut keys: Vec<String> = tombstones.iter().map(Tombstone::key).collect();
        keys.sort();
        let item = Item::Recording {
            hash: hash.clone(),
            requests: keys,
        };
        out.push(group(item, tombstones));
    }
    for (hash, r) in &requests.envelopes {
        if r.state == State::Deleted {
            let t = Tombstone::Envelope(hash.clone());
            out.push(group(Item::Envelope(hash.clone()), vec![t]));
        }
    }
    for (sub, r) in &requests.subjects {
        if r.state == State::Deleted {
            let t = Tombstone::Subject(sub.clone());
            out.push(group(Item::Subject(sub.clone()), vec![t]));
        }
    }
    out
}

/// Every version and delete marker of a tombstoned `item`'s keys: a
/// recording's and an envelope's [`object_keys`], a subject's pointer keys
/// whose `<sub>` is canonically it (both `arkavo:<uuid>` and `<uuid>`), in
/// key order. Its objects are the versions that aren't markers.
async fn tombstoned<O: ObjectStore>(store: &O, item: &Item) -> anyhow::Result<Listed> {
    let Item::Subject(sub) = item else {
        return list_keys(store, object_keys(item)).await;
    };
    let mut versions = list_versions(store, POINTERS).await?;
    versions.retain(|v| pointer_subject(&v.key) == Some(sub.as_str()));
    let keys: BTreeSet<String> = versions.iter().map(|v| v.key.clone()).collect();
    Ok(Listed {
        keys: keys.into_iter().collect(),
        versions,
    })
}

/// Whether `key`, one of `item`'s objects, is one a new push or publish
/// writes (rule 1): a recording's [`PUSHED_OBJECTS`], an envelope's
/// [`PUBLISHED_OBJECTS`], a subject's pointers.
fn pushed_or_published(item: &Item, key: &str) -> bool {
    let prefixes: &[&str] = match item {
        Item::Recording { .. } => &PUSHED_OBJECTS,
        Item::Envelope(_) => &PUBLISHED_OBJECTS,
        Item::Subject(_) => &[POINTERS],
    };
    prefixes.iter().any(|p| key.starts_with(p))
}

/// A recording's or an envelope's object keys, in the order they are
/// deleted; none for a subject.
fn object_keys(item: &Item) -> Vec<String> {
    let (prefixes, hash): (&[&str], _) = match item {
        Item::Recording { hash, .. } => (&RECORDING_OBJECTS, hash),
        Item::Envelope(hash) => (&ENVELOPE_OBJECTS, hash),
        Item::Subject(_) => return Vec::new(),
    };
    prefixes.iter().map(|p| format!("{p}{hash}")).collect()
}

/// The keys of the pointers rule 3 deletes again, now or once their
/// subject's tombstone is [`VERIFY_AFTER`] old: those of a subject with a
/// `subjects/` tombstone of any age whose catalog block stands, whose
/// current version was written by [`VERIFY_AFTER`] after the tombstone was
/// (`written`, by key: an in-flight publish). One written later is a
/// returning creator's, and counts. A tombstone whose write time is
/// unknown makes every pointer of its subject late: rule 2 then forgets
/// nothing on their account.
async fn late_pointers<O: ObjectStore>(
    store: &O,
    requests: &Requests,
    written: &BTreeMap<String, i64>,
    moderation: &ModerationView,
) -> anyhow::Result<BTreeSet<String>> {
    let written_by: BTreeMap<&str, i64> = requests
        .subjects
        .iter()
        .filter(|(sub, r)| {
            r.state == State::Deleted && moderation.catalog_blocked.contains(sub.as_str())
        })
        .map(|(sub, _)| {
            let by = written
                .get(&subject_key(sub))
                .map_or(i64::MAX, |w| w.saturating_add(VERIFY_AFTER));
            (sub.as_str(), by)
        })
        .collect();
    if written_by.is_empty() {
        return Ok(BTreeSet::new());
    }
    let pointers = store
        .list(POINTERS)
        .await
        .with_context(|| format!("listing {POINTERS} failed"))?;
    Ok(pointers
        .into_iter()
        .filter(|p| {
            pointer_subject(&p.key)
                .and_then(|sub| written_by.get(sub))
                .is_some_and(|by| p.modified <= *by)
        })
        .map(|p| p.key)
        .collect())
}

/// A pointer key's subject, canonical; `None` for a name that isn't one.
fn pointer_subject(key: &str) -> Option<&str> {
    key.strip_prefix(POINTERS)
        .filter(|sub| valid_subject(sub))
        .map(canonical_subject)
}

/// Whether an envelope request of `subject` (canonical) is pending.
fn envelopes_pending(requests: &Requests, catalogs: &Catalogs, subject: &str) -> bool {
    requests
        .envelopes
        .values()
        .any(|r| r.state == State::Pending && due::envelope_owner(r, catalogs) == Some(subject))
}

/// Remove every version of each of `group`'s tombstones.
async fn remove<O: ObjectStore>(store: &O, group: &Tombstones) -> anyhow::Result<()> {
    for t in &group.tombstones {
        delete_record(store, &t.key()).await?;
    }
    Ok(())
}

/// Rule 3: objects came back, none of them fresh (each written by an hour
/// after the delete, or an outboard, which never is), and `listed` holds
/// them, listed before this fresh read. With `delete`, re-check the item
/// on a fresh read, as step 6 does (but for its push check,
/// [`pushed_again`]), then delete again exactly the `listed` versions
/// (markers included), a recording's and an envelope's keys in order, a
/// subject's pointer keys: one written since the listing stays, and the
/// next run judges it. In a dry run, re-check it on `read` and
/// `requests`. The tombstones stay as they are. `Err` when the fresh read
/// fails.
#[allow(clippy::too_many_arguments)]
async fn again<O: ObjectStore>(
    store: &O,
    delete: bool,
    group: &Tombstones,
    listed: &Listed,
    read: &Snapshot,
    requests: &Requests,
    baseline: &mut Pointers,
    now: i64,
    report: &mut Report,
) -> anyhow::Result<()> {
    let id = group.item.id();
    if !delete {
        match deletable_again(read, requests, group, baseline, now) {
            Ok(()) => report.recreated(&id),
            Err(why) => report.kept(&id, &why),
        }
        return Ok(());
    }
    let fresh = snapshot::read(store)
        .await
        .with_context(|| format!("re-checking {id}"))?;
    if let Err(why) = deletable_again(&fresh, &fresh.requests, group, baseline, now) {
        report.kept(&id, &why);
        return Ok(());
    }
    match listed.delete(store, baseline).await {
        Ok(()) => report.recreated(&id),
        Err(e) => report.failed(&id, &e),
    }
    Ok(())
}

/// Step 6's re-check for a tombstoned item, on `fresh` and its
/// `requests`: whether [`due::due`] has it due with its tombstones pending
/// again, and [`held`] doesn't hold it; else why not.
///
/// Its owner record's absence doesn't count against it: the sweep deleted
/// that record with the recording. Only one naming another account (whose
/// push it is) keeps it. "No owner record" is the last rule a recording's
/// request is kept for ([`due::NO_OWNER_RECORD`]), so a tombstone kept for
/// it passes every other. Step 6's push check ([`pushed_again`]) is no
/// part of it: every write that recreates the recording is after the drop,
/// and one within the hour after the tombstone is in flight (ruling 36),
/// deleted again rather than given a new grace.
fn deletable_again(
    fresh: &Snapshot,
    requests: &Requests,
    group: &Tombstones,
    baseline: &Pointers,
    now: i64,
) -> Result<(), String> {
    let mut revived = requests.clone();
    for t in &group.tombstones {
        t.revive(&mut revived);
    }
    let view = due::view(&fresh.catalogs, &revived, &fresh.moderation);
    let decision = due::due(fresh, &revived, &view, now);
    let id = group.item.id();
    let item = match decision.due.iter().find(|i| i.id() == id) {
        Some(item) => item,
        None => {
            let ids: Vec<String> = group.tombstones.iter().map(Tombstone::id).collect();
            let why: Vec<&str> = decision
                .kept
                .iter()
                .filter(|(kept, _)| ids.contains(kept))
                .map(|(_, why)| why.as_str())
                .collect();
            if !why.contains(&due::NO_OWNER_RECORD) {
                return Err(why.first().copied().unwrap_or(NO_LONGER_DUE).to_string());
            }
            &group.item
        }
    };
    match held(item, fresh, baseline) {
        Some(Hold::PointerNamesIt) => Err(POINTER_NAMES_IT.to_string()),
        Some(Hold::Moved) => Err(CATALOG_CHANGED.to_string()),
        None => Ok(()),
    }
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

async fn list_versions<O: ObjectStore>(
    store: &O,
    prefix: &str,
) -> anyhow::Result<Vec<VersionInfo>> {
    store
        .list_versions(prefix)
        .await
        .with_context(|| format!("listing {prefix} failed"))
}

/// Delete every version of a record the sweep writes or folds (a request,
/// a transition), whatever is there now. An item's objects go by
/// [`Listed::delete`] instead: exactly the versions judged.
async fn delete_record<O: ObjectStore>(store: &O, key: &str) -> anyhow::Result<()> {
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
    use crate::catalog_v2::test_support::{bundle, pointer_bytes};
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
    /// When [`pushed`] writes a recording: before any drop here.
    const PUSHED_AT: i64 = NOW - 3 * GRACE;

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    /// A bucket whose clock reads `NOW`, the time the runs here pass: what
    /// a run writes, its tombstones included, is stamped as S3 would.
    fn bucket() -> MemObjects {
        let m = MemObjects::default();
        m.set_now(NOW);
        m
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

    /// [`recording`] as pushed at [`PUSHED_AT`], before any drop here, so
    /// a drop's request can delete it; the clock is left as it was.
    fn pushed(m: &MemObjects, hash: &str, owner: &str) {
        let now = m.now();
        m.set_now(PUSHED_AT);
        recording(m, hash, owner);
        m.set_now(now);
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
        pushed(m, hash, U);
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
        let m = bucket();
        let (p, q) = (h("a1"), h("a2"));
        // Folding writes a request and an envelope request, and deletes
        // two transitions.
        dropped(&m, &p);
        // A stored request, due.
        pushed(&m, &q, U);
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
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
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
        let m = bucket();
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
        let m = bucket();
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
        let m = bucket();
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
        let m = bucket();
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
        let m = bucket();
        let (p, q) = (h("a1"), h("a2"));
        for hash in [&p, &q] {
            pushed(&m, hash, U);
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
        let m = bucket();
        dropped(&m, &h("a1"));
        pushed(&m, &h("a2"), U);
        request(&m, U, &h("a2"), NOW - GRACE);
        let garbage = "deletion-requests/subjects/u9";
        m.insert(garbage, "not json");
        let before = versions(&m).await;

        let Aborted { report, error } = sweep(&m, true, NOW).await.unwrap_err();
        assert!(format!("{error:#}").contains(garbage), "{error:#}");
        assert_eq!(
            report,
            Report {
                dry_run: false,
                ..Report::default()
            },
            "an empty report"
        );
        assert_eq!(versions(&m).await, before);
        assert!(m.deletes().is_empty());
    }

    /// The document's owner is read before anything is written, so a
    /// failed read of it aborts with nothing written either.
    #[tokio::test]
    async fn an_unreadable_document_owner_aborts_before_any_write() {
        let m = bucket();
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
        let m = bucket();
        let p = h("a1");
        let [first, second] = dropped(&m, &p);
        m.fail_on(&recording_key(U, &p), Op::Put);

        let Aborted { report, error } = sweep(&m, true, NOW).await.unwrap_err();
        assert!(
            format!("{error:#}").contains(&recording_key(U, &p)),
            "{error:#}"
        );
        assert!(report.lines.is_empty(), "{report}");
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
        let m = bucket();
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
        assert!(
            has(
                &report,
                &format!(
                    "deleted transition {U}/{}: lost its publish",
                    transition_name(2, &h("ee"))
                )
            ),
            "{report}"
        );
    }

    #[tokio::test]
    async fn an_observed_envelope_takes_its_documents_owner() {
        let m = bucket();
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

    /// The routine leftover of a publish whose writes stopped after its
    /// index record and transition: no document, outboard or pointer. The
    /// fold keeps its transition, which no pointer reaches. Its envelope is
    /// observed as untracked with no owner of its own (no document to name
    /// one), its owner is its index record's, and it is deleted once its
    /// grace has passed. Nothing aborts.
    #[tokio::test]
    async fn an_index_record_left_alone_is_deleted_after_grace() {
        let m = bucket();
        let base_index = publish_2(&m, U, 1, b"doc-u", &[]);
        let e = catalog(b"doc-left");
        put(
            &m,
            &format!("catalog-indexes/{e}"),
            index_record(&arkavo(U), &[]),
        );
        // Its transition: seq 2 over `U`'s stored seq 1.
        let digest = |seq, doc: &[u8], index: &str| {
            hex::encode(Sha256::digest(pointer_bytes(U, seq, doc, Some(index))))
        };
        let left_index = crate::creator_catalog::index_hash(&[]);
        let pointer = digest(2, b"doc-left", &left_index);
        let name = transition_name(2, &pointer);
        put(
            &m,
            &transition_key(U, &name),
            Transition {
                subject: U.into(),
                seq: 2,
                catalog_hash: e.clone(),
                pointer,
                base: Some(TransitionBase {
                    seq: 1,
                    catalog_hash: catalog(b"doc-u"),
                    pointer: digest(1, b"doc-u", &base_index),
                }),
                at: NOW,
                dropped: vec![],
                added: vec![],
            },
        );
        let kept_transition = |why: &str| format!("kept transition {U}/{name}: {why}");

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 0, "{report}");
        assert!(
            has(&report, &kept_transition("younger than grace")),
            "{report}"
        );
        assert!(
            has(&report, &format!("kept envelope {e}: within grace")),
            "{report}"
        );
        let observed: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
        assert_eq!(
            observed,
            EnvelopeRequest {
                hash: e.clone(),
                owner: None,
                superseded_at: NOW,
                source: Source::Observed,
                state: State::Pending,
                deleted_at: None,
            }
        );

        // A grace later: due, its owner the index record's (canonical). An
        // unknown owner would keep it ("unknown owner").
        let later = NOW + GRACE;
        m.set_now(later);
        let report = sweep(&m, true, later).await.unwrap();
        assert_eq!(report.failures, 0, "{report}");
        assert!(
            has(&report, &kept_transition("seq above the current pointer")),
            "{report}"
        );
        assert!(m.get(&transition_key(U, &name)).await.unwrap().is_some());
        assert!(has(&report, &format!("deleted envelope {e}")), "{report}");
        assert_eq!(m.deletes(), envelope_keys(&e));
        assert!(gone(&m, &format!("catalog-indexes/{e}")).await);
        let r: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
        assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(later)));
        // The current envelope's index record stays.
        assert!(!gone(&m, &format!("catalog-indexes/{}", catalog(b"doc-u"))).await);
        snapshot::read(&m).await.unwrap();
    }

    /// A subject's pointers go first, then recordings, then envelopes.
    /// Deleting the subject's own pointers is no catalog change: its
    /// recordings and envelopes are deleted in the same run.
    #[tokio::test]
    async fn items_go_subject_then_recording_then_envelope() {
        let m = bucket();
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
        let m = bucket();
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

    /// A request past its grace for an envelope a stored pointer names (in
    /// `C`) deletes nothing of it: not its document, outboard or index
    /// record. The node's `GET` and `PUT` each read a pointer whose catalog
    /// has no index record as one from before envelopes, on their own
    /// paths, so they agree only while no current envelope loses its index
    /// record. Both a `/2` pointer and one from before envelopes.
    #[tokio::test]
    async fn a_due_request_for_a_current_envelope_deletes_nothing() {
        let m = bucket();
        // `U`'s `/2` catalog: its index record, pointer, document, outboard.
        publish_2(&m, U, 1, b"doc-u", &[]);
        let e = catalog(b"doc-u");
        m.insert_with_owner(&format!("catalog-documents/{e}"), "doc-u", U);
        m.insert(&format!("catalog-outboards/{e}"), "outboard");
        // `U2`'s pointer from before envelopes: no index record.
        let old = catalog(b"doc-old");
        m.insert(
            &format!("{POINTERS}{U2}"),
            serde_json::to_vec(&bundle(U2, 3, b"doc-old", None)).unwrap(),
        );
        m.insert_with_owner(&format!("catalog-documents/{old}"), "doc-old", U2);
        envelope_request(&m, &e, U, NOW - GRACE);
        envelope_request(&m, &old, U2, NOW - GRACE);
        let before = versions(&m).await;

        let report = sweep(&m, true, NOW).await.unwrap();
        for hash in [&e, &old] {
            assert!(
                has(&report, &format!("kept envelope {hash}: still current")),
                "{report}"
            );
            let r: EnvelopeRequest = record(&m, &envelope_key(hash)).await;
            assert_eq!(r.state, State::Pending);
        }
        assert_eq!((report.deleted, report.failures), (0, 0), "{report}");
        assert!(m.deletes().is_empty(), "{report}");
        assert_eq!(versions(&m).await, before, "every object and version");
        snapshot::read(&m).await.unwrap();
    }

    /// Deletion is per hash: a recording due under one request marks every
    /// pending request for it deleted, of any subject, due on its own or
    /// not. The block that made it due is kept.
    #[tokio::test]
    async fn a_deleted_recording_marks_every_request_for_it() {
        let m = bucket();
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
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
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
        let m = bucket();
        let p = h("a1");
        let [_, second] = dropped(&m, &p);
        let key = recording_key(U, &p);
        m.on_before_delete(&second.key, move |m| m.fail_on(&key, Op::Get));

        let Aborted { error, .. } = sweep(&m, true, NOW).await.unwrap_err();
        assert!(
            format!("{error:#}").contains(&recording_key(U, &p)),
            "{error:#}"
        );
        for key in recording_keys(&p) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
    }

    /// A run that aborts part way still reports what it did: here the
    /// re-check of the second item fails after the first was deleted.
    #[tokio::test]
    async fn an_abort_keeps_the_lines_of_what_it_did() {
        let m = bucket();
        let (p, q) = (h("a1"), h("a2"));
        for hash in [&p, &q] {
            pushed(&m, hash, U);
            request(&m, U, hash, NOW - GRACE);
        }
        let key = recording_key(U, &q);
        m.on_before_delete(&format!("blobs/{p}"), move |m| m.fail_on(&key, Op::Get));

        let Aborted { report, error } = sweep(&m, true, NOW).await.unwrap_err();
        assert_eq!(report.lines, [format!("deleted recording {p}")], "{report}");
        assert_eq!(report.deleted, 1);
        assert!(
            format!("{error:#}").contains(&recording_key(U, &q)),
            "{error:#}"
        );
        for key in recording_keys(&q) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &q)).await;
        assert_eq!(r.state, State::Pending);
    }

    /// The final read (spec 3.4 step 8) comes after every delete: a failed
    /// one is a failure of the run, not an abort.
    #[tokio::test]
    async fn a_failed_final_read_is_a_failure() {
        let m = bucket();
        let (p, q) = (h("a1"), h("a2"));
        // A clean tombstone, verified; just before its removal, the next
        // read of a request fails.
        m.set_now(NOW - VERIFY_AFTER);
        put(
            &m,
            &recording_key(U, &p),
            RecordingRequest {
                hash: p.clone(),
                subject: U.into(),
                requested_at: NOW - 2 * GRACE,
                seq: 1,
                state: State::Deleted,
                deleted_at: Some(NOW - VERIFY_AFTER),
            },
        );
        m.set_now(NOW);
        request(&m, U, &q, NOW);
        let key = recording_key(U, &q);
        m.on_before_delete(&recording_key(U, &p), move |m| m.fail_on(&key, Op::Get));

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 1, "{report}");
        let failed = "failed final read: ";
        let line = report
            .lines
            .iter()
            .find(|l| l.starts_with(failed))
            .unwrap_or_else(|| panic!("{report}"));
        assert!(line.contains(&recording_key(U, &q)), "{line}");
        assert!(has(&report, &format!("verified recording {p}")), "{report}");
        assert_eq!(
            report.to_string().lines().last(),
            Some("0 deleted, 1 kept, 0 deferred, 1 failed")
        );
    }

    /// A transition that lost its publish is deleted unfolded, with a line
    /// (not counted: it is no item).
    #[tokio::test]
    async fn a_lost_transition_is_reported() {
        let m = bucket();
        publish_2(&m, U, 2, b"doc-2", &[]);
        let name = transition_name(2, &h("ee"));
        put(
            &m,
            &transition_key(U, &name),
            Transition {
                subject: U.into(),
                seq: 2,
                catalog_hash: catalog(b"lost"),
                pointer: h("ee"),
                base: None,
                at: NOW - 2 * GRACE,
                dropped: vec![],
                added: vec![],
            },
        );

        let report = sweep(&m, false, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!(
                "would delete transition {U}/{name}: lost its publish\n\
                 0 would delete, 0 kept, 0 deferred, 0 failed"
            )
        );
        assert!(m.deletes().is_empty());

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!(
                "deleted transition {U}/{name}: lost its publish\n\
                 0 deleted, 0 kept, 0 deferred, 0 failed"
            )
        );
        assert_eq!(m.deletes(), [transition_key(U, &name)]);
    }

    /// Every version outside `deletion-requests/`: what recordings and
    /// envelopes hold.
    async fn stored(m: &MemObjects) -> Vec<VersionInfo> {
        versions(m)
            .await
            .into_iter()
            .filter(|v| !v.key.starts_with("deletion-requests/"))
            .collect()
    }

    /// A drop's request left pending after its recording was deleted (the
    /// tombstone write failed) when the owner pushes the recording again,
    /// listed nowhere: the push restarts the grace from its own write, and
    /// a grace later, still unlisted, the push is deleted.
    #[tokio::test]
    async fn a_push_after_the_drop_restarts_a_stale_requests_grace() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        m.fail_on(&recording_key(U, &p), Op::Put);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 1, "{report}");
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Pending);

        // The same account pushes it again.
        m.set_now(NOW + 10);
        recording(&m, &p, U);
        let push = stored(&m).await;

        m.set_now(NOW + 20);
        let report = sweep(&m, true, NOW + 20).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("pushed again recording {p}\n0 deleted, 1 kept, 0 deferred, 0 failed")
        );
        assert_eq!(stored(&m).await, push, "every version of the push");
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(
            (r.state, r.requested_at, r.seq),
            (State::Pending, NOW + 10, 1),
            "the grace restarts from the push"
        );
        assert_eq!(m.deletes(), recording_keys(&p));

        // Within the new grace: kept. A grace after the push: deleted.
        let report = sweep(&m, true, NOW + 20).await.unwrap();
        assert_eq!(
            report.lines,
            [format!("kept recording {U}/{p}: within grace")],
            "{report}"
        );
        let later = NOW + 10 + GRACE;
        m.set_now(later);
        let report = sweep(&m, true, later).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("deleted recording {p}\n1 deleted, 0 kept, 0 deferred, 0 failed")
        );
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(later)));
    }

    /// The same when the deletes stopped before the owner record: the push
    /// writes a new blob and manifest, and the old owner record stays.
    #[tokio::test]
    async fn a_push_after_a_partial_delete_restarts_the_grace() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        let owner = format!("moderation/publishers/{p}");
        m.fail_on(&owner, Op::Delete);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(report.failures, 1, "{report}");
        assert!(gone(&m, &format!("blobs/{p}")).await);
        assert!(m.get(&owner).await.unwrap().is_some());

        m.set_now(NOW + 10);
        m.insert(&format!("outboards/{p}"), "outboard");
        m.insert(&format!("blobs/{p}"), "blob");
        m.insert(&format!("manifests/{p}"), "{}");
        let push = stored(&m).await;

        m.set_now(NOW + 20);
        let report = sweep(&m, true, NOW + 20).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("pushed again recording {p}\n0 deleted, 1 kept, 0 deferred, 0 failed")
        );
        assert_eq!(stored(&m).await, push);
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW + 10));
    }

    /// A routine re-push while the blob is still stored writes only a new
    /// manifest (and outboard, which never counts): that too restarts the
    /// grace, and cancels nothing.
    #[tokio::test]
    async fn a_new_manifest_alone_restarts_the_grace() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        m.set_now(NOW - 50);
        m.insert(&format!("manifests/{p}"), "{}");
        m.set_now(NOW);
        let before = stored(&m).await;

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("pushed again recording {p}\n0 deleted, 1 kept, 0 deferred, 0 failed")
        );
        assert_eq!(stored(&m).await, before);
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW - 50));

        let later = NOW - 50 + GRACE;
        m.set_now(later);
        let report = sweep(&m, true, later).await.unwrap();
        assert!(has(&report, &format!("deleted recording {p}")), "{report}");
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
    }

    /// Only a listing cancels a drop: a push restarts its grace, and a
    /// publish that lists the hash again then cancels the request.
    #[tokio::test]
    async fn a_listing_after_a_push_cancels_the_drop() {
        let m = bucket();
        let p = h("a1");
        let [_, second] = dropped(&m, &p);
        m.set_now(NOW - 100);
        recording(&m, &p, U);
        m.set_now(NOW);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(
            has(&report, &format!("pushed again recording {p}")),
            "{report}"
        );
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW - 100));

        publish(
            &m,
            U,
            3,
            b"doc-3",
            &[&p],
            Some(&second),
            NOW + 10,
            &[],
            &[&p],
        );
        m.set_now(NOW + 20);
        let report = sweep(&m, true, NOW + 20).await.unwrap();
        assert_eq!(report.failures, 0, "{report}");
        assert!(gone(&m, &recording_key(U, &p)).await, "cancelled: {report}");
        for key in recording_keys(&p) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
    }

    /// A push moves `requestedAt` forward only, and the fold never moves it
    /// back: a drop folded later whose `at` is older (here from the
    /// subject's other pointer key) keeps the push's time.
    #[tokio::test]
    async fn the_fold_keeps_a_requested_at_a_push_moved() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        m.set_now(NOW - 100);
        recording(&m, &p, U);
        m.set_now(NOW);
        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(
            has(&report, &format!("pushed again recording {p}")),
            "{report}"
        );

        publish(
            &m,
            &arkavo(U),
            1,
            b"doc-a",
            &[],
            None,
            NOW - 2000,
            &[&p],
            &[],
        );
        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(
            has(&report, &format!("kept recording {U}/{p}: within grace")),
            "{report}"
        );
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW - 100));
    }

    /// A push that lands during the item's fresh read, after the listing
    /// the delete would use, is judged all the same: the pushed objects are
    /// listed again after the read, and it restarts the grace.
    #[tokio::test]
    async fn a_push_during_the_fresh_read_restarts_the_grace() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        // Folded and deleted after the first read: it arms a write inside
        // the item's fresh read, a routine re-push.
        let t = publish(&m, U, 1, b"doc-u", &[], None, PUSHED_AT, &[], &[]);
        let (key, hash) = (recording_key(U, &p), p.clone());
        m.on_before_delete(&t.key, move |m| {
            m.on_before_get(&key, move |m| {
                m.insert(&format!("outboards/{hash}"), "outboard");
                m.insert(&format!("manifests/{hash}"), "{}");
            });
        });

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(
            has(&report, &format!("pushed again recording {p}")),
            "{report}"
        );
        for key in recording_keys(&p) {
            assert!(m.get(&key).await.unwrap().is_some(), "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW));
    }

    /// A subject's pointer version written during the item's fresh read,
    /// after its listing, survives the delete.
    #[tokio::test]
    async fn a_pointer_written_during_the_fresh_read_survives() {
        let m = bucket();
        let t = publish(&m, U, 1, b"doc-u", &[], None, NOW - 10, &[], &[]);
        catalog_block(&m, U);
        subject_request(&m, U);
        let pointer = format!("catalog-pointers/{U}");
        let body = m.get(&pointer).await.unwrap().unwrap();
        let listed = ids(&m, &pointer).await;
        let (key, again) = (subject_key(U), pointer.clone());
        m.on_before_delete(&t.key, move |m| {
            m.on_before_get(&key, move |m| m.insert(&again, body));
        });

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted subject {U}")), "{report}");
        let left = ids(&m, &pointer).await;
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(!listed.contains(&left[0]), "{left:?}");
        snapshot::read(&m).await.unwrap();
    }

    /// An envelope object's version written during the item's fresh read,
    /// after its listing, survives the delete.
    #[tokio::test]
    async fn an_envelope_object_written_during_the_fresh_read_survives() {
        let m = bucket();
        let t = publish(&m, U, 2, b"doc-2", &[], None, NOW - 10, &[], &[]);
        let e = envelope(&m, U, b"doc-1");
        envelope_request(&m, &e, U, NOW - GRACE);
        let document = format!("catalog-documents/{e}");
        let listed = ids(&m, &document).await;
        let (key, again) = (envelope_key(&e), document.clone());
        m.on_before_delete(&t.key, move |m| {
            m.on_before_get(&key, move |m| m.insert(&again, "doc-1"));
        });

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted envelope {e}")), "{report}");
        let left = ids(&m, &document).await;
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(!listed.contains(&left[0]), "{left:?}");
        for key in &envelope_keys(&e)[1..] {
            assert!(gone(&m, key).await, "{key}");
        }
    }

    /// The version IDs of exactly `key`.
    async fn ids(m: &MemObjects, key: &str) -> Vec<String> {
        m.list_versions(key)
            .await
            .unwrap()
            .into_iter()
            .filter(|v| v.key == key)
            .map(|v| v.version_id)
            .collect()
    }

    /// A delete marker listed with an item's versions is deleted with them.
    #[tokio::test]
    async fn a_listed_delete_marker_is_deleted() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        m.set_now(PUSHED_AT);
        m.delete_current(&format!("outboards/{p}"));
        m.set_now(NOW);
        request(&m, U, &p, NOW - GRACE);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted recording {p}")), "{report}");
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "no version or marker of {key}");
        }
    }

    /// An operator's scope-`hash` request deletes a recording pushed again
    /// after its owner's drop while the block stands, whatever the push.
    #[tokio::test]
    async fn a_scope_hash_request_still_deletes_a_push_again() {
        let m = bucket();
        let p = h("a1");
        recording(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        put(
            &m,
            &format!("moderation/blocks/{p}"),
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
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Deleted);
        let r: OperatorRequest = record(&m, &operator_key(U2, &p)).await;
        assert_eq!(r.state, State::Deleted);
    }

    /// A recording whose pushed objects are no newer than the drop (up to
    /// its own second) is deleted, and its request becomes a tombstone. An
    /// outboard written since is no push: the node writes one itself.
    #[tokio::test]
    async fn a_push_before_the_drop_is_deleted() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        m.set_now(NOW - GRACE);
        m.insert(&format!("manifests/{p}"), "{}");
        m.set_now(NOW - 10);
        m.insert(&format!("outboards/{p}"), "outboard");
        m.set_now(NOW);
        request(&m, U, &p, NOW - GRACE);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("deleted recording {p}\n1 deleted, 0 kept, 0 deferred, 0 failed")
        );
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(NOW)));
    }

    /// An item's delete removes exactly the versions listed before its
    /// re-check: one written after the listing (a push landing mid-delete)
    /// stays, for the tombstone's verification to judge.
    #[tokio::test]
    async fn a_version_written_after_the_listing_survives_the_delete() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        let blob = format!("blobs/{p}");
        let listed: Vec<String> = m
            .list_versions(&blob)
            .await
            .unwrap()
            .into_iter()
            .map(|v| v.version_id)
            .collect();
        let key = blob.clone();
        m.on_before_delete(&blob, move |m| m.insert(&key, "written meanwhile"));

        let report = sweep(&m, true, NOW).await.unwrap();
        assert!(has(&report, &format!("deleted recording {p}")), "{report}");
        let left = m.list_versions(&blob).await.unwrap();
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(!listed.contains(&left[0].version_id), "{left:?}");
        assert_eq!(
            m.get(&blob).await.unwrap(),
            Some(Bytes::from_static(b"written meanwhile"))
        );
        for key in &recording_keys(&p)[1..] {
            assert!(gone(&m, key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Deleted);
    }

    /// A dry run reports a recording pushed again since its drop, and
    /// writes nothing.
    #[tokio::test]
    async fn a_dry_run_reports_a_push_again() {
        let m = bucket();
        let (p, q) = (h("a1"), h("a2"));
        // Pushed now, after its drop.
        recording(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        pushed(&m, &q, U);
        request(&m, U, &q, NOW - GRACE);
        let before = versions(&m).await;

        let report = sweep(&m, false, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!(
                "pushed again recording {p}\nwould delete recording {q}\n\
                 1 would delete, 1 kept, 0 deferred, 0 failed"
            )
        );
        assert_eq!(versions(&m).await, before, "its grace isn't restarted");
        assert!(m.deletes().is_empty());
    }

    /// The listing at an item's re-check is a read: one that fails aborts
    /// the run before the item loses anything.
    #[tokio::test]
    async fn a_failed_listing_aborts() {
        let m = bucket();
        let p = h("a1");
        pushed(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        m.fail_on(&format!("blobs/{p}"), Op::List);

        let Aborted { report, error } = sweep(&m, true, NOW).await.unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("blobs/{p}")),
            "{error:#}"
        );
        assert!(report.lines.is_empty(), "{report}");
        assert!(m.deletes().is_empty());
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Pending);
    }

    /// A push after the drop restarts only the owner's drop: an operator's
    /// scope-`subject` request still deletes the recording, and marks the
    /// drop's request deleted with it. One not due is left as it was.
    #[tokio::test]
    async fn an_operator_request_still_deletes_a_push_again() {
        let operator = |m: &MemObjects, p: &str| {
            put(
                m,
                &operator_key(U, p),
                OperatorRequest {
                    hash: p.into(),
                    subject: U.into(),
                    requested_at: NOW - GRACE,
                    reason: "account closed".into(),
                    scope: Scope::Subject,
                    state: State::Pending,
                    deleted_at: None,
                },
            );
        };
        let m = bucket();
        let p = h("a1");
        recording(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        operator(&m, &p);
        catalog_block(&m, U);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("deleted recording {p}\n1 deleted, 0 kept, 0 deferred, 0 failed")
        );
        for key in recording_keys(&p) {
            assert!(gone(&m, &key).await, "{key}");
        }
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!(r.state, State::Deleted);
        let r: OperatorRequest = record(&m, &operator_key(U, &p)).await;
        assert_eq!(r.state, State::Deleted);

        // Without the catalog block, the operator's request isn't due.
        let m = bucket();
        recording(&m, &p, U);
        request(&m, U, &p, NOW - GRACE);
        operator(&m, &p);

        let report = sweep(&m, true, NOW).await.unwrap();
        assert_eq!(
            report.to_string(),
            format!("pushed again recording {p}\n0 deleted, 1 kept, 0 deferred, 0 failed")
        );
        let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW));
        let r: OperatorRequest = record(&m, &operator_key(U, &p)).await;
        assert_eq!((r.state, r.requested_at), (State::Pending, NOW - GRACE));
        assert!(m.deletes().is_empty());
    }

    /// Spec 3.4 step 7: tombstones verified an hour after their delete.
    mod verify {
        use super::*;
        use crate::deletion::VERIFY_AFTER;

        /// When the tombstones were written.
        const T: i64 = 1000;
        /// When they are verified: an hour later.
        const AT: i64 = T + VERIFY_AFTER;

        /// `recordings/<sub>/<hash>`, deleted at `T`, requested a grace
        /// period before (so it was due then, and would be again). Each
        /// tombstone here is written at its `deletedAt`, as a run writes
        /// it, and leaves the bucket's clock there.
        fn tombstone(m: &MemObjects, sub: &str, hash: &str) {
            m.set_now(T);
            put(
                m,
                &recording_key(sub, hash),
                RecordingRequest {
                    hash: hash.into(),
                    subject: sub.into(),
                    requested_at: T - GRACE,
                    seq: 1,
                    state: State::Deleted,
                    deleted_at: Some(T),
                },
            );
        }

        /// `operator/<sub>/<hash>`, scope `hash`, deleted at `deleted_at`.
        fn operator_tombstone(m: &MemObjects, sub: &str, hash: &str, deleted_at: i64) {
            m.set_now(deleted_at);
            put(
                m,
                &operator_key(sub, hash),
                OperatorRequest {
                    hash: hash.into(),
                    subject: sub.into(),
                    requested_at: T,
                    reason: "court order".into(),
                    scope: Scope::Hash,
                    state: State::Deleted,
                    deleted_at: Some(deleted_at),
                },
            );
        }

        /// `envelopes/<hash>` of `owner`, deleted at `deleted_at`.
        fn envelope_tombstone(m: &MemObjects, hash: &str, owner: &str, deleted_at: i64) {
            m.set_now(deleted_at);
            put(
                m,
                &envelope_key(hash),
                EnvelopeRequest {
                    hash: hash.into(),
                    owner: Some(owner.into()),
                    superseded_at: deleted_at - GRACE,
                    source: Source::Transition,
                    state: State::Deleted,
                    deleted_at: Some(deleted_at),
                },
            );
        }

        /// `subjects/<sub>`, deleted at `T`.
        fn subject_tombstone(m: &MemObjects, sub: &str) {
            subject_tombstone_at(m, sub, T);
        }

        /// `subjects/<sub>`, deleted at `deleted_at`.
        fn subject_tombstone_at(m: &MemObjects, sub: &str, deleted_at: i64) {
            m.set_now(deleted_at);
            put(
                m,
                &subject_key(sub),
                SubjectRequest {
                    subject: sub.into(),
                    requested_at: T,
                    reason: "account closed".into(),
                    state: State::Deleted,
                    deleted_at: Some(deleted_at),
                },
            );
        }

        fn block(m: &MemObjects, hash: &str) {
            put(
                m,
                &format!("moderation/blocks/{hash}"),
                json!({"hash": hash, "reason": "r", "by": "op", "at": 1}),
            );
        }

        #[tokio::test]
        async fn a_clean_tombstone_is_removed() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            // Written twice: every version goes.
            tombstone(&m, U, &p);

            let report = sweep(&m, true, AT).await.unwrap();
            assert_eq!(
                report.to_string(),
                format!("verified recording {p}\n0 deleted, 0 kept, 0 deferred, 0 failed")
            );
            assert!(gone(&m, &recording_key(U, &p)).await);
            assert_eq!(m.deletes(), [recording_key(U, &p)]);
        }

        #[tokio::test]
        async fn a_fresh_push_keeps_everything() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            // A new push, by a new owner, after the hour.
            m.set_now(AT + 1);
            m.insert(&format!("blobs/{p}"), "blob");
            put(
                &m,
                &format!("moderation/publishers/{p}"),
                json!({"hash": p, "subject": U2, "endpointId": "e", "at": AT + 1}),
            );

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("fresh recording {p}")), "{report}");
            assert_eq!(report.failures, 0);
            assert!(gone(&m, &recording_key(U, &p)).await);
            assert_eq!(m.deletes(), [recording_key(U, &p)], "no object");
            assert!(m.get(&format!("blobs/{p}")).await.unwrap().is_some());
        }

        #[tokio::test]
        async fn a_relisted_recording_keeps_its_objects() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            // Within the hour: re-listed beats recreated.
            m.set_now(T + 10);
            recording(&m, &p, U2);
            publish_2(&m, U2, 1, b"other", &[&p]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("listed again recording {p}")),
                "{report}"
            );
            assert_eq!(report.failures, 0);
            assert!(gone(&m, &recording_key(U, &p)).await);
            assert_eq!(m.deletes(), [recording_key(U, &p)], "no object");
            for key in recording_keys(&p) {
                assert!(m.get(&key).await.unwrap().is_some(), "{key}");
            }
        }

        /// An in-flight write that landed after the delete is deleted
        /// again; its tombstone stays, as written. The owner record went
        /// with the recording, so its absence doesn't hold it back.
        #[tokio::test]
        async fn a_late_write_is_deleted_again() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            m.insert(&format!("outboards/{p}"), "outboard");
            let before: RecordingRequest = record(&m, &recording_key(U, &p)).await;

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            assert_eq!(report.failures, 0);
            assert_eq!(m.deletes(), recording_keys(&p), "in order");
            assert!(gone(&m, &format!("outboards/{p}")).await);
            let after: RecordingRequest = record(&m, &recording_key(U, &p)).await;
            assert_eq!(after, before, "the tombstone is kept unchanged");
        }

        /// Deleting again removes exactly the versions verification
        /// listed: one written after the listing stays, for the next run.
        #[tokio::test]
        async fn a_version_written_after_the_listing_survives_deleting_again() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            let blob = format!("blobs/{p}");
            m.insert(&blob, "blob");
            m.insert(&format!("outboards/{p}"), "outboard");
            let listed: Vec<String> = m
                .list_versions(&blob)
                .await
                .unwrap()
                .into_iter()
                .map(|v| v.version_id)
                .collect();
            m.set_now(AT);
            let key = blob.clone();
            m.on_before_delete(&blob, move |m| m.insert(&key, "written meanwhile"));

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            let left = m.list_versions(&blob).await.unwrap();
            assert_eq!(left.len(), 1, "{left:?}");
            assert!(!listed.contains(&left[0].version_id), "{left:?}");
            assert_eq!(
                m.get(&blob).await.unwrap(),
                Some(Bytes::from_static(b"written meanwhile"))
            );
            assert!(gone(&m, &format!("outboards/{p}")).await);
            let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
            assert_eq!(r.state, State::Deleted);
        }

        /// A delete marker listed with a late write is deleted again with it.
        #[tokio::test]
        async fn a_listed_delete_marker_is_deleted_again() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            m.insert(&format!("outboards/{p}"), "outboard");
            m.delete_current(&format!("blobs/{p}"));

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            for key in recording_keys(&p) {
                assert!(gone(&m, &key).await, "no version or marker of {key}");
            }
        }

        /// A late write under another account's owner record is that
        /// account's push: kept, and so is the tombstone.
        #[tokio::test]
        async fn a_late_write_by_another_owner_is_kept() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            recording(&m, &p, U2);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(
                    &report,
                    &format!("kept recording {p}: owner is not the requester")
                ),
                "{report}"
            );
            assert!(m.deletes().is_empty());
            for key in recording_keys(&p) {
                assert!(m.get(&key).await.unwrap().is_some(), "{key}");
            }
            let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
            assert_eq!(r.state, State::Deleted);
        }

        /// Step 7 measures from the tombstone's own write (its S3 time),
        /// not the run's `now`: a run that reaches an item two hours in
        /// writes its tombstone then. Its `deletedAt` stays the run's.
        #[tokio::test]
        async fn a_long_runs_tombstone_counts_from_its_own_write() {
            let m = MemObjects::default();
            m.set_now(NOW);
            let p = h("a1");
            pushed(&m, &p, U);
            request(&m, U, &p, NOW - GRACE);
            let late = NOW + 2 * VERIFY_AFTER;
            m.on_before_delete(&format!("moderation/publishers/{p}"), move |m| {
                m.set_now(late)
            });
            let report = sweep(&m, true, NOW).await.unwrap();
            assert!(has(&report, &format!("deleted recording {p}")), "{report}");
            let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
            assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(NOW)));

            // An hour after the run's `now`, but not after the write.
            let report = sweep(&m, true, NOW + VERIFY_AFTER).await.unwrap();
            assert!(report.lines.is_empty(), "{report}");
            assert!(m.get(&recording_key(U, &p)).await.unwrap().is_some());

            // A push in flight lands just after the delete: deleted again,
            // not fresh.
            m.set_now(late + 10);
            m.insert(&format!("blobs/{p}"), "blob");
            let report = sweep(&m, true, late + VERIFY_AFTER).await.unwrap();
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            assert!(gone(&m, &format!("blobs/{p}")).await);
            assert!(m.get(&recording_key(U, &p)).await.unwrap().is_some());
        }

        /// Write `key`'s current body again at `at`: a tombstone a long
        /// run wrote well after its `deletedAt`.
        async fn rewrite_at(m: &MemObjects, key: &str, at: i64) {
            let body = m.get(key).await.unwrap().unwrap();
            m.set_now(at);
            m.insert(key, body);
        }

        /// Of a hash's tombstones, the newest write counts.
        #[tokio::test]
        async fn a_hashs_newest_tombstone_write_counts() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            operator_tombstone(&m, U2, &p, T);
            // Its `deletedAt` is as old, its write an hour newer.
            rewrite_at(&m, &operator_key(U2, &p), AT).await;

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(report.lines.is_empty(), "{report}");
            assert!(m.deletes().is_empty());
        }

        /// A subject's tombstone too: a pointer an in-flight publish wrote
        /// just after a late delete is deleted again, and, while its
        /// catalog block stands, lists nothing meanwhile (rule 2), so the
        /// recording it lists is deleted again too.
        #[tokio::test]
        async fn a_late_subject_tombstone_counts_from_its_own_write() {
            let m = MemObjects::default();
            let p = h("a1");
            let late = T + 2 * VERIFY_AFTER;
            subject_tombstone(&m, U);
            tombstone(&m, U, &p);
            rewrite_at(&m, &subject_key(U), late).await;
            rewrite_at(&m, &recording_key(U, &p), late).await;
            catalog_block(&m, U);
            m.set_now(late + 10);
            recording(&m, &p, U);
            publish_2(&m, U, 1, b"doc-late", &[&p]);

            let report = sweep(&m, true, late + VERIFY_AFTER).await.unwrap();
            assert!(has(&report, &format!("recreated subject {U}")), "{report}");
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            assert!(gone(&m, &format!("catalog-pointers/{U}")).await);
            for key in recording_keys(&p) {
                assert!(gone(&m, &key).await, "{key}");
            }
            assert!(m.get(&recording_key(U, &p)).await.unwrap().is_some());
        }

        /// Rule 1 counts only what a new push or publish writes. The node
        /// writes an outboard itself when it serves a blob or envelope
        /// that lacks one, so a newer outboard alone is a late write,
        /// deleted again; a newer manifest or document is fresh.
        #[tokio::test]
        async fn a_newer_outboard_alone_is_not_fresh() {
            let m = MemObjects::default();
            let (p, e) = (h("a1"), h("e1"));
            tombstone(&m, U, &p);
            envelope_tombstone(&m, &e, U, T);
            m.set_now(AT + 1);
            m.insert(&format!("outboards/{p}"), "outboard");
            m.insert(&format!("catalog-outboards/{e}"), "outboard");

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            assert!(has(&report, &format!("recreated envelope {e}")), "{report}");
            assert!(gone(&m, &format!("outboards/{p}")).await);
            assert!(gone(&m, &format!("catalog-outboards/{e}")).await);

            let m = MemObjects::default();
            tombstone(&m, U, &p);
            envelope_tombstone(&m, &e, U, T);
            m.set_now(AT + 1);
            m.insert(&format!("manifests/{p}"), "{}");
            m.insert_with_owner(&format!("catalog-documents/{e}"), "doc", U);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("fresh recording {p}")), "{report}");
            assert!(has(&report, &format!("fresh envelope {e}")), "{report}");
            assert!(
                m.deletes()
                    .iter()
                    .all(|k| k.starts_with("deletion-requests/"))
            );
        }

        #[tokio::test]
        async fn a_young_tombstone_waits() {
            let m = MemObjects::default();
            let (p, q) = (h("a1"), h("a2"));
            tombstone(&m, U, &p);
            tombstone(&m, U, &q);
            m.set_now(T + 10);
            m.insert(&format!("outboards/{q}"), "outboard");
            let before = versions(&m).await;

            let report = sweep(&m, true, AT - 1).await.unwrap();
            assert!(report.lines.is_empty(), "{report}");
            assert_eq!(versions(&m).await, before);
            assert!(m.deletes().is_empty());
        }

        #[tokio::test]
        async fn envelope_and_subject_tombstones_verify_the_same_way() {
            let m = MemObjects::default();
            let e = h("e1");
            envelope_tombstone(&m, &e, U, T);
            subject_tombstone(&m, U);
            // A returning creator's new pointer, under the other key form.
            m.set_now(AT + 1);
            publish_2(&m, &arkavo(U), 1, b"doc-new", &[]);
            let pointer = format!("catalog-pointers/{}", arkavo(U));

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("verified envelope {e}")), "{report}");
            assert!(has(&report, &format!("fresh subject {U}")), "{report}");
            assert_eq!(report.failures, 0);
            assert!(gone(&m, &envelope_key(&e)).await);
            assert!(gone(&m, &subject_key(U)).await);
            assert!(m.get(&pointer).await.unwrap().is_some());
        }

        /// A subject's tombstone releases its hidden envelopes while its
        /// catalog block stands (spec 3.4 step 5), so it stays while any
        /// envelope request of that owner is pending and the block stands.
        #[tokio::test]
        async fn a_subject_tombstone_waits_for_its_envelopes() {
            let m = MemObjects::default();
            subject_tombstone(&m, U);
            catalog_block(&m, U);
            // Its owner named by the index record only, in the other form.
            let e = envelope(&m, &arkavo(U), b"doc-u");
            put(
                &m,
                &envelope_key(&e),
                EnvelopeRequest {
                    hash: e.clone(),
                    owner: None,
                    superseded_at: AT,
                    source: Source::Observed,
                    state: State::Pending,
                    deleted_at: None,
                },
            );

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("kept subject {U}: envelopes pending")),
                "{report}"
            );
            let r: SubjectRequest = record(&m, &subject_key(U)).await;
            assert_eq!(r.state, State::Deleted);

            // Once the envelope is deleted, the subject verifies.
            let mut r: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
            (r.state, r.deleted_at) = (State::Deleted, Some(AT));
            put(&m, &envelope_key(&e), r);
            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("verified subject {U}")), "{report}");
            assert!(gone(&m, &subject_key(U)).await);
        }

        /// With its catalog block lifted, a subject's tombstone releases
        /// nothing: its owner's envelope is kept while a hideCatalog
        /// suspension hides it, and the tombstone verifies all the same.
        #[tokio::test]
        async fn a_lifted_blocks_subject_tombstone_releases_nothing() {
            let m = MemObjects::default();
            subject_tombstone(&m, U);
            put(
                &m,
                &format!("moderation/suspensions/{U}"),
                json!({"subject": U, "reason": "r", "hideCatalog": true, "by": "op", "at": 1}),
            );
            let e = envelope(&m, U, b"doc-u");
            envelope_request(&m, &e, U, AT - GRACE);

            let report = sweep(&m, true, AT).await.unwrap();
            assert_eq!(
                report.lines,
                [
                    format!("verified subject {U}"),
                    format!("kept envelope {e}: owner hidden"),
                ],
                "{report}"
            );
            assert!(gone(&m, &subject_key(U)).await);
            for key in envelope_keys(&e) {
                assert!(m.get(&key).await.unwrap().is_some(), "{key}");
            }
            let r: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
            assert_eq!(r.state, State::Pending);
        }

        /// A late pointer of a subject still catalog-blocked is deleted
        /// again, and no other account's; with the block lifted it is
        /// kept.
        #[tokio::test]
        async fn a_late_pointer_is_deleted_again_while_the_block_stands() {
            let m = MemObjects::default();
            subject_tombstone(&m, U);
            catalog_block(&m, U);
            publish_2(&m, U2, 1, b"doc-other", &[]);
            m.set_now(T + 10);
            publish_2(&m, U, 1, b"doc-late", &[]);
            let pointer = format!("catalog-pointers/{U}");

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("recreated subject {U}")), "{report}");
            assert_eq!(report.failures, 0);
            assert_eq!(m.deletes(), std::slice::from_ref(&pointer));
            assert!(gone(&m, &pointer).await);
            let other = format!("catalog-pointers/{U2}");
            assert!(m.get(&other).await.unwrap().is_some());
            let r: SubjectRequest = record(&m, &subject_key(U)).await;
            assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(T)));

            let m = MemObjects::default();
            subject_tombstone(&m, U);
            m.set_now(T + 10);
            publish_2(&m, U, 1, b"doc-late", &[]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("kept subject {U}: catalog block lifted")),
                "{report}"
            );
            assert!(m.get(&pointer).await.unwrap().is_some());
            assert!(m.get(&subject_key(U)).await.unwrap().is_some());
        }

        /// A late envelope a stored pointer names stays (the pointer is
        /// its subject's, being deleted, whose delete failed): deleting the
        /// index record of a live `/2` pointer would break every strict
        /// read.
        #[tokio::test]
        async fn a_late_envelope_a_pointer_names_is_kept() {
            let m = MemObjects::default();
            let e = catalog(b"doc-u");
            envelope_tombstone(&m, &e, U, T);
            catalog_block(&m, U);
            subject_request(&m, U);
            m.set_now(T + 10);
            publish_2(&m, U, 1, b"doc-u", &[]);
            let pointer = format!("catalog-pointers/{U}");
            m.fail_on(&pointer, Op::Delete);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(
                    &report,
                    &format!("kept envelope {e}: a pointer still names it")
                ),
                "{report}"
            );
            assert!(
                m.get(&format!("catalog-indexes/{e}"))
                    .await
                    .unwrap()
                    .is_some()
            );
            snapshot::read(&m).await.unwrap();
        }

        /// Rule 2 for an envelope: a pointer names it again.
        #[tokio::test]
        async fn a_current_envelope_keeps_its_objects() {
            let m = MemObjects::default();
            let e = catalog(b"doc-e");
            envelope_tombstone(&m, &e, U, T);
            m.set_now(T + 10);
            publish_2(&m, U, 1, b"doc-e", &[]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("current again envelope {e}")),
                "{report}"
            );
            assert_eq!(report.failures, 0);
            assert_eq!(m.deletes(), [envelope_key(&e)], "no object");
            let index = format!("catalog-indexes/{e}");
            assert!(m.get(&index).await.unwrap().is_some());
        }

        /// A late envelope object no pointer names is deleted again, its
        /// keys in order.
        #[tokio::test]
        async fn a_late_envelope_is_deleted_again() {
            let m = MemObjects::default();
            let e = h("e1");
            envelope_tombstone(&m, &e, U, T);
            m.set_now(T + 10);
            m.insert(&format!("catalog-outboards/{e}"), "outboard");
            let before: EnvelopeRequest = record(&m, &envelope_key(&e)).await;

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("recreated envelope {e}")), "{report}");
            assert_eq!(m.deletes(), envelope_keys(&e));
            assert!(gone(&m, &format!("catalog-outboards/{e}")).await);
            let after: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
            assert_eq!(after, before, "the tombstone is kept unchanged");
        }

        /// A delete marker is no object, even one written after the hour.
        #[tokio::test]
        async fn a_delete_marker_is_no_object() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            m.set_now(AT + 1);
            m.delete_current(&format!("blobs/{p}"));

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("verified recording {p}")), "{report}");
            assert!(gone(&m, &recording_key(U, &p)).await);
        }

        /// A dry run verifies against the requests the run would have
        /// written: here, an envelope request observed this run keeps the
        /// subject's tombstone.
        #[tokio::test]
        async fn a_dry_run_verifies_against_what_it_would_write() {
            let m = MemObjects::default();
            subject_tombstone(&m, U);
            catalog_block(&m, U);
            // Untracked: observed this run, owned by `U`.
            envelope(&m, U, b"doc-u");

            let report = sweep(&m, false, AT).await.unwrap();
            assert!(
                has(&report, &format!("kept subject {U}: envelopes pending")),
                "{report}"
            );
            assert!(m.deletes().is_empty());
        }

        /// A deleted subject's late pointer (an in-flight publish, still
        /// catalog-blocked) is deleted again by rule 3, so what it lists is
        /// not listed again: the recording is deleted again too, not
        /// forgotten with no request left to delete it.
        #[tokio::test]
        async fn a_deleted_subjects_late_pointer_lists_nothing() {
            let m = MemObjects::default();
            let p = h("a1");
            subject_tombstone(&m, U);
            catalog_block(&m, U);
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            recording(&m, &p, U);
            publish_2(&m, U, 1, b"doc-late", &[&p]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("recreated subject {U}")), "{report}");
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            assert_eq!(report.failures, 0);
            for key in recording_keys(&p) {
                assert!(gone(&m, &key).await, "{key}");
            }
            let r: RecordingRequest = record(&m, &recording_key(U, &p)).await;
            assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(T)));
        }

        /// The same while the subject's tombstone is young: the recording
        /// waits, kept with its tombstone, until the pointer is gone.
        #[tokio::test]
        async fn a_young_deleted_subjects_late_pointer_lists_nothing() {
            let m = MemObjects::default();
            let p = h("a1");
            subject_tombstone_at(&m, U, T + 1);
            catalog_block(&m, U);
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            recording(&m, &p, U);
            publish_2(&m, U, 1, b"doc-late", &[&p]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("kept recording {p}: still listed")),
                "{report}"
            );
            assert!(m.deletes().is_empty());
            assert!(m.get(&recording_key(U, &p)).await.unwrap().is_some());
        }

        /// A deleted subject's pointer written after the hour is a
        /// returning creator's: it lists and names as any other.
        #[tokio::test]
        async fn a_returning_subjects_pointer_still_lists() {
            let m = MemObjects::default();
            let p = h("a1");
            subject_tombstone(&m, U);
            catalog_block(&m, U);
            tombstone(&m, U, &p);
            m.set_now(T + 10);
            recording(&m, &p, U);
            m.set_now(AT + 1);
            publish_2(&m, U, 1, b"doc-new", &[&p]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("fresh subject {U}")), "{report}");
            assert!(
                has(&report, &format!("listed again recording {p}")),
                "{report}"
            );
            for key in recording_keys(&p) {
                assert!(m.get(&key).await.unwrap().is_some(), "{key}");
            }
            assert!(gone(&m, &recording_key(U, &p)).await);
        }

        /// The envelope a deleted subject's late pointer names is not
        /// current: it is deleted again after the pointer.
        #[tokio::test]
        async fn a_deleted_subjects_late_pointer_names_nothing() {
            let m = MemObjects::default();
            let e = catalog(b"doc-e");
            subject_tombstone(&m, U);
            catalog_block(&m, U);
            envelope_tombstone(&m, &e, U, T);
            m.set_now(T + 10);
            publish_2(&m, U, 1, b"doc-e", &[]);

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(has(&report, &format!("recreated subject {U}")), "{report}");
            assert!(has(&report, &format!("recreated envelope {e}")), "{report}");
            assert_eq!(report.failures, 0);
            let mut expected = vec![format!("catalog-pointers/{U}")];
            expected.extend(envelope_keys(&e));
            assert_eq!(m.deletes(), expected);
            let r: EnvelopeRequest = record(&m, &envelope_key(&e)).await;
            assert_eq!((r.state, r.deleted_at), (State::Deleted, Some(T)));
            snapshot::read(&m).await.unwrap();
        }

        /// A late write whose requester published since the run's first
        /// read waits for the next run, like a due item.
        #[tokio::test]
        async fn a_late_write_waits_for_a_moved_catalog() {
            let m = MemObjects::default();
            let (p, q) = (h("a1"), h("a2"));
            let [_, second] = dropped(&m, &p);
            m.set_now(NOW - VERIFY_AFTER);
            put(
                &m,
                &recording_key(U, &q),
                RecordingRequest {
                    hash: q.clone(),
                    subject: U.into(),
                    requested_at: NOW - 2 * GRACE,
                    seq: 1,
                    state: State::Deleted,
                    deleted_at: Some(NOW - VERIFY_AFTER),
                },
            );
            m.set_now(NOW - VERIFY_AFTER + 10);
            m.insert(&format!("blobs/{q}"), "blob");
            m.on_before_delete(&second.key, |m| {
                publish_2(m, U, 3, b"doc-3", &[]);
            });

            let report = sweep(&m, true, NOW).await.unwrap();
            assert!(
                has(&report, &format!("kept recording {q}: catalog changed")),
                "{report}"
            );
            assert!(m.get(&format!("blobs/{q}")).await.unwrap().is_some());
            assert!(m.get(&recording_key(U, &q)).await.unwrap().is_some());
        }

        /// Deletion is per hash, and so is verification: one line, and
        /// every tombstone for the hash removed together. A young one
        /// among them makes the whole hash wait.
        #[tokio::test]
        async fn a_hashs_tombstones_verify_together() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            operator_tombstone(&m, U2, &p, T);

            let report = sweep(&m, true, AT).await.unwrap();
            assert_eq!(
                report.lines,
                [format!("verified recording {p}")],
                "{report}"
            );
            assert!(gone(&m, &recording_key(U, &p)).await);
            assert!(gone(&m, &operator_key(U2, &p)).await);

            let m = MemObjects::default();
            tombstone(&m, U, &p);
            operator_tombstone(&m, U2, &p, T + 1);
            let report = sweep(&m, true, AT).await.unwrap();
            assert!(report.lines.is_empty(), "{report}");
            assert!(m.deletes().is_empty());
        }

        /// A blocked hash's late write is deleted again under its
        /// operator's scope-`hash` tombstone, whatever the owner's
        /// tombstone says.
        #[tokio::test]
        async fn any_tombstone_of_a_hash_can_delete_it_again() {
            let m = MemObjects::default();
            let p = h("a1");
            tombstone(&m, U, &p);
            operator_tombstone(&m, U2, &p, T);
            block(&m, &p);
            m.set_now(T + 10);
            m.insert(&format!("blobs/{p}"), "blob");

            let report = sweep(&m, true, AT).await.unwrap();
            assert!(
                has(&report, &format!("recreated recording {p}")),
                "{report}"
            );
            assert!(gone(&m, &format!("blobs/{p}")).await);
        }

        #[tokio::test]
        async fn a_failed_removal_is_reported_and_the_run_goes_on() {
            let m = MemObjects::default();
            let (p, q) = (h("a1"), h("a2"));
            tombstone(&m, U, &p);
            tombstone(&m, U, &q);
            m.fail_on(&recording_key(U, &p), Op::Delete);

            let report = sweep(&m, true, AT).await.unwrap();
            assert_eq!(report.failures, 1);
            let failed = format!("failed recording {p}: ");
            assert!(
                report.lines.iter().any(|l| l.starts_with(&failed)),
                "{report}"
            );
            assert!(m.get(&recording_key(U, &p)).await.unwrap().is_some());
            assert!(has(&report, &format!("verified recording {q}")), "{report}");
            assert!(gone(&m, &recording_key(U, &q)).await);
        }

        #[tokio::test]
        async fn a_dry_run_verifies_nothing() {
            let m = MemObjects::default();
            let (p, q, r) = (h("a1"), h("a2"), h("a3"));
            for hash in [&p, &q, &r] {
                tombstone(&m, U, hash);
            }
            m.set_now(T + 10);
            m.insert(&format!("outboards/{r}"), "outboard");
            m.set_now(AT + 1);
            m.insert(&format!("blobs/{q}"), "blob");
            let before = versions(&m).await;

            let report = sweep(&m, false, AT).await.unwrap();
            assert_eq!(
                report.lines,
                [
                    format!("would verify recording {p}"),
                    format!("would forget recording {q}: fresh"),
                    format!("would delete again recording {r}"),
                ],
                "{report}"
            );
            assert_eq!(versions(&m).await, before);
            assert!(m.deletes().is_empty());
        }
    }
}
