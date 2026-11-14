//! What is due (spec 3.4 steps 3 to 5), decided from what the run read
//! ([`Snapshot`]) and the requests after folding.
//!
//! - [`view`]: the pointers of subjects being deleted (`S`), every payload
//!   hash still listed (`L`) and every current envelope (`C`);
//! - [`observe`]: a request for each envelope whose objects no pointer
//!   names and no request tracks;
//! - [`due`]: each pending request due now, as the [`Item`]s the sweep
//!   deletes, and why each other one is kept.
//!
//! Never delete a recording its owner didn't ask to delete, and never
//! delete anything still listed. So a recording is due only on a request
//! its owner record bears out, or on an operator's over an active block;
//! and `L` counts every catalog whatever its visibility: hidden, blocked
//! and catalog-blocked owners' too. Only the pointers of a subject an
//! operator asked to delete, while its catalog block and its suspension
//! stand ([`all_lifted`]), leave it.
//!
//! Every rule reads the requests passed in (the folded ones, with those
//! [`observe`] made), never the snapshot's. Subjects compare canonically.
//! Tombstones (`deleted` requests) are neither due nor kept here: the
//! sweep verifies them (spec 3.4 step 7).
//!
//! Pure: no I/O, and `now` is a parameter.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::snapshot::{ModerationView, Requests, Snapshot};
use super::{
    EnvelopeRequest, GRACE, OperatorRequest, RecordingRequest, Scope, Source, State, operator_key,
    recording_key,
};
use crate::catalog_scan::Catalogs;
use crate::moderation::canonical_subject;

/// Why a pending request is kept.
const WITHIN_GRACE: &str = "within grace";
const STILL_LISTED: &str = "still listed";
const STILL_CURRENT: &str = "still current";
const BLOCKED: &str = "blocked";
const NOT_THE_REQUESTER: &str = "owner is not the requester";
/// The last rule of both [`recording_kept`] and [`operator_kept`]: a
/// request kept for it passes every other rule. The sweep relies on that
/// when it verifies a tombstone, and when it closes such a request whose
/// recording has nothing left ([`Decision::unowned`]).
pub(super) const NO_OWNER_RECORD: &str = "no owner record";
const BLOCK_LIFTED: &str = "block lifted";
const CATALOG_BLOCK_LIFTED: &str = "catalog block lifted";
const SUSPENSION_LIFTED: &str = "suspension lifted";
const OWNER_HIDDEN: &str = "owner hidden";
const UNKNOWN_OWNER: &str = "unknown owner";

/// Spec 3.4 step 3.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    /// `S`: the keys (`catalog-pointers/<sub>`) of every pointer whose
    /// canonical subject has a pending `subjects/` request, an active
    /// catalog block and an active suspension ([`all_lifted`]). Both pointer
    /// keys of one subject (`arkavo:<uuid>` and `<uuid>`) are here together.
    pub s: BTreeSet<String>,
    /// `L`: every payload hash in the live index of a pointer not in `S`,
    /// whatever its visibility.
    pub l: HashSet<String>,
    /// `C`: the catalog hash of every pointer not in `S`.
    pub c: HashSet<String>,
}

/// `S`, `L` and `C` (see [`View`]). A pointer from before envelopes has
/// no live index: it lists nothing, and its catalog hash is still current.
pub fn view(catalogs: &Catalogs, requests: &Requests, moderation: &ModerationView) -> View {
    view_except(catalogs, requests, moderation, &BTreeSet::new())
}

/// [`view`] as if the pointers at `except` (their keys) were gone: in
/// none of `S`, `L` and `C`.
pub fn view_except(
    catalogs: &Catalogs,
    requests: &Requests,
    moderation: &ModerationView,
    except: &BTreeSet<String>,
) -> View {
    let mut view = View::default();
    for p in catalogs
        .pointers
        .iter()
        .filter(|p| !except.contains(&p.key))
    {
        let subject = canonical_subject(&p.subject);
        if pending_subject(requests, subject) && all_lifted(moderation, subject).is_none() {
            view.s.insert(p.key.clone());
            continue;
        }
        view.c.insert(p.catalog_hash.clone());
        if let Some(hashes) = catalogs.live_hashes(p) {
            view.l.extend(hashes.iter().cloned());
        }
    }
    view
}

/// Spec 3.4 step 4: a request for each catalog hash with an object under
/// `catalog-documents/`, `catalog-outboards/` or `catalog-indexes/` that
/// is not in `C` and has no `envelopes/` record (a tombstone is one), by
/// hash. Superseded now, as far as the sweep can tell. Its `owner` is
/// left to the sweep, which reads the document's owner metadata.
pub fn observe(
    snapshot: &Snapshot,
    requests: &Requests,
    view: &View,
    now: i64,
) -> Vec<EnvelopeRequest> {
    snapshot
        .envelope_objects
        .iter()
        .filter(|hash| !view.c.contains(*hash) && !requests.envelopes.contains_key(*hash))
        .map(|hash| EnvelopeRequest {
            hash: hash.clone(),
            owner: None,
            superseded_at: now,
            source: Source::Observed,
            state: State::Pending,
            deleted_at: None,
        })
        .collect()
}

/// What the sweep deletes for one due item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Recording `hash`: `blobs/`, `outboards/`, `manifests/` and its owner
    /// record. `requests` are the keys ([`super::recording_key`],
    /// [`super::operator_key`]) of every pending request for it, of any
    /// subject, due or not, sorted. Deletion is per hash, so deleting it
    /// satisfies them all, and the sweep marks each `deleted`. The sweep
    /// first lists its versions: if it was pushed again after the drops
    /// that have it due, and no other request has it due, it deletes
    /// nothing, and every pending `recordings/` request of the hash older
    /// than the push restarts its grace from it (`sweep::pushed_again`);
    /// otherwise it deletes exactly the versions it listed.
    Recording { hash: String, requests: Vec<String> },
    /// Subject (canonical): its pointers in `S`, then every transition
    /// under either of its keys (`catalog-transitions/<sub>/`), then
    /// `subjects/<sub>`.
    Subject(String),
    /// Envelope hash: `catalog-documents/`, `catalog-outboards/`,
    /// `catalog-indexes/`, then `envelopes/<hash>`.
    Envelope(String),
}

impl Item {
    /// `<kind> <name>`: how the report names it, and the order of
    /// [`Decision::due`].
    pub fn id(&self) -> String {
        match self {
            Item::Recording { hash, .. } => format!("recording {hash}"),
            Item::Subject(sub) => format!("subject {sub}"),
            Item::Envelope(hash) => format!("envelope {hash}"),
        }
    }
}

/// What [`due`] decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    /// One item per recording hash, subject and envelope due, by
    /// [`Item::id`]: envelopes, then recordings, then subjects.
    pub due: Vec<Item>,
    /// Each pending request not due, as `(id, why)`, by id:
    /// `recording <sub>/<hash>`, `operator <sub>/<hash>`, `subject <sub>`
    /// or `envelope <hash>`. `why` is the first rule it fails, in the
    /// spec's order. A request for a recording hash that is due is not
    /// here: its [`Item::Recording`] names it.
    pub kept: Vec<(String, String)>,
    /// Each recording hash none of whose pending requests is due, but some
    /// kept only for want of an owner record ([`NO_OWNER_RECORD`], the last
    /// rule: they pass every other), as an [`Item::Recording`] whose
    /// `requests` are those, by [`Item::id`]. They are in `kept` too. When
    /// nothing of the recording is left, an earlier run deleted it and
    /// failed to mark these `deleted` (the sweep deletes the owner record
    /// last), or a push failed after its outboard: the sweep closes them
    /// then, deleting their records (and such an outboard).
    pub unowned: Vec<Item>,
}

/// One recording hash's pending requests, `recordings/` and `operator/`
/// of every subject.
#[derive(Default)]
struct HashRequests {
    /// Their keys.
    keys: Vec<String>,
    /// Those not due on their own, as `(id, why)`.
    kept: Vec<(String, &'static str)>,
    /// The keys of those kept for [`NO_OWNER_RECORD`].
    unowned: Vec<String>,
}

impl HashRequests {
    fn add(&mut self, key: String, id: String, kept: Option<&'static str>) {
        if kept == Some(NO_OWNER_RECORD) {
            self.unowned.push(key.clone());
        }
        self.keys.push(key);
        if let Some(why) = kept {
            self.kept.push((id, why));
        }
    }

    /// Whether any of them is due, which makes the hash due.
    fn any_due(&self) -> bool {
        self.kept.len() < self.keys.len()
    }
}

/// Spec 3.4 step 5: every pending request in `requests`, due or kept.
///
/// Deletion is per hash: a recording hash due under any of its requests is
/// one [`Item::Recording`] naming every pending request for it, and none
/// of them is reported kept. A hash none of whose requests is due reports
/// each of them.
pub fn due(snapshot: &Snapshot, requests: &Requests, view: &View, now: i64) -> Decision {
    let mut recordings: BTreeMap<&str, HashRequests> = BTreeMap::new();
    let mut items = Vec::new();
    let mut kept = Vec::new();
    let mut unowned = Vec::new();

    for ((sub, hash), r) in &requests.recordings {
        if r.state != State::Pending {
            continue;
        }
        recordings.entry(hash).or_default().add(
            recording_key(sub, hash),
            format!("recording {sub}/{hash}"),
            recording_kept(snapshot, view, sub, hash, r, now),
        );
    }
    for ((sub, hash), r) in &requests.operator {
        if r.state != State::Pending {
            continue;
        }
        recordings.entry(hash).or_default().add(
            operator_key(sub, hash),
            format!("operator {sub}/{hash}"),
            operator_kept(snapshot, view, sub, hash, r),
        );
    }
    for (hash, mut requested) in recordings {
        if requested.any_due() {
            requested.keys.sort();
            items.push(Item::Recording {
                hash: hash.to_string(),
                requests: requested.keys,
            });
        } else {
            kept.append(&mut requested.kept);
            if !requested.unowned.is_empty() {
                requested.unowned.sort();
                unowned.push(Item::Recording {
                    hash: hash.to_string(),
                    requests: requested.unowned,
                });
            }
        }
    }
    for (sub, r) in &requests.subjects {
        if r.state != State::Pending {
            continue;
        }
        // While its catalog block and its suspension stand.
        match all_lifted(&snapshot.moderation, canonical_subject(sub)) {
            None => items.push(Item::Subject(sub.clone())),
            Some(why) => kept.push((format!("subject {sub}"), why)),
        }
    }
    for (hash, r) in &requests.envelopes {
        if r.state != State::Pending {
            continue;
        }
        match envelope_kept(snapshot, requests, view, hash, r, now) {
            None => items.push(Item::Envelope(hash.clone())),
            Some(why) => kept.push((format!("envelope {hash}"), why)),
        }
    }

    items.sort_by_cached_key(Item::id);
    kept.sort();
    Decision {
        due: items,
        kept: kept
            .into_iter()
            .map(|(id, why)| (id, why.to_string()))
            .collect(),
        unowned,
    }
}

/// `recordings/<sub>/<hash>`: due once `GRACE` has passed since the drop,
/// while `hash` is in no listing and not blocked, if its owner record
/// names `sub`. A push after the drop restarts its grace from the push
/// (only a listing cancels it), but only the versions' write times show a
/// push, which this module doesn't read: the sweep checks for one when it
/// takes the item, and moves `requestedAt` forward (`sweep::pushed_again`).
fn recording_kept(
    snapshot: &Snapshot,
    view: &View,
    sub: &str,
    hash: &str,
    r: &RecordingRequest,
    now: i64,
) -> Option<&'static str> {
    if r.requested_at.saturating_add(GRACE) > now {
        Some(WITHIN_GRACE)
    } else if view.l.contains(hash) {
        Some(STILL_LISTED)
    } else if snapshot.moderation.blocked.contains(hash) {
        Some(BLOCKED)
    } else {
        not_owned_by(&snapshot.owners, hash, sub)
    }
}

/// `operator/<sub>/<hash>`. Scope `hash`: while `hash`'s block stands, at
/// once, listed or not. Scope `subject`: while `sub`'s catalog block and
/// suspension stand ([`all_lifted`]), `hash` is in no listing and not
/// blocked, and its owner record names `sub`. Moderation keeps a blocked
/// hash while its block stands (decision 3), so only a scope-`hash`
/// request deletes one.
fn operator_kept(
    snapshot: &Snapshot,
    view: &View,
    sub: &str,
    hash: &str,
    r: &OperatorRequest,
) -> Option<&'static str> {
    let moderation = &snapshot.moderation;
    match r.scope {
        Scope::Hash => (!moderation.blocked.contains(hash)).then_some(BLOCK_LIFTED),
        Scope::Subject => {
            if let Some(why) = all_lifted(moderation, canonical_subject(sub)) {
                Some(why)
            } else if view.l.contains(hash) {
                Some(STILL_LISTED)
            } else if moderation.blocked.contains(hash) {
                Some(BLOCKED)
            } else {
                not_owned_by(&snapshot.owners, hash, sub)
            }
        }
    }
}

/// `envelopes/<hash>`: due once `GRACE` has passed since it was
/// superseded, while it is not current and not blocked, unless its owner's
/// catalog is hidden (an operator asking for everything the owner
/// published lifts that, while the owner's catalog block and suspension
/// stand) or its owner is unknown.
fn envelope_kept(
    snapshot: &Snapshot,
    requests: &Requests,
    view: &View,
    hash: &str,
    r: &EnvelopeRequest,
    now: i64,
) -> Option<&'static str> {
    if r.superseded_at.saturating_add(GRACE) > now {
        return Some(WITHIN_GRACE);
    }
    if view.c.contains(hash) {
        return Some(STILL_CURRENT);
    }
    if snapshot.moderation.blocked.contains(hash) {
        return Some(BLOCKED);
    }
    match envelope_owner(r, &snapshot.catalogs) {
        Some(owner) => (snapshot.moderation.hidden.contains(owner)
            && !everything_requested(requests, &snapshot.moderation, owner))
        .then_some(OWNER_HIDDEN),
        None if snapshot.envelope_objects.contains(hash) => Some(UNKNOWN_OWNER),
        // No owner known, and no object left to hold back: due, so the
        // sweep, deleting nothing, marks the request `deleted`.
        None => None,
    }
}

/// An envelope's owner, canonical: its request's (the transition's
/// subject, or the document's owner metadata the sweep read), else its
/// index record's.
pub(super) fn envelope_owner<'a>(
    r: &'a EnvelopeRequest,
    catalogs: &'a Catalogs,
) -> Option<&'a str> {
    r.owner
        .as_deref()
        .or_else(|| catalogs.indexes.get(&r.hash).map(|i| i.owner.as_str()))
        .map(canonical_subject)
}

/// Whether an operator asked for everything `subject` published, which
/// releases its envelopes from its hidden catalog: a `subjects/` record in
/// any state, while `subject`'s catalog block and suspension (the
/// request's preconditions, [`all_lifted`]) stand. A tombstone counts: the
/// envelopes current when the subject's pointers were deleted are observed
/// on that run and fall due after their grace (spec 3.4 step 6), and
/// tombstone verification keeps a `subjects/` tombstone while a pending
/// envelope request names its subject and both still stand. With either
/// lifted, the request holds nothing: a hidden owner's envelopes stay
/// hidden.
fn everything_requested(requests: &Requests, moderation: &ModerationView, subject: &str) -> bool {
    requests.subjects.contains_key(subject) && all_lifted(moderation, subject).is_none()
}

/// The first of `request-deletion --all`'s preconditions for `subject`
/// (canonical) that no longer stands, as the reason its requests are kept:
/// its catalog block, then its suspension. `None` while both stand. A
/// catalog block hides the catalog but doesn't stop publishing; a
/// suspension does, so no fresh pointer can appear while the sweep deletes
/// the account. Every rule that acts on `--all`'s requests re-checks both
/// through this: `S`, a `subjects/` request, a scope-`subject` request,
/// the release of a hidden owner's envelopes, and (in the sweep) a deleted
/// subject's late pointers and the hold on its tombstone.
pub(super) fn all_lifted(moderation: &ModerationView, subject: &str) -> Option<&'static str> {
    if !moderation.catalog_blocked.contains(subject) {
        Some(CATALOG_BLOCK_LIFTED)
    } else if !moderation.suspended.contains(subject) {
        Some(SUSPENSION_LIFTED)
    } else {
        None
    }
}

fn pending_subject(requests: &Requests, subject: &str) -> bool {
    requests
        .subjects
        .get(subject)
        .is_some_and(|r| r.state == State::Pending)
}

/// Why `hash` isn't `sub`'s to delete, per its owner record; `None` when
/// the record names `sub`.
fn not_owned_by(owners: &HashMap<String, String>, hash: &str, sub: &str) -> Option<&'static str> {
    match owners.get(hash) {
        Some(owner) if canonical_subject(owner) == canonical_subject(sub) => None,
        Some(_) => Some(NOT_THE_REQUESTER),
        None => Some(NO_OWNER_RECORD),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_scan::{POINTERS, ScannedIndex, ScannedPointer};
    use crate::deletion::{
        GRACE, OperatorRequest, RecordingRequest, Scope, Source, State, SubjectRequest,
        operator_key, recording_key,
    };
    use crate::moderation::canonical_subject;

    const U: &str = "550e8400-e29b-41d4-a716-446655440000";
    const U2: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const NOW: i64 = 1_000_000_000;

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    fn arkavo(uuid: &str) -> String {
        format!("arkavo:{uuid}")
    }

    fn pointer_key(sub: &str) -> String {
        format!("{POINTERS}{sub}")
    }

    /// `catalog-pointers/<sub>` at `catalog`, whose index record (owner
    /// `sub`, as recorded) lists `payloads`.
    fn point(s: &mut Snapshot, sub: &str, catalog: &str, payloads: &[&str]) {
        point_1(s, sub, catalog);
        s.catalogs.indexes.insert(
            catalog.to_string(),
            ScannedIndex {
                owner: sub.to_string(),
                hashes: payloads.iter().map(|p| p.to_string()).collect(),
            },
        );
    }

    /// `catalog-pointers/<sub>` at `catalog`, with no index record: a
    /// catalog from before envelopes.
    fn point_1(s: &mut Snapshot, sub: &str, catalog: &str) {
        s.catalogs.pointers.push(ScannedPointer {
            key: pointer_key(sub),
            subject: canonical_subject(sub).to_string(),
            seq: 1,
            catalog_hash: catalog.to_string(),
            index_hash: None,
            digest: h("d1"),
        });
        s.catalogs.pointers.sort_by(|a, b| a.key.cmp(&b.key));
    }

    fn recording(r: &mut Requests, sub: &str, hash: &str, requested_at: i64) {
        r.recordings.insert(
            (sub.to_string(), hash.to_string()),
            RecordingRequest {
                hash: hash.to_string(),
                subject: sub.to_string(),
                requested_at,
                seq: 1,
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    fn operator(r: &mut Requests, sub: &str, hash: &str, scope: Scope) {
        r.operator.insert(
            (sub.to_string(), hash.to_string()),
            OperatorRequest {
                hash: hash.to_string(),
                subject: sub.to_string(),
                requested_at: NOW,
                reason: "r".into(),
                scope,
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    fn subject(r: &mut Requests, sub: &str) {
        r.subjects.insert(
            sub.to_string(),
            SubjectRequest {
                subject: sub.to_string(),
                requested_at: NOW,
                reason: "r".into(),
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    fn envelope(r: &mut Requests, hash: &str, owner: Option<&str>, superseded_at: i64) {
        r.envelopes.insert(
            hash.to_string(),
            EnvelopeRequest {
                hash: hash.to_string(),
                owner: owner.map(str::to_string),
                superseded_at,
                source: Source::Transition,
                state: State::Pending,
                deleted_at: None,
            },
        );
    }

    fn catalog_block(s: &mut Snapshot, sub: &str) {
        s.moderation.catalog_blocked.insert(sub.to_string());
        s.moderation.hidden.insert(sub.to_string());
    }

    fn lift_catalog_block(s: &mut Snapshot, sub: &str) {
        s.moderation.catalog_blocked.remove(sub);
        s.moderation.hidden.remove(sub);
    }

    fn suspend(s: &mut Snapshot, sub: &str) {
        s.moderation.suspended.insert(sub.to_string());
    }

    fn lift_suspension(s: &mut Snapshot, sub: &str) {
        s.moderation.suspended.remove(sub);
    }

    /// `request-deletion --all`'s preconditions: a catalog block and a
    /// suspension.
    fn block_and_suspend(s: &mut Snapshot, sub: &str) {
        catalog_block(s, sub);
        suspend(s, sub);
    }

    fn owns(s: &mut Snapshot, hash: &str, sub: &str) {
        s.owners.insert(hash.to_string(), sub.to_string());
    }

    /// Decide on `requests`, passed apart from the snapshot (whose own
    /// `requests` the tests leave empty: the functions read the folded
    /// ones only).
    fn decide(s: &Snapshot, requests: &Requests) -> Decision {
        due(
            s,
            requests,
            &view(&s.catalogs, requests, &s.moderation),
            NOW,
        )
    }

    fn rec(hash: &str, requests: &[String]) -> Item {
        Item::Recording {
            hash: hash.to_string(),
            requests: requests.to_vec(),
        }
    }

    fn kept(id: String, why: &str) -> (String, String) {
        (id, why.to_string())
    }

    fn set<const N: usize>(items: [String; N]) -> HashSet<String> {
        HashSet::from(items)
    }

    #[test]
    fn s_holds_every_pointer_of_a_subject_being_deleted() {
        let mut s = Snapshot::default();
        point(&mut s, &arkavo(U), &h("c1"), &[&h("a1")]);
        point(&mut s, U, &h("c2"), &[&h("a2")]);
        point(&mut s, "u2", &h("c3"), &[&h("a3")]);
        let mut r = Requests::default();
        subject(&mut r, U);
        block_and_suspend(&mut s, U);

        let v = view(&s.catalogs, &r, &s.moderation);
        assert_eq!(
            v.s,
            BTreeSet::from([pointer_key(&arkavo(U)), pointer_key(U)]),
            "both pointer keys of the canonical subject"
        );
        assert_eq!(v.l, set([h("a3")]));
        assert_eq!(v.c, set([h("c3")]));

        // With the block lifted, nothing is being deleted.
        lift_catalog_block(&mut s, U);
        let v = view(&s.catalogs, &r, &s.moderation);
        assert!(v.s.is_empty(), "{:?}", v.s);
        assert_eq!(v.l, set([h("a1"), h("a2"), h("a3")]));
        assert_eq!(v.c, set([h("c1"), h("c2"), h("c3")]));

        // Nor with the suspension lifted: the subject's request waits
        // (`suspension lifted`), so its pointers still list and name.
        catalog_block(&mut s, U);
        lift_suspension(&mut s, U);
        let v = view(&s.catalogs, &r, &s.moderation);
        assert!(v.s.is_empty(), "{:?}", v.s);
        assert_eq!(v.l, set([h("a1"), h("a2"), h("a3")]));
        assert_eq!(v.c, set([h("c1"), h("c2"), h("c3")]));

        // Nor with the block and suspension alone, or over a tombstone.
        suspend(&mut s, U);
        assert!(
            view(&s.catalogs, &Requests::default(), &s.moderation)
                .s
                .is_empty()
        );
        let done = r.subjects.get_mut(U).unwrap();
        done.state = State::Deleted;
        done.deleted_at = Some(NOW);
        assert!(view(&s.catalogs, &r, &s.moderation).s.is_empty());
    }

    #[test]
    fn l_counts_hidden_catalogs() {
        let mut s = Snapshot::default();
        // Catalog-blocked, with no subject request.
        point(&mut s, "u1", &h("c1"), &[&h("a1")]);
        catalog_block(&mut s, "u1");
        // Hidden by a hideCatalog suspension, with a subject request (no
        // catalog block, so not being deleted).
        point(&mut s, "u2", &h("c2"), &[&h("a2")]);
        s.moderation.hidden.insert("u2".into());
        let mut r = Requests::default();
        subject(&mut r, "u2");
        // A blocked envelope.
        point(&mut s, "u3", &h("c3"), &[&h("a3")]);
        s.moderation.blocked.insert(h("c3"));
        // From before envelopes: current, listing nothing.
        point_1(&mut s, "u4", &h("c4"));

        let v = view(&s.catalogs, &r, &s.moderation);
        assert!(v.s.is_empty(), "{:?}", v.s);
        assert_eq!(v.l, set([h("a1"), h("a2"), h("a3")]));
        assert_eq!(v.c, set([h("c1"), h("c2"), h("c3"), h("c4")]));
    }

    #[test]
    fn untracked_envelopes_are_observed() {
        let mut s = Snapshot::default();
        point(&mut s, "u1", &h("c1"), &[]);
        // Being deleted: its current envelope is no longer in `C`.
        point(&mut s, U, &h("c2"), &[]);
        block_and_suspend(&mut s, U);
        let mut r = Requests::default();
        subject(&mut r, U);
        // Tracked: pending, and a tombstone.
        envelope(&mut r, &h("e2"), None, 1);
        envelope(&mut r, &h("e3"), None, 1);
        let done = r.envelopes.get_mut(&h("e3")).unwrap();
        done.state = State::Deleted;
        done.deleted_at = Some(2);
        s.envelope_objects = BTreeSet::from([h("c1"), h("c2"), h("e1"), h("e2"), h("e3")]);

        let v = view(&s.catalogs, &r, &s.moderation);
        let observed = |hash: String| EnvelopeRequest {
            hash,
            owner: None,
            superseded_at: NOW,
            source: Source::Observed,
            state: State::Pending,
            deleted_at: None,
        };
        assert_eq!(
            observe(&s, &r, &v, NOW),
            [observed(h("c2")), observed(h("e1"))],
            "by hash"
        );
    }

    #[test]
    fn a_dropped_recording_is_due_after_grace() {
        let mut s = Snapshot::default();
        point(&mut s, "u2", &h("c1"), &[&h("a3")]);
        s.moderation.blocked.insert(h("a4"));
        for hash in ["a1", "a2", "a3", "a4"] {
            owns(&mut s, &h(hash), "u1");
        }
        owns(&mut s, &h("a5"), "u2");
        let mut r = Requests::default();
        recording(&mut r, "u1", &h("a1"), NOW - GRACE);
        recording(&mut r, "u1", &h("a2"), NOW - GRACE + 1);
        for hash in ["a3", "a4", "a5", "a6"] {
            recording(&mut r, "u1", &h(hash), NOW - GRACE);
        }

        let out = decide(&s, &r);
        assert_eq!(out.due, [rec(&h("a1"), &[recording_key("u1", &h("a1"))])]);
        let id = |hash: &str| format!("recording u1/{}", h(hash));
        assert_eq!(
            out.kept,
            [
                kept(id("a2"), "within grace"),
                kept(id("a3"), "still listed"),
                kept(id("a4"), "blocked"),
                kept(id("a5"), "owner is not the requester"),
                kept(id("a6"), "no owner record"),
            ]
        );
        assert_eq!(
            out.unowned,
            [rec(&h("a6"), &[recording_key("u1", &h("a6"))])]
        );

        // A grace that would overflow never reads as due.
        let mut r = Requests::default();
        recording(&mut r, "u1", &h("a1"), i64::MAX);
        let out = decide(&s, &r);
        assert!(out.due.is_empty());
        assert_eq!(out.kept, [kept(id("a1"), "within grace")]);
    }

    /// A hash none of whose requests is due, some kept only for want of
    /// an owner record, is `unowned`, naming those; not one with a request
    /// due (a scope-`hash` one needs no owner record), nor one whose
    /// requests are kept for anything else.
    #[test]
    fn a_hash_kept_only_for_its_owner_record_is_unowned() {
        let mut s = Snapshot::default();
        s.moderation.blocked.insert(h("a2"));
        let mut r = Requests::default();
        // a1: no owner record; its operator request's block was lifted.
        recording(&mut r, U, &h("a1"), NOW - GRACE);
        recording(&mut r, "u2", &h("a1"), NOW);
        operator(&mut r, "u3", &h("a1"), Scope::Hash);
        // a2: blocked, and an operator's scope-hash request makes it due.
        recording(&mut r, U, &h("a2"), NOW - GRACE);
        operator(&mut r, "u3", &h("a2"), Scope::Hash);
        // a3: within grace only.
        recording(&mut r, U, &h("a3"), NOW);

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [rec(
                &h("a2"),
                &[operator_key("u3", &h("a2")), recording_key(U, &h("a2"))]
            )]
        );
        assert_eq!(out.unowned, [rec(&h("a1"), &[recording_key(U, &h("a1"))])]);
        assert!(
            out.kept.contains(&kept(
                format!("recording {U}/{}", h("a1")),
                "no owner record"
            )),
            "{:?}",
            out.kept
        );
    }

    #[test]
    fn one_item_per_recording() {
        let mut s = Snapshot::default();
        owns(&mut s, &h("a1"), U);
        block_and_suspend(&mut s, U);
        let mut r = Requests::default();
        recording(&mut r, U, &h("a1"), NOW - GRACE);
        operator(&mut r, U, &h("a1"), Scope::Subject);

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [rec(
                &h("a1"),
                &[operator_key(U, &h("a1")), recording_key(U, &h("a1"))]
            )]
        );
        assert!(out.kept.is_empty(), "{:?}", out.kept);
    }

    /// Deletion is per hash: a hash due under one request is due, and its
    /// item names every pending request for it, due or kept, of any
    /// subject. The deletion satisfies them all, so none is reported kept.
    #[test]
    fn a_due_hash_names_every_pending_request_for_it() {
        let mut s = Snapshot::default();
        owns(&mut s, &h("a1"), "u1");
        s.moderation.blocked.insert(h("a1"));
        let mut r = Requests::default();
        // Kept on its own: blocked.
        recording(&mut r, "u1", &h("a1"), NOW - GRACE);
        operator(&mut r, "u1", &h("a1"), Scope::Hash);
        // Another subject's request for the same hash: still one item.
        operator(&mut r, "u2", &h("a1"), Scope::Hash);
        // A tombstone is not pending, so not named.
        operator(&mut r, "u3", &h("a1"), Scope::Hash);
        let done = r.operator.get_mut(&("u3".into(), h("a1"))).unwrap();
        (done.state, done.deleted_at) = (State::Deleted, Some(1));

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [rec(
                &h("a1"),
                &[
                    operator_key("u1", &h("a1")),
                    operator_key("u2", &h("a1")),
                    recording_key("u1", &h("a1")),
                ]
            )]
        );
        assert!(out.kept.is_empty(), "{:?}", out.kept);

        // A due recording request, and another subject's scope-subject
        // request whose catalog block is lifted.
        let mut s = Snapshot::default();
        owns(&mut s, &h("a1"), "u1");
        let mut r = Requests::default();
        recording(&mut r, "u1", &h("a1"), NOW - GRACE);
        operator(&mut r, "u2", &h("a1"), Scope::Subject);
        // A hash none of whose requests is due reports each of them.
        recording(&mut r, "u1", &h("a2"), NOW);
        operator(&mut r, "u2", &h("a2"), Scope::Subject);

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [rec(
                &h("a1"),
                &[operator_key("u2", &h("a1")), recording_key("u1", &h("a1"))]
            )]
        );
        assert_eq!(
            out.kept,
            [
                kept(format!("operator u2/{}", h("a2")), "catalog block lifted"),
                kept(format!("recording u1/{}", h("a2")), "within grace"),
            ]
        );
    }

    /// Moderation keeps a blocked hash while its block stands (decision
    /// 3): only a scope-`hash` request deletes it.
    #[test]
    fn operator_subject_scope_keeps_a_blocked_hash() {
        let mut s = Snapshot::default();
        block_and_suspend(&mut s, U);
        owns(&mut s, &h("a1"), U);
        s.moderation.blocked.insert(h("a1"));
        let mut r = Requests::default();
        operator(&mut r, U, &h("a1"), Scope::Subject);

        let out = decide(&s, &r);
        assert!(out.due.is_empty(), "{:?}", out.due);
        assert_eq!(
            out.kept,
            [kept(format!("operator {U}/{}", h("a1")), "blocked")]
        );
    }

    #[test]
    fn operator_hash_scope_needs_only_its_block() {
        let mut s = Snapshot::default();
        // Listed, owned by another account, and requested just now.
        point(&mut s, "u2", &h("c1"), &[&h("a1")]);
        owns(&mut s, &h("a1"), "u2");
        s.moderation.blocked.insert(h("a1"));
        let mut r = Requests::default();
        operator(&mut r, "u1", &h("a1"), Scope::Hash);

        let out = decide(&s, &r);
        assert_eq!(out.due, [rec(&h("a1"), &[operator_key("u1", &h("a1"))])]);
        assert!(out.kept.is_empty(), "{:?}", out.kept);

        s.moderation.blocked.clear();
        let out = decide(&s, &r);
        assert!(out.due.is_empty(), "{:?}", out.due);
        assert_eq!(
            out.kept,
            [kept(format!("operator u1/{}", h("a1")), "block lifted")]
        );
    }

    #[test]
    fn operator_subject_scope_needs_the_catalog_block_and_suspension() {
        let mut s = Snapshot::default();
        // `U`'s own catalog lists a1, but `U` is being deleted: its
        // pointer is in `S`, so a1 is not in `L`.
        point(&mut s, &arkavo(U), &h("c1"), &[&h("a1")]);
        point(&mut s, "u2", &h("c2"), &[&h("a2")]);
        block_and_suspend(&mut s, U);
        for hash in ["a1", "a2"] {
            owns(&mut s, &h(hash), U);
        }
        owns(&mut s, &h("a3"), "u2");
        let mut r = Requests::default();
        subject(&mut r, U);
        for hash in ["a1", "a2", "a3", "a4"] {
            operator(&mut r, U, &h(hash), Scope::Subject);
        }
        let id = |hash: &str| format!("operator {U}/{}", h(hash));

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [
                rec(&h("a1"), &[operator_key(U, &h("a1"))]),
                Item::Subject(U.to_string()),
            ]
        );
        assert_eq!(
            out.kept,
            [
                kept(id("a2"), "still listed"),
                kept(id("a3"), "owner is not the requester"),
                kept(id("a4"), "no owner record"),
            ]
        );
        assert_eq!(out.unowned, [rec(&h("a4"), &[operator_key(U, &h("a4"))])]);

        lift_catalog_block(&mut s, U);
        let out = decide(&s, &r);
        assert!(out.due.is_empty(), "{:?}", out.due);
        assert_eq!(
            out.kept,
            [
                kept(id("a1"), "catalog block lifted"),
                kept(id("a2"), "catalog block lifted"),
                kept(id("a3"), "catalog block lifted"),
                kept(id("a4"), "catalog block lifted"),
                kept(format!("subject {U}"), "catalog block lifted"),
            ]
        );

        // The block stands and the suspension is lifted: every request
        // waits, a1 included, which `U`'s pointer lists again.
        catalog_block(&mut s, U);
        lift_suspension(&mut s, U);
        let out = decide(&s, &r);
        assert!(out.due.is_empty(), "{:?}", out.due);
        assert_eq!(
            out.kept,
            [
                kept(id("a1"), "suspension lifted"),
                kept(id("a2"), "suspension lifted"),
                kept(id("a3"), "suspension lifted"),
                kept(id("a4"), "suspension lifted"),
                kept(format!("subject {U}"), "suspension lifted"),
            ]
        );

        // Both lifted: the block is named.
        lift_catalog_block(&mut s, U);
        let out = decide(&s, &r);
        assert!(
            out.kept
                .iter()
                .all(|(_, why)| why == "catalog block lifted"),
            "{:?}",
            out.kept
        );
    }

    #[test]
    fn a_subject_is_due_while_its_catalog_block_and_suspension_stand() {
        let mut s = Snapshot::default();
        point(&mut s, &arkavo(U), &h("c1"), &[]);
        point(&mut s, U, &h("c2"), &[]);
        block_and_suspend(&mut s, U);
        let mut r = Requests::default();
        subject(&mut r, U);
        // A subject with no pointer left is due too.
        subject(&mut r, U2);
        block_and_suspend(&mut s, U2);

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [Item::Subject(U.to_string()), Item::Subject(U2.to_string())]
        );
        assert!(out.kept.is_empty(), "{:?}", out.kept);

        lift_catalog_block(&mut s, U);
        let out = decide(&s, &r);
        assert_eq!(out.due, [Item::Subject(U2.to_string())]);
        assert_eq!(
            out.kept,
            [kept(format!("subject {U}"), "catalog block lifted")]
        );

        // A suspension, `hideCatalog` or not, is the other half.
        catalog_block(&mut s, U);
        lift_suspension(&mut s, U);
        let out = decide(&s, &r);
        assert_eq!(out.due, [Item::Subject(U2.to_string())]);
        assert_eq!(
            out.kept,
            [kept(format!("subject {U}"), "suspension lifted")]
        );
    }

    #[test]
    fn an_envelope_is_due_after_grace() {
        let mut s = Snapshot::default();
        point(&mut s, "u3", &h("e3"), &[]);
        s.moderation.blocked.insert(h("e4"));
        catalog_block(&mut s, "u4");
        s.moderation.hidden.insert("u5".into());
        block_and_suspend(&mut s, "u6");
        let mut r = Requests::default();
        subject(&mut r, "u6");
        let past = NOW - GRACE;
        envelope(&mut r, &h("e1"), Some("u1"), past);
        envelope(&mut r, &h("e2"), Some("u1"), past + 1);
        envelope(&mut r, &h("e3"), Some("u3"), past);
        envelope(&mut r, &h("e4"), Some("u1"), past);
        // Hidden: by a catalog block, and by hideCatalog.
        envelope(&mut r, &h("e5"), Some("u4"), past);
        envelope(&mut r, &h("e6"), Some("u5"), past);
        // Hidden, but the operator asked for everything u6 published.
        envelope(&mut r, &h("e7"), Some("u6"), past);
        // No owner known, and its objects are there.
        envelope(&mut r, &h("e8"), None, past);
        s.envelope_objects = (1..=8).map(|i| h(&format!("e{i}"))).collect();

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [
                Item::Envelope(h("e1")),
                Item::Envelope(h("e7")),
                Item::Subject("u6".into()),
            ]
        );
        let id = |hash: &str| format!("envelope {}", h(hash));
        assert_eq!(
            out.kept,
            [
                kept(id("e2"), "within grace"),
                kept(id("e3"), "still current"),
                kept(id("e4"), "blocked"),
                kept(id("e5"), "owner hidden"),
                kept(id("e6"), "owner hidden"),
                kept(id("e8"), "unknown owner"),
            ]
        );
    }

    /// An envelope's owner is its request's, else its index record's; both
    /// compared canonically.
    #[test]
    fn an_envelopes_owner_is_its_requests_else_its_index_records() {
        let mut s = Snapshot::default();
        catalog_block(&mut s, U);
        let past = NOW - GRACE;
        let mut r = Requests::default();
        // The index record names the owner: not hidden, then hidden.
        envelope(&mut r, &h("e1"), None, past);
        envelope(&mut r, &h("e2"), None, past);
        for (hash, owner) in [("e1", U2.to_string()), ("e2", arkavo(U))] {
            s.catalogs.indexes.insert(
                h(hash),
                ScannedIndex {
                    owner,
                    hashes: BTreeSet::new(),
                },
            );
        }
        // The request names the owner first, over its index record's.
        envelope(&mut r, &h("e3"), Some(&arkavo(U)), past);
        s.catalogs.indexes.insert(
            h("e3"),
            ScannedIndex {
                owner: U2.to_string(),
                hashes: BTreeSet::new(),
            },
        );
        s.envelope_objects = BTreeSet::from([h("e1"), h("e2"), h("e3")]);

        let out = decide(&s, &r);
        assert_eq!(out.due, [Item::Envelope(h("e1"))]);
        assert_eq!(
            out.kept,
            [
                kept(format!("envelope {}", h("e2")), "owner hidden"),
                kept(format!("envelope {}", h("e3")), "owner hidden"),
            ]
        );
    }

    /// With every object gone, an unknown owner holds nothing back: the
    /// sweep deletes nothing and marks the request `deleted`. Only that
    /// hold is waived: grace, `C`, a block and a hidden owner still keep it.
    #[test]
    fn an_envelope_whose_objects_are_gone_is_due() {
        let mut s = Snapshot::default();
        point(&mut s, "u3", &h("e3"), &[]);
        s.moderation.blocked.insert(h("e4"));
        catalog_block(&mut s, U);
        let past = NOW - GRACE;
        let mut r = Requests::default();
        envelope(&mut r, &h("e1"), None, past);
        envelope(&mut r, &h("e2"), None, past + 1);
        envelope(&mut r, &h("e3"), None, past);
        envelope(&mut r, &h("e4"), None, past);
        // A known owner, hidden, with no `subjects/` record.
        envelope(&mut r, &h("e5"), Some(U), past);
        assert!(s.envelope_objects.is_empty());

        let out = decide(&s, &r);
        assert_eq!(out.due, [Item::Envelope(h("e1"))]);
        let id = |hash: &str| format!("envelope {}", h(hash));
        assert_eq!(
            out.kept,
            [
                kept(id("e2"), "within grace"),
                kept(id("e3"), "still current"),
                kept(id("e4"), "blocked"),
                kept(id("e5"), "owner hidden"),
            ]
        );
    }

    /// A `subjects/` record in any state releases a hidden owner's
    /// envelopes while the owner's catalog block stands: a deleted
    /// subject's envelopes are observed on the run that deletes its
    /// pointers, and fall due once their grace ends, with the subject's
    /// tombstone still there (spec 3.4 step 6).
    #[test]
    fn a_subject_tombstone_releases_a_hidden_owners_envelope() {
        let mut s = Snapshot::default();
        block_and_suspend(&mut s, U);
        catalog_block(&mut s, U2);
        let mut r = Requests::default();
        subject(&mut r, U);
        let done = r.subjects.get_mut(U).unwrap();
        done.state = State::Deleted;
        done.deleted_at = Some(NOW - GRACE);
        envelope(&mut r, &h("e1"), Some(U), NOW - GRACE);
        envelope(&mut r, &h("e2"), Some(U), NOW - GRACE + 1);
        // Hidden, with no `subjects/` record.
        envelope(&mut r, &h("e3"), Some(U2), NOW - GRACE);
        s.envelope_objects = BTreeSet::from([h("e1"), h("e2"), h("e3")]);

        let out = decide(&s, &r);
        assert_eq!(out.due, [Item::Envelope(h("e1"))]);
        assert_eq!(
            out.kept,
            [
                kept(format!("envelope {}", h("e2")), "within grace"),
                kept(format!("envelope {}", h("e3")), "owner hidden"),
            ]
        );
    }

    /// Only while the owner's catalog block and suspension stand: with
    /// either lifted, the operator's request no longer holds, and a
    /// hideCatalog suspension or the catalog block hides the owner's
    /// envelopes as any hidden owner's.
    #[test]
    fn a_subject_record_releases_envelopes_only_while_its_block_and_suspension_stand() {
        let mut s = Snapshot::default();
        s.moderation.hidden.insert(U.to_string());
        s.moderation.hidden.insert(U2.to_string());
        let mut r = Requests::default();
        // A tombstone, and a pending request.
        subject(&mut r, U);
        let done = r.subjects.get_mut(U).unwrap();
        (done.state, done.deleted_at) = (State::Deleted, Some(NOW - GRACE));
        subject(&mut r, U2);
        envelope(&mut r, &h("e1"), Some(U), NOW - GRACE);
        envelope(&mut r, &h("e2"), Some(U2), NOW - GRACE);
        s.envelope_objects = BTreeSet::from([h("e1"), h("e2")]);

        let out = decide(&s, &r);
        assert!(out.due.is_empty(), "{:?}", out.due);
        assert_eq!(
            out.kept,
            [
                kept(format!("envelope {}", h("e1")), "owner hidden"),
                kept(format!("envelope {}", h("e2")), "owner hidden"),
                kept(format!("subject {U2}"), "catalog block lifted"),
            ]
        );

        // The catalog blocks stand, the suspensions are lifted.
        catalog_block(&mut s, U);
        catalog_block(&mut s, U2);
        let out = decide(&s, &r);
        assert!(out.due.is_empty(), "{:?}", out.due);
        assert_eq!(
            out.kept,
            [
                kept(format!("envelope {}", h("e1")), "owner hidden"),
                kept(format!("envelope {}", h("e2")), "owner hidden"),
                kept(format!("subject {U2}"), "suspension lifted"),
            ]
        );

        // Both stand: released.
        suspend(&mut s, U);
        suspend(&mut s, U2);
        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [
                Item::Envelope(h("e1")),
                Item::Envelope(h("e2")),
                Item::Subject(U2.to_string()),
            ]
        );
        assert!(out.kept.is_empty(), "{:?}", out.kept);
    }

    #[test]
    fn tombstones_are_neither_due_nor_kept() {
        let mut s = Snapshot::default();
        owns(&mut s, &h("a1"), "u1");
        s.moderation.blocked.insert(h("a2"));
        catalog_block(&mut s, "u1");
        let mut r = Requests::default();
        recording(&mut r, "u1", &h("a1"), 1);
        operator(&mut r, "u1", &h("a2"), Scope::Hash);
        subject(&mut r, "u1");
        envelope(&mut r, &h("e1"), None, 1);
        for request in r.recordings.values_mut() {
            (request.state, request.deleted_at) = (State::Deleted, Some(2));
        }
        for request in r.operator.values_mut() {
            (request.state, request.deleted_at) = (State::Deleted, Some(2));
        }
        for request in r.subjects.values_mut() {
            (request.state, request.deleted_at) = (State::Deleted, Some(2));
        }
        for request in r.envelopes.values_mut() {
            (request.state, request.deleted_at) = (State::Deleted, Some(2));
        }

        assert_eq!(decide(&s, &r), Decision::default());
    }

    #[test]
    fn due_and_kept_are_listed_by_id() {
        let mut s = Snapshot::default();
        owns(&mut s, &h("a1"), "u1");
        owns(&mut s, &h("a2"), "u1");
        block_and_suspend(&mut s, "u1");
        let mut r = Requests::default();
        subject(&mut r, "u1");
        recording(&mut r, "u1", &h("a2"), NOW - GRACE);
        recording(&mut r, "u1", &h("a1"), NOW - GRACE);
        envelope(&mut r, &h("e2"), None, NOW - GRACE);
        envelope(&mut r, &h("e1"), None, NOW - GRACE);
        // Kept, one of each kind.
        recording(&mut r, "u2", &h("a3"), NOW);
        operator(&mut r, "u2", &h("a3"), Scope::Hash);
        subject(&mut r, "u2");
        envelope(&mut r, &h("e3"), None, NOW);

        let out = decide(&s, &r);
        assert_eq!(
            out.due,
            [
                Item::Envelope(h("e1")),
                Item::Envelope(h("e2")),
                rec(&h("a1"), &[recording_key("u1", &h("a1"))]),
                rec(&h("a2"), &[recording_key("u1", &h("a2"))]),
                Item::Subject("u1".into()),
            ]
        );
        let ids: Vec<_> = out.kept.iter().map(|(id, _)| id.clone()).collect();
        assert_eq!(
            ids,
            [
                format!("envelope {}", h("e3")),
                format!("operator u2/{}", h("a3")),
                format!("recording u2/{}", h("a3")),
                "subject u2".to_string(),
            ]
        );
    }
}
