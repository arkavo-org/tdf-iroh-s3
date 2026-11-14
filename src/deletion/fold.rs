//! Folding committed transitions into deletion requests (spec 3.4 step 2).
//!
//! A transition is committed when a current pointer reaches it by `base`
//! links (spec 3.1); one from a publish that lost the pointer race never
//! is. [`fold`] walks back from each pointer to the first missing
//! transition (the start of history, or one an earlier run folded and
//! deleted), applies that chain oldest first, and sorts every transition
//! no pointer reaches into lost (deleted unfolded) or kept.
//!
//! A run that stops after writing its requests and before deleting the
//! transitions it folded folds them again next time. So applying a
//! transition over what it already wrote changes nothing (plan call 9):
//! - a drop sets a request pending over no record, a pending record, or a
//!   tombstone older than the drop, never over a tombstone at or after it;
//! - an add cancels a pending request only, never a tombstone.
//!
//! Pure: the sweep reads the [`Snapshot`] and writes what this decides.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::snapshot::{Requests, Snapshot};
use super::{
    EnvelopeRequest, GRACE, RecordingRequest, Source, State, Transition, transition_key,
    transition_name,
};
use crate::catalog_scan::{POINTERS, ScannedPointer};
use crate::moderation::canonical_subject;

/// Why an unreachable transition is kept: it may be a publish in flight.
const YOUNG: &str = "younger than grace";
/// Why an unreachable transition is kept: its publish may still land.
const AHEAD: &str = "seq above the current pointer";
/// Why an unreachable transition is kept: nothing says its publish lost.
const NO_POINTER: &str = "no pointer";
/// Why a chain is kept unfolded: its `base` links never end.
const CYCLE: &str = "a cycle in its chain";

/// What [`fold`] decided. The sweep writes `requests`, deletes the
/// `cancelled` requests, then deletes the `folded` transitions in order,
/// and the `lost` ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fold {
    /// Every request after folding: the snapshot's, with each committed
    /// transition applied.
    pub requests: Requests,
    /// `(sub, hash)` of each recording request the snapshot held pending
    /// that folding removed, because an add re-listed its hash: the sweep
    /// deletes these. A request an add cancelled and a later drop set
    /// again is in `requests`, not here.
    pub cancelled: Vec<(String, String)>,
    /// The transitions applied, by key, oldest first in each chain. Deleted
    /// in this order, a run that stops part way leaves each chain's newest
    /// transitions, still reachable from the pointer.
    pub folded: Vec<String>,
    /// Transitions no pointer reaches, at least [`GRACE`] old, whose
    /// subject's current pointer has a `seq` at least theirs: publishes
    /// that lost the pointer race. Deleted unfolded.
    pub lost: Vec<String>,
    /// Transitions left as they are, with why: unreachable ones not yet
    /// lost, and each transition of a chain whose `base` links cycle.
    pub kept: Vec<(String, &'static str)>,
}

/// Fold every committed transition in `snapshot` into its requests, and
/// sort out the transitions no pointer reaches. `now` is Unix seconds.
pub fn fold(snapshot: &Snapshot, now: i64) -> Fold {
    let Snapshot {
        catalogs,
        transitions,
        requests: stored,
        ..
    } = snapshot;
    // No chain without a cycle is longer than the transitions there are.
    let cap = catalogs.pointers.len() + transitions.len();
    let mut requests = stored.clone();
    let mut folded = Vec::new();
    let mut kept = Vec::new();
    // Every transition a pointer reaches, folded or kept.
    let mut reached = HashSet::new();
    for p in &catalogs.pointers {
        match walk(transitions, p, cap) {
            Walk::Chain(chain) => {
                for (key, t) in chain.into_iter().rev() {
                    apply(&mut requests, t);
                    reached.insert(key);
                    folded.push(key.clone());
                }
            }
            Walk::Cycle(keys) => {
                for key in keys {
                    if reached.insert(key) {
                        kept.push((key.clone(), CYCLE));
                    }
                }
            }
        }
    }

    // Each pointer's `seq`, by its key's sub, byte for byte, as transition
    // keys and bodies name it.
    let current: HashMap<&str, u64> = catalogs
        .pointers
        .iter()
        .map(|p| (pointer_sub(p), p.seq))
        .collect();
    let mut lost = Vec::new();
    for (key, t) in transitions {
        if reached.contains(key) {
            continue;
        }
        let why = if t.at.saturating_add(GRACE) > now {
            Some(YOUNG)
        } else {
            match current.get(t.subject.as_str()) {
                None => Some(NO_POINTER),
                Some(&seq) if seq < t.seq => Some(AHEAD),
                Some(_) => None,
            }
        };
        match why {
            Some(why) => kept.push((key.clone(), why)),
            None => lost.push(key.clone()),
        }
    }

    let cancelled = stored
        .recordings
        .iter()
        .filter(|(key, r)| r.state == State::Pending && !requests.recordings.contains_key(*key))
        .map(|(key, _)| key.clone())
        .collect();
    Fold {
        requests,
        cancelled,
        folded,
        lost,
        kept,
    }
}

/// A pointer's walk back through `base` links.
enum Walk<'a> {
    /// Newest first, from the transition of the pointer's own publish to
    /// the last before a missing one or a `null` base.
    Chain(Vec<(&'a String, &'a Transition)>),
    /// The keys walked, newest first and with repeats, when the walk took
    /// `cap` steps and could go on: only `base` links that cycle do that.
    Cycle(Vec<&'a String>),
}

fn walk<'a>(
    transitions: &'a BTreeMap<String, Transition>,
    p: &ScannedPointer,
    cap: usize,
) -> Walk<'a> {
    let sub = pointer_sub(p);
    let mut chain: Vec<(&String, &Transition)> = Vec::new();
    let mut next = Some(transition_key(sub, &transition_name(p.seq, &p.digest)));
    while let Some((key, t)) = next.take().and_then(|k| transitions.get_key_value(&k)) {
        if chain.len() == cap {
            return Walk::Cycle(chain.into_iter().map(|(key, _)| key).collect());
        }
        chain.push((key, t));
        next = t
            .base
            .as_ref()
            .map(|b| transition_key(sub, &transition_name(b.seq, &b.pointer)));
    }
    Walk::Chain(chain)
}

/// The pointer key's `<sub>`, byte for byte, which transition keys carry.
/// [`crate::catalog_scan::scan`] lists every pointer under [`POINTERS`].
fn pointer_sub(p: &ScannedPointer) -> &str {
    p.key.strip_prefix(POINTERS).unwrap_or(&p.key)
}

/// Apply one committed transition (spec 3.4 step 2, under plan call 9).
/// Request keys carry the canonical subject.
fn apply(requests: &mut Requests, t: &Transition) {
    let subject = canonical_subject(&t.subject);
    let key = |hash: &String| (subject.to_string(), hash.clone());
    for hash in &t.added {
        if requests
            .recordings
            .get(&key(hash))
            .is_some_and(|r| r.state == State::Pending)
        {
            requests.recordings.remove(&key(hash));
        }
    }
    for hash in &t.dropped {
        let stored = requests.recordings.get(&key(hash));
        if may_set_pending(stored.map(|r| (r.state, r.deleted_at)), t.at) {
            requests.recordings.insert(
                key(hash),
                RecordingRequest {
                    hash: hash.clone(),
                    subject: subject.to_string(),
                    requested_at: t.at,
                    seq: t.seq,
                    state: State::Pending,
                    deleted_at: None,
                },
            );
        }
    }
    if let Some(base) = &t.base
        && base.catalog_hash != t.catalog_hash
    {
        let stored = requests.envelopes.get(&base.catalog_hash);
        if may_set_pending(stored.map(|r| (r.state, r.deleted_at)), t.at) {
            requests.envelopes.insert(
                base.catalog_hash.clone(),
                EnvelopeRequest {
                    hash: base.catalog_hash.clone(),
                    owner: Some(subject.to_string()),
                    superseded_at: t.at,
                    source: Source::Transition,
                    state: State::Pending,
                    deleted_at: None,
                },
            );
        }
    }
}

/// Whether a request may be set pending at `at` over the stored one's
/// `(state, deletedAt)`: none, a pending one, or a tombstone from before
/// `at`. A tombstone at or after `at` stays: the transition is a re-fold
/// of one its deletion already covered. So does one without a date, which
/// the strict read refuses anyway.
fn may_set_pending(stored: Option<(State, Option<i64>)>, at: i64) -> bool {
    match stored {
        None | Some((State::Pending, _)) => true,
        Some((State::Deleted, deleted_at)) => deleted_at.is_some_and(|d| d < at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_scan::{POINTERS, ScannedPointer};
    use crate::deletion::{
        EnvelopeRequest, GRACE, RecordingRequest, Source, State, Transition, TransitionBase,
        transition_key, transition_name,
    };
    use crate::moderation::canonical_subject;

    const U: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    /// The signed pointer digest of `seq`'s publish, in these tests.
    fn digest(seq: u64) -> String {
        format!("{seq:064x}")
    }

    /// The envelope `seq`'s publish names, in these tests.
    fn catalog(seq: u64) -> String {
        format!("{:064x}", 0xc000 + seq)
    }

    /// `sub`'s publish `seq` at `at`, based on publish `seq - 1` (none for
    /// seq 1), each with its own envelope.
    fn transition(sub: &str, seq: u64, at: i64, dropped: &[&str], added: &[&str]) -> Transition {
        Transition {
            subject: sub.into(),
            seq,
            catalog_hash: catalog(seq),
            pointer: digest(seq),
            base: (seq > 1).then(|| TransitionBase {
                seq: seq - 1,
                catalog_hash: catalog(seq - 1),
                pointer: digest(seq - 1),
            }),
            at,
            dropped: dropped.iter().map(|s| s.to_string()).collect(),
            added: added.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Where `t` is stored.
    fn key_of(t: &Transition) -> String {
        transition_key(&t.subject, &transition_name(t.seq, &t.pointer))
    }

    /// `sub`'s publish `seq`'s key, as [`transition`] builds it.
    fn key(sub: &str, seq: u64) -> String {
        transition_key(sub, &transition_name(seq, &digest(seq)))
    }

    fn store(s: &mut Snapshot, t: Transition) {
        s.transitions.insert(key_of(&t), t);
    }

    /// `catalog-pointers/<sub>` at publish `seq`.
    fn point(s: &mut Snapshot, sub: &str, seq: u64) {
        s.catalogs.pointers.push(ScannedPointer {
            key: format!("{POINTERS}{sub}"),
            subject: canonical_subject(sub).to_string(),
            seq,
            catalog_hash: catalog(seq),
            index_hash: Some(h("1d")),
            digest: digest(seq),
        });
    }

    /// `sub`'s pointer at the last of `steps`, and one stored transition
    /// per step, seq 1 onwards: `(at, dropped, added)`.
    fn chain(sub: &str, steps: &[(i64, &[&str], &[&str])]) -> Snapshot {
        let mut s = Snapshot::default();
        for (seq, (at, dropped, added)) in (1..).zip(steps) {
            store(&mut s, transition(sub, seq, *at, dropped, added));
        }
        point(&mut s, sub, steps.len() as u64);
        s
    }

    fn pending(sub: &str, hash: &str, requested_at: i64, seq: u64) -> RecordingRequest {
        RecordingRequest {
            hash: hash.into(),
            subject: sub.into(),
            requested_at,
            seq,
            state: State::Pending,
            deleted_at: None,
        }
    }

    fn tombstone(sub: &str, hash: &str, deleted_at: i64) -> RecordingRequest {
        RecordingRequest {
            state: State::Deleted,
            deleted_at: Some(deleted_at),
            ..pending(sub, hash, 1, 1)
        }
    }

    fn with_recording(s: &mut Snapshot, r: RecordingRequest) {
        s.requests
            .recordings
            .insert((r.subject.clone(), r.hash.clone()), r);
    }

    fn rk(sub: &str, hash: &str) -> (String, String) {
        (sub.to_string(), hash.to_string())
    }

    const NOW: i64 = 1_000_000_000;

    #[test]
    fn a_chain_is_folded_oldest_first() {
        let p1 = h("a1");
        let s = chain(
            "u1",
            &[(100, &[], &[&p1]), (200, &[&p1], &[]), (300, &[], &[&p1])],
        );
        let out = fold(&s, NOW);
        assert_eq!(out.requests.recordings.get(&rk("u1", &p1)), None);
        assert_eq!(out.folded, [key("u1", 1), key("u1", 2), key("u1", 3)]);
        assert!(out.cancelled.is_empty(), "no stored request to cancel");
        assert!(out.lost.is_empty() && out.kept.is_empty());

        // Oldest first: a drop after an add stands, an add after a drop
        // cancels it.
        let s = chain("u1", &[(100, &[], &[&p1]), (200, &[&p1], &[])]);
        assert_eq!(
            fold(&s, NOW).requests.recordings[&rk("u1", &p1)],
            pending("u1", &p1, 200, 2)
        );
        let s = chain("u1", &[(100, &[&p1], &[]), (200, &[], &[&p1])]);
        assert_eq!(fold(&s, NOW).requests.recordings.get(&rk("u1", &p1)), None);
    }

    #[test]
    fn the_newest_drop_wins() {
        let p = h("a1");
        let s = chain(
            "u1",
            &[(100, &[&p], &[]), (200, &[], &[&p]), (300, &[&p], &[])],
        );
        let out = fold(&s, NOW);
        assert_eq!(
            out.requests.recordings[&rk("u1", &p)],
            pending("u1", &p, 300, 3)
        );
        assert!(out.cancelled.is_empty(), "the request stands");

        // Over a stored pending request too: the add cancels it, the newer
        // drop sets it again, and it is not cancelled (the sweep would
        // delete the request it writes).
        let mut s = chain("u1", &[(200, &[], &[&p]), (300, &[&p], &[])]);
        with_recording(&mut s, pending("u1", &p, 100, 7));
        let out = fold(&s, NOW);
        assert_eq!(
            out.requests.recordings[&rk("u1", &p)],
            pending("u1", &p, 300, 2)
        );
        assert!(out.cancelled.is_empty(), "{:?}", out.cancelled);
    }

    #[test]
    fn an_add_cancels_a_stored_pending_request() {
        let (p, q) = (h("a1"), h("a2"));
        let mut s = chain("u1", &[(200, &[], &[&p])]);
        with_recording(&mut s, pending("u1", &p, 100, 7));
        with_recording(&mut s, pending("u1", &q, 100, 7));
        let out = fold(&s, NOW);
        assert_eq!(out.requests.recordings.get(&rk("u1", &p)), None);
        assert_eq!(out.cancelled, [rk("u1", &p)]);
        assert_eq!(
            out.requests.recordings[&rk("u1", &q)],
            pending("u1", &q, 100, 7),
            "untouched"
        );
    }

    #[test]
    fn requests_are_keyed_canonically() {
        let p = h("a1");
        let arkavo = format!("arkavo:{U}");
        let s = chain(&arkavo, &[(100, &[], &[&p]), (200, &[&p], &[])]);
        let out = fold(&s, NOW);
        assert_eq!(out.folded, [key(&arkavo, 1), key(&arkavo, 2)]);
        assert_eq!(
            out.requests.recordings.keys().collect::<Vec<_>>(),
            [&rk(U, &p)]
        );
        assert_eq!(out.requests.recordings[&rk(U, &p)].subject, U);

        // And a stored request under the canonical subject is the one an
        // add cancels.
        let mut s = chain(&arkavo, &[(300, &[], &[&p])]);
        with_recording(&mut s, pending(U, &p, 200, 2));
        let out = fold(&s, NOW);
        assert!(out.requests.recordings.is_empty());
        assert_eq!(out.cancelled, [rk(U, &p)]);
    }

    #[test]
    fn a_superseded_envelope_becomes_pending() {
        let arkavo = format!("arkavo:{U}");
        let mut s = chain(&arkavo, &[(100, &[], &[]), (200, &[], &[])]);
        // Publish 3 names publish 2's envelope again: nothing superseded.
        let mut same = transition(&arkavo, 3, 300, &[], &[]);
        same.catalog_hash = catalog(2);
        store(&mut s, same);
        s.catalogs.pointers[0].seq = 3;
        s.catalogs.pointers[0].digest = digest(3);

        let out = fold(&s, NOW);
        assert_eq!(
            out.requests.envelopes.keys().collect::<Vec<_>>(),
            [&catalog(1)],
            "only a base with another catalog hash"
        );
        assert_eq!(
            out.requests.envelopes[&catalog(1)],
            EnvelopeRequest {
                hash: catalog(1),
                owner: Some(U.to_string()),
                superseded_at: 200,
                source: Source::Transition,
                state: State::Pending,
                deleted_at: None,
            }
        );
    }

    #[test]
    fn the_walk_stops_at_a_missing_transition() {
        let (p, q) = (h("a1"), h("a2"));
        let mut s = chain(
            "u1",
            &[(100, &[&p], &[]), (200, &[&q], &[]), (300, &[], &[])],
        );
        s.transitions.remove(&key("u1", 1));
        let out = fold(&s, NOW);
        assert_eq!(out.folded, [key("u1", 2), key("u1", 3)]);
        assert_eq!(
            out.requests.recordings.keys().collect::<Vec<_>>(),
            [&rk("u1", &q)]
        );

        // A pointer with no transition of its own (from before transitions)
        // folds nothing, and keeps what its subject stored.
        let mut s = Snapshot::default();
        point(&mut s, "u1", 4);
        store(&mut s, transition("u1", 3, NOW, &[&p], &[]));
        let out = fold(&s, NOW);
        assert!(out.folded.is_empty());
        assert!(out.requests.recordings.is_empty());
    }

    #[test]
    fn refolding_is_idempotent() {
        let p = h("a1");
        for (at, expected) in [
            (200, tombstone("u1", &p, 500)),
            (500, tombstone("u1", &p, 500)),
            (600, pending("u1", &p, 600, 1)),
        ] {
            let mut s = chain("u1", &[(at, &[&p], &[])]);
            with_recording(&mut s, tombstone("u1", &p, 500));
            let out = fold(&s, NOW);
            assert_eq!(out.requests.recordings[&rk("u1", &p)], expected, "{at}");
            assert!(out.cancelled.is_empty());
        }

        // Envelopes the same way.
        let deleted = EnvelopeRequest {
            hash: catalog(1),
            owner: Some("u1".into()),
            superseded_at: 100,
            source: Source::Transition,
            state: State::Deleted,
            deleted_at: Some(500),
        };
        for (at, state) in [
            (200, State::Deleted),
            (500, State::Deleted),
            (600, State::Pending),
        ] {
            let mut s = chain("u1", &[(100, &[], &[]), (at, &[], &[])]);
            s.requests.envelopes.insert(catalog(1), deleted.clone());
            let envelope = &fold(&s, NOW).requests.envelopes[&catalog(1)];
            if state == State::Deleted {
                assert_eq!(envelope, &deleted, "{at}");
            } else {
                assert_eq!(envelope.state, State::Pending);
                assert_eq!(envelope.superseded_at, at);
                assert_eq!(envelope.deleted_at, None);
            }
        }

        // Folding what a fold wrote, over the same transitions (a crash
        // before they were deleted), changes nothing.
        let (q, r) = (h("a2"), h("a3"));
        let mut s = chain(
            "u1",
            &[
                (100, &[&p, &q], &[&r]),
                (200, &[&r], &[&p]),
                (300, &[], &[&q]),
            ],
        );
        with_recording(&mut s, pending("u1", &q, 50, 1));
        with_recording(&mut s, tombstone("u1", &r, 150));
        let first = fold(&s, NOW);
        s.requests = first.requests.clone();
        let second = fold(&s, NOW);
        assert_eq!(second.requests, first.requests);
        assert!(second.cancelled.is_empty(), "{:?}", second.cancelled);
        assert_eq!(second.folded, first.folded);
    }

    #[test]
    fn an_add_does_not_cancel_a_tombstone() {
        let p = h("a1");
        let mut s = chain("u1", &[(600, &[], &[&p])]);
        with_recording(&mut s, tombstone("u1", &p, 500));
        let out = fold(&s, NOW);
        assert_eq!(
            out.requests.recordings[&rk("u1", &p)],
            tombstone("u1", &p, 500)
        );
        assert!(out.cancelled.is_empty());
    }

    /// Publish `seq` of `sub` that lost the pointer race: its own digest,
    /// so no pointer reaches it.
    fn losing(sub: &str, seq: u64, at: i64, dropped: &[&str]) -> Transition {
        Transition {
            pointer: h("ee"),
            ..transition(sub, seq, at, dropped, &[])
        }
    }

    #[test]
    fn a_lost_transition_is_deleted_after_grace() {
        let p = h("a1");
        let mut s = chain("u1", &[(100, &[], &[]), (200, &[], &[])]);
        let below = losing("u1", 1, 100, &[&p]);
        let equal = losing("u1", 2, 200, &[&p]);
        let (below_key, equal_key) = (key_of(&below), key_of(&equal));
        store(&mut s, below);
        store(&mut s, equal);

        let out = fold(&s, 200 + GRACE);
        assert_eq!(out.lost, [below_key, equal_key]);
        assert!(out.kept.is_empty(), "{:?}", out.kept);
        assert_eq!(out.folded, [key("u1", 1), key("u1", 2)]);
        assert!(
            out.requests.recordings.is_empty(),
            "a lost transition is never applied"
        );
    }

    #[test]
    fn an_unreachable_transition_is_kept_otherwise() {
        let p = h("a1");
        let arkavo = format!("arkavo:{U}");
        let mut s = chain("u1", &[(100, &[], &[]), (200, &[], &[])]);
        let young = losing("u1", 2, 200, &[&p]);
        let ahead = losing("u1", 3, 100, &[&p]);
        // No pointer: none under its sub, byte for byte (the `arkavo:`
        // pointer is not `U`'s).
        let orphan = losing(U, 1, 100, &[&p]);
        point(&mut s, &arkavo, 1);
        let keys = [key_of(&young), key_of(&ahead), key_of(&orphan)];
        for t in [young, ahead, orphan] {
            store(&mut s, t);
        }

        let out = fold(&s, 200 + GRACE - 1);
        let mut kept = out.kept.clone();
        kept.sort();
        let mut expected = vec![
            (keys[0].clone(), "younger than grace"),
            (keys[1].clone(), "seq above the current pointer"),
            (keys[2].clone(), "no pointer"),
        ];
        expected.sort();
        assert_eq!(kept, expected);
        assert!(out.lost.is_empty());
        assert!(out.requests.recordings.is_empty());
    }

    #[test]
    fn a_cycle_is_kept_unfolded() {
        let p = h("a1");
        // A transition whose base names itself.
        let mut s = chain("u1", &[(100, &[&p], &[])]);
        s.transitions.get_mut(&key("u1", 1)).unwrap().base = Some(TransitionBase {
            seq: 1,
            catalog_hash: catalog(0),
            pointer: digest(1),
        });
        let out = fold(&s, NOW);
        assert!(out.folded.is_empty());
        assert_eq!(out.kept, [(key("u1", 1), "a cycle in its chain")]);
        assert!(out.lost.is_empty());
        assert_eq!(out.requests, s.requests, "nothing applied");

        // Two transitions naming each other, under a pointer that also has a
        // sound neighbour: each is kept once, and the neighbour folds.
        let mut s = chain("u1", &[(100, &[&p], &[]), (200, &[&p], &[])]);
        s.transitions.get_mut(&key("u1", 1)).unwrap().base = Some(TransitionBase {
            seq: 2,
            catalog_hash: catalog(2),
            pointer: digest(2),
        });
        let sound = chain("u2", &[(100, &[&p], &[])]);
        s.transitions.extend(sound.transitions);
        s.catalogs.pointers.extend(sound.catalogs.pointers);
        let out = fold(&s, NOW);
        assert_eq!(out.folded, [key("u2", 1)]);
        assert_eq!(
            out.kept,
            [
                (key("u1", 2), "a cycle in its chain"),
                (key("u1", 1), "a cycle in its chain"),
            ]
        );
        assert!(out.lost.is_empty());
        assert_eq!(
            out.requests.recordings.keys().collect::<Vec<_>>(),
            [&rk("u2", &p)]
        );
    }
}
