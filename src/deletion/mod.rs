//! Deletion requests (`docs/superpowers/specs/2026-11-13-deletion-requests-design.md`,
//! Part 3): a recording its owner dropped from their catalog is deleted.
//!
//! Each publish records a [`Transition`] at
//! `catalog-transitions/<sub>/<`[`transition_name`]`>`: what it dropped from
//! the served base catalog and what it added. The offline sweep folds only
//! committed transitions, those reachable from a current pointer by `base`
//! links, into deletion requests; a transition from a publish that lost the
//! pointer race is never reachable. Deleting an account deletes its
//! transitions, its publish history, with its pointers.
//!
//! The requests (spec 3.2) live under `deletion-requests/`, written only by
//! the sweep and the operator commands. Their keys carry canonical subjects
//! (`moderation::canonical_subject`); transition keys carry the pointer
//! key's subject, byte for byte.

use serde::{Deserialize, Serialize};

use crate::catalog_scan::INDEXES;
use crate::creator_catalog::Object;

pub mod due;
pub mod fold;
pub mod operator;
pub mod snapshot;
pub mod sweep;

/// Where transitions live: `catalog-transitions/<sub>/<name>`.
pub const TRANSITIONS: &str = "catalog-transitions/";
/// `deletion-requests/recordings/<sub>/<hash>`: [`RecordingRequest`].
pub const RECORDINGS: &str = "deletion-requests/recordings/";
/// `deletion-requests/envelopes/<hash>`: [`EnvelopeRequest`].
pub const ENVELOPES: &str = "deletion-requests/envelopes/";
/// `deletion-requests/operator/<sub>/<hash>`: [`OperatorRequest`].
pub const OPERATOR: &str = "deletion-requests/operator/";
/// `deletion-requests/subjects/<sub>`: [`SubjectRequest`].
pub const SUBJECTS: &str = "deletion-requests/subjects/";

/// Where a catalog document lives, with its `owner` metadata:
/// `catalog-documents/<catalog hash>`.
pub const DOCUMENTS: &str = "catalog-documents/";
/// A catalog envelope's objects, each keyed by its catalog hash, in the
/// order the sweep deletes them: its document, its outboard, its index
/// record. The snapshot only lists them ([`snapshot::Snapshot::envelope_objects`]).
pub const ENVELOPE_OBJECTS: [&str; 3] = [DOCUMENTS, "catalog-outboards/", INDEXES];

/// How long a request waits before it is due, and how old an unreachable
/// transition must be before the sweep deletes it unfolded: 7 days, in
/// seconds.
pub const GRACE: i64 = 604_800;

/// How long after a deletion its tombstone is verified: 1 hour, in seconds.
pub const VERIFY_AFTER: i64 = 3_600;

/// A transition's name under `catalog-transitions/<sub>/`: the publish's
/// `seq` (20 digits, so names sort by it) and the lowercase hex SHA-256 of
/// its signed pointer bytes, which makes the name unique to one signed
/// pointer.
pub fn transition_name(seq: u64, digest: &str) -> String {
    format!("{seq:020}-{digest}")
}

/// `catalog-transitions/<sub>/<name>`: `sub` is the pointer key's, byte for
/// byte (not canonical), and `name` a [`transition_name`].
pub fn transition_key(sub: &str, name: &str) -> String {
    format!("{TRANSITIONS}{sub}/{name}")
}

/// `deletion-requests/recordings/<sub>/<hash>`; `sub` canonical.
pub fn recording_key(sub: &str, hash: &str) -> String {
    format!("{RECORDINGS}{sub}/{hash}")
}

/// `deletion-requests/envelopes/<hash>`.
pub fn envelope_key(hash: &str) -> String {
    format!("{ENVELOPES}{hash}")
}

/// `deletion-requests/operator/<sub>/<hash>`; `sub` canonical.
pub fn operator_key(sub: &str, hash: &str) -> String {
    format!("{OPERATOR}{sub}/{hash}")
}

/// `deletion-requests/subjects/<sub>`; `sub` canonical.
pub fn subject_key(sub: &str) -> String {
    format!("{SUBJECTS}{sub}")
}

/// Where a request stands. A `deleted` request is a tombstone: it carries
/// `deletedAt` and stays until a later run verifies every object is still
/// gone (spec 3.4 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Pending,
    Deleted,
}

/// How the sweep learned an envelope was superseded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// A folded transition's `base` named it.
    Transition,
    /// Listed under `catalog-documents/`, `catalog-outboards/` or
    /// `catalog-indexes/`, named by no pointer and by no request.
    Observed,
}

/// What an operator request covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// One blocked hash (`request-deletion --hash`).
    Hash,
    /// One hash of a catalog-blocked, suspended subject
    /// (`request-deletion --all`).
    Subject,
}

/// `deletion-requests/recordings/<sub>/<hash>`: the owner dropped `hash`
/// from their catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingRequest {
    pub hash: String,
    /// Canonical.
    pub subject: String,
    /// The dropping transition's `at`.
    pub requested_at: i64,
    /// The dropping transition's `seq`.
    pub seq: u64,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// `deletion-requests/envelopes/<hash>`: a catalog envelope no pointer
/// names any more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeRequest {
    pub hash: String,
    /// The publisher, when known: the transition's subject, or the
    /// document's `owner` metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub superseded_at: i64,
    pub source: Source,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// `deletion-requests/operator/<sub>/<hash>`: an operator asked for
/// `hash` to go (`request-deletion`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorRequest {
    pub hash: String,
    /// Canonical.
    pub subject: String,
    pub requested_at: i64,
    pub reason: String,
    pub scope: Scope,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// `deletion-requests/subjects/<sub>`: an operator asked for everything
/// `sub` published to go (`request-deletion --all`), its pointers and its
/// transitions included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectRequest {
    /// Canonical.
    pub subject: String,
    pub requested_at: i64,
    pub reason: String,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

/// What one publish changed (spec 3.1), written after its index record and
/// before its document, outboard and pointer, once per signed pointer
/// (`catalogs_v2_api::write_transition`), and never served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transition {
    /// The pointer key's subject, byte for byte.
    pub subject: String,
    pub seq: u64,
    /// The new envelope's BLAKE3 hash.
    pub catalog_hash: String,
    /// Lowercase hex SHA-256 of this publish's signed pointer bytes.
    pub pointer: String,
    /// The stored pointer this publish replaces, whatever its visibility;
    /// `null` when none was stored. A missing key reads as `null`.
    #[serde(default, deserialize_with = "optional_object")]
    pub base: Option<TransitionBase>,
    /// When the publish was made (Unix seconds): a drop's clock.
    pub at: i64,
    /// Payload hashes in the served base's index and not in the new one,
    /// less those blocked at publish and those whose owner record doesn't
    /// name the publisher. Sorted.
    pub dropped: Vec<String>,
    /// Payload hashes in the new index and not in the base's live index.
    /// Sorted.
    pub added: Vec<String>,
}

/// The stored pointer a publish replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionBase {
    pub seq: u64,
    pub catalog_hash: String,
    /// Lowercase hex SHA-256 of the stored pointer's signed bytes.
    pub pointer: String,
}

/// `null`, or a `T` read through `creator_catalog::object`.
fn optional_object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Ok(Option::<Object<T>>::deserialize(d)?.map(|o| o.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_sort_by_seq() {
        assert_eq!(transition_name(1, "ab"), "00000000000000000001-ab");
        assert_eq!(
            transition_name(u64::MAX, "cd"),
            "18446744073709551615-cd",
            "20 digits hold every seq"
        );
        assert!(transition_name(9, "ff") < transition_name(10, "00"));
    }

    #[test]
    fn a_transition_reads_back_and_refuses_unknown_keys() {
        let first = Transition {
            subject: "u1".into(),
            seq: 1,
            catalog_hash: "aa".into(),
            pointer: "bb".into(),
            base: None,
            at: 7,
            dropped: vec![],
            added: vec!["cc".into()],
        };
        let value = serde_json::to_value(&first).unwrap();
        assert_eq!(
            value,
            json!({"subject": "u1", "seq": 1, "catalogHash": "aa", "pointer": "bb",
                   "base": null, "at": 7, "dropped": [], "added": ["cc"]})
        );
        assert_eq!(
            serde_json::from_value::<Transition>(value.clone()).unwrap(),
            first
        );

        let mut extra = value;
        extra["base"] = json!({"seq": 0, "catalogHash": "dd", "pointer": "ee", "x": 1});
        assert!(serde_json::from_value::<Transition>(extra.clone()).is_err());
        extra["base"] = json!(null);
        extra["x"] = json!(1);
        assert!(serde_json::from_value::<Transition>(extra).is_err());
    }

    fn h(byte: &str) -> String {
        byte.repeat(32)
    }

    /// `record` serializes to exactly `expected` and reads back as itself.
    fn round_trips<T>(record: &T, expected: serde_json::Value)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(value, expected);
        assert_eq!(&serde_json::from_value::<T>(value).unwrap(), record);
    }

    #[test]
    fn records_round_trip_in_the_spec_shape() {
        let mut recording = RecordingRequest {
            hash: h("aa"),
            subject: "u1".into(),
            requested_at: 100,
            seq: 3,
            state: State::Pending,
            deleted_at: None,
        };
        round_trips(
            &recording,
            json!({"hash": h("aa"), "subject": "u1", "requestedAt": 100, "seq": 3,
                   "state": "pending"}),
        );
        recording.state = State::Deleted;
        recording.deleted_at = Some(200);
        round_trips(
            &recording,
            json!({"hash": h("aa"), "subject": "u1", "requestedAt": 100, "seq": 3,
                   "state": "deleted", "deletedAt": 200}),
        );

        let mut envelope = EnvelopeRequest {
            hash: h("bb"),
            owner: None,
            superseded_at: 100,
            source: Source::Transition,
            state: State::Pending,
            deleted_at: None,
        };
        round_trips(
            &envelope,
            json!({"hash": h("bb"), "supersededAt": 100, "source": "transition",
                   "state": "pending"}),
        );
        envelope.owner = Some("arkavo:u1".into());
        envelope.source = Source::Observed;
        envelope.state = State::Deleted;
        envelope.deleted_at = Some(200);
        round_trips(
            &envelope,
            json!({"hash": h("bb"), "owner": "arkavo:u1", "supersededAt": 100,
                   "source": "observed", "state": "deleted", "deletedAt": 200}),
        );

        let mut operator = OperatorRequest {
            hash: h("cc"),
            subject: "u1".into(),
            requested_at: 100,
            reason: "court order".into(),
            scope: Scope::Hash,
            state: State::Pending,
            deleted_at: None,
        };
        round_trips(
            &operator,
            json!({"hash": h("cc"), "subject": "u1", "requestedAt": 100,
                   "reason": "court order", "scope": "hash", "state": "pending"}),
        );
        operator.scope = Scope::Subject;
        operator.state = State::Deleted;
        operator.deleted_at = Some(200);
        round_trips(
            &operator,
            json!({"hash": h("cc"), "subject": "u1", "requestedAt": 100,
                   "reason": "court order", "scope": "subject", "state": "deleted",
                   "deletedAt": 200}),
        );

        let mut subject = SubjectRequest {
            subject: "u1".into(),
            requested_at: 100,
            reason: "account closed".into(),
            state: State::Pending,
            deleted_at: None,
        };
        round_trips(
            &subject,
            json!({"subject": "u1", "requestedAt": 100, "reason": "account closed",
                   "state": "pending"}),
        );
        subject.state = State::Deleted;
        subject.deleted_at = Some(200);
        round_trips(
            &subject,
            json!({"subject": "u1", "requestedAt": 100, "reason": "account closed",
                   "state": "deleted", "deletedAt": 200}),
        );
    }

    #[test]
    fn an_unknown_field_is_unreadable() {
        fn refuses<T: serde::de::DeserializeOwned>(valid: serde_json::Value) {
            assert!(
                serde_json::from_value::<T>(valid.clone()).is_ok(),
                "{valid}"
            );
            let mut extra = valid;
            extra["x"] = json!(1);
            assert!(
                serde_json::from_value::<T>(extra.clone()).is_err(),
                "{extra}"
            );
        }
        refuses::<RecordingRequest>(json!({"hash": h("aa"), "subject": "u1",
            "requestedAt": 1, "seq": 1, "state": "pending"}));
        refuses::<EnvelopeRequest>(json!({"hash": h("aa"), "supersededAt": 1,
            "source": "observed", "state": "pending"}));
        refuses::<OperatorRequest>(json!({"hash": h("aa"), "subject": "u1",
            "requestedAt": 1, "reason": "r", "scope": "hash", "state": "pending"}));
        refuses::<SubjectRequest>(json!({"subject": "u1", "requestedAt": 1,
            "reason": "r", "state": "pending"}));

        // Enums are the spec's lowercase words, nothing else.
        assert!(serde_json::from_value::<State>(json!("Pending")).is_err());
        assert!(serde_json::from_value::<State>(json!("lifted")).is_err());
        assert!(serde_json::from_value::<Source>(json!("pointer")).is_err());
        assert!(serde_json::from_value::<Scope>(json!("all")).is_err());
        // And every field but `owner` and `deletedAt` is required.
        assert!(
            serde_json::from_value::<SubjectRequest>(
                json!({"subject": "u1", "requestedAt": 1, "state": "pending"})
            )
            .is_err()
        );
    }

    #[test]
    fn keys_are_the_spec_layout() {
        let h = h("aa");
        assert_eq!(
            recording_key("u1", &h),
            format!("deletion-requests/recordings/u1/{h}")
        );
        assert_eq!(envelope_key(&h), format!("deletion-requests/envelopes/{h}"));
        assert_eq!(
            operator_key("u1", &h),
            format!("deletion-requests/operator/u1/{h}")
        );
        assert_eq!(subject_key("u1"), "deletion-requests/subjects/u1");
        assert_eq!(
            transition_key("arkavo:u1", &transition_name(7, "ab")),
            "catalog-transitions/arkavo:u1/00000000000000000007-ab",
            "the pointer key's sub, byte for byte"
        );
    }
}
