//! Deletion requests (`docs/superpowers/specs/2026-11-13-deletion-requests-design.md`,
//! Part 3): a recording its owner dropped from their catalog is deleted.
//!
//! Each publish records a [`Transition`] at
//! `catalog-transitions/<sub>/<`[`transition_name`]`>`: what it dropped from
//! the served base catalog and what it added. The offline sweep folds only
//! committed transitions, those reachable from a current pointer by `base`
//! links, into deletion requests; a transition from a publish that lost the
//! pointer race is never reachable.

use serde::{Deserialize, Serialize};

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

/// What one publish changed (spec 3.1), written before its document, index
/// and pointer, and never served.
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
    /// `null` when none was stored.
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
}
