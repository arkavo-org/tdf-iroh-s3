//! Ingest-time catalog index (tdf-iroh-s3#5, phase 1).
//!
//! Performance rationale: the manifest is already parsed and in memory
//! during ingest validation, so deriving catalog artifacts at that moment
//! costs two small S3 PUTs. The alternative — indexing later — would mean
//! downloading multi-gigabyte content blobs and unzipping them just to
//! read a few kilobytes of policy. Three artifacts per blob:
//!
//! - `blobs/<hash>` — the TDF itself (pre-existing).
//! - `manifests/<hash>` — the extracted manifest.json, so any future
//!   consumer (re-indexing, catalog UI metadata, debugging) can read
//!   policy without touching the payload.
//! - `catalog-index/<group>/<hash>` — a tiny JSON entry per group the
//!   blob belongs to, keyed by the configured grouping attribute
//!   (default: the Patreon campaign id). This is the read path for the
//!   entitled-catalog endpoint: list a prefix, never open a blob.
//!
//! Grouping derives from the TDF's own data attributes — consistent with
//! the curation model (ArkavoKit#1): creators curate by labeling, and a
//! blob with no grouping attribute is simply in no catalog.

use anyhow::{Context, Result};
use opentdf::{AttributePolicy, AttributeValue, LogicalOperator, Policy};
use serde::{Deserialize, Serialize};

/// One catalog index entry, stored as `catalog-index/<group>/<hash>`.
/// Kept small: the catalog read path fetches many of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// BLAKE3 hash of the TDF blob (hex) — also the iroh fetch key.
    pub hash: String,
    /// Blob size in bytes.
    pub size: u64,
    /// Every attribute-value FQN referenced by the TDF's policy. These are
    /// the resource attributes for the future authorization-service
    /// decision call, and drive entitlement badges in catalog UIs.
    pub attribute_fqns: Vec<String>,
    /// Unix timestamp of ingest.
    pub ingested_at: i64,
}

/// Extract every attribute-value FQN referenced by a TDF policy
/// (`https://<namespace>/attr/<name>/value/<value>`; value-less conditions
/// such as `Present` yield `https://<namespace>/attr/<name>`). The result
/// is deduplicated and sorted for deterministic index entries.
pub fn extract_attribute_fqns(policy_json: &str) -> Result<Vec<String>> {
    let policy: Policy =
        serde_json::from_str(policy_json).context("Failed to parse TDF policy JSON")?;

    let mut fqns = Vec::new();
    for attr_policy in &policy.body.attributes {
        collect_fqns(attr_policy, &mut fqns);
    }
    fqns.sort();
    fqns.dedup();
    Ok(fqns)
}

fn collect_fqns(policy: &AttributePolicy, out: &mut Vec<String>) {
    match policy {
        AttributePolicy::Condition(cond) => {
            let base = format!(
                "https://{}/attr/{}",
                cond.attribute.namespace, cond.attribute.name
            );
            match &cond.value {
                Some(AttributeValue::String(s)) => out.push(format!("{base}/value/{s}")),
                Some(AttributeValue::StringArray(values)) => {
                    for s in values {
                        out.push(format!("{base}/value/{s}"));
                    }
                }
                Some(AttributeValue::Number(n)) => out.push(format!("{base}/value/{n}")),
                Some(AttributeValue::Boolean(b)) => out.push(format!("{base}/value/{b}")),
                Some(AttributeValue::DateTime(dt)) => {
                    out.push(format!("{base}/value/{}", dt.to_rfc3339()));
                }
                Some(AttributeValue::NumberArray(values)) => {
                    for n in values {
                        out.push(format!("{base}/value/{n}"));
                    }
                }
                None => out.push(base),
            }
        }
        AttributePolicy::Logical(op) => match op {
            LogicalOperator::AND { conditions } | LogicalOperator::OR { conditions } => {
                for c in conditions {
                    collect_fqns(c, out);
                }
            }
            LogicalOperator::NOT { condition } => collect_fqns(condition, out),
        },
    }
}

/// Everything ingest derives from a validated manifest: the extracted
/// manifest JSON plus one serialized index entry per catalog group. Pure —
/// no I/O — so the full pipeline is testable from TDF bytes alone.
pub struct DerivedArtifacts {
    pub manifest_json: String,
    /// (group, serialized CatalogEntry) pairs.
    pub entries: Vec<(String, Vec<u8>)>,
}

pub fn derive_artifacts(
    manifest: &opentdf::TdfManifest,
    hash_hex: &str,
    size: u64,
    ingested_at: i64,
    catalog_config: &crate::config::CatalogConfig,
) -> Result<DerivedArtifacts> {
    let manifest_json = manifest
        .to_json()
        .context("Failed to serialize manifest for extraction")?;

    let mut entries = Vec::new();
    if catalog_config.enabled {
        let policy_json = manifest
            .get_policy_raw()
            .context("Failed to decode policy from manifest")?;
        let fqns = extract_attribute_fqns(&policy_json)
            .context("Failed to extract attribute FQNs from policy")?;
        let groups = group_keys(&fqns, &catalog_config.group_attribute_prefix());
        if !groups.is_empty() {
            let entry = CatalogEntry {
                hash: hash_hex.to_string(),
                size,
                attribute_fqns: fqns,
                ingested_at,
            };
            let entry_json =
                serde_json::to_vec(&entry).context("Failed to serialize catalog entry")?;
            entries = groups
                .into_iter()
                .map(|group| (group, entry_json.clone()))
                .collect();
        }
    }
    Ok(DerivedArtifacts {
        manifest_json,
        entries,
    })
}

/// Derive the catalog group keys for a blob: the values of every FQN that
/// starts with the configured grouping-attribute prefix (e.g.
/// `https://patreon.arkavo.com/attr/campaign/value/` → campaign ids).
/// Values that would be unsafe as S3 key segments are skipped — loudly, so
/// a valid policy value silently producing no catalog entry is observable
/// (e.g. DateTime values render with '+'/':' beyond the safe alphabet).
pub fn group_keys(fqns: &[String], group_attribute_prefix: &str) -> Vec<String> {
    if group_attribute_prefix.is_empty() {
        return Vec::new();
    }
    let mut groups = Vec::new();
    for fqn in fqns {
        let Some(value) = fqn.strip_prefix(group_attribute_prefix) else {
            continue;
        };
        if is_safe_key_segment(value) {
            groups.push(value.to_string());
        } else {
            tracing::warn!(
                %fqn,
                "Grouping-attribute value is not a safe key segment; item will not be cataloged under it"
            );
        }
    }
    groups.sort();
    groups.dedup();
    groups
}

/// A group value becomes one S3 key path segment — no slashes, no
/// traversal, conservative alphabet.
fn is_safe_key_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '@'))
        && !s.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_json(fqns: &[&str]) -> String {
        use opentdf::prelude::*;
        let mut builder = PolicyBuilder::new().id_auto().dissemination(["t@test"]);
        for fqn in fqns {
            builder = builder.attribute_fqn(fqn).unwrap();
        }
        serde_json::to_string(&builder.build().unwrap()).unwrap()
    }

    #[test]
    fn extracts_fqns_from_policy() {
        let json = policy_json(&[
            "https://patreon.arkavo.com/attr/campaign/value/12345678",
            "https://patreon.arkavo.com/attr/tier/value/gold",
        ]);
        let fqns = extract_attribute_fqns(&json).unwrap();
        assert!(
            fqns.contains(&"https://patreon.arkavo.com/attr/campaign/value/12345678".to_string()),
            "campaign FQN missing: {fqns:?}"
        );
        assert!(
            fqns.contains(&"https://patreon.arkavo.com/attr/tier/value/gold".to_string()),
            "tier FQN missing: {fqns:?}"
        );
    }

    #[test]
    fn fqns_are_deduped_and_sorted() {
        let json = policy_json(&[
            "https://b.example/attr/x/value/1",
            "https://a.example/attr/x/value/1",
            "https://a.example/attr/x/value/1",
        ]);
        let fqns = extract_attribute_fqns(&json).unwrap();
        let mut sorted = fqns.clone();
        sorted.sort();
        assert_eq!(fqns, sorted);
        assert_eq!(
            fqns.iter()
                .filter(|f| f.as_str() == "https://a.example/attr/x/value/1")
                .count(),
            1
        );
    }

    #[test]
    fn group_keys_match_prefix_only() {
        let fqns = vec![
            "https://patreon.arkavo.com/attr/campaign/value/12345678".to_string(),
            "https://patreon.arkavo.com/attr/tier/value/gold".to_string(),
            "https://other.example/attr/campaign/value/99".to_string(),
        ];
        let groups = group_keys(&fqns, "https://patreon.arkavo.com/attr/campaign/value/");
        assert_eq!(groups, vec!["12345678".to_string()]);
    }

    #[test]
    fn group_keys_reject_unsafe_segments() {
        let fqns = vec![
            "https://p.example/attr/campaign/value/ok-1".to_string(),
            "https://p.example/attr/campaign/value/../escape".to_string(),
            "https://p.example/attr/campaign/value/has/slash".to_string(),
        ];
        let groups = group_keys(&fqns, "https://p.example/attr/campaign/value/");
        assert_eq!(groups, vec!["ok-1".to_string()]);
    }

    #[test]
    fn empty_prefix_disables_grouping() {
        let fqns = vec!["https://p.example/attr/campaign/value/1".to_string()];
        assert!(group_keys(&fqns, "").is_empty());
    }

    #[test]
    fn catalog_entry_roundtrips() {
        let entry = CatalogEntry {
            hash: "ab".repeat(32),
            size: 1024,
            attribute_fqns: vec!["https://p.example/attr/tier/value/gold".into()],
            ingested_at: 1_900_000_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: CatalogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hash, entry.hash);
        assert_eq!(back.attribute_fqns, entry.attribute_fqns);
    }
}
