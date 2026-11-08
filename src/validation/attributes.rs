use anyhow::{Context, Result, bail};
use opentdf::TdfManifest;
use opentdf::fqn::AttributeFqn;

use crate::catalog_metadata::extract_attribute_fqns;

/// Validates that the TDF manifest's policy names all required attributes.
/// The required_attributes are FQN strings like "https://example.com/attr/name/value/val".
///
/// If required_attributes is empty, validation always passes.
pub fn validate_attributes(manifest: &TdfManifest, required_attributes: &[String]) -> Result<()> {
    if required_attributes.is_empty() {
        return Ok(());
    }

    // Decode the policy from the manifest (base64-encoded JSON)
    let policy_json = manifest
        .get_policy_raw()
        .context("Failed to read policy from manifest")?;

    for required in required_attributes {
        if !policy_names(&policy_json, required)? {
            bail!("Required attribute '{}' not found in TDF policy", required);
        }
    }

    Ok(())
}

/// Whether the policy's `body.dataAttributes` name `required`, an attribute
/// FQN, as read by [`extract_attribute_fqns`] (the spec form
/// `{"attribute": "<FQN>"}` and opentdf-rs's structured form).
///
/// - A required FQN with a value matches an FQN in the policy byte for
///   byte: `…/campaign/value/123` is not named by `…/campaign/value/1234`.
/// - A required FQN without a value (`https://<namespace>/attr/<name>`)
///   matches that attribute with any value, or with none.
///
/// Comparison is case-sensitive, as for the catalog checks
/// ([`crate::catalog_metadata::ManifestPolicy::has_attribute`]).
pub(crate) fn policy_names(policy_json: &str, required: &str) -> Result<bool> {
    let parsed = AttributeFqn::parse(required)
        .with_context(|| format!("Invalid attribute FQN: '{required}'"))?;
    let named = extract_attribute_fqns(policy_json)?;
    if parsed.get_value().is_some() {
        return Ok(named.iter().any(|fqn| fqn == required));
    }
    let any_value = format!("{required}/value/");
    Ok(named
        .iter()
        .any(|fqn| fqn == required || fqn.starts_with(&any_value)))
}

#[cfg(test)]
mod tests {
    use super::policy_names;

    const CAMPAIGN_123: &str = "https://patreon.arkavo.com/attr/campaign/value/123";

    /// A policy in the spec form Creator writes.
    fn spec_policy(fqns: &[&str]) -> String {
        let attributes: Vec<_> = fqns
            .iter()
            .map(|fqn| serde_json::json!({ "attribute": fqn }))
            .collect();
        serde_json::json!({
            "uuid": "u",
            "body": { "dataAttributes": attributes, "dissem": [] },
            "arkavo:classification": "general",
        })
        .to_string()
    }

    /// A policy in opentdf-rs's structured form: one `equals` condition.
    fn structured_policy(namespace: &str, name: &str, value: &str) -> String {
        serde_json::json!({
            "uuid": "u",
            "body": {
                "dataAttributes": [{
                    "attribute": { "namespace": namespace, "name": name },
                    "operator": "equals",
                    "value": value,
                }],
                "dissem": [],
            },
        })
        .to_string()
    }

    #[test]
    fn a_value_matches_byte_for_byte() {
        assert!(policy_names(&spec_policy(&[CAMPAIGN_123]), CAMPAIGN_123).unwrap());
        assert!(
            policy_names(
                &structured_policy("patreon.arkavo.com", "campaign", "123"),
                CAMPAIGN_123
            )
            .unwrap()
        );
    }

    #[test]
    fn a_longer_value_is_another_value() {
        let other = "https://patreon.arkavo.com/attr/campaign/value/1234";
        assert!(!policy_names(&spec_policy(&[other]), CAMPAIGN_123).unwrap());
        assert!(
            !policy_names(
                &structured_policy("patreon.arkavo.com", "campaign", "1234"),
                CAMPAIGN_123
            )
            .unwrap()
        );
    }

    #[test]
    fn parts_spread_over_other_attributes_do_not_match() {
        // Namespace, name and value each appear, but not as one attribute.
        let policy = spec_policy(&[
            "https://example.com/attr/storage/value/temporary",
            "https://example.com/attr/level/value/permanent",
        ]);
        assert!(
            !policy_names(&policy, "https://example.com/attr/storage/value/permanent").unwrap()
        );
    }

    #[test]
    fn parts_elsewhere_in_the_policy_do_not_match() {
        let mut policy: serde_json::Value = serde_json::from_str(&spec_policy(&[
            "https://example.com/attr/level/value/public",
        ]))
        .unwrap();
        policy["body"]["dissem"] =
            serde_json::json!(["https://patreon.arkavo.com/attr/campaign/value/123"]);
        assert!(!policy_names(&policy.to_string(), CAMPAIGN_123).unwrap());
    }

    #[test]
    fn without_a_value_any_value_matches() {
        let attribute = "https://patreon.arkavo.com/attr/campaign";
        assert!(policy_names(&spec_policy(&[CAMPAIGN_123]), attribute).unwrap());
        assert!(policy_names(&spec_policy(&[attribute]), attribute).unwrap());
        // Another attribute whose name starts with this one's is not it.
        let longer_name = "https://patreon.arkavo.com/attr/campaigns/value/123";
        assert!(!policy_names(&spec_policy(&[longer_name]), attribute).unwrap());
    }

    #[test]
    fn a_value_is_not_matched_by_a_bare_attribute() {
        let bare = "https://patreon.arkavo.com/attr/campaign";
        assert!(!policy_names(&spec_policy(&[bare]), CAMPAIGN_123).unwrap());
    }

    #[test]
    fn an_invalid_required_fqn_is_an_error() {
        let err = policy_names(&spec_policy(&[CAMPAIGN_123]), "not an fqn").unwrap_err();
        assert!(err.to_string().contains("Invalid attribute FQN"), "{err}");
    }
}
