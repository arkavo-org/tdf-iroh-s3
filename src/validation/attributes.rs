use anyhow::{Context, Result, bail};
use opentdf::TdfManifest;
use opentdf::fqn::AttributeFqn;

/// Validates that the TDF manifest's policy contains all required attributes.
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

    // Check each required attribute is present in the policy JSON
    for required in required_attributes {
        if !attribute_in_policy(&policy_json, required)? {
            bail!("Required attribute '{}' not found in TDF policy", required);
        }
    }

    Ok(())
}

/// Returns true if the given FQN is represented in the policy JSON.
///
/// The policy JSON stores attributes as structured objects with separate
/// namespace, name, and value fields rather than the full FQN string.
/// For example, "https://example.com/attr/storage/value/permanent" is stored as:
///   {"attribute": {"namespace": "example.com", "name": "storage"}, "operator": "equals", "value": "permanent"}
fn attribute_in_policy(policy_json: &str, fqn: &str) -> Result<bool> {
    let parsed =
        AttributeFqn::parse(fqn).with_context(|| format!("Invalid attribute FQN: '{fqn}'"))?;

    let namespace = parsed.get_namespace();
    let name = parsed.get_name();

    // Both namespace and name must appear in the policy JSON
    if !policy_json.contains(namespace) || !policy_json.contains(name) {
        return Ok(false);
    }

    // If the FQN includes a value, also verify the value appears
    if let Some(value) = parsed.get_value()
        && !policy_json.contains(value)
    {
        return Ok(false);
    }

    Ok(true)
}
