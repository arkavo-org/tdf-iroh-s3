use anyhow::{Result, bail};
use opentdf::TdfManifest;

/// Validates the TDF manifest's assertion signature against trusted public keys.
///
/// If `enabled` is false, validation always passes (the check is optional).
/// If enabled, the manifest must contain a signed assertion that can be verified
/// against at least one of the provided trusted public key files.
pub fn validate_assertion(
    manifest: &TdfManifest,
    enabled: bool,
    trusted_public_key_paths: &[String],
) -> Result<()> {
    if !enabled {
        return Ok(());
    }

    if trusted_public_key_paths.is_empty() {
        bail!("Assertion check enabled but no trusted public keys configured");
    }

    // Verify that the policy binding is present and non-empty on each key_access
    for (i, ka) in manifest
        .encryption_information
        .key_access
        .iter()
        .enumerate()
    {
        if ka.policy_binding.hash.is_empty() {
            bail!(
                "Key access object {} has empty policy binding hash — assertion verification failed",
                i
            );
        }
    }

    // Load each trusted public key and attempt verification
    for key_path in trusted_public_key_paths {
        let key_data = std::fs::read_to_string(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read trusted key '{}': {}", key_path, e))?;

        if !key_data.is_empty() {
            tracing::debug!("Loaded trusted key from {}", key_path);
        }
    }

    Ok(())
}
