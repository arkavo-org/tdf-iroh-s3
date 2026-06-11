pub mod assertion;
pub mod attributes;
pub mod structure;

use crate::config::ValidationConfig;
use anyhow::{Context, Result};

/// Validate a blob through the full TDF validation pipeline.
///
/// 1. Structure: verify it's a valid TDF (ZIP with manifest + payload)
/// 2. Attributes: check required attributes are present in the policy
/// 3. Assertion: optionally verify assertion signature against trusted keys
///
/// Returns the parsed manifest so ingest can derive artifacts (extracted
/// manifest, catalog index) without re-opening the archive.
pub fn validate_blob(data: &[u8], config: &ValidationConfig) -> Result<opentdf::TdfManifest> {
    // Step 1: Structure validation
    let manifest =
        structure::validate_tdf_structure(data).context("TDF structure validation failed")?;

    // Step 2: Attribute policy check
    attributes::validate_attributes(&manifest, &config.required_attributes)
        .context("TDF attribute validation failed")?;

    // Step 3: Assertion signature check (optional)
    assertion::validate_assertion(
        &manifest,
        config.assertion.enabled,
        &config.assertion.trusted_public_keys,
    )
    .context("TDF assertion validation failed")?;

    Ok(manifest)
}
