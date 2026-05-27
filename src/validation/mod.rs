pub mod assertion;
pub mod attributes;
pub mod structure;

use crate::config::ValidationConfig;
use anyhow::{Context, Result};
use opentdf::TdfManifest;

/// Validate a blob through the full TDF validation pipeline and return the
/// parsed manifest. Callers that want the manifest (e.g. ingest, to extract
/// attribute-value FQNs for the catalog event) should use this directly
/// instead of `validate_blob` to avoid re-parsing the ZIP.
///
/// 1. Structure: verify it's a valid TDF (ZIP with manifest + payload)
/// 2. Attributes: check required attributes are present in the policy
/// 3. Assertion: optionally verify assertion signature against trusted keys
pub fn validate_blob_and_parse(
    data: &[u8],
    config: &ValidationConfig,
) -> Result<TdfManifest> {
    let manifest = structure::validate_tdf_structure(data)
        .context("TDF structure validation failed")?;

    attributes::validate_attributes(&manifest, &config.required_attributes)
        .context("TDF attribute validation failed")?;

    assertion::validate_assertion(
        &manifest,
        config.assertion.enabled,
        &config.assertion.trusted_public_keys,
    )
    .context("TDF assertion validation failed")?;

    Ok(manifest)
}

/// Validate a blob through the full TDF validation pipeline (discarding the
/// parsed manifest). Thin wrapper over [`validate_blob_and_parse`] for
/// callers that only need pass/fail.
pub fn validate_blob(data: &[u8], config: &ValidationConfig) -> Result<()> {
    validate_blob_and_parse(data, config).map(|_| ())
}
