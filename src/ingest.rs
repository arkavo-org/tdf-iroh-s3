use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_blobs::Hash;
use iroh_blobs::store::fs::FsStore;
use tracing::info;

use crate::catalog::{self, CatalogEntry};
use crate::config::{CatalogConfig, ValidationConfig};
use crate::store::s3::S3Client;
use crate::validation;

/// Result of a successful ingest operation.
pub struct IngestResult {
    /// BLAKE3 hash of the blob (hex-encoded).
    pub hash_hex: String,
    /// Size of the blob in bytes.
    pub size: u64,
}

/// Ingest a blob: validate it as a TDF, store it in S3, and write the
/// derived artifacts (extracted manifest + catalog index entries).
pub async fn ingest_blob(
    data: &[u8],
    validation_config: &ValidationConfig,
    catalog_config: &CatalogConfig,
    s3_client: &S3Client,
) -> Result<IngestResult> {
    let size = data.len() as u64;

    // Step 1: Validate through TDF pipeline (returns the parsed manifest —
    // everything the derived artifacts need is already in memory here).
    let manifest = validation::validate_blob(data, validation_config)
        .context("Blob rejected by TDF validation")?;

    // Step 2: Compute BLAKE3 hash
    let hash = blake3::hash(data);
    let hash_hex = hash.to_hex().to_string();

    // Step 3: Upload blob to S3 unless already present. Derived artifacts
    // below are written even for duplicate blobs, so a push retried after a
    // partial failure (or content predating the index) self-repairs.
    if s3_client.has_blob(&hash_hex).await? {
        info!(hash = %hash_hex, "Blob already exists in S3, skipping upload");
    } else {
        s3_client
            .put_blob(&hash_hex, Bytes::copy_from_slice(data))
            .await
            .context("Failed to upload blob to S3")?;
    }

    // Step 4: Extract the manifest next to the blob. Policy/metadata readers
    // (catalog indexing, UIs, repair) hit this small object instead of
    // downloading and unzipping the full TDF.
    let manifest_json = manifest
        .to_json()
        .context("Failed to serialize manifest for extraction")?;
    s3_client
        .put_manifest(&hash_hex, Bytes::from(manifest_json))
        .await
        .context("Failed to store extracted manifest")?;

    // Step 5: Catalog index entries, one per grouping-attribute value in the
    // policy. A blob whose policy carries no grouping attribute is in no
    // catalog — curation is the creator's labeling (ArkavoKit#1).
    if catalog_config.enabled {
        let policy_json = manifest
            .get_policy_raw()
            .context("Failed to decode policy from manifest")?;
        let fqns = catalog::extract_attribute_fqns(&policy_json)
            .context("Failed to extract attribute FQNs from policy")?;
        let groups = catalog::group_keys(&fqns, &catalog_config.group_attribute_prefix);
        if groups.is_empty() {
            info!(hash = %hash_hex, "No grouping attribute in policy; not cataloged");
        } else {
            let entry = CatalogEntry {
                hash: hash_hex.clone(),
                size,
                attribute_fqns: fqns,
                ingested_at: unix_now(),
            };
            let entry_json =
                serde_json::to_vec(&entry).context("Failed to serialize catalog entry")?;
            for group in &groups {
                s3_client
                    .put_catalog_entry(group, &hash_hex, Bytes::from(entry_json.clone()))
                    .await
                    .with_context(|| format!("Failed to store catalog entry for group {group}"))?;
            }
            info!(hash = %hash_hex, groups = ?groups, "Catalog index entries written");
        }
    }

    info!(hash = %hash_hex, size, "Blob ingested and stored to S3");
    Ok(IngestResult { hash_hex, size })
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read a blob from the FsStore by hash, validate it, and upload to S3.
/// Returns Ok(Some(result)) on success, Ok(None) if the blob is not yet available,
/// or Err if validation/upload fails.
pub async fn ingest_from_store(
    hash: Hash,
    store: &FsStore,
    validation_config: &crate::config::ValidationConfig,
    catalog_config: &CatalogConfig,
    s3_client: &S3Client,
) -> Result<Option<IngestResult>> {
    // Try to read blob bytes directly. For pushed blobs, get_bytes() works
    // even when status() returns NotFound (it reads from file storage,
    // bypassing the database metadata which updates asynchronously).
    let data = match store.get_bytes(hash).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::trace!(hash = %hash, error = %e, "Blob not yet available in store");
            return Ok(None);
        }
    };

    // Delegate to the existing ingest pipeline
    ingest_blob(&data, validation_config, catalog_config, s3_client)
        .await
        .map(Some)
}
