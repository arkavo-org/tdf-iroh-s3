use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_blobs::Hash;
use iroh_blobs::store::fs::FsStore;
use tracing::{info, warn};

use crate::catalog;
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

    // Steps 4–5: derived artifacts (extracted manifest + catalog index
    // entries). Best-effort: the content blob is already durably stored, so
    // a manifest/index write failure must not mask a successful ingest —
    // it is loudly logged, and re-pushing the same content rewrites the
    // artifacts (self-repair). Note: the index prefixes (`manifests/`,
    // `catalog-index/`) need the same S3 write permissions as `blobs/`.
    match catalog::derive_artifacts(&manifest, &hash_hex, size, unix_now(), catalog_config) {
        Ok(derived) => {
            if let Err(e) = s3_client
                .put_manifest(&hash_hex, Bytes::from(derived.manifest_json))
                .await
            {
                warn!(hash = %hash_hex, error = %e,
                    "Failed to store extracted manifest — blob remains available; re-push to repair");
            }
            if catalog_config.enabled && derived.entries.is_empty() {
                info!(hash = %hash_hex, "No grouping attribute in policy; not cataloged");
            }
            for (group, entry_json) in derived.entries {
                match s3_client
                    .put_catalog_entry(&group, &hash_hex, Bytes::from(entry_json))
                    .await
                {
                    Ok(()) => info!(hash = %hash_hex, %group, "Catalog index entry written"),
                    Err(e) => warn!(hash = %hash_hex, %group, error = %e,
                        "Failed to store catalog entry — blob remains available; re-push to repair"),
                }
            }
        }
        Err(e) => {
            warn!(hash = %hash_hex, error = %e, "Failed to derive catalog artifacts");
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
