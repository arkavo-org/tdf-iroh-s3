use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_blobs::Hash;
use iroh_blobs::store::fs::FsStore;
use tracing::info;

use crate::config::ValidationConfig;
use crate::store::s3::S3Client;
use crate::validation;

/// Result of a successful ingest operation.
pub struct IngestResult {
    /// BLAKE3 hash of the blob (hex-encoded).
    pub hash_hex: String,
    /// Size of the blob in bytes.
    pub size: u64,
}

/// Ingest a blob: validate it as a TDF, then store it in S3.
pub async fn ingest_blob(
    data: &[u8],
    validation_config: &ValidationConfig,
    s3_client: &S3Client,
) -> Result<IngestResult> {
    let size = data.len() as u64;

    // Step 1: Validate through TDF pipeline
    validation::validate_blob(data, validation_config)
        .context("Blob rejected by TDF validation")?;

    // Step 2: Compute BLAKE3 hash
    let hash = blake3::hash(data);
    let hash_hex = hash.to_hex().to_string();

    // Step 3: Check if already stored
    if s3_client.has_blob(&hash_hex).await? {
        info!(hash = %hash_hex, "Blob already exists in S3, skipping upload");
        return Ok(IngestResult { hash_hex, size });
    }

    // Step 4: Upload blob to S3
    s3_client
        .put_blob(&hash_hex, Bytes::copy_from_slice(data))
        .await
        .context("Failed to upload blob to S3")?;

    info!(hash = %hash_hex, size, "Blob ingested and stored to S3");
    Ok(IngestResult { hash_hex, size })
}

/// Read a blob from the FsStore by hash, validate it, and upload to S3.
/// Returns Ok(Some(result)) on success, Ok(None) if the blob is not yet available,
/// or Err if validation/upload fails.
pub async fn ingest_from_store(
    hash: Hash,
    store: &FsStore,
    validation_config: &crate::config::ValidationConfig,
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
    ingest_blob(&data, validation_config, s3_client).await.map(Some)
}
