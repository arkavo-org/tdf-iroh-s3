//! Ingest: validate a pushed blob as a TDF and store it in S3.
//!
//! The blob is never held in memory. It is exported from the iroh store to
//! a scratch file (a reflink where the filesystem supports one, a copy
//! otherwise), validated from that file by reading only the ZIP central
//! directory and the manifest, and uploaded to S3 streaming from it. The
//! BLAKE3 hash is the push's: the store verified every chunk against it on
//! import, so it is not computed again. Blocking file work runs on
//! `spawn_blocking` threads, never on the async runtime's workers.

use anyhow::{Context, anyhow};
use bytes::Bytes;
use iroh_blobs::Hash;
use iroh_blobs::store::fs::FsStore;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Why ingest did not finish.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// The blob is not acceptable: larger than `max_blob_bytes`, or not a
    /// valid TDF. It must not be served, and can be deleted.
    #[error("refused: {0:#}")]
    Refused(anyhow::Error),
    /// Ingest could not finish (reading the store, storage). The blob may be
    /// valid; it is kept.
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

/// A pushed blob that validated, waiting in its scratch file for upload.
pub struct Validated {
    hash: Hash,
    size: u64,
    manifest: opentdf::TdfManifest,
    file: ScratchFile,
}

/// Export a complete pushed blob to a scratch file under `scratch_dir` and
/// validate it. `Ok(None)` when the blob is not complete in the store yet.
pub async fn validate_from_store(
    hash: Hash,
    store: &FsStore,
    validation_config: &ValidationConfig,
    scratch_dir: &Path,
) -> Result<Option<Validated>, IngestError> {
    // The bitfield carries the size the pusher declared; refuse an oversize
    // blob before copying a byte of it.
    let bitfield = match store.observe(hash).await {
        Ok(bitfield) => bitfield,
        Err(e) => {
            tracing::trace!(%hash, error = %e, "Blob not yet observable in store");
            return Ok(None);
        }
    };
    validation::check_blob_size(bitfield.size(), validation_config)
        .context("Blob refused before reading")
        .map_err(IngestError::Refused)?;
    if !bitfield.is_complete() {
        return Ok(None);
    }

    let file = ScratchFile::new(scratch_dir, hash);
    let size = store
        .blobs()
        .export(hash, file.path())
        .await
        .with_context(|| format!("Failed to export blob to {}", file.path().display()))
        .map_err(IngestError::Failed)?;

    let path = file.path().to_path_buf();
    let config = validation_config.clone();
    let manifest = tokio::task::spawn_blocking(move || {
        let reader = std::io::BufReader::new(
            std::fs::File::open(&path)
                .with_context(|| format!("Failed to open {}", path.display()))?,
        );
        validation::validate_archive(reader, size, &config)
    })
    .await
    .map_err(|e| IngestError::Failed(anyhow!("validation task failed: {e}")))?
    .context("Blob rejected by TDF validation")
    .map_err(IngestError::Refused)?;

    Ok(Some(Validated {
        hash,
        size,
        manifest,
        file,
    }))
}

/// Upload a validated blob to S3, streaming from its scratch file, and
/// write the derived artifacts (extracted manifest + catalog index
/// entries). The scratch file is removed either way.
pub async fn upload(
    validated: Validated,
    catalog_config: &CatalogConfig,
    s3_client: &S3Client,
) -> Result<IngestResult, IngestError> {
    let Validated {
        hash,
        size,
        manifest,
        file,
    } = validated;
    let hash_hex = hash.to_hex().to_string();

    // Upload the blob unless already present. Derived artifacts below are
    // written even for duplicate blobs, so a push retried after a partial
    // failure (or content predating the index) self-repairs.
    let present = s3_client
        .blob_size(&hash_hex)
        .await
        .map_err(IngestError::Failed)?
        .is_some();
    if present {
        info!(hash = %hash_hex, "Blob already exists in S3, skipping upload");
    } else {
        s3_client
            .put_blob_file(&hash_hex, file.path(), size)
            .await
            .context("Failed to upload blob to S3")
            .map_err(IngestError::Failed)?;
    }
    file.remove().await;

    // Derived artifacts (extracted manifest + catalog index entries).
    // Best-effort: the content blob is already durably stored, so a
    // manifest/index write failure must not mask a successful ingest — it
    // is loudly logged, and re-pushing the same content rewrites the
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

/// [`validate_from_store`] then [`upload`]. `Ok(None)` when the blob is not
/// complete in the store yet.
pub async fn ingest_from_store(
    hash: Hash,
    store: &FsStore,
    validation_config: &ValidationConfig,
    catalog_config: &CatalogConfig,
    s3_client: &S3Client,
    scratch_dir: &Path,
) -> Result<Option<IngestResult>, IngestError> {
    match validate_from_store(hash, store, validation_config, scratch_dir).await? {
        Some(validated) => upload(validated, catalog_config, s3_client).await.map(Some),
        None => Ok(None),
    }
}

/// The scratch directory ingest exports blobs into: `<data_dir>/ingest`,
/// absolute (the store's export needs an absolute target). Emptied, since
/// files left there belong to ingests a restart interrupted.
pub async fn prepare_scratch_dir(data_dir: &str) -> anyhow::Result<PathBuf> {
    let dir = std::path::absolute(Path::new(data_dir).join("ingest"))
        .context("Failed to resolve the ingest scratch directory")?;
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("Failed to empty {}", dir.display())),
    }
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("Failed to create {}", dir.display()))?;
    Ok(dir)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A blob's scratch copy. Removed when dropped, off the runtime's worker
/// threads, since unlinking a multi-GiB file can take a while.
struct ScratchFile {
    path: PathBuf,
}

impl ScratchFile {
    fn new(dir: &Path, hash: Hash) -> Self {
        // Unique per ingest: two pushes of one hash may ingest at once.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self {
            path: dir.join(format!("{}.{n}.tdf", hash.to_hex())),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Remove now, waiting for it.
    async fn remove(mut self) {
        let path = std::mem::take(&mut self.path);
        remove_quietly(path).await;
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let path = std::mem::take(&mut self.path);
        if path.as_os_str().is_empty() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(remove_quietly(path));
            }
            Err(_) => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

async fn remove_quietly(path: PathBuf) {
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(path = %path.display(), error = %e, "Failed to remove ingest scratch file"),
    }
}
