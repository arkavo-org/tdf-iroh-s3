//! Ingest: validate a pushed blob as a TDF and store it in S3.
//!
//! The blob is never held in memory. It is exported from the iroh store to
//! a scratch file (a reflink where the filesystem supports one, a copy
//! otherwise), validated from that file by reading only the ZIP central
//! directory and the manifest, and uploaded to S3 streaming from it. The
//! blob's BAO outboard (the hash tree that lets a viewer verify each 16 KiB
//! chunk group of a ranged read) is computed from the same file, in one
//! streaming pass, and uploaded before the blob. The BLAKE3 hash is the
//! push's: the store verified every chunk against it on import, and the
//! outboard's root is checked against it. Blocking file work runs on
//! `spawn_blocking` threads, never on the async runtime's workers.

use anyhow::{Context, anyhow};
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::sync::CreateOutboard;
use bytes::Bytes;
use iroh_blobs::Hash;
use iroh_blobs::store::IROH_BLOCK_SIZE;
use iroh_blobs::store::fs::FsStore;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

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
    /// The blob's pre-order BAO outboard at [`IROH_BLOCK_SIZE`], root
    /// verified against `hash`. Empty for a blob of one chunk group (16 KiB)
    /// or less.
    outboard: Vec<u8>,
    file: ScratchFile,
}

/// The pre-order outboard of `size` bytes read from `data`, at
/// [`IROH_BLOCK_SIZE`] (what iroh-blobs' own store uses, so the bytes are
/// what a BAO encoder needs to serve ranges of the blob). Streams `data`;
/// memory is the outboard (about 64 bytes per 16 KiB), not the blob.
///
/// Fails when the outboard's root is not `expected`: the bytes do not hash
/// to the key, so nothing derived from them may be stored under it.
pub fn compute_outboard(data: impl Read, size: u64, expected: Hash) -> anyhow::Result<Vec<u8>> {
    let outboard = PreOrderOutboard::<Vec<u8>>::create_sized(data, size, IROH_BLOCK_SIZE)
        .context("Failed to compute the blob's outboard")?;
    let root = Hash::from(outboard.root);
    if root != expected {
        return Err(anyhow!(
            "the blob's bytes hash to {root}, not {expected}; refusing to store an outboard for it"
        ));
    }
    Ok(outboard.data)
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

    // The outboard comes from the same scratch file, after validation so a
    // refused blob costs no full read. A mismatch means the store handed us
    // bytes that do not hash to the key: not the pusher's fault, not
    // uploadable.
    let path = file.path().to_path_buf();
    let outboard = tokio::task::spawn_blocking(move || {
        let reader = std::io::BufReader::new(
            std::fs::File::open(&path)
                .with_context(|| format!("Failed to open {}", path.display()))?,
        );
        compute_outboard(reader, size, hash)
    })
    .await
    .map_err(|e| IngestError::Failed(anyhow!("outboard task failed: {e}")))?
    .map_err(IngestError::Failed)?;

    Ok(Some(Validated {
        hash,
        size,
        manifest,
        outboard,
        file,
    }))
}

/// Upload a validated blob to S3, streaming from its scratch file, and
/// write its extracted manifest. It can be retried; the scratch file goes
/// when `validated` is dropped.
pub async fn upload(
    validated: &Validated,
    s3_client: &S3Client,
) -> Result<IngestResult, IngestError> {
    let Validated {
        hash,
        size,
        manifest,
        outboard,
        file,
    } = validated;
    let size = *size;
    let hash_hex = hash.to_hex().to_string();

    // The outboard goes first, always (it is small, and a re-push repairs a
    // missing one), so a blob that exists in S3 always has its outboard.
    // An empty outboard (a blob of 16 KiB or less) is a zero-length object.
    s3_client
        .put_outboard(&hash_hex, Bytes::copy_from_slice(outboard))
        .await
        .context("Failed to upload outboard to S3")
        .map_err(IngestError::Failed)?;

    // Upload the blob unless already present. The manifest below is
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
    // The extracted manifest, which the catalog publish checks read
    // (`catalogs_api::check_payloads`). Best-effort: the content blob is
    // already durably stored, so a manifest write failure must not mask a
    // successful ingest. It is loudly logged, and re-pushing the same
    // content rewrites it (self-repair).
    match manifest.to_json() {
        Ok(json) => {
            if let Err(e) = s3_client.put_manifest(&hash_hex, Bytes::from(json)).await {
                warn!(hash = %hash_hex, error = %e,
                    "Failed to store extracted manifest — blob remains available; re-push to repair");
            }
        }
        Err(e) => warn!(hash = %hash_hex, error = %e, "Failed to serialize the manifest"),
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
    s3_client: &S3Client,
    scratch_dir: &Path,
) -> Result<Option<IngestResult>, IngestError> {
    match validate_from_store(hash, store, validation_config, scratch_dir).await? {
        Some(validated) => upload(&validated, s3_client).await.map(Some),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bao_tree::{BaoTree, ChunkRanges};

    /// Deterministic, non-repeating bytes (so chunks differ).
    fn data(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    fn outboard_of(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        compute_outboard(bytes, bytes.len() as u64, Hash::new(bytes))
    }

    #[test]
    fn outboard_root_and_length_match_the_tree() {
        let bytes = data(100 * 1024);
        let outboard = PreOrderOutboard::<Vec<u8>>::create_sized(
            &bytes[..],
            bytes.len() as u64,
            IROH_BLOCK_SIZE,
        )
        .unwrap();
        assert_eq!(Hash::from(outboard.root), Hash::new(&bytes));
        let expected = BaoTree::new(bytes.len() as u64, IROH_BLOCK_SIZE).outboard_size();
        assert!(expected > 0);
        assert_eq!(outboard.data.len() as u64, expected);
        // The checked entry point returns the same bytes.
        assert_eq!(outboard_of(&bytes).unwrap(), outboard.data);
    }

    #[test]
    fn a_blob_of_one_chunk_group_or_less_has_an_empty_outboard() {
        for len in [0, 1, 10 * 1024, 16 * 1024] {
            assert!(outboard_of(&data(len)).unwrap().is_empty(), "{len} bytes");
        }
        // One byte more needs a hash pair.
        assert_eq!(outboard_of(&data(16 * 1024 + 1)).unwrap().len(), 64);
    }

    #[test]
    fn an_outboard_whose_root_is_not_the_key_is_refused() {
        let bytes = data(100 * 1024);
        let err =
            compute_outboard(&bytes[..], bytes.len() as u64, Hash::new(b"other")).unwrap_err();
        assert!(format!("{err:#}").contains("not"), "{err:#}");
        // A short read (the file is smaller than the size it was told) fails.
        assert!(compute_outboard(&bytes[..1000], bytes.len() as u64, Hash::new(&bytes)).is_err());
    }

    /// Cross-check against iroh-blobs itself: the store's own BAO encoding
    /// of the whole blob (built from the outboard it keeps; the store has no
    /// public outboard read) is byte for byte what bao-tree encodes from our
    /// outboard and the data, and that stream decodes and verifies against
    /// our outboard's root.
    #[tokio::test]
    async fn outboard_matches_what_iroh_blobs_uses() {
        use iroh_blobs::store::mem::MemStore;

        for len in [100 * 1024, 16 * 1024 + 1, 1_000_000] {
            let bytes = data(len);
            let outboard = PreOrderOutboard {
                root: blake3::Hash::from(Hash::new(&bytes)),
                tree: BaoTree::new(len as u64, IROH_BLOCK_SIZE),
                data: outboard_of(&bytes).unwrap(),
            };

            let store = MemStore::new();
            let hash = store.add_slice(&bytes).await.unwrap().hash;
            assert_eq!(hash, Hash::new(&bytes));
            let from_store = store
                .export_bao(hash, ChunkRanges::all())
                .bao_to_vec()
                .await
                .unwrap();

            // The store's stream leads with the blob size (8 bytes LE), which
            // bao-tree's encoder leaves to the caller.
            let (prefix, from_store) = from_store.split_at(8);
            assert_eq!(prefix, (len as u64).to_le_bytes());

            let mut ours = Vec::new();
            bao_tree::io::sync::encode_ranges_validated(
                &bytes[..],
                &outboard,
                &ChunkRanges::all(),
                &mut ours,
            )
            .unwrap();
            assert!(
                from_store == &ours[..],
                "{len} bytes: iroh-blobs' BAO stream differs from ours"
            );

            // And the stream verifies and reproduces the data.
            let mut decoded = vec![0u8; len];
            let mut empty = bao_tree::io::outboard::EmptyOutboard {
                tree: outboard.tree,
                root: outboard.root,
            };
            bao_tree::io::sync::decode_ranges(
                &ours[..],
                &ChunkRanges::all(),
                &mut decoded[..],
                &mut empty,
            )
            .unwrap();
            assert!(decoded == bytes);
        }
    }
}
