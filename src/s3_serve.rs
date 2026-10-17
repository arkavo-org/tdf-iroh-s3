//! Serving fetches straight from S3.
//!
//! The node holds no copy of what it serves. A get is answered from
//! `blobs/<hash>` and `outboards/<hash>` (the blob's BAO hash tree, written
//! by ingest before the blob): the response is the blob's size, then the
//! BAO encoding of the requested ranges, exactly as iroh-blobs' own
//! provider sends it, so any iroh-blobs client verifies every chunk group
//! against the hash. Both objects are read sequentially through one open
//! range GET each, reopened only when a read jumps backwards or far ahead,
//! so a whole-blob get costs two S3 GETs and constant memory.
//!
//! A blob ingested before outboards were stored has none: the first fetch
//! of it computes the outboard by streaming the blob from S3 once, checks
//! its root against the hash, and stores it; that fetch is told to try
//! again.

use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bao_tree::io::fsm::{AsyncSliceReader, CreateOutboard, encode_ranges_validated};
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::{BaoTree, ChunkRanges};
use bytes::{Bytes, BytesMut};
use iroh_blobs::Hash;
use iroh_blobs::store::IROH_BLOCK_SIZE;
use tokio::io::{AsyncBufRead, AsyncReadExt};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::store::s3::S3Client;

/// An S3 GET that sends nothing for this long fails (the fetch is told to
/// try again).
pub const S3_STALL: Duration = Duration::from_secs(30);

/// The longest an S3 HEAD may take.
const S3_HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// A forward jump this small is read through rather than reopening the GET.
const SKIP_LIMIT: u64 = 256 * 1024;

/// Outboards computed for blobs that lack one, at once.
const BACKFILLS: usize = 2;

/// Most blob sizes remembered.
const SIZES_CAPACITY: usize = 100_000;

/// Why a hash is not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Final: S3 holds no such blob.
    Gone,
    /// Try again: S3 did not answer, or the outboard is being computed.
    Busy,
}

/// Serves blobs from S3.
pub struct S3Server {
    s3: Arc<S3Client>,
    /// Sizes of blobs known to be servable (blob and outboard in S3).
    servable: Mutex<HashMap<Hash, u64>>,
    /// Hashes whose outboard is being computed.
    backfilling: Mutex<HashSet<Hash>>,
    backfills: Arc<Semaphore>,
}

impl S3Server {
    pub fn new(s3: Arc<S3Client>) -> Arc<Self> {
        Arc::new(Self {
            s3,
            servable: Mutex::default(),
            backfilling: Mutex::default(),
            backfills: Arc::new(Semaphore::new(BACKFILLS)),
        })
    }

    /// The blob's size when S3 can serve it: the blob and its outboard are
    /// both there. A blob without an outboard gets one computed in the
    /// background, and is refused as busy meanwhile.
    pub async fn check(self: &Arc<Self>, hash: Hash) -> Result<u64, Refusal> {
        if let Some(size) = lock(&self.servable).get(&hash) {
            return Ok(*size);
        }
        let hex = hash.to_hex();
        let size = match head(self.s3.blob_size(&hex)).await {
            Ok(Some(size)) => size,
            Ok(None) => return Err(Refusal::Gone),
            Err(e) => {
                warn!(%hash, error = %e, "Blob lookup failed");
                return Err(Refusal::Busy);
            }
        };
        let expected = BaoTree::new(size, IROH_BLOCK_SIZE).outboard_size();
        if expected > 0 {
            match head(self.s3.outboard_size(&hex)).await {
                Ok(Some(n)) if n == expected => {}
                Ok(found) => {
                    if found.is_some() {
                        warn!(%hash, ?found, expected, "Outboard in S3 has the wrong size; computing it again");
                    }
                    self.backfill(hash, size);
                    return Err(Refusal::Busy);
                }
                Err(e) => {
                    warn!(%hash, error = %e, "Outboard lookup failed");
                    return Err(Refusal::Busy);
                }
            }
        }
        let mut servable = lock(&self.servable);
        if servable.len() >= SIZES_CAPACITY {
            servable.clear();
        }
        servable.insert(hash, size);
        Ok(size)
    }

    /// Write `hash`'s size, then the BAO encoding of `ranges`, to `writer`.
    /// The hash must have passed [`Self::check`].
    pub async fn send(
        &self,
        hash: Hash,
        size: u64,
        ranges: &ChunkRanges,
        writer: &mut iroh::endpoint::SendStream,
    ) -> io::Result<()> {
        let hex = hash.to_hex();
        let tree = BaoTree::new(size, IROH_BLOCK_SIZE);
        let data = S3Reader::new(Arc::clone(&self.s3), self.s3.blob_key(&hex), size);
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from(hash),
            tree,
            data: S3Reader::new(
                Arc::clone(&self.s3),
                self.s3.outboard_key(&hex),
                tree.outboard_size(),
            ),
        };
        writer
            .write_all(&size.to_le_bytes())
            .await
            .map_err(io::Error::other)?;
        encode_ranges_validated(data, outboard, ranges, QuicWriter(writer))
            .await
            .map_err(io::Error::other)
    }

    /// Compute and store the outboard of a blob that lacks one, unless that
    /// runs already or [`BACKFILLS`] run.
    fn backfill(self: &Arc<Self>, hash: Hash, size: u64) {
        let Ok(permit) = Arc::clone(&self.backfills).try_acquire_owned() else {
            return;
        };
        if !lock(&self.backfilling).insert(hash) {
            return;
        }
        let server = Arc::clone(self);
        tokio::spawn(async move {
            match server.compute_outboard(hash, size).await {
                Ok(()) => info!(%hash, size, "Outboard computed from S3 and stored"),
                Err(e) => {
                    warn!(%hash, error = format!("{e:#}"), "Computing the outboard failed; a later fetch tries again")
                }
            }
            lock(&server.backfilling).remove(&hash);
            drop(permit);
        });
    }

    async fn compute_outboard(&self, hash: Hash, size: u64) -> anyhow::Result<()> {
        let hex = hash.to_hex();
        let data = S3Reader::new(Arc::clone(&self.s3), self.s3.blob_key(&hex), size);
        let outboard = PreOrderOutboard::<Vec<u8>>::create(data, IROH_BLOCK_SIZE).await?;
        anyhow::ensure!(
            Hash::from(outboard.root) == hash,
            "blob in S3 hashes to {}, not its key",
            Hash::from(outboard.root)
        );
        self.s3.put_outboard(&hex, Bytes::from(outboard.data)).await
    }
}

/// An S3 HEAD, bounded by [`S3_HEAD_TIMEOUT`].
async fn head<F: Future<Output = anyhow::Result<Option<u64>>>>(
    request: F,
) -> anyhow::Result<Option<u64>> {
    tokio::time::timeout(S3_HEAD_TIMEOUT, request)
        .await
        .map_err(|_| anyhow::anyhow!("S3 HEAD timed out"))?
}

/// Reads one S3 object at increasing offsets through one open GET.
struct S3Reader {
    s3: Arc<S3Client>,
    key: String,
    size: u64,
    open: Option<OpenGet>,
}

struct OpenGet {
    pos: u64,
    body: Pin<Box<dyn AsyncBufRead + Send>>,
}

impl S3Reader {
    fn new(s3: Arc<S3Client>, key: String, size: u64) -> Self {
        Self {
            s3,
            key,
            size,
            open: None,
        }
    }

    async fn open_at(&mut self, offset: u64) -> io::Result<&mut OpenGet> {
        let reusable = self
            .open
            .as_ref()
            .is_some_and(|o| o.pos <= offset && offset - o.pos <= SKIP_LIMIT);
        if !reusable {
            self.open = None;
            let body = tokio::time::timeout(S3_STALL, self.s3.get_object_from(&self.key, offset))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "S3 GET got no response"))?
                .map_err(io::Error::other)?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{} is not in S3", self.key),
                    )
                })?;
            self.open = Some(OpenGet { pos: offset, body });
        }
        let open = self.open.as_mut().expect("opened above");
        while open.pos < offset {
            let skip = (offset - open.pos).min(64 * 1024) as usize;
            let mut sink = vec![0u8; skip];
            read_exact(&mut open.body, &mut sink).await?;
            open.pos += skip as u64;
        }
        Ok(open)
    }
}

impl AsyncSliceReader for S3Reader {
    async fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Bytes> {
        if offset >= self.size || len == 0 {
            return Ok(Bytes::new());
        }
        let len = len.min(usize::try_from(self.size - offset).unwrap_or(usize::MAX));
        let result = async {
            let open = self.open_at(offset).await?;
            let mut buf = BytesMut::zeroed(len);
            read_exact(&mut open.body, &mut buf).await?;
            open.pos += len as u64;
            Ok(buf.freeze())
        }
        .await;
        if result.is_err() {
            // A failed read leaves the body somewhere unknown.
            self.open = None;
        }
        result
    }

    async fn size(&mut self) -> io::Result<u64> {
        Ok(self.size)
    }
}

/// Fill `buf` from `body`, failing if no bytes arrive for [`S3_STALL`].
async fn read_exact(
    body: &mut Pin<Box<dyn AsyncBufRead + Send>>,
    buf: &mut [u8],
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = tokio::time::timeout(S3_STALL, body.read(&mut buf[filled..]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "S3 GET stalled"))??;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += n;
    }
    Ok(())
}

/// The BAO encoder's writer over an iroh QUIC stream.
struct QuicWriter<'a>(&'a mut iroh::endpoint::SendStream);

impl iroh_io::AsyncStreamWriter for QuicWriter<'_> {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.0.write_all(data).await.map_err(io::Error::other)
    }

    async fn write_bytes(&mut self, data: Bytes) -> io::Result<()> {
        self.0.write_chunk(data).await.map_err(io::Error::other)
    }

    async fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
