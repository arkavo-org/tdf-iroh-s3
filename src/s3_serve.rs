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
//!
//! A hash that is not a blob may be a creator's catalog document (catalog
//! v2), served the same way from `catalog-documents/<hash>` and
//! `catalog-outboards/<hash>`. Those prefixes stay apart from `blobs/` so
//! a catalog document never passes as an ingested recording.

use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bao_tree::io::EncodeError;
use bao_tree::io::fsm::{AsyncSliceReader, CreateOutboard, encode_ranges_validated};
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::{BaoTree, ChunkRanges};
use bytes::{Bytes, BytesMut};
use iroh_blobs::Hash;
use iroh_blobs::store::IROH_BLOCK_SIZE;
use iroh_io::AsyncStreamWriter;
use tokio::io::{AsyncBufRead, AsyncReadExt};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::store::s3::S3Client;

/// An S3 GET that sends nothing for this long fails (the fetch is told to
/// try again).
pub const S3_STALL: Duration = Duration::from_secs(30);

/// A write to the fetcher that makes no progress for this long fails: a
/// peer that keeps its connection open but stops reading would otherwise
/// hold a serve slot, and two open S3 GETs, for as long as it likes.
pub const PEER_STALL: Duration = Duration::from_secs(60);

/// After a failed outboard computation, how long fetches of the blob are
/// told to try again without starting another (each streams the whole blob
/// from S3).
const BACKFILL_COOLDOWN: Duration = Duration::from_secs(600);

/// Most hashes remembered as corrupt, or as failed backfills.
const BAD_CAPACITY: usize = 10_000;

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
    /// Final: S3 holds no such blob, or its object does not match the hash.
    Gone,
    /// Try again: S3 did not answer, or the outboard is being computed.
    Busy,
}

/// What a servable hash is in S3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    /// A pushed TDF: `blobs/<hash>`, `outboards/<hash>`.
    Blob,
    /// A creator's catalog document: `catalog-documents/<hash>`,
    /// `catalog-outboards/<hash>`. `owner` is the document's recorded owner,
    /// so a fetch can apply that creator's `hideCatalog` suspension.
    CatalogDocument { owner: Option<String> },
}

impl Object {
    fn data_key(&self, s3: &S3Client, hex: &str) -> String {
        match self {
            Object::Blob => s3.blob_key(hex),
            Object::CatalogDocument { .. } => s3.catalog_document_key(hex),
        }
    }

    fn outboard_key(&self, s3: &S3Client, hex: &str) -> String {
        match self {
            Object::Blob => s3.outboard_key(hex),
            Object::CatalogDocument { .. } => s3.catalog_outboard_key(hex),
        }
    }
}

/// A hash S3 can serve: its size and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servable {
    pub size: u64,
    pub object: Object,
}

/// Serves blobs from S3.
pub struct S3Server {
    s3: Arc<S3Client>,
    /// Hashes known to be servable (object and outboard in S3).
    servable: Mutex<HashMap<Hash, Servable>>,
    /// Hashes whose outboard is being computed.
    backfilling: Mutex<HashSet<Hash>>,
    backfills: Arc<Semaphore>,
    /// Hashes whose S3 object does not match them, found while serving or
    /// computing an outboard. Refused for good until the node restarts; a
    /// push of the blob does not repair it (ingest keeps an existing
    /// object), so an operator deletes the object and the publisher pushes
    /// again.
    corrupt: Mutex<HashSet<Hash>>,
    /// When each recent outboard computation failed ([`BACKFILL_COOLDOWN`]).
    backfill_failed: Mutex<HashMap<Hash, Instant>>,
}

impl S3Server {
    pub fn new(s3: Arc<S3Client>) -> Arc<Self> {
        Arc::new(Self {
            s3,
            servable: Mutex::default(),
            backfilling: Mutex::default(),
            backfills: Arc::new(Semaphore::new(BACKFILLS)),
            corrupt: Mutex::default(),
            backfill_failed: Mutex::default(),
        })
    }

    /// What S3 can serve for `hash`: a blob, or else a catalog document,
    /// with its outboard there too. One without an outboard gets one
    /// computed in the background, and is refused as busy meanwhile.
    pub async fn check(self: &Arc<Self>, hash: Hash) -> Result<Servable, Refusal> {
        if lock(&self.corrupt).contains(&hash) {
            return Err(Refusal::Gone);
        }
        if let Some(servable) = lock(&self.servable).get(&hash) {
            return Ok(servable.clone());
        }
        let hex = hash.to_hex();
        let (size, object) = match head(self.s3.blob_size(&hex)).await {
            Ok(Some(size)) => (size, Object::Blob),
            Ok(None) => match head(self.s3.catalog_document_size(&hex)).await {
                Ok(Some((size, owner))) => (size, Object::CatalogDocument { owner }),
                Ok(None) => return Err(Refusal::Gone),
                Err(e) => {
                    warn!(%hash, error = %e, "Catalog document lookup failed");
                    return Err(Refusal::Busy);
                }
            },
            Err(e) => {
                warn!(%hash, error = %e, "Blob lookup failed");
                return Err(Refusal::Busy);
            }
        };
        let expected = BaoTree::new(size, IROH_BLOCK_SIZE).outboard_size();
        if expected > 0 {
            let found = match &object {
                Object::Blob => head(self.s3.outboard_size(&hex)).await,
                Object::CatalogDocument { .. } => head(self.s3.catalog_outboard_size(&hex)).await,
            };
            match found {
                Ok(Some(n)) if n == expected => {}
                Ok(found) => {
                    if found.is_some() {
                        warn!(%hash, ?found, expected, "Outboard in S3 has the wrong size; computing it again");
                    }
                    self.backfill(hash, size, object);
                    return Err(Refusal::Busy);
                }
                Err(e) => {
                    warn!(%hash, error = %e, "Outboard lookup failed");
                    return Err(Refusal::Busy);
                }
            }
        }
        let servable = Servable { size, object };
        let mut known = lock(&self.servable);
        if known.len() >= SIZES_CAPACITY {
            known.clear();
        }
        known.insert(hash, servable.clone());
        Ok(servable)
    }

    /// Write `hash`'s size, then the BAO encoding of `ranges`, to `writer`.
    /// `servable` is what [`Self::check`] returned for the hash.
    pub async fn send(
        &self,
        hash: Hash,
        servable: &Servable,
        ranges: &ChunkRanges,
        writer: &mut iroh::endpoint::SendStream,
    ) -> io::Result<()> {
        let hex = hash.to_hex();
        let size = servable.size;
        let tree = BaoTree::new(size, IROH_BLOCK_SIZE);
        let object = &servable.object;
        let data = S3Reader::new(Arc::clone(&self.s3), object.data_key(&self.s3, &hex), size);
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from(hash),
            tree,
            data: S3Reader::new(
                Arc::clone(&self.s3),
                object.outboard_key(&self.s3, &hex),
                tree.outboard_size(),
            ),
        };
        let mut writer = QuicWriter(writer);
        writer.write(&size.to_le_bytes()).await?;
        encode_ranges_validated(data, outboard, ranges, writer)
            .await
            .map_err(|e| {
                if matches!(
                    e,
                    EncodeError::LeafHashMismatch(_) | EncodeError::ParentHashMismatch(_)
                ) {
                    // Nothing that fails the check is sent.
                    self.mark_corrupt(hash, object, &format!("{e:?}"));
                }
                io::Error::other(e)
            })
    }

    /// Refuse `hash` for good: its S3 object does not match it.
    fn mark_corrupt(&self, hash: Hash, object: &Object, why: &str) {
        match object {
            Object::Blob => {
                error!(%hash, why, "S3 object does not match its hash; refused until restart. Delete blobs/<hash> and outboards/<hash> so the publisher can push it again")
            }
            Object::CatalogDocument { .. } => {
                error!(%hash, why, "S3 catalog document does not match its hash; refused until restart. Delete catalog-documents/<hash> and catalog-outboards/<hash> so the creator can publish it again")
            }
        }
        let mut corrupt = lock(&self.corrupt);
        if corrupt.len() >= BAD_CAPACITY {
            corrupt.clear();
        }
        corrupt.insert(hash);
        lock(&self.servable).remove(&hash);
    }

    /// Drop what is remembered of `hash`, so the next fetch asks S3 again.
    pub fn forget(&self, hash: &Hash) {
        lock(&self.servable).remove(hash);
    }

    /// Compute and store the outboard of a blob that lacks one, unless that
    /// runs already or [`BACKFILLS`] run.
    fn backfill(self: &Arc<Self>, hash: Hash, size: u64, object: Object) {
        let cooling = lock(&self.backfill_failed)
            .get(&hash)
            .is_some_and(|at| at.elapsed() < BACKFILL_COOLDOWN);
        if cooling {
            return;
        }
        let Ok(permit) = Arc::clone(&self.backfills).try_acquire_owned() else {
            return;
        };
        if !lock(&self.backfilling).insert(hash) {
            return;
        }
        let server = Arc::clone(self);
        tokio::spawn(async move {
            match server.compute_outboard(hash, size, &object).await {
                Ok(None) => info!(%hash, size, "Outboard computed from S3 and stored"),
                Ok(Some(actual)) => {
                    server.mark_corrupt(
                        hash,
                        &object,
                        &format!("the object in S3 hashes to {actual}"),
                    );
                }
                Err(e) => {
                    warn!(%hash, error = format!("{e:#}"), ?BACKFILL_COOLDOWN, "Computing the outboard failed; tried again after the cooldown");
                    let mut failed = lock(&server.backfill_failed);
                    if failed.len() >= BAD_CAPACITY {
                        failed.retain(|_, at| at.elapsed() < BACKFILL_COOLDOWN);
                    }
                    failed.insert(hash, Instant::now());
                }
            }
            lock(&server.backfilling).remove(&hash);
            drop(permit);
        });
    }

    /// Store the outboard of `hash`'s object, computed from S3. `Some` (and
    /// nothing stored) when the object hashes to something else.
    async fn compute_outboard(
        &self,
        hash: Hash,
        size: u64,
        object: &Object,
    ) -> anyhow::Result<Option<Hash>> {
        let hex = hash.to_hex();
        let data = S3Reader::new(Arc::clone(&self.s3), object.data_key(&self.s3, &hex), size);
        let outboard = PreOrderOutboard::<Vec<u8>>::create(data, IROH_BLOCK_SIZE).await?;
        let actual = Hash::from(outboard.root);
        if actual != hash {
            return Ok(Some(actual));
        }
        let data = Bytes::from(outboard.data);
        match object {
            Object::Blob => self.s3.put_outboard(&hex, data).await?,
            Object::CatalogDocument { .. } => self.s3.put_catalog_outboard(&hex, data).await?,
        }
        Ok(None)
    }
}

/// An S3 HEAD, bounded by [`S3_HEAD_TIMEOUT`].
async fn head<T, F: Future<Output = anyhow::Result<Option<T>>>>(
    request: F,
) -> anyhow::Result<Option<T>> {
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

/// A write to the fetcher, failing if it makes no progress for
/// [`PEER_STALL`].
async fn peer_write<E: std::error::Error + Send + Sync + 'static>(
    write: impl Future<Output = Result<(), E>>,
) -> io::Result<()> {
    tokio::time::timeout(PEER_STALL, write)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fetcher stopped reading"))?
        .map_err(io::Error::other)
}

/// The BAO encoder's writer over an iroh QUIC stream.
struct QuicWriter<'a>(&'a mut iroh::endpoint::SendStream);

impl AsyncStreamWriter for QuicWriter<'_> {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        peer_write(self.0.write_all(data)).await
    }

    async fn write_bytes(&mut self, data: Bytes) -> io::Result<()> {
        peer_write(self.0.write_chunk(data)).await
    }

    async fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
