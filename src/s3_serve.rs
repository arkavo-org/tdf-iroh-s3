//! Serving fetches straight from S3.
//!
//! The node holds no copy of blob data. A get is answered from
//! `blobs/<hash>` and `outboards/<hash>` (the blob's BAO hash tree, written
//! by ingest before the blob): the response is the blob's size, then the
//! BAO encoding of the requested ranges, exactly as iroh-blobs' own
//! provider sends it, so any iroh-blobs client verifies every chunk group
//! against the hash.
//!
//! Data reads from `blobs/<hash>` are bounded to the requested chunk-group
//! spans (merged across gaps up to [`SKIP_LIMIT`]), so a whole-blob get costs
//! one full S3 GET and a single-segment range get costs one tight bounded
//! `Range: bytes=start-end` GET instead of streaming the rest of the archive.
//! Outboards up to [`MAX_CACHED_OUTBOARD_BYTES`] (16 MiB, covering blobs up to
//! 4 GiB) are kept in a bounded LRU cache so streaming a recording segment by
//! segment reads `outboards/<hash>` from S3 once instead of re-reading Merkle
//! tree paths on every segment.
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::ops::Range;
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
/// hold a serve slot, and open S3 GETs, for as long as it likes.
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

/// Total memory budget for cached BAO outboards (64 MiB: ~4 max-size 4 GiB
/// recordings, or ~160 100 MiB recordings).
const OUTBOARD_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Largest single outboard cached in memory (16 MiB, which covers blobs up to
/// 4 GiB at [`IROH_BLOCK_SIZE`]). Larger outboards are read from S3 with
/// bounded range GETs.
const MAX_CACHED_OUTBOARD_BYTES: usize = 16 * 1024 * 1024;

/// Most outboards held in the cache at once, bounding map overhead when
/// serving many small blobs.
const OUTBOARD_CACHE_ENTRIES: usize = 1024;

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
    /// Bounded LRU cache of pre-order BAO outboards (`outboards/<hash>` and
    /// `catalog-outboards/<hash>`), so segment-by-segment streaming avoids
    /// re-fetching Merkle tree paths from S3 on every range request.
    outboards: Mutex<OutboardCache>,
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
            outboards: Mutex::new(OutboardCache::new(
                OUTBOARD_CACHE_BYTES,
                MAX_CACHED_OUTBOARD_BYTES,
                OUTBOARD_CACHE_ENTRIES,
            )),
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
        let spans = data_spans(ranges, size);
        let data = S3Reader::with_spans(
            Arc::clone(&self.s3),
            object.data_key(&self.s3, &hex),
            size,
            spans,
        );
        let outboard_size = tree.outboard_size();
        let (outboard_data, newly_loaded) = self
            .load_outboard(hash, object, &hex, outboard_size)
            .await?;
        let outboard = PreOrderOutboard {
            root: blake3::Hash::from(hash),
            tree,
            data: outboard_data,
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
            })?;
        // Cache only after BAO validation succeeded so corrupt outboards are
        // never cached.
        if let Some(bytes) = newly_loaded {
            lock(&self.outboards).insert(hash, bytes);
        }
        Ok(())
    }

    /// Return the BAO outboard reader for `hash`: from memory if cached (or
    /// empty), fetched whole into memory if it fits in the cache budget, or
    /// streamed with bounded S3 range reads if larger than
    /// [`MAX_CACHED_OUTBOARD_BYTES`]. Returns `(reader, Some(bytes))` when
    /// fetched fresh so the caller can cache it after validation succeeds.
    async fn load_outboard(
        &self,
        hash: Hash,
        object: &Object,
        hex: &str,
        outboard_size: u64,
    ) -> io::Result<(OutboardData, Option<Bytes>)> {
        if outboard_size == 0 {
            return Ok((OutboardData::Memory(Bytes::new()), None));
        }
        if let Some(cached) = lock(&self.outboards).get(&hash)
            && cached.len() as u64 == outboard_size
        {
            return Ok((OutboardData::Memory(cached), None));
        }
        let key = object.outboard_key(&self.s3, hex);
        if outboard_size <= MAX_CACHED_OUTBOARD_BYTES as u64 {
            let bytes = read_object_exact(&self.s3, &key, outboard_size as usize).await?;
            return Ok((OutboardData::Memory(bytes.clone()), Some(bytes)));
        }
        let reader = S3Reader::bounded_reads(Arc::clone(&self.s3), key, outboard_size);
        Ok((OutboardData::S3(reader), None))
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
        lock(&self.outboards).remove(&hash);
    }

    /// Drop what is remembered of `hash`, so the next fetch asks S3 again.
    pub fn forget(&self, hash: &Hash) {
        lock(&self.servable).remove(hash);
        lock(&self.outboards).remove(hash);
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
            Object::Blob => self.s3.put_outboard(&hex, data.clone()).await?,
            Object::CatalogDocument { .. } => {
                self.s3.put_catalog_outboard(&hex, data.clone()).await?;
            }
        }
        lock(&self.outboards).insert(hash, data);
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

/// Byte ranges of a `size`-byte blob that `encode_ranges_validated` reads
/// for `ranges`, rounded outward to [`IROH_BLOCK_SIZE`] chunk-group
/// boundaries and merged across gaps up to [`SKIP_LIMIT`].
fn data_spans(ranges: &ChunkRanges, size: u64) -> Vec<Range<u64>> {
    if size == 0 {
        return Vec::new();
    }
    let block_bytes = IROH_BLOCK_SIZE.bytes() as u64;
    let mut spans: Vec<Range<u64>> = Vec::new();
    // `ChunkRanges` is a `RangeSet2<ChunkNum>`: its sorted `boundaries()` pair
    // up as `[b[2k], b[2k+1])`, with an odd trailing boundary meaning
    // `[b[last], ∞)` (so `ChunkRanges::all()` is `[ChunkNum(0)]`).
    for pair in ranges.boundaries().chunks(2) {
        let start_byte = pair[0].0.saturating_mul(1024);
        if start_byte >= size {
            break;
        }
        let aligned_start = (start_byte / block_bytes) * block_bytes;
        let aligned_end = match pair.get(1) {
            Some(end) => {
                if pair[0] >= *end {
                    continue;
                }
                let end_byte = end.0.saturating_mul(1024);
                end_byte
                    .div_ceil(block_bytes)
                    .saturating_mul(block_bytes)
                    .min(size)
            }
            None => size,
        };
        let span = aligned_start..aligned_end;
        if let Some(prev) = spans.last_mut()
            && span.start <= prev.end.saturating_add(SKIP_LIMIT)
        {
            prev.end = prev.end.max(span.end);
        } else {
            spans.push(span);
        }
    }
    spans
}

/// Read an entire S3 object whose expected length is `expected` bytes,
/// failing on stall ([`S3_STALL`]), missing key, or unexpected length.
async fn read_object_exact(s3: &S3Client, key: &str, expected: usize) -> io::Result<Bytes> {
    let mut body = tokio::time::timeout(S3_STALL, s3.get_object_range(key, 0, None))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "S3 GET got no response"))?
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{key} is not in S3")))?;
    let mut buf = BytesMut::zeroed(expected);
    read_exact(&mut body, &mut buf).await?;
    // Ensure the object has no trailing bytes beyond what `check()` observed.
    let mut extra = [0u8; 1];
    let trailing = tokio::time::timeout(S3_STALL, body.read(&mut extra))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "S3 GET stalled"))??;
    if trailing != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{key} is longer than the {expected} bytes expected"),
        ));
    }
    Ok(buf.freeze())
}

/// Exact LRU cache of pre-order BAO outboards, bounded by total bytes,
/// per-entry bytes, and entry count.
struct OutboardCache {
    max_bytes: usize,
    max_entry_bytes: usize,
    max_entries: usize,
    total_bytes: usize,
    tick: u64,
    entries: HashMap<Hash, (u64, Bytes)>,
    order: BTreeMap<u64, Hash>,
}

impl OutboardCache {
    fn new(max_bytes: usize, max_entry_bytes: usize, max_entries: usize) -> Self {
        Self {
            max_bytes,
            max_entry_bytes,
            max_entries,
            total_bytes: 0,
            tick: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    fn get(&mut self, hash: &Hash) -> Option<Bytes> {
        let (old_tick, bytes) = self.entries.get_mut(hash)?;
        self.order.remove(old_tick);
        self.tick += 1;
        *old_tick = self.tick;
        self.order.insert(self.tick, *hash);
        Some(bytes.clone())
    }

    fn insert(&mut self, hash: Hash, bytes: Bytes) {
        let len = bytes.len();
        if len == 0 || len > self.max_entry_bytes || len > self.max_bytes || self.max_entries == 0 {
            return;
        }
        self.remove(&hash);
        while self.total_bytes + len > self.max_bytes || self.entries.len() >= self.max_entries {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            if let Some((_, evicted)) = self.entries.remove(&oldest) {
                self.total_bytes -= evicted.len();
            }
        }
        self.tick += 1;
        self.entries.insert(hash, (self.tick, bytes));
        self.order.insert(self.tick, hash);
        self.total_bytes += len;
    }

    fn remove(&mut self, hash: &Hash) {
        if let Some((old_tick, evicted)) = self.entries.remove(hash) {
            self.order.remove(&old_tick);
            self.total_bytes -= evicted.len();
        }
    }
}

/// Backing store for a pre-order BAO outboard: in-memory [`Bytes`] (zero-copy
/// slices) or bounded range GETs against S3 for outboards above
/// [`MAX_CACHED_OUTBOARD_BYTES`].
enum OutboardData {
    Memory(Bytes),
    S3(S3Reader),
}

impl AsyncSliceReader for OutboardData {
    async fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Bytes> {
        match self {
            OutboardData::Memory(bytes) => {
                let total = bytes.len() as u64;
                if offset >= total || len == 0 {
                    return Ok(Bytes::new());
                }
                let start = offset as usize;
                let end = start.saturating_add(len).min(bytes.len());
                Ok(bytes.slice(start..end))
            }
            OutboardData::S3(reader) => reader.read_at(offset, len).await,
        }
    }

    async fn size(&mut self) -> io::Result<u64> {
        match self {
            OutboardData::Memory(bytes) => Ok(bytes.len() as u64),
            OutboardData::S3(reader) => reader.size().await,
        }
    }
}

/// Reads one S3 object at increasing offsets through bounded range GETs.
struct S3Reader {
    s3: Arc<S3Client>,
    key: String,
    size: u64,
    /// Precomputed byte spans this reader expects to cover; each span opens
    /// one bounded S3 GET (`bytes=start-(end-1)`). Reads outside these spans
    /// fall back to an exact `[offset, offset + len)` range GET.
    spans: Vec<Range<u64>>,
    open: Option<OpenGet>,
}

struct OpenGet {
    pos: u64,
    end: u64,
    body: Pin<Box<dyn AsyncBufRead + Send>>,
}

impl S3Reader {
    /// Read the whole object sequentially (`[0, size)`).
    fn new(s3: Arc<S3Client>, key: String, size: u64) -> Self {
        let spans = (size > 0).then_some(0..size).into_iter().collect();
        Self::with_spans(s3, key, size, spans)
    }

    /// Read only the precomputed byte `spans`, opening one bounded S3 GET per
    /// span.
    fn with_spans(s3: Arc<S3Client>, key: String, size: u64, spans: Vec<Range<u64>>) -> Self {
        Self {
            s3,
            key,
            size,
            spans,
            open: None,
        }
    }

    /// Issue an exact bounded S3 range GET for each `read_at` call.
    fn bounded_reads(s3: Arc<S3Client>, key: String, size: u64) -> Self {
        Self::with_spans(s3, key, size, Vec::new())
    }

    /// Exclusive upper byte bound for a new S3 GET starting at `offset` that
    /// must cover at least `needed_end`.
    fn fetch_end(&self, offset: u64, needed_end: u64) -> u64 {
        self.spans
            .iter()
            .find(|s| s.start <= offset && offset < s.end)
            .map_or(needed_end, |s| s.end.max(needed_end))
            .min(self.size)
    }

    async fn open_at(&mut self, offset: u64, len: usize) -> io::Result<&mut OpenGet> {
        let needed_end = offset.saturating_add(len as u64).min(self.size);
        let reusable = self.open.as_ref().is_some_and(|o| {
            o.pos <= offset && offset - o.pos <= SKIP_LIMIT && needed_end <= o.end
        });
        if !reusable {
            self.open = None;
            let fetch_end = self.fetch_end(offset, needed_end);
            // A full-object GET from 0 omits `Range` (handles 0-byte objects
            // and avoids an unnecessary 206 header).
            let range_end = (offset > 0 || fetch_end < self.size).then_some(fetch_end);
            let body = tokio::time::timeout(
                S3_STALL,
                self.s3.get_object_range(&self.key, offset, range_end),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "S3 GET got no response"))?
            .map_err(io::Error::other)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} is not in S3", self.key),
                )
            })?;
            self.open = Some(OpenGet {
                pos: offset,
                end: fetch_end,
                body,
            });
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
            let open = self.open_at(offset, len).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use bao_tree::ChunkNum;

    fn span_bounds(ranges: &ChunkRanges, size: u64) -> Vec<(u64, u64)> {
        data_spans(ranges, size)
            .into_iter()
            .map(|r| (r.start, r.end))
            .collect()
    }

    #[test]
    fn data_spans_all_covers_whole_blob() {
        assert_eq!(
            span_bounds(&ChunkRanges::all(), 1_000_000),
            [(0, 1_000_000)]
        );
        assert!(data_spans(&ChunkRanges::all(), 0).is_empty());
    }

    #[test]
    fn data_spans_rounds_to_chunk_groups_and_clamps_to_size() {
        // Chunks 3..5 lie inside chunk group 0 (0..16 KiB).
        let ranges = ChunkRanges::from(ChunkNum(3)..ChunkNum(5));
        assert_eq!(span_bounds(&ranges, 1_000_000), [(0, 16_384)]);

        // Chunks 17..45 span chunk groups 1..3 (16 KiB..48 KiB).
        let ranges = ChunkRanges::from(ChunkNum(17)..ChunkNum(45));
        assert_eq!(span_bounds(&ranges, 1_000_000), [(16_384, 49_152)]);

        // Tail range clamps to the exact blob size.
        let size = 100_000u64;
        let last = ChunkNum((size - 1) / 1024);
        let ranges = ChunkRanges::from(last..ChunkNum(last.0 + 1));
        assert_eq!(span_bounds(&ranges, size), [(98_304, 100_000)]);
    }

    #[test]
    fn data_spans_merges_nearby_ranges_and_splits_distant_ones() {
        // Two ranges separated by <= SKIP_LIMIT (256 KiB) merge into one span.
        let mut nearby = ChunkRanges::from(ChunkNum(0)..ChunkNum(1));
        nearby |= ChunkRanges::from(ChunkNum(100)..ChunkNum(101));
        assert_eq!(span_bounds(&nearby, 2_000_000), [(0, 114_688)]);

        // Two ranges separated by > SKIP_LIMIT stay two distinct bounded spans.
        let mut far = ChunkRanges::from(ChunkNum(0)..ChunkNum(1));
        far |= ChunkRanges::from(ChunkNum(1000)..ChunkNum(1001));
        assert_eq!(
            span_bounds(&far, 2_000_000),
            [(0, 16_384), (1_015_808, 1_032_192)]
        );
    }

    #[test]
    fn data_spans_handles_open_ended_and_out_of_bounds() {
        let from = ChunkRanges::from(ChunkNum(20)..);
        assert_eq!(span_bounds(&from, 100_000), [(16_384, 100_000)]);

        let past_eof = ChunkRanges::from(ChunkNum(500)..ChunkNum(600));
        assert!(data_spans(&past_eof, 100_000).is_empty());
    }

    #[test]
    fn outboard_cache_evicts_lru_by_bytes_and_entries() {
        let mut cache = OutboardCache::new(100, 60, 2);
        let h1 = Hash::new(b"one");
        let h2 = Hash::new(b"two");
        let h3 = Hash::new(b"three");

        cache.insert(h1, Bytes::from(vec![1u8; 40]));
        cache.insert(h2, Bytes::from(vec![2u8; 40]));
        assert_eq!(cache.total_bytes, 80);

        // Touch h1 so h2 becomes least recently used.
        assert_eq!(cache.get(&h1).unwrap().len(), 40);

        // Inserting h3 (40 bytes) exceeds both max_bytes (120 > 100) and
        // max_entries (3 > 2), evicting h2 while keeping h1.
        cache.insert(h3, Bytes::from(vec![3u8; 40]));
        assert!(cache.get(&h2).is_none());
        assert_eq!(cache.get(&h1).unwrap().len(), 40);
        assert_eq!(cache.get(&h3).unwrap().len(), 40);
        assert_eq!(cache.total_bytes, 80);

        // Entries larger than max_entry_bytes or empty are ignored.
        let huge = Hash::new(b"huge");
        cache.insert(huge, Bytes::from(vec![9u8; 61]));
        assert!(cache.get(&huge).is_none());
        let empty = Hash::new(b"empty");
        cache.insert(empty, Bytes::new());
        assert!(cache.get(&empty).is_none());

        // Explicit removal frees bytes.
        cache.remove(&h1);
        assert!(cache.get(&h1).is_none());
        assert_eq!(cache.total_bytes, 40);
    }
}
