use anyhow::{Context, Result};
use bao_tree::ChunkRanges;
use futures::StreamExt;
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::protocol::{ERR_LIMIT, ERR_PERMISSION, Request};
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate,
};
use iroh_blobs::provider::{self, StreamPair};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::fs::options::{InlineOptions, Options};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::ingest::{self, IngestError};
use crate::moderation::{BlobOwner, PublishGate, now_secs};
use crate::s3_serve::{Refusal, S3Server};
use crate::secret_key;
use crate::staging::{PendingPush, Staging};
use crate::store::s3::S3Client;

pub struct TdfIrohNode {
    router: Router,
    store: FsStore,
    endpoint: Endpoint,
    pub s3_client: Arc<S3Client>,
    pub config: Arc<Config>,
    staging: Arc<Staging>,
    cancel: CancellationToken,
}

impl TdfIrohNode {
    /// A node that accepts every push (tests and `[publishing] required =
    /// false`).
    pub async fn spawn(config: Config) -> Result<Self> {
        Self::spawn_with_gate(config, None).await
    }

    /// With a gate, pushes are accepted only from endpoints holding a
    /// publish session, and blocked hashes are neither accepted nor served.
    pub async fn spawn_with_gate(config: Config, gate: Option<Arc<PublishGate>>) -> Result<Self> {
        let config = Arc::new(config);

        let s3_client = Arc::new(
            S3Client::from_config(&config.s3)
                .await
                .context("Failed to create S3 client")?,
        );

        // The local store only stages pushes; its garbage collector deletes
        // whatever no pending push needs (see `staging`).
        let staging = Staging::new();
        let store = {
            let root = Path::new(&config.iroh.data_dir);
            // Outboards are never inlined: iroh-blobs moves an inlined
            // outboard into its database when an import completes but leaves
            // the `.obao4` file the import wrote, and deleting the blob later
            // never removes that file, so every staged push of 16 KiB to
            // 4 MiB would leave up to 16 KiB on disk. Data stays inlined: a
            // blob that small has no outboard and leaves nothing behind.
            let options = Options {
                gc: Some(
                    staging.gc_config(Duration::from_secs(config.iroh.gc_interval_secs.max(1))),
                ),
                inline: InlineOptions {
                    max_outboard_inlined: 0,
                    ..InlineOptions::default()
                },
                ..Options::new(root)
            };
            FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .context("Failed to load FsStore")?
        };
        staging.attach(store.clone().into());

        let mut builder = Endpoint::builder(presets::N0);
        if !config.iroh.secret_key_param.is_empty() {
            let secret_key =
                secret_key::load_or_create(&config.iroh.secret_key_param, &config.s3.region)
                    .await
                    .context("Failed to load or create node secret key")?;
            builder = builder.secret_key(secret_key);
        }

        let endpoint = builder
            .bind_addr((Ipv4Addr::UNSPECIFIED, config.iroh.bind_port))
            .context("Invalid bind address")?
            .bind()
            .await
            .context("Failed to bind Iroh endpoint")?;

        info!("Iroh endpoint bound on port {}", config.iroh.bind_port);
        endpoint.online().await;
        info!("Iroh endpoint online");

        let cancel = CancellationToken::new();

        // The node runs its own blobs protocol handler (`BlobsHandler`).
        // Pushes go to iroh-blobs' provider into the local store, which only
        // stages them; gets are answered from S3 (`s3_serve`); observe is
        // refused. So only pushes, and with a gate connections, raise
        // events: `run_ingest_loop` answers each push, refusing a hash
        // sequence (its child blobs would bypass validation) and, with a
        // gate, a push without a publish session; `connected: Intercept`
        // reports each connection's authenticated endpoint ID, which
        // identifies the pusher. For push, `EventMask::DEFAULT` is
        // `Disabled`, which would refuse every push.
        //
        // The update stream of an intercepted push carries no events. It
        // closes when the transfer ends, and `wait_and_ingest` waits for
        // that. InterceptLog would reset any request whose update stream the
        // loop stopped reading.
        let mask = EventMask {
            connected: if gate.is_some() {
                ConnectMode::Intercept
            } else {
                EventMask::DEFAULT.connected
            },
            push: RequestMode::Intercept,
            ..EventMask::DEFAULT
        };
        let (event_sender, event_rx) = EventSender::channel(64, mask);

        let connections = Arc::new(Connections::default());
        let blobs = BlobsHandler {
            store: store.clone(),
            events: event_sender,
            connections: Arc::clone(&connections),
            server: S3Server::new(Arc::clone(&s3_client)),
            gate: gate.clone(),
            serves: Arc::new(Semaphore::new(SERVES)),
        };

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();

        let addr = endpoint.addr();
        info!("Node ID: {}", addr.id);

        // Spawn the ingest background task
        {
            let ingester = Arc::new(Ingester {
                connections,
                staging: Arc::clone(&staging),
                store: store.clone(),
                s3_client: Arc::clone(&s3_client),
                config: Arc::clone(&config),
                scratch_dir: ingest::prepare_scratch_dir(&config.iroh.data_dir).await?,
                permits: Arc::new(Semaphore::new(
                    config.validation.max_concurrent_ingests.get(),
                )),
            });
            let cancel = cancel.clone();
            tokio::spawn(async move {
                run_ingest_loop(event_rx, ingester, gate, cancel).await;
            });
        }

        Ok(Self {
            router,
            store,
            endpoint,
            s3_client,
            config,
            staging,
            cancel,
        })
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// The running endpoint (`GET /node` reads its identity and relay).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn store(&self) -> &FsStore {
        &self.store
    }

    /// Pushes being received or ingested.
    pub fn staging(&self) -> &Arc<Staging> {
        &self.staging
    }

    pub async fn shutdown(self) -> Result<()> {
        self.cancel.cancel();
        self.router
            .shutdown()
            .await
            .context("Failed to shutdown router")?;
        let _ = self.store.shutdown().await;
        Ok(())
    }
}

/// What ingesting a pushed blob needs.
struct Ingester {
    /// Open connections, so an oversize push's can be closed.
    connections: Arc<Connections>,
    staging: Arc<Staging>,
    store: FsStore,
    s3_client: Arc<S3Client>,
    config: Arc<Config>,
    /// `<data_dir>/ingest`, where blobs are exported for validation.
    scratch_dir: PathBuf,
    /// `[validation] max_concurrent_ingests` permits.
    permits: Arc<Semaphore>,
}

async fn run_ingest_loop(
    mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    ingester: Arc<Ingester>,
    gate: Option<Arc<PublishGate>>,
    cancel: CancellationToken,
) {
    info!("Ingest loop started");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Ingest loop cancelled");
                break;
            }
            msg = rx.recv() => {
                if let Some(ref m) = msg {
                    debug!("Received provider message: {:?}", m);
                }
                // Every message with a `tx` holds its request until it is
                // answered, so each arm answers, here or in a task it
                // spawns. A dropped `tx` refuses the request (iroh-blobs
                // resets it with an internal error); it never approves it.
                // The match lists every variant, so a new one is a compile
                // error rather than an unanswered request.
                match msg {
                    Some(ProviderMessage::PushRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
                        let connection_id = msg.inner.connection_id;
                        if !msg.inner.request.ranges.is_blob() {
                            warn!(%hash, "Push of a hash sequence refused");
                            msg.tx.send(Err(AbortReason::Permission)).await.ok();
                            continue;
                        }
                        let owner = match &gate {
                            None => None,
                            Some(g) => match g.authorize_push(msg.inner.connection_id, &hash.to_hex()) {
                                Ok(owner) => Some(owner),
                                Err(why) => {
                                    warn!(%hash, ?why, "Push refused");
                                    msg.tx.send(Err(AbortReason::Permission)).await.ok();
                                    continue;
                                }
                            },
                        };
                        info!(%hash, subject = ?owner.as_ref().map(|o| &o.0), "Push accepted");
                        let ingester = Arc::clone(&ingester);
                        tokio::spawn(async move {
                            let pending = ingester.staging.track(hash);
                            msg.tx.send(Ok(())).await.ok();
                            // Recorded once the blob is ingested.
                            if wait_and_ingest(hash, msg.rx, connection_id, pending, &ingester).await
                                && let Some((subject, endpoint)) = owner
                            {
                                record_owner(&ingester.s3_client, hash, subject, endpoint).await;
                            }
                        });
                    }
                    // The node's handler answers gets and observes itself
                    // and its mask sends no events for them; answer anyway.
                    Some(ProviderMessage::GetRequestReceived(msg)) => {
                        msg.tx.send(Err(AbortReason::Permission)).await.ok();
                    }
                    Some(ProviderMessage::GetManyRequestReceived(msg)) => {
                        msg.tx.send(Err(AbortReason::Permission)).await.ok();
                    }
                    Some(ProviderMessage::ObserveRequestReceived(msg)) => {
                        msg.tx.send(Err(AbortReason::Permission)).await.ok();
                    }
                    Some(ProviderMessage::ClientConnected(msg)) => {
                        if let Some(g) = &gate {
                            g.connected(msg.inner.connection_id, msg.inner.endpoint_id);
                        }
                        msg.tx.send(Ok(())).await.ok();
                    }
                    Some(ProviderMessage::ConnectionClosed(msg)) => {
                        if let Some(g) = &gate {
                            g.closed(msg.inner.connection_id);
                        }
                    }
                    // Throttling is off (`ThrottleMode::None`); answer anyway.
                    Some(ProviderMessage::Throttle(msg)) => {
                        msg.tx.send(Ok(())).await.ok();
                    }
                    // Neither mask enables these notifications.
                    Some(
                        ProviderMessage::ClientConnectedNotify(_)
                        | ProviderMessage::PushRequestReceivedNotify(_)
                        | ProviderMessage::GetRequestReceivedNotify(_)
                        | ProviderMessage::GetManyRequestReceivedNotify(_)
                        | ProviderMessage::ObserveRequestReceivedNotify(_),
                    ) => {
                        debug!("Unrequested provider notification ignored");
                    }
                    None => {
                        info!("Event channel closed, ingest loop exiting");
                        break;
                    }
                }
            }
        }
    }
}

/// Most hashes one get_many may name. Creator and the viewer fetch one blob
/// at a time; a request naming more is refused before any lookup, so it
/// cannot make the node send S3 a lookup per hash.
const MAX_FETCH_HASHES: usize = 64;

/// Record who pushed a blob, so a suspension can be traced to content.
async fn record_owner(
    s3_client: &S3Client,
    hash: iroh_blobs::Hash,
    subject: String,
    endpoint: iroh::EndpointId,
) {
    let owner = BlobOwner {
        hash: hash.to_hex().to_string(),
        subject,
        endpoint_id: endpoint.to_string(),
        at: now_secs(),
    };
    let body = bytes::Bytes::from(serde_json::to_vec(&owner).expect("owner serializes"));
    if let Err(e) = s3_client
        .put_moderation_record("publishers", &owner.hash, body)
        .await
    {
        warn!(%hash, error = %e, "Recording the blob's publisher failed");
    }
}

/// Wait for a push to land and ingest it. `true` when the blob validated
/// (it is served from then on, whether or not its upload worked).
/// A transfer that aborts is still checked: the store may hold the whole
/// blob already.
async fn wait_and_ingest(
    hash: iroh_blobs::Hash,
    mut rx: irpc::channel::mpsc::Receiver<RequestUpdate>,
    connection_id: u64,
    pending: PendingPush,
    ingester: &Ingester,
) -> bool {
    // A push carries its size in its first 8 bytes, and the store records
    // it with the first chunks written. When it exceeds max_blob_bytes, the
    // connection is closed then, so the push stops long before it can fill
    // the disk. The connection is also watched for a stall: on a P2P network a peer
    // can stop sending without closing, and the push would hold its hash
    // pending for as long as the connection lives.
    let max = ingester.config.validation.max_blob_bytes;
    let stall = Duration::from_secs(ingester.config.iroh.push_stall_secs.max(1));
    let mut trouble = Box::pin(watch_push(ingester, connection_id, hash, max, stall));

    // Wait for the push transfer to complete
    let mut completed = false;
    loop {
        let update = tokio::select! {
            update = rx.recv() => update,
            trouble = &mut trouble => {
                match trouble {
                    PushTrouble::Oversize(size) => {
                        warn!(%hash, size, max, "Push exceeds max_blob_bytes; closing its connection");
                        ingester.connections.close(connection_id, b"blob exceeds max_blob_bytes");
                    }
                    PushTrouble::Stalled => {
                        // Closed, then checked like an aborted transfer: the
                        // store may hold the whole blob already.
                        warn!(%hash, ?stall, "Push stalled; closing its connection");
                        ingester.connections.close(connection_id, b"push stalled");
                        break;
                    }
                }
                return false;
            }
        };
        let Ok(Some(update)) = update else {
            break;
        };
        match update {
            RequestUpdate::Started(s) => {
                info!(%hash, size = s.size, "Push transfer started");
            }
            RequestUpdate::Progress(_) => {}
            RequestUpdate::Completed(_) => {
                info!(%hash, "Push transfer completed");
                completed = true;
                break;
            }
            RequestUpdate::Aborted(_) => {
                // Check the store anyway: the blob may be complete already.
                warn!(%hash, "Push transfer aborted");
                break;
            }
        }
    }
    // The transfer is over; stop watching it.
    drop(trouble);
    if !completed {
        // In Notify and Intercept modes the stream carries no events.
        // iroh-blobs holds its sender until the push handler returns, after
        // the data is written (or the transfer fails), so the stream closes
        // when the transfer ends, never at the notification.
        info!(%hash, "Push transfer ended, checking store");
    }

    ingest_stored(hash, pending, ingester).await
}

/// Upload attempts for a blob that validated, with this pause before
/// each retry: an S3 hiccup should not fail a publish.
const UPLOAD_RETRIES: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(5)];

/// Ingest the blob the store holds for `hash` once it is complete:
/// validate, then upload. `true` when it is in S3, and so served. The
/// push stays pending (its staged copy kept) until this returns; then the
/// collector deletes the copy, whatever happened. A push that failed here
/// shows as `GET /blobs` 404, and the publisher pushes again.
async fn ingest_stored(hash: iroh_blobs::Hash, pending: PendingPush, ingester: &Ingester) -> bool {
    let _pending = pending;
    // Retry briefly for FsStore's async DB propagation; an aborted transfer
    // leaves the blob incomplete. This waits without an ingest permit, so
    // an abandoned push holds up no one.
    let mut complete = false;
    for attempt in 0..10 {
        match ingester.store.observe(hash).await {
            Ok(bitfield) if bitfield.is_complete() => {
                complete = true;
                break;
            }
            Ok(_) => {}
            Err(e) => {
                error!(%hash, error = %e, "Store lookup failed");
                return false;
            }
        }
        debug!(%hash, attempt, "Blob not yet complete, retrying");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !complete {
        warn!(%hash, "Blob incomplete after the push ended");
        return false;
    }

    // At most `max_concurrent_ingests` blobs are exported, validated and
    // uploaded at once; each holds a scratch copy on disk meanwhile.
    let Ok(_permit) = ingester.permits.acquire().await else {
        return false;
    };
    let config = &ingester.config;
    let validated = match ingest::validate_from_store(
        hash,
        &ingester.store,
        &config.validation,
        &ingester.scratch_dir,
    )
    .await
    {
        Ok(Some(validated)) => validated,
        Ok(None) => {
            error!(%hash, "Blob incomplete at validation");
            return false;
        }
        Err(IngestError::Refused(e)) => {
            warn!(%hash, error = format!("{e:#}"), "Ingest refused the blob");
            return false;
        }
        Err(IngestError::Failed(e)) => {
            error!(%hash, error = format!("{e:#}"), "Ingest failed");
            return false;
        }
    };
    let mut retries = UPLOAD_RETRIES.iter();
    loop {
        match ingest::upload(&validated, &config.catalog, &ingester.s3_client).await {
            Ok(result) => {
                info!(hash = %result.hash_hex, size = result.size, "Blob ingested successfully");
                return true;
            }
            Err(e) => match retries.next() {
                Some(pause) => {
                    warn!(%hash, error = %e, ?pause, "Upload failed; retrying");
                    tokio::time::sleep(*pause).await;
                }
                None => {
                    error!(%hash, error = %e, "Upload failed; the publisher must push again");
                    return false;
                }
            },
        }
    }
}

/// Why a push is stopped before its transfer ends.
enum PushTrouble {
    /// It declared more than max_blob_bytes.
    Oversize(u64),
    /// Its connection received less than [`PUSH_STALL_MIN_BYTES`] in the
    /// stall window.
    Stalled,
}

/// Bytes a push's connection must receive per stall window
/// (`[iroh] push_stall_secs`) to count as moving. QUIC keep-alives alone
/// stay far below it. Counted on the connection, not the store: a push
/// over data the store already holds writes nothing new while it moves.
const PUSH_STALL_MIN_BYTES: u64 = 64 * 1024;

/// Resolves when `hash`'s push declares a size over `max`, or its
/// connection stalls; otherwise never. A connection that closes ends the
/// transfer by itself.
async fn watch_push(
    ingester: &Ingester,
    connection_id: u64,
    hash: iroh_blobs::Hash,
    max: u64,
    stall: Duration,
) -> PushTrouble {
    let stalled = async {
        let mut last = ingester.connections.rx_bytes(connection_id);
        loop {
            tokio::time::sleep(stall).await;
            let now = ingester.connections.rx_bytes(connection_id);
            match (last, now) {
                (Some(before), Some(after))
                    if after.saturating_sub(before) < PUSH_STALL_MIN_BYTES =>
                {
                    return;
                }
                (_, None) => std::future::pending::<()>().await,
                _ => last = now,
            }
        }
    };
    tokio::select! {
        size = oversize_push(&ingester.store, hash, max) => PushTrouble::Oversize(size),
        () = stalled => PushTrouble::Stalled,
    }
}

/// Resolves with the size `hash`'s push declared once that exceeds `max`;
/// otherwise never. The size is fixed by the hash, so once a size within
/// `max` is known there is nothing left to watch.
async fn oversize_push(store: &FsStore, hash: iroh_blobs::Hash, max: u64) -> u64 {
    if let Ok(updates) = store.observe(hash).stream().await {
        tokio::pin!(updates);
        while let Some(bitfield) = updates.next().await {
            match bitfield.size() {
                0 => continue,
                size if size > max => return size,
                _ => break,
            }
        }
    }
    std::future::pending().await
}

/// Open connections of the blobs protocol, by the id iroh-blobs reports in
/// its events (`Connection::stable_id`).
#[derive(Debug, Default)]
struct Connections(std::sync::Mutex<HashMap<u64, Connection>>);

impl Connections {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Connection>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Bytes connection `id` has received so far, while it is open.
    fn rx_bytes(&self, id: u64) -> Option<u64> {
        self.lock().get(&id).map(|conn| conn.stats().udp_rx.bytes)
    }

    /// Close connection `id`, if it is still open, with application error
    /// code 1 and `reason`.
    fn close(&self, id: u64, reason: &[u8]) {
        if let Some(conn) = self.lock().get(&id) {
            conn.close(VarInt::from_u32(1), reason);
        }
    }
}

/// Gets served from S3 at once; more are refused as "try again".
const SERVES: usize = 256;

/// The node's blobs protocol. A push is handed to iroh-blobs' provider,
/// which writes it into the local store (staging) and raises the events
/// `run_ingest_loop` answers. A get or get_many is answered from S3
/// ([`S3Server`]). Observe is refused: nothing uses it, and the node holds
/// no copy to observe. Each open connection is kept in [`Connections`] so
/// the ingest loop can close one carrying an oversize or stalled push.
#[derive(Clone)]
struct BlobsHandler {
    store: FsStore,
    events: EventSender,
    connections: Arc<Connections>,
    server: Arc<S3Server>,
    gate: Option<Arc<PublishGate>>,
    serves: Arc<Semaphore>,
}

impl std::fmt::Debug for BlobsHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobsHandler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for BlobsHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        use iroh_blobs::provider::events::{ClientConnected, ConnectionClosed, HasErrorCode};
        let id = conn.stable_id() as u64;
        if let Err(cause) = self
            .events
            .client_connected(|| ClientConnected {
                connection_id: id,
                endpoint_id: Some(conn.remote_id()),
            })
            .await
        {
            conn.close(cause.code(), cause.reason());
            return Ok(());
        }
        self.connections.lock().insert(id, conn.clone());
        while let Ok((send, recv)) = conn.accept_bi().await {
            let handler = self.clone();
            tokio::spawn(async move { handler.stream(id, send, recv).await });
        }
        self.connections.lock().remove(&id);
        self.events
            .connection_closed(|| ConnectionClosed { connection_id: id })
            .await
            .ok();
        Ok(())
    }
}

impl BlobsHandler {
    async fn stream(&self, connection_id: u64, mut send: SendStream, mut recv: RecvStream) {
        let request = match Request::read_async(&mut recv).await {
            Ok((request, _)) => request,
            Err(e) => {
                debug!(error = %e, "Unreadable blobs request");
                send.reset(ERR_PERMISSION).ok();
                return;
            }
        };
        match request {
            Request::Push(request) => {
                let pair = StreamPair::new(connection_id, recv, send, self.events.clone());
                if let Err(e) =
                    provider::handle_push(pair, self.store.clone().into(), request).await
                {
                    debug!(error = %e, "Push stream ended with an error");
                }
            }
            Request::Get(request) => {
                // A single blob only: a hash-sequence get would serve
                // children without their own check.
                match request.ranges.as_single() {
                    Some((0, ranges)) => {
                        let wanted = vec![(request.hash, ranges.clone())];
                        self.serve(wanted, send, "get").await
                    }
                    _ => refuse(send, ERR_PERMISSION, "get of a hash sequence", None),
                }
            }
            Request::GetMany(request) => {
                if request.hashes.len() > MAX_FETCH_HASHES {
                    return refuse(
                        send,
                        ERR_PERMISSION,
                        "get_many naming too many hashes",
                        None,
                    );
                }
                let wanted = request
                    .hashes
                    .iter()
                    .copied()
                    .zip(request.ranges.iter_infinite())
                    .filter(|(_, ranges)| !ranges.is_empty())
                    .map(|(hash, ranges)| (hash, ranges.clone()))
                    .collect();
                self.serve(wanted, send, "get_many").await
            }
            _ => refuse(send, ERR_PERMISSION, "observe or unknown request", None),
        }
    }

    /// Answer a get or get_many from S3. Every hash is checked before a
    /// byte is sent, so a refusal is clean: `ERR_PERMISSION` when one is
    /// blocked or S3 has no such blob, `ERR_LIMIT` (try again) when S3 did
    /// not answer, its outboard is being computed, or the node is busy. An
    /// S3 failure mid-transfer also resets with `ERR_LIMIT`: on a P2P
    /// network and with S3 behind it, a transfer that breaks is worth
    /// another attempt.
    async fn serve(
        &self,
        wanted: Vec<(iroh_blobs::Hash, ChunkRanges)>,
        mut send: SendStream,
        request: &'static str,
    ) {
        let Ok(_permit) = Arc::clone(&self.serves).try_acquire_owned() else {
            return refuse(send, ERR_LIMIT, "too many fetches at once", None);
        };
        let mut sizes = Vec::with_capacity(wanted.len());
        for (hash, _) in &wanted {
            let blocked = self
                .gate
                .as_ref()
                .is_some_and(|g| g.moderation.is_blocked(&hash.to_hex()));
            if blocked {
                return refuse(send, ERR_PERMISSION, "blocked content", Some(*hash));
            }
            match self.server.check(*hash).await {
                Ok(size) => sizes.push(size),
                Err(Refusal::Gone) => {
                    return refuse(send, ERR_PERMISSION, "not in storage", Some(*hash));
                }
                Err(Refusal::Busy) => {
                    return refuse(send, ERR_LIMIT, "storage not ready", Some(*hash));
                }
            }
        }
        for ((hash, ranges), size) in wanted.iter().zip(sizes) {
            if let Err(e) = self.server.send(*hash, size, ranges, &mut send).await {
                warn!(request, %hash, error = %e, "Serving from S3 broke off; the fetcher may try again");
                // Checked again on the next fetch: a blob deleted from S3 is
                // then refused for good.
                self.server.forget(hash);
                send.reset(ERR_LIMIT).ok();
                return;
            }
        }
        send.finish().ok();
    }
}

/// Refuse a request: `ERR_PERMISSION` is final, `ERR_LIMIT` means try again.
fn refuse(mut send: SendStream, code: VarInt, why: &'static str, hash: Option<iroh_blobs::Hash>) {
    let retry = code == ERR_LIMIT;
    info!(?hash, why, retry, "Fetch refused");
    send.reset(code).ok();
}
