use anyhow::{Context, Result};
use futures::StreamExt;
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::BlobsProtocol;
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ObserveMode, ProviderMessage, RequestMode,
    RequestUpdate,
};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::store::fs::options::Options;
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
use crate::quarantine::{PendingPush, Quarantine};
use crate::secret_key;
use crate::store::s3::S3Client;

pub struct TdfIrohNode {
    router: Router,
    store: FsStore,
    endpoint: Endpoint,
    pub s3_client: Arc<S3Client>,
    pub config: Arc<Config>,
    quarantine: Arc<Quarantine>,
    cancel: CancellationToken,
}

impl TdfIrohNode {
    /// A node that accepts every push and serves every blob (tests and
    /// `[publishing] required = false`).
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

        // The store's garbage collector deletes refused blobs (and nothing
        // else): see `quarantine`.
        let quarantine = Quarantine::load(Path::new(&config.iroh.data_dir))
            .await
            .context("Failed to load refused blobs")?;
        let store = {
            let root = Path::new(&config.iroh.data_dir);
            let options = Options {
                gc: Some(
                    quarantine.gc_config(Duration::from_secs(config.iroh.gc_interval_secs.max(1))),
                ),
                ..Options::new(root)
            };
            FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .context("Failed to load FsStore")?
        };
        quarantine.attach(store.clone().into(), Arc::clone(&s3_client));

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

        // Each request type follows its own field of the mask. A field left
        // at `EventMask::DEFAULT` sends no events; for push, DEFAULT is
        // `Disabled`, which refuses every push.
        //
        // Push, get, get_many and observe are intercepted, gated or not, and
        // `run_ingest_loop` answers each one. A push is recorded as pending
        // before it is answered, so the blob is withheld (and protected from
        // the garbage collector) from its first byte. get, get_many and
        // observe are refused for a withheld hash (a push not yet validated,
        // or refused), and on a gated node for a blocked hash. With a gate, a
        // push also needs a publish session, and `connected: Intercept`
        // reports each connection's authenticated endpoint ID, which
        // identifies the pusher.
        //
        // The update stream of an intercepted request carries no events. It
        // closes when the transfer ends, and `wait_and_ingest` waits for
        // that. InterceptLog would reset any request whose update stream the
        // loop stopped reading.
        let mask = EventMask {
            connected: if gate.is_some() {
                ConnectMode::Intercept
            } else {
                EventMask::DEFAULT.connected
            },
            get: RequestMode::Intercept,
            get_many: RequestMode::Intercept,
            push: RequestMode::Intercept,
            observe: ObserveMode::Intercept,
            ..EventMask::DEFAULT
        };
        let (event_sender, event_rx) = EventSender::channel(64, mask);

        let connections = Arc::new(Connections::default());
        let blobs = TrackedBlobs {
            inner: BlobsProtocol::new(&store, Some(event_sender)),
            connections: Arc::clone(&connections),
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
                quarantine: Arc::clone(&quarantine),
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
            quarantine,
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

    /// Pushed blobs withheld from serving, and refused ones awaiting
    /// deletion.
    pub fn quarantine(&self) -> &Arc<Quarantine> {
        &self.quarantine
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
    quarantine: Arc<Quarantine>,
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
    // Not served: a blocked hash (gated nodes), or a pushed blob that has
    // not validated or was refused.
    let blocked = |hash: &iroh_blobs::Hash| {
        ingester.quarantine.is_withheld(hash)
            || gate
                .as_ref()
                .is_some_and(|g| g.moderation.is_blocked(&hash.to_hex()))
    };
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Ingest loop cancelled");
                break;
            }
            msg = rx.recv() => {
                if let Some(ref m) = msg {
                    info!("Received provider message: {:?}", m);
                }
                // Every message with a `tx` holds its request until it is
                // answered, so each arm answers. A dropped `tx` refuses the
                // request (iroh-blobs resets it with an internal error); it
                // never approves it. The match lists every variant, so a new
                // one is a compile error rather than an unanswered request.
                match msg {
                    Some(ProviderMessage::PushRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
                        let connection_id = msg.inner.connection_id;
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
                        let pending = ingester.quarantine.track(hash).await;
                        msg.tx.send(Ok(())).await.ok();
                        let ingester = Arc::clone(&ingester);
                        tokio::spawn(async move {
                            if wait_and_ingest(hash, msg.rx, connection_id, pending, &ingester).await
                                && let Some((subject, endpoint)) = owner
                            {
                                record_owner(&ingester.s3_client, hash, subject, endpoint).await;
                            }
                        });
                    }
                    Some(ProviderMessage::GetRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
                        if blocked(&hash) {
                            info!(%hash, "Fetch of withheld or blocked content refused");
                            msg.tx.send(Err(AbortReason::Permission)).await.ok();
                        } else {
                            msg.tx.send(Ok(())).await.ok();
                        }
                    }
                    Some(ProviderMessage::GetManyRequestReceived(msg)) => {
                        if msg.inner.request.hashes.iter().any(&blocked) {
                            info!("Fetch of withheld or blocked content refused (get_many)");
                            msg.tx.send(Err(AbortReason::Permission)).await.ok();
                        } else {
                            msg.tx.send(Ok(())).await.ok();
                        }
                    }
                    Some(ProviderMessage::ObserveRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
                        if blocked(&hash) {
                            info!(%hash, "Observe of withheld or blocked content refused");
                            msg.tx.send(Err(AbortReason::Permission)).await.ok();
                        } else {
                            msg.tx.send(Ok(())).await.ok();
                        }
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

/// Wait for a push to land and ingest it. `true` when the blob was ingested.
/// Dropping `pending` without validating refuses the blob, so every path
/// that does not reach validation leaves it withheld and to be deleted.
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
    // the disk. Only a push of a hash the node does not hold is watched.
    let max = ingester.config.validation.max_blob_bytes;
    let watched = pending.is_tracked();
    let mut oversize = Box::pin(async {
        if watched {
            oversize_push(&ingester.store, hash, max).await
        } else {
            std::future::pending().await
        }
    });

    // Wait for the push transfer to complete
    let mut completed = false;
    loop {
        let update = tokio::select! {
            update = rx.recv() => update,
            size = &mut oversize => {
                warn!(%hash, size, max, "Push exceeds max_blob_bytes; closing its connection");
                ingester.connections.close(connection_id, b"blob exceeds max_blob_bytes");
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
                warn!(%hash, "Push transfer aborted");
                return false;
            }
        }
    }
    // The transfer is over; stop watching its size.
    drop(oversize);
    if !completed {
        // In Notify and Intercept modes the stream carries no events.
        // iroh-blobs holds its sender until the push handler returns, after
        // the data is written (or the transfer fails), so the stream closes
        // when the transfer ends, never at the notification.
        info!(%hash, "Push transfer ended, checking store");
    }

    // At most `max_concurrent_ingests` blobs are exported, validated and
    // uploaded at once; each holds a scratch copy on disk meanwhile.
    let Ok(_permit) = ingester.permits.acquire().await else {
        return false;
    };
    let config = &ingester.config;

    // The transfer is over. Retry briefly for FsStore's async DB
    // propagation; an aborted transfer leaves the blob incomplete.
    for attempt in 0..10 {
        let result = ingest::validate_from_store(
            hash,
            &ingester.store,
            &config.validation,
            &ingester.scratch_dir,
        )
        .await;
        match result {
            Ok(Some(validated)) => {
                // Servable from here on, whatever the upload does.
                pending.validated();
                return match ingest::upload(validated, &config.catalog, &ingester.s3_client).await {
                    Ok(result) => {
                        info!(
                            hash = %result.hash_hex,
                            size = result.size,
                            "Blob ingested successfully"
                        );
                        true
                    }
                    Err(e) => {
                        error!(%hash, error = %e, "Ingest failed");
                        false
                    }
                };
            }
            Ok(None) => {
                debug!(%hash, attempt, "Blob not yet readable, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(IngestError::Refused(e)) => {
                warn!(%hash, error = format!("{e:#}"), "Ingest refused the blob");
                return false;
            }
            Err(IngestError::Failed(e)) => {
                error!(%hash, error = format!("{e:#}"), "Ingest failed");
                return false;
            }
        }
    }
    error!(%hash, "Blob incomplete after the push ended");
    false
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

    /// Close connection `id`, if it is still open, with application error
    /// code 1 and `reason`.
    fn close(&self, id: u64, reason: &[u8]) {
        if let Some(conn) = self.lock().get(&id) {
            conn.close(VarInt::from_u32(1), reason);
        }
    }
}

/// The blobs protocol, keeping each open connection in [`Connections`] so
/// the ingest loop can close the one carrying an oversize push.
#[derive(Debug, Clone)]
struct TrackedBlobs {
    inner: BlobsProtocol,
    connections: Arc<Connections>,
}

impl ProtocolHandler for TrackedBlobs {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let id = conn.stable_id() as u64;
        self.connections.lock().insert(id, conn.clone());
        let result = self.inner.accept(conn).await;
        self.connections.lock().remove(&id);
        result
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await
    }
}
