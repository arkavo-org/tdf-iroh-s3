use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::BlobsProtocol;
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate,
};
use iroh_blobs::store::fs::FsStore;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::ingest::ingest_from_store;
use crate::moderation::{BlobOwner, PublishGate, now_secs};
use crate::secret_key;
use crate::store::s3::S3Client;

pub struct TdfIrohNode {
    router: Router,
    store: FsStore,
    endpoint: Endpoint,
    pub s3_client: Arc<S3Client>,
    pub config: Arc<Config>,
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
            S3Client::new(&config.s3.bucket, &config.s3.region, &config.s3.prefix)
                .await
                .context("Failed to create S3 client")?,
        );

        let store = FsStore::load(&config.iroh.data_dir)
            .await
            .context("Failed to load FsStore")?;

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

        // iroh-blobs 0.103's EventSender::request() reads only `mask.get`, for
        // every request type (get, get_many, push, observe). With a gate,
        // Intercept lets the loop refuse a request; its update stream then
        // just closes when the transfer ends, which `wait_and_ingest`
        // handles. (InterceptLog would reset any request whose update
        // stream the loop stopped reading.) `connected: Intercept` reports
        // each connection's authenticated endpoint ID: the pusher.
        let mask = if gate.is_some() {
            EventMask {
                connected: ConnectMode::Intercept,
                get: RequestMode::Intercept,
                ..EventMask::DEFAULT
            }
        } else {
            EventMask {
                get: RequestMode::Notify,
                ..EventMask::DEFAULT
            }
        };
        let (event_sender, event_rx) = EventSender::channel(64, mask);

        let blobs = BlobsProtocol::new(&store, Some(event_sender));

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();

        let addr = endpoint.addr();
        info!("Node ID: {}", addr.id);

        // Spawn the ingest background task
        {
            let store = store.clone();
            let s3_client = Arc::clone(&s3_client);
            let config = Arc::clone(&config);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                run_ingest_loop(event_rx, store, s3_client, config, gate, cancel).await;
            });
        }

        Ok(Self {
            router,
            store,
            endpoint,
            s3_client,
            config,
            cancel,
        })
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub fn store(&self) -> &FsStore {
        &self.store
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

async fn run_ingest_loop(
    mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    store: FsStore,
    s3_client: Arc<S3Client>,
    config: Arc<Config>,
    gate: Option<Arc<PublishGate>>,
    cancel: CancellationToken,
) {
    info!("Ingest loop started");
    let blocked = |hash: &iroh_blobs::Hash| {
        gate.as_ref()
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
                match msg {
                    Some(ProviderMessage::PushRequestReceivedNotify(msg)) => {
                        let hash = msg.inner.request.hash;
                        info!(%hash, "Push request received (notify)");
                        let store = store.clone();
                        let s3_client = Arc::clone(&s3_client);
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            wait_and_ingest(hash, msg.rx, &store, &s3_client, &config).await;
                        });
                    }
                    Some(ProviderMessage::PushRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
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
                        msg.tx.send(Ok(())).await.ok();
                        let store = store.clone();
                        let s3_client = Arc::clone(&s3_client);
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            if wait_and_ingest(hash, msg.rx, &store, &s3_client, &config).await
                                && let Some((subject, endpoint)) = owner
                            {
                                record_owner(&s3_client, hash, subject, endpoint).await;
                            }
                        });
                    }
                    Some(ProviderMessage::GetRequestReceivedNotify(_)) => {
                        debug!("Get request received (notify)");
                    }
                    Some(ProviderMessage::GetRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
                        if blocked(&hash) {
                            info!(%hash, "Fetch of blocked content refused");
                            msg.tx.send(Err(AbortReason::Permission)).await.ok();
                        } else {
                            msg.tx.send(Ok(())).await.ok();
                        }
                    }
                    Some(ProviderMessage::GetManyRequestReceived(msg)) => {
                        if msg.inner.request.hashes.iter().any(&blocked) {
                            info!("Fetch of blocked content refused (get_many)");
                            msg.tx.send(Err(AbortReason::Permission)).await.ok();
                        } else {
                            msg.tx.send(Ok(())).await.ok();
                        }
                    }
                    Some(ProviderMessage::ObserveRequestReceived(msg)) => {
                        let result = if blocked(&msg.inner.request.hash) {
                            Err(AbortReason::Permission)
                        } else {
                            Ok(())
                        };
                        msg.tx.send(result).await.ok();
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
                    Some(other) => {
                        debug!("Other event received: {:?}", std::mem::discriminant(&other));
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
async fn wait_and_ingest(
    hash: iroh_blobs::Hash,
    mut rx: irpc::channel::mpsc::Receiver<RequestUpdate>,
    store: &FsStore,
    s3_client: &S3Client,
    config: &Config,
) -> bool {
    // Wait for the push transfer to complete
    let mut completed = false;
    while let Ok(Some(update)) = rx.recv().await {
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
    if !completed {
        // Notify mode doesn't provide RequestUpdate events — the stream closes
        // immediately. The blob should already be in the store by this point.
        info!(%hash, "Push notification received, checking store");
    }

    // Blob is written — ingest with small retry for FsStore async DB propagation
    for attempt in 0..10 {
        match ingest_from_store(hash, store, &config.validation, &config.catalog, s3_client).await {
            Ok(Some(result)) => {
                info!(
                    hash = %result.hash_hex,
                    size = result.size,
                    "Blob ingested successfully"
                );
                return true;
            }
            Ok(None) => {
                debug!(%hash, attempt, "Blob not yet readable, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                error!(%hash, error = %e, "Ingest failed");
                return false;
            }
        }
    }
    error!(%hash, "Blob not readable after transfer completed");
    false
}
