use anyhow::{Context, Result};
use iroh::endpoint::{presets, Connection};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::provider::events::{
    EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate,
};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::BlobsProtocol;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::auth::{CoseKeyCache, Verifier};
use crate::catalog::store::EventStore;
use crate::config::Config;
use crate::ingest::ingest_from_store;
use crate::pdp::cache::AccessPdpCache;
use crate::protocol::catalog_read::{
    self, CatalogReadDeps, SubscriptionLimits,
};
use crate::secret_key;
use crate::store::s3::S3Client;

pub struct TdfIrohNode {
    router: Router,
    store: FsStore,
    endpoint: Endpoint,
    pub s3_client: Arc<S3Client>,
    pub config: Arc<Config>,
    pub catalog: Arc<EventStore>,
    pub verifier: Arc<Verifier>,
    pub pdp: Arc<AccessPdpCache>,
    cancel: CancellationToken,
}

impl TdfIrohNode {
    pub async fn spawn(config: Config) -> Result<Self> {
        // Fail-closed: required auth/PDP URLs must be present before we bind
        // anything externally observable.
        config
            .validate()
            .context("invalid node configuration")?;

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

        // NotifyLog on `get` enables event delivery for ALL request types (get, push, etc.)
        // and provides a RequestUpdate stream to track transfer completion.
        // Note: EventSender::request() checks only mask.get, not mask.push.
        let mask = EventMask {
            get: RequestMode::Notify,
            ..EventMask::DEFAULT
        };
        let (event_sender, event_rx) = EventSender::channel(64, mask);

        let blobs = BlobsProtocol::new(&store, Some(event_sender));

        // Local redb-backed event log. Single-author (this node).
        let catalog_path =
            std::path::PathBuf::from(&config.catalog.data_dir).join("events.redb");
        let catalog = Arc::new(
            EventStore::open(&catalog_path)
                .await
                .context("Failed to open EventStore")?,
        );
        info!(path = %catalog_path.display(), "EventStore ready");

        // Shared HTTP client for COSE keyset + PDP attribute-defs fetches.
        let http_client = reqwest::Client::builder()
            .build()
            .context("Failed to build reqwest client")?;

        // AccessPdp cache — fail-closed on the boot fetch.
        let pdp = AccessPdpCache::spawn(
            config.pdp.attribute_defs_url.clone(),
            Duration::from_secs(config.pdp.refresh_interval_secs),
            http_client.clone(),
        )
        .await
        .context("Failed to spawn PDP cache")?;

        // CWT verifier (COSE keys fetched from config-supplied endpoint).
        let keys = CoseKeyCache::spawn(
            config.auth.cose_keys_url.clone(),
            Duration::from_secs(config.auth.refresh_interval_secs),
            http_client,
        )
        .await
        .context("Failed to spawn COSE key cache")?;
        let verifier = Arc::new(Verifier::new(
            keys,
            config.auth.issuer.clone(),
            config.auth.clock_skew_secs,
        ));

        // Reader-side subscription concurrency caps.
        let limits = SubscriptionLimits::new(
            config.catalog.max_subscriptions_per_peer,
            config.catalog.max_subscriptions_total,
        );

        let catalog_proto = CatalogReadProtocol {
            verifier: Arc::clone(&verifier),
            store: Arc::clone(&catalog),
            pdp: Arc::clone(&pdp),
            limits,
            cancel: cancel.clone(),
        };

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .accept(catalog_read::ALPN, catalog_proto)
            .spawn();

        let addr = endpoint.addr();
        info!("Node ID: {}", addr.id);

        // Spawn the ingest background task
        {
            let store = store.clone();
            let s3_client = Arc::clone(&s3_client);
            let config = Arc::clone(&config);
            let catalog = Arc::clone(&catalog);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                run_ingest_loop(event_rx, store, s3_client, config, catalog, cancel).await;
            });
        }

        Ok(Self {
            router,
            store,
            endpoint,
            s3_client,
            config,
            catalog,
            verifier,
            pdp,
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

/// `ProtocolHandler` adapter for `tdf/catalog/1`. Each incoming QUIC
/// connection at this ALPN gets a single bidi stream handled by
/// [`catalog_read::handle`].
#[derive(Clone)]
struct CatalogReadProtocol {
    verifier: Arc<Verifier>,
    store: Arc<EventStore>,
    pdp: Arc<AccessPdpCache>,
    limits: Arc<SubscriptionLimits>,
    cancel: CancellationToken,
}

impl std::fmt::Debug for CatalogReadProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogReadProtocol").finish_non_exhaustive()
    }
}

impl ProtocolHandler for CatalogReadProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // Hex-lowercase EndpointId — matches the format CWT `cnf.iroh_node_id`
        // is expected to carry (verifier hex-decodes this string).
        let peer = connection.remote_id().to_string();

        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;

        let deps = CatalogReadDeps {
            verifier: Arc::clone(&self.verifier),
            store: Arc::clone(&self.store),
            pdp: Arc::clone(&self.pdp),
            limits: Arc::clone(&self.limits),
            cancel: self.cancel.clone(),
        };

        if let Err(e) = catalog_read::handle(recv, send, peer, deps).await {
            warn!(err = %e, "catalog_read::handle returned error");
        }
        Ok(())
    }
}

async fn run_ingest_loop(
    mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    store: FsStore,
    s3_client: Arc<S3Client>,
    config: Arc<Config>,
    catalog: Arc<EventStore>,
    cancel: CancellationToken,
) {
    info!("Ingest loop started");
    // `catalog` is threaded through so Task 17 can append on successful ingest
    // without changing this signature again. Currently unused.
    let _ = &catalog;
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
                        let catalog = Arc::clone(&catalog);
                        tokio::spawn(async move {
                            wait_and_ingest(hash, msg.rx, &store, &s3_client, &config, &catalog).await;
                        });
                    }
                    Some(ProviderMessage::PushRequestReceived(msg)) => {
                        let hash = msg.inner.request.hash;
                        info!(%hash, "Push request received (intercept)");
                        msg.tx.send(Ok(())).await.ok();
                        let store = store.clone();
                        let s3_client = Arc::clone(&s3_client);
                        let config = Arc::clone(&config);
                        let catalog = Arc::clone(&catalog);
                        tokio::spawn(async move {
                            wait_and_ingest(hash, msg.rx, &store, &s3_client, &config, &catalog).await;
                        });
                    }
                    Some(ProviderMessage::GetRequestReceivedNotify(_)) => {
                        debug!("Get request received (notify)");
                    }
                    Some(ProviderMessage::GetRequestReceived(msg)) => {
                        debug!("Get request received (intercept)");
                        msg.tx.send(Ok(())).await.ok();
                    }
                    Some(ProviderMessage::ClientConnected(msg)) => {
                        debug!("Client connected, accepting");
                        msg.tx.send(Ok(())).await.ok();
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

async fn wait_and_ingest(
    hash: iroh_blobs::Hash,
    mut rx: irpc::channel::mpsc::Receiver<RequestUpdate>,
    store: &FsStore,
    s3_client: &S3Client,
    config: &Config,
    catalog: &EventStore,
) {
    let _ = catalog; // Task 17 will append a ContentEvent on successful ingest.
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
                return;
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
        match ingest_from_store(hash, store, &config.validation, s3_client).await {
            Ok(Some(result)) => {
                info!(
                    hash = %result.hash_hex,
                    size = result.size,
                    "Blob ingested successfully"
                );
                return;
            }
            Ok(None) => {
                debug!(%hash, attempt, "Blob not yet readable, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                error!(%hash, error = %e, "Ingest failed");
                return;
            }
        }
    }
    error!(%hash, "Blob not readable after transfer completed");
}
