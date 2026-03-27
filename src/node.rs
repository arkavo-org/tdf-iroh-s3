use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::provider::events::{EventMask, EventSender, ProviderMessage, RequestMode};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::BlobsProtocol;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::ingest::ingest_from_store;
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
    pub async fn spawn(config: Config) -> Result<Self> {
        let config = Arc::new(config);

        let s3_client = Arc::new(
            S3Client::new(&config.s3.bucket, &config.s3.region, &config.s3.prefix)
                .await
                .context("Failed to create S3 client")?,
        );

        let store = FsStore::load(&config.iroh.data_dir)
            .await
            .context("Failed to load FsStore")?;

        let endpoint = Endpoint::builder(presets::N0)
            .bind_addr((Ipv4Addr::UNSPECIFIED, config.iroh.bind_port))
            .context("Invalid bind address")?
            .bind()
            .await
            .context("Failed to bind Iroh endpoint")?;

        info!("Iroh endpoint bound on port {}", config.iroh.bind_port);
        endpoint.online().await;
        info!("Iroh endpoint online");

        let cancel = CancellationToken::new();

        // Create event sender with push notifications enabled
        let mask = EventMask {
            push: RequestMode::Notify,
            ..EventMask::DEFAULT
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
                run_ingest_loop(event_rx, store, s3_client, config, cancel).await;
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
                match msg {
                    Some(ProviderMessage::PushRequestReceivedNotify(msg)) => {
                        let hash = msg.inner.request.hash;
                        let store = store.clone();
                        let s3_client = Arc::clone(&s3_client);
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            ingest_pushed_blob(hash, &store, &s3_client, &config).await;
                        });
                    }
                    Some(_) => {} // Ignore other message types
                    None => {
                        info!("Event channel closed, ingest loop exiting");
                        break;
                    }
                }
            }
        }
    }
}

async fn ingest_pushed_blob(
    hash: iroh_blobs::Hash,
    store: &FsStore,
    s3_client: &S3Client,
    config: &Config,
) {
    info!(hash = %hash, "Push received, starting ingest");

    const MAX_ATTEMPTS: u32 = 300;
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

    for attempt in 0..MAX_ATTEMPTS {
        match ingest_from_store(hash, store, &config.validation, s3_client).await {
            Ok(Some(result)) => {
                info!(
                    hash = %result.hash_hex,
                    size = result.size,
                    attempts = attempt + 1,
                    "Blob ingested successfully"
                );
                return;
            }
            Ok(None) => {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Err(e) => {
                error!(hash = %hash, error = %e, "Ingest failed");
                return;
            }
        }
    }

    warn!(hash = %hash, "Ingest timed out waiting for blob to complete");
}
