use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::BlobsProtocol;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::store::s3::S3Client;

pub struct TdfIrohNode {
    router: Router,
    store: MemStore,
    endpoint: Endpoint,
    pub s3_client: Arc<S3Client>,
    pub config: Arc<Config>,
}

impl TdfIrohNode {
    pub async fn spawn(config: Config) -> Result<Self> {
        let s3_client = Arc::new(
            S3Client::new(&config.s3.bucket, &config.s3.region, &config.s3.prefix)
                .await
                .context("Failed to create S3 client")?,
        );

        let store = MemStore::new();

        let endpoint = Endpoint::builder(presets::N0)
            .bind_addr((Ipv4Addr::UNSPECIFIED, config.iroh.bind_port))
            .context("Invalid bind address")?
            .bind()
            .await
            .context("Failed to bind Iroh endpoint")?;

        info!("Iroh endpoint bound on port {}", config.iroh.bind_port);
        endpoint.online().await;
        info!("Iroh endpoint online");

        let blobs = BlobsProtocol::new(&store, None);

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();

        let addr = endpoint.addr();
        info!("Node ID: {}", addr.id);

        Ok(Self {
            router,
            store,
            endpoint,
            s3_client,
            config: Arc::new(config),
        })
    }

    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub fn store(&self) -> &MemStore {
        &self.store
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .context("Failed to shutdown router")?;
        Ok(())
    }
}
