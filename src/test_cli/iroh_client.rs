use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_base::TransportAddr;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::protocol::{GetRequest, PushRequest};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::{Hash, HashAndFormat};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

/// Parse an endpoint ID string into an `EndpointId`.
pub fn parse_endpoint_id(s: &str) -> Result<EndpointId> {
    EndpointId::from_str(s).context("Invalid endpoint ID")
}

/// Build an `EndpointAddr` from a node ID and optional direct address.
pub fn build_endpoint_addr(node_id: EndpointId, addr: Option<SocketAddr>) -> EndpointAddr {
    let mut addrs = BTreeSet::new();
    if let Some(addr) = addr {
        addrs.insert(TransportAddr::Ip(addr));
    }
    EndpointAddr { id: node_id, addrs }
}

/// An Iroh test client that can connect to remote nodes, push blobs, and fetch blobs.
pub struct IrohTestClient {
    endpoint: Endpoint,
    store: MemStore,
}

impl IrohTestClient {
    /// Create a new Iroh test client with a memory store and endpoint bound on a random port.
    pub async fn new() -> Result<Self> {
        let store = MemStore::new();
        let endpoint = Endpoint::builder(presets::N0)
            .bind_addr((Ipv4Addr::UNSPECIFIED, 0u16))
            .context("Invalid bind address")?
            .bind()
            .await
            .context("Failed to bind client endpoint")?;
        endpoint.online().await;
        // Create the blobs protocol handler (needed for store operations)
        let _blobs = BlobsProtocol::new(&store, None);
        Ok(Self { endpoint, store })
    }

    /// Add bytes to the local store and return the hash.
    pub async fn add_bytes(&self, data: &[u8]) -> Result<Hash> {
        let tag_info = self
            .store
            .add_slice(data)
            .await
            .context("Failed to add bytes to store")?;
        Ok(tag_info.hash)
    }

    /// Push a blob to a remote node. Adds the data to the local store first,
    /// then sends it to the remote node using the iroh-blobs push protocol.
    pub async fn push_to_node(&self, addr: impl Into<EndpointAddr>, data: &[u8]) -> Result<Hash> {
        // Add blob to local store
        let hash = self.add_bytes(data).await?;

        // Connect to remote node using the blobs ALPN
        let conn = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .context("Failed to connect to remote node")?;

        // Keep a handle to prevent the connection from closing before the
        // server has processed the push. execute_push takes ownership of its
        // Connection, but Connection is Clone — the underlying QUIC connection
        // stays open as long as any handle exists.
        let _conn_guard = conn.clone();

        // Create a push request for the entire blob
        let request = PushRequest::from(GetRequest::blob(hash));

        // Execute the push using the remote API
        let _stats = self
            .store
            .remote()
            .execute_push(conn, request)
            .await
            .context("Failed to push blob to remote node")?;

        // Give the server time to process the push before dropping the connection
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        Ok(hash)
    }

    /// Fetch a blob from a remote node by hash.
    pub async fn fetch_from_node(
        &self,
        addr: impl Into<EndpointAddr>,
        hash: Hash,
    ) -> Result<bytes::Bytes> {
        // Connect to remote node using the blobs ALPN
        let conn = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .context("Failed to connect to remote node")?;

        // Fetch the blob using the remote API (this stores it locally too)
        let content = HashAndFormat::raw(hash);
        let _stats = self
            .store
            .remote()
            .fetch(conn, content)
            .await
            .context("Failed to fetch blob from remote node")?;

        // Read the fetched data from the local store
        let data = self
            .store
            .get_bytes(hash)
            .await
            .context("Failed to read fetched blob from local store")?;

        Ok(data)
    }

    /// Shut down the client endpoint.
    pub async fn shutdown(self) -> Result<()> {
        self.endpoint.close().await;
        Ok(())
    }
}
