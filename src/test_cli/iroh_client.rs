use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_base::TransportAddr;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::api::blobs::Bitfield;
use iroh_blobs::protocol::{GetManyRequest, GetRequest, ObserveRequest, PushRequest};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::{Hash, HashAndFormat};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
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

/// Load the Ed25519 secret key stored as 64 hex characters in `path`,
/// generating and saving a new one (mode 0600) when the file does not
/// exist. The same file gives `publish-session` and a later push the same
/// endpoint ID, which a publish session requires.
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let bytes: [u8; 32] = hex::decode(text.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .with_context(|| format!("{} must hold a 32-byte key as hex", path.display()))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options
                .open(path)
                .with_context(|| format!("Failed to create {}", path.display()))?;
            std::io::Write::write_all(&mut file, hex::encode(key.to_bytes()).as_bytes())
                .with_context(|| format!("Failed to write {}", path.display()))?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

impl IrohTestClient {
    /// Create a new Iroh test client with a memory store and endpoint bound on a random port.
    pub async fn new() -> Result<Self> {
        Self::with_secret_key(None).await
    }

    /// Like [`Self::new`], with a fixed endpoint key (a random one when
    /// `None`). A push to a gated node must come from the endpoint a publish
    /// session names.
    pub async fn with_secret_key(secret_key: Option<SecretKey>) -> Result<Self> {
        let store = MemStore::new();
        let mut builder = Endpoint::builder(presets::N0);
        if let Some(key) = secret_key {
            builder = builder.secret_key(key);
        }
        let endpoint = builder
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

    /// This client's endpoint ID, which a publish session names.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
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

    /// Start pushing `data` and abandon the push after `run_for`, closing
    /// the connection mid-transfer: a push that ends early, for tests.
    pub async fn push_to_node_abandoned(
        &self,
        addr: impl Into<EndpointAddr>,
        data: &[u8],
        run_for: std::time::Duration,
    ) -> Result<Hash> {
        let hash = self.add_bytes(data).await?;
        let conn = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .context("Failed to connect to remote node")?;
        let request = PushRequest::from(GetRequest::blob(hash));
        let push = self.store.remote().execute_push(conn.clone(), request);
        let _ = tokio::time::timeout(run_for, push).await;
        conn.close(0u32.into(), b"abandoned");
        Ok(hash)
    }

    /// Fetch a blob from a remote node by hash. A blob already complete in
    /// this client's store is returned without asking the node, so a client
    /// that pushed a blob cannot use this to check the node has it.
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

    /// Fetch blobs from a remote node with one get-many request, returning
    /// them in the order of `hashes`. Unlike [`Self::fetch_from_node`], this
    /// asks the node even for blobs this client already holds.
    pub async fn get_many_from_node(
        &self,
        addr: impl Into<EndpointAddr>,
        hashes: &[Hash],
    ) -> Result<Vec<bytes::Bytes>> {
        let conn = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .context("Failed to connect to remote node")?;
        self.store
            .remote()
            .execute_get_many(conn, GetManyRequest::from_iter(hashes.iter().copied()))
            .complete()
            .await
            .context("Failed to get blobs from remote node")?;
        let mut blobs = Vec::with_capacity(hashes.len());
        for hash in hashes {
            blobs.push(
                self.store
                    .get_bytes(*hash)
                    .await
                    .context("Failed to read fetched blob from local store")?,
            );
        }
        Ok(blobs)
    }

    /// The remote node's first answer to an observe request: which ranges of
    /// the blob it holds. Observing a hash the node does not hold can create an
    /// empty entry for it there.
    pub async fn observe_on_node(
        &self,
        addr: impl Into<EndpointAddr>,
        hash: Hash,
    ) -> Result<Bitfield> {
        use futures::StreamExt;

        let conn = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .context("Failed to connect to remote node")?;
        let updates = self.store.remote().observe(conn, ObserveRequest::new(hash));
        let mut updates = std::pin::pin!(updates);
        updates
            .next()
            .await
            .context("Observe stream ended without an answer")?
            .context("Failed to observe blob on remote node")
    }

    /// Shut down the client endpoint.
    pub async fn shutdown(self) -> Result<()> {
        self.endpoint.close().await;
        Ok(())
    }
}
