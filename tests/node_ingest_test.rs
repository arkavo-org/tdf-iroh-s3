//! Integration tests: push blobs to a running node over iroh and check what
//! it stores, ingests and serves.
//!
//! S3 is a loopback fake that records the keys the node writes. Ingest
//! uploads `blobs/<hash>` only after the blob validates as a TDF, so that key
//! shows a push reached ingest.
//!
//! A check that the node holds a blob fetches it with a client that did not
//! push it: `fetch_from_node` returns a blob the client already holds
//! without asking the node.

use axum::body::Bytes;
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use iroh_blobs::Hash;
use iroh_blobs::api::blobs::BlobStatus;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tdf_iroh_s3::config::{
    CatalogConfig, Config, HttpConfig, IrohConfig, PublishingConfig, S3Config, ValidationConfig,
};
use tdf_iroh_s3::moderation::{Moderation, PublishGate};
use tdf_iroh_s3::node::TdfIrohNode;
use tdf_iroh_s3::test_cli::iroh_client::IrohTestClient;

const BUCKET: &str = "test-bucket";
const INGEST_TIMEOUT: Duration = Duration::from_secs(10);

fn test_config(data_dir: &str) -> Config {
    Config {
        iroh: IrohConfig {
            bind_port: 0, // Random port
            secret_key_param: String::new(),
            data_dir: data_dir.to_string(),
            public_addresses: Vec::new(),
            gc_interval_secs: 1,
        },
        s3: S3Config {
            bucket: BUCKET.to_string(),
            region: "us-east-1".to_string(),
            prefix: String::new(),
            endpoint_url: String::new(),
            force_path_style: false,
        },
        validation: ValidationConfig::default(),
        http: HttpConfig::default(),
        catalog: CatalogConfig::default(),
        publishing: PublishingConfig::default(),
    }
}

/// Dummy credentials, so the AWS SDK neither fails nor queries IMDS.
fn set_dummy_aws_credentials() {
    // SAFETY: current_thread runtime ensures no other threads read env vars concurrently.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
}

/// A loopback stand-in for S3. HEAD answers 404, so every blob is new,
/// except for keys in `present`. PUT succeeds and records its key.
#[derive(Clone, Default)]
struct FakeS3 {
    puts: Arc<Mutex<Vec<String>>>,
    /// Keys HEAD finds, with their sizes: blobs ingested before the test.
    present: Arc<Mutex<std::collections::HashMap<String, u64>>>,
}

impl FakeS3 {
    /// Serve on a random loopback port and return the endpoint URL.
    async fn start() -> (Self, String) {
        let s3 = Self::default();
        let puts = Arc::clone(&s3.puts);
        let present = Arc::clone(&s3.present);
        let app = axum::Router::new()
            .fallback(move |method: Method, uri: Uri, _body: Bytes| {
                let puts = Arc::clone(&puts);
                let present = Arc::clone(&present);
                async move {
                    let path = uri.path();
                    let key = path.strip_prefix(&format!("/{BUCKET}/")).unwrap_or(path);
                    if method == Method::PUT {
                        puts.lock().unwrap().push(key.to_string());
                        (StatusCode::OK, [("etag", "\"fake\"")]).into_response()
                    } else if method == Method::HEAD
                        && let Some(size) = present.lock().unwrap().get(key)
                    {
                        (StatusCode::OK, [("content-length", size.to_string())]).into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
            })
            // Blobs can be larger than axum's default 2 MB body limit.
            .layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        (s3, url)
    }

    /// Answer HEAD of `blobs/<hash>` as an ingested blob of `size` bytes.
    fn ingested(&self, hash: Hash, size: u64) {
        self.present.lock().unwrap().insert(blob_key(hash), size);
    }

    fn has_put(&self, key: &str) -> bool {
        self.puts.lock().unwrap().iter().any(|k| k == key)
    }

    /// Whether `key` is written within [`INGEST_TIMEOUT`].
    async fn wait_for_put(&self, key: &str) -> bool {
        let deadline = tokio::time::Instant::now() + INGEST_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if self.has_put(key) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.has_put(key)
    }
}

/// A node writing to a fresh [`FakeS3`], gated when `gate` is given.
async fn spawn_node(gate: Option<Arc<PublishGate>>) -> (TdfIrohNode, FakeS3, tempfile::TempDir) {
    spawn_node_with(gate, |_| {}).await
}

/// [`spawn_node`], with `edit` applied to the configuration.
async fn spawn_node_with(
    gate: Option<Arc<PublishGate>>,
    edit: impl FnOnce(&mut Config),
) -> (TdfIrohNode, FakeS3, tempfile::TempDir) {
    let (s3, endpoint_url) = FakeS3::start().await;
    spawn_node_on(tempfile::tempdir().unwrap(), s3, endpoint_url, gate, edit).await
}

/// A node on `data_dir`, which may hold a store already, writing to `s3`.
async fn spawn_node_on(
    data_dir: tempfile::TempDir,
    s3: FakeS3,
    endpoint_url: String,
    gate: Option<Arc<PublishGate>>,
    edit: impl FnOnce(&mut Config),
) -> (TdfIrohNode, FakeS3, tempfile::TempDir) {
    set_dummy_aws_credentials();
    let mut config = test_config(data_dir.path().to_str().unwrap());
    edit(&mut config);
    config.s3.endpoint_url = endpoint_url;
    config.s3.force_path_style = true;
    let node = TdfIrohNode::spawn_with_gate(config, gate).await.unwrap();
    (node, s3, data_dir)
}

fn blob_key(hash: Hash) -> String {
    format!("blobs/{}", hash.to_hex())
}

/// A refused push leaves nothing behind: the node's store does not have
/// the blob, the node serves nothing for it, and ingest never uploads it.
async fn assert_push_not_taken(node: &TdfIrohNode, s3: &FakeS3, hash: Hash) {
    // push_to_node waited 500 ms after the transfer, time enough for a
    // wrongly accepted push to land.
    let status = node.store().status(hash).await.unwrap();
    assert!(
        matches!(status, BlobStatus::NotFound),
        "a refused push must not be stored, status: {status:?}"
    );
    let probe = IrohTestClient::new().await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            probe.fetch_from_node(node.addr().id, hash)
        )
        .await
        .is_ok_and(|r| r.is_err()),
        "a refused push must not be served"
    );
    probe.shutdown().await.unwrap();
    assert!(
        !s3.has_put(&blob_key(hash)),
        "a refused push must not be ingested"
    );
}

/// iroh-blobs resets a request the event handler refused with
/// ERR_PERMISSION (1). A request the handler left unanswered would be reset
/// with ERR_INTERNAL (3).
fn assert_refused_for_permission<T: std::fmt::Debug>(result: anyhow::Result<T>, request: &str) {
    let error = format!("{:#}", result.expect_err(request));
    assert!(
        error.contains("reset by peer: error 1"),
        "{request}: expected a permission refusal, got: {error}"
    );
}

/// Without a gate, a push is accepted, ingested and served. Ingest runs only
/// because the mask enables push events.
#[tokio::test(flavor = "current_thread")]
async fn test_ungated_push_is_ingested_and_served() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;

    let tdf = create_test_tdf();
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(
        s3.wait_for_put(&blob_key(hash)).await,
        "an ungated push must be ingested"
    );
    assert!(s3.has_put(&format!("manifests/{}", hash.to_hex())));

    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert_eq!(fetched.as_ref(), tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A blob that is not a TDF is refused: never served, not ingested, and
/// deleted from the node's store by the garbage collector, which keeps the
/// blobs that validated.
#[tokio::test(flavor = "current_thread")]
async fn test_a_refused_blob_is_withheld_and_deleted() {
    // The collector first runs 4 s after start, after the refusal below.
    let (node, s3, _data_dir) = spawn_node_with(None, |c| c.iroh.gc_interval_secs = 4).await;
    let node_id = node.addr().id;

    let pusher = IrohTestClient::new().await.unwrap();
    let tdf = create_test_tdf();
    let kept = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(kept)).await);

    // Larger than the store inlines (16 KiB), so it is a file on disk.
    let garbage = vec![0xDEu8; 64 * 1024];
    let refused = pusher.push_to_node(node_id, &garbage).await.unwrap();

    // Refused while still in the store...
    let deadline = tokio::time::Instant::now() + INGEST_TIMEOUT;
    while !node.quarantine().is_refused(&refused) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the blob is refused"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // (The store commits its database in batches; reads trail writes until
    // a sync.)
    node.store().sync_db().await.unwrap();
    let bitfield = node.store().observe(refused).await.unwrap();
    assert!(
        bitfield.is_complete(),
        "the refused blob was stored: {bitfield:?}"
    );
    // Not served to a client that did not push it while it waits.
    let viewer = IrohTestClient::new().await.unwrap();
    assert_refused_for_permission(viewer.fetch_from_node(node_id, refused).await, "get");
    assert!(!s3.has_put(&blob_key(refused)));

    // ...then deleted by the collector, whose next run forgets it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let bitfield = node.store().observe(refused).await.unwrap();
        if bitfield.size() == 0 && !node.quarantine().is_refused(&refused) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refused blob is deleted, bitfield: {bitfield:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(matches!(
        node.store().status(refused).await.unwrap(),
        BlobStatus::NotFound
    ));
    let viewer = IrohTestClient::new().await.unwrap();
    assert!(
        viewer.fetch_from_node(node_id, refused).await.is_err(),
        "a deleted blob is not served"
    );

    // The collector kept the TDF, which is still served.
    assert!(matches!(
        node.store().status(kept).await.unwrap(),
        BlobStatus::Complete { .. }
    ));
    let fetched = viewer.fetch_from_node(node_id, kept).await.unwrap();
    assert_eq!(fetched.as_ref(), tdf.as_slice());

    // The ingest loop survives the refusal: the next TDF is ingested.
    let next = create_test_tdf();
    let hash = pusher.push_to_node(node_id, &next).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A gated node (tdf-iroh-s3#17) takes a push only from an endpoint with a
/// publish session whose subject is not suspended.
#[tokio::test(flavor = "current_thread")]
async fn test_gated_push_needs_a_session() {
    let gate = Arc::new(PublishGate::new(Arc::new(Moderation::default())));
    let (node, s3, _data_dir) = spawn_node(Some(Arc::clone(&gate))).await;
    let node_id = node.addr().id;

    // No session: the push is refused and nothing is stored. (The pusher
    // may not see the refusal; the node simply never takes the blob.)
    let stranger = IrohTestClient::new().await.unwrap();
    let refused = create_test_tdf();
    let _ = stranger.push_to_node(node_id, &refused).await;
    assert_push_not_taken(&node, &s3, Hash::new(&refused)).await;

    // A session for this endpoint: the push is ingested, its publisher is
    // recorded, and it is served.
    let creator = IrohTestClient::new().await.unwrap();
    gate.open_session(
        creator.endpoint_id(),
        "arkavo:creator-1",
        Duration::from_secs(60),
    );
    let accepted = create_test_tdf();
    let hash = creator
        .push_to_node(node_id, &accepted)
        .await
        .map_err(|e| format!("{e:#}"))
        .unwrap();
    assert!(
        s3.wait_for_put(&blob_key(hash)).await,
        "a push with a session must be ingested"
    );
    assert!(
        s3.wait_for_put(&format!("moderation/publishers/{}", hash.to_hex()))
            .await,
        "the publisher of an ingested push must be recorded"
    );
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert_eq!(fetched.as_ref(), accepted.as_slice());

    // A suspended subject: refused although the session is live.
    gate.moderation.suspend_for_test("arkavo:creator-1", false);
    let suspended = create_test_tdf();
    let _ = creator.push_to_node(node_id, &suspended).await;
    assert_push_not_taken(&node, &s3, Hash::new(&suspended)).await;

    for c in [stranger, creator, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A blocked hash is refused for get, get_many and observe, each with a
/// permission error, while another hash is still served for each.
#[tokio::test(flavor = "current_thread")]
async fn test_gated_node_refuses_blocked_hashes() {
    let gate = Arc::new(PublishGate::new(Arc::new(Moderation::default())));
    let (node, s3, _data_dir) = spawn_node(Some(Arc::clone(&gate))).await;
    let node_id = node.addr().id;

    let creator = IrohTestClient::new().await.unwrap();
    gate.open_session(
        creator.endpoint_id(),
        "arkavo:creator-1",
        Duration::from_secs(60),
    );
    // TDFs, so both validate and are served until one is blocked.
    let (blocked_bytes, open_bytes) = (create_test_tdf(), create_test_tdf());
    let blocked = creator.push_to_node(node_id, &blocked_bytes).await.unwrap();
    let open = creator.push_to_node(node_id, &open_bytes).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(blocked)).await);
    assert!(s3.wait_for_put(&blob_key(open)).await);

    // Served before the block.
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, blocked).await.unwrap();
    assert_eq!(fetched.as_ref(), blocked_bytes.as_slice());

    gate.moderation.block_for_test(&blocked.to_hex());

    // get
    let client = IrohTestClient::new().await.unwrap();
    let fetched = client.fetch_from_node(node_id, open).await.unwrap();
    assert_eq!(fetched.as_ref(), open_bytes.as_slice());
    assert_refused_for_permission(client.fetch_from_node(node_id, blocked).await, "get");

    // get_many: refused when any of its hashes is blocked.
    let client = IrohTestClient::new().await.unwrap();
    let fetched = client.get_many_from_node(node_id, &[open]).await.unwrap();
    assert_eq!(fetched, vec![Bytes::from(open_bytes.clone())]);
    assert_refused_for_permission(
        client.get_many_from_node(node_id, &[blocked]).await,
        "get_many",
    );
    assert_refused_for_permission(
        client.get_many_from_node(node_id, &[open, blocked]).await,
        "get_many with a blocked hash among others",
    );

    // observe
    let client = IrohTestClient::new().await.unwrap();
    let bitfield = client.observe_on_node(node_id, open).await.unwrap();
    assert!(bitfield.is_complete());
    assert_eq!(bitfield.size(), open_bytes.len() as u64);
    assert_refused_for_permission(client.observe_on_node(node_id, blocked).await, "observe");

    for c in [creator, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

fn create_test_tdf() -> Vec<u8> {
    use opentdf::prelude::*;

    let policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["test@example.com"])
        .attribute_fqn("https://example.com/attr/test/value/integration")
        .unwrap()
        .build()
        .unwrap();

    Tdf::encrypt(b"integration test payload")
        .kas_url("https://kas.example.com")
        .policy(policy)
        .to_bytes()
        .unwrap()
}

/// `GET /node` reports the running endpoint's ID and the configured public
/// addresses.
#[tokio::test(flavor = "current_thread")]
async fn test_node_route_reports_the_running_endpoint() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    set_dummy_aws_credentials();
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = test_config(tmp_dir.path().to_str().unwrap());
    config.iroh.public_addresses = vec!["203.0.113.7:11204".parse().unwrap()];
    let node = TdfIrohNode::spawn(config).await.unwrap();

    let app = tdf_iroh_s3::node_api::router(tdf_iroh_s3::node_api::live(
        node.endpoint().clone(),
        &node.config.iroh.public_addresses,
        node.config.validation.max_blob_bytes,
    ));
    let res = app
        .oneshot(
            axum::http::Request::get("/node")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let id = body["endpointId"].as_str().unwrap();
    assert_eq!(id, node.addr().id.to_string());
    assert_eq!(id.len(), 64);
    assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert!(body["relayUrl"].is_null() || body["relayUrl"].is_string());
    assert_eq!(
        body["directAddresses"],
        serde_json::json!(["203.0.113.7:11204"])
    );

    node.shutdown().await.unwrap();
}

/// A TDF of about `payload` bytes, larger than the store inlines.
fn create_large_test_tdf(payload: usize) -> Vec<u8> {
    use opentdf::prelude::*;
    let policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["test@example.com"])
        .build()
        .unwrap();
    Tdf::encrypt(vec![0x42u8; payload])
        .kas_url("https://kas.example.com")
        .policy(policy)
        .to_bytes()
        .unwrap()
}

/// Another endpoint pushing the hash of an ingested TDF and abandoning the
/// push mid-transfer neither withholds nor deletes it: the node keeps
/// serving it, through a collector run.
#[tokio::test(flavor = "current_thread")]
async fn test_an_abandoned_re_push_cannot_condemn_a_held_blob() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;

    let tdf = create_large_test_tdf(20 * 1024 * 1024);
    let owner = IrohTestClient::new().await.unwrap();
    let held = owner.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(held)).await);

    let attacker = IrohTestClient::new().await.unwrap();
    let pushed = attacker
        .push_to_node_abandoned(node_id, &tdf, Duration::from_millis(150))
        .await
        .unwrap();
    assert_eq!(pushed, held);

    // Served at once to a client that pushed nothing...
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, held).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());
    assert!(node.quarantine().is_validated(&held));

    // ...and after a collector run, which a refused blob forces.
    let garbage = vec![0xDEu8; 64 * 1024];
    let refused = owner.push_to_node(node_id, &garbage).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while node.quarantine().is_refused(&refused)
        || node.store().observe(refused).await.unwrap().size() != 0
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refused blob is deleted"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    node.store().sync_db().await.unwrap();
    assert!(node.store().observe(held).await.unwrap().is_complete());
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, held).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    for c in [owner, attacker, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A push larger than max_blob_bytes is stopped while it transfers: the
/// node closes its connection once the push's declared size is known, so it
/// never stores the whole blob, and refuses and deletes what arrived.
#[tokio::test(flavor = "current_thread")]
async fn test_an_oversize_push_is_stopped_mid_transfer() {
    let (node, s3, _data_dir) =
        spawn_node_with(None, |c| c.validation.max_blob_bytes = 1024 * 1024).await;
    let node_id = node.addr().id;

    let oversize = vec![0x5Au8; 50 * 1024 * 1024];
    let hash = Hash::new(&oversize);
    let pusher = IrohTestClient::new().await.unwrap();
    let result = pusher.push_to_node(node_id, &oversize).await;
    let error = format!("{:#}", result.expect_err("the node stops the push"));
    assert!(error.contains("max_blob_bytes"), "{error}");

    // Only the first part arrived, it is refused, and it is deleted.
    node.store().sync_db().await.unwrap();
    let bitfield = node.store().observe(hash).await.unwrap();
    assert!(!bitfield.is_complete(), "the whole blob never arrived");
    assert!(node.quarantine().is_refused(&hash));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while node.quarantine().is_refused(&hash)
        || node.store().observe(hash).await.unwrap().size() != 0
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the partial push is deleted"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!s3.has_put(&blob_key(hash)));

    // A push within the limit still goes through.
    let tdf = create_test_tdf();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    pusher.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// Only single-blob requests are taken. A hash-sequence push would import
/// child blobs no validation sees, and a hash-sequence get would serve
/// children without their own check, so both are refused.
#[tokio::test(flavor = "current_thread")]
async fn test_hash_sequence_requests_are_refused() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;

    // The pusher may see a refused push succeed (it finishes writing
    // before it reads the reset), so check what the node took.
    let child = vec![0xC4u8; 64 * 1024];
    let pusher = IrohTestClient::new().await.unwrap();
    let _ = pusher.push_hash_seq_to_node(node_id, &[&child]).await;
    let root = Hash::new(iroh_blobs::hashseq::HashSeq::from_iter([Hash::new(&child)]).into_inner());
    node.store().sync_db().await.unwrap();
    for hash in [root, Hash::new(&child)] {
        assert_push_not_taken(&node, &s3, hash).await;
    }

    // A served TDF is served as a blob, not as a hash sequence.
    let tdf = create_test_tdf();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);
    let viewer = IrohTestClient::new().await.unwrap();
    assert_refused_for_permission(
        viewer.get_hash_seq_from_node(node_id, hash).await,
        "hash-sequence get",
    );
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert_eq!(fetched.as_ref(), tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// Wait until `done`, failing with `what` after 20 s.
async fn wait_until<F: std::future::Future<Output = bool>>(
    what: &str,
    mut done: impl FnMut() -> F,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !done().await {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// After a restart, or on a store written by builds that did not validate
/// first, a stored blob is served only once it is known valid. One S3
/// holds is served at once. One S3 lacks is ingested again on its first
/// fetch: a good TDF whose upload failed is uploaded and served, and one
/// that never validated is refused and deleted.
#[tokio::test(flavor = "current_thread")]
async fn test_a_stored_blob_is_served_only_once_known_valid() {
    use iroh_blobs::store::fs::FsStore;
    use iroh_blobs::store::fs::options::Options;

    // A store left with an ingested TDF, a TDF whose upload failed, and a
    // blob that never validated, none tagged, as pushes leave them.
    let data_dir = tempfile::tempdir().unwrap();
    let tdf = create_test_tdf();
    let unuploaded_tdf = create_test_tdf();
    let garbage = vec![0xDEu8; 64 * 1024];
    let (ingested, unuploaded, never) = {
        let root = data_dir.path();
        let store = FsStore::load_with_opts(root.join("blobs.db"), Options::new(root))
            .await
            .unwrap();
        let ingested = store.add_slice(&tdf).temp_tag().await.unwrap().hash();
        let unuploaded = store
            .add_slice(&unuploaded_tdf)
            .temp_tag()
            .await
            .unwrap()
            .hash();
        let never = store.add_slice(&garbage).temp_tag().await.unwrap().hash();
        store.sync_db().await.unwrap();
        store.shutdown().await.unwrap();
        (ingested, unuploaded, never)
    };
    let (s3, endpoint_url) = FakeS3::start().await;
    s3.ingested(ingested, tdf.len() as u64);
    let (node, s3, _data_dir) = spawn_node_on(data_dir, s3, endpoint_url, None, |_| {}).await;
    let node_id = node.addr().id;
    let q = node.quarantine();

    // Ingested: served at once.
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, ingested).await.unwrap();
    assert_eq!(fetched.as_ref(), tdf.as_slice());
    assert!(q.is_validated(&ingested));

    // Never validated: refused, then deleted by the collector.
    assert_refused_for_permission(viewer.fetch_from_node(node_id, never).await, "get");
    wait_until("the unvalidated blob is refused", || async {
        q.is_refused(&never)
    })
    .await;
    wait_until("the unvalidated blob is deleted", || async {
        !q.is_refused(&never) && node.store().observe(never).await.unwrap().size() == 0
    })
    .await;

    // Valid but never uploaded: refused at first, uploaded, then served.
    assert_refused_for_permission(viewer.fetch_from_node(node_id, unuploaded).await, "get");
    assert!(
        s3.wait_for_put(&blob_key(unuploaded)).await,
        "uploaded on recovery"
    );
    wait_until("the recovered blob validates", || async {
        q.is_validated(&unuploaded)
    })
    .await;
    let fetched = viewer.fetch_from_node(node_id, unuploaded).await.unwrap();
    assert_eq!(fetched.as_ref(), unuploaded_tdf.as_slice());
    assert!(!q.is_refused(&unuploaded));

    node.store().sync_db().await.unwrap();
    for kept in [ingested, unuploaded] {
        assert!(node.store().observe(kept).await.unwrap().is_complete());
    }
    viewer.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// A push of a hash S3 holds but the node's store lacks (a fresh node) is
/// tracked like a new push: abandoned partway, its partial data is refused
/// and deleted rather than kept and served; pushed whole, it validates and
/// is served.
#[tokio::test(flavor = "current_thread")]
async fn test_a_push_of_an_ingested_hash_the_store_lacks_is_tracked() {
    let (s3, endpoint_url) = FakeS3::start().await;
    let tdf = create_large_test_tdf(20 * 1024 * 1024);
    let hash = Hash::new(&tdf);
    s3.ingested(hash, tdf.len() as u64);
    let (node, s3, _data_dir) =
        spawn_node_on(tempfile::tempdir().unwrap(), s3, endpoint_url, None, |_| {}).await;
    let node_id = node.addr().id;
    let q = node.quarantine();

    let pusher = IrohTestClient::new().await.unwrap();
    pusher
        .push_to_node_abandoned(node_id, &tdf, Duration::from_millis(150))
        .await
        .unwrap();
    wait_until("the partial push is refused", || async {
        q.is_refused(&hash)
    })
    .await;
    assert!(!q.is_validated(&hash));
    wait_until("the partial push is deleted", || async {
        !q.is_refused(&hash) && node.store().observe(hash).await.unwrap().size() == 0
    })
    .await;

    let pusher = IrohTestClient::new().await.unwrap();
    pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(
        s3.wait_for_put(&format!("manifests/{}", hash.to_hex()))
            .await
    );
    wait_until("the full push validates", || async {
        q.is_validated(&hash)
    })
    .await;
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A single get of a hash the node does not hold is not refused by the
/// node: it approves the request and iroh-blobs answers "not found". A
/// get_many or observe naming one is refused: a get_many reads its blobs in
/// turn, so a hash absent at approval could be pushed, unvalidated, before
/// the request reaches it (and iroh-blobs ends a get_many at a missing blob
/// anyway); an observe could create an entry for it.
#[tokio::test(flavor = "current_thread")]
async fn test_only_a_single_get_may_name_a_missing_hash() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_test_tdf();
    let pusher = IrohTestClient::new().await.unwrap();
    let held = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(held)).await);

    let viewer = IrohTestClient::new().await.unwrap();
    let missing = Hash::new(b"not on the node");
    let error = format!(
        "{:#}",
        viewer
            .fetch_from_node(node_id, missing)
            .await
            .expect_err("not found")
    );
    assert!(
        !error.contains("reset by peer: error 1"),
        "get refused for permission: {error}"
    );
    assert_refused_for_permission(
        viewer.get_many_from_node(node_id, &[held, missing]).await,
        "get_many",
    );
    // An observe could create an entry for the hash; it is refused.
    assert_refused_for_permission(viewer.observe_on_node(node_id, missing).await, "observe");
    // The held blob alone is served.
    let fetched = viewer.fetch_from_node(node_id, held).await.unwrap();
    assert_eq!(fetched.as_ref(), tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}
