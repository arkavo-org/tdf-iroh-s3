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
use axum::http::{HeaderMap, Method, StatusCode, Uri};
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
            push_stall_secs: 120,
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

/// A loopback stand-in for S3. PUT stores the object (and records its key),
/// HEAD and GET answer for stored objects the way S3 does, ranges included.
/// HEAD also finds the keys in `present`; everything else is 404.
#[derive(Clone, Default)]
struct FakeS3 {
    puts: Arc<Mutex<Vec<String>>>,
    /// Keys HEAD finds, with their sizes: blobs ingested before the test.
    present: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    /// The bodies PUT (or seeded with [`FakeS3::put_object`]), by key.
    objects: Arc<Mutex<std::collections::HashMap<String, Bytes>>>,
    /// When set, a GET sends this many bytes of the slice it was asked for
    /// and then breaks the body with an error. A slice no longer than this
    /// is sent whole.
    fail_get_after: Arc<Mutex<Option<usize>>>,
    /// `x-amz-meta-*` headers stored with each object, returned by HEAD and
    /// GET (a catalog document's owner).
    metadata: Arc<Mutex<std::collections::HashMap<String, Metadata>>>,
}

/// The `x-amz-meta-*` headers of one object, as (name, value).
type Metadata = Vec<(String, String)>;

/// The real object bytes of a PUT body: `aws-chunked` framing
/// (`<hex-size>[;chunk-signature=...]\r\n<data>\r\n ... 0\r\n<trailers>`)
/// is decoded, any other body is the object as sent.
fn decode_put_body(headers: &HeaderMap, body: Bytes) -> Bytes {
    let named = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let chunked = named("content-encoding").contains("aws-chunked")
        || headers.contains_key("x-amz-decoded-content-length")
        || named("x-amz-content-sha256").starts_with("streaming-");
    if !chunked {
        return body;
    }
    let mut out = Vec::new();
    let mut rest: &[u8] = &body;
    while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
        let header = std::str::from_utf8(&rest[..line_end]).unwrap();
        let size = usize::from_str_radix(header.split(';').next().unwrap().trim(), 16)
            .unwrap_or_else(|_| panic!("bad aws-chunked chunk header: {header:?}"));
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Bytes::from(out)
}

/// The inclusive byte range a `Range` header asks of an object of `total`
/// bytes: `None` when it starts at or beyond the end (416), the end
/// clamped to the last byte.
fn requested_range(header: &str, total: usize) -> Option<(usize, usize)> {
    let spec = header.strip_prefix("bytes=").expect("a bytes range");
    let (start, end) = spec.split_once('-').expect("START-END");
    let (start, end) = if start.is_empty() {
        // Suffix range: the last `end` bytes.
        let n: usize = end.parse().unwrap();
        (total.saturating_sub(n), total.saturating_sub(1))
    } else {
        let start: usize = start.parse().unwrap();
        let end = if end.is_empty() {
            usize::MAX
        } else {
            end.parse().unwrap()
        };
        (start, end.min(total.saturating_sub(1)))
    };
    (start < total).then_some((start, end))
}

impl FakeS3 {
    /// Serve on a random loopback port and return the endpoint URL.
    async fn start() -> (Self, String) {
        let s3 = Self::default();
        let state = s3.clone();
        let app = axum::Router::new()
            .fallback(
                move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                    let s3 = state.clone();
                    async move { s3.handle(method, uri, headers, body) }
                },
            )
            // Blobs can be larger than axum's default 2 MB body limit.
            .layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        (s3, url)
    }

    fn handle(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> axum::response::Response {
        let path = uri.path();
        let key = path.strip_prefix(&format!("/{BUCKET}/")).unwrap_or(path);
        if method == Method::PUT {
            let meta: Vec<(String, String)> = headers
                .iter()
                .filter(|(name, _)| name.as_str().starts_with("x-amz-meta-"))
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_string()))
                .collect();
            self.metadata.lock().unwrap().insert(key.to_string(), meta);
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), decode_put_body(&headers, body));
            self.puts.lock().unwrap().push(key.to_string());
            return (StatusCode::OK, [("etag", "\"fake\"")]).into_response();
        }
        let stored = self.objects.lock().unwrap().get(key).cloned();
        if method == Method::HEAD {
            let size = stored
                .map(|b| b.len() as u64)
                .or_else(|| self.present.lock().unwrap().get(key).copied());
            return match size {
                Some(size) => {
                    let mut response = axum::http::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-length", size.to_string())
                        .header("etag", "\"fake\"");
                    for (name, value) in self.meta(key) {
                        response = response.header(name, value);
                    }
                    response.body(axum::body::Body::empty()).unwrap()
                }
                None => StatusCode::NOT_FOUND.into_response(),
            };
        }
        if method == Method::GET
            && let Some(object) = stored
        {
            let mut response = self.get(&headers, &object);
            for (name, value) in self.meta(key) {
                response.headers_mut().insert(
                    axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            return response;
        }
        if method == Method::GET {
            return (
                StatusCode::NOT_FOUND,
                [("content-type", "application/xml")],
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code>\
                     <Message>The specified key does not exist.</Message><Key>{key}</Key></Error>"
                ),
            )
                .into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    }

    /// A GET of a stored object: whole, or the slice a `Range` names.
    fn get(&self, headers: &HeaderMap, object: &Bytes) -> axum::response::Response {
        let total = object.len();
        let (status, start, end) = match headers.get("range").and_then(|v| v.to_str().ok()) {
            None => (StatusCode::OK, 0, total),
            Some(range) => match requested_range(range, total) {
                Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end + 1),
                None => {
                    return (
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        [("content-range", format!("bytes */{total}"))],
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>InvalidRange\
                         </Code><Message>The requested range is not satisfiable</Message></Error>",
                    )
                        .into_response();
                }
            },
        };
        let slice = object.slice(start..end);
        let mut response_headers = vec![
            ("content-length", slice.len().to_string()),
            ("etag", "\"fake\"".to_string()),
            ("accept-ranges", "bytes".to_string()),
        ];
        if status == StatusCode::PARTIAL_CONTENT {
            response_headers.push((
                "content-range",
                format!("bytes {start}-{}/{total}", end - 1),
            ));
        }
        let fail_after = (*self.fail_get_after.lock().unwrap()).filter(|n| *n < slice.len());
        let body = match fail_after {
            Some(n) => {
                let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
                    Ok(slice.slice(..n)),
                    Err(std::io::Error::other("FakeS3: GET broken mid-body")),
                ];
                axum::body::Body::from_stream(futures::stream::iter(chunks))
            }
            None => axum::body::Body::from(slice),
        };
        let mut response = axum::http::Response::builder().status(status);
        for (name, value) in response_headers {
            response = response.header(name, value);
        }
        response.body(body).unwrap()
    }

    fn meta(&self, key: &str) -> Vec<(String, String)> {
        self.metadata
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    /// Store `body` under `key` with `x-amz-meta-*` headers, as if PUT
    /// before the test.
    fn put_object_with_meta(&self, key: &str, body: &[u8], meta: &[(&str, &str)]) {
        self.put_object(key, body);
        self.metadata.lock().unwrap().insert(
            key.to_string(),
            meta.iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        );
    }

    /// Answer HEAD of `blobs/<hash>` as an ingested blob of `size` bytes.
    fn ingested(&self, hash: Hash, size: u64) {
        self.present.lock().unwrap().insert(blob_key(hash), size);
    }

    /// The body stored under `key`: what was PUT, or seeded with
    /// [`FakeS3::put_object`].
    fn body(&self, key: &str) -> Option<Bytes> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    /// Store `body` under `key`, as if it had been PUT before the test.
    /// It is not recorded in `puts`.
    fn put_object(&self, key: &str, body: &[u8]) {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_string(), Bytes::copy_from_slice(body));
    }

    /// Delete `key`, as if removed from the bucket.
    fn delete_object(&self, key: &str) {
        self.objects.lock().unwrap().remove(key);
        self.present.lock().unwrap().remove(key);
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

fn outboard_key(hash: Hash) -> String {
    format!("outboards/{}", hash.to_hex())
}

/// The files the store keeps for blobs it holds outside its database.
fn staged_files(data_dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(data_dir.join("data"))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Wait until the store holds none of `hashes` and no blob files at all:
/// the collector deleted every staged copy, outboards included.
async fn wait_for_empty_staging(node: &TdfIrohNode, data_dir: &std::path::Path, hashes: &[Hash]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        node.store().sync_db().await.unwrap();
        let mut held = Vec::new();
        for hash in hashes {
            if node.store().observe(*hash).await.unwrap().size() != 0 {
                held.push(*hash);
            }
        }
        let files = staged_files(data_dir);
        if held.is_empty() && files.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "staging is not emptied: held {held:?}, files {files:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

/// iroh-blobs resets a request the event handler answered "try again"
/// (`RateLimited`) with ERR_LIMIT (2).
fn assert_refused_as_rate_limited<T: std::fmt::Debug>(result: anyhow::Result<T>, request: &str) {
    let error = format!("{:#}", result.expect_err(request));
    assert!(
        error.contains("reset by peer: error 2"),
        "{request}: expected a try-again refusal, got: {error}"
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

/// The node's store only stages pushes: once ingest is done with a push,
/// ingested or refused, the collector deletes its copy, files included. A
/// refused blob never reaches S3 and is not served; the TDF is served from
/// S3.
#[tokio::test(flavor = "current_thread")]
async fn test_staged_pushes_are_deleted_once_ingested_or_refused() {
    let (node, s3, data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;

    // Both larger than the store inlines (16 KiB), so each is files on disk,
    // an outboard among them.
    let pusher = IrohTestClient::new().await.unwrap();
    let tdf = create_large_test_tdf(64 * 1024);
    let kept = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(kept)).await);
    assert!(
        s3.has_put(&outboard_key(kept)),
        "the outboard is stored before the blob"
    );
    let garbage = vec![0xDEu8; 64 * 1024];
    let refused = pusher.push_to_node(node_id, &garbage).await.unwrap();

    wait_for_empty_staging(&node, data_dir.path(), &[kept, refused]).await;
    assert!(!s3.has_put(&blob_key(refused)));
    let viewer = IrohTestClient::new().await.unwrap();
    assert_refused_for_permission(viewer.fetch_from_node(node_id, refused).await, "get");
    let fetched = viewer.fetch_from_node(node_id, kept).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

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

    // observe: refused for every hash, blocked or not; the node holds no
    // copy to observe.
    let client = IrohTestClient::new().await.unwrap();
    assert_refused_for_permission(client.observe_on_node(node_id, open).await, "observe");
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
/// push mid-transfer changes nothing for viewers: the blob is served from
/// S3 throughout, S3 is untouched, and the partial copy is deleted.
#[tokio::test(flavor = "current_thread")]
async fn test_an_abandoned_re_push_changes_nothing() {
    let (node, s3, data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;

    let tdf = create_large_test_tdf(20 * 1024 * 1024);
    let owner = IrohTestClient::new().await.unwrap();
    let held = owner.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(held)).await);
    wait_for_empty_staging(&node, data_dir.path(), &[held]).await;

    let attacker = IrohTestClient::new().await.unwrap();
    let pushed = attacker
        .push_to_node_abandoned(node_id, &tdf, Duration::from_millis(150))
        .await
        .unwrap();
    assert_eq!(pushed, held);

    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, held).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    wait_for_empty_staging(&node, data_dir.path(), &[held]).await;
    assert!(s3.body(&blob_key(held)).unwrap().as_ref() == tdf.as_slice());
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
/// never stores the whole blob, and deletes what arrived.
#[tokio::test(flavor = "current_thread")]
async fn test_an_oversize_push_is_stopped_mid_transfer() {
    let (node, s3, data_dir) =
        spawn_node_with(None, |c| c.validation.max_blob_bytes = 1024 * 1024).await;
    let node_id = node.addr().id;

    let oversize = vec![0x5Au8; 50 * 1024 * 1024];
    let hash = Hash::new(&oversize);
    let pusher = IrohTestClient::new().await.unwrap();
    let result = pusher.push_to_node(node_id, &oversize).await;
    let error = format!("{:#}", result.expect_err("the node stops the push"));
    assert!(error.contains("max_blob_bytes"), "{error}");

    // Only the first part arrived, and it is deleted.
    node.store().sync_db().await.unwrap();
    let bitfield = node.store().observe(hash).await.unwrap();
    assert!(!bitfield.is_complete(), "the whole blob never arrived");
    wait_for_empty_staging(&node, data_dir.path(), &[hash]).await;
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

/// A store left by a build that served from it: nothing in it is served,
/// and the collector deletes it all. What S3 holds is served from S3. A
/// blob ingested before outboards were stored gets one computed from S3 on
/// its first fetch, which is told to try again; then it is served.
#[tokio::test(flavor = "current_thread")]
async fn test_an_old_store_is_cleared_and_old_blobs_get_an_outboard() {
    use iroh_blobs::store::fs::FsStore;
    use iroh_blobs::store::fs::options::Options;

    let data_dir = tempfile::tempdir().unwrap();
    // Larger than one chunk group (16 KiB), so it needs an outboard.
    let tdf = create_large_test_tdf(256 * 1024);
    let garbage = vec![0xDEu8; 64 * 1024];
    let (ingested, never) = {
        let root = data_dir.path();
        let store = FsStore::load_with_opts(root.join("blobs.db"), Options::new(root))
            .await
            .unwrap();
        let ingested = store.add_slice(&tdf).temp_tag().await.unwrap().hash();
        let never = store.add_slice(&garbage).temp_tag().await.unwrap().hash();
        store.sync_db().await.unwrap();
        store.shutdown().await.unwrap();
        (ingested, never)
    };
    // Ingested by an older build: the blob, but no outboard.
    let (s3, endpoint_url) = FakeS3::start().await;
    s3.put_object(&blob_key(ingested), &tdf);
    let (node, s3, data_dir) = spawn_node_on(data_dir, s3, endpoint_url, None, |_| {}).await;
    let node_id = node.addr().id;

    let viewer = IrohTestClient::new().await.unwrap();
    assert_refused_as_rate_limited(viewer.fetch_from_node(node_id, ingested).await, "get");
    assert!(
        s3.wait_for_put(&outboard_key(ingested)).await,
        "the outboard is computed from S3 and stored"
    );
    let fetched = viewer.fetch_from_node(node_id, ingested).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    // Stored but never in S3: not served.
    assert_refused_for_permission(viewer.fetch_from_node(node_id, never).await, "get");

    wait_for_empty_staging(&node, data_dir.path(), &[ingested, never]).await;
    viewer.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// A creator's catalog document (catalog v2) is served over iroh from
/// `catalog-documents/` and `catalog-outboards/`, computing a missing
/// outboard there, never under `blobs/` or `outboards/`; a creator
/// suspended with `hideCatalog` has its documents refused.
#[tokio::test(flavor = "current_thread")]
async fn test_catalog_documents_are_served_over_iroh() {
    let gate = Arc::new(PublishGate::new(Arc::new(Moderation::default())));
    let (node, s3, _data_dir) = spawn_node(Some(Arc::clone(&gate))).await;
    let node_id = node.addr().id;
    let owner = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";
    let meta = [("x-amz-meta-owner", owner)];

    // Over one chunk group, so it has a real outboard.
    let document = format!(
        r#"{{"schema":"arkavo.creator-catalog/1","owner":"{owner}","entries":[],"pad":"{}"}}"#,
        "x".repeat(40 * 1024)
    )
    .into_bytes();
    let hash = Hash::new(&document);
    let outboard =
        tdf_iroh_s3::ingest::compute_outboard(&document[..], document.len() as u64, hash).unwrap();
    assert!(!outboard.is_empty());
    let hex = hash.to_hex();
    s3.put_object_with_meta(&format!("catalog-documents/{hex}"), &document, &meta);
    s3.put_object(&format!("catalog-outboards/{hex}"), &outboard);

    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert!(fetched.as_ref() == document.as_slice());

    // One stored without its outboard gets one computed into
    // catalog-outboards/, and is served after.
    let second = [document.clone(), b" ".to_vec()].concat();
    let second_hash = Hash::new(&second);
    let second_hex = second_hash.to_hex();
    s3.put_object_with_meta(&format!("catalog-documents/{second_hex}"), &second, &meta);
    assert_refused_as_rate_limited(viewer.fetch_from_node(node_id, second_hash).await, "get");
    assert!(
        s3.wait_for_put(&format!("catalog-outboards/{second_hex}"))
            .await,
        "the outboard is computed into catalog-outboards/"
    );
    assert!(!s3.has_put(&outboard_key(second_hash)));
    let fetched = viewer.fetch_from_node(node_id, second_hash).await.unwrap();
    assert!(fetched.as_ref() == second.as_slice());

    // A blocked creator catalog: refused on every fetch from then on.
    gate.moderation.block_catalog_for_test(owner);
    let client = IrohTestClient::new().await.unwrap();
    assert_refused_for_permission(client.fetch_from_node(node_id, hash).await, "get");

    for c in [viewer, client] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A fetch naming a hash S3 does not hold is refused for good, and a
/// get_many naming one among held hashes is refused whole, before a byte is
/// sent.
#[tokio::test(flavor = "current_thread")]
async fn test_a_fetch_naming_a_missing_hash_is_refused() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_test_tdf();
    let pusher = IrohTestClient::new().await.unwrap();
    let held = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(held)).await);

    let viewer = IrohTestClient::new().await.unwrap();
    let missing = Hash::new(b"not on the node");
    assert_refused_for_permission(viewer.fetch_from_node(node_id, missing).await, "get");
    assert_refused_for_permission(
        viewer.get_many_from_node(node_id, &[held, missing]).await,
        "get_many",
    );
    assert_refused_for_permission(viewer.observe_on_node(node_id, missing).await, "observe");
    // The held blob alone is served.
    let fetched = viewer.fetch_from_node(node_id, held).await.unwrap();
    assert_eq!(fetched.as_ref(), tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A fetcher that drops mid-transfer of a served blob changes nothing on
/// the node: the blob is served again.
#[tokio::test(flavor = "current_thread")]
async fn test_a_fetcher_dropping_mid_transfer_changes_nothing() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_large_test_tdf(20 * 1024 * 1024);
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    for _ in 0..3 {
        let flaky = IrohTestClient::new().await.unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(30),
            flaky.fetch_from_node(node_id, hash),
        )
        .await;
        flaky.shutdown().await.unwrap();
    }
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A push that stops sending without closing, as on a dead link, is
/// closed once its connection stalls; its partial copy is never ingested and
/// is deleted.
#[tokio::test(flavor = "current_thread")]
async fn test_a_stalled_push_is_closed() {
    let (node, s3, data_dir) = spawn_node_with(None, |c| c.iroh.push_stall_secs = 2).await;
    let node_id = node.addr().id;
    let tdf = create_large_test_tdf(20 * 1024 * 1024);
    let pusher = IrohTestClient::new().await.unwrap();
    let (hash, stalled) = pusher
        .push_to_node_stalled(node_id, &tdf, Duration::from_millis(150))
        .await
        .unwrap();
    wait_for_empty_staging(&node, data_dir.path(), &[hash]).await;
    assert!(!s3.has_put(&blob_key(hash)));
    drop(stalled);
    pusher.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// A get_many naming more hashes than Creator or the viewer ever do is
/// refused before any lookup.
#[tokio::test(flavor = "current_thread")]
async fn test_a_huge_get_many_is_refused() {
    let (node, _s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let viewer = IrohTestClient::new().await.unwrap();
    let hashes: Vec<Hash> = (0u32..65).map(|i| Hash::new(i.to_le_bytes())).collect();
    assert_refused_for_permission(
        viewer.get_many_from_node(node_id, &hashes).await,
        "get_many",
    );
    viewer.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// A stalled re-push of a blob the store holds whole (a valid TDF whose
/// upload failed before a restart) is not lost: once the stalled push is
/// closed, the node checks the store, validates the blob, uploads it, and
/// deletes its staged copy.
#[tokio::test(flavor = "current_thread")]
async fn test_a_stalled_re_push_of_a_whole_blob_validates_it() {
    use iroh_blobs::store::fs::FsStore;
    use iroh_blobs::store::fs::options::Options;

    let data_dir = tempfile::tempdir().unwrap();
    let tdf = create_large_test_tdf(20 * 1024 * 1024);
    let hash = {
        let root = data_dir.path();
        let store = FsStore::load_with_opts(root.join("blobs.db"), Options::new(root))
            .await
            .unwrap();
        let hash = store.add_slice(&tdf).temp_tag().await.unwrap().hash();
        store.sync_db().await.unwrap();
        store.shutdown().await.unwrap();
        hash
    };
    let (s3, endpoint_url) = FakeS3::start().await;
    // The collector's first run comes after the push is tracked.
    let (node, s3, data_dir) = spawn_node_on(data_dir, s3, endpoint_url, None, |c| {
        c.iroh.push_stall_secs = 2;
        c.iroh.gc_interval_secs = 5;
    })
    .await;
    let node_id = node.addr().id;

    let pusher = IrohTestClient::new().await.unwrap();
    let (pushed, stalled) = pusher
        .push_to_node_stalled(node_id, &tdf, Duration::from_millis(150))
        .await
        .unwrap();
    assert_eq!(pushed, hash);
    assert!(
        s3.wait_for_put(&blob_key(hash)).await,
        "validated and uploaded"
    );
    wait_for_empty_staging(&node, data_dir.path(), &[hash]).await;
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    drop(stalled);
    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A get of some ranges of a blob is answered from S3 with exactly those
/// ranges, verified by the client: within one chunk group, across chunk
/// groups, and the blob's last chunk.
#[tokio::test(flavor = "current_thread")]
async fn test_a_partial_range_get_is_served_from_s3() {
    use bao_tree::{ChunkNum, ChunkRanges};

    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_large_test_tdf(1024 * 1024);
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    let len = tdf.len() as u64;
    let last = (len - 1) / 1024;
    for (first, end) in [(3u64, 5u64), (17, 45), (last, last + 1)] {
        let viewer = IrohTestClient::new().await.unwrap();
        let bytes = (first * 1024)..(end * 1024).min(len);
        let fetched = viewer
            .get_ranges_from_node(
                node_id,
                hash,
                ChunkRanges::from(ChunkNum(first)..ChunkNum(end)),
                bytes.clone(),
            )
            .await
            .unwrap();
        assert!(
            fetched == tdf[bytes.start as usize..bytes.end as usize],
            "chunks {first}..{end}"
        );
        viewer.shutdown().await.unwrap();
    }

    pusher.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

/// S3 breaking off a GET mid-transfer resets the fetch with ERR_LIMIT (try
/// again), and the next fetch is served whole.
#[tokio::test(flavor = "current_thread")]
async fn test_s3_failing_mid_transfer_is_try_again() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_large_test_tdf(1024 * 1024);
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    // The outboard (about 4 KiB) is still sent whole; the blob breaks.
    *s3.fail_get_after.lock().unwrap() = Some(100 * 1024);
    let viewer = IrohTestClient::new().await.unwrap();
    assert_refused_as_rate_limited(viewer.fetch_from_node(node_id, hash).await, "get");
    viewer.shutdown().await.unwrap();

    *s3.fail_get_after.lock().unwrap() = None;
    let viewer = IrohTestClient::new().await.unwrap();
    let fetched = viewer.fetch_from_node(node_id, hash).await.unwrap();
    assert!(fetched.as_ref() == tdf.as_slice());

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// A blob deleted from S3 after the node served it: the first fetch breaks
/// off with "try again", and the node checks S3 again, so every later fetch
/// is refused for good.
#[tokio::test(flavor = "current_thread")]
async fn test_a_blob_deleted_from_s3_is_refused_for_good() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_large_test_tdf(64 * 1024);
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);
    let viewer = IrohTestClient::new().await.unwrap();
    viewer.fetch_from_node(node_id, hash).await.unwrap();
    viewer.shutdown().await.unwrap();

    s3.delete_object(&blob_key(hash));
    let viewer = IrohTestClient::new().await.unwrap();
    assert_refused_as_rate_limited(viewer.fetch_from_node(node_id, hash).await, "get");
    assert_refused_for_permission(viewer.fetch_from_node(node_id, hash).await, "get");

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// An S3 object whose bytes no longer match its hash is never sent: the
/// node checks each chunk group against the hash before sending it, and
/// resets the fetch at the first that fails. From then on the hash is
/// refused for good: a re-push would not repair the object.
#[tokio::test(flavor = "current_thread")]
async fn test_a_corrupt_s3_object_is_not_served() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;
    let tdf = create_large_test_tdf(256 * 1024);
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    let mut corrupt = tdf.clone();
    corrupt[200 * 1024] ^= 0xFF;
    s3.put_object(&blob_key(hash), &corrupt);
    let viewer = IrohTestClient::new().await.unwrap();
    // Reset by the node (ERR_LIMIT), not caught by the client's own check.
    assert_refused_as_rate_limited(viewer.fetch_from_node(node_id, hash).await, "get");
    assert_refused_for_permission(viewer.fetch_from_node(node_id, hash).await, "get");

    for c in [pusher, viewer] {
        c.shutdown().await.unwrap();
    }
    node.shutdown().await.unwrap();
}

/// An SDK client for the fake at `endpoint_url`, set up as the node's is.
async fn sdk_client(endpoint_url: &str) -> aws_sdk_s3::Client {
    set_dummy_aws_credentials();
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .load()
        .await;
    let config = aws_sdk_s3::config::Builder::from(&sdk_config)
        .force_path_style(true)
        .endpoint_url(endpoint_url)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn sdk_put(client: &aws_sdk_s3::Client, key: &str, body: &[u8]) {
    client
        .put_object()
        .bucket(BUCKET)
        .key(key)
        .body(aws_sdk_s3::primitives::ByteStream::from(body.to_vec()))
        .send()
        .await
        .unwrap();
}

/// GET `key` (with `range`, if given) and read the whole body.
async fn sdk_get(
    client: &aws_sdk_s3::Client,
    key: &str,
    range: Option<&str>,
) -> Result<(aws_sdk_s3::operation::get_object::GetObjectOutput, Bytes), Box<dyn std::error::Error>>
{
    let mut request = client.get_object().bucket(BUCKET).key(key);
    if let Some(range) = range {
        request = request.range(range);
    }
    let mut output = request.send().await?;
    let body = std::mem::take(&mut output.body)
        .collect()
        .await?
        .into_bytes();
    Ok((output, body))
}

fn fake_payload() -> Vec<u8> {
    (0..20u8).collect()
}

/// The fake stores what is PUT, and HEAD reports its length and an ETag.
#[tokio::test(flavor = "current_thread")]
async fn test_fake_s3_stores_a_put_and_answers_head() {
    let (s3, url) = FakeS3::start().await;
    let client = sdk_client(&url).await;
    let payload = fake_payload();
    sdk_put(&client, "blobs/a", &payload).await;

    assert!(s3.has_put("blobs/a"));
    assert_eq!(s3.body("blobs/a").unwrap().as_ref(), payload.as_slice());
    assert!(s3.body("blobs/b").is_none());

    let head = client
        .head_object()
        .bucket(BUCKET)
        .key("blobs/a")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(payload.len() as i64));
    assert!(head.e_tag().is_some());

    let missing = client
        .head_object()
        .bucket(BUCKET)
        .key("blobs/b")
        .send()
        .await
        .unwrap_err();
    assert!(missing.as_service_error().is_some_and(|e| e.is_not_found()));

    // A seeded object is found, but is no PUT; `ingested` keys still answer HEAD.
    s3.put_object("blobs/seeded", b"seed");
    assert!(!s3.has_put("blobs/seeded"));
    let head = client
        .head_object()
        .bucket(BUCKET)
        .key("blobs/seeded")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(4));
    let hash = Hash::new(b"present");
    s3.ingested(hash, 77);
    let head = client
        .head_object()
        .bucket(BUCKET)
        .key(blob_key(hash))
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(77));
}

/// GET returns the whole object, or the slice a `Range` names with a
/// `Content-Range`; an end past the object is clamped.
#[tokio::test(flavor = "current_thread")]
async fn test_fake_s3_serves_whole_and_ranged_gets() {
    let (s3, url) = FakeS3::start().await;
    let client = sdk_client(&url).await;
    let payload = fake_payload();
    sdk_put(&client, "outboards/a", &payload).await;
    assert!(s3.has_put("outboards/a"));

    let (whole, body) = sdk_get(&client, "outboards/a", None).await.unwrap();
    assert_eq!(body.as_ref(), payload.as_slice());
    assert_eq!(whole.content_length(), Some(20));
    assert!(whole.content_range().is_none());

    let (part, body) = sdk_get(&client, "outboards/a", Some("bytes=3-9"))
        .await
        .unwrap();
    assert_eq!(body.as_ref(), &payload[3..=9]);
    assert_eq!(part.content_length(), Some(7));
    assert_eq!(part.content_range(), Some("bytes 3-9/20"));

    let (part, body) = sdk_get(&client, "outboards/a", Some("bytes=5-"))
        .await
        .unwrap();
    assert_eq!(body.as_ref(), &payload[5..]);
    assert_eq!(part.content_length(), Some(15));
    assert_eq!(part.content_range(), Some("bytes 5-19/20"));

    let (part, body) = sdk_get(&client, "outboards/a", Some("bytes=15-1000"))
        .await
        .unwrap();
    assert_eq!(body.as_ref(), &payload[15..]);
    assert_eq!(part.content_range(), Some("bytes 15-19/20"));

    // The crate's own client reads the same bytes.
    let crate_client = tdf_iroh_s3::store::s3::S3Client::from_config(&S3Config {
        bucket: BUCKET.to_string(),
        region: "us-east-1".to_string(),
        prefix: String::new(),
        endpoint_url: url.clone(),
        force_path_style: true,
    })
    .await
    .unwrap();
    s3.put_object("blobs/ab", &payload);
    assert_eq!(crate_client.blob_size("ab").await.unwrap(), Some(20));
    assert_eq!(crate_client.blob_size("cd").await.unwrap(), None);
    assert_eq!(
        crate_client.get_blob("ab").await.unwrap().as_ref(),
        payload.as_slice()
    );
}

/// A range starting at or past the end is 416 with `Content-Range: bytes
/// */TOTAL`; an unknown key is a NoSuchKey 404.
#[tokio::test(flavor = "current_thread")]
async fn test_fake_s3_refuses_unsatisfiable_ranges_and_unknown_keys() {
    let (_s3, url) = FakeS3::start().await;
    let client = sdk_client(&url).await;
    sdk_put(&client, "blobs/a", &fake_payload()).await;

    for range in ["bytes=20-", "bytes=20-30", "bytes=500-"] {
        let error = client
            .get_object()
            .bucket(BUCKET)
            .key("blobs/a")
            .range(range)
            .send()
            .await
            .unwrap_err();
        let response = error.raw_response().expect("an HTTP response");
        assert_eq!(response.status().as_u16(), 416, "{range}");
        assert_eq!(
            response.headers().get("content-range"),
            Some("bytes */20"),
            "{range}"
        );
    }

    let error = client
        .get_object()
        .bucket(BUCKET)
        .key("blobs/none")
        .send()
        .await
        .unwrap_err();
    assert!(
        error.as_service_error().is_some_and(|e| e.is_no_such_key()),
        "{error:?}"
    );
}

/// A zero-length object (a small blob's empty outboard) GETs as 200 and an
/// empty body; any range on it is unsatisfiable.
#[tokio::test(flavor = "current_thread")]
async fn test_fake_s3_serves_a_zero_length_object() {
    let (s3, url) = FakeS3::start().await;
    let client = sdk_client(&url).await;
    sdk_put(&client, "outboards/empty", b"").await;
    assert_eq!(s3.body("outboards/empty").unwrap().len(), 0);

    let (output, body) = sdk_get(&client, "outboards/empty", None).await.unwrap();
    assert!(body.is_empty());
    assert_eq!(output.content_length(), Some(0));

    let error = client
        .get_object()
        .bucket(BUCKET)
        .key("outboards/empty")
        .range("bytes=0-")
        .send()
        .await
        .unwrap_err();
    assert_eq!(error.raw_response().unwrap().status().as_u16(), 416);
}

/// With `fail_get_after` set, a GET sends that many bytes and then breaks
/// the body; a slice that short is sent whole; cleared, GETs work again.
#[tokio::test(flavor = "current_thread")]
async fn test_fake_s3_breaks_a_get_mid_body_on_request() {
    let (s3, url) = FakeS3::start().await;
    let client = sdk_client(&url).await;
    let payload = vec![7u8; 100_000];
    sdk_put(&client, "blobs/big", &payload).await;

    *s3.fail_get_after.lock().unwrap() = Some(1000);
    assert!(
        sdk_get(&client, "blobs/big", None).await.is_err(),
        "the body must break"
    );
    assert!(
        sdk_get(&client, "blobs/big", Some("bytes=10-50000"))
            .await
            .is_err(),
        "a ranged body must break"
    );
    // A slice within the limit arrives whole.
    let (_, body) = sdk_get(&client, "blobs/big", Some("bytes=0-999"))
        .await
        .unwrap();
    assert_eq!(body.len(), 1000);

    *s3.fail_get_after.lock().unwrap() = None;
    let (_, body) = sdk_get(&client, "blobs/big", None).await.unwrap();
    assert_eq!(body.as_ref(), payload.as_slice());
}

/// `aws-chunked` framing is stripped, with or without chunk signatures and
/// trailers; a plain body is kept as is.
#[test]
fn test_fake_s3_decodes_aws_chunked_bodies() {
    let mut headers = HeaderMap::new();
    headers.insert("content-encoding", "aws-chunked".parse().unwrap());
    headers.insert("x-amz-decoded-content-length", "11".parse().unwrap());
    let framed = Bytes::from_static(
        b"5;chunk-signature=abc\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:AAAA==\r\n\r\n",
    );
    assert_eq!(decode_put_body(&headers, framed).as_ref(), b"hello world");

    let plain = Bytes::from_static(b"5\r\nhello\r\n0\r\n\r\n");
    assert_eq!(
        decode_put_body(&HeaderMap::new(), plain.clone()),
        plain,
        "an unframed body is stored as sent"
    );
}

/// The blob the node uploads, which it streams from disk, is stored in the
/// fake byte for byte, and the crate's client reads it back.
#[tokio::test(flavor = "current_thread")]
async fn test_a_node_uploaded_blob_is_stored_byte_for_byte() {
    let (node, s3, _data_dir) = spawn_node(None).await;
    let node_id = node.addr().id;

    let tdf = create_large_test_tdf(300_000);
    let pusher = IrohTestClient::new().await.unwrap();
    let hash = pusher.push_to_node(node_id, &tdf).await.unwrap();
    assert!(s3.wait_for_put(&blob_key(hash)).await);

    let stored = s3.body(&blob_key(hash)).expect("the blob is stored");
    assert_eq!(stored.len(), tdf.len());
    assert!(stored.as_ref() == tdf.as_slice(), "stored bytes differ");

    pusher.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}
