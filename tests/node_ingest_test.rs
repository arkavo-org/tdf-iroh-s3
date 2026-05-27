//! Integration test: push a TDF blob to a node, verify it arrives and is accessible.
//!
//! Note: This test does NOT verify S3 upload (requires LocalStack/MinIO).
//! It verifies the network flow: push -> node stores blob -> blob fetchable.
//!
//! The FsStore's direct `status()` API does not reflect blobs received via the
//! iroh-blobs push protocol (they are stored internally by BlobsProtocol and
//! served via the network protocol). We verify accessibility by fetching the
//! blob back from the node over the iroh-blobs GET protocol.

use std::path::Path;
use std::sync::Arc;
use tdf_iroh_s3::auth::test_signer::TestSigner;
use tdf_iroh_s3::config::{AuthConfig, CatalogConfig, Config, IrohConfig, PdpConfig, S3Config, ValidationConfig};
use tdf_iroh_s3::node::TdfIrohNode;
use tdf_iroh_s3::test_cli::iroh_client::IrohTestClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spin up a minimal in-process HTTP server that serves `body` forever.
/// Returns the base URL (e.g. `http://127.0.0.1:PORT`).
async fn serve_static(body: Vec<u8>, content_type: &'static str) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    content_type,
                    body.len()
                );
                let _ = s.write_all(h.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    format!("http://{addr}")
}

async fn test_config_with_fixtures(tmp_dir: &Path) -> (Config, TestSigner) {
    let issuer = "https://issuer.example".to_string();
    let signer = TestSigner::new(&issuer);

    // COSE keys: serve the signer's published keyset.
    let cose_keys_url = serve_static(
        signer.cose_key_set(),
        "application/cose-key-set+cbor",
    )
    .await;

    // PDP: serve an empty attribute set (valid JSON for AccessPdp::new).
    let attribute_defs_url = serve_static(b"[]".to_vec(), "application/json").await;

    let config = Config {
        iroh: IrohConfig {
            bind_port: 0,
            secret_key_param: String::new(),
            data_dir: tmp_dir.join("iroh").to_str().unwrap().to_string(),
        },
        s3: S3Config {
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            prefix: String::new(),
        },
        validation: ValidationConfig::default(),
        catalog: CatalogConfig {
            data_dir: tmp_dir.join("catalog").to_str().unwrap().to_string(),
            max_subscriptions_per_peer: 4,
            max_subscriptions_total: 256,
        },
        auth: AuthConfig {
            cose_keys_url,
            issuer,
            refresh_interval_secs: 300,
            clock_skew_secs: 60,
        },
        pdp: PdpConfig {
            attribute_defs_url,
            refresh_interval_secs: 300,
        },
    };
    (config, signer)
}

#[tokio::test(flavor = "current_thread")]
async fn test_push_blob_stored_in_node() {
    // Set dummy AWS credentials so S3Client::new doesn't hang
    // trying to reach the IMDS endpoint.
    // SAFETY: current_thread runtime ensures no other threads read env vars concurrently.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }

    let tmp_dir = tempfile::tempdir().unwrap();
    let (config, _signer) = test_config_with_fixtures(tmp_dir.path()).await;

    let node = TdfIrohNode::spawn(config).await.unwrap();
    let node_id = node.addr().id;

    // Smoke check: EventStore opened cleanly (tail is 0 on a fresh DB).
    let tail = node.catalog.current_tail();
    assert_eq!(tail, 0, "fresh EventStore should have tail 0");

    // Create a valid TDF blob
    let tdf_bytes = create_test_tdf();

    // Push it to the node
    let client = IrohTestClient::new().await.unwrap();
    let hash = client.push_to_node(node_id, &tdf_bytes).await.unwrap();

    // Verify the blob is accessible by fetching it back from the node
    // (fetch_from_node blocks until the blob is available over the protocol)
    let fetched = client.fetch_from_node(node_id, hash).await.unwrap();
    assert_eq!(
        fetched.as_ref(),
        tdf_bytes.as_slice(),
        "Fetched blob should match the original TDF bytes"
    );

    client.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_push_invalid_blob_does_not_crash_node() {
    // SAFETY: current_thread runtime ensures no other threads read env vars concurrently.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }

    let tmp_dir = tempfile::tempdir().unwrap();
    let (config, _signer) = test_config_with_fixtures(tmp_dir.path()).await;

    let node = TdfIrohNode::spawn(config).await.unwrap();
    let node_id = node.addr().id;

    // Push garbage (non-TDF) bytes to the node
    let garbage = vec![0xDEu8; 256];
    let client = IrohTestClient::new().await.unwrap();
    let hash = client.push_to_node(node_id, &garbage).await.unwrap();

    // Give the ingest loop time to attempt (and reject) the blob
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // The node should still be alive — verify by fetching the blob back
    // (it's stored in FsStore even though ingest to S3 was rejected)
    let fetched = client.fetch_from_node(node_id, hash).await.unwrap();
    assert_eq!(fetched.as_ref(), garbage.as_slice());

    client.shutdown().await.unwrap();
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
