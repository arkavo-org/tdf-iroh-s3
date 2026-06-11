//! Integration test: push a TDF blob to a node, verify it arrives and is accessible.
//!
//! Note: This test does NOT verify S3 upload (requires LocalStack/MinIO).
//! It verifies the network flow: push -> node stores blob -> blob fetchable.
//!
//! The FsStore's direct `status()` API does not reflect blobs received via the
//! iroh-blobs push protocol (they are stored internally by BlobsProtocol and
//! served via the network protocol). We verify accessibility by fetching the
//! blob back from the node over the iroh-blobs GET protocol.

use tdf_iroh_s3::config::{Config, HttpConfig, IrohConfig, S3Config, ValidationConfig};
use tdf_iroh_s3::node::TdfIrohNode;
use tdf_iroh_s3::test_cli::iroh_client::IrohTestClient;

fn test_config(data_dir: &str) -> Config {
    Config {
        iroh: IrohConfig {
            bind_port: 0, // Random port
            secret_key_param: String::new(),
            data_dir: data_dir.to_string(),
        },
        s3: S3Config {
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
            prefix: String::new(),
        },
        validation: ValidationConfig::default(),
        http: HttpConfig::default(),
    }
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
    let config = test_config(tmp_dir.path().to_str().unwrap());

    let node = TdfIrohNode::spawn(config).await.unwrap();
    let node_id = node.addr().id;

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
    let config = test_config(tmp_dir.path().to_str().unwrap());

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
