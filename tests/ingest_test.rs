use tdf_iroh_s3::config::ValidationConfig;
use tdf_iroh_s3::validation::validate_blob;

#[test]
fn test_ingest_validates_before_accepting() {
    let valid_tdf = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let config = ValidationConfig {
        required_attributes: vec!["https://example.com/attr/storage/value/permanent".to_string()],
        assertion: Default::default(),
        ..Default::default()
    };

    let result = validate_blob(&valid_tdf, &config);
    assert!(result.is_ok());

    let hash = blake3::hash(&valid_tdf);
    let hash_hex = hash.to_hex().to_string();
    assert!(!hash_hex.is_empty());
}

#[test]
fn test_ingest_rejects_invalid_blob() {
    let garbage = vec![0u8; 256];
    let config = ValidationConfig {
        required_attributes: vec![],
        assertion: Default::default(),
        ..Default::default()
    };

    let result = validate_blob(&garbage, &config);
    assert!(result.is_err());
}

#[test]
fn test_blake3_hash_deterministic() {
    let data = b"test data for hashing";
    let hash1 = blake3::hash(data);
    let hash2 = blake3::hash(data);
    assert_eq!(hash1, hash2);
}

fn create_tdf_with_attribute(attr_fqn: &str) -> Vec<u8> {
    use opentdf::prelude::*;

    let policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["test@example.com"])
        .attribute_fqn(attr_fqn)
        .unwrap()
        .build()
        .unwrap();

    Tdf::encrypt(b"test data")
        .kas_url("https://kas.example.com")
        .policy(policy)
        .to_bytes()
        .unwrap()
}

#[test]
fn derive_artifacts_produces_manifest_and_group_entries() {
    use tdf_iroh_s3::catalog::{CatalogEntry, derive_artifacts};
    use tdf_iroh_s3::config::CatalogConfig;
    use tdf_iroh_s3::validation::validate_blob;

    // End-to-end from real TDF bytes: validate → derive. The grouping
    // attribute value becomes the catalog group; the entry carries every
    // policy FQN; the manifest sidecar is standalone-parseable JSON.
    let tdf = create_tdf_with_attribute("https://patreon.arkavo.com/attr/campaign/value/12345678");
    let manifest = validate_blob(&tdf, &ValidationConfig::default()).unwrap();

    let config = CatalogConfig {
        enabled: true,
        ..CatalogConfig::default()
    };
    let derived = derive_artifacts(&manifest, &"ab".repeat(32), tdf.len() as u64, 42, &config)
        .expect("derivation succeeds");

    let parsed: serde_json::Value =
        serde_json::from_str(&derived.manifest_json).expect("extracted manifest is valid JSON");
    assert!(parsed.get("encryptionInformation").is_some());

    assert_eq!(derived.entries.len(), 1, "one group entry expected");
    let (group, entry_json) = &derived.entries[0];
    assert_eq!(group, "12345678");
    let entry: CatalogEntry = serde_json::from_slice(entry_json).unwrap();
    assert_eq!(entry.hash, "ab".repeat(32));
    assert_eq!(entry.ingested_at, 42);
    assert!(
        entry
            .attribute_fqns
            .contains(&"https://patreon.arkavo.com/attr/campaign/value/12345678".to_string()),
        "entry FQNs: {:?}",
        entry.attribute_fqns
    );
}

#[test]
fn derive_artifacts_with_catalog_disabled_still_extracts_manifest() {
    use tdf_iroh_s3::catalog::derive_artifacts;
    use tdf_iroh_s3::config::CatalogConfig;
    use tdf_iroh_s3::validation::validate_blob;

    let tdf = create_tdf_with_attribute("https://patreon.arkavo.com/attr/campaign/value/1");
    let manifest = validate_blob(&tdf, &ValidationConfig::default()).unwrap();
    let derived =
        derive_artifacts(&manifest, &"cd".repeat(32), 1, 0, &CatalogConfig::default()).unwrap();
    assert!(!derived.manifest_json.is_empty());
    assert!(
        derived.entries.is_empty(),
        "disabled catalog indexes nothing"
    );
}

#[test]
fn derive_artifacts_ungrouped_policy_yields_no_entries() {
    use tdf_iroh_s3::catalog::derive_artifacts;
    use tdf_iroh_s3::config::CatalogConfig;
    use tdf_iroh_s3::validation::validate_blob;

    // No grouping attribute → in no catalog (curation = labeling).
    let tdf = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let manifest = validate_blob(&tdf, &ValidationConfig::default()).unwrap();
    let config = CatalogConfig {
        enabled: true,
        ..CatalogConfig::default()
    };
    let derived = derive_artifacts(&manifest, &"ee".repeat(32), 1, 0, &config).unwrap();
    assert!(derived.entries.is_empty());
}

#[test]
fn blobs_over_max_blob_bytes_are_refused() {
    let tdf = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let at_limit = ValidationConfig {
        max_blob_bytes: tdf.len() as u64,
        ..Default::default()
    };
    assert!(validate_blob(&tdf, &at_limit).is_ok());

    let below = ValidationConfig {
        max_blob_bytes: tdf.len() as u64 - 1,
        ..Default::default()
    };
    let err = validate_blob(&tdf, &below).unwrap_err();
    assert!(format!("{err:#}").contains("max_blob_bytes"), "{err:#}");
}

/// The store path refuses an oversize blob before reading it, and before
/// any S3 call (the mock client would fail one).
#[tokio::test]
async fn ingest_from_store_refuses_an_oversize_blob() {
    use iroh_blobs::store::fs::FsStore;
    use tdf_iroh_s3::config::CatalogConfig;
    use tdf_iroh_s3::ingest::{IngestError, ingest_from_store, prepare_scratch_dir};
    use tdf_iroh_s3::store::s3::S3Client;

    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::load(dir.path()).await.unwrap();
    let scratch = prepare_scratch_dir(dir.path().to_str().unwrap())
        .await
        .unwrap();
    let tdf = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let hash = store.add_slice(&tdf).await.unwrap().hash;
    // The size check reads the blob's bitfield, not its bytes.
    assert_eq!(store.observe(hash).await.unwrap().size(), tdf.len() as u64);
    let s3 = S3Client::new_mock("test-bucket", "us-east-1", "");
    let config = ValidationConfig {
        max_blob_bytes: 16,
        ..Default::default()
    };

    let result = ingest_from_store(
        hash,
        &store,
        &config,
        &CatalogConfig::default(),
        &s3,
        &scratch,
    )
    .await;
    match result {
        Err(IngestError::Refused(e)) => {
            assert!(format!("{e:#}").contains("max_blob_bytes"), "{e:#}")
        }
        Err(e) => panic!("an oversize blob is refused, not failed: {e}"),
        Ok(_) => panic!("an oversize blob must be refused"),
    }
    assert_scratch_empty(&scratch).await;
    store.shutdown().await.unwrap();
}

/// A loopback S3 that answers HEAD with 404 and records each PUT: its key,
/// body, and whether it was sent `aws-chunked`.
type Puts = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>, bool)>>>;

async fn recording_s3() -> (String, Puts) {
    use axum::http::{Method, StatusCode};
    use axum::response::IntoResponse;
    use std::sync::Arc;

    let puts: Puts = Arc::default();
    let recorded = Arc::clone(&puts);
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let puts = Arc::clone(&recorded);
        async move {
            let (parts, body) = req.into_parts();
            let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            if parts.method != Method::PUT {
                return StatusCode::NOT_FOUND.into_response();
            }
            let chunked = parts
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("aws-chunked"));
            let key = parts
                .uri
                .path()
                .trim_start_matches("/test-bucket/")
                .to_string();
            puts.lock().unwrap().push((key, body.to_vec(), chunked));
            (StatusCode::OK, [("etag", "\"fake\"")]).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    (url, puts)
}

async fn assert_scratch_empty(scratch: &std::path::Path) {
    // A refused blob's scratch file is removed by a spawned task.
    for _ in 0..50 {
        if std::fs::read_dir(scratch).unwrap().next().is_none() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("scratch files left in {}", scratch.display());
}

/// A valid blob is exported, validated from its file and uploaded to S3
/// byte for byte, streamed from that file; the scratch copy is removed.
#[tokio::test(flavor = "current_thread")]
async fn ingest_from_store_streams_a_valid_blob_to_s3() {
    use iroh_blobs::store::fs::FsStore;
    use tdf_iroh_s3::config::{CatalogConfig, S3Config};
    use tdf_iroh_s3::ingest::{ingest_from_store, prepare_scratch_dir};
    use tdf_iroh_s3::store::s3::S3Client;

    // SAFETY: current_thread runtime ensures no other threads read env vars concurrently.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
    let (endpoint_url, puts) = recording_s3().await;
    let s3 = S3Client::from_config(&S3Config {
        bucket: "test-bucket".into(),
        region: "us-east-1".into(),
        prefix: String::new(),
        endpoint_url,
        force_path_style: true,
    })
    .await
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::load(dir.path()).await.unwrap();
    let scratch = prepare_scratch_dir(dir.path().to_str().unwrap())
        .await
        .unwrap();
    // Larger than the store inlines (16 KiB), so it is a file in the store.
    let tdf = {
        use opentdf::prelude::*;
        let policy = PolicyBuilder::new()
            .id_auto()
            .dissemination(["test@example.com"])
            .build()
            .unwrap();
        Tdf::encrypt(vec![7u8; 300_000])
            .kas_url("https://kas.example.com")
            .policy(policy)
            .to_bytes()
            .unwrap()
    };
    let hash = store.add_slice(&tdf).await.unwrap().hash;

    let result = ingest_from_store(
        hash,
        &store,
        &ValidationConfig::default(),
        &CatalogConfig::default(),
        &s3,
        &scratch,
    )
    .await
    .unwrap()
    .expect("a complete blob is ingested");
    assert_eq!(result.hash_hex, hash.to_hex().to_string());
    assert_eq!(result.size, tdf.len() as u64);

    let puts = puts.lock().unwrap().clone();
    let (_, uploaded, chunked) = puts
        .iter()
        .find(|(key, _, _)| *key == format!("blobs/{}", hash.to_hex()))
        .expect("the blob is uploaded");
    assert_eq!(uploaded.len(), tdf.len());
    assert!(*uploaded == tdf, "the uploaded bytes are the blob's");
    // aws-runtime 1.7.1 mis-sizes a streamed aws-chunked body (see
    // S3Client::put_blob_file); the upload must be sent plain.
    assert!(!chunked, "the streamed blob is sent without aws-chunked");
    assert!(
        puts.iter()
            .any(|(key, _, _)| *key == format!("manifests/{}", hash.to_hex()))
    );
    assert_scratch_empty(&scratch).await;

    // Garbage is refused from its file, and its copy removed too.
    let garbage = vec![0xEEu8; 40_000];
    let hash = store.add_slice(&garbage).await.unwrap().hash;
    let result = ingest_from_store(
        hash,
        &store,
        &ValidationConfig::default(),
        &CatalogConfig::default(),
        &s3,
        &scratch,
    )
    .await;
    assert!(
        matches!(result, Err(tdf_iroh_s3::ingest::IngestError::Refused(_))),
        "garbage is refused"
    );
    assert_scratch_empty(&scratch).await;
    store.shutdown().await.unwrap();
}
