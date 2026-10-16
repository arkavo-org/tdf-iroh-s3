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
    use tdf_iroh_s3::ingest::ingest_from_store;
    use tdf_iroh_s3::store::s3::S3Client;

    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::load(dir.path()).await.unwrap();
    let tdf = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let hash = store.add_slice(&tdf).await.unwrap().hash;
    // The size check reads the blob's bitfield, not its bytes.
    assert_eq!(store.observe(hash).await.unwrap().size(), tdf.len() as u64);
    let s3 = S3Client::new_mock("test-bucket", "us-east-1", "");
    let config = ValidationConfig {
        max_blob_bytes: 16,
        ..Default::default()
    };

    let err = match ingest_from_store(hash, &store, &config, &CatalogConfig::default(), &s3).await {
        Err(e) => e,
        Ok(_) => panic!("an oversize blob must be refused"),
    };
    assert!(format!("{err:#}").contains("max_blob_bytes"), "{err:#}");
    store.shutdown().await.unwrap();
}
