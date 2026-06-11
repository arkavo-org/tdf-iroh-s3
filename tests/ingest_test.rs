use tdf_iroh_s3::config::ValidationConfig;
use tdf_iroh_s3::validation::validate_blob;

#[test]
fn test_ingest_validates_before_accepting() {
    let valid_tdf = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let config = ValidationConfig {
        required_attributes: vec!["https://example.com/attr/storage/value/permanent".to_string()],
        assertion: Default::default(),
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
