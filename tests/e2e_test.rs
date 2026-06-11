//! End-to-end test: create TDF -> validate -> verify hash
//!
//! Note: S3 operations require LocalStack or MinIO.
//! This test covers the validation + hashing flow without S3.

use tdf_iroh_s3::config::ValidationConfig;
use tdf_iroh_s3::validation::validate_blob;

#[test]
fn test_e2e_valid_tdf_full_pipeline() {
    let tdf_bytes = create_tdf("https://example.com/attr/storage/value/permanent");

    let config = ValidationConfig {
        required_attributes: vec!["https://example.com/attr/storage/value/permanent".to_string()],
        assertion: Default::default(),
    };

    let result = validate_blob(&tdf_bytes, &config);
    assert!(result.is_ok(), "Valid TDF should pass: {:?}", result.err());

    let hash = blake3::hash(&tdf_bytes);
    let hash_hex = hash.to_hex().to_string();
    assert_eq!(hash_hex.len(), 64, "BLAKE3 hash should be 64 hex chars");

    let hash2 = blake3::hash(&tdf_bytes);
    assert_eq!(hash, hash2);
}

#[test]
fn test_e2e_reject_non_tdf() {
    let garbage = b"this is not a TDF file at all".to_vec();
    let config = ValidationConfig {
        required_attributes: vec![],
        assertion: Default::default(),
    };
    let result = validate_blob(&garbage, &config);
    assert!(result.is_err());
}

#[test]
fn test_e2e_reject_wrong_attribute() {
    let tdf_bytes = create_tdf("https://example.com/attr/level/value/public");
    let config = ValidationConfig {
        required_attributes: vec!["https://example.com/attr/storage/value/permanent".to_string()],
        assertion: Default::default(),
    };
    let result = validate_blob(&tdf_bytes, &config);
    assert!(result.is_err());
}

#[test]
fn test_e2e_no_requirements_accepts_any_tdf() {
    let tdf_bytes = create_tdf("https://example.com/attr/anything/value/whatever");
    let config = ValidationConfig::default();
    let result = validate_blob(&tdf_bytes, &config);
    assert!(result.is_ok());
}

fn create_tdf(attr_fqn: &str) -> Vec<u8> {
    use opentdf::prelude::*;

    let policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["test@example.com"])
        .attribute_fqn(attr_fqn)
        .unwrap()
        .build()
        .unwrap();

    Tdf::encrypt(b"end-to-end test payload")
        .kas_url("https://kas.example.com")
        .policy(policy)
        .to_bytes()
        .unwrap()
}
