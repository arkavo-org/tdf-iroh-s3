use tdf_iroh_s3::config::ValidationConfig;
use tdf_iroh_s3::validation::validate_blob;

#[test]
fn test_valid_tdf_passes_full_pipeline() {
    let tdf_bytes = create_tdf_with_attribute("https://example.com/attr/storage/value/permanent");
    let config = ValidationConfig {
        required_attributes: vec!["https://example.com/attr/storage/value/permanent".to_string()],
        assertion: Default::default(),
    };
    let result = validate_blob(&tdf_bytes, &config);
    assert!(result.is_ok(), "Valid TDF should pass: {:?}", result.err());
}

#[test]
fn test_garbage_fails_pipeline() {
    let garbage = vec![0u8; 256];
    let config = ValidationConfig::default();
    let result = validate_blob(&garbage, &config);
    assert!(result.is_err(), "Garbage should fail");
}

#[test]
fn test_missing_attribute_fails_pipeline() {
    let tdf_bytes = create_tdf_with_attribute("https://example.com/attr/level/value/public");
    let config = ValidationConfig {
        required_attributes: vec!["https://example.com/attr/storage/value/permanent".to_string()],
        assertion: Default::default(),
    };
    let result = validate_blob(&tdf_bytes, &config);
    assert!(result.is_err(), "Missing attribute should fail");
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
