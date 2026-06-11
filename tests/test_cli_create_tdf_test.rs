use tdf_iroh_s3::test_cli::create_tdf::create_tdf_bytes;

#[test]
fn test_create_tdf_with_attribute() {
    let attr = "https://example.com/attr/storage/value/permanent";
    let data = b"test payload";
    let tdf_bytes = create_tdf_bytes(attr, data).unwrap();
    assert!(!tdf_bytes.is_empty());

    use tdf_iroh_s3::config::ValidationConfig;
    use tdf_iroh_s3::validation::validate_blob;
    let config = ValidationConfig {
        required_attributes: vec![attr.to_string()],
        assertion: Default::default(),
    };
    let result = validate_blob(&tdf_bytes, &config);
    assert!(
        result.is_ok(),
        "Created TDF should pass validation: {:?}",
        result.err()
    );
}

#[test]
fn test_create_tdf_hash_is_consistent() {
    let attr = "https://example.com/attr/storage/value/permanent";
    let tdf_bytes = create_tdf_bytes(attr, b"payload").unwrap();
    let hash1 = blake3::hash(&tdf_bytes);
    let hash2 = blake3::hash(&tdf_bytes);
    assert_eq!(hash1, hash2);
}
