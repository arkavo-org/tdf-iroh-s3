use opentdf::TdfManifest;
use tdf_iroh_s3::validation::attributes::validate_attributes;

#[test]
fn test_no_required_attributes_always_passes() {
    let tdf_bytes = create_tdf_with_attribute("https://example.com/attr/level/value/public");
    let manifest = parse_manifest(&tdf_bytes);
    let required: Vec<String> = vec![];
    let result = validate_attributes(&manifest, &required);
    assert!(result.is_ok());
}

#[test]
fn test_matching_attribute_passes() {
    let attr = "https://example.com/attr/storage/value/permanent";
    let tdf_bytes = create_tdf_with_attribute(attr);
    let manifest = parse_manifest(&tdf_bytes);
    let required = vec![attr.to_string()];
    let result = validate_attributes(&manifest, &required);
    assert!(
        result.is_ok(),
        "TDF with required attribute should pass: {:?}",
        result.err()
    );
}

#[test]
fn test_missing_attribute_fails() {
    let tdf_bytes = create_tdf_with_attribute("https://example.com/attr/level/value/public");
    let manifest = parse_manifest(&tdf_bytes);
    let required = vec!["https://example.com/attr/storage/value/permanent".to_string()];
    let result = validate_attributes(&manifest, &required);
    assert!(
        result.is_err(),
        "TDF missing required attribute should fail"
    );
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

fn parse_manifest(tdf_bytes: &[u8]) -> TdfManifest {
    use tdf_iroh_s3::validation::structure::validate_tdf_structure;
    validate_tdf_structure(tdf_bytes).unwrap()
}
