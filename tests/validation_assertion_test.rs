use opentdf::TdfManifest;
use tdf_iroh_s3::validation::assertion::validate_assertion;

#[test]
fn test_assertion_disabled_always_passes() {
    let tdf_bytes = create_basic_tdf();
    let manifest = parse_manifest(&tdf_bytes);
    let trusted_keys: Vec<String> = vec![];
    let result = validate_assertion(&manifest, false, &trusted_keys);
    assert!(result.is_ok());
}

#[test]
fn test_assertion_enabled_no_assertion_fails() {
    let tdf_bytes = create_basic_tdf();
    let manifest = parse_manifest(&tdf_bytes);
    let trusted_keys = vec!["/tmp/nonexistent.pem".to_string()];
    let result = validate_assertion(&manifest, true, &trusted_keys);
    assert!(
        result.is_err(),
        "TDF without assertion should fail when check is enabled"
    );
}

fn create_basic_tdf() -> Vec<u8> {
    use opentdf::prelude::*;

    let policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["test@example.com"])
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
