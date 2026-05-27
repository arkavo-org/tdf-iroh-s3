use tdf_iroh_s3::config::Config;

const TEST_AUTH: &str = r#"
[auth]
cose_keys_url = "https://issuer.example/.well-known/cose-keys"
issuer = "https://issuer.example"
"#;

#[test]
fn test_config_default_data_dir() {
    let toml_str = format!(
        r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
{TEST_AUTH}"#
    );
    let config: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(config.iroh.data_dir, "/var/lib/tdf-iroh-s3/data");
}

#[test]
fn test_config_custom_data_dir() {
    let toml_str = format!(
        r#"
[iroh]
data_dir = "/tmp/my-data"

[s3]
bucket = "test-bucket"
region = "us-east-1"
{TEST_AUTH}"#
    );
    let config: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(config.iroh.data_dir, "/tmp/my-data");
}

#[test]
fn test_parse_minimal_config() {
    let toml_str = format!(
        r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
{TEST_AUTH}"#
    );
    let config: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(config.s3.bucket, "test-bucket");
    assert_eq!(config.s3.region, "us-east-1");
    assert_eq!(config.iroh.bind_port, 11204);
    assert!(config.validation.required_attributes.is_empty());
    assert!(!config.validation.assertion.enabled);
}

#[test]
fn test_config_default_catalog_data_dir() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"

[auth]
cose_keys_url = "https://issuer.example/.well-known/cose-keys"
issuer = "https://issuer.example"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.catalog.data_dir, "/var/lib/tdf-iroh-s3/catalog");
}

#[test]
fn test_config_auth_required() {
    // auth is now optional at parse time; validate() enforces required URLs fail-closed.
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
"#;
    let cfg = toml::from_str::<Config>(toml_str).expect("parses without auth section");
    // validate() should reject empty URLs
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("auth"), "expected auth-missing error, got: {err}");
}

#[test]
fn test_config_auth_defaults() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"

[auth]
cose_keys_url = "https://issuer.example/.well-known/cose-keys"
issuer = "https://issuer.example"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        config.auth.cose_keys_url,
        "https://issuer.example/.well-known/cose-keys"
    );
    assert_eq!(config.auth.issuer, "https://issuer.example");
    assert_eq!(config.auth.refresh_interval_secs, 300);
    assert_eq!(config.auth.clock_skew_secs, 60);
}

#[test]
fn test_config_auth_custom() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"

[auth]
cose_keys_url = "https://issuer.example/.well-known/cose-keys"
issuer = "https://issuer.example"
refresh_interval_secs = 60
clock_skew_secs = 5

[catalog]
data_dir = "/tmp/my-docs"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.auth.refresh_interval_secs, 60);
    assert_eq!(config.auth.clock_skew_secs, 5);
    assert_eq!(config.catalog.data_dir, "/tmp/my-docs");
}

#[test]
fn test_parse_full_config() {
    let toml_str = format!(
        r#"
[iroh]
bind_port = 9999
secret_key_param = "/my-app/node-secret-key"

[s3]
bucket = "prod-bucket"
region = "eu-west-1"
prefix = "blobs/"

[validation]
required_attributes = [
    "https://example.com/attr/storage/value/permanent"
]

[validation.assertion]
enabled = true
trusted_public_keys = ["/tmp/key1.pem", "/tmp/key2.pem"]
{TEST_AUTH}"#
    );
    let config: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(config.iroh.bind_port, 9999);
    assert_eq!(config.iroh.secret_key_param, "/my-app/node-secret-key");
    assert_eq!(config.s3.prefix, "blobs/");
    assert_eq!(config.validation.required_attributes.len(), 1);
    assert!(config.validation.assertion.enabled);
    assert_eq!(config.validation.assertion.trusted_public_keys.len(), 2);
}

#[test]
fn missing_auth_section_uses_default_with_empty_urls() {
    let toml = r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
    "#;
    let cfg: tdf_iroh_s3::config::Config = toml::from_str(toml).expect("parses");
    assert_eq!(cfg.auth.cose_keys_url, "");
    assert_eq!(cfg.auth.issuer, "");
    assert_eq!(cfg.pdp.attribute_defs_url, "");
}

#[test]
fn refresh_interval_zero_is_rejected() {
    let toml = r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
        [auth]
        cose_keys_url = "https://x"
        issuer = "https://x"
        refresh_interval_secs = 0
    "#;
    let err = toml::from_str::<tdf_iroh_s3::config::Config>(toml).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("auth.refresh_interval_secs"), "expected auth-named error, got: {s}");
}

#[test]
fn pdp_refresh_interval_zero_is_rejected() {
    let toml = r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
        [auth]
        cose_keys_url = "https://x"
        issuer = "https://x"
        [pdp]
        attribute_defs_url = "https://x"
        refresh_interval_secs = 0
    "#;
    let err = toml::from_str::<tdf_iroh_s3::config::Config>(toml).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("pdp.refresh_interval_secs"), "expected pdp-named error, got: {s}");
}

#[test]
fn auth_and_pdp_url_required_at_validate() {
    let cfg: tdf_iroh_s3::config::Config = toml::from_str(r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
    "#).unwrap();
    let err = cfg.validate().unwrap_err();
    let s = err.to_string();
    assert!(s.contains("auth.cose_keys_url"), "got: {s}");
    assert!(s.contains("auth.issuer"),         "got: {s}");
    assert!(s.contains("pdp.attribute_defs_url"), "got: {s}");
}
