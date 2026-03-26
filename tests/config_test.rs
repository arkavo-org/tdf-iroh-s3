use tdf_iroh_s3::config::Config;

#[test]
fn test_parse_minimal_config() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.s3.bucket, "test-bucket");
    assert_eq!(config.s3.region, "us-east-1");
    assert_eq!(config.iroh.bind_port, 11204);
    assert!(config.validation.required_attributes.is_empty());
    assert!(!config.validation.assertion.enabled);
}

#[test]
fn test_parse_full_config() {
    let toml_str = r#"
[iroh]
bind_port = 9999
secret_key_path = "/tmp/test.key"

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
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.iroh.bind_port, 9999);
    assert_eq!(config.iroh.secret_key_path, "/tmp/test.key");
    assert_eq!(config.s3.prefix, "blobs/");
    assert_eq!(config.validation.required_attributes.len(), 1);
    assert!(config.validation.assertion.enabled);
    assert_eq!(config.validation.assertion.trusted_public_keys.len(), 2);
}
