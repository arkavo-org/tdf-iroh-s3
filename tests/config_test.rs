use tdf_iroh_s3::config::Config;

#[test]
fn test_config_default_data_dir() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.iroh.data_dir, "/var/lib/tdf-iroh-s3/data");
}

#[test]
fn test_config_custom_data_dir() {
    let toml_str = r#"
[iroh]
data_dir = "/tmp/my-data"

[s3]
bucket = "test-bucket"
region = "us-east-1"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.iroh.data_dir, "/tmp/my-data");
}

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
    assert_eq!(
        config.validation.max_blob_bytes,
        tdf_iroh_s3::config::DEFAULT_MAX_BLOB_BYTES
    );
    assert_eq!(tdf_iroh_s3::config::DEFAULT_MAX_BLOB_BYTES, 4_294_967_295);
}

#[test]
fn test_max_blob_bytes_is_configurable() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"

[validation]
max_blob_bytes = 1048576
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.validation.max_blob_bytes, 1_048_576);
    assert!(config.validation.required_attributes.is_empty());
}

#[test]
fn test_parse_full_config() {
    let toml_str = r#"
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
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.iroh.bind_port, 9999);
    assert_eq!(config.iroh.secret_key_param, "/my-app/node-secret-key");
    assert_eq!(config.s3.prefix, "blobs/");
    assert_eq!(config.validation.required_attributes.len(), 1);
    assert!(config.validation.assertion.enabled);
    assert_eq!(config.validation.assertion.trusted_public_keys.len(), 2);
}

#[test]
fn test_authz_client_secret_param_defaults() {
    // Unset ⇒ the node-secret-key-style SSM default, so the production path
    // works without an explicit config line.
    let toml_str = r#"
[s3]
bucket = "b"
region = "us-east-1"

[catalog.authz]
endpoint = "https://platform.arkavo.net"
token_url = "https://identity.arkavo.net/oauth/token"
client_id = "catalog-node"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(
        config.catalog.authz.client_secret_param,
        "/tdf-iroh-s3/catalog-authz-client-secret"
    );
    assert!(config.catalog.authz.client_secret.is_empty());
    assert_eq!(config.catalog.authz.protocol, "authzen");
}

#[test]
fn test_authz_client_secret_param_override() {
    let toml_str = r#"
[s3]
bucket = "b"
region = "us-east-1"

[catalog.authz]
client_secret_param = "/custom/path"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.catalog.authz.client_secret_param, "/custom/path");
}

#[test]
fn test_publishing_defaults_to_gated() {
    let config: Config = toml::from_str("[s3]\nbucket = \"b\"\nregion = \"us-east-1\"\n").unwrap();
    let p = &config.publishing;
    assert!(p.required);
    assert_eq!(
        p.entitlement,
        "https://patreon.arkavo.com/attr/arkavo-creator/value/publish"
    );
    assert_eq!(p.audience, "arkavo");
    assert_eq!(p.session_ttl_secs, 900);
    assert!(p.operator_client_ids.is_empty());
}

#[test]
fn test_publishing_config() {
    let toml_str = r#"
[s3]
bucket = "b"
region = "us-east-1"

[publishing]
required = false
operator_client_ids = ["moderation"]
session_ttl_secs = 60
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(!config.publishing.required);
    assert_eq!(config.publishing.operator_client_ids, vec!["moderation"]);
    assert_eq!(config.publishing.session_ttl_secs, 60);
}

#[test]
fn test_config_http_tls_defaults() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"

[http.tls]
cert_path = "/etc/tdf-iroh-s3/tls/fullchain.pem"
key_path = "/etc/tdf-iroh-s3/tls/privkey.pem"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    let tls = config.http.tls.expect("tls section");
    assert_eq!(tls.bind_port, 443);
    assert_eq!(tls.reload_check_secs, 60);
    assert!(tls.acm_certificate_arn.is_empty());
}

#[test]
fn test_config_http_tls_absent_by_default() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.http.tls.is_none());
}

#[test]
fn test_s3_compatible_endpoint() {
    let toml_str = r#"
[s3]
bucket = "test-bucket"
region = "us-east-1"
endpoint_url = "http://127.0.0.1:4566"
force_path_style = true
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.s3.endpoint_url, "http://127.0.0.1:4566");
    assert!(config.s3.force_path_style);

    let config: Config = toml::from_str("[s3]\nbucket = \"b\"\nregion = \"r\"\n").unwrap();
    assert!(config.s3.endpoint_url.is_empty());
    assert!(!config.s3.force_path_style);
}

#[test]
fn test_public_addresses_and_http_bind_address() {
    let toml_str = r#"
[iroh]
public_addresses = ["3.91.18.97:11204", "[2001:db8::1]:11204"]

[s3]
bucket = "test-bucket"
region = "us-east-1"

[http]
enabled = true
bind_address = "127.0.0.1"
"#;
    let config: Config = toml::from_str(toml_str).unwrap();
    let addrs: Vec<String> = config
        .iroh
        .public_addresses
        .iter()
        .map(|a| a.to_string())
        .collect();
    assert_eq!(addrs, ["3.91.18.97:11204", "[2001:db8::1]:11204"]);
    assert_eq!(config.http.bind_address.to_string(), "127.0.0.1");

    let config: Config = toml::from_str("[s3]\nbucket = \"b\"\nregion = \"r\"\n").unwrap();
    assert!(config.iroh.public_addresses.is_empty());
    assert_eq!(config.http.bind_address.to_string(), "0.0.0.0");

    // An address without a port is refused at load.
    let bad = "[iroh]\npublic_addresses = [\"3.91.18.97\"]\n[s3]\nbucket = \"b\"\nregion = \"r\"\n";
    assert!(toml::from_str::<Config>(bad).is_err());
}

#[test]
fn test_max_concurrent_ingests_defaults_to_one_and_refuses_zero() {
    let base = "[s3]\nbucket = \"b\"\nregion = \"r\"\n";
    let config: Config = toml::from_str(base).unwrap();
    assert_eq!(config.validation.max_concurrent_ingests.get(), 1);

    let config: Config =
        toml::from_str(&format!("{base}[validation]\nmax_concurrent_ingests = 3\n")).unwrap();
    assert_eq!(config.validation.max_concurrent_ingests.get(), 3);

    assert!(
        toml::from_str::<Config>(&format!("{base}[validation]\nmax_concurrent_ingests = 0\n"))
            .is_err()
    );
}
