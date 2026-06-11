use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub iroh: IrohConfig,
    pub s3: S3Config,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub http: HttpConfig,
}

#[derive(Debug, Deserialize)]
pub struct IrohConfig {
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default = "default_secret_key_param")]
    pub secret_key_param: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            bind_port: default_bind_port(),
            secret_key_param: default_secret_key_param(),
            data_dir: default_data_dir(),
        }
    }
}

fn default_bind_port() -> u16 {
    11204
}

fn default_secret_key_param() -> String {
    "/tdf-iroh-s3/node-secret-key".to_string()
}

fn default_data_dir() -> String {
    "/var/lib/tdf-iroh-s3/data".to_string()
}

#[derive(Debug, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub prefix: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ValidationConfig {
    #[serde(default)]
    pub required_attributes: Vec<String>,
    #[serde(default)]
    pub assertion: AssertionConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct AssertionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub trusted_public_keys: Vec<String>,
}

/// HTTP tag API (catalog discovery). Disabled unless `[http]` is configured
/// with `enabled = true` and a `cose_keys_url` to verify tag-write CWTs
/// against (identity.arkavo.net's `/.well-known/cose-keys`).
#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_http_bind_port")]
    pub bind_port: u16,
    #[serde(default)]
    pub cose_keys_url: String,
    /// Required `iss` claim on tag-write CWTs (e.g.
    /// "https://identity.arkavo.net"). Empty disables the issuer check —
    /// any token signed by a key in the key set is accepted.
    #[serde(default)]
    pub expected_issuer: String,
    #[serde(default = "default_tag_prefix")]
    pub tag_prefix: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_port: default_http_bind_port(),
            cose_keys_url: String::new(),
            expected_issuer: String::new(),
            tag_prefix: default_tag_prefix(),
        }
    }
}

fn default_http_bind_port() -> u16 {
    8090
}

fn default_tag_prefix() -> String {
    "catalog/".to_string()
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
