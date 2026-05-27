use serde::{Deserialize, Deserializer};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub iroh: IrohConfig,
    pub s3: S3Config,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub catalog: CatalogConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub pdp: PdpConfig,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Fail-closed checks for required URL fields. Kept out of serde so that
    /// `toml::from_str` succeeds even when the user hasn't filled them in yet
    /// (tests, partial deploys).
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.auth.cose_keys_url.is_empty() {
            anyhow::bail!("config: auth.cose_keys_url is required");
        }
        if self.auth.issuer.is_empty() {
            anyhow::bail!("config: auth.issuer is required");
        }
        if self.pdp.attribute_defs_url.is_empty() {
            anyhow::bail!("config: pdp.attribute_defs_url is required");
        }
        Ok(())
    }
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

fn default_bind_port() -> u16 { 11204 }
fn default_secret_key_param() -> String { "/tdf-iroh-s3/node-secret-key".to_string() }
fn default_data_dir() -> String { "/var/lib/tdf-iroh-s3/data".to_string() }

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

#[derive(Debug, Deserialize, Clone)]
pub struct CatalogConfig {
    /// Directory holding `events.redb`. Parent must be writable.
    #[serde(default = "default_catalog_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_max_subs_per_peer")]
    pub max_subscriptions_per_peer: u32,
    #[serde(default = "default_max_subs_total")]
    pub max_subscriptions_total: u32,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            data_dir: default_catalog_data_dir(),
            max_subscriptions_per_peer: default_max_subs_per_peer(),
            max_subscriptions_total: default_max_subs_total(),
        }
    }
}

fn default_catalog_data_dir() -> String { "/var/lib/tdf-iroh-s3/catalog".to_string() }
fn default_max_subs_per_peer() -> u32 { 4 }
fn default_max_subs_total() -> u32 { 256 }

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthConfig {
    /// URL of the COSE_KeySet endpoint (`application/cose-key-set+cbor`).
    /// For arkavo: `https://identity.arkavo.net/.well-known/cose-keys`.
    #[serde(default)]
    pub cose_keys_url: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default = "default_refresh_interval_secs", deserialize_with = "nonzero_u64")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: i64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PdpConfig {
    #[serde(default)]
    pub attribute_defs_url: String,
    #[serde(default = "default_refresh_interval_secs", deserialize_with = "nonzero_u64")]
    pub refresh_interval_secs: u64,
}

fn default_refresh_interval_secs() -> u64 { 300 }
fn default_clock_skew_secs() -> i64 { 60 }

fn nonzero_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    use serde::de::Error;
    let v = u64::deserialize(d)?;
    if v == 0 {
        return Err(D::Error::custom("refresh_interval_secs must be > 0"));
    }
    Ok(v)
}
