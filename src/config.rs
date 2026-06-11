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
    #[serde(default)]
    pub catalog: CatalogConfig,
}

/// Catalog (see tdf-iroh-s3#5). When enabled, every ingested blob gets a
/// `catalog-index/<group>/<hash>` entry per value of the grouping attribute
/// found in its policy, and the HTTP listener serves `GET /catalog/{group}`.
/// The extracted manifest is written to `manifests/<hash>` regardless, so
/// future indexing never has to re-download content blobs.
///
/// Attributes are never hardcoded: `attributes_file` points at the
/// OpenTDF-shaped definitions artifact (served publicly on `/attributes`
/// and FQN-resolving `/attr/...` routes), and `group_attribute_fqn` must
/// name an attribute defined in it.
#[derive(Debug, Deserialize)]
pub struct CatalogConfig {
    #[serde(default)]
    pub enabled: bool,
    /// FQN of the attribute whose values become catalog groups (without
    /// `/value/...`), e.g. the Patreon campaign attribute: items labeled
    /// with campaign X are indexed under group X.
    #[serde(default = "default_group_attribute_fqn")]
    pub group_attribute_fqn: String,
    /// Path to the attribute definitions artifact (JSON). Required when
    /// `enabled`; the grouping attribute must be defined in it.
    #[serde(default)]
    pub attributes_file: String,
    /// How long `/catalog/{group}` responses may serve a cached index
    /// listing before re-reading S3.
    #[serde(default = "default_catalog_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    #[serde(default)]
    pub authz: AuthzConfig,
}

impl CatalogConfig {
    /// The FQN prefix that group values are extracted from at ingest.
    pub fn group_attribute_prefix(&self) -> String {
        if self.group_attribute_fqn.is_empty() {
            String::new()
        } else {
            format!("{}/value/", self.group_attribute_fqn.trim_end_matches('/'))
        }
    }
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            group_attribute_fqn: default_group_attribute_fqn(),
            attributes_file: String::new(),
            cache_ttl_secs: default_catalog_cache_ttl_secs(),
            authz: AuthzConfig::default(),
        }
    }
}

fn default_group_attribute_fqn() -> String {
    "https://patreon.arkavo.com/attr/campaign".to_string()
}

fn default_catalog_cache_ttl_secs() -> u64 {
    30
}

/// OpenTDF authorization service used for per-item catalog decisions.
/// Empty endpoint ⇒ fail closed (catalog lists, nothing entitled).
#[derive(Debug, Deserialize)]
pub struct AuthzConfig {
    /// Base URL of the platform, e.g. "https://platform.arkavo.net".
    #[serde(default)]
    pub endpoint: String,
    /// Action evaluated per resource.
    #[serde(default = "default_authz_action")]
    pub action: String,
    /// Optional service bearer token presented to the platform.
    #[serde(default)]
    pub bearer_token: String,
    /// Environment this node asserts as an NPE (e.g. its region). Empty ⇒
    /// no environment entity is appended to chains.
    #[serde(default)]
    pub environment_region: String,
    /// How entities are presented to the authorization service:
    /// "claims" (default) sends an entityChain of claims-bearing entities
    /// built from claims this node extracted from verified CWTs — the
    /// shape the platform's ERS resolves for Arkavo tokens. "token" sends
    /// `entityIdentifier.token` for JWT-issuing IdPs (the platform's ERS
    /// token parser rejects CWTs).
    #[serde(default)]
    pub entity_mode: String,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            action: default_authz_action(),
            bearer_token: String::new(),
            environment_region: String::new(),
            entity_mode: String::new(),
        }
    }
}

fn default_authz_action() -> String {
    "read".to_string()
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
