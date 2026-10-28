use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
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
    #[serde(default)]
    pub publishing: PublishingConfig,
}

/// Creator publishing gate and moderation (tdf-iroh-s3#17). On by default:
/// pushes need a publish session and tag writes need the entitlement.
#[derive(Debug, Deserialize)]
pub struct PublishingConfig {
    /// `false` restores open pushes and tag writes (development only).
    #[serde(default = "default_true")]
    pub required: bool,
    /// Entitlement required in the publisher CWT's `arkavo_entitlements`.
    #[serde(default = "default_publish_entitlement")]
    pub entitlement: String,
    /// Required `aud` on publisher CWTs (identity.arkavo.net passkey tokens
    /// carry `arkavo`). Empty disables the audience check.
    #[serde(default = "default_publisher_audience")]
    pub audience: String,
    /// How long a publish session lets an iroh endpoint push.
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    /// Service client IDs (`sub = client:<id>`) allowed to suspend creators
    /// and block content. Empty disables the operator API (503).
    #[serde(default)]
    pub operator_client_ids: Vec<String>,
    /// How often moderation records are re-read from S3.
    #[serde(default = "default_moderation_refresh_secs")]
    pub moderation_refresh_secs: u64,
    /// Who decides whether a subject may publish (tdf-iroh-s3#35):
    /// `local` (this node, from the CWT), `shadow` (both; the local answer
    /// is enforced and every disagreement logged) or `pdp` (the platform's
    /// decision service, through `[catalog.authz]`, failing closed).
    #[serde(default)]
    pub decisions: PublishDecisions,
}

/// `[publishing] decisions`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublishDecisions {
    #[default]
    Local,
    Shadow,
    Pdp,
}

impl Default for PublishingConfig {
    fn default() -> Self {
        Self {
            required: true,
            entitlement: default_publish_entitlement(),
            audience: default_publisher_audience(),
            session_ttl_secs: default_session_ttl_secs(),
            operator_client_ids: Vec::new(),
            moderation_refresh_secs: default_moderation_refresh_secs(),
            decisions: PublishDecisions::Local,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_publish_entitlement() -> String {
    crate::moderation::DEFAULT_PUBLISH_ENTITLEMENT.to_string()
}

fn default_publisher_audience() -> String {
    "arkavo".to_string()
}

fn default_session_ttl_secs() -> u64 {
    900
}

fn default_moderation_refresh_secs() -> u64 {
    30
}

/// `[catalog]`: holds only `[catalog.authz]`, the decision service the
/// catalog v2 reads and the publish decisions ask. The
/// ingest-time campaign listing it once configured is gone; its keys
/// (`enabled`, `group_attribute_fqn`, `attributes_url`, `attributes_file`,
/// `cache_ttl_secs`) are ignored.
#[derive(Debug, Default, Deserialize)]
pub struct CatalogConfig {
    #[serde(default)]
    pub authz: AuthzConfig,
}

/// OpenTDF authorization service used for catalog and publish decisions.
/// Empty endpoint ⇒ fail closed (nothing entitled).
#[derive(Debug, Deserialize)]
pub struct AuthzConfig {
    /// Base URL of the platform, e.g. "https://platform.arkavo.net".
    #[serde(default)]
    pub endpoint: String,
    /// Action evaluated per resource.
    #[serde(default = "default_authz_action")]
    pub action: String,
    /// OAuth client_credentials against the IdP token endpoint — the
    /// production credential. The node mints and refreshes its own
    /// short-lived service CWT (the platform requires an authenticated
    /// caller, and access tokens live ~1h, so a static token would
    /// silently fail-close the catalog after an hour). All three must be
    /// set together.
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// SSM Parameter Store name holding the `client_credentials` secret as a
    /// `SecureString`. Used only when `client_secret` (TOML) and the
    /// `CATALOG_AUTHZ_CLIENT_SECRET` env var are both empty, mirroring the
    /// node-secret-key load path (`secret_key.rs`) so the long-lived
    /// credential never sits in the config file or IMDS-readable user-data.
    /// Loaded (decrypted) at startup via the instance role.
    #[serde(default = "default_authz_client_secret_param")]
    pub client_secret_param: String,
    /// Static bearer token override (tests / externally rotated
    /// credentials). Ignored when client_credentials is configured.
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
    /// Decision protocol: `"authzen"` (default, AuthZEN Access Evaluations
    /// after well-known discovery) or `"opentdf-v2"` (ConnectRPC JSON
    /// GetDecisionMultiResource). `opentdf-v2` is rollback only.
    #[serde(default = "default_authz_protocol")]
    pub protocol: String,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            action: default_authz_action(),
            token_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            client_secret_param: default_authz_client_secret_param(),
            bearer_token: String::new(),
            environment_region: String::new(),
            entity_mode: String::new(),
            protocol: default_authz_protocol(),
        }
    }
}

fn default_authz_action() -> String {
    "read".to_string()
}

fn default_authz_protocol() -> String {
    "authzen".to_string()
}

fn default_authz_client_secret_param() -> String {
    "/tdf-iroh-s3/catalog-authz-client-secret".to_string()
}

#[derive(Debug, Deserialize)]
pub struct IrohConfig {
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default = "default_secret_key_param")]
    pub secret_key_param: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Public `ip:port` addresses peers can dial directly, reported by
    /// `GET /node` as `directAddresses` (for example the instance's elastic
    /// IP and the iroh port). The node cannot discover these itself behind
    /// NAT. Empty by default.
    #[serde(default)]
    pub public_addresses: Vec<SocketAddr>,
    /// How often the store's garbage collector deletes staged pushes that
    /// ingest is done with (it runs only while some are stored). Seconds;
    /// default 60.
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,
    /// A push whose connection receives less than 64 KiB in this many
    /// seconds is stalled: the node closes it, so a dead link or a peer
    /// that stops sending does not hold the push open. Default 120.
    #[serde(default = "default_push_stall_secs")]
    pub push_stall_secs: u64,
}

fn default_gc_interval_secs() -> u64 {
    60
}

fn default_push_stall_secs() -> u64 {
    120
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            bind_port: default_bind_port(),
            secret_key_param: default_secret_key_param(),
            data_dir: default_data_dir(),
            public_addresses: Vec::new(),
            gc_interval_secs: default_gc_interval_secs(),
            push_stall_secs: default_push_stall_secs(),
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
    /// An S3-compatible endpoint such as LocalStack or MinIO
    /// (`http://127.0.0.1:4566`). Empty uses AWS, or `AWS_ENDPOINT_URL_S3` /
    /// `AWS_ENDPOINT_URL` when set.
    #[serde(default)]
    pub endpoint_url: String,
    /// Put the bucket in the request path instead of the host name. Most
    /// S3-compatible endpoints need this; AWS does not.
    #[serde(default)]
    pub force_path_style: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationConfig {
    #[serde(default)]
    pub required_attributes: Vec<String>,
    #[serde(default)]
    pub assertion: AssertionConfig,
    /// Pushed blobs larger than this many bytes are refused. Ingest reads
    /// the blob from a file, so memory does not bound this; disk does (see
    /// Deploy in the README).
    #[serde(default = "default_max_blob_bytes")]
    pub max_blob_bytes: u64,
    /// How many pushed blobs are validated and uploaded at once. Each one in
    /// progress holds a copy of the blob on disk (none when the filesystem
    /// supports reflinks). At least 1; default 1.
    #[serde(default = "default_max_concurrent_ingests")]
    pub max_concurrent_ingests: NonZeroUsize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            required_attributes: Vec::new(),
            assertion: AssertionConfig::default(),
            max_blob_bytes: default_max_blob_bytes(),
            max_concurrent_ingests: default_max_concurrent_ingests(),
        }
    }
}

fn default_max_concurrent_ingests() -> NonZeroUsize {
    NonZeroUsize::MIN
}

/// The largest `payloadSize` a creator catalog may name.
pub const DEFAULT_MAX_BLOB_BYTES: u64 = crate::creator_catalog::MAX_PAYLOAD_SIZE;

fn default_max_blob_bytes() -> u64 {
    DEFAULT_MAX_BLOB_BYTES
}

#[derive(Debug, Clone, Default, Deserialize)]
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
    /// Listen address of the plain listener without `[http.tls]`:
    /// `127.0.0.1` when a TLS proxy on the same host fronts the API; the
    /// default `0.0.0.0` listens on every interface. With `[http.tls]` the
    /// plain listener is always `127.0.0.1`.
    #[serde(default = "default_http_bind_address")]
    pub bind_address: IpAddr,
    #[serde(default = "default_http_bind_port")]
    pub bind_port: u16,
    #[serde(default)]
    pub cose_keys_url: String,
    /// Required `iss` claim on tag-write CWTs (e.g.
    /// "https://identity.arkavo.net"). Empty disables the issuer check —
    /// any token signed by a key in the key set is accepted.
    #[serde(default)]
    pub expected_issuer: String,
    /// HTTPS listener. When set, the node terminates TLS itself and the
    /// plain listener on `bind_port` binds to loopback only.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// WebAuthn relying party ID creators sign catalog v2 pointers with;
    /// the origin is `https://<rp id>`.
    #[serde(default = "default_passkey_rp_id")]
    pub passkey_rp_id: String,
    /// The IdP's passkey credential status route, with `{credentialId}`
    /// (unpadded base64url) in it. Catalog v2 publishes are refused for a
    /// revoked or unknown credential. Empty skips the check (development
    /// only).
    #[serde(default = "default_passkey_status_url")]
    pub passkey_status_url: String,
}

/// TLS for the HTTP API, terminated by the node (rustls, TLS 1.3 only). The
/// PEM cert chain and key are read from disk and reloaded when either file
/// changes; on EC2 `tdf-iroh-s3-cert-sync` keeps them current from ACM.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_https_bind_port")]
    pub bind_port: u16,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Exportable ACM certificate the cert-sync job exports into
    /// `cert_path`/`key_path`. The node itself never calls ACM.
    #[serde(default)]
    pub acm_certificate_arn: String,
    #[serde(default = "default_tls_reload_check_secs")]
    pub reload_check_secs: u64,
}

fn default_https_bind_port() -> u16 {
    443
}

fn default_tls_reload_check_secs() -> u64 {
    60
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_http_bind_address(),
            bind_port: default_http_bind_port(),
            cose_keys_url: String::new(),
            expected_issuer: String::new(),
            tls: None,
            passkey_rp_id: default_passkey_rp_id(),
            passkey_status_url: default_passkey_status_url(),
        }
    }
}

fn default_passkey_rp_id() -> String {
    "identity.arkavo.net".to_string()
}

fn default_passkey_status_url() -> String {
    "https://identity.arkavo.net/passkeys/credentials/{credentialId}/status".to_string()
}

fn default_http_bind_address() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
}

fn default_http_bind_port() -> u16 {
    8090
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
