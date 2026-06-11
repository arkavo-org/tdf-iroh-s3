//! Entitlement decisions for the catalog, delegated to the OpenTDF
//! authorization service (authorization.v2) — this node never evaluates
//! policy locally, so there is exactly one PDP (the platform).
//!
//! Requests are made over ConnectRPC's JSON mapping (a plain HTTP POST of
//! the proto-JSON request — no codegen needed).
//!
//! ## Contract (verified against the platform source)
//!
//! `JustInTimePDP.resolveEntitiesFromEntityChain` round-trips every chain
//! entity through ERS `ResolveEntities`, and the Patreon ERS resolves
//! `Entity_Claims` entities via `resolveFromClaims` (lookup order:
//! `patreon_access_token` → `patreon_user_id` → `email` →
//! `preferred_username`). So the default request shape is an entityChain
//! whose SUBJECT entity carries claims this node extracted from the
//! *verified* PE CWT (`arkavo_patreon.patreon_user_id`, `email`).
//!
//! Two contract facts that shape this client:
//! - `entityIdentifier.token` is parsed by the ERS with a JWT parser —
//!   Arkavo CWTs (CBOR) fail that parse, so token mode only works for
//!   JWT-issuing IdPs (kept available via config for that case).
//! - CATEGORY_ENVIRONMENT entities are *skipped* by the decision flow
//!   (`skipEnvironmentEntities=true`); NPE device/environment entities are
//!   forwarded for forward-compatibility but do not affect decisions yet.
//!
//! Unconfigured ⇒ `DenyAll`: the catalog still lists, nothing is entitled.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::warn;

/// One entity in the chain, ordered PE first.
#[derive(Debug, Clone)]
pub struct ChainEntity {
    /// True for the person entity; false for NPEs (category ENVIRONMENT).
    pub is_subject: bool,
    /// Bearer token (base64url) — used only in token mode, and only for
    /// the subject.
    pub token: Option<String>,
    /// Claims the node asserts for this entity. For the PE these are
    /// extracted from the verified CWT (patreon_user_id, email, sub); for
    /// NPEs they describe the attested device or observed environment.
    pub claims: Value,
}

#[derive(Debug, Clone)]
pub struct DecisionRequest {
    pub chain: Vec<ChainEntity>,
    pub action: String,
    /// (resource id, attribute-value FQNs) per catalog item.
    pub resources: Vec<(String, Vec<String>)>,
}

/// Per-resource verdicts keyed by resource id. Missing id ⇒ treat as deny.
pub type Decisions = HashMap<String, bool>;

pub trait DecisionProvider: Send + Sync + 'static {
    fn decide(&self, req: DecisionRequest) -> impl Future<Output = Result<Decisions>> + Send;
}

/// Fail-closed provider used when no authorization endpoint is configured.
pub struct DenyAll;

impl DecisionProvider for DenyAll {
    async fn decide(&self, req: DecisionRequest) -> Result<Decisions> {
        Ok(req
            .resources
            .into_iter()
            .map(|(id, _)| (id, false))
            .collect())
    }
}

/// How the entity identifier is presented to the authorization service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntityMode {
    /// entityChain of claims-bearing entities, built from claims this node
    /// extracted from *verified* CWTs. The contract-verified default for
    /// Arkavo CWTs.
    #[default]
    Claims,
    /// entityIdentifier.token — the platform ERS parses the token itself.
    /// Only works for JWT-issuing IdPs (the ERS's parser rejects CWTs).
    Token,
}

impl std::str::FromStr for EntityMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "claims" | "" => Ok(EntityMode::Claims),
            "token" => Ok(EntityMode::Token),
            other => Err(format!("invalid entity_mode {other:?} (claims|token)")),
        }
    }
}

/// How this node authenticates to the authorization service. The platform
/// REQUIRES an authenticated caller (the PEP client identity is taken from
/// the verified token), so production uses `ClientCredentials`: the node
/// mints its own short-lived service CWT from the IdP's token endpoint and
/// refreshes before expiry — a static token would silently fail-close the
/// catalog one access-token lifetime (~1h) after boot.
pub enum ServiceCredential {
    /// Fixed bearer string (tests, or externally rotated credentials).
    Static(String),
    /// OAuth client_credentials against the IdP token endpoint.
    ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
    },
    /// No Authorization header (only viable if the platform runs authless —
    /// never true in production).
    None,
}

/// Refresh this long before `expires_in` elapses.
const TOKEN_REFRESH_MARGIN: std::time::Duration = std::time::Duration::from_secs(60);

struct CachedToken {
    token: String,
    expires_at: std::time::Instant,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

/// ConnectRPC-JSON client for authorization.v2.
pub struct ConnectAuthzClient {
    endpoint: String,
    credential: ServiceCredential,
    entity_mode: EntityMode,
    http: reqwest::Client,
    token_cache: tokio::sync::Mutex<Option<CachedToken>>,
}

impl ConnectAuthzClient {
    pub fn new(endpoint: String, credential: ServiceCredential, entity_mode: EntityMode) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            credential,
            entity_mode,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            token_cache: tokio::sync::Mutex::new(None),
        }
    }

    /// The bearer token for the next decision request, minting/refreshing
    /// via client_credentials as needed. The mutex doubles as single-flight:
    /// concurrent refreshes collapse to one IdP round-trip.
    async fn bearer(&self) -> Result<Option<String>> {
        let (token_url, client_id, client_secret) = match &self.credential {
            ServiceCredential::None => return Ok(None),
            ServiceCredential::Static(token) => return Ok(Some(token.clone())),
            ServiceCredential::ClientCredentials {
                token_url,
                client_id,
                client_secret,
            } => (token_url, client_id, client_secret),
        };

        let mut cache = self.token_cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && std::time::Instant::now() < cached.expires_at
        {
            return Ok(Some(cached.token.clone()));
        }

        let resp = self
            .http
            .post(token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
            ])
            .send()
            .await
            .with_context(|| format!("token POST {token_url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            anyhow::bail!("token endpoint returned {status}");
        }
        let parsed: TokenResponse = resp.json().await.context("token JSON parse")?;
        let ttl = std::time::Duration::from_secs(parsed.expires_in.max(120));
        let expires_at = std::time::Instant::now() + ttl.saturating_sub(TOKEN_REFRESH_MARGIN);
        let token = parsed.access_token.clone();
        *cache = Some(CachedToken {
            token: parsed.access_token,
            expires_at,
        });
        tracing::info!(
            ttl_secs = ttl.as_secs(),
            "Minted service token via client_credentials"
        );
        Ok(Some(token))
    }

    /// Build the proto-JSON GetDecisionMultiResource request.
    fn build_request(&self, req: &DecisionRequest) -> Result<Value> {
        let pe = req
            .chain
            .iter()
            .find(|e| e.is_subject)
            .context("decision request has no subject entity")?;

        let entity_identifier = match self.entity_mode {
            EntityMode::Token => {
                let pe_token = pe
                    .token
                    .as_ref()
                    .context("subject entity has no token (entity_mode = token)")?;
                if req.chain.len() > 1 {
                    warn!(
                        dropped = req.chain.len() - 1,
                        "NPE/environment entities not representable in token mode"
                    );
                }
                json!({ "token": { "ephemeralId": "pe", "jwt": pe_token } })
            }
            EntityMode::Claims => {
                // Every chain entity travels as Entity_Claims (an Any-wrapped
                // Struct). The PDP resolves all of them through the ERS;
                // CATEGORY_ENVIRONMENT entries are filtered by the decision
                // flow today and carried for forward-compatibility.
                let entities: Vec<Value> = req
                    .chain
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let category = if e.is_subject {
                            "CATEGORY_SUBJECT"
                        } else {
                            "CATEGORY_ENVIRONMENT"
                        };
                        json!({
                            "ephemeralId": format!("e{i}"),
                            "category": category,
                            "claims": {
                                "@type": "type.googleapis.com/google.protobuf.Struct",
                                "value": e.claims,
                            },
                        })
                    })
                    .collect();
                json!({ "entityChain": { "ephemeralId": "chain", "entities": entities } })
            }
        };

        Ok(json!({
            "entityIdentifier": entity_identifier,
            "action": { "name": req.action },
            "resources": req.resources.iter().map(|(id, fqns)| json!({
                "ephemeralId": id,
                "attributeValues": { "fqns": fqns },
            })).collect::<Vec<_>>(),
        }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultiResourceResponse {
    #[serde(default)]
    resource_decisions: Vec<ResourceDecision>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceDecision {
    #[serde(default)]
    ephemeral_resource_id: String,
    #[serde(default)]
    decision: String,
}

impl DecisionProvider for ConnectAuthzClient {
    async fn decide(&self, req: DecisionRequest) -> Result<Decisions> {
        let url = format!(
            "{}/authorization.v2.AuthorizationService/GetDecisionMultiResource",
            self.endpoint
        );
        let body = self.build_request(&req)?;

        let mut http_req = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body);
        if let Some(token) = self.bearer().await? {
            http_req = http_req.bearer_auth(token);
        }

        let resp = http_req
            .send()
            .await
            .with_context(|| format!("authorization POST {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            warn!(%status, "authorization service rejected decision request");
            anyhow::bail!("authorization service returned {status}: {text}");
        }
        let parsed: MultiResourceResponse = resp
            .json()
            .await
            .context("authorization response JSON parse")?;

        Ok(parsed
            .resource_decisions
            .into_iter()
            .map(|d| (d.ephemeral_resource_id, d.decision == "DECISION_PERMIT"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(token: &str) -> ChainEntity {
        ChainEntity {
            is_subject: true,
            token: Some(token.to_string()),
            claims: json!({ "patreon_user_id": "p-1", "sub": "arkavo:u1" }),
        }
    }

    #[tokio::test]
    async fn deny_all_denies_everything() {
        let req = DecisionRequest {
            chain: vec![],
            action: "read".into(),
            resources: vec![("r1".into(), vec![])],
        };
        let d = DenyAll.decide(req).await.unwrap();
        assert_eq!(d.get("r1"), Some(&false));
    }

    fn client(mode: EntityMode) -> ConnectAuthzClient {
        ConnectAuthzClient::new(
            "https://platform.test".into(),
            ServiceCredential::None,
            mode,
        )
    }

    #[test]
    fn claims_mode_sends_subject_claims_chain() {
        // The contract-verified default: the PE travels as Entity_Claims
        // carrying the identifiers the Patreon ERS resolves
        // (patreon_user_id / email), wrapped as an Any Struct.
        let req = DecisionRequest {
            chain: vec![pe("tok-abc")],
            action: "read".into(),
            resources: vec![(
                "hash1".into(),
                vec!["https://p.example/attr/tier/value/gold".into()],
            )],
        };
        let body = client(EntityMode::Claims).build_request(&req).unwrap();
        let entities = body["entityIdentifier"]["entityChain"]["entities"]
            .as_array()
            .unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0]["category"], "CATEGORY_SUBJECT");
        assert_eq!(
            entities[0]["claims"]["@type"],
            "type.googleapis.com/google.protobuf.Struct"
        );
        assert_eq!(entities[0]["claims"]["value"]["patreon_user_id"], "p-1");
        assert_eq!(body["action"]["name"], "read");
        assert_eq!(body["resources"][0]["ephemeralId"], "hash1");
        assert_eq!(
            body["resources"][0]["attributeValues"]["fqns"][0],
            "https://p.example/attr/tier/value/gold"
        );
    }

    #[test]
    fn token_mode_uses_token_identifier() {
        let req = DecisionRequest {
            chain: vec![pe("tok-abc")],
            action: "read".into(),
            resources: vec![("hash1".into(), vec![])],
        };
        let body = client(EntityMode::Token).build_request(&req).unwrap();
        assert_eq!(body["entityIdentifier"]["token"]["jwt"], "tok-abc");
        assert!(body["entityIdentifier"]["entityChain"].is_null());
    }

    #[test]
    fn token_mode_drops_npes_rather_than_burying_them() {
        // Token mode cannot represent NPEs; they must never be smuggled in
        // a shape the ERS would silently fail to resolve.
        let req = DecisionRequest {
            chain: vec![
                pe("pe-tok"),
                ChainEntity {
                    is_subject: false,
                    token: None,
                    claims: json!({ "region": "us-east-1" }),
                },
            ],
            action: "read".into(),
            resources: vec![("r".into(), vec![])],
        };
        let body = client(EntityMode::Token).build_request(&req).unwrap();
        assert_eq!(body["entityIdentifier"]["token"]["jwt"], "pe-tok");
        assert!(body["entityIdentifier"]["entityChain"].is_null());
    }

    #[test]
    fn request_without_subject_is_an_error() {
        let req = DecisionRequest {
            chain: vec![ChainEntity {
                is_subject: false,
                token: None,
                claims: json!({}),
            }],
            action: "read".into(),
            resources: vec![],
        };
        assert!(client(EntityMode::Claims).build_request(&req).is_err());
    }

    #[test]
    fn chain_with_npes_uses_entity_chain() {
        let req = DecisionRequest {
            chain: vec![
                pe("pe-tok"),
                ChainEntity {
                    is_subject: false,
                    token: Some("npe-tok".into()),
                    claims: json!({ "sub": "arkavo:u1", "kind": "ios-app" }),
                },
                ChainEntity {
                    is_subject: false,
                    token: None,
                    claims: json!({ "region": "us-east-1" }),
                },
            ],
            action: "read".into(),
            resources: vec![("r".into(), vec![])],
        };
        let body = client(EntityMode::Claims).build_request(&req).unwrap();
        let entities = body["entityIdentifier"]["entityChain"]["entities"]
            .as_array()
            .unwrap();
        assert_eq!(entities.len(), 3);
        assert_eq!(entities[0]["category"], "CATEGORY_SUBJECT");
        assert_eq!(entities[1]["category"], "CATEGORY_ENVIRONMENT");
        assert_eq!(entities[2]["claims"]["value"]["region"], "us-east-1");
    }

    /// Token endpoint stub counting mints; returns a 1h token.
    async fn spawn_token_endpoint(counter: std::sync::Arc<std::sync::atomic::AtomicU32>) -> String {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/oauth/token",
            post(move || {
                let counter = std::sync::Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "access_token": "svc-token-1",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/oauth/token")
    }

    #[tokio::test]
    async fn client_credentials_mints_and_caches() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let token_url = spawn_token_endpoint(std::sync::Arc::clone(&counter)).await;
        let client = ConnectAuthzClient::new(
            "https://platform.test".into(),
            ServiceCredential::ClientCredentials {
                token_url,
                client_id: "catalog-node".into(),
                client_secret: "s3cret".into(),
            },
            EntityMode::Claims,
        );

        for _ in 0..3 {
            let tok = client.bearer().await.unwrap();
            assert_eq!(tok.as_deref(), Some("svc-token-1"));
        }
        // 3600s token with 60s margin: one mint serves all three calls.
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn static_and_none_credentials() {
        let c = ConnectAuthzClient::new(
            "https://p.test".into(),
            ServiceCredential::Static("fixed".into()),
            EntityMode::Claims,
        );
        assert_eq!(c.bearer().await.unwrap().as_deref(), Some("fixed"));

        let c = ConnectAuthzClient::new(
            "https://p.test".into(),
            ServiceCredential::None,
            EntityMode::Claims,
        );
        assert!(c.bearer().await.unwrap().is_none());
    }
}
