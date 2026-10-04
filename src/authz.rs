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
use serde_json::{Map, Value, json};
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

/// PEP↔PDP decision protocol. Default is AuthZEN; `opentdf-v2` is rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthzProtocol {
    OpentdfV2,
    #[default]
    Authzen,
}

impl std::str::FromStr for AuthzProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "authzen" | "" => Ok(AuthzProtocol::Authzen),
            "opentdf-v2" => Ok(AuthzProtocol::OpentdfV2),
            other => Err(format!("invalid protocol {other:?} (opentdf-v2|authzen)")),
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
        service_bearer(&self.http, &self.credential, &self.token_cache).await
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

async fn service_bearer(
    http: &reqwest::Client,
    credential: &ServiceCredential,
    cache: &tokio::sync::Mutex<Option<CachedToken>>,
) -> Result<Option<String>> {
    let (token_url, client_id, client_secret) = match credential {
        ServiceCredential::None => return Ok(None),
        ServiceCredential::Static(token) => return Ok(Some(token.clone())),
        ServiceCredential::ClientCredentials {
            token_url,
            client_id,
            client_secret,
        } => (token_url, client_id, client_secret),
    };

    let mut cache = cache.lock().await;
    if let Some(cached) = cache.as_ref()
        && std::time::Instant::now() < cached.expires_at
    {
        return Ok(Some(cached.token.clone()));
    }

    let resp = http
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

/// AuthZEN Access Evaluations client. `endpoint` is the PDP base URL.
pub struct AuthZenClient {
    endpoint: String,
    credential: ServiceCredential,
    http: reqwest::Client,
    token_cache: tokio::sync::Mutex<Option<CachedToken>>,
    /// Process-lifetime cache of `access_evaluations_endpoint`. A PDP that
    /// rotates the URL fails closed until restart.
    evaluations_url: tokio::sync::Mutex<Option<String>>,
}

impl AuthZenClient {
    pub fn new(endpoint: String, credential: ServiceCredential) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            credential,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
            token_cache: tokio::sync::Mutex::new(None),
            evaluations_url: tokio::sync::Mutex::new(None),
        }
    }

    async fn bearer(&self) -> Result<Option<String>> {
        service_bearer(&self.http, &self.credential, &self.token_cache).await
    }

    async fn evaluations_endpoint(&self) -> Result<String> {
        {
            let cached = self.evaluations_url.lock().await;
            if let Some(url) = cached.as_ref() {
                return Ok(url.clone());
            }
        }
        let well_known = format!("{}/.well-known/authzen-configuration", self.endpoint);
        let resp = self
            .http
            .get(&well_known)
            .send()
            .await
            .with_context(|| format!("AuthZEN discovery GET {well_known}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("AuthZEN discovery returned {}", resp.status());
        }
        let disc: AuthzenDiscovery = resp.json().await.context("AuthZEN discovery JSON")?;
        let url = disc
            .access_evaluations_endpoint
            .filter(|s| !s.is_empty())
            .context("discovery missing access_evaluations_endpoint")?;
        // The service CWT is posted to this URL, so it must stay on the
        // configured PDP's origin; a spoofed or misconfigured discovery
        // document is an error, not a redirect.
        anyhow::ensure!(
            same_origin(&url, &self.endpoint),
            "discovered access_evaluations_endpoint {url} is not on {}",
            self.endpoint
        );
        *self.evaluations_url.lock().await = Some(url.clone());
        Ok(url)
    }
}

/// The facade's per-request evaluation limit (arkavo-rs `MAX_EVALUATIONS`).
pub(crate) const MAX_EVALUATIONS: usize = 500;

/// Whether `url` has the same scheme, host and port as `base`.
fn same_origin(url: &str, base: &str) -> bool {
    match (reqwest::Url::parse(url), reqwest::Url::parse(base)) {
        (Ok(u), Ok(b)) => {
            u.scheme() == b.scheme()
                && u.host_str() == b.host_str()
                && u.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

#[derive(Deserialize)]
struct AuthzenDiscovery {
    #[serde(default)]
    access_evaluations_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct EvaluationsResponse {
    #[serde(default)]
    evaluations: Vec<EvaluationEntry>,
}

#[derive(Deserialize)]
struct EvaluationEntry {
    #[serde(default)]
    decision: bool,
    #[serde(default)]
    context: Option<Value>,
}

impl DecisionProvider for AuthZenClient {
    async fn decide(&self, req: DecisionRequest) -> Result<Decisions> {
        if req.resources.is_empty() {
            return Ok(HashMap::new());
        }
        let url = self.evaluations_endpoint().await?;
        // The facade refuses more than MAX_EVALUATIONS per request, so a
        // large group is decided in batches and merged.
        let mut decisions = HashMap::with_capacity(req.resources.len());
        for chunk in req.resources.chunks(MAX_EVALUATIONS) {
            let part = DecisionRequest {
                chain: req.chain.clone(),
                action: req.action.clone(),
                resources: chunk.to_vec(),
            };
            decisions.extend(self.decide_batch(&url, &part).await?);
        }
        Ok(decisions)
    }
}

impl AuthZenClient {
    async fn decide_batch(&self, url: &str, req: &DecisionRequest) -> Result<Decisions> {
        let body = build_authzen_request(req)?;

        let mut http_req = self
            .http
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body);
        if let Some(token) = self.bearer().await? {
            http_req = http_req.bearer_auth(token);
        }

        let resp = http_req
            .send()
            .await
            .with_context(|| format!("AuthZEN POST {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            warn!(%status, "AuthZEN evaluations rejected");
            anyhow::bail!("AuthZEN evaluations returned {status}");
        }
        let parsed: EvaluationsResponse = resp.json().await.context("AuthZEN response JSON")?;
        Ok(map_evaluations(&req.resources, &parsed.evaluations))
    }
}

pub(crate) fn build_authzen_request(req: &DecisionRequest) -> Result<Value> {
    let pe = req
        .chain
        .iter()
        .find(|e| e.is_subject)
        .context("decision request has no subject entity")?;
    anyhow::ensure!(
        !req.resources.is_empty(),
        "empty resources must not be posted"
    );

    let devices: Vec<&ChainEntity> = req
        .chain
        .iter()
        .filter(|e| !e.is_subject && e.token.is_some())
        .collect();
    let environment = req
        .chain
        .iter()
        .find(|e| !e.is_subject && e.token.is_none());

    let mut context = Map::new();
    match devices.len() {
        0 => {}
        1 => {
            context.insert("device".into(), allowlist_device(&devices[0].claims));
        }
        _ => {
            context.insert(
                "devices".into(),
                Value::Array(
                    devices
                        .iter()
                        .map(|d| allowlist_device(&d.claims))
                        .collect(),
                ),
            );
        }
    }
    if let Some(env) = environment {
        context.insert("environment".into(), allowlist_environment(&env.claims));
    }
    context.insert("pep".into(), json!({ "fulfillable_obligation_fqns": [] }));

    Ok(json!({
        "subject": authzen_subject(pe),
        "action": { "name": req.action },
        "context": context,
        "evaluations": req.resources.iter().map(|(id, fqns)| json!({
            "resource": {
                "type": "catalog_item",
                "id": id,
                "properties": { "attribute_value_fqns": fqns },
            }
        })).collect::<Vec<_>>(),
        "options": { "evaluations_semantic": "execute_all" },
    }))
}

fn authzen_subject(pe: &ChainEntity) -> Value {
    let mut properties = Map::new();
    insert_claim(&mut properties, &pe.claims, "iss");
    insert_claim(&mut properties, &pe.claims, "email");
    insert_claim(&mut properties, &pe.claims, "email_verified");
    insert_claim(&mut properties, &pe.claims, "idp");
    insert_claim(&mut properties, &pe.claims, "arkavo_account_id");
    insert_claim(&mut properties, &pe.claims, "arkavo_roles");
    insert_claim(&mut properties, &pe.claims, "arkavo_entitlements");
    insert_claim(&mut properties, &pe.claims, "client_id");
    if let Some(p) = pe.claims.get("arkavo_patreon") {
        properties.insert("arkavo_patreon".into(), sanitize_patreon(p));
    }
    json!({
        "type": "identity",
        "id": pe.claims.get("sub").cloned().unwrap_or(Value::Null),
        "properties": properties,
    })
}

fn insert_claim(out: &mut Map<String, Value>, claims: &Value, key: &str) {
    if let Some(v) = claims.get(key) {
        out.insert(key.into(), v.clone());
    }
}

fn allowlist_device(claims: &Value) -> Value {
    json!({
        "sub": claims.get("sub").and_then(Value::as_str).unwrap_or(""),
        "iss": claims.get("iss").and_then(Value::as_str).unwrap_or(""),
        "aud": claims.get("aud").and_then(Value::as_str).unwrap_or(""),
        "kid": claims.get("kid").and_then(Value::as_str).unwrap_or(""),
    })
}

fn allowlist_environment(claims: &Value) -> Value {
    let mut out = Map::new();
    if let Some(map) = claims.as_object() {
        if let Some(r) = map.get("region") {
            out.insert("region".into(), r.clone());
        }
        if let Some(k) = map.get("kind") {
            out.insert("kind".into(), k.clone());
        }
    }
    Value::Object(out)
}

/// Fields of `arkavo_patreon` that may reach the PDP: an allowlist, so
/// anything an issuer adds later (tokens, e-mail) is dropped. Mirrors the
/// facade's `cwt_subject::sanitize_patreon`.
const PATREON_ALLOWED: [&str; 5] = [
    "role",
    "patreon_user_id",
    "memberships",
    "verified_at",
    "cache_expires_at",
];

fn sanitize_patreon(p: &Value) -> Value {
    let Some(obj) = p.as_object() else {
        return Value::Object(Map::new());
    };
    let mut out = Map::new();
    for k in PATREON_ALLOWED {
        if let Some(v) = obj.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    // Only a creator may carry campaign_id.
    if obj.get("role").and_then(Value::as_str) == Some("creator")
        && let Some(v) = obj.get("campaign_id")
    {
        out.insert("campaign_id".into(), v.clone());
    }
    Value::Object(out)
}

fn required_obligations_nonempty(context: Option<&Value>) -> bool {
    match context
        .and_then(|c| c.get("obligations"))
        .and_then(|o| o.get("required"))
    {
        None => false,
        Some(Value::Array(a)) => !a.is_empty(),
        // Present and not an empty array (string, object, bool, …) → fail closed.
        Some(_) => true,
    }
}

pub(crate) fn evaluation_entitled(decision: bool, context: Option<&Value>) -> bool {
    decision && !required_obligations_nonempty(context)
}

fn map_evaluations(
    resources: &[(String, Vec<String>)],
    evaluations: &[EvaluationEntry],
) -> Decisions {
    resources
        .iter()
        .enumerate()
        .map(|(i, (id, _))| {
            let entitled = evaluations
                .get(i)
                .is_some_and(|e| evaluation_entitled(e.decision, e.context.as_ref()));
            (id.clone(), entitled)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(token: &str) -> ChainEntity {
        ChainEntity {
            is_subject: true,
            token: Some(token.to_string()),
            claims: json!({
                "patreon_user_id": "p-1",
                "sub": "arkavo:u1",
                "iss": "https://identity.test",
            }),
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

    fn device(sub: &str, kid: &str) -> ChainEntity {
        ChainEntity {
            is_subject: false,
            token: Some("device-cwt".into()),
            claims: json!({
                "sub": sub,
                "iss": "https://identity.arkavo.net",
                "aud": "arkavo:devicecheck",
                "kid": kid,
                "email": "dropped@example.com",
            }),
        }
    }

    #[test]
    fn authzen_request_two_devices_and_environment_allowlist() {
        let req = DecisionRequest {
            chain: vec![
                pe("pe-cwt"),
                device("550e8400-e29b-41d4-a716-446655440000", "cGhvbmUta2lk"),
                device("550e8400-e29b-41d4-a716-446655440000", "d2F0Y2gta2lk"),
                ChainEntity {
                    is_subject: false,
                    token: None,
                    claims: json!({
                        "region": "us-east-1",
                        "kind": "environment",
                        "sub": "injected",
                        "email": "x@y.z",
                    }),
                },
            ],
            action: "read".into(),
            resources: vec![(
                "aa".repeat(32),
                vec!["https://p.example/attr/tier/value/gold".into()],
            )],
        };
        let body = build_authzen_request(&req).unwrap();
        assert_eq!(body["subject"]["type"], "identity");
        assert_eq!(body["subject"]["id"], "arkavo:u1");
        assert_eq!(
            body["subject"]["properties"]["iss"],
            "https://identity.test"
        );
        assert!(body["context"].get("device").is_none());
        let devices = body["context"]["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0]["kid"], "cGhvbmUta2lk");
        assert_eq!(devices[1]["kid"], "d2F0Y2gta2lk");
        assert!(devices[0].get("email").is_none());
        let env = body["context"]["environment"].as_object().unwrap();
        assert_eq!(env["region"], "us-east-1");
        assert_eq!(env["kind"], "environment");
        assert_eq!(env.len(), 2);
        assert_eq!(
            body["context"]["pep"]["fulfillable_obligation_fqns"],
            json!([])
        );
        assert_eq!(body["options"]["evaluations_semantic"], "execute_all");
        assert_eq!(body["evaluations"][0]["resource"]["type"], "catalog_item");
        assert_eq!(body["evaluations"][0]["resource"]["id"], "aa".repeat(32));
        assert_eq!(body["action"]["name"], "read");
    }

    #[test]
    fn authzen_one_device_uses_context_device() {
        let req = DecisionRequest {
            chain: vec![pe("pe-cwt"), device("arkavo:u1", "cGhvbmUta2lk")],
            action: "read".into(),
            resources: vec![("r".into(), vec![])],
        };
        let body = build_authzen_request(&req).unwrap();
        assert!(body["context"].get("devices").is_none());
        assert_eq!(body["context"]["device"]["kid"], "cGhvbmUta2lk");
    }

    #[test]
    fn authzen_zero_devices_omits_device_fields() {
        let req = DecisionRequest {
            chain: vec![pe("pe-cwt")],
            action: "read".into(),
            resources: vec![("r".into(), vec![])],
        };
        let body = build_authzen_request(&req).unwrap();
        assert!(body["context"].get("device").is_none());
        assert!(body["context"].get("devices").is_none());
    }

    #[test]
    fn permit_empty_obligations_is_entitled() {
        assert!(evaluation_entitled(
            true,
            Some(&json!({ "obligations": { "required": [] } }))
        ));
        assert!(evaluation_entitled(true, None));
    }

    #[test]
    fn permit_nonempty_obligations_is_not_entitled() {
        assert!(!evaluation_entitled(
            true,
            Some(&json!({ "obligations": { "required": ["https://example/attr/x"] } }))
        ));
        // Present but not an empty array → fail closed (confused-PDP / non-array).
        assert!(!evaluation_entitled(
            true,
            Some(&json!({ "obligations": { "required": "https://example/attr/x" } }))
        ));
        assert!(!evaluation_entitled(
            true,
            Some(&json!({ "obligations": { "required": { "fqn": "x" } } }))
        ));
    }

    #[test]
    fn decision_false_is_not_entitled() {
        assert!(!evaluation_entitled(
            false,
            Some(&json!({ "obligations": { "required": [] } }))
        ));
    }

    #[test]
    fn authzen_empty_resources_is_an_error() {
        let req = DecisionRequest {
            chain: vec![pe("pe-cwt")],
            action: "read".into(),
            resources: vec![],
        };
        assert!(build_authzen_request(&req).is_err());
    }

    /// A PDP that answers `decision: true` for every evaluation and counts
    /// requests; its discovery document names `evaluations_url`.
    async fn spawn_pdp(
        evaluations_url: Option<String>,
        calls: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> String {
        use axum::routing::{get, post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let eval = evaluations_url.unwrap_or_else(|| format!("{base}/access/v1/evaluations"));
        let app = axum::Router::new()
            .route(
                "/.well-known/authzen-configuration",
                get(move || {
                    let eval = eval.clone();
                    async move { axum::Json(json!({ "access_evaluations_endpoint": eval })) }
                }),
            )
            .route(
                "/access/v1/evaluations",
                post(move |axum::Json(body): axum::Json<Value>| {
                    let calls = std::sync::Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let n = body["evaluations"].as_array().map_or(0, Vec::len);
                        assert!(n <= MAX_EVALUATIONS, "batch of {n}");
                        axum::Json(json!({
                            "evaluations": (0..n).map(|_| json!({ "decision": true })).collect::<Vec<_>>()
                        }))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    fn many(n: usize) -> DecisionRequest {
        DecisionRequest {
            chain: vec![pe("tok")],
            action: "read".into(),
            resources: (0..n).map(|i| (format!("h{i}"), vec![])).collect(),
        }
    }

    #[tokio::test]
    async fn large_groups_are_decided_in_batches() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let base = spawn_pdp(None, std::sync::Arc::clone(&calls)).await;
        let client = AuthZenClient::new(base, ServiceCredential::None);
        let d = client.decide(many(1_201)).await.unwrap();
        assert_eq!(d.len(), 1_201);
        assert!(d.values().all(|&v| v));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_discovered_endpoint_off_origin_is_refused() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let base = spawn_pdp(
            Some("https://evil.example/access/v1/evaluations".into()),
            std::sync::Arc::clone(&calls),
        )
        .await;
        let client = AuthZenClient::new(base, ServiceCredential::Static("svc".into()));
        assert!(client.decide(many(1)).await.is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn origin_comparison() {
        assert!(same_origin("https://p.test/a", "https://p.test"));
        assert!(same_origin("https://p.test:443/a", "https://p.test"));
        assert!(!same_origin("http://p.test/a", "https://p.test"));
        assert!(!same_origin("https://p.test:8443/a", "https://p.test"));
        assert!(!same_origin("https://q.test/a", "https://p.test"));
        assert!(!same_origin("not a url", "https://p.test"));
    }

    #[test]
    fn patreon_claim_is_allowlisted() {
        let p = json!({
            "role": "consumer",
            "patreon_user_id": "1",
            "campaign_id": "c",
            "memberships": [],
            "access_token": "secret",
        });
        let out = sanitize_patreon(&p);
        assert!(out.get("access_token").is_none());
        assert!(out.get("campaign_id").is_none());
        assert_eq!(out["patreon_user_id"], "1");
        let mut creator = p.clone();
        creator["role"] = json!("creator");
        assert_eq!(sanitize_patreon(&creator)["campaign_id"], "c");
        assert_eq!(sanitize_patreon(&json!("x")), json!({}));
    }
}
