//! `GET /catalog/{group}` — the entitled catalog (phase 2 of #5).
//!
//! Lists a group's ingested items (from the ingest-time index) and, when
//! the requester presents credentials, annotates each with whether the
//! full entity chain is entitled to it — storefront and "your library"
//! in one response.
//!
//! Entity chain (PE → NPE → NPE):
//! - PE: `Authorization: Bearer <Arkavo CWT>`.
//! - NPE: zero or more `X-Entity-Token: <Arkavo CWT>` headers (attested
//!   app/device tokens). Each must verify and carry the same `sub` as the
//!   PE — mix-and-match chains are rejected.
//! - NPE: the environment this node observes (configured region),
//!   appended server-side; never client-supplied.
//!
//! Decisions are delegated to the OpenTDF authorization service; this
//! node never evaluates policy. Fail-closed everywhere: no credentials,
//! verification failure handling aside (401), or an unreachable PDP all
//! degrade to `entitled: false`, never to access.

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

use crate::auth::CwtVerifier;
use crate::authz::{ChainEntity, DecisionProvider, DecisionRequest};
use crate::catalog::CatalogEntry;

/// Read side of the catalog index. `S3Client` is the production impl.
pub trait CatalogStore: Send + Sync + 'static {
    fn list_group(
        &self,
        group: &str,
    ) -> impl Future<Output = anyhow::Result<Vec<CatalogEntry>>> + Send;
}

impl CatalogStore for crate::store::s3::S3Client {
    async fn list_group(&self, group: &str) -> anyhow::Result<Vec<CatalogEntry>> {
        use futures::StreamExt;
        let hashes = self.list_catalog_hashes(group).await?;
        let mut entries: Vec<CatalogEntry> = futures::stream::iter(hashes)
            .map(|hash| async move {
                match self.get_catalog_entry(group, &hash).await {
                    Ok(Some(bytes)) => match serde_json::from_slice::<CatalogEntry>(&bytes) {
                        Ok(entry) => Some(entry),
                        Err(e) => {
                            warn!(%group, %hash, error = %e, "Unparseable catalog entry");
                            None
                        }
                    },
                    Ok(None) => None,
                    Err(e) => {
                        warn!(%group, %hash, error = %e, "Catalog entry fetch failed");
                        None
                    }
                }
            })
            .buffer_unordered(16)
            .filter_map(std::future::ready)
            .collect()
            .await;
        entries.sort_by_key(|e| std::cmp::Reverse(e.ingested_at));
        Ok(entries)
    }
}

type CachedGroup = (Instant, Arc<Vec<CatalogEntry>>);

/// Bound on distinct cached groups — `/catalog/{group}` is a public GET,
/// so without this an attacker enumerating group names grows the map
/// without limit.
const MAX_CACHED_GROUPS: usize = 1024;

/// Read-through cache over the index so catalog browsing doesn't relist S3
/// on every request. Entries expire after `ttl`; freshness within the TTL
/// is acceptable for a discovery surface. Misses are single-flighted per
/// group (concurrent requests share one S3 listing), the map is bounded,
/// and an S3 failure serves the stale listing rather than a 502.
pub struct CatalogCache<S: CatalogStore> {
    store: Arc<S>,
    ttl: Duration,
    groups: RwLock<HashMap<String, CachedGroup>>,
    refresh_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<S: CatalogStore> CatalogCache<S> {
    pub fn new(store: Arc<S>, ttl: Duration) -> Self {
        Self {
            store,
            ttl,
            groups: RwLock::new(HashMap::new()),
            refresh_locks: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub async fn entries(&self, group: &str) -> anyhow::Result<Arc<Vec<CatalogEntry>>> {
        if let Some(fresh) = self.fresh_hit(group).await {
            return Ok(fresh);
        }

        // Single-flight per group: concurrent misses queue here and the
        // late arrivals find the refreshed entry on the re-check.
        let group_lock = {
            let mut locks = self.refresh_locks.lock().await;
            if locks.len() > MAX_CACHED_GROUPS {
                locks.retain(|_, l| Arc::strong_count(l) > 1);
            }
            Arc::clone(locks.entry(group.to_string()).or_default())
        };
        let _guard = group_lock.lock().await;

        if let Some(fresh) = self.fresh_hit(group).await {
            return Ok(fresh);
        }

        match self.store.list_group(group).await {
            Ok(listing) => {
                let fresh = Arc::new(listing);
                let mut groups = self.groups.write().await;
                groups.insert(group.to_string(), (Instant::now(), Arc::clone(&fresh)));
                Self::evict(&mut groups, self.ttl);
                Ok(fresh)
            }
            Err(e) => {
                // Stale-on-error: a slightly outdated listing beats a 502
                // on a discovery surface that already tolerates TTL lag.
                if let Some((_, stale)) = self.groups.read().await.get(group) {
                    warn!(%group, error = %e, "Index refresh failed; serving stale listing");
                    return Ok(Arc::clone(stale));
                }
                Err(e)
            }
        }
    }

    async fn fresh_hit(&self, group: &str) -> Option<Arc<Vec<CatalogEntry>>> {
        let groups = self.groups.read().await;
        let (at, entries) = groups.get(group)?;
        (at.elapsed() < self.ttl).then(|| Arc::clone(entries))
    }

    fn evict(groups: &mut HashMap<String, CachedGroup>, ttl: Duration) {
        if groups.len() <= MAX_CACHED_GROUPS {
            return;
        }
        groups.retain(|_, (at, _)| at.elapsed() < ttl);
        while groups.len() > MAX_CACHED_GROUPS {
            let Some(oldest) = groups
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            groups.remove(&oldest);
        }
    }
}

pub struct CatalogApiState<S: CatalogStore, D: DecisionProvider> {
    pub cache: CatalogCache<S>,
    pub provider: D,
    pub verifier: Arc<CwtVerifier>,
    pub action: String,
    /// Environment claims this node asserts (e.g. its region). None ⇒ no
    /// environment entity is appended.
    pub environment: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct CatalogItem {
    #[serde(flatten)]
    entry: CatalogEntry,
    entitled: bool,
}

#[derive(Serialize)]
struct CatalogResponse {
    group: String,
    /// "evaluated" | "anonymous" | "unavailable"
    decision: &'static str,
    items: Vec<CatalogItem>,
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
}

fn err(status: StatusCode, error: &'static str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error }))
}

pub fn router<S: CatalogStore, D: DecisionProvider>(state: Arc<CatalogApiState<S, D>>) -> Router {
    Router::new()
        .route("/catalog/{group}", get(get_catalog::<S, D>))
        .with_state(state)
}

fn valid_group(group: &str) -> bool {
    !group.is_empty()
        && group.len() <= 128
        && !group.contains("..")
        && group
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '@'))
}

async fn get_catalog<S: CatalogStore, D: DecisionProvider>(
    State(state): State<Arc<CatalogApiState<S, D>>>,
    Path(group): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CatalogResponse>, (StatusCode, Json<ApiError>)> {
    if !valid_group(&group) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid group"));
    }

    let entries = state.cache.entries(&group).await.map_err(|e| {
        warn!(%group, error = %e, "Catalog listing failed");
        err(StatusCode::BAD_GATEWAY, "storage unavailable")
    })?;

    // Assemble and verify the entity chain. Verification failures are 401 —
    // a presented-but-invalid credential is an error, not anonymity.
    let chain = match build_chain(&state, &headers).await {
        Ok(chain) => chain,
        Err(e) => return Err(e),
    };

    let (decision, verdicts) = match &chain {
        None => ("anonymous", HashMap::new()),
        Some(chain) => {
            let req = DecisionRequest {
                chain: chain.clone(),
                action: state.action.clone(),
                resources: entries
                    .iter()
                    .map(|e| (e.hash.clone(), e.attribute_fqns.clone()))
                    .collect(),
            };
            match state.provider.decide(req).await {
                Ok(verdicts) => ("evaluated", verdicts),
                Err(e) => {
                    warn!(%group, error = %e, "Decision request failed; failing closed");
                    ("unavailable", HashMap::new())
                }
            }
        }
    };

    let items = entries
        .iter()
        .map(|entry| CatalogItem {
            entry: entry.clone(),
            entitled: verdicts.get(&entry.hash).copied().unwrap_or(false),
        })
        .collect();

    Ok(Json(CatalogResponse {
        group,
        decision,
        items,
    }))
}

/// Build the verified entity chain from request headers. `Ok(None)` means
/// anonymous (no credentials at all); NPE tokens without a PE, or any
/// token that fails verification or subject matching, is a 401.
async fn build_chain<S: CatalogStore, D: DecisionProvider>(
    state: &CatalogApiState<S, D>,
    headers: &HeaderMap,
) -> Result<Option<Vec<ChainEntity>>, (StatusCode, Json<ApiError>)> {
    let pe_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let npe_tokens: Vec<&str> = headers
        .get_all("x-entity-token")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    let Some(pe_token) = pe_token else {
        if npe_tokens.is_empty() {
            return Ok(None);
        }
        // NPEs cannot stand alone — there is no chain without a subject.
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "entity tokens require a bearer subject",
        ));
    };

    let now = unix_now();
    let pe = state.verifier.verify(pe_token, now).await.map_err(|e| {
        warn!(error = %e, "PE token verification failed");
        err(StatusCode::UNAUTHORIZED, "invalid token")
    })?;

    // Subject claims for the decision: extracted from the *verified* CWT.
    // Forward the whole arkavo_patreon claim so the platform's
    // claims-passthrough derives campaign-qualified entitlements from the
    // memberships array — this node verified the CWT signature, so the
    // claim is authoritative. iss is included so the platform can pin the
    // materializer's issuer. patreon_user_id/email remain as the ERS's
    // fallback lookup keys.
    let mut subject_claims = serde_json::Map::new();
    subject_claims.insert("sub".into(), pe.sub.clone().into());
    subject_claims.insert("iss".into(), pe.iss.clone().into());
    if let Some(uid) = &pe.patreon_user_id {
        subject_claims.insert("patreon_user_id".into(), uid.clone().into());
    }
    if let Some(email) = &pe.email {
        subject_claims.insert("email".into(), email.clone().into());
    }
    if let Some(patreon) = &pe.arkavo_patreon {
        subject_claims.insert("arkavo_patreon".into(), patreon.clone());
    }
    let mut chain = vec![ChainEntity {
        is_subject: true,
        token: Some(pe_token.to_string()),
        claims: serde_json::Value::Object(subject_claims),
    }];

    for token in npe_tokens {
        let claims = state.verifier.verify(token, now).await.map_err(|e| {
            warn!(error = %e, "NPE token verification failed");
            err(StatusCode::UNAUTHORIZED, "invalid entity token")
        })?;
        // Mix-and-match defense: every NPE must be bound to the same subject.
        if claims.sub != pe.sub {
            warn!(pe_sub = %pe.sub, npe_sub = %claims.sub, "Entity chain subject mismatch");
            return Err(err(
                StatusCode::UNAUTHORIZED,
                "entity token subject does not match bearer subject",
            ));
        }
        chain.push(ChainEntity {
            is_subject: false,
            token: Some(token.to_string()),
            claims: serde_json::json!({ "sub": claims.sub, "iss": claims.iss }),
        });
    }

    // Observed environment: asserted by this node, never client-supplied.
    if let Some(env) = &state.environment {
        chain.push(ChainEntity {
            is_subject: false,
            token: None,
            claims: env.clone(),
        });
    }

    Ok(Some(chain))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::{keypair, mint};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    struct MemCatalog {
        groups: HashMap<String, Vec<CatalogEntry>>,
        fail: std::sync::atomic::AtomicBool,
    }

    impl MemCatalog {
        fn new(groups: HashMap<String, Vec<CatalogEntry>>) -> Self {
            Self {
                groups,
                fail: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl CatalogStore for MemCatalog {
        async fn list_group(&self, group: &str) -> anyhow::Result<Vec<CatalogEntry>> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("simulated S3 outage");
            }
            Ok(self.groups.get(group).cloned().unwrap_or_default())
        }
    }

    /// Permits exactly the hashes it was created with; records the chain
    /// length it saw for assertions.
    struct StubProvider {
        permit: Vec<String>,
        seen_chain_len: std::sync::Mutex<Option<usize>>,
        seen_subject_claims: std::sync::Mutex<Option<serde_json::Value>>,
    }

    impl DecisionProvider for StubProvider {
        async fn decide(&self, req: DecisionRequest) -> anyhow::Result<crate::authz::Decisions> {
            *self.seen_chain_len.lock().unwrap() = Some(req.chain.len());
            if let Some(pe) = req.chain.iter().find(|e| e.is_subject) {
                *self.seen_subject_claims.lock().unwrap() = Some(pe.claims.clone());
            }
            Ok(req
                .resources
                .into_iter()
                .map(|(id, _)| {
                    let ok = self.permit.contains(&id);
                    (id, ok)
                })
                .collect())
        }
    }

    fn entry(hash: &str) -> CatalogEntry {
        CatalogEntry {
            hash: hash.to_string(),
            size: 1,
            attribute_fqns: vec!["https://p.example/attr/tier/value/gold".into()],
            ingested_at: 0,
        }
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    struct Rig {
        router: Router,
        token: String,
        sk: p256::ecdsa::SigningKey,
        state: Arc<CatalogApiState<MemCatalog, StubProvider>>,
    }

    fn rig(permit: Vec<String>, environment: Option<serde_json::Value>) -> Rig {
        let (sk, vk) = keypair();
        let store = Arc::new(MemCatalog::new(HashMap::from([(
            "camp1".to_string(),
            vec![entry(&"aa".repeat(32)), entry(&"bb".repeat(32))],
        )])));
        let state = Arc::new(CatalogApiState {
            cache: CatalogCache::new(store, Duration::from_secs(30)),
            provider: StubProvider {
                permit,
                seen_chain_len: std::sync::Mutex::new(None),
                seen_subject_claims: std::sync::Mutex::new(None),
            },
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            action: "read".into(),
            environment,
        });
        let token = mint(
            &sk,
            b"kid-1",
            "https://i.test",
            "arkavo:u1",
            now(),
            now() + 3600,
        );
        Rig {
            router: router(Arc::clone(&state)),
            token,
            sk,
            state,
        }
    }

    async fn get_json(
        router: &Router,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = router
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn anonymous_lists_with_nothing_entitled() {
        let r = rig(vec!["aa".repeat(32)], None);
        let (status, body) = get_json(&r.router, "/catalog/camp1", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], "anonymous");
        assert_eq!(body["items"].as_array().unwrap().len(), 2);
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["entitled"] == false)
        );
    }

    #[tokio::test]
    async fn forwards_full_arkavo_patreon_claim_to_decision() {
        use crate::auth::test_support::mint_with_extras;
        let r = rig(vec![], None);
        // Mint a PE token carrying a multi-campaign arkavo_patreon claim.
        let patreon = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("role".into()),
                ciborium::value::Value::Text("consumer".into()),
            ),
            (
                ciborium::value::Value::Text("patreon_user_id".into()),
                ciborium::value::Value::Text("p-1".into()),
            ),
            (
                ciborium::value::Value::Text("memberships".into()),
                ciborium::value::Value::Array(vec![ciborium::value::Value::Map(vec![
                    (
                        ciborium::value::Value::Text("campaign_id".into()),
                        ciborium::value::Value::Text("11111111".into()),
                    ),
                    (
                        ciborium::value::Value::Text("patron_status".into()),
                        ciborium::value::Value::Text("active_patron".into()),
                    ),
                    (
                        ciborium::value::Value::Text("tier_slugs".into()),
                        ciborium::value::Value::Array(vec![ciborium::value::Value::Text(
                            "gold-tier".into(),
                        )]),
                    ),
                ])]),
            ),
        ]);
        let token = mint_with_extras(
            &r.sk,
            b"kid-1",
            "https://i.test",
            "arkavo:u1",
            now(),
            now() + 3600,
            &[("arkavo_patreon", patreon)],
        );
        let auth = format!("Bearer {token}");
        let (status, _) = get_json(&r.router, "/catalog/camp1", &[("authorization", &auth)]).await;
        assert_eq!(status, StatusCode::OK);

        // The decision provider saw the full membership in the subject claims.
        let claims = r
            .state
            .provider
            .seen_subject_claims
            .lock()
            .unwrap()
            .clone()
            .expect("subject claims captured");
        assert_eq!(claims["iss"], "https://i.test");
        let ap = &claims["arkavo_patreon"];
        assert_eq!(ap["memberships"][0]["campaign_id"], "11111111");
        assert_eq!(ap["memberships"][0]["tier_slugs"][0], "gold-tier");
    }

    #[tokio::test]
    async fn pe_token_gets_evaluated_entitlements() {
        let r = rig(vec!["aa".repeat(32)], None);
        let auth = format!("Bearer {}", r.token);
        let (status, body) =
            get_json(&r.router, "/catalog/camp1", &[("authorization", &auth)]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], "evaluated");
        let items = body["items"].as_array().unwrap();
        let entitled: HashMap<&str, bool> = items
            .iter()
            .map(|i| {
                (
                    i["hash"].as_str().unwrap(),
                    i["entitled"].as_bool().unwrap(),
                )
            })
            .collect();
        assert!(entitled[&*"aa".repeat(32)]);
        assert!(!entitled[&*"bb".repeat(32)]);
    }

    #[tokio::test]
    async fn npe_with_matching_sub_joins_chain_and_environment_appends() {
        let r = rig(
            vec![],
            Some(json!({ "region": "us-east-1", "kind": "environment" })),
        );
        let npe = mint(
            &r.sk,
            b"kid-1",
            "https://i.test",
            "arkavo:u1",
            now(),
            now() + 3600,
        );
        let auth = format!("Bearer {}", r.token);
        let (status, _) = get_json(
            &r.router,
            "/catalog/camp1",
            &[("authorization", &auth), ("x-entity-token", &npe)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // PE + NPE + environment = 3 entities.
        assert_eq!(*r.state.provider.seen_chain_len.lock().unwrap(), Some(3));
    }

    #[tokio::test]
    async fn npe_sub_mismatch_is_401() {
        let r = rig(vec![], None);
        let npe = mint(
            &r.sk,
            b"kid-1",
            "https://i.test",
            "arkavo:other",
            now(),
            now() + 3600,
        );
        let auth = format!("Bearer {}", r.token);
        let (status, _) = get_json(
            &r.router,
            "/catalog/camp1",
            &[("authorization", &auth), ("x-entity-token", &npe)],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn npe_without_pe_is_401() {
        let r = rig(vec![], None);
        let npe = mint(
            &r.sk,
            b"kid-1",
            "https://i.test",
            "arkavo:u1",
            now(),
            now() + 3600,
        );
        let (status, _) = get_json(&r.router, "/catalog/camp1", &[("x-entity-token", &npe)]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_pe_token_is_401_not_anonymous() {
        let r = rig(vec![], None);
        let (status, _) = get_json(
            &r.router,
            "/catalog/camp1",
            &[("authorization", "Bearer not-a-token")],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cache_serves_stale_listing_when_refresh_fails() {
        let store = Arc::new(MemCatalog::new(HashMap::from([(
            "camp1".to_string(),
            vec![entry(&"cc".repeat(32))],
        )])));
        // Zero TTL: every request is a refresh.
        let cache = CatalogCache::new(Arc::clone(&store), Duration::from_secs(0));

        let first = cache.entries("camp1").await.unwrap();
        assert_eq!(first.len(), 1);

        // Store starts failing → the stale listing is served, not an error.
        store.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let stale = cache.entries("camp1").await.unwrap();
        assert_eq!(stale.len(), 1);

        // A group never cached has no stale fallback → error propagates.
        assert!(cache.entries("never-seen").await.is_err());
    }

    #[tokio::test]
    async fn unsafe_group_is_400_and_unknown_group_is_empty() {
        let r = rig(vec![], None);
        let (status, _) = get_json(&r.router, "/catalog/..%2Fescape", &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, body) = get_json(&r.router, "/catalog/no-such-group", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["items"].as_array().unwrap().len(), 0);
    }
}
