//! Creator publishing gate and moderation (tdf-iroh-s3#17).
//!
//! - **Publishing** needs the Arkavo creator-publishing entitlement in the
//!   publisher's CWT (`arkavo_entitlements`, issued by authnz-rs#91). An
//!   entitled publisher opens a short-lived *publish session* naming its
//!   iroh endpoint ID; the node accepts iroh pushes only from endpoints with
//!   a live session, and `PUT /tags/catalog/<sub>` only with the entitlement.
//! - **Suspension** stops a subject publishing (and optionally hides its
//!   catalog tag) regardless of membership.
//! - **Takedown** blocks a content hash: iroh fetches of it are refused and
//!   no tag may point at it. Stored bytes are not deleted.
//!
//! Suspensions and blocks are stored as JSON objects under
//! `moderation/suspensions/<subject>` and `moderation/blocks/<hash>`. Each
//! object is its own audit record (who, when, why, report ID), and lifting
//! one marks it lifted rather than deleting it. Every node re-reads them
//! periodically, so changes apply without a redeploy.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::auth::{AuthError, CwtVerifier, VerifiedClaims, VerifyOpts, subject_id_bind};

pub const DEFAULT_PUBLISH_ENTITLEMENT: &str =
    "https://patreon.arkavo.com/attr/arkavo-creator/value/publish";

const SUSPENSIONS: &str = "suspensions";
const BLOCKS: &str = "blocks";
const AUDIT: &str = "audit";
const MAX_REASON_CHARS: usize = 1_000;

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The canonical form used for every subject comparison: `arkavo:<uuid>`
/// and a bare `<uuid>` name the same account.
pub fn canonical_subject(sub: &str) -> &str {
    subject_id_bind(sub)
}

/// Subjects become S3 keys: the viewer's identifier alphabet, no `..`.
pub fn valid_subject(s: &str) -> bool {
    (1..=248).contains(&s.len())
        && s != "."
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'@' | b'-'))
}

pub fn valid_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Suspension {
    /// Canonical subject.
    pub subject: String,
    pub reason: String,
    #[serde(default)]
    pub report_id: Option<String>,
    /// Also make `GET /tags/catalog/<subject>` answer 404.
    #[serde(default)]
    pub hide_catalog: bool,
    pub by: String,
    pub at: i64,
    #[serde(default)]
    pub lifted_by: Option<String>,
    #[serde(default)]
    pub lifted_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    /// Lower-case hex BLAKE3 hash.
    pub hash: String,
    pub reason: String,
    #[serde(default)]
    pub report_id: Option<String>,
    pub by: String,
    pub at: i64,
    #[serde(default)]
    pub lifted_by: Option<String>,
    #[serde(default)]
    pub lifted_at: Option<i64>,
}

/// Who pushed a blob, recorded at ingest so a suspension can be traced to
/// content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobOwner {
    pub hash: String,
    pub subject: String,
    pub endpoint_id: String,
    pub at: i64,
}

/// Durable storage for moderation records. `S3Client` in production.
pub trait ModerationStore: Send + Sync + 'static {
    fn list_records(&self, kind: &str) -> impl Future<Output = anyhow::Result<Vec<Bytes>>> + Send;
    fn put_record(
        &self,
        kind: &str,
        key: &str,
        body: Bytes,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
}

impl ModerationStore for crate::store::s3::S3Client {
    async fn list_records(&self, kind: &str) -> anyhow::Result<Vec<Bytes>> {
        self.list_moderation_records(kind).await
    }

    async fn put_record(&self, kind: &str, key: &str, body: Bytes) -> anyhow::Result<()> {
        self.put_moderation_record(kind, key, body).await
    }
}

/// The in-memory view every gate reads: active suspensions and blocks.
/// Reads are synchronous so the iroh event loop can check them per request.
#[derive(Default)]
pub struct Moderation {
    suspensions: RwLock<HashMap<String, Suspension>>,
    blocks: RwLock<HashMap<String, Block>>,
}

impl Moderation {
    /// The active suspension for `subject`, if any.
    pub fn suspension(&self, subject: &str) -> Option<Suspension> {
        self.suspensions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(canonical_subject(subject))
            .cloned()
    }

    pub fn is_suspended(&self, subject: &str) -> bool {
        self.suspension(subject).is_some()
    }

    pub fn is_blocked(&self, hash_hex: &str) -> bool {
        self.blocks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&hash_hex.to_ascii_lowercase())
    }

    pub fn active_suspensions(&self) -> Vec<Suspension> {
        let mut v: Vec<_> = self
            .suspensions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.subject.cmp(&b.subject));
        v
    }

    pub fn active_blocks(&self) -> Vec<Block> {
        let mut v: Vec<_> = self
            .blocks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.hash.cmp(&b.hash));
        v
    }

    /// Block a hash in memory only (integration tests).
    #[doc(hidden)]
    pub fn block_for_test(&self, hash_hex: &str) {
        self.apply_block(Block {
            hash: hash_hex.to_ascii_lowercase(),
            reason: "test".into(),
            report_id: None,
            by: "test".into(),
            at: now_secs(),
            lifted_by: None,
            lifted_at: None,
        });
    }

    /// Suspend a subject in memory only (tests).
    #[doc(hidden)]
    pub fn suspend_for_test(&self, subject: &str, hide_catalog: bool) {
        self.apply_suspension(Suspension {
            subject: canonical_subject(subject).to_string(),
            reason: "test".into(),
            report_id: None,
            hide_catalog,
            by: "test".into(),
            at: now_secs(),
            lifted_by: None,
            lifted_at: None,
        });
    }

    fn apply_suspension(&self, s: Suspension) {
        let mut m = self.suspensions.write().unwrap_or_else(|e| e.into_inner());
        if s.lifted_at.is_some() {
            m.remove(&s.subject);
        } else {
            m.insert(s.subject.clone(), s);
        }
    }

    fn apply_block(&self, b: Block) {
        let mut m = self.blocks.write().unwrap_or_else(|e| e.into_inner());
        if b.lifted_at.is_some() {
            m.remove(&b.hash);
        } else {
            m.insert(b.hash.clone(), b);
        }
    }

    /// Replace the view with what the store holds. On error the previous
    /// view is kept, so a storage blip never lifts a suspension.
    pub async fn reload<S: ModerationStore>(&self, store: &S) -> anyhow::Result<()> {
        let mut suspensions = HashMap::new();
        for raw in store.list_records(SUSPENSIONS).await? {
            match serde_json::from_slice::<Suspension>(&raw) {
                Ok(s) if s.lifted_at.is_none() => {
                    suspensions.insert(s.subject.clone(), s);
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "Skipping unreadable suspension record"),
            }
        }
        let mut blocks = HashMap::new();
        for raw in store.list_records(BLOCKS).await? {
            match serde_json::from_slice::<Block>(&raw) {
                Ok(b) if b.lifted_at.is_none() => {
                    blocks.insert(b.hash.clone(), b);
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "Skipping unreadable block record"),
            }
        }
        *self.suspensions.write().unwrap_or_else(|e| e.into_inner()) = suspensions;
        *self.blocks.write().unwrap_or_else(|e| e.into_inner()) = blocks;
        Ok(())
    }

    /// Re-read the store every `every`, keeping nodes in step with changes
    /// another node made.
    pub fn spawn_refresh<S: ModerationStore>(self: &Arc<Self>, store: Arc<S>, every: Duration) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = this.reload(store.as_ref()).await {
                    warn!(error = %e, "Moderation refresh failed; keeping the last view");
                }
            }
        });
    }
}

struct Session {
    subject: String,
    expires: Instant,
}

/// Which iroh endpoints may push, and for whom. Node-local and in memory: a
/// session lasts minutes, and a restart just means opening a new one.
pub struct PublishGate {
    pub moderation: Arc<Moderation>,
    sessions: Mutex<HashMap<EndpointId, Session>>,
    connections: Mutex<HashMap<u64, EndpointId>>,
}

/// Why a push was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum PushRefusal {
    NoSession,
    Suspended,
    Blocked,
}

impl PublishGate {
    pub fn new(moderation: Arc<Moderation>) -> Self {
        Self {
            moderation,
            sessions: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
        }
    }

    pub fn open_session(&self, endpoint: EndpointId, subject: &str, ttl: Duration) -> Instant {
        let expires = Instant::now() + ttl;
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        s.retain(|_, v| v.expires > now);
        s.insert(
            endpoint,
            Session {
                subject: canonical_subject(subject).to_string(),
                expires,
            },
        );
        expires
    }

    pub fn connected(&self, connection_id: u64, endpoint: Option<EndpointId>) {
        if let Some(e) = endpoint {
            self.connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(connection_id, e);
        }
    }

    pub fn closed(&self, connection_id: u64) {
        self.connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&connection_id);
    }

    /// The subject a push on `connection_id` is accepted for, or why not.
    pub fn authorize_push(
        &self,
        connection_id: u64,
        hash_hex: &str,
    ) -> Result<(String, EndpointId), PushRefusal> {
        let endpoint = self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&connection_id)
            .copied()
            .ok_or(PushRefusal::NoSession)?;
        let subject = {
            let s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            match s.get(&endpoint) {
                Some(session) if session.expires > Instant::now() => session.subject.clone(),
                _ => return Err(PushRefusal::NoSession),
            }
        };
        if self.moderation.is_suspended(&subject) {
            return Err(PushRefusal::Suspended);
        }
        if self.moderation.is_blocked(hash_hex) {
            return Err(PushRefusal::Blocked);
        }
        Ok((subject, endpoint))
    }
}

/// Publishing and operator settings the HTTP layer needs.
pub struct PublishPolicy {
    /// Required in `arkavo_entitlements`; `None` turns the check off.
    pub entitlement: Option<String>,
    /// Required `aud` on publisher tokens; `None` turns the check off.
    pub audience: Option<String>,
    pub session_ttl: Duration,
    /// Service clients allowed to use the operator API.
    pub operator_client_ids: HashSet<String>,
}

impl PublishPolicy {
    /// Verify a publisher token and check the entitlement and suspension.
    pub async fn publisher(
        &self,
        verifier: &CwtVerifier,
        moderation: &Moderation,
        headers: &HeaderMap,
    ) -> Result<VerifiedClaims, (StatusCode, &'static str)> {
        let token = bearer(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let claims = verifier
            .verify_with(
                token,
                now_secs(),
                VerifyOpts {
                    expected_aud: self.audience.as_deref(),
                },
            )
            .await
            .map_err(|e| match e {
                AuthError::KeySet(_) => (StatusCode::BAD_GATEWAY, "invalid token"),
                _ => (StatusCode::UNAUTHORIZED, "invalid token"),
            })?;
        if claims.sub.starts_with("client:") {
            return Err((StatusCode::FORBIDDEN, "service tokens cannot publish"));
        }
        if let Some(want) = &self.entitlement {
            let entitled = claims
                .arkavo_entitlements
                .as_ref()
                .is_some_and(|e| e.iter().any(|x| x == want));
            if !entitled {
                return Err((StatusCode::FORBIDDEN, "publishing entitlement required"));
            }
        }
        if moderation.is_suspended(&claims.sub) {
            return Err((StatusCode::FORBIDDEN, "publishing suspended"));
        }
        Ok(claims)
    }

    /// Verify an operator: a service CWT (`sub = client:<id>`, role
    /// `service-account`, `aud` naming the client) on the allowlist.
    pub async fn operator(
        &self,
        verifier: &CwtVerifier,
        headers: &HeaderMap,
    ) -> Result<String, (StatusCode, &'static str)> {
        if self.operator_client_ids.is_empty() {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "operator API not configured",
            ));
        }
        let token = bearer(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let claims = verifier
            .verify(token, now_secs())
            .await
            .map_err(|e| match e {
                AuthError::KeySet(_) => (StatusCode::BAD_GATEWAY, "invalid token"),
                _ => (StatusCode::UNAUTHORIZED, "invalid token"),
            })?;
        let client = claims
            .sub
            .strip_prefix("client:")
            .filter(|c| !c.is_empty())
            .ok_or((StatusCode::FORBIDDEN, "operator token required"))?;
        let service = claims
            .arkavo_roles
            .as_ref()
            .is_some_and(|r| r.iter().any(|x| x == "service-account"));
        if !service || !claims.aud.contains(client) {
            return Err((StatusCode::FORBIDDEN, "operator token required"));
        }
        if !self.operator_client_ids.contains(client) {
            return Err((StatusCode::FORBIDDEN, "not an operator"));
        }
        Ok(format!("client:{client}"))
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

pub struct ModerationApi<S: ModerationStore> {
    pub store: Arc<S>,
    pub verifier: Arc<CwtVerifier>,
    pub gate: Arc<PublishGate>,
    pub policy: Arc<PublishPolicy>,
}

type ApiResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

fn fail((status, msg): (StatusCode, &'static str)) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

pub fn router<S: ModerationStore>(state: Arc<ModerationApi<S>>) -> Router {
    Router::new()
        .route("/publish/sessions", post(open_session::<S>))
        .route("/moderation/suspensions", get(list_suspensions::<S>))
        .route(
            "/moderation/suspensions/{subject}",
            put(suspend::<S>).delete(lift_suspension::<S>),
        )
        .route("/moderation/blocks", get(list_blocks::<S>))
        .route(
            "/moderation/blocks/{hash}",
            put(block::<S>).delete(lift_block::<S>),
        )
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionRequest {
    endpoint_id: String,
    /// Unix seconds when the client signed; within [`SESSION_SKEW_SECS`].
    timestamp: i64,
    /// Hex Ed25519 signature by the endpoint's secret key over
    /// [`session_message`]: proof that the caller holds the endpoint.
    signature: String,
}

/// How far a session signature's timestamp may be from the node's clock.
pub const SESSION_SKEW_SECS: i64 = 300;

/// The bytes a publisher signs with its iroh endpoint key to open a
/// session. Binding the bearer token (by BLAKE3 hash) means a captured
/// signature cannot be replayed with another subject's token, and the
/// timestamp bounds replay with the same one.
pub fn session_message(endpoint: &EndpointId, bearer_token: &str, timestamp: i64) -> Vec<u8> {
    format!(
        "tdf-iroh-s3 publish-session v1\n{endpoint}\n{}\n{timestamp}",
        blake3::hash(bearer_token.as_bytes()).to_hex()
    )
    .into_bytes()
}

fn verify_possession(
    endpoint: &EndpointId,
    bearer_token: &str,
    timestamp: i64,
    signature_hex: &str,
) -> Result<(), (StatusCode, &'static str)> {
    if (now_secs() - timestamp).abs() > SESSION_SKEW_SECS {
        return Err((StatusCode::BAD_REQUEST, "timestamp out of range"));
    }
    let bytes: [u8; 64] = hex::decode(signature_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or((StatusCode::BAD_REQUEST, "invalid signature"))?;
    let signature = iroh_base::Signature::from_bytes(&bytes);
    endpoint
        .verify(
            &session_message(endpoint, bearer_token, timestamp),
            &signature,
        )
        .map_err(|_| (StatusCode::FORBIDDEN, "signature does not match endpointId"))
}

async fn open_session<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let claims = s
        .policy
        .publisher(&s.verifier, &s.gate.moderation, &headers)
        .await
        .map_err(fail)?;
    let endpoint = EndpointId::from_str(body.endpoint_id.trim())
        .map_err(|_| fail((StatusCode::BAD_REQUEST, "invalid endpointId")))?;
    let token = bearer(&headers).unwrap_or_default();
    verify_possession(&endpoint, token, body.timestamp, &body.signature).map_err(fail)?;
    s.gate
        .open_session(endpoint, &claims.sub, s.policy.session_ttl);
    let expires_at = now_secs() + s.policy.session_ttl.as_secs() as i64;
    info!(sub = %claims.sub, %endpoint, "Publish session opened");
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "endpointId": endpoint.to_string(),
            "subject": canonical_subject(&claims.sub),
            "expiresAt": expires_at,
        })),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActionRequest {
    reason: String,
    #[serde(default)]
    report_id: Option<String>,
    #[serde(default)]
    hide_catalog: bool,
}

fn checked_reason(r: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let r = r.trim();
    if r.is_empty() || r.chars().count() > MAX_REASON_CHARS {
        return Err(fail((
            StatusCode::BAD_REQUEST,
            "reason is required (≤ 1000 characters)",
        )));
    }
    Ok(r.to_string())
}

fn checked_report_id(
    r: Option<String>,
) -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
    match r {
        Some(id) if !valid_subject(&id) => Err(fail((StatusCode::BAD_REQUEST, "invalid reportId"))),
        other => Ok(other),
    }
}

async fn persist<S: ModerationStore, T: Serialize>(
    store: &S,
    kind: &str,
    key: &str,
    record: &T,
) -> ApiResult<()> {
    let body = serde_json::to_vec(record).expect("record serializes");
    store
        .put_record(kind, key, Bytes::from(body))
        .await
        .map_err(|e| {
            warn!(%kind, %key, error = %e, "Moderation write failed");
            fail((StatusCode::BAD_GATEWAY, "storage unavailable"))
        })
}

/// Append an immutable audit event under `moderation/audit/<kind>/<key>/`.
/// Current-state objects are overwritten on each change; these are not, so
/// every suspend, block and lift stays on record.
async fn audit<S: ModerationStore, T: Serialize>(
    store: &S,
    action: &str,
    kind: &str,
    key: &str,
    record: &T,
) -> ApiResult<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let event = serde_json::json!({ "action": action, "record": record });
    persist(store, AUDIT, &format!("{kind}/{key}/{nanos:020}"), &event).await
}

async fn list_suspensions<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Suspension>>> {
    s.policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    Ok(Json(s.gate.moderation.active_suspensions()))
}

async fn suspend<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    Path(subject): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ActionRequest>,
) -> ApiResult<Json<Suspension>> {
    let by = s
        .policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    let subject = canonical_subject(&subject).to_string();
    if !valid_subject(&subject) {
        return Err(fail((StatusCode::BAD_REQUEST, "invalid subject")));
    }
    let record = Suspension {
        subject: subject.clone(),
        reason: checked_reason(&body.reason)?,
        report_id: checked_report_id(body.report_id)?,
        hide_catalog: body.hide_catalog,
        by,
        at: now_secs(),
        lifted_by: None,
        lifted_at: None,
    };
    audit(s.store.as_ref(), "suspend", SUSPENSIONS, &subject, &record).await?;
    persist(s.store.as_ref(), SUSPENSIONS, &subject, &record).await?;
    s.gate.moderation.apply_suspension(record.clone());
    info!(audit = "suspend", %subject, by = %record.by, report = ?record.report_id, hide = record.hide_catalog, "Creator suspended");
    Ok(Json(record))
}

async fn lift_suspension<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    Path(subject): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Suspension>> {
    let by = s
        .policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    let mut record = s
        .gate
        .moderation
        .suspension(&subject)
        .ok_or_else(|| fail((StatusCode::NOT_FOUND, "no active suspension")))?;
    record.lifted_by = Some(by);
    record.lifted_at = Some(now_secs());
    audit(
        s.store.as_ref(),
        "lift_suspension",
        SUSPENSIONS,
        &record.subject,
        &record,
    )
    .await?;
    persist(s.store.as_ref(), SUSPENSIONS, &record.subject, &record).await?;
    s.gate.moderation.apply_suspension(record.clone());
    info!(audit = "lift_suspension", subject = %record.subject, by = ?record.lifted_by, "Suspension lifted");
    Ok(Json(record))
}

async fn list_blocks<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Block>>> {
    s.policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    Ok(Json(s.gate.moderation.active_blocks()))
}

async fn block<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ActionRequest>,
) -> ApiResult<Json<Block>> {
    let by = s
        .policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    if !valid_hash(&hash) {
        return Err(fail((StatusCode::BAD_REQUEST, "hash must be 64 hex chars")));
    }
    if body.hide_catalog {
        return Err(fail((
            StatusCode::BAD_REQUEST,
            "hideCatalog applies to suspensions",
        )));
    }
    let hash = hash.to_ascii_lowercase();
    let record = Block {
        hash: hash.clone(),
        reason: checked_reason(&body.reason)?,
        report_id: checked_report_id(body.report_id)?,
        by,
        at: now_secs(),
        lifted_by: None,
        lifted_at: None,
    };
    audit(s.store.as_ref(), "block", BLOCKS, &hash, &record).await?;
    persist(s.store.as_ref(), BLOCKS, &hash, &record).await?;
    s.gate.moderation.apply_block(record.clone());
    info!(audit = "block", %hash, by = %record.by, report = ?record.report_id, "Content blocked");
    Ok(Json(record))
}

async fn lift_block<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Block>> {
    let by = s
        .policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    let hash = hash.to_ascii_lowercase();
    let mut record = s
        .gate
        .moderation
        .active_blocks()
        .into_iter()
        .find(|b| b.hash == hash)
        .ok_or_else(|| fail((StatusCode::NOT_FOUND, "no active block")))?;
    record.lifted_by = Some(by);
    record.lifted_at = Some(now_secs());
    audit(s.store.as_ref(), "lift_block", BLOCKS, &hash, &record).await?;
    persist(s.store.as_ref(), BLOCKS, &hash, &record).await?;
    s.gate.moderation.apply_block(record.clone());
    info!(audit = "lift_block", %hash, by = ?record.lifted_by, "Block lifted");
    Ok(Json(record))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Moderation records keyed by `kind/key`.
    #[derive(Default)]
    pub struct MemModeration {
        pub records: Mutex<HashMap<String, Bytes>>,
        pub fail: Mutex<bool>,
    }

    impl ModerationStore for MemModeration {
        async fn list_records(&self, kind: &str) -> anyhow::Result<Vec<Bytes>> {
            anyhow::ensure!(!*self.fail.lock().unwrap(), "down");
            let prefix = format!("{kind}/");
            Ok(self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.clone())
                .collect())
        }

        async fn put_record(&self, kind: &str, key: &str, body: Bytes) -> anyhow::Result<()> {
            anyhow::ensure!(!*self.fail.lock().unwrap(), "down");
            self.records
                .lock()
                .unwrap()
                .insert(format!("{kind}/{key}"), body);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemModeration;
    use super::*;
    use crate::auth::test_support::{keypair, mint_map};
    use axum::body::Body;
    use axum::http::Request;
    use ciborium::value::Value;
    use tower::ServiceExt;

    const KID: &[u8] = b"kid-1";
    const ISS: &str = "https://identity.arkavo.net";

    fn token(sub: &str, aud: &str, entitlements: &[&str], roles: &[&str]) -> String {
        let (sk, _) = keypair();
        let now = now_secs();
        let text = |s: &str| Value::Text(s.into());
        let list = |v: &[&str]| Value::Array(v.iter().map(|s| text(s)).collect());
        mint_map(
            &sk,
            KID,
            vec![
                (Value::Integer(1.into()), text(ISS)),
                (Value::Integer(2.into()), text(sub)),
                (Value::Integer(3.into()), text(aud)),
                (Value::Integer(4.into()), Value::Integer((now + 600).into())),
                (Value::Integer(6.into()), Value::Integer(now.into())),
                (
                    Value::Integer(7.into()),
                    Value::Bytes(sub.as_bytes().to_vec()),
                ),
                (text("arkavo_entitlements"), list(entitlements)),
                (text("arkavo_roles"), list(roles)),
            ],
        )
    }

    fn creator(sub: &str) -> String {
        token(sub, "arkavo", &[DEFAULT_PUBLISH_ENTITLEMENT], &[])
    }

    fn operator() -> String {
        token("client:moderation", "moderation", &[], &["service-account"])
    }

    struct Harness {
        app: Router,
        store: Arc<MemModeration>,
        gate: Arc<PublishGate>,
    }

    fn harness() -> Harness {
        let (_, vk) = keypair();
        let store = Arc::new(MemModeration::default());
        let gate = Arc::new(PublishGate::new(Arc::new(Moderation::default())));
        let api = Arc::new(ModerationApi {
            store: store.clone(),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(KID.to_vec(), vk)])),
            gate: gate.clone(),
            policy: Arc::new(PublishPolicy {
                entitlement: Some(DEFAULT_PUBLISH_ENTITLEMENT.into()),
                audience: Some("arkavo".into()),
                session_ttl: Duration::from_secs(600),
                operator_client_ids: HashSet::from(["moderation".to_string()]),
            }),
        });
        Harness {
            app: router(api),
            store,
            gate,
        }
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"));
        if body.is_some() {
            req = req.header("content-type", "application/json");
        }
        let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
        let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn key() -> iroh::SecretKey {
        use std::sync::atomic::{AtomicU8, Ordering};
        static SEED: AtomicU8 = AtomicU8::new(1);
        iroh::SecretKey::from_bytes(&[SEED.fetch_add(1, Ordering::Relaxed); 32])
    }

    fn endpoint() -> EndpointId {
        key().public()
    }

    /// A session request signed by `sk` for `bearer`.
    fn signed(sk: &iroh::SecretKey, bearer: &str) -> Option<serde_json::Value> {
        let ep = sk.public();
        let ts = now_secs();
        let sig = sk.sign(&session_message(&ep, bearer, ts));
        Some(serde_json::json!({
            "endpointId": ep.to_string(),
            "timestamp": ts,
            "signature": hex::encode(sig.to_bytes()),
        }))
    }

    #[tokio::test]
    async fn an_entitled_creator_opens_a_session_and_may_push() {
        let h = harness();
        let sk = key();
        let ep = sk.public();
        let tok = creator("arkavo:u1");
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["subject"], "u1");
        h.gate.connected(7, Some(ep));
        let (sub, got) = h.gate.authorize_push(7, &"a".repeat(64)).unwrap();
        assert_eq!((sub.as_str(), got), ("u1", ep));
        // Another connection without a session is refused.
        h.gate.connected(8, Some(endpoint()));
        assert_eq!(
            h.gate.authorize_push(8, &"a".repeat(64)),
            Err(PushRefusal::NoSession)
        );
        assert_eq!(
            h.gate.authorize_push(9, &"a".repeat(64)),
            Err(PushRefusal::NoSession)
        );
    }

    #[tokio::test]
    async fn sessions_need_the_entitlement_audience_and_a_person() {
        let h = harness();
        let sk = key();
        for (t, want) in [
            (token("u1", "arkavo", &[], &[]), StatusCode::FORBIDDEN),
            (
                token("u1", "other", &[DEFAULT_PUBLISH_ENTITLEMENT], &[]),
                StatusCode::UNAUTHORIZED,
            ),
            (
                token(
                    "client:x",
                    "arkavo",
                    &[DEFAULT_PUBLISH_ENTITLEMENT],
                    &["service-account"],
                ),
                StatusCode::FORBIDDEN,
            ),
            ("garbage".to_string(), StatusCode::UNAUTHORIZED),
        ] {
            let (status, _) = call(&h.app, "POST", "/publish/sessions", &t, signed(&sk, &t)).await;
            assert_eq!(status, want, "{t}");
        }
    }

    #[tokio::test]
    async fn suspension_is_audited_stops_sessions_and_pushes_and_can_be_lifted() {
        let h = harness();
        let sk = key();
        let ep = sk.public();
        let tok = creator("u1");
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED);
        h.gate.connected(1, Some(ep));

        let (status, rec) = call(
            &h.app,
            "PUT",
            "/moderation/suspensions/arkavo:u1",
            &operator(),
            Some(serde_json::json!({ "reason": "repeated violations", "reportId": "r-1", "hideCatalog": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rec}");
        assert_eq!(rec["subject"], "u1");
        assert_eq!(rec["by"], "client:moderation");
        assert_eq!(rec["reportId"], "r-1");
        let stored: Suspension =
            serde_json::from_slice(&h.store.records.lock().unwrap()["suspensions/u1"]).unwrap();
        assert!(stored.hide_catalog);

        // An open session no longer pushes; a new one cannot be opened.
        assert_eq!(
            h.gate.authorize_push(1, &"b".repeat(64)),
            Err(PushRefusal::Suspended)
        );
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, lifted) = call(
            &h.app,
            "DELETE",
            "/moderation/suspensions/u1",
            &operator(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(lifted["liftedBy"], "client:moderation");
        // The record is kept, marked lifted: it is the audit trail.
        let stored: Suspension =
            serde_json::from_slice(&h.store.records.lock().unwrap()["suspensions/u1"]).unwrap();
        assert!(stored.lifted_at.is_some());
        assert!(h.gate.authorize_push(1, &"b".repeat(64)).is_ok());
    }

    #[tokio::test]
    async fn blocked_hashes_are_refused_for_push() {
        let h = harness();
        let hash = "C".repeat(64);
        let (status, rec) = call(
            &h.app,
            "PUT",
            &format!("/moderation/blocks/{hash}"),
            &operator(),
            Some(serde_json::json!({ "reason": "takedown", "reportId": "r-2" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rec}");
        assert_eq!(rec["hash"], "c".repeat(64));
        assert!(h.gate.moderation.is_blocked(&hash));
        let ep = endpoint();
        h.gate.open_session(ep, "u2", Duration::from_secs(60));
        h.gate.connected(3, Some(ep));
        assert_eq!(h.gate.authorize_push(3, &hash), Err(PushRefusal::Blocked));

        let (_, list) = call(&h.app, "GET", "/moderation/blocks", &operator(), None).await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        call(
            &h.app,
            "DELETE",
            &format!("/moderation/blocks/{hash}"),
            &operator(),
            None,
        )
        .await;
        assert!(!h.gate.moderation.is_blocked(&hash));
    }

    #[tokio::test]
    async fn only_allowlisted_service_tokens_operate() {
        let h = harness();
        let body = Some(serde_json::json!({ "reason": "x" }));
        for (t, want) in [
            (creator("u1"), StatusCode::FORBIDDEN),
            (
                token("client:other", "other", &[], &["service-account"]),
                StatusCode::FORBIDDEN,
            ),
            (
                token("client:moderation", "moderation", &[], &[]),
                StatusCode::FORBIDDEN,
            ),
            (
                token(
                    "client:moderation",
                    "someone-else",
                    &[],
                    &["service-account"],
                ),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let (status, _) = call(
                &h.app,
                "PUT",
                "/moderation/suspensions/u9",
                &t,
                body.clone(),
            )
            .await;
            assert_eq!(status, want, "{t}");
        }
        assert!(h.store.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bad_operator_input_is_refused() {
        let h = harness();
        let op = operator();
        for (uri, body) in [
            (
                "/moderation/suspensions/a..b",
                serde_json::json!({ "reason": "x" }),
            ),
            (
                "/moderation/suspensions/u1",
                serde_json::json!({ "reason": "  " }),
            ),
            (
                "/moderation/suspensions/u1",
                serde_json::json!({ "reason": "x", "reportId": "a b" }),
            ),
            (
                "/moderation/blocks/xyz",
                serde_json::json!({ "reason": "x" }),
            ),
        ] {
            let (status, _) = call(&h.app, "PUT", uri, &op, Some(body.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} {body}");
        }
    }

    #[tokio::test]
    async fn a_failed_write_changes_nothing() {
        let h = harness();
        *h.store.fail.lock().unwrap() = true;
        let (status, _) = call(
            &h.app,
            "PUT",
            "/moderation/suspensions/u1",
            &operator(),
            Some(serde_json::json!({ "reason": "x" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!h.gate.moderation.is_suspended("u1"));
    }

    #[tokio::test]
    async fn reload_reads_active_records_and_keeps_the_view_on_error() {
        let store = MemModeration::default();
        let active = Suspension {
            subject: "u1".into(),
            reason: "r".into(),
            report_id: None,
            hide_catalog: false,
            by: "client:m".into(),
            at: 1,
            lifted_by: None,
            lifted_at: None,
        };
        let mut lifted = active.clone();
        lifted.subject = "u2".into();
        lifted.lifted_at = Some(2);
        for s in [&active, &lifted] {
            store
                .put_record(
                    SUSPENSIONS,
                    &s.subject,
                    Bytes::from(serde_json::to_vec(s).unwrap()),
                )
                .await
                .unwrap();
        }
        let m = Moderation::default();
        m.reload(&store).await.unwrap();
        assert!(m.is_suspended("arkavo:u1"));
        assert!(!m.is_suspended("u2"));
        *store.fail.lock().unwrap() = true;
        assert!(m.reload(&store).await.is_err());
        assert!(
            m.is_suspended("u1"),
            "a storage blip must not lift a suspension"
        );
    }

    #[tokio::test]
    async fn a_session_needs_proof_of_the_endpoint_key() {
        let h = harness();
        let tok = creator("u1");
        let mine = key();
        let victim = key().public();

        // Someone else's endpoint ID, signed with my key: refused.
        let mut body = signed(&mine, &tok).unwrap();
        body["endpointId"] = serde_json::json!(victim.to_string());
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A signature made for another token cannot be replayed with this one.
        let other = creator("u2");
        let (status, _) = call(
            &h.app,
            "POST",
            "/publish/sessions",
            &tok,
            signed(&mine, &other),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Stale timestamp, missing or malformed signature.
        let ep = mine.public();
        let old = now_secs() - SESSION_SKEW_SECS - 10;
        let stale = serde_json::json!({
            "endpointId": ep.to_string(),
            "timestamp": old,
            "signature": hex::encode(mine.sign(&session_message(&ep, &tok, old)).to_bytes()),
        });
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, Some(stale)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        for bad in [
            serde_json::json!({ "endpointId": ep.to_string() }),
            serde_json::json!({ "endpointId": ep.to_string(), "timestamp": now_secs(), "signature": "zz" }),
        ] {
            let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, Some(bad)).await;
            assert!(status.is_client_error(), "{status}");
        }
        h.gate.connected(5, Some(victim));
        assert_eq!(
            h.gate.authorize_push(5, &"a".repeat(64)),
            Err(PushRefusal::NoSession)
        );
    }

    #[tokio::test]
    async fn every_change_is_kept_in_the_audit_history() {
        let h = harness();
        let op = operator();
        let body = |r: &str| Some(serde_json::json!({ "reason": r }));
        call(
            &h.app,
            "PUT",
            "/moderation/suspensions/u1",
            &op,
            body("first"),
        )
        .await;
        call(&h.app, "DELETE", "/moderation/suspensions/u1", &op, None).await;
        call(
            &h.app,
            "PUT",
            "/moderation/suspensions/u1",
            &op,
            body("second"),
        )
        .await;
        let hash = "e".repeat(64);
        call(
            &h.app,
            "PUT",
            &format!("/moderation/blocks/{hash}"),
            &op,
            body("takedown"),
        )
        .await;

        let records = h.store.records.lock().unwrap();
        let mut events: Vec<(String, serde_json::Value)> = records
            .iter()
            .filter(|(k, _)| k.starts_with("audit/"))
            .map(|(k, v)| (k.clone(), serde_json::from_slice(v).unwrap()))
            .collect();
        events.sort_by(|a, b| a.0.cmp(&b.0));
        let actions: Vec<&str> = events
            .iter()
            .map(|(_, e)| e["action"].as_str().unwrap())
            .collect();
        assert_eq!(actions, ["block", "suspend", "lift_suspension", "suspend"]);
        let reasons: Vec<&str> = events
            .iter()
            .filter(|(k, _)| k.starts_with("audit/suspensions/u1/"))
            .map(|(_, e)| e["record"]["reason"].as_str().unwrap())
            .collect();
        assert_eq!(reasons, ["first", "first", "second"]);
        // The current record is the latest; history survives the overwrite.
        let current: Suspension = serde_json::from_slice(&records["suspensions/u1"]).unwrap();
        assert_eq!(current.reason, "second");
    }
}
