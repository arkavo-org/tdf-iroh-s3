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
//!
//! Publish sessions are also written to `moderation/sessions/<endpoint>`,
//! so a push finds its session on any instance, or after a restart, and
//! not only on the one that opened it (tdf-iroh-s3#32).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::auth::{AuthError, CwtVerifier, VerifiedClaims, VerifyOpts, subject_id_bind};
use crate::authz::ChainEntity;
use crate::entity_chain;
use crate::publish_decision::{
    PublishDecider, PublishDecisions, StoredEntity, Verdict, log_shadow, restore, strip_tokens,
};

pub const DEFAULT_PUBLISH_ENTITLEMENT: &str =
    "https://patreon.arkavo.com/attr/arkavo-creator/value/publish";

const SUSPENSIONS: &str = "suspensions";
const BLOCKS: &str = "blocks";
/// `moderation/catalog-blocks/<subject>`: a sibling of `blocks/`, because
/// records are listed recursively and would otherwise be read as blocks.
const CATALOG_BLOCKS: &str = "catalog-blocks";
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

/// A blocked creator catalog: the catalog tag, the v2 pointer and every
/// catalog document the subject owns are refused (tdf-iroh-s3#35). Written
/// by the moderation client when it suspends the creator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogBlock {
    /// Canonical subject.
    pub subject: String,
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

/// Where the gate looks up a session it does not hold: the records
/// `POST /publish/sessions` wrote. Object-safe, so the gate needs no type
/// parameter.
pub trait SessionStore: Send + Sync + 'static {
    fn get_session<'a>(
        &'a self,
        endpoint: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>>;
}

impl SessionStore for crate::store::s3::S3Client {
    fn get_session<'a>(
        &'a self,
        endpoint: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>> {
        Box::pin(self.get_moderation_record(SESSIONS, endpoint))
    }
}

/// `moderation/sessions/<endpoint>`.
const SESSIONS: &str = "sessions";

/// How long a push waits for the session store before it is refused.
const SESSION_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Session lookups at once. A push that finds them all busy is refused:
/// a peer with no session must not be able to make the node send S3 a
/// request per push.
const SESSION_LOOKUPS: usize = 16;

/// How long an endpoint whose lookup found no live session is refused
/// without asking the store again.
const SESSION_MISS_TTL: Duration = Duration::from_secs(10);

/// Most endpoints remembered as misses; past it the oldest are dropped.
const SESSION_MISSES: usize = 4096;

/// A stored publish session. `expiresAt` is Unix seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionRecord {
    endpoint_id: String,
    subject: String,
    expires_at: i64,
    /// The entity chain the session was decided with, without tokens, so a
    /// push can be decided again (tdf-iroh-s3#35). Absent on records
    /// written before it, and when decisions are local.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<Vec<StoredEntity>>,
}

/// The in-memory view every gate reads: active suspensions and blocks.
/// Reads are synchronous so the iroh event loop can check them per request.
#[derive(Default)]
pub struct Moderation {
    suspensions: RwLock<HashMap<String, Suspension>>,
    blocks: RwLock<HashMap<String, Block>>,
    catalog_blocks: RwLock<HashMap<String, CatalogBlock>>,
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

    /// Whether `subject`'s catalog and catalog documents are refused: a
    /// catalog block, or a suspension with `hideCatalog`.
    pub fn catalog_hidden(&self, subject: &str) -> bool {
        let subject = canonical_subject(subject);
        self.catalog_blocks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(subject)
            || self.suspension(subject).is_some_and(|s| s.hide_catalog)
    }

    pub fn active_catalog_blocks(&self) -> Vec<CatalogBlock> {
        let mut v: Vec<_> = self
            .catalog_blocks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.subject.cmp(&b.subject));
        v
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

    /// Block a subject's catalog in memory only (tests).
    #[doc(hidden)]
    pub fn block_catalog_for_test(&self, subject: &str) {
        self.apply_catalog_block(CatalogBlock {
            subject: canonical_subject(subject).to_string(),
            reason: "test".into(),
            report_id: None,
            by: "test".into(),
            at: now_secs(),
            lifted_by: None,
            lifted_at: None,
        });
    }

    fn apply_catalog_block(&self, b: CatalogBlock) {
        let mut m = self
            .catalog_blocks
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if b.lifted_at.is_some() {
            m.remove(&b.subject);
        } else {
            m.insert(b.subject.clone(), b);
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
        let mut catalog_blocks = HashMap::new();
        for raw in store.list_records(CATALOG_BLOCKS).await? {
            match serde_json::from_slice::<CatalogBlock>(&raw) {
                Ok(b) if b.lifted_at.is_none() => {
                    catalog_blocks.insert(b.subject.clone(), b);
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "Skipping unreadable catalog block record"),
            }
        }
        *self.suspensions.write().unwrap_or_else(|e| e.into_inner()) = suspensions;
        *self.blocks.write().unwrap_or_else(|e| e.into_inner()) = blocks;
        *self
            .catalog_blocks
            .write()
            .unwrap_or_else(|e| e.into_inner()) = catalog_blocks;
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
    chain: Option<Vec<StoredEntity>>,
}

/// A live session: its subject, and the chain it was decided with.
type HeldSession = (String, Option<Vec<StoredEntity>>);

/// Which iroh endpoints may push, and for whom. Sessions are held in memory
/// and, with a session store, read back from it on a miss: another instance
/// (during a replacement) or this one before a restart may have opened it.
pub struct PublishGate {
    pub moderation: Arc<Moderation>,
    sessions: Mutex<HashMap<EndpointId, Session>>,
    connections: Mutex<HashMap<u64, EndpointId>>,
    store: Option<Arc<dyn SessionStore>>,
    lookups: tokio::sync::Semaphore,
    /// Endpoints whose last lookup found no live session, and when.
    misses: Mutex<HashMap<EndpointId, Instant>>,
    decider: Arc<PublishDecider>,
}

/// Why a push was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum PushRefusal {
    NoSession,
    Suspended,
    Blocked,
    /// The decision service denied the session's subject.
    NotPermitted,
    /// The decision service couldn't be asked (`decisions = pdp` fails
    /// closed).
    DecisionUnavailable,
}

impl PublishGate {
    pub fn new(moderation: Arc<Moderation>) -> Self {
        Self {
            moderation,
            sessions: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            store: None,
            lookups: tokio::sync::Semaphore::new(SESSION_LOOKUPS),
            misses: Mutex::new(HashMap::new()),
            decider: Arc::new(PublishDecider::default()),
        }
    }

    /// Decide pushes with `decider` as well (tdf-iroh-s3#35).
    pub fn with_decider(mut self, decider: Arc<PublishDecider>) -> Self {
        self.decider = decider;
        self
    }

    /// Look up sessions this gate does not hold in `store`.
    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn open_session(&self, endpoint: EndpointId, subject: &str, ttl: Duration) -> Instant {
        self.open_session_with_chain(endpoint, subject, ttl, None)
    }

    /// Open a session that keeps the (token-free) chain it was decided with.
    pub fn open_session_with_chain(
        &self,
        endpoint: EndpointId,
        subject: &str,
        ttl: Duration,
        chain: Option<Vec<StoredEntity>>,
    ) -> Instant {
        let expires = Instant::now() + ttl;
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        s.retain(|_, v| v.expires > now);
        s.insert(
            endpoint,
            Session {
                subject: canonical_subject(subject).to_string(),
                expires,
                chain,
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

    /// The live session's subject and stored chain for `endpoint` held in
    /// memory.
    fn held_session(&self, endpoint: &EndpointId) -> Option<HeldSession> {
        let s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        s.get(endpoint)
            .filter(|session| session.expires > Instant::now())
            .map(|session| (session.subject.clone(), session.chain.clone()))
    }

    /// The live session for `endpoint` in the session store, kept in memory
    /// once found. A store that fails or does not answer in time refuses the
    /// push, as no session would. An endpoint that just missed, or a push
    /// that finds every lookup busy, is refused without asking the store.
    async fn stored_session(&self, endpoint: &EndpointId) -> Option<HeldSession> {
        let store = self.store.as_ref()?;
        if self.recently_missed(endpoint) {
            return None;
        }
        let Ok(_permit) = self.lookups.try_acquire() else {
            warn!(%endpoint, "Session lookups busy; push refused");
            return None;
        };
        let found = self.look_up(store.as_ref(), endpoint).await;
        if found.is_none() {
            self.missed(*endpoint);
        }
        found
    }

    fn recently_missed(&self, endpoint: &EndpointId) -> bool {
        self.misses
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(endpoint)
            .is_some_and(|at| at.elapsed() < SESSION_MISS_TTL)
    }

    fn missed(&self, endpoint: EndpointId) {
        let mut misses = self.misses.lock().unwrap_or_else(|e| e.into_inner());
        if misses.len() >= SESSION_MISSES {
            misses.retain(|_, at| at.elapsed() < SESSION_MISS_TTL);
        }
        if misses.len() >= SESSION_MISSES
            && let Some(oldest) = misses.iter().min_by_key(|(_, at)| **at).map(|(e, _)| *e)
        {
            misses.remove(&oldest);
        }
        misses.insert(endpoint, Instant::now());
    }

    async fn look_up(
        &self,
        store: &dyn SessionStore,
        endpoint: &EndpointId,
    ) -> Option<HeldSession> {
        let key = endpoint.to_string();
        let body = match tokio::time::timeout(SESSION_LOOKUP_TIMEOUT, store.get_session(&key)).await
        {
            Ok(Ok(body)) => body?,
            Ok(Err(e)) => {
                warn!(%endpoint, error = %e, "Session lookup failed");
                return None;
            }
            Err(_) => {
                warn!(%endpoint, "Session lookup timed out");
                return None;
            }
        };
        let record: SessionRecord = serde_json::from_slice(&body)
            .inspect_err(|e| warn!(%endpoint, error = %e, "Unreadable session record"))
            .ok()?;
        let left = record.expires_at - now_secs();
        if record.endpoint_id != key || left <= 0 {
            return None;
        }
        info!(%endpoint, sub = %record.subject, "Publish session found in the session store");
        self.open_session_with_chain(
            *endpoint,
            &record.subject,
            Duration::from_secs(left as u64),
            record.chain.clone(),
        );
        Some((canonical_subject(&record.subject).to_string(), record.chain))
    }

    /// The subject a push on `connection_id` is accepted for, or why not.
    pub async fn authorize_push(
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
        let (subject, chain) = match self.held_session(&endpoint) {
            Some(held) => held,
            None => self
                .stored_session(&endpoint)
                .await
                .ok_or(PushRefusal::NoSession)?,
        };
        if self.moderation.is_suspended(&subject) {
            return Err(PushRefusal::Suspended);
        }
        if self.moderation.is_blocked(hash_hex) {
            return Err(PushRefusal::Blocked);
        }
        self.decide_push(&subject, chain.as_deref()).await?;
        Ok((subject, endpoint))
    }

    /// Ask the decision service again for a push, with the chain its session
    /// was decided with (reused for 30 s per subject). So a suspension
    /// stops pushes without waiting for the session to expire.
    async fn decide_push(
        &self,
        subject: &str,
        chain: Option<&[StoredEntity]>,
    ) -> Result<(), PushRefusal> {
        let mode = self.decider.mode();
        if mode == PublishDecisions::Local {
            return Ok(());
        }
        let Some(chain) = chain else {
            // A session opened before decisions were asked, or by a node
            // that decided locally, has nothing to ask with.
            if mode == PublishDecisions::Pdp {
                warn!(%subject, "Session has no stored chain; push refused");
                return Err(PushRefusal::NoSession);
            }
            warn!(%subject, "Publish decision shadow: session has no stored chain");
            return Ok(());
        };
        let verdict = self.decider.ask_for_push(subject, &restore(chain)).await;
        match mode {
            PublishDecisions::Shadow => {
                log_shadow("push", subject, true, verdict);
                Ok(())
            }
            _ => match verdict {
                Verdict::Permit => Ok(()),
                Verdict::Deny => Err(PushRefusal::NotPermitted),
                Verdict::Unavailable => Err(PushRefusal::DecisionUnavailable),
            },
        }
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
    /// Who decides whether a subject may publish (tdf-iroh-s3#35).
    pub decider: Arc<PublishDecider>,
}

impl PublishPolicy {
    /// Verify a publisher token and check the entitlement and suspension.
    /// Every refusal is logged, with the token's subject once it verifies.
    pub async fn publisher(
        &self,
        verifier: &CwtVerifier,
        moderation: &Moderation,
        headers: &HeaderMap,
    ) -> Result<VerifiedClaims, (StatusCode, &'static str)> {
        self.publisher_with_chain(verifier, moderation, headers)
            .await
            .map(|(claims, _)| claims)
    }

    /// [`publisher`](Self::publisher), also returning the entity chain the
    /// decision service was asked with (`None` when decisions are local).
    pub async fn publisher_with_chain(
        &self,
        verifier: &CwtVerifier,
        moderation: &Moderation,
        headers: &HeaderMap,
    ) -> Result<(VerifiedClaims, Option<Vec<ChainEntity>>), (StatusCode, &'static str)> {
        let refuse = |status: StatusCode, reason: &'static str| {
            warn!(%status, reason, "Publisher refused");
            (status, reason)
        };
        let token = bearer(headers)
            .ok_or_else(|| refuse(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let claims = verifier
            .verify_with(
                token,
                now_secs(),
                VerifyOpts {
                    expected_aud: self.audience.as_deref(),
                },
            )
            .await
            .map_err(|e| {
                let status = match e {
                    AuthError::KeySet(_) => StatusCode::BAD_GATEWAY,
                    _ => StatusCode::UNAUTHORIZED,
                };
                warn!(%status, error = %e, "Publisher refused: invalid token");
                (status, "invalid token")
            })?;
        let refuse = |status: StatusCode, reason: &'static str| {
            warn!(
                sub = %claims.sub,
                entitlements = ?claims.arkavo_entitlements,
                %status,
                reason,
                "Publisher refused"
            );
            (status, reason)
        };
        if claims.sub.starts_with("client:") {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                "service tokens cannot publish",
            ));
        }
        // Kept in every mode until the platform's suspension constraint is
        // live (tdf-iroh-s3#35, step 4e).
        if moderation.is_suspended(&claims.sub) {
            return Err(refuse(StatusCode::FORBIDDEN, "publishing suspended"));
        }
        let local = match &self.entitlement {
            Some(want)
                if !claims
                    .arkavo_entitlements
                    .as_ref()
                    .is_some_and(|e| e.iter().any(|x| x == want)) =>
            {
                Err((StatusCode::FORBIDDEN, "publishing entitlement required"))
            }
            _ => Ok(()),
        };
        match self.decider.mode() {
            PublishDecisions::Local => {
                local.map_err(|(status, reason)| refuse(status, reason))?;
                Ok((claims, None))
            }
            PublishDecisions::Shadow => {
                // A device token that fails here only means the shadow
                // decision can't be asked: the local answer is enforced.
                let chain = self.chain(verifier, headers, &claims, token).await;
                let verdict = match &chain {
                    Ok(chain) => self.decider.ask(chain).await,
                    Err((_, reason)) => {
                        warn!(sub = %claims.sub, reason, "Publish decision shadow: chain refused");
                        Verdict::Unavailable
                    }
                };
                log_shadow("publisher", &claims.sub, local.is_ok(), verdict);
                local.map_err(|(status, reason)| refuse(status, reason))?;
                Ok((claims, chain.ok()))
            }
            PublishDecisions::Pdp => {
                let chain = self
                    .chain(verifier, headers, &claims, token)
                    .await
                    .map_err(|(status, reason)| refuse(status, reason))?;
                match self.decider.ask(&chain).await {
                    Verdict::Permit => Ok((claims, Some(chain))),
                    Verdict::Deny => Err(refuse(StatusCode::FORBIDDEN, "publishing not permitted")),
                    Verdict::Unavailable => Err(refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "decision service unavailable",
                    )),
                }
            }
        }
    }

    /// The verified entity chain for a publish decision: the person, each
    /// `X-Entity-Token` device bound to it, and this node's environment.
    async fn chain(
        &self,
        verifier: &CwtVerifier,
        headers: &HeaderMap,
        claims: &VerifiedClaims,
        token: &str,
    ) -> Result<Vec<ChainEntity>, (StatusCode, &'static str)> {
        let devices = entity_chain::entity_tokens(headers);
        let environment = self.decider.environment();
        entity_chain::check_length(devices.len(), environment.is_some())?;
        let mut chain = vec![entity_chain::subject_entity(claims, Some(token))];
        chain.extend(
            entity_chain::verified_devices(verifier, &devices, &claims.sub, now_secs()).await?,
        );
        if let Some(env) = environment {
            chain.push(entity_chain::environment_entity(env));
        }
        Ok(chain)
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
        .route("/moderation/blocks/catalogs", get(list_catalog_blocks::<S>))
        .route(
            "/moderation/blocks/catalogs/{subject}",
            put(block_catalog::<S>).delete(lift_catalog_block::<S>),
        )
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
    let (claims, chain) = s
        .policy
        .publisher_with_chain(&s.verifier, &s.gate.moderation, &headers)
        .await
        .map_err(fail)?;
    let chain = chain.as_deref().map(strip_tokens);
    let refuse = |(status, reason): (StatusCode, &'static str)| {
        warn!(sub = %claims.sub, %status, reason, "Publish session refused");
        fail((status, reason))
    };
    let endpoint = EndpointId::from_str(body.endpoint_id.trim())
        .map_err(|_| refuse((StatusCode::BAD_REQUEST, "invalid endpointId")))?;
    let token = bearer(&headers).unwrap_or_default();
    verify_possession(&endpoint, token, body.timestamp, &body.signature).map_err(refuse)?;
    let expires_at = now_secs() + s.policy.session_ttl.as_secs() as i64;
    // Stored so that any instance finds it (#32). Without it the session
    // still works on this instance, as before.
    let record = SessionRecord {
        endpoint_id: endpoint.to_string(),
        subject: claims.sub.clone(),
        expires_at,
        chain: chain.clone(),
    };
    let body = Bytes::from(serde_json::to_vec(&record).expect("session record serializes"));
    if let Err(e) = s
        .store
        .put_record(SESSIONS, &record.endpoint_id, body)
        .await
    {
        warn!(sub = %claims.sub, %endpoint, error = %e, "Publish session not stored; it holds on this instance only");
    }
    s.gate
        .open_session_with_chain(endpoint, &claims.sub, s.policy.session_ttl, chain);
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

async fn list_catalog_blocks<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<CatalogBlock>>> {
    s.policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    Ok(Json(s.gate.moderation.active_catalog_blocks()))
}

async fn block_catalog<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    Path(subject): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ActionRequest>,
) -> ApiResult<Json<CatalogBlock>> {
    let by = s
        .policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    let subject = canonical_subject(&subject).to_string();
    if !valid_subject(&subject) {
        return Err(fail((StatusCode::BAD_REQUEST, "invalid subject")));
    }
    if body.hide_catalog {
        return Err(fail((
            StatusCode::BAD_REQUEST,
            "hideCatalog applies to suspensions",
        )));
    }
    let record = CatalogBlock {
        subject: subject.clone(),
        reason: checked_reason(&body.reason)?,
        report_id: checked_report_id(body.report_id)?,
        by,
        at: now_secs(),
        lifted_by: None,
        lifted_at: None,
    };
    audit(
        s.store.as_ref(),
        "block_catalog",
        CATALOG_BLOCKS,
        &subject,
        &record,
    )
    .await?;
    persist(s.store.as_ref(), CATALOG_BLOCKS, &subject, &record).await?;
    s.gate.moderation.apply_catalog_block(record.clone());
    info!(audit = "block_catalog", %subject, by = %record.by, report = ?record.report_id, "Creator catalog blocked");
    Ok(Json(record))
}

async fn lift_catalog_block<S: ModerationStore>(
    State(s): State<Arc<ModerationApi<S>>>,
    Path(subject): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<CatalogBlock>> {
    let by = s
        .policy
        .operator(&s.verifier, &headers)
        .await
        .map_err(fail)?;
    let subject = canonical_subject(&subject).to_string();
    let mut record = s
        .gate
        .moderation
        .active_catalog_blocks()
        .into_iter()
        .find(|b| b.subject == subject)
        .ok_or_else(|| fail((StatusCode::NOT_FOUND, "no active catalog block")))?;
    record.lifted_by = Some(by);
    record.lifted_at = Some(now_secs());
    audit(
        s.store.as_ref(),
        "lift_catalog_block",
        CATALOG_BLOCKS,
        &subject,
        &record,
    )
    .await?;
    persist(s.store.as_ref(), CATALOG_BLOCKS, &subject, &record).await?;
    s.gate.moderation.apply_catalog_block(record.clone());
    info!(audit = "lift_catalog_block", %subject, by = ?record.lifted_by, "Catalog block lifted");
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
        /// Session lookups served.
        pub session_gets: std::sync::atomic::AtomicUsize,
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

    impl SessionStore for MemModeration {
        fn get_session<'a>(
            &'a self,
            endpoint: &'a str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>> {
            Box::pin(async move {
                self.session_gets
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                anyhow::ensure!(!*self.fail.lock().unwrap(), "down");
                Ok(self
                    .records
                    .lock()
                    .unwrap()
                    .get(&format!("{SESSIONS}/{endpoint}"))
                    .cloned())
            })
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
        harness_with(Default::default())
    }

    fn harness_with(decider: Arc<PublishDecider>) -> Harness {
        let (_, vk) = keypair();
        let store = Arc::new(MemModeration::default());
        let gate = Arc::new(
            PublishGate::new(Arc::new(Moderation::default())).with_decider(Arc::clone(&decider)),
        );
        let api = Arc::new(ModerationApi {
            store: store.clone(),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(KID.to_vec(), vk)])),
            gate: gate.clone(),
            policy: Arc::new(PublishPolicy {
                entitlement: Some(DEFAULT_PUBLISH_ENTITLEMENT.into()),
                audience: Some("arkavo".into()),
                session_ttl: Duration::from_secs(600),
                operator_client_ids: HashSet::from(["moderation".to_string()]),
                decider,
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
        call_with(app, method, uri, bearer, &[], body).await
    }

    async fn call_with(
        app: &Router,
        method: &str,
        uri: &str,
        bearer: &str,
        headers: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {bearer}"));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
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
        let (sub, got) = h.gate.authorize_push(7, &"a".repeat(64)).await.unwrap();
        assert_eq!((sub.as_str(), got), ("u1", ep));
        // Another connection without a session is refused.
        h.gate.connected(8, Some(endpoint()));
        assert_eq!(
            h.gate.authorize_push(8, &"a".repeat(64)).await,
            Err(PushRefusal::NoSession)
        );
        assert_eq!(
            h.gate.authorize_push(9, &"a".repeat(64)).await,
            Err(PushRefusal::NoSession)
        );
    }

    /// Another instance's gate: the same moderation view and session store,
    /// none of this gate's sessions.
    fn other_instance(h: &Harness) -> PublishGate {
        PublishGate::new(Arc::clone(&h.gate.moderation))
            .with_session_store(Arc::clone(&h.store) as Arc<dyn SessionStore>)
    }

    #[tokio::test]
    async fn a_session_is_stored_and_another_instance_accepts_its_push() {
        let h = harness();
        let sk = key();
        let ep = sk.public();
        let tok = creator("arkavo:u1");
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let stored: SessionRecord =
            serde_json::from_slice(&h.store.records.lock().unwrap()[&format!("sessions/{ep}")])
                .unwrap();
        assert_eq!(stored.endpoint_id, ep.to_string());
        assert_eq!(stored.subject, "arkavo:u1");
        assert_eq!(stored.expires_at, body["expiresAt"].as_i64().unwrap());

        // The push lands on an instance that never saw the session (#32).
        let other = other_instance(&h);
        other.connected(1, Some(ep));
        let (sub, got) = other.authorize_push(1, &"a".repeat(64)).await.unwrap();
        assert_eq!((sub.as_str(), got), ("u1", ep));
        // Found once, it is held: the store is no longer needed.
        *h.store.fail.lock().unwrap() = true;
        assert!(other.authorize_push(1, &"a".repeat(64)).await.is_ok());
    }

    #[tokio::test]
    async fn a_stored_session_is_refused_when_expired_foreign_unreadable_or_unreachable() {
        let h = harness();
        let ep = endpoint();
        let put = |record: serde_json::Value| {
            h.store
                .records
                .lock()
                .unwrap()
                .insert(format!("sessions/{ep}"), Bytes::from(record.to_string()));
        };
        let other = other_instance(&h);
        other.connected(1, Some(ep));
        // Each step asks the store afresh, past the miss a step leaves.
        let refused = || async {
            other.misses.lock().unwrap().clear();
            other.authorize_push(1, &"a".repeat(64)).await
        };

        assert_eq!(refused().await, Err(PushRefusal::NoSession), "no record");
        put(
            serde_json::json!({"endpointId": ep.to_string(), "subject": "u1", "expiresAt": now_secs() - 1}),
        );
        assert_eq!(refused().await, Err(PushRefusal::NoSession), "expired");
        put(
            serde_json::json!({"endpointId": endpoint().to_string(), "subject": "u1", "expiresAt": now_secs() + 60}),
        );
        assert_eq!(
            refused().await,
            Err(PushRefusal::NoSession),
            "another endpoint's"
        );
        h.store
            .records
            .lock()
            .unwrap()
            .insert(format!("sessions/{ep}"), Bytes::from_static(b"{"));
        assert_eq!(refused().await, Err(PushRefusal::NoSession), "unreadable");

        put(
            serde_json::json!({"endpointId": ep.to_string(), "subject": "u1", "expiresAt": now_secs() + 60}),
        );
        *h.store.fail.lock().unwrap() = true;
        assert_eq!(refused().await, Err(PushRefusal::NoSession), "store down");
        *h.store.fail.lock().unwrap() = false;
        assert!(refused().await.is_ok());

        // A gate without a session store never looks.
        h.gate.connected(2, Some(ep));
        assert_eq!(
            h.gate.authorize_push(2, &"a".repeat(64)).await,
            Err(PushRefusal::NoSession)
        );
    }

    #[tokio::test]
    async fn a_missing_session_is_looked_up_once_then_refused_from_memory() {
        use std::sync::atomic::Ordering;
        let h = harness();
        let other = other_instance(&h);
        let ep = endpoint();
        other.connected(1, Some(ep));
        for _ in 0..5 {
            assert_eq!(
                other.authorize_push(1, &"a".repeat(64)).await,
                Err(PushRefusal::NoSession)
            );
        }
        assert_eq!(h.store.session_gets.load(Ordering::Relaxed), 1);

        // With every lookup busy, a push is refused without one.
        let _all = other
            .lookups
            .try_acquire_many(SESSION_LOOKUPS as u32)
            .unwrap();
        other.connected(2, Some(endpoint()));
        assert_eq!(
            other.authorize_push(2, &"a".repeat(64)).await,
            Err(PushRefusal::NoSession)
        );
        assert_eq!(h.store.session_gets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn misses_are_bounded() {
        let gate = PublishGate::new(Arc::new(Moderation::default()));
        for i in 0..SESSION_MISSES as u32 + 10 {
            let mut seed = [0xa5; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            gate.missed(iroh::SecretKey::from_bytes(&seed).public());
        }
        assert_eq!(gate.misses.lock().unwrap().len(), SESSION_MISSES);
    }

    #[tokio::test]
    async fn a_stored_session_still_honours_suspensions() {
        let h = harness();
        let sk = key();
        let tok = creator("u1");
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED);
        h.gate.moderation.suspend_for_test("u1", false);
        let other = other_instance(&h);
        other.connected(1, Some(sk.public()));
        assert_eq!(
            other.authorize_push(1, &"a".repeat(64)).await,
            Err(PushRefusal::Suspended)
        );
    }

    #[tokio::test]
    async fn a_session_the_store_refuses_still_holds_on_this_instance() {
        let h = harness();
        let sk = key();
        let tok = creator("u1");
        *h.store.fail.lock().unwrap() = true;
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED);
        h.gate.connected(1, Some(sk.public()));
        assert!(h.gate.authorize_push(1, &"a".repeat(64)).await.is_ok());
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
            h.gate.authorize_push(1, &"b".repeat(64)).await,
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
        assert!(h.gate.authorize_push(1, &"b".repeat(64)).await.is_ok());
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
        assert_eq!(
            h.gate.authorize_push(3, &hash).await,
            Err(PushRefusal::Blocked)
        );

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
            h.gate.authorize_push(5, &"a".repeat(64)).await,
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

    /// A decision service whose answer the test sets: permit, deny or down.
    #[derive(Default)]
    struct Pdp {
        answer: std::sync::atomic::AtomicU8,
        calls: std::sync::atomic::AtomicUsize,
    }

    const PERMIT: u8 = 0;
    const DENY: u8 = 1;
    const DOWN: u8 = 2;

    impl crate::authz::DecisionProvider for Pdp {
        async fn decide(
            &self,
            req: crate::authz::DecisionRequest,
        ) -> anyhow::Result<crate::authz::Decisions> {
            use std::sync::atomic::Ordering;
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = self.answer.load(Ordering::SeqCst);
            anyhow::ensure!(answer != DOWN, "pdp down");
            Ok(req
                .resources
                .into_iter()
                .map(|(id, _)| (id, answer == PERMIT))
                .collect())
        }
    }

    fn deciding(mode: PublishDecisions) -> (Harness, Arc<Pdp>) {
        let pdp = Arc::new(Pdp::default());
        let decider = PublishDecider::new(
            mode,
            Some(Arc::clone(&pdp) as crate::authz::SharedDecisionProvider),
            DEFAULT_PUBLISH_ENTITLEMENT.into(),
            Some(serde_json::json!({ "kind": "environment", "region": "us-east-1" })),
        )
        .unwrap();
        (harness_with(Arc::new(decider)), pdp)
    }

    fn set(pdp: &Pdp, answer: u8) {
        pdp.answer
            .store(answer, std::sync::atomic::Ordering::SeqCst);
    }

    #[tokio::test]
    async fn pdp_decides_sessions_and_replaces_the_local_entitlement_check() {
        let (h, pdp) = deciding(PublishDecisions::Pdp);
        // No entitlement in the token, but the PDP permits: the PDP decides.
        let tok = token("arkavo:u1", "arkavo", &[], &[]);
        let sk = key();
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        set(&pdp, DENY);
        let sk = key();
        let tok = creator("arkavo:u2");
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "publishing not permitted");

        set(&pdp, DOWN);
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "decision service unavailable");
    }

    #[tokio::test]
    async fn pdp_sessions_store_the_chain_without_tokens_and_pushes_are_decided_again() {
        let (h, pdp) = deciding(PublishDecisions::Pdp);
        let sk = key();
        let ep = sk.public();
        let tok = creator("arkavo:u1");
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let raw = h.store.records.lock().unwrap()[&format!("sessions/{ep}")].clone();
        assert!(!String::from_utf8_lossy(&raw).contains(&tok));
        let stored: SessionRecord = serde_json::from_slice(&raw).unwrap();
        let chain = stored.chain.expect("chain stored");
        assert_eq!(
            chain.iter().map(|e| e.kind).collect::<Vec<_>>(),
            vec![
                crate::authz::EntityKind::Subject,
                crate::authz::EntityKind::Environment
            ]
        );

        // Another instance reads the session back and asks the PDP again.
        let other = other_instance(&h).with_decider(Arc::clone(&h.gate.decider));
        other.connected(1, Some(ep));
        let before = pdp.calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(other.authorize_push(1, &"a".repeat(64)).await.is_ok());
        assert_eq!(
            pdp.calls.load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
    }

    #[tokio::test]
    async fn pdp_pushes_are_refused_when_denied_unavailable_or_without_a_stored_chain() {
        for (answer, want) in [
            (DENY, PushRefusal::NotPermitted),
            (DOWN, PushRefusal::DecisionUnavailable),
        ] {
            let (h, pdp) = deciding(PublishDecisions::Pdp);
            let sk = key();
            let tok = creator("arkavo:u1");
            let (status, _) =
                call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
            assert_eq!(status, StatusCode::CREATED);
            set(&pdp, answer);
            h.gate.connected(1, Some(sk.public()));
            assert_eq!(h.gate.authorize_push(1, &"a".repeat(64)).await, Err(want));
        }

        // A session opened without a chain (before this change) has nothing
        // to ask with.
        let (h, _) = deciding(PublishDecisions::Pdp);
        let ep = endpoint();
        h.gate
            .open_session(ep, "arkavo:u1", Duration::from_secs(60));
        h.gate.connected(2, Some(ep));
        assert_eq!(
            h.gate.authorize_push(2, &"a".repeat(64)).await,
            Err(PushRefusal::NoSession)
        );
    }

    #[tokio::test]
    async fn shadow_enforces_the_local_answer() {
        let (h, pdp) = deciding(PublishDecisions::Shadow);
        // Entitled locally, denied by the PDP: allowed.
        set(&pdp, DENY);
        let sk = key();
        let tok = creator("arkavo:u1");
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED);
        h.gate.connected(1, Some(sk.public()));
        assert!(h.gate.authorize_push(1, &"a".repeat(64)).await.is_ok());

        // Not entitled locally, permitted by the PDP: refused.
        set(&pdp, PERMIT);
        let sk = key();
        let tok = token("arkavo:u2", "arkavo", &[], &[]);
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "publishing entitlement required");

        // The PDP being down changes nothing.
        set(&pdp, DOWN);
        let sk = key();
        let tok = creator("arkavo:u3");
        let (status, _) = call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(pdp.calls.load(std::sync::atomic::Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn device_tokens_are_verified_only_when_the_pdp_is_asked() {
        let bad = [("x-entity-token", "not-a-cwt")];
        let tok = creator("arkavo:u1");

        let h = harness();
        let sk = key();
        let (status, _) = call_with(
            &h.app,
            "POST",
            "/publish/sessions",
            &tok,
            &bad,
            signed(&sk, &tok),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "local mode ignores device tokens"
        );

        let (h, pdp) = deciding(PublishDecisions::Pdp);
        let sk = key();
        let (status, body) = call_with(
            &h.app,
            "POST",
            "/publish/sessions",
            &tok,
            &bad,
            signed(&sk, &tok),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid entity token");
        assert_eq!(pdp.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn suspensions_still_apply_when_the_pdp_decides() {
        let (h, _) = deciding(PublishDecisions::Pdp);
        h.gate.moderation.suspend_for_test("arkavo:u1", false);
        let sk = key();
        let tok = creator("arkavo:u1");
        let (status, body) =
            call(&h.app, "POST", "/publish/sessions", &tok, signed(&sk, &tok)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "publishing suspended");
    }

    #[tokio::test]
    async fn catalog_blocks_are_audited_hide_the_catalog_and_can_be_lifted() {
        let h = harness();
        let op = operator();
        let (status, body) = call(
            &h.app,
            "PUT",
            "/moderation/blocks/catalogs/arkavo:u1",
            &op,
            Some(serde_json::json!({ "reason": "suspended", "reportId": "r-1" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["subject"], "u1");
        assert!(h.gate.moderation.catalog_hidden("arkavo:u1"));
        assert!(h.gate.moderation.catalog_hidden("u1"));
        assert!(!h.gate.moderation.catalog_hidden("u2"));
        // Stored under its own prefix, never read back as a hash block.
        assert!(
            h.store
                .records
                .lock()
                .unwrap()
                .contains_key("catalog-blocks/u1")
        );
        let view = Moderation::default();
        view.reload(h.store.as_ref()).await.unwrap();
        assert!(view.catalog_hidden("u1"));
        assert!(view.active_blocks().is_empty());

        let (status, list) = call(&h.app, "GET", "/moderation/blocks/catalogs", &op, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);

        let (status, _) = call(
            &h.app,
            "DELETE",
            "/moderation/blocks/catalogs/u1",
            &op,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!h.gate.moderation.catalog_hidden("u1"));
        let audit = h
            .store
            .records
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("audit/catalog-blocks/u1/"))
            .count();
        assert_eq!(audit, 2);

        // Only operators.
        let tok = creator("u3");
        let (status, _) = call(
            &h.app,
            "PUT",
            "/moderation/blocks/catalogs/u3",
            &tok,
            Some(serde_json::json!({ "reason": "x" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_hide_catalog_suspension_still_hides_the_catalog() {
        let m = Moderation::default();
        m.suspend_for_test("u1", false);
        assert!(!m.catalog_hidden("u1"));
        m.suspend_for_test("u2", true);
        assert!(m.catalog_hidden("arkavo:u2"));
    }
}
