//! HTTP tag API: the catalog discovery surface for iroh.arkavo.net.
//!
//! Content blobs are immutable (keyed by BLAKE3 hash), so every catalog
//! update produces a new hash — consumers need a *stable name with a
//! mutable pointer* to find a creator's latest catalog. That is a tag.
//!
//! - `GET /tags/{name}` — public resolution: tag name → current blob hash.
//! - `PUT /tags/{name}` — authenticated write. The bearer CWT's `sub`
//!   must own the tag: the name must be exactly `<tag_prefix><sub>`
//!   (default prefix `catalog/`), so a creator can only move their own
//!   pointer. Under the prefix the hash must name a stored catalog document
//!   whose `owner` is that subject (`docs/creator-catalogs.md`); any other
//!   tag must point at an ingested blob. No dangling pointers.
//! - `GET /healthz` — liveness.
//!
//! The creator catalog routes (`PUT /catalogs/{sub}` and friends) share
//! this state and live in [`crate::catalogs_api`].
//!
//! TLS is expected to terminate in front of this listener (ALB / reverse
//! proxy); the API itself serves plain HTTP.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::auth::{AuthError, CwtVerifier, VerifiedClaims};
use crate::config::CatalogToken;
use crate::creator_catalog;
use crate::moderation::{Moderation, PublishPolicy, bearer};

/// Storage the tag and catalog APIs need. `S3Client` is the production
/// implementation; tests use an in-memory store.
pub trait TagStore: Send + Sync + 'static {
    fn get_tag(&self, name: &str) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;
    fn put_tag(
        &self,
        name: &str,
        hash_hex: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Size of an ingested blob; `None` when it was never ingested.
    fn blob_size(&self, hash_hex: &str)
    -> impl Future<Output = anyhow::Result<Option<u64>>> + Send;
    /// The manifest ingest stored for a blob (`manifests/<hash>`); `None`
    /// when there is none.
    fn get_manifest(
        &self,
        hash_hex: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Bytes>>> + Send;
    fn get_catalog_document(
        &self,
        hash_hex: &str,
    ) -> impl Future<Output = anyhow::Result<Option<StoredDocument>>> + Send;
    /// Whether a catalog document is stored, without reading its body.
    fn head_catalog_document(
        &self,
        hash_hex: &str,
    ) -> impl Future<Output = anyhow::Result<Option<DocumentHead>>> + Send;
    /// Store a document with its owner recorded alongside.
    fn put_catalog_document(
        &self,
        hash_hex: &str,
        body: Bytes,
        owner: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// Store a catalog document's BAO outboard (catalog v2: the document is
    /// served over iroh).
    fn put_catalog_outboard(
        &self,
        hash_hex: &str,
        outboard: Bytes,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// A creator's stored catalog v2 pointer bundle.
    fn get_catalog_pointer(
        &self,
        sub: &str,
    ) -> impl Future<Output = anyhow::Result<Option<StoredPointer>>> + Send;
    /// Store a creator's pointer bundle only if the stored one still has
    /// the ETag `expected` (with `None`: only if none is stored). `false`
    /// when another write got there first.
    fn put_catalog_pointer(
        &self,
        sub: &str,
        body: Bytes,
        expected: Option<&str>,
    ) -> impl Future<Output = anyhow::Result<bool>> + Send;
}

/// A stored catalog v2 pointer bundle and the version it was read at.
#[derive(Debug, Clone)]
pub struct StoredPointer {
    pub body: Bytes,
    pub etag: String,
}

/// A stored catalog document.
#[derive(Debug, Clone)]
pub struct StoredDocument {
    pub body: Bytes,
    /// The owner recorded with the document at upload; `None` for a
    /// document stored without it.
    pub owner: Option<String>,
}

impl StoredDocument {
    /// The recorded owner, or the owner the bytes name for a document
    /// stored without one. `None` when neither is available.
    pub fn owner(&self) -> Option<String> {
        self.owner
            .clone()
            .or_else(|| creator_catalog::parse(&self.body).ok().map(|d| d.owner))
    }
}

/// A HEAD of a stored catalog document.
#[derive(Debug, Clone)]
pub struct DocumentHead {
    /// As [`StoredDocument::owner`]: `None` when the document was stored
    /// without it.
    pub owner: Option<String>,
}

// Inherent methods take precedence over trait methods in method-call
// resolution, so these delegate to S3Client's own methods.
impl TagStore for crate::store::s3::S3Client {
    async fn get_tag(&self, name: &str) -> anyhow::Result<Option<String>> {
        Self::get_tag(self, name).await
    }

    async fn put_tag(&self, name: &str, hash_hex: &str) -> anyhow::Result<()> {
        Self::put_tag(self, name, hash_hex).await
    }

    async fn blob_size(&self, hash_hex: &str) -> anyhow::Result<Option<u64>> {
        Self::blob_size(self, hash_hex).await
    }

    async fn get_manifest(&self, hash_hex: &str) -> anyhow::Result<Option<Bytes>> {
        Self::get_manifest(self, hash_hex).await
    }

    async fn get_catalog_document(&self, hash_hex: &str) -> anyhow::Result<Option<StoredDocument>> {
        Ok(Self::get_catalog_document(self, hash_hex)
            .await?
            .map(|(body, owner)| StoredDocument { body, owner }))
    }

    async fn head_catalog_document(&self, hash_hex: &str) -> anyhow::Result<Option<DocumentHead>> {
        Ok(Self::head_catalog_document(self, hash_hex)
            .await?
            .map(|owner| DocumentHead { owner }))
    }

    async fn put_catalog_document(
        &self,
        hash_hex: &str,
        body: Bytes,
        owner: &str,
    ) -> anyhow::Result<()> {
        Self::put_catalog_document(self, hash_hex, body, owner).await
    }

    async fn put_catalog_outboard(&self, hash_hex: &str, outboard: Bytes) -> anyhow::Result<()> {
        Self::put_catalog_outboard(self, hash_hex, outboard).await
    }

    async fn get_catalog_pointer(&self, sub: &str) -> anyhow::Result<Option<StoredPointer>> {
        Ok(Self::get_catalog_pointer(self, sub)
            .await?
            .map(|(body, etag)| StoredPointer { body, etag }))
    }

    async fn put_catalog_pointer(
        &self,
        sub: &str,
        body: Bytes,
        expected: Option<&str>,
    ) -> anyhow::Result<bool> {
        Self::put_catalog_pointer(self, sub, body, expected).await
    }
}

pub struct ApiState<S: TagStore> {
    pub store: Arc<S>,
    /// Shared with the catalog API so PE/NPE tokens verify against one
    /// cached key set.
    pub verifier: Arc<CwtVerifier>,
    pub tag_prefix: String,
    /// The creator publishing gate (tdf-iroh-s3#17). `None` keeps tag
    /// writes open to any verified subject (development only).
    pub publishing: Option<TagPublishing>,
    /// Which tag targets are catalog documents, so `GET /tags` asks S3
    /// once per hash.
    pub catalog_documents: DocumentPresence,
    pub catalog: CatalogRules,
}

/// Catalog settings from `[http]` (tdf-iroh-s3#39).
#[derive(Debug, Clone, Copy)]
pub struct CatalogRules {
    pub token: CatalogToken,
    /// Whether `/1` catalogs may still be published.
    pub accept_schema_1: bool,
}

impl Default for CatalogRules {
    fn default() -> Self {
        Self {
            token: CatalogToken::Optional,
            accept_schema_1: true,
        }
    }
}

/// Whether a hash names a stored catalog document, as `GET /tags` found.
/// A document is never replaced, and a TDF blob's hash never becomes a
/// document's, so both answers stand; the map is cleared when it reaches
/// [`Self::CAPACITY`] hashes.
#[derive(Default)]
pub struct DocumentPresence(std::sync::Mutex<std::collections::HashMap<String, bool>>);

impl DocumentPresence {
    const CAPACITY: usize = 100_000;

    fn get(&self, hash: &str) -> Option<bool> {
        self.lock().get(hash).copied()
    }

    fn insert(&self, hash: &str, present: bool) {
        let mut known = self.lock();
        if known.len() >= Self::CAPACITY {
            known.clear();
        }
        known.insert(hash.to_string(), present);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, bool>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct TagPublishing {
    pub policy: Arc<PublishPolicy>,
    pub moderation: Arc<Moderation>,
}

#[derive(Serialize)]
struct TagResponse {
    name: String,
    hash: String,
}

#[derive(Deserialize)]
struct PutTagRequest {
    hash: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn error_json(status: StatusCode, error: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
}

pub fn router<S: TagStore>(state: Arc<ApiState<S>>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/tags/{*name}", get(get_tag::<S>).put(put_tag::<S>))
        .with_state(state)
}

/// Tag names become S3 keys; constrain them to a safe alphabet. Allows
/// `catalog/arkavo:UUID`-style names (prefix slash, sub with colon).
fn valid_tag_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | ':' | '.' | '_' | '-' | '@'))
}

fn valid_blob_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

async fn get_tag<S: TagStore>(
    State(state): State<Arc<ApiState<S>>>,
    Path(name): Path<String>,
) -> Result<Json<TagResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !valid_tag_name(&name) {
        return Err(error_json(StatusCode::BAD_REQUEST, "invalid tag name"));
    }
    // A blocked creator's catalog is hidden; a blocked hash is never handed
    // out.
    let hidden = |hash: Option<&str>| {
        state.publishing.as_ref().is_some_and(|p| {
            hash.is_some_and(|h| p.moderation.is_blocked(h))
                || name
                    .strip_prefix(&state.tag_prefix)
                    .is_some_and(|sub| p.moderation.catalog_hidden(sub))
        })
    };
    if hidden(None) {
        return Err(error_json(StatusCode::NOT_FOUND, "tag not found"));
    }
    match state.store.get_tag(&name).await {
        Ok(Some(hash)) if hidden(Some(&hash)) => {
            Err(error_json(StatusCode::NOT_FOUND, "tag not found"))
        }
        Ok(Some(hash)) => {
            // A catalog tag resolves only to a stored catalog document. Tags
            // written before catalog documents existed may name a TDF blob;
            // for those there is no catalog yet. Each hash is looked up once.
            // When the lookup fails the tag resolves anyway: a reader then
            // asks `GET /catalog-documents` for it, which answers for itself.
            if name.starts_with(&state.tag_prefix) {
                let present = match state.catalog_documents.get(&hash) {
                    Some(present) => Some(present),
                    None => match state.store.head_catalog_document(&hash).await {
                        Ok(head) => {
                            state.catalog_documents.insert(&hash, head.is_some());
                            Some(head.is_some())
                        }
                        Err(e) => {
                            warn!(tag = %name, error = %e, "Catalog document lookup failed; resolving the tag unchecked");
                            None
                        }
                    },
                };
                if present == Some(false) {
                    info!(tag = %name, %hash, "Catalog tag names no catalog document");
                    return Err(error_json(StatusCode::NOT_FOUND, "tag not found"));
                }
            }
            Ok(Json(TagResponse { name, hash }))
        }
        Ok(None) => Err(error_json(StatusCode::NOT_FOUND, "tag not found")),
        Err(e) => {
            warn!(tag = %name, error = %e, "Tag lookup failed");
            Err(error_json(StatusCode::BAD_GATEWAY, "storage unavailable"))
        }
    }
}

async fn put_tag<S: TagStore>(
    State(state): State<Arc<ApiState<S>>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PutTagRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if !valid_tag_name(&name) {
        return Err(error_json(StatusCode::BAD_REQUEST, "invalid tag name"));
    }

    let claims = authorize_publisher(&state, &headers)
        .await
        .map_err(|(status, msg)| {
            warn!(%status, reason = msg, "Tag write rejected");
            error_json(status, msg)
        })?;

    // Namespace binding: a subject may only move its own tag.
    let expected = format!("{}{}", state.tag_prefix, claims.sub);
    if name != expected {
        warn!(tag = %name, sub = %claims.sub, "Tag write rejected: namespace mismatch");
        return Err(error_json(
            StatusCode::FORBIDDEN,
            "tag name does not match token subject",
        ));
    }

    if !valid_blob_hash(&body.hash) {
        return Err(error_json(
            StatusCode::BAD_REQUEST,
            "hash must be 64 hex chars",
        ));
    }

    if is_blocked(&state, &body.hash) {
        warn!(tag = %name, hash = %body.hash, "Tag write rejected: content is blocked");
        return Err(error_json(StatusCode::FORBIDDEN, "content is blocked"));
    }

    // No dangling pointers: the tag points at a stored catalog document of
    // its own subject, so rolling back to an earlier version can never
    // borrow someone else's catalog. (The namespace binding above means
    // every writable tag is `<tag_prefix><sub>`; no tag outside the prefix
    // can be written.) New catalogs go through `PUT /catalogs/{sub}`; this
    // route only moves the tag between stored ones.
    let doc = match state.store.get_catalog_document(&body.hash).await {
        Ok(Some(stored)) => creator_catalog::parse(&stored.body)
            .ok()
            .filter(|d| d.owner == claims.sub),
        Ok(None) => None,
        Err(e) => {
            warn!(error = %e, "Catalog document lookup failed");
            return Err(error_json(StatusCode::BAD_GATEWAY, "storage unavailable"));
        }
    };
    let Some(doc) = doc else {
        return Err(error_json(
            StatusCode::UNPROCESSABLE_ENTITY,
            "hash does not reference a catalog document of this subject",
        ));
    };

    // The earlier catalog passes today's payload checks, as a new upload
    // would: a block, or a payload gone from storage, since it was
    // published keeps the tag off it.
    crate::catalogs_api::check_catalog(&state, &doc)
        .await
        .map_err(|(status, msg)| {
            warn!(tag = %name, hash = %body.hash, %status, reason = %msg, "Tag write rejected");
            error_json(status, msg)
        })?;

    state.store.put_tag(&name, &body.hash).await.map_err(|e| {
        warn!(tag = %name, error = %e, "Tag write failed");
        error_json(StatusCode::BAD_GATEWAY, "storage unavailable")
    })?;

    info!(tag = %name, hash = %body.hash, sub = %claims.sub, "Tag updated");
    Ok(StatusCode::NO_CONTENT)
}

/// The token checks every publishing write shares (`PUT /tags/{name}`,
/// `PUT /catalogs/{sub}`). On a gated node: an entitled, unsuspended person
/// token (`PublishPolicy::publisher`). On an ungated node the token must
/// still verify; the publishing checks are skipped.
pub async fn authorize_publisher<S: TagStore>(
    state: &ApiState<S>,
    headers: &HeaderMap,
) -> Result<VerifiedClaims, (StatusCode, &'static str)> {
    match &state.publishing {
        Some(p) => {
            p.policy
                .publisher(&state.verifier, &p.moderation, headers)
                .await
        }
        None => {
            let token =
                bearer(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
            state
                .verifier
                .verify(token, crate::moderation::now_secs())
                .await
                .map_err(|e| {
                    warn!(error = %e, "Token verification failed");
                    match e {
                        AuthError::KeySet(_) => (StatusCode::BAD_GATEWAY, "invalid token"),
                        _ => (StatusCode::UNAUTHORIZED, "invalid token"),
                    }
                })
        }
    }
}

/// True when `hash` is blocked on this node. Only a gated node loads
/// moderation records, so an ungated node blocks nothing.
pub fn is_blocked<S: TagStore>(state: &ApiState<S>, hash: &str) -> bool {
    state
        .publishing
        .as_ref()
        .is_some_and(|p| p.moderation.is_blocked(hash))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// In-memory tags, ingested blobs (hash → size) and catalog documents.
    #[derive(Default)]
    pub struct MemStore {
        pub tags: Mutex<HashMap<String, String>>,
        pub blobs: Mutex<HashMap<String, u64>>,
        /// hash → stored manifest JSON.
        pub manifests: Mutex<HashMap<String, Bytes>>,
        /// How many times `get_manifest` was asked.
        pub manifest_reads: std::sync::atomic::AtomicUsize,
        pub catalog_documents: Mutex<HashMap<String, StoredDocument>>,
        /// How many times `blob_size` was asked (one S3 HEAD each).
        pub blob_lookups: std::sync::atomic::AtomicUsize,
        /// Every call fails, as an unreachable store would.
        pub down: std::sync::atomic::AtomicBool,
        /// How many times `head_catalog_document` was asked.
        pub document_heads: std::sync::atomic::AtomicUsize,
        /// `head_catalog_document` fails.
        pub heads_down: std::sync::atomic::AtomicBool,
        pub catalog_outboards: Mutex<HashMap<String, Bytes>>,
        /// sub → (bundle, version). The version stands in for S3's ETag.
        pub catalog_pointers: Mutex<HashMap<String, (Bytes, u64)>>,
        pub pointer_versions: std::sync::atomic::AtomicU64,
        /// The next conditional pointer write loses, as if another publish
        /// had moved the pointer since it was read.
        pub lose_next_pointer_race: std::sync::atomic::AtomicBool,
    }

    impl MemStore {
        pub fn new() -> Self {
            Self::default()
        }

        /// Record `hash` as ingested with `size` bytes.
        pub async fn ingest(&self, hash: &str, size: u64) {
            self.blobs.lock().await.insert(hash.to_string(), size);
        }

        /// Record `hash` as ingested with `size` bytes and `manifest`.
        pub async fn ingest_with_manifest(&self, hash: &str, size: u64, manifest: Vec<u8>) {
            self.ingest(hash, size).await;
            self.manifests
                .lock()
                .await
                .insert(hash.to_string(), Bytes::from(manifest));
        }

        fn up(&self) -> anyhow::Result<()> {
            anyhow::ensure!(
                !self.down.load(std::sync::atomic::Ordering::Relaxed),
                "store down"
            );
            Ok(())
        }
    }

    impl TagStore for MemStore {
        async fn get_tag(&self, name: &str) -> anyhow::Result<Option<String>> {
            self.up()?;
            Ok(self.tags.lock().await.get(name).cloned())
        }
        async fn put_tag(&self, name: &str, hash_hex: &str) -> anyhow::Result<()> {
            self.up()?;
            self.tags
                .lock()
                .await
                .insert(name.to_string(), hash_hex.to_string());
            Ok(())
        }
        async fn blob_size(&self, hash_hex: &str) -> anyhow::Result<Option<u64>> {
            self.up()?;
            self.blob_lookups
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.blobs.lock().await.get(hash_hex).copied())
        }
        async fn get_manifest(&self, hash_hex: &str) -> anyhow::Result<Option<Bytes>> {
            self.up()?;
            self.manifest_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.manifests.lock().await.get(hash_hex).cloned())
        }
        async fn get_catalog_document(
            &self,
            hash_hex: &str,
        ) -> anyhow::Result<Option<StoredDocument>> {
            self.up()?;
            Ok(self.catalog_documents.lock().await.get(hash_hex).cloned())
        }
        async fn head_catalog_document(
            &self,
            hash_hex: &str,
        ) -> anyhow::Result<Option<DocumentHead>> {
            self.up()?;
            self.document_heads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            anyhow::ensure!(
                !self.heads_down.load(std::sync::atomic::Ordering::Relaxed),
                "document lookups down"
            );
            Ok(self
                .catalog_documents
                .lock()
                .await
                .get(hash_hex)
                .map(|d| DocumentHead {
                    owner: d.owner.clone(),
                }))
        }
        async fn put_catalog_document(
            &self,
            hash_hex: &str,
            body: Bytes,
            owner: &str,
        ) -> anyhow::Result<()> {
            self.up()?;
            self.catalog_documents.lock().await.insert(
                hash_hex.to_string(),
                StoredDocument {
                    body,
                    owner: Some(owner.to_string()),
                },
            );
            Ok(())
        }
        async fn put_catalog_outboard(
            &self,
            hash_hex: &str,
            outboard: Bytes,
        ) -> anyhow::Result<()> {
            self.up()?;
            self.catalog_outboards
                .lock()
                .await
                .insert(hash_hex.to_string(), outboard);
            Ok(())
        }
        async fn get_catalog_pointer(&self, sub: &str) -> anyhow::Result<Option<StoredPointer>> {
            self.up()?;
            Ok(self
                .catalog_pointers
                .lock()
                .await
                .get(sub)
                .map(|(body, v)| StoredPointer {
                    body: body.clone(),
                    etag: format!("\"{v}\""),
                }))
        }
        /// As S3's conditional put: `If-Match` the version, or
        /// `If-None-Match: *`.
        async fn put_catalog_pointer(
            &self,
            sub: &str,
            body: Bytes,
            expected: Option<&str>,
        ) -> anyhow::Result<bool> {
            self.up()?;
            if self
                .lose_next_pointer_race
                .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                return Ok(false);
            }
            let mut pointers = self.catalog_pointers.lock().await;
            let current = pointers.get(sub).map(|(_, v)| format!("\"{v}\""));
            if current.as_deref() != expected {
                return Ok(false);
            }
            let v = self
                .pointer_versions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            pointers.insert(sub.to_string(), (body, v));
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MemStore;
    use super::*;
    use crate::auth::test_support::{keypair, mint};
    use crate::creator_catalog::test_support::catalog;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    struct Harness {
        router: Router,
        store: Arc<MemStore>,
        token: String,
    }

    /// Router with one creator ("arkavo:creator-1") and one ingested blob.
    fn harness() -> Harness {
        let (sk, vk) = keypair();
        let store = Arc::new(MemStore::new());
        let state = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            tag_prefix: "catalog/".to_string(),
            publishing: None,
            catalog_documents: Default::default(),
            catalog: Default::default(),
        });
        let token = mint(
            &sk,
            b"kid-1",
            "https://identity.test",
            "arkavo:creator-1",
            now(),
            now() + 3600,
        );
        Harness {
            router: router(state),
            store,
            token,
        }
    }

    fn blob_hash() -> String {
        "ab".repeat(32)
    }

    /// The `payloadSize` of `creator_catalog::test_support::entry`.
    const PAYLOAD_SIZE: u64 = 7_342_067;

    /// Store a catalog document for `owner` listing `n` entries of the
    /// ingested blob; its hash.
    async fn store_catalog(store: &MemStore, owner: &str, n: usize) -> String {
        use crate::creator_catalog::test_support::entry;
        store.ingest(&blob_hash(), PAYLOAD_SIZE).await;
        let entries = (0..n)
            .map(|i| entry(&format!("rec-{i}"), &blob_hash()))
            .collect();
        store_document(store, owner, entries).await
    }

    /// Store a catalog document for `owner` listing `entries`; its hash.
    async fn store_document(
        store: &MemStore,
        owner: &str,
        entries: Vec<serde_json::Value>,
    ) -> String {
        let bytes = catalog(owner, entries);
        let hash = blake3::hash(&bytes).to_hex().to_string();
        store
            .put_catalog_document(&hash, Bytes::from(bytes), owner)
            .await
            .unwrap();
        hash
    }

    async fn put(
        router: &Router,
        name: &str,
        hash: &str,
        token: Option<&str>,
    ) -> (StatusCode, String) {
        let mut req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/tags/{name}"))
            .header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = router
            .clone()
            .oneshot(
                req.body(Body::from(format!("{{\"hash\":\"{hash}\"}}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get_status(router: &Router, name: &str) -> (StatusCode, String) {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/tags/{name}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn get_unknown_tag_is_404() {
        let h = harness();
        let (status, _) = get_status(&h.router, "catalog/arkavo:creator-1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() {
        let h = harness();
        let hash = store_catalog(&h.store, "arkavo:creator-1", 1).await;

        let (status, body) =
            put(&h.router, "catalog/arkavo:creator-1", &hash, Some(&h.token)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

        let (status, body) = get_status(&h.router, "catalog/arkavo:creator-1").await;
        assert_eq!(status, StatusCode::OK);
        let got: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            got,
            serde_json::json!({ "name": "catalog/arkavo:creator-1", "hash": hash })
        );
    }

    #[tokio::test]
    async fn put_rolls_back_to_an_earlier_catalog() {
        let h = harness();
        let first = store_catalog(&h.store, "arkavo:creator-1", 1).await;
        let second = store_catalog(&h.store, "arkavo:creator-1", 2).await;
        for hash in [&second, &first] {
            let (status, body) =
                put(&h.router, "catalog/arkavo:creator-1", hash, Some(&h.token)).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        }
        let (_, body) = get_status(&h.router, "catalog/arkavo:creator-1").await;
        assert!(body.contains(&first), "{body}");
    }

    #[tokio::test]
    async fn put_without_token_is_401() {
        let h = harness();
        let (status, _) = put(&h.router, "catalog/arkavo:creator-1", &blob_hash(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn put_to_someone_elses_tag_is_403() {
        let h = harness();
        let hash = store_catalog(&h.store, "arkavo:other-creator", 1).await;
        let (status, body) = put(
            &h.router,
            "catalog/arkavo:other-creator",
            &hash,
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body.contains("tag name does not match token subject"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn put_needs_a_catalog_document_of_this_subject() {
        const WANT: &str = "hash does not reference a catalog document of this subject";
        let h = harness();
        // Nothing stored under the hash.
        let (status, body) = put(
            &h.router,
            "catalog/arkavo:creator-1",
            &blob_hash(),
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains(WANT), "{body}");

        // An ingested TDF blob is not a catalog document.
        h.store.ingest(&blob_hash(), 10).await;
        let (status, body) = put(
            &h.router,
            "catalog/arkavo:creator-1",
            &blob_hash(),
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains(WANT), "{body}");

        // Another subject's catalog, including the bare form of the same
        // UUID: owners compare byte for byte.
        for owner in ["arkavo:other-creator", "creator-1"] {
            let theirs = store_catalog(&h.store, owner, 1).await;
            let (status, body) = put(
                &h.router,
                "catalog/arkavo:creator-1",
                &theirs,
                Some(&h.token),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{owner}");
            assert!(body.contains(WANT), "{body}");
        }
        assert!(h.store.tags.lock().await.is_empty());
    }

    #[tokio::test]
    async fn put_reports_storage_failure_as_502() {
        let h = harness();
        let hash = store_catalog(&h.store, "arkavo:creator-1", 1).await;
        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let (status, _) = put(&h.router, "catalog/arkavo:creator-1", &hash, Some(&h.token)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn put_garbage_hash_is_400() {
        let h = harness();
        let (status, _) = put(
            &h.router,
            "catalog/arkavo:creator-1",
            "not-a-hash",
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_unsafe_tag_names() {
        let h = harness();
        let (status, _) = get_status(&h.router, "catalog/../blobs/steal").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_with_expired_token_is_401() {
        let (sk, vk) = keypair();
        let store = Arc::new(MemStore::new());
        let hash = store_catalog(&store, "arkavo:creator-1", 1).await;
        let state = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            tag_prefix: "catalog/".to_string(),
            publishing: None,
            catalog_documents: Default::default(),
            catalog: Default::default(),
        });
        let router = router(state);
        let expired = mint(
            &sk,
            b"kid-1",
            "https://identity.test",
            "arkavo:creator-1",
            now() - 7200,
            now() - 3600,
        );
        let (status, _) = put(&router, "catalog/arkavo:creator-1", &hash, Some(&expired)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A gated router (tdf-iroh-s3#17) and creator tokens with and without
    /// the publishing entitlement.
    struct Gated {
        router: Router,
        store: Arc<MemStore>,
        moderation: Arc<Moderation>,
        entitled: String,
        unentitled: String,
    }

    fn gated() -> Gated {
        use crate::auth::test_support::mint_with_aud;
        use crate::moderation::DEFAULT_PUBLISH_ENTITLEMENT;
        use ciborium::value::Value;
        let (sk, vk) = keypair();
        let store = Arc::new(MemStore::new());
        let moderation = Arc::new(Moderation::default());
        let state = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            tag_prefix: "catalog/".to_string(),
            catalog_documents: Default::default(),
            catalog: Default::default(),
            publishing: Some(TagPublishing {
                policy: Arc::new(PublishPolicy {
                    entitlement: Some(DEFAULT_PUBLISH_ENTITLEMENT.into()),
                    audience: Some("arkavo".into()),
                    session_ttl: std::time::Duration::from_secs(60),
                    operator_client_ids: Default::default(),
                    decider: Default::default(),
                }),
                moderation: Arc::clone(&moderation),
            }),
        });
        let tok = |ents: &[&str]| {
            mint_with_aud(
                &sk,
                b"kid-1",
                "https://identity.test",
                "arkavo:creator-1",
                "arkavo",
                now(),
                now() + 3600,
                &[(
                    "arkavo_entitlements",
                    Value::Array(ents.iter().map(|e| Value::Text((*e).into())).collect()),
                )],
            )
        };
        Gated {
            router: router(state),
            store,
            moderation,
            entitled: tok(&[DEFAULT_PUBLISH_ENTITLEMENT]),
            unentitled: tok(&["https://arkavo.ai/attr/action/value/read"]),
        }
    }

    #[tokio::test]
    async fn gated_put_needs_the_entitlement() {
        let g = gated();
        let hash = store_catalog(&g.store, "arkavo:creator-1", 1).await;
        let (status, _) = put(
            &g.router,
            "catalog/arkavo:creator-1",
            &hash,
            Some(&g.unentitled),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = put(
            &g.router,
            "catalog/arkavo:creator-1",
            &hash,
            Some(&g.entitled),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn gated_put_refuses_blocked_content_and_suspended_creators() {
        let g = gated();
        let hash = store_catalog(&g.store, "arkavo:creator-1", 1).await;
        g.moderation.block_for_test(&hash);
        let (status, body) = put(
            &g.router,
            "catalog/arkavo:creator-1",
            &hash,
            Some(&g.entitled),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let other = store_catalog(&g.store, "arkavo:creator-1", 2).await;
        g.moderation.suspend_for_test("creator-1", false);
        let (status, body) = put(
            &g.router,
            "catalog/arkavo:creator-1",
            &other,
            Some(&g.entitled),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("suspended"));
    }

    #[tokio::test]
    async fn a_hidden_catalog_or_blocked_target_is_not_resolved() {
        let g = gated();
        let hash = store_catalog(&g.store, "arkavo:creator-1", 1).await;
        g.store
            .tags
            .lock()
            .await
            .insert("catalog/arkavo:creator-1".into(), hash.clone());
        assert_eq!(
            get_status(&g.router, "catalog/arkavo:creator-1").await.0,
            StatusCode::OK
        );

        // Suspended without hiding: still resolves.
        g.moderation.suspend_for_test("creator-1", false);
        assert_eq!(
            get_status(&g.router, "catalog/arkavo:creator-1").await.0,
            StatusCode::OK
        );
        // Hidden: 404.
        g.moderation.suspend_for_test("creator-1", true);
        assert_eq!(
            get_status(&g.router, "catalog/arkavo:creator-1").await.0,
            StatusCode::NOT_FOUND
        );

        // A catalog block hides it the same way.
        let g = gated();
        let hash = store_catalog(&g.store, "arkavo:creator-1", 1).await;
        g.store
            .tags
            .lock()
            .await
            .insert("catalog/arkavo:creator-1".into(), hash);
        g.moderation.block_catalog_for_test("arkavo:creator-1");
        assert_eq!(
            get_status(&g.router, "catalog/arkavo:creator-1").await.0,
            StatusCode::NOT_FOUND
        );

        let g = gated();
        let hash = store_catalog(&g.store, "arkavo:creator-1", 1).await;
        g.store
            .tags
            .lock()
            .await
            .insert("catalog/arkavo:creator-1".into(), hash.clone());
        g.moderation.block_for_test(&hash);
        assert_eq!(
            get_status(&g.router, "catalog/arkavo:creator-1").await.0,
            StatusCode::NOT_FOUND
        );
    }

    /// A catalog tag written before catalog documents existed may name a
    /// TDF blob. It resolves as "no catalog", so Creator starts a fresh one
    /// and a viewer shows none, instead of both failing on
    /// `GET /catalog-documents`.
    #[tokio::test]
    async fn a_catalog_tag_naming_no_catalog_document_is_not_found() {
        let h = harness();
        h.store.ingest(&blob_hash(), PAYLOAD_SIZE).await;
        h.store
            .tags
            .lock()
            .await
            .insert("catalog/arkavo:creator-1".into(), blob_hash());
        let (status, body) = get_status(&h.router, "catalog/arkavo:creator-1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("tag not found"), "{body}");

        // Once the creator publishes, the tag resolves.
        let hash = store_catalog(&h.store, "arkavo:creator-1", 1).await;
        let (status, _) = put(&h.router, "catalog/arkavo:creator-1", &hash, Some(&h.token)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            get_status(&h.router, "catalog/arkavo:creator-1").await.0,
            StatusCode::OK
        );

        // A tag outside the catalog prefix is not a catalog tag.
        h.store
            .tags
            .lock()
            .await
            .insert("other/name".into(), blob_hash());
        assert_eq!(get_status(&h.router, "other/name").await.0, StatusCode::OK);
    }

    /// Rolling the tag back applies today's payload checks to the earlier
    /// catalog, as publishing it again would.
    #[tokio::test]
    async fn a_rollback_applies_the_payload_checks() {
        use crate::creator_catalog::test_support::entry;
        const TAG: &str = "catalog/arkavo:creator-1";

        // A payload blocked since the catalog was published.
        let g = gated();
        let earlier = store_catalog(&g.store, "arkavo:creator-1", 1).await;
        g.moderation.block_for_test(&blob_hash());
        let (status, body) = put(&g.router, TAG, &earlier, Some(&g.entitled)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("content is blocked"), "{body}");
        assert!(g.store.tags.lock().await.is_empty());

        // A payload that is not an ingested blob.
        let h = harness();
        let missing = "cd".repeat(32);
        let hash =
            store_document(&h.store, "arkavo:creator-1", vec![entry("rec-1", &missing)]).await;
        let (status, body) = put(&h.router, TAG, &hash, Some(&h.token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body.contains(&format!("payload {missing} is not ingested")),
            "{body}"
        );

        // A payloadSize that differs from the stored blob.
        h.store.ingest(&blob_hash(), PAYLOAD_SIZE).await;
        let mut wrong = entry("rec-1", &blob_hash());
        wrong["payloadSize"] = serde_json::json!(PAYLOAD_SIZE - 1);
        let hash = store_document(&h.store, "arkavo:creator-1", vec![wrong]).await;
        let (status, body) = put(&h.router, TAG, &hash, Some(&h.token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            body.contains(&format!("payload {} size does not match", blob_hash())),
            "{body}"
        );
        assert!(h.store.tags.lock().await.is_empty());
    }

    /// `GET /tags` asks storage once per hash whether it names a catalog
    /// document, and resolves the tag when storage cannot answer.
    #[tokio::test]
    async fn a_tag_read_looks_up_each_document_once() {
        use std::sync::atomic::Ordering::Relaxed;
        const TAG: &str = "catalog/arkavo:creator-1";
        let h = harness();
        let hash = store_catalog(&h.store, "arkavo:creator-1", 1).await;
        let (status, body) = put(&h.router, TAG, &hash, Some(&h.token)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        for _ in 0..3 {
            assert_eq!(get_status(&h.router, TAG).await.0, StatusCode::OK);
        }
        assert_eq!(h.store.document_heads.load(Relaxed), 1);

        // A legacy tag's answer is kept too.
        h.store.tags.lock().await.insert(TAG.into(), blob_hash());
        for _ in 0..3 {
            assert_eq!(get_status(&h.router, TAG).await.0, StatusCode::NOT_FOUND);
        }
        assert_eq!(h.store.document_heads.load(Relaxed), 2);

        // Storage cannot answer for a new hash: the tag resolves.
        h.store.heads_down.store(true, Relaxed);
        let other = "ef".repeat(32);
        h.store.tags.lock().await.insert(TAG.into(), other.clone());
        let (status, body) = get_status(&h.router, TAG).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(&other), "{body}");
    }

    /// A rollback looks up every payload, including one the current
    /// catalog also lists: it may have left storage since.
    #[tokio::test]
    async fn a_rollback_rechecks_payloads_the_current_catalog_shares() {
        const TAG: &str = "catalog/arkavo:creator-1";
        let h = harness();
        let earlier = store_catalog(&h.store, "arkavo:creator-1", 1).await;
        let current = store_catalog(&h.store, "arkavo:creator-1", 2).await;
        let (status, body) = put(&h.router, TAG, &current, Some(&h.token)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

        h.store.blobs.lock().await.remove(&blob_hash());
        let (status, body) = put(&h.router, TAG, &earlier, Some(&h.token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.contains(&format!("payload {} is not ingested", blob_hash())),
            "{body}"
        );
        assert_eq!(h.store.tags.lock().await.get(TAG), Some(&current));
    }
}
