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
//!   pointer. The referenced hash must already be ingested (no dangling
//!   pointers to unvalidated content).
//! - `GET /healthz` — liveness.
//!
//! TLS is expected to terminate in front of this listener (ALB / reverse
//! proxy); the API itself serves plain HTTP.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::auth::{AuthError, CwtVerifier};

/// Storage the tag API needs. `S3Client` is the production implementation;
/// tests use an in-memory store.
pub trait TagStore: Send + Sync + 'static {
    fn get_tag(&self, name: &str) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;
    fn put_tag(
        &self,
        name: &str,
        hash_hex: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn has_blob(&self, hash_hex: &str) -> impl Future<Output = anyhow::Result<bool>> + Send;
}

// Inherent methods take precedence over trait methods in method-call
// resolution, so these delegate to S3Client's own get_tag/put_tag/has_blob.
impl TagStore for crate::store::s3::S3Client {
    async fn get_tag(&self, name: &str) -> anyhow::Result<Option<String>> {
        Self::get_tag(self, name).await
    }

    async fn put_tag(&self, name: &str, hash_hex: &str) -> anyhow::Result<()> {
        Self::put_tag(self, name, hash_hex).await
    }

    async fn has_blob(&self, hash_hex: &str) -> anyhow::Result<bool> {
        Self::has_blob(self, hash_hex).await
    }
}

pub struct ApiState<S: TagStore> {
    pub store: Arc<S>,
    /// Shared with the catalog API so PE/NPE tokens verify against one
    /// cached key set.
    pub verifier: Arc<CwtVerifier>,
    pub tag_prefix: String,
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
    error: &'static str,
}

fn error_json(status: StatusCode, error: &'static str) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error }))
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
    match state.store.get_tag(&name).await {
        Ok(Some(hash)) => Ok(Json(TagResponse { name, hash })),
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

    let token = bearer_token(&headers)
        .ok_or_else(|| error_json(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let claims = state.verifier.verify(token, now).await.map_err(|e| {
        let status = match e {
            AuthError::KeySet(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::UNAUTHORIZED,
        };
        warn!(error = %e, "Tag write rejected: token verification failed");
        error_json(status, "invalid token")
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

    // No dangling pointers: the catalog blob must already be ingested
    // (i.e. it passed TDF validation and landed in S3).
    match state.store.has_blob(&body.hash).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(error_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                "hash does not reference an ingested blob",
            ));
        }
        Err(e) => {
            warn!(error = %e, "Blob existence check failed");
            return Err(error_json(StatusCode::BAD_GATEWAY, "storage unavailable"));
        }
    }

    state.store.put_tag(&name, &body.hash).await.map_err(|e| {
        warn!(tag = %name, error = %e, "Tag write failed");
        error_json(StatusCode::BAD_GATEWAY, "storage unavailable")
    })?;

    info!(tag = %name, hash = %body.hash, sub = %claims.sub, "Tag updated");
    Ok(StatusCode::NO_CONTENT)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::{keypair, mint};
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    struct MemStore {
        tags: Mutex<HashMap<String, String>>,
        blobs: Mutex<Vec<String>>,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                tags: Mutex::new(HashMap::new()),
                blobs: Mutex::new(Vec::new()),
            }
        }
    }

    impl TagStore for MemStore {
        async fn get_tag(&self, name: &str) -> anyhow::Result<Option<String>> {
            Ok(self.tags.lock().await.get(name).cloned())
        }
        async fn put_tag(&self, name: &str, hash_hex: &str) -> anyhow::Result<()> {
            self.tags
                .lock()
                .await
                .insert(name.to_string(), hash_hex.to_string());
            Ok(())
        }
        async fn has_blob(&self, hash_hex: &str) -> anyhow::Result<bool> {
            Ok(self.blobs.lock().await.iter().any(|h| h == hash_hex))
        }
    }

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
        h.store.blobs.lock().await.push(blob_hash());

        let (status, body) = put(
            &h.router,
            "catalog/arkavo:creator-1",
            &blob_hash(),
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

        let (status, body) = get_status(&h.router, "catalog/arkavo:creator-1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(&blob_hash()), "{body}");
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
        h.store.blobs.lock().await.push(blob_hash());
        let (status, _) = put(
            &h.router,
            "catalog/arkavo:other-creator",
            &blob_hash(),
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn put_unknown_blob_is_422() {
        // Blob NOT ingested → refuse the pointer.
        let h = harness();
        let (status, _) = put(
            &h.router,
            "catalog/arkavo:creator-1",
            &blob_hash(),
            Some(&h.token),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
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
        store.blobs.lock().await.push(blob_hash());
        let state = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            tag_prefix: "catalog/".to_string(),
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
        let (status, _) = put(
            &router,
            "catalog/arkavo:creator-1",
            &blob_hash(),
            Some(&expired),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
