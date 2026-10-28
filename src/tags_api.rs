//! The catalog APIs' shared state and checks, and `GET /healthz`.
//!
//! [`ApiState`] and the [`TagStore`] it reads and writes are shared by the
//! creator catalog routes ([`crate::catalogs_api`],
//! [`crate::catalogs_v2_api`]); so are the token checks for publishing
//! ([`authorize_publisher`]) and for resolving a catalog
//! ([`authorize_catalog_reader`]). The tag routes (`GET`/`PUT /tags/{name}`)
//! were retired with catalog `/1` (tdf-iroh-s3#39): a creator's catalog is
//! found through its signed v2 pointer.

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use bytes::Bytes;
use std::sync::Arc;
use tracing::warn;

use crate::auth::{AuthError, CwtVerifier, VerifiedClaims};
use crate::moderation::{Moderation, PublishPolicy, bearer};

/// Storage the catalog APIs need. `S3Client` is the production
/// implementation; tests use an in-memory store.
pub trait TagStore: Send + Sync + 'static {
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
    /// Store a catalog's index record (`catalog-indexes/<hash>`), never
    /// served.
    fn put_catalog_index(
        &self,
        hash_hex: &str,
        body: Bytes,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// A catalog's index record; `None` for a catalog stored without one.
    fn get_catalog_index(
        &self,
        hash_hex: &str,
    ) -> impl Future<Output = anyhow::Result<Option<Bytes>>> + Send;
    /// Record `creator` as the creator of the Patreon campaign
    /// `campaign_id` (`campaign-creators/<id>`).
    fn put_campaign_creator(
        &self,
        campaign_id: &str,
        creator: &str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;
    /// The creator recorded for the Patreon campaign `campaign_id`, or
    /// `None`.
    fn get_campaign_creator(
        &self,
        campaign_id: &str,
    ) -> impl Future<Output = anyhow::Result<Option<String>>> + Send;
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

    async fn put_catalog_index(&self, hash_hex: &str, body: Bytes) -> anyhow::Result<()> {
        Self::put_catalog_index(self, hash_hex, body).await
    }

    async fn get_catalog_index(&self, hash_hex: &str) -> anyhow::Result<Option<Bytes>> {
        Self::get_catalog_index(self, hash_hex).await
    }

    async fn put_campaign_creator(&self, campaign_id: &str, creator: &str) -> anyhow::Result<()> {
        Self::put_campaign_creator(self, campaign_id, creator).await
    }

    async fn get_campaign_creator(&self, campaign_id: &str) -> anyhow::Result<Option<String>> {
        Self::get_campaign_creator(self, campaign_id).await
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
    /// The creator publishing gate (tdf-iroh-s3#17). `None` keeps catalog
    /// writes open to any verified subject (development only).
    pub publishing: Option<TagPublishing>,
}

pub struct TagPublishing {
    pub policy: Arc<PublishPolicy>,
    pub moderation: Arc<Moderation>,
}

pub fn router<S: TagStore>(state: Arc<ApiState<S>>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

/// The token on routes that resolve a subject to its catalog
/// (tdf-iroh-s3#39), run before anything else, so a caller without a token
/// learns nothing about which subjects have a catalog: 401 `token required`
/// without one. Any Arkavo CWT the node verifies counts (issuer pin, no
/// audience pin), service CWTs included; what the reader may open is then
/// the catalog decision's.
pub async fn authorize_catalog_reader(
    verifier: &CwtVerifier,
    headers: &HeaderMap,
) -> Result<VerifiedClaims, (StatusCode, &'static str)> {
    let Some(token) = bearer(headers) else {
        warn!("Catalog read refused: no token");
        return Err((StatusCode::UNAUTHORIZED, "token required"));
    };
    match verifier.verify(token, crate::moderation::now_secs()).await {
        Ok(claims) => Ok(claims),
        Err(AuthError::KeySet(e)) => {
            warn!(error = %e, "Catalog read refused: key set unavailable");
            Err((StatusCode::BAD_GATEWAY, "key set unavailable"))
        }
        Err(e) => {
            warn!(error = %e, "Catalog read refused: invalid token");
            Err((StatusCode::UNAUTHORIZED, "invalid token"))
        }
    }
}

/// The token checks every publishing write shares (`PUT
/// /v2/catalogs/{sub}`). On a gated node: an entitled, unsuspended person
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

    /// In-memory ingested blobs (hash → size), catalog documents, indexes
    /// and pointers.
    #[derive(Default)]
    pub struct MemStore {
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
        pub catalog_outboards: Mutex<HashMap<String, Bytes>>,
        pub catalog_indexes: Mutex<HashMap<String, Bytes>>,
        /// campaign id → creator.
        pub campaign_creators: Mutex<HashMap<String, String>>,
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
        async fn put_catalog_index(&self, hash_hex: &str, body: Bytes) -> anyhow::Result<()> {
            self.up()?;
            self.catalog_indexes
                .lock()
                .await
                .insert(hash_hex.to_string(), body);
            Ok(())
        }
        async fn get_catalog_index(&self, hash_hex: &str) -> anyhow::Result<Option<Bytes>> {
            self.up()?;
            Ok(self.catalog_indexes.lock().await.get(hash_hex).cloned())
        }
        async fn put_campaign_creator(
            &self,
            campaign_id: &str,
            creator: &str,
        ) -> anyhow::Result<()> {
            self.up()?;
            self.campaign_creators
                .lock()
                .await
                .insert(campaign_id.to_string(), creator.to_string());
            Ok(())
        }
        async fn get_campaign_creator(&self, campaign_id: &str) -> anyhow::Result<Option<String>> {
            self.up()?;
            Ok(self
                .campaign_creators
                .lock()
                .await
                .get(campaign_id)
                .cloned())
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
