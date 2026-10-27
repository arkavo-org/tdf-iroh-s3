//! Creator catalog routes shared by every catalog (`docs/creator-catalogs.md`).
//!
//! - `GET /catalog-documents/{hash}` — public, immutable read of a stored
//!   catalog document: the envelope ZTDF, ciphertext to anyone without the
//!   catalog's attribute.
//! - `GET /blobs/{hash}` — public ingest confirmation: the size of an
//!   ingested, unblocked TDF.
//!
//! [`check_payloads`] holds the per-entry publish checks `PUT
//! /v2/catalogs/{sub}` runs on a catalog's index. On an ungated node
//! (`[publishing] required = false`) nothing is blocked (moderation records
//! are only loaded when gated).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use tracing::warn;

use crate::catalog_metadata::{self, MetadataRefusal};
use crate::creator_catalog::{CreatorCatalogEntry, is_lower_hex_hash};
use crate::tags_api::{ApiState, TagStore, is_blocked};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn fail(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

fn storage_unavailable(what: &str, e: anyhow::Error) -> ApiError {
    warn!(error = %e, "{what} failed");
    fail(StatusCode::BAD_GATEWAY, "storage unavailable")
}

/// How many blob existence checks one catalog upload runs at a time.
const INGEST_CHECK_CONCURRENCY: usize = 16;

pub fn router<S: TagStore>(state: Arc<ApiState<S>>) -> Router {
    Router::new()
        .route("/catalog-documents/{hash}", get(get_catalog_document::<S>))
        .route("/blobs/{hash}", get(get_blob::<S>))
        .with_state(state)
}

/// The checks for a catalog's index entries, in the contract's order:
/// - no payload or metadata TDF blocked (403 `content is blocked`);
/// - every one ingested (422 `payload <hash> is not ingested`, then
///   `metadata <hash> is not ingested`, the first missing one in entry
///   order);
/// - every entry's sizes equal to those blobs' (422 `payload <hash> size
///   does not match`, then `metadata <hash> size does not match`);
/// - each metadata TDF fits its recording, and each recording carries the
///   catalog's `attribute` (see [`check_metadata`]).
///
/// Each distinct hash is looked up once, at most
/// [`INGEST_CHECK_CONCURRENCY`] at a time.
pub(crate) async fn check_payloads<S: TagStore>(
    state: &ApiState<S>,
    entries: &[CreatorCatalogEntry],
    attribute: &str,
) -> Result<(), (StatusCode, String)> {
    let metadata = || entries.iter().map(|e| &e.metadata);
    if entries.iter().any(|e| is_blocked(state, &e.payload_hash))
        || metadata().any(|m| is_blocked(state, &m.hash))
    {
        return Err((StatusCode::FORBIDDEN, "content is blocked".to_string()));
    }

    let sizes = look_up(state, hashes(entries), |store, kind, hash| async move {
        match store.blob_size(&hash).await {
            Ok(Some(size)) => Ok(size),
            Ok(None) => Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{kind} {hash} is not ingested"),
            )),
            Err(e) => {
                warn!(error = %e, "Payload ingest check failed");
                Err((StatusCode::BAD_GATEWAY, "storage unavailable".to_string()))
            }
        }
    })
    .await?;

    // Per entry, not per hash: two entries naming one payload are each
    // checked.
    if let Some(e) = entries
        .iter()
        .find(|e| sizes.get(&e.payload_hash) != Some(&e.payload_size))
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("payload {} size does not match", e.payload_hash),
        ));
    }
    if let Some(m) = metadata().find(|m| sizes.get(&m.hash) != Some(&m.size)) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("metadata {} size does not match", m.hash),
        ));
    }
    check_metadata(state, entries, attribute).await
}

/// Each metadata TDF fits its recording, compared on the manifests ingest
/// stored (`catalog_metadata`). In order:
/// - both manifests are stored (422 `payload <hash> manifest is not
///   stored`, then `metadata <hash> …`) and readable (`… manifest is
///   unreadable`);
/// - the metadata policy holds only `uuid` and `body` (422 `metadata <hash>
///   policy may only hold uuid and body`), and its `uuid` is a non-empty
///   string (422 `metadata <hash> policy has no uuid`);
/// - its `payload.mimeType` is `CATALOG_ENTRY_MIME_TYPE` (422 `metadata
///   <hash> is not catalog metadata`);
/// - its attributes, dissemination list and KAS are the recording's (422
///   `metadata <hash> policy does not match payload <hash>`);
/// - no two metadata TDFs share a policy `uuid` (422 `metadata <hash> policy
///   uuid duplicates metadata <hash>`): a viewer unwraps them all in one bulk
///   rewrap, which refuses duplicate policy ids;
/// - then every entry's recording policy names `attribute`, the envelope's
///   (422 `entry <contentID> policy does not include the catalog
///   attribute`): a viewer who can open an entry can open the catalog.
async fn check_metadata<S: TagStore>(
    state: &ApiState<S>,
    entries: &[CreatorCatalogEntry],
    attribute: &str,
) -> Result<(), (StatusCode, String)> {
    if entries.is_empty() {
        return Ok(());
    }
    let manifests = look_up(state, hashes(entries), |store, kind, hash| async move {
        match store.get_manifest(&hash).await {
            Ok(Some(bytes)) => catalog_metadata::read_manifest(&bytes).ok_or_else(|| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{kind} {hash} manifest is unreadable"),
                )
            }),
            Ok(None) => Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("{kind} {hash} manifest is not stored"),
            )),
            Err(e) => {
                warn!(error = %e, "Manifest read failed");
                Err((StatusCode::BAD_GATEWAY, "storage unavailable".to_string()))
            }
        }
    })
    .await?;
    let mut policy_ids: HashMap<&str, &str> = HashMap::new();
    for e in entries {
        let m = &e.metadata;
        let (Some(payload), Some(meta)) = (manifests.get(&e.payload_hash), manifests.get(&m.hash))
        else {
            continue;
        };
        catalog_metadata::check(payload, meta).map_err(|why| {
            let msg = match why {
                MetadataRefusal::ExtraPolicyKeys => {
                    format!("metadata {} policy may only hold uuid and body", m.hash)
                }
                MetadataRefusal::NoPolicyId => format!("metadata {} policy has no uuid", m.hash),
                MetadataRefusal::NotCatalogMetadata => {
                    format!("metadata {} is not catalog metadata", m.hash)
                }
                MetadataRefusal::PolicyMismatch => format!(
                    "metadata {} policy does not match payload {}",
                    m.hash, e.payload_hash
                ),
            };
            (StatusCode::UNPROCESSABLE_ENTITY, msg)
        })?;
        if let Some(id) = meta.policy_id()
            && let Some(first) = policy_ids.insert(id, &m.hash)
        {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "metadata {} policy uuid duplicates metadata {first}",
                    m.hash
                ),
            ));
        }
    }
    if let Some(e) = entries.iter().find(|e| {
        !manifests
            .get(&e.payload_hash)
            .is_some_and(|p| p.has_attribute(attribute))
    }) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "entry {} policy does not include the catalog attribute",
                e.content_id
            ),
        ));
    }
    Ok(())
}

/// What a hash in a catalog entry names.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Payload,
    Metadata,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            Kind::Payload => "payload",
            Kind::Metadata => "metadata",
        })
    }
}

/// The distinct hashes `entries` name, each with what it is: every
/// payload, then every metadata TDF, in entry order. An index never names
/// one hash as both.
fn hashes<'a>(
    entries: impl IntoIterator<Item = &'a CreatorCatalogEntry> + Clone,
) -> Vec<(Kind, String)> {
    let mut seen = HashSet::new();
    let payloads = entries
        .clone()
        .into_iter()
        .map(|e| (Kind::Payload, e.payload_hash.as_str()));
    let metadata = entries
        .into_iter()
        .map(|e| (Kind::Metadata, e.metadata.hash.as_str()));
    payloads
        .chain(metadata)
        .filter(|(_, h)| seen.insert(*h))
        .map(|(kind, h)| (kind, h.to_string()))
        .collect()
}

/// Run `f` for each hash, at most [`INGEST_CHECK_CONCURRENCY`] at a time,
/// and stop at the first refusal in `hashes` order.
async fn look_up<S, T, F, Fut>(
    state: &ApiState<S>,
    hashes: Vec<(Kind, String)>,
    f: F,
) -> Result<HashMap<String, T>, (StatusCode, String)>
where
    S: TagStore,
    F: Fn(Arc<S>, Kind, String) -> Fut,
    Fut: Future<Output = Result<T, (StatusCode, String)>>,
{
    let mut found = HashMap::with_capacity(hashes.len());
    let mut checks = futures::stream::iter(hashes)
        .map(|(kind, hash)| {
            let lookup = f(Arc::clone(&state.store), kind, hash.clone());
            async move { (hash, lookup.await) }
        })
        .buffered(INGEST_CHECK_CONCURRENCY);
    while let Some((hash, result)) = checks.next().await {
        found.insert(hash, result?);
    }
    Ok(found)
}

/// `application/json`, with or without parameters such as `charset`.
pub(crate) fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

/// How long a client or proxy may reuse a catalog document. The bytes
/// never change, but a later block or `hideCatalog` suspension must reach
/// readers, so the reuse is short and revalidated with the ETag.
pub const CATALOG_DOCUMENT_CACHE_CONTROL: &str = "public, max-age=300";

async fn get_catalog_document<S: TagStore>(
    State(state): State<Arc<ApiState<S>>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !is_lower_hex_hash(&hash) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid hash"));
    }
    if is_blocked(&state, &hash) {
        return Err(fail(StatusCode::NOT_FOUND, "catalog not found"));
    }
    let not_found = || fail(StatusCode::NOT_FOUND, "catalog not found");
    let etag = format!("\"{hash}\"");
    let cache_headers = [
        (header::ETAG, etag.clone()),
        (
            header::CACHE_CONTROL,
            CATALOG_DOCUMENT_CACHE_CONTROL.to_string(),
        ),
    ];

    // A client holding this version revalidates: a HEAD answers whether it
    // is still stored and whose it is, without reading the body.
    if if_none_match(&headers, &etag) {
        let head = match state.store.head_catalog_document(&hash).await {
            Ok(Some(head)) => head,
            Ok(None) => return Err(not_found()),
            Err(e) => return Err(storage_unavailable("Catalog document lookup", e)),
        };
        if owner_hidden(&state, head.owner.as_deref()) {
            return Err(not_found());
        }
        return Ok((StatusCode::NOT_MODIFIED, cache_headers).into_response());
    }

    match state.store.get_catalog_document(&hash).await {
        Ok(Some(doc)) => {
            if owner_hidden(&state, doc.owner.as_deref()) {
                return Err(not_found());
            }
            Ok((
                cache_headers,
                [(header::CONTENT_TYPE, "application/zip")],
                doc.body,
            )
                .into_response())
        }
        Ok(None) => Err(not_found()),
        Err(e) => Err(storage_unavailable("Catalog document read", e)),
    }
}

/// True when the document's owner has a catalog block (or a `hideCatalog`
/// suspension) on this (gated) node.
pub(crate) fn owner_hidden<S: TagStore>(state: &ApiState<S>, owner: Option<&str>) -> bool {
    state
        .publishing
        .as_ref()
        .is_some_and(|p| owner.is_some_and(|o| p.moderation.catalog_hidden(o)))
}

/// Whether `If-None-Match` names `etag`: `*`, the tag itself, or its weak
/// form `W/"..."`, alone or in a comma-separated list.
fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag)
}

async fn get_blob<S: TagStore>(
    State(state): State<Arc<ApiState<S>>>,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_lower_hex_hash(&hash) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid hash"));
    }
    if is_blocked(&state, &hash) {
        return Err(fail(StatusCode::NOT_FOUND, "blob not found"));
    }
    match state.store.blob_size(&hash).await {
        Ok(Some(size)) => Ok(Json(serde_json::json!({ "hash": hash, "size": size }))),
        Ok(None) => Err(fail(StatusCode::NOT_FOUND, "blob not found")),
        Err(e) => Err(storage_unavailable("Blob lookup", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CwtVerifier;
    use crate::auth::test_support::keypair;
    use crate::catalog_metadata::test_support::{
        CAMPAIGN, KAS, manifest, metadata_manifest, metadata_policy, recording_policy,
    };
    use crate::creator_catalog::test_support::{METADATA_SIZE, PAYLOAD_SIZE, entry};
    use crate::creator_catalog::{self, CreatorCatalogEntry};
    use crate::moderation::{DEFAULT_PUBLISH_ENTITLEMENT, Moderation, PublishPolicy};
    use crate::tags_api::test_support::MemStore;
    use crate::tags_api::{StoredDocument, TagPublishing};
    use axum::body::Body;
    use axum::http::Request;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    const SUB: &str = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";

    struct Harness {
        app: Router,
        state: Arc<ApiState<MemStore>>,
        store: Arc<MemStore>,
        moderation: Arc<Moderation>,
    }

    fn harness(gated: bool) -> Harness {
        let (_, vk) = keypair();
        let store = Arc::new(MemStore::new());
        let moderation = Arc::new(Moderation::default());
        let state = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            publishing: gated.then(|| TagPublishing {
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
        Harness {
            app: router(Arc::clone(&state)),
            state,
            store,
            moderation,
        }
    }

    fn payload(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn meta(n: u8) -> String {
        format!("{:02x}", 0x80 + n).repeat(32)
    }

    /// Ingest payload(n) (a recording) and meta(n) (its metadata TDF), each
    /// with a stored manifest.
    async fn ingest_pair(h: &Harness, n: u8, meta_policy: serde_json::Value, kas: &[&str]) {
        h.store
            .ingest_with_manifest(
                &payload(n),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        h.store
            .ingest_with_manifest(&meta(n), METADATA_SIZE, metadata_manifest(meta_policy, kas))
            .await;
    }

    /// `metadata_policy()` with another uuid.
    fn metadata_policy_with_id(id: &str) -> serde_json::Value {
        let mut p = metadata_policy();
        p["uuid"] = json!(id);
        p
    }

    fn index(entries: Vec<serde_json::Value>) -> Vec<CreatorCatalogEntry> {
        creator_catalog::parse_index(json!(entries)).unwrap()
    }

    /// One entry: rec-1, payload(1), meta(1).
    fn one() -> Vec<CreatorCatalogEntry> {
        index(vec![entry("rec-1", &payload(1), &meta(1))])
    }

    async fn check(
        h: &Harness,
        entries: &[CreatorCatalogEntry],
    ) -> Result<(), (StatusCode, String)> {
        check_payloads(&h.state, entries, CAMPAIGN).await
    }

    fn unprocessable(msg: String) -> Result<(), (StatusCode, String)> {
        Err((StatusCode::UNPROCESSABLE_ENTITY, msg))
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn error(&self) -> String {
            serde_json::from_slice::<serde_json::Value>(&self.body).unwrap_or_default()["error"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
    }

    async fn get_with(app: &Router, uri: &str, if_none_match: Option<&str>) -> Reply {
        let mut req = Request::get(uri);
        if let Some(tag) = if_none_match {
            req = req.header(header::IF_NONE_MATCH, tag);
        }
        let res = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body,
        }
    }

    async fn get(app: &Router, uri: &str) -> Reply {
        get_with(app, uri, None).await
    }

    /// Store `body` as a catalog document of `owner`; its hash.
    async fn store_document(h: &Harness, body: &[u8], owner: Option<&str>) -> String {
        let hash = blake3::hash(body).to_hex().to_string();
        h.store.catalog_documents.lock().await.insert(
            hash.clone(),
            StoredDocument {
                body: Bytes::copy_from_slice(body),
                owner: owner.map(str::to_string),
            },
        );
        hash
    }

    #[tokio::test]
    async fn an_index_whose_metadata_fits_passes() {
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        assert_eq!(check(&h, &one()).await, Ok(()));
        assert_eq!(check(&h, &[]).await, Ok(()));
    }

    #[tokio::test]
    async fn blocked_content_is_refused_before_the_ingest_check() {
        let blocked = Err((StatusCode::FORBIDDEN, "content is blocked".to_string()));
        // payload(1) blocked and never ingested: the block answers.
        let h = harness(true);
        h.moderation.block_for_test(&payload(1));
        assert_eq!(check(&h, &one()).await, blocked);
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        h.moderation.block_for_test(&meta(1));
        assert_eq!(check(&h, &one()).await, blocked);
        // An ungated node blocks nothing.
        let h = harness(false);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        h.moderation.block_for_test(&payload(1));
        assert_eq!(check(&h, &one()).await, Ok(()));
    }

    #[tokio::test]
    async fn every_payload_must_be_ingested() {
        let h = harness(true);
        for n in [1, 3] {
            ingest_pair(&h, n, metadata_policy_with_id(&format!("u{n}")), &[KAS]).await;
        }
        let entries = index(vec![
            entry("rec-1", &payload(1), &meta(1)),
            entry("rec-2", &payload(2), &meta(2)),
            entry("rec-3", &payload(3), &meta(3)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!("payload {} is not ingested", payload(2)))
        );
    }

    #[tokio::test]
    async fn every_size_must_match_the_stored_blob() {
        let h = harness(true);
        for n in 1..=3 {
            ingest_pair(&h, n, metadata_policy_with_id(&format!("u{n}")), &[KAS]).await;
        }
        h.store.ingest(&payload(2), PAYLOAD_SIZE - 1).await;
        h.store.ingest(&payload(3), PAYLOAD_SIZE + 1).await;
        // The first mismatching entry, in entry order, is reported.
        let entries = index(vec![
            entry("rec-1", &payload(1), &meta(1)),
            entry("rec-3", &payload(3), &meta(3)),
            entry("rec-2", &payload(2), &meta(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!("payload {} size does not match", payload(3)))
        );
        // Two entries naming one payload are each checked.
        let mut wrong = entry("rec-1b", &payload(1), &meta(2));
        wrong["payloadSize"] = json!(PAYLOAD_SIZE + 1);
        let entries = index(vec![entry("rec-1", &payload(1), &meta(1)), wrong]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!("payload {} size does not match", payload(1)))
        );
        // An ingest failure is reported before any size mismatch.
        let entries = index(vec![
            entry("rec-3", &payload(3), &meta(3)),
            entry("rec-4", &payload(4), &meta(4)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!("payload {} is not ingested", payload(4)))
        );
    }

    #[tokio::test]
    async fn each_distinct_hash_is_looked_up_once() {
        use std::sync::atomic::Ordering::Relaxed;
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        h.store
            .ingest_with_manifest(
                &meta(2),
                METADATA_SIZE,
                metadata_manifest(metadata_policy_with_id("other"), &[KAS]),
            )
            .await;
        // Two entries share one recording.
        let entries = index(vec![
            entry("rec-1", &payload(1), &meta(1)),
            entry("rec-2", &payload(1), &meta(2)),
        ]);
        assert_eq!(check(&h, &entries).await, Ok(()));
        assert_eq!(h.store.blob_lookups.load(Relaxed), 3);
        assert_eq!(h.store.manifest_reads.load(Relaxed), 3);
    }

    #[tokio::test]
    async fn metadata_must_be_ingested_unblocked_and_of_its_size() {
        let h = harness(true);
        h.store
            .ingest_with_manifest(
                &payload(1),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("metadata {} is not ingested", meta(1)))
        );
        h.store
            .ingest_with_manifest(
                &meta(1),
                METADATA_SIZE + 1,
                metadata_manifest(metadata_policy(), &[KAS]),
            )
            .await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("metadata {} size does not match", meta(1)))
        );
    }

    #[tokio::test]
    async fn a_missing_payload_is_reported_before_missing_metadata() {
        let h = harness(true);
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("payload {} is not ingested", payload(1)))
        );
    }

    #[tokio::test]
    async fn both_manifests_must_be_stored_and_readable() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store
            .ingest_with_manifest(
                &meta(1),
                METADATA_SIZE,
                metadata_manifest(metadata_policy(), &[KAS]),
            )
            .await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("payload {} manifest is not stored", payload(1)))
        );
        h.store
            .ingest_with_manifest(
                &payload(1),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        h.store
            .ingest_with_manifest(&meta(1), METADATA_SIZE, b"not a manifest".to_vec())
            .await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("metadata {} manifest is unreadable", meta(1)))
        );
        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            check(&h, &one()).await,
            Err((StatusCode::BAD_GATEWAY, "storage unavailable".to_string()))
        );
    }

    #[tokio::test]
    async fn the_metadata_policy_is_minimal_and_matches_the_recording() {
        let mut classified = metadata_policy();
        classified["arkavo:classification"] = json!("flagged");
        let h = harness(true);
        ingest_pair(&h, 1, classified, &[KAS]).await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!(
                "metadata {} policy may only hold uuid and body",
                meta(1)
            ))
        );

        // A recording's manifest, not a metadata TDF's.
        let h = harness(true);
        h.store
            .ingest_with_manifest(
                &payload(1),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        h.store
            .ingest_with_manifest(&meta(1), METADATA_SIZE, manifest(metadata_policy(), &[KAS]))
            .await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("metadata {} is not catalog metadata", meta(1)))
        );

        let other_campaign = json!({ "uuid": "u", "body": {
            "dataAttributes": [{ "attribute": CAMPAIGN.replace("12345678", "1") }], "dissem": [] } });
        let open = json!({ "uuid": "u", "body": { "dataAttributes": [], "dissem": [] } });
        for (policy, kas) in [
            (other_campaign, &[KAS][..]),
            (open, &[KAS][..]),
            (metadata_policy(), &["https://other.example/kas"][..]),
        ] {
            let h = harness(true);
            ingest_pair(&h, 1, policy.clone(), kas).await;
            assert_eq!(
                check(&h, &one()).await,
                unprocessable(format!(
                    "metadata {} policy does not match payload {}",
                    meta(1),
                    payload(1)
                )),
                "{policy} {kas:?}"
            );
        }
    }

    #[tokio::test]
    async fn each_metadata_policy_has_its_own_uuid() {
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy_with_id(""), &[KAS]).await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("metadata {} policy has no uuid", meta(1)))
        );

        // One bulk rewrap refuses duplicate policy ids, even across recordings.
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        ingest_pair(&h, 2, metadata_policy(), &[KAS]).await;
        let entries = index(vec![
            entry("rec-1", &payload(1), &meta(1)),
            entry("rec-2", &payload(2), &meta(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!(
                "metadata {} policy uuid duplicates metadata {}",
                meta(2),
                meta(1)
            ))
        );
    }

    #[tokio::test]
    async fn every_recording_carries_the_catalog_attribute() {
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        let other = "https://patreon.arkavo.com/attr/campaign/value/99";
        assert_eq!(
            check_payloads(&h.state, &one(), other).await,
            unprocessable("entry rec-1 policy does not include the catalog attribute".into())
        );

        // The first entry whose recording lacks it is named, after every
        // metadata check passed.
        let other_policy = json!({ "uuid": "r2", "body": {
            "dataAttributes": [{ "attribute": other }], "dissem": [] } });
        h.store
            .ingest_with_manifest(
                &payload(2),
                PAYLOAD_SIZE,
                manifest(other_policy.clone(), &[KAS]),
            )
            .await;
        let mut meta2 = other_policy;
        meta2["uuid"] = json!("m2");
        h.store
            .ingest_with_manifest(&meta(2), METADATA_SIZE, metadata_manifest(meta2, &[KAS]))
            .await;
        let entries = index(vec![
            entry("rec-1", &payload(1), &meta(1)),
            entry("rec-2", &payload(2), &meta(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable("entry rec-2 policy does not include the catalog attribute".into())
        );
    }

    #[tokio::test]
    async fn catalog_documents_404_400_blocked_and_zip() {
        let h = harness(true);
        let r = get(&h.app, &format!("/catalog-documents/{}", payload(9))).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
        for bad in ["4F".repeat(32), "4f".repeat(31), "zz".repeat(32)] {
            let r = get(&h.app, &format!("/catalog-documents/{bad}")).await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::BAD_REQUEST, "invalid hash"),
                "{bad}"
            );
        }
        let hash = store_document(&h, b"PK envelope", Some(SUB)).await;
        let path = format!("/catalog-documents/{hash}");
        let r = get(&h.app, &path).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body.as_ref(), b"PK envelope");
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/zip");
        h.moderation.block_for_test(&hash);
        assert_eq!(get(&h.app, &path).await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_held_version_revalidates_with_its_etag() {
        let h = harness(true);
        let hash = store_document(&h, b"PK envelope", Some(SUB)).await;
        let path = format!("/catalog-documents/{hash}");
        let etag = format!("\"{hash}\"");

        for held in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"{}\", {etag}", payload(7)),
            "*".to_string(),
        ] {
            let r = get_with(&h.app, &path, Some(&held)).await;
            assert_eq!(r.status, StatusCode::NOT_MODIFIED, "{held}");
            assert!(r.body.is_empty(), "{held}");
            assert_eq!(r.headers[header::ETAG], etag.as_str());
            assert_eq!(r.headers[header::CACHE_CONTROL], "public, max-age=300");
        }

        // Another version held: the full document.
        let r = get_with(&h.app, &path, Some(&format!("\"{}\"", payload(7)))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body.as_ref(), b"PK envelope");

        // A document that is not stored is 404 even to `*`.
        let missing = format!("/catalog-documents/{}", payload(9));
        let r = get_with(&h.app, &missing, Some("*")).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );

        // A block reaches a client that revalidates.
        h.moderation.block_for_test(&hash);
        let r = get_with(&h.app, &path, Some(&etag)).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
    }

    #[tokio::test]
    async fn a_catalog_block_or_hidden_owner_hides_the_document() {
        let h = harness(true);
        let hash = store_document(&h, b"PK envelope", Some(SUB)).await;
        let path = format!("/catalog-documents/{hash}");
        let etag = format!("\"{hash}\"");
        assert_eq!(get(&h.app, &path).await.status, StatusCode::OK);

        // Suspended without hideCatalog: still served.
        h.moderation.suspend_for_test(SUB, false);
        assert_eq!(get(&h.app, &path).await.status, StatusCode::OK);
        // With hideCatalog: 404 to a plain read and to a revalidation.
        h.moderation.suspend_for_test(SUB, true);
        assert_eq!(get(&h.app, &path).await.status, StatusCode::NOT_FOUND);
        assert_eq!(
            get_with(&h.app, &path, Some(&etag)).await.status,
            StatusCode::NOT_FOUND
        );

        let h = harness(true);
        let hash = store_document(&h, b"PK envelope", Some(SUB)).await;
        h.moderation.block_catalog_for_test(SUB);
        let r = get(&h.app, &format!("/catalog-documents/{hash}")).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );

        // An ungated node hides nothing.
        let h = harness(false);
        let hash = store_document(&h, b"PK envelope", Some(SUB)).await;
        h.moderation.block_catalog_for_test(SUB);
        let r = get(&h.app, &format!("/catalog-documents/{hash}")).await;
        assert_eq!(r.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn storage_failure_is_502() {
        let h = harness(true);
        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let r = get(&h.app, &format!("/blobs/{}", payload(1))).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
        let r = get(&h.app, &format!("/catalog-documents/{}", payload(1))).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn blobs_confirm_ingest() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = get(&h.app, &format!("/blobs/{}", payload(1))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&r.body).unwrap(),
            json!({ "hash": payload(1), "size": 7_342_067 })
        );
        let r = get(&h.app, &format!("/blobs/{}", payload(2))).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "blob not found")
        );
        for bad in ["AB".repeat(32), "abc".to_string()] {
            let r = get(&h.app, &format!("/blobs/{bad}")).await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::BAD_REQUEST, "invalid hash")
            );
        }
        h.moderation.block_for_test(&payload(1));
        let r = get(&h.app, &format!("/blobs/{}", payload(1))).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "blob not found")
        );
    }
}
