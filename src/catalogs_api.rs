//! Creator catalog routes (`docs/creator-catalogs.md`).
//!
//! - `PUT /catalogs/{sub}` — publish a catalog document: store its exact
//!   bytes under `catalog-documents/<blake3>` and point the tag
//!   `<tag_prefix><sub>` at it. Same token checks as `PUT /tags/{name}`.
//! - `GET /catalog-documents/{hash}` — public, immutable read of a stored
//!   document.
//! - `GET /blobs/{hash}` — public ingest confirmation: the size of an
//!   ingested, unblocked TDF.
//!
//! The routes share [`ApiState`] with the tag API and exist whenever the
//! HTTP listener does. On an ungated node (`[publishing] required = false`)
//! the token still has to verify, the publishing checks are skipped, and
//! nothing is blocked (moderation records are only loaded when gated).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use tracing::{info, warn};

use crate::catalog_metadata::{self, MetadataRefusal};
use crate::creator_catalog::{
    self, CreatorCatalogEntry, MAX_CATALOG_BYTES, SCHEMA_2, Schema, is_lower_hex_hash,
};
use crate::tags_api::{ApiState, TagStore, authorize_publisher, is_blocked};

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
        .route("/catalogs/{sub}", put(put_catalog::<S>))
        .route("/catalog-documents/{hash}", get(get_catalog_document::<S>))
        .route("/blobs/{hash}", get(get_blob::<S>))
        .with_state(state)
}

async fn put_catalog<S: TagStore>(
    State(state): State<Arc<ApiState<S>>>,
    Path(sub): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    // 1. The publishing token checks (on an ungated node: verification only).
    let claims = authorize_publisher(&state, &headers)
        .await
        .map_err(|(status, msg)| {
            warn!(%status, reason = msg, %sub, "Catalog upload rejected");
            fail(status, msg)
        })?;

    // 2. A subject publishes only its own catalog. Byte for byte: no
    //    canonicalization, so `arkavo:<uuid>` and `<uuid>` differ.
    if sub != claims.sub {
        warn!(%sub, token_sub = %claims.sub, "Catalog upload rejected: subject mismatch");
        return Err(fail(
            StatusCode::FORBIDDEN,
            "catalog does not match token subject",
        ));
    }

    if !is_json(&headers) {
        return Err(fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type must be application/json",
        ));
    }

    // 3. At most MAX_CATALOG_BYTES, read only after the token checks.
    let declared_too_large = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_CATALOG_BYTES as u64);
    if declared_too_large {
        return Err(fail(StatusCode::PAYLOAD_TOO_LARGE, "catalog too large"));
    }
    let bytes = axum::body::to_bytes(body, MAX_CATALOG_BYTES)
        .await
        .map_err(|e| {
            let too_large = std::error::Error::source(&e)
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            if too_large {
                fail(StatusCode::PAYLOAD_TOO_LARGE, "catalog too large")
            } else {
                warn!(error = %e, "Catalog upload body unreadable");
                fail(StatusCode::BAD_REQUEST, "unreadable request body")
            }
        })?;
    // A `/1` document keeps `/1`'s smaller limit.
    if creator_catalog::too_large(&bytes) {
        return Err(fail(StatusCode::PAYLOAD_TOO_LARGE, "catalog too large"));
    }

    // 4. A valid document of this subject.
    let doc = creator_catalog::parse(&bytes).map_err(|reason| {
        fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid catalog: {reason}"),
        )
    })?;
    if doc.owner != sub {
        return Err(fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid catalog: owner does not match the catalog subject",
        ));
    }

    // 5. The document itself is not blocked (no tag may point at blocked
    //    content), then 6–8: its payloads pass the checks every catalog a
    //    tag points at must pass, each looked up again: a payload the
    //    current catalog lists may have left storage since it was published.
    let hash = blake3::hash(&bytes).to_hex().to_string();
    if is_blocked(&state, &hash) {
        warn!(%sub, "Catalog upload rejected: content is blocked");
        return Err(fail(StatusCode::FORBIDDEN, "content is blocked"));
    }
    check_catalog(&state, &doc).await.map_err(|(status, msg)| {
        warn!(%sub, %status, reason = %msg, "Catalog upload rejected");
        fail(status, msg)
    })?;

    // 9. Store the exact bytes, then move the tag.
    let size = bytes.len();
    let entries = doc.entries.len();
    state
        .store
        .put_catalog_document(&hash, bytes, &sub)
        .await
        .map_err(|e| storage_unavailable("Catalog document write", e))?;
    let name = format!("{}{}", state.tag_prefix, sub);
    state
        .store
        .put_tag(&name, &hash)
        .await
        .map_err(|e| storage_unavailable("Catalog tag write", e))?;

    info!(tag = %name, %hash, size, entries, "Catalog published");
    Ok(Json(serde_json::json!({
        "name": name,
        "hash": hash,
        "size": size,
    })))
}

/// Every check a catalog passes before a tag may point at it: its schema
/// is still accepted (`[http] accept_catalog_schema_1`; 422 `invalid
/// catalog: schema must be "arkavo.creator-catalog/2"`), then
/// [`check_payloads`].
pub(crate) async fn check_catalog<S: TagStore>(
    state: &ApiState<S>,
    doc: &creator_catalog::CreatorCatalog,
) -> Result<(), (StatusCode, String)> {
    if doc.schema == Schema::V1 && !state.catalog.accept_schema_1 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid catalog: schema must be \"{SCHEMA_2}\""),
        ));
    }
    check_payloads(state, &doc.entries).await
}

/// The checks for a catalog a tag will point at, in the contract's order:
/// - no payload or metadata TDF blocked (403 `content is blocked`);
/// - every one ingested (422 `payload <hash> is not ingested`, then
///   `metadata <hash> is not ingested`, the first missing one in entry
///   order);
/// - every entry's sizes equal to those blobs' (422 `payload <hash> size
///   does not match`, then `metadata <hash> size does not match`);
/// - for `/2`, each metadata TDF fits its recording (see [`check_metadata`]).
///
/// Each distinct hash is looked up once, at most
/// [`INGEST_CHECK_CONCURRENCY`] at a time.
pub(crate) async fn check_payloads<S: TagStore>(
    state: &ApiState<S>,
    entries: &[CreatorCatalogEntry],
) -> Result<(), (StatusCode, String)> {
    let metadata = || entries.iter().filter_map(|e| e.metadata.as_ref());
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
    check_metadata(state, entries).await
}

/// `/2`: each metadata TDF fits its recording, compared on the manifests
/// ingest stored (`catalog_metadata`). In order:
/// - both manifests are stored (422 `payload <hash> manifest is not
///   stored`, then `metadata <hash> …`) and readable (`… manifest is
///   unreadable`);
/// - the metadata policy holds only `uuid` and `body` (422 `metadata <hash>
///   policy may only hold uuid and body`);
/// - its attributes, dissemination list and KAS are the recording's (422
///   `metadata <hash> policy does not match payload <hash>`).
async fn check_metadata<S: TagStore>(
    state: &ApiState<S>,
    entries: &[CreatorCatalogEntry],
) -> Result<(), (StatusCode, String)> {
    let with_metadata: Vec<&CreatorCatalogEntry> =
        entries.iter().filter(|e| e.metadata.is_some()).collect();
    if with_metadata.is_empty() {
        return Ok(());
    }
    let manifests = look_up(
        state,
        hashes(with_metadata.iter().copied()),
        |store, kind, hash| async move {
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
        },
    )
    .await?;
    for e in with_metadata {
        let Some(m) = &e.metadata else { continue };
        let (Some(payload), Some(meta)) = (manifests.get(&e.payload_hash), manifests.get(&m.hash))
        else {
            continue;
        };
        catalog_metadata::check(payload, meta).map_err(|why| {
            let msg = match why {
                MetadataRefusal::ExtraPolicyKeys => {
                    format!("metadata {} policy may only hold uuid and body", m.hash)
                }
                MetadataRefusal::PolicyMismatch => format!(
                    "metadata {} policy does not match payload {}",
                    m.hash, e.payload_hash
                ),
            };
            (StatusCode::UNPROCESSABLE_ENTITY, msg)
        })?;
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
/// payload, then every metadata TDF, in entry order. `/2` never names one
/// hash as both.
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
        .filter_map(|e| e.metadata.as_ref())
        .map(|m| (Kind::Metadata, m.hash.as_str()));
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
        let owner = match head.owner {
            Some(owner) => Some(owner),
            // Stored without owner metadata: the bytes name the owner. Only
            // a gated node hides anything, so only it needs them.
            None if state.publishing.is_some() => {
                match state.store.get_catalog_document(&hash).await {
                    Ok(Some(doc)) => doc.owner(),
                    Ok(None) => return Err(not_found()),
                    Err(e) => return Err(storage_unavailable("Catalog document read", e)),
                }
            }
            None => None,
        };
        if owner_hidden(&state, owner.as_deref()) {
            return Err(not_found());
        }
        return Ok((StatusCode::NOT_MODIFIED, cache_headers).into_response());
    }

    match state.store.get_catalog_document(&hash).await {
        Ok(Some(doc)) => {
            if state.publishing.is_some() && owner_hidden(&state, doc.owner().as_deref()) {
                return Err(not_found());
            }
            Ok((
                cache_headers,
                [(header::CONTENT_TYPE, "application/json")],
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
    use crate::auth::test_support::{keypair, mint, mint_with_aud};
    use crate::catalog_metadata::test_support::{
        CAMPAIGN, KAS, manifest, metadata_policy, recording_policy,
    };
    use crate::creator_catalog::test_support::{METADATA_SIZE, catalog, catalog2, entry, entry2};
    use crate::moderation::{DEFAULT_PUBLISH_ENTITLEMENT, Moderation, PublishPolicy, now_secs};
    use crate::tags_api::CatalogRules;
    use crate::tags_api::TagPublishing;
    use crate::tags_api::test_support::MemStore;
    use axum::http::{Method, Request};
    use bytes::Bytes;
    use ciborium::value::Value;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const SUB: &str = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";
    /// The `payloadSize` of `creator_catalog::test_support::entry`.
    const PAYLOAD_SIZE: u64 = 7_342_067;
    const ISS: &str = "https://identity.test";

    struct Harness {
        app: Router,
        store: Arc<MemStore>,
        moderation: Arc<Moderation>,
    }

    /// The catalog routes plus the tag routes, as main.rs wires them.
    fn harness(gated: bool) -> Harness {
        harness_with(gated, CatalogRules::default())
    }

    fn harness_with(gated: bool, catalog: CatalogRules) -> Harness {
        let (_, vk) = keypair();
        let store = Arc::new(MemStore::new());
        let moderation = Arc::new(Moderation::default());
        let state = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            tag_prefix: "catalog/".to_string(),
            catalog_documents: Default::default(),
            catalog,
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
            app: router(Arc::clone(&state)).merge(crate::tags_api::router(state)),
            store,
            moderation,
        }
    }

    /// A passkey-style token for `sub` carrying `entitlements`.
    fn token(sub: &str, entitlements: &[&str]) -> String {
        let (sk, _) = keypair();
        mint_with_aud(
            &sk,
            b"kid-1",
            ISS,
            sub,
            "arkavo",
            now_secs(),
            now_secs() + 3600,
            &[(
                "arkavo_entitlements",
                Value::Array(
                    entitlements
                        .iter()
                        .map(|e| Value::Text((*e).into()))
                        .collect(),
                ),
            )],
        )
    }

    fn creator() -> String {
        token(SUB, &[DEFAULT_PUBLISH_ENTITLEMENT])
    }

    fn payload(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    /// A catalog of SUB listing payload(1).
    fn doc() -> Vec<u8> {
        catalog(SUB, vec![entry("rec-1", &payload(1))])
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).unwrap_or_default()
        }

        fn error(&self) -> String {
            self.json()["error"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
    }

    async fn send(app: &Router, req: Request<axum::body::Body>) -> Reply {
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body,
        }
    }

    async fn put_catalog(app: &Router, sub: &str, bearer: Option<&str>, body: Vec<u8>) -> Reply {
        let mut req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/catalogs/{sub}"))
            .header("content-type", "application/json");
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        send(app, req.body(Body::from(body)).unwrap()).await
    }

    async fn get(app: &Router, uri: &str) -> Reply {
        send(app, Request::get(uri).body(Body::empty()).unwrap()).await
    }

    #[tokio::test]
    async fn publish_stores_the_exact_bytes_and_moves_the_tag() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let bytes = doc();
        let want = blake3::hash(&bytes).to_hex().to_string();

        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            r.json(),
            serde_json::json!({
                "name": format!("catalog/{SUB}"),
                "hash": want,
                "size": bytes.len(),
            })
        );
        {
            let stored = &h.store.catalog_documents.lock().await[&want];
            assert_eq!(stored.body, Bytes::from(bytes.clone()));
            assert_eq!(stored.owner.as_deref(), Some(SUB), "owner recorded");
        }

        // Readers: tag, then the document, byte for byte.
        let r = get(&h.app, &format!("/tags/catalog/{SUB}")).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            r.json(),
            serde_json::json!({ "name": format!("catalog/{SUB}"), "hash": want })
        );
        let r = get(&h.app, &format!("/catalog-documents/{want}")).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, Bytes::from(bytes.clone()));
        assert_eq!(r.headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(r.headers[header::CACHE_CONTROL], "public, max-age=300");
        assert_eq!(r.headers[header::ETAG], format!("\"{want}\"").as_str());

        // Uploading the same catalog again is harmless.
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json()["hash"], want);
        assert_eq!(h.store.catalog_documents.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn an_empty_catalog_publishes() {
        let h = harness(true);
        let r = put_catalog(&h.app, SUB, Some(&creator()), catalog(SUB, vec![])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn token_checks_come_first() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let (sk, _) = keypair();
        let expired = mint(
            &sk,
            b"kid-1",
            ISS,
            SUB,
            now_secs() - 7200,
            now_secs() - 3600,
        );
        for (bearer, status, msg) in [
            (None, StatusCode::UNAUTHORIZED, "missing bearer token"),
            (Some("garbage"), StatusCode::UNAUTHORIZED, "invalid token"),
            (
                Some(expired.as_str()),
                StatusCode::UNAUTHORIZED,
                "invalid token",
            ),
        ] {
            // Even an oversize body is answered by the token check.
            let r = put_catalog(&h.app, SUB, bearer, vec![b' '; MAX_CATALOG_BYTES + 1]).await;
            assert_eq!((r.status, r.error().as_str()), (status, msg));
        }

        let unentitled = token(SUB, &["https://arkavo.ai/attr/action/value/read"]);
        let service = token("client:svc", &[DEFAULT_PUBLISH_ENTITLEMENT]);
        for (bearer, sub, msg) in [
            (unentitled.as_str(), SUB, "publishing entitlement required"),
            (
                service.as_str(),
                "client:svc",
                "service tokens cannot publish",
            ),
        ] {
            let r = put_catalog(&h.app, sub, Some(bearer), doc()).await;
            assert_eq!((r.status, r.error().as_str()), (StatusCode::FORBIDDEN, msg));
        }

        h.moderation.suspend_for_test(SUB, false);
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "publishing suspended")
        );
        assert!(h.store.tags.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());
    }

    #[tokio::test]
    async fn an_ungated_node_still_verifies_the_token() {
        let h = harness(false);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = put_catalog(&h.app, SUB, Some("garbage"), doc()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        let r = put_catalog(&h.app, SUB, None, doc()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        // No entitlement needed when ungated.
        let r = put_catalog(&h.app, SUB, Some(&token(SUB, &[])), doc()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn the_path_must_be_the_token_subject_byte_for_byte() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let tok = token(&format!("arkavo:{SUB}"), &[DEFAULT_PUBLISH_ENTITLEMENT]);
        // The bare UUID is a different subject from arkavo:<uuid>.
        let r = put_catalog(&h.app, SUB, Some(&tok), doc()).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::FORBIDDEN,
                "catalog does not match token subject"
            )
        );
        let r = put_catalog(&h.app, "someone-else", Some(&creator()), doc()).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        // The prefixed subject publishes its own, prefixed tag.
        let mine = catalog(&format!("arkavo:{SUB}"), vec![entry("rec-1", &payload(1))]);
        let r = put_catalog(&h.app, &format!("arkavo:{SUB}"), Some(&tok), mine).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(r.json()["name"], format!("catalog/arkavo:{SUB}"));
    }

    #[tokio::test]
    async fn the_body_must_be_json() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        for content_type in [None, Some("text/plain"), Some("application/jsonx")] {
            let mut req = Request::builder()
                .method(Method::PUT)
                .uri(format!("/catalogs/{SUB}"))
                .header("authorization", format!("Bearer {}", creator()));
            if let Some(ct) = content_type {
                req = req.header("content-type", ct);
            }
            let r = send(&h.app, req.body(Body::from(doc())).unwrap()).await;
            assert_eq!(
                r.status,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type:?}"
            );
            assert_eq!(r.error(), "content type must be application/json");
        }
        let r = send(
            &h.app,
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/catalogs/{SUB}"))
                .header("authorization", format!("Bearer {}", creator()))
                .header("content-type", "application/json; charset=utf-8")
                .body(Body::from(doc()))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn the_body_is_at_most_262144_bytes_or_524288_for_v2() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;

        let mut v2 = catalog2(SUB, vec![]);
        v2.resize(MAX_CATALOG_BYTES, b' ');
        let r = put_catalog(&h.app, SUB, Some(&creator()), v2.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        v2.push(b' ');
        let r = put_catalog(&h.app, SUB, Some(&creator()), v2).await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

        let mut bytes = doc();
        bytes.resize(creator_catalog::MAX_CATALOG_1_BYTES, b' ');
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(r.json()["size"], creator_catalog::MAX_CATALOG_1_BYTES);

        bytes.push(b' ');
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes.clone()).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::PAYLOAD_TOO_LARGE, "catalog too large")
        );

        // Streamed without a Content-Length: the limit still holds.
        let chunks: Vec<Result<Bytes, std::io::Error>> = bytes
            .chunks(4096)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let r = send(
            &h.app,
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/catalogs/{SUB}"))
                .header("authorization", format!("Bearer {}", creator()))
                .header("content-type", "application/json")
                .body(Body::from_stream(futures::stream::iter(chunks)))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

        // An oversize invalid document is too large, not invalid.
        let r = put_catalog(
            &h.app,
            SUB,
            Some(&creator()),
            vec![b'x'; MAX_CATALOG_BYTES + 1],
        )
        .await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

        // Beyond axum's 2 MB default body limit the handler still answers,
        // with the contract's JSON error, after the token checks.
        let huge = vec![b' '; 3 * 1024 * 1024];
        let r = put_catalog(&h.app, SUB, Some(&creator()), huge.clone()).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::PAYLOAD_TOO_LARGE, "catalog too large")
        );
        let r = put_catalog(&h.app, SUB, None, huge).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_invalid_document_is_422_with_its_reason() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = put_catalog(&h.app, SUB, Some(&creator()), b"{\"schema\":1}".to_vec()).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().starts_with("invalid catalog: "), "{}", r.error());

        let dup = format!(
            r#"{{"schema":"arkavo.creator-catalog/1","owner":"{SUB}","owner":"{SUB}","entries":[]}}"#
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), dup.into_bytes()).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("duplicate key"), "{}", r.error());

        // A valid document of another owner.
        let theirs = catalog("someone-else", vec![entry("rec-1", &payload(1))]);
        let r = put_catalog(&h.app, SUB, Some(&creator()), theirs).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid catalog: owner does not match the catalog subject"
            )
        );
        assert!(h.store.tags.lock().await.is_empty());
    }

    #[tokio::test]
    async fn blocked_content_is_refused_before_the_ingest_check() {
        let h = harness(true);
        // payload(1) blocked and never ingested: the block answers.
        h.moderation.block_for_test(&payload(1));
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "content is blocked")
        );

        // A blocked catalog document cannot be republished either.
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.moderation
            .block_for_test(blake3::hash(&doc()).to_hex().as_str());
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert!(h.store.tags.lock().await.is_empty());
    }

    #[tokio::test]
    async fn every_payload_must_be_ingested() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let bytes = catalog(
            SUB,
            vec![
                entry("rec-1", &payload(1)),
                entry("rec-2", &payload(2)),
                entry("rec-3", &payload(3)),
            ],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes).await;
        assert_eq!(
            (r.status, r.error()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} is not ingested", payload(2))
            )
        );
        assert!(h.store.tags.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());
    }

    #[tokio::test]
    async fn every_payload_size_must_match_the_stored_blob() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store.ingest(&payload(2), PAYLOAD_SIZE - 1).await;
        h.store.ingest(&payload(3), PAYLOAD_SIZE + 1).await;

        // The first mismatching entry, in entry order, is reported.
        let bytes = catalog(
            SUB,
            vec![
                entry("rec-1", &payload(1)),
                entry("rec-3", &payload(3)),
                entry("rec-2", &payload(2)),
            ],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes).await;
        assert_eq!(
            (r.status, r.error()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} size does not match", payload(3))
            )
        );
        assert!(h.store.tags.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());

        // Two entries naming one payload are each checked: the second is
        // wrong although the first is right.
        let mut wrong = entry("rec-1b", &payload(1));
        wrong["payloadSize"] = serde_json::json!(PAYLOAD_SIZE + 1);
        let bytes = catalog(SUB, vec![entry("rec-1", &payload(1)), wrong]);
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes).await;
        assert_eq!(
            (r.status, r.error()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} size does not match", payload(1))
            )
        );

        // An ingest failure is reported before any size mismatch.
        let bytes = catalog(
            SUB,
            vec![entry("rec-3", &payload(3)), entry("rec-4", &payload(4))],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), bytes).await;
        assert_eq!(r.error(), format!("payload {} is not ingested", payload(4)));

        // Sizes that match publish.
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(h.store.tags.lock().await.len(), 1);
    }

    /// An edit looks up every payload, including those the current catalog
    /// lists, each distinct hash once.
    #[tokio::test]
    async fn an_edit_looks_up_every_payload() {
        use std::sync::atomic::Ordering::Relaxed;
        let h = harness(true);
        for n in 1..=4 {
            h.store.ingest(&payload(n), PAYLOAD_SIZE).await;
        }
        let lookups = || h.store.blob_lookups.load(Relaxed);

        // First publish: both payloads, the duplicate once.
        let first = catalog(
            SUB,
            vec![
                entry("rec-1", &payload(1)),
                entry("rec-2", &payload(2)),
                entry("rec-2b", &payload(2)),
            ],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), first).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(lookups(), 2);

        // An edit looks up every distinct payload again, listed or new.
        let second = catalog(
            SUB,
            vec![
                entry("rec-1", &payload(1)),
                entry("rec-2", &payload(2)),
                entry("rec-3", &payload(3)),
            ],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), second).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(lookups(), 5);

        // A payload gone from storage since the current catalog listed it
        // is refused.
        h.store.blobs.lock().await.remove(&payload(1));
        let third = catalog(
            SUB,
            vec![entry("rec-1", &payload(1)), entry("rec-2", &payload(2))],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), third).await;
        assert_eq!(
            (r.status, r.error()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} is not ingested", payload(1))
            )
        );

        // Blocks still apply to listed payloads.
        h.moderation.block_for_test(&payload(2));
        let fourth = catalog(SUB, vec![entry("rec-2", &payload(2))]);
        let r = put_catalog(&h.app, SUB, Some(&creator()), fourth).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "content is blocked")
        );
    }

    #[tokio::test]
    async fn storage_failure_is_502() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
        let r = get(&h.app, &format!("/blobs/{}", payload(1))).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
        let r = get(&h.app, &format!("/catalog-documents/{}", payload(1))).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn catalog_documents_404_400_and_blocked() {
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

        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        let hash = r.json()["hash"].as_str().unwrap().to_string();
        h.moderation.block_for_test(&hash);
        let r = get(&h.app, &format!("/catalog-documents/{hash}")).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
        // ...and the tag pointing at it no longer resolves.
        let r = get(&h.app, &format!("/tags/catalog/{SUB}")).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }

    async fn get_with(app: &Router, path: &str, if_none_match: &str) -> Reply {
        send(
            app,
            Request::get(path)
                .header(header::IF_NONE_MATCH, if_none_match)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn a_held_version_revalidates_with_its_etag() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        let hash = r.json()["hash"].as_str().unwrap().to_string();
        let path = format!("/catalog-documents/{hash}");
        let etag = format!("\"{hash}\"");

        for held in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"{}\", {etag}", payload(7)),
            "*".to_string(),
        ] {
            let r = get_with(&h.app, &path, &held).await;
            assert_eq!(r.status, StatusCode::NOT_MODIFIED, "{held}");
            assert!(r.body.is_empty(), "{held}");
            assert_eq!(r.headers[header::ETAG], etag.as_str());
            assert_eq!(r.headers[header::CACHE_CONTROL], "public, max-age=300");
        }

        // Another version, or none held: the full document.
        let r = get_with(&h.app, &path, &format!("\"{}\"", payload(7))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, Bytes::from(doc()));

        // A document that is not stored is 404 even to a matching tag.
        let missing = format!("/catalog-documents/{}", payload(9));
        let r = get_with(&h.app, &missing, "*").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );

        // A block reaches a client that revalidates.
        h.moderation.block_for_test(&hash);
        let r = get_with(&h.app, &path, &etag).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
    }

    #[tokio::test]
    async fn a_catalog_block_hides_the_document() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        let hash = r.json()["hash"].as_str().unwrap().to_string();
        let path = format!("/catalog-documents/{hash}");
        assert_eq!(get(&h.app, &path).await.status, StatusCode::OK);
        h.moderation.block_catalog_for_test(SUB);
        let r = get(&h.app, &path).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
    }

    #[tokio::test]
    async fn a_hidden_owner_hides_the_document() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc()).await;
        let hash = r.json()["hash"].as_str().unwrap().to_string();
        let path = format!("/catalog-documents/{hash}");
        let etag = format!("\"{hash}\"");

        // Suspended without hideCatalog: still served.
        h.moderation.suspend_for_test(SUB, false);
        assert_eq!(get(&h.app, &path).await.status, StatusCode::OK);

        // With hideCatalog: 404 to a plain read and to a revalidation.
        h.moderation.suspend_for_test(SUB, true);
        let r = get(&h.app, &path).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
        let r = get_with(&h.app, &path, &etag).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);

        // A document stored without owner metadata: the owner its bytes name
        // is hidden the same way.
        let legacy = catalog(SUB, vec![]);
        let legacy_hash = blake3::hash(&legacy).to_hex().to_string();
        h.store.catalog_documents.lock().await.insert(
            legacy_hash.clone(),
            crate::tags_api::StoredDocument {
                body: Bytes::from(legacy),
                owner: None,
            },
        );
        let legacy_path = format!("/catalog-documents/{legacy_hash}");
        assert_eq!(
            get(&h.app, &legacy_path).await.status,
            StatusCode::NOT_FOUND
        );
        let r = get_with(&h.app, &legacy_path, &format!("\"{legacy_hash}\"")).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);

        // An ungated node hides nothing.
        let ungated = harness(false);
        ungated.store.catalog_documents.lock().await.insert(
            hash.clone(),
            h.store.catalog_documents.lock().await[&hash].clone(),
        );
        assert_eq!(get(&ungated.app, &path).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn blobs_confirm_ingest() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let r = get(&h.app, &format!("/blobs/{}", payload(1))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            r.json(),
            serde_json::json!({ "hash": payload(1), "size": 7_342_067 })
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
            .ingest_with_manifest(&meta(n), METADATA_SIZE, manifest(meta_policy, kas))
            .await;
    }

    fn doc2() -> Vec<u8> {
        catalog2(SUB, vec![entry2("rec-1", &payload(1), &meta(1))])
    }

    async fn refusal(h: &Harness, body: Vec<u8>) -> (StatusCode, String) {
        let r = put_catalog(&h.app, SUB, Some(&creator()), body).await;
        (r.status, r.error())
    }

    #[tokio::test]
    async fn a_v2_catalog_publishes_when_its_metadata_fits() {
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        let r = put_catalog(&h.app, SUB, Some(&creator()), doc2()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let hash = r.json()["hash"].as_str().unwrap().to_string();
        let r = get(&h.app, &format!("/catalog-documents/{hash}")).await;
        assert_eq!(r.body.as_ref(), doc2().as_slice());
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
            refusal(&h, doc2()).await,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("metadata {} is not ingested", meta(1))
            )
        );

        h.store
            .ingest_with_manifest(
                &meta(1),
                METADATA_SIZE + 1,
                manifest(metadata_policy(), &[KAS]),
            )
            .await;
        assert_eq!(
            refusal(&h, doc2()).await,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("metadata {} size does not match", meta(1))
            )
        );

        h.store.ingest(&meta(1), METADATA_SIZE).await;
        h.moderation.block_for_test(&meta(1));
        assert_eq!(
            refusal(&h, doc2()).await,
            (StatusCode::FORBIDDEN, "content is blocked".to_string())
        );
    }

    #[tokio::test]
    async fn a_missing_payload_is_reported_before_missing_metadata() {
        let h = harness(true);
        let r = refusal(&h, doc2()).await;
        assert_eq!(
            r,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} is not ingested", payload(1))
            )
        );
    }

    #[tokio::test]
    async fn both_manifests_must_be_stored_and_readable() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store
            .ingest_with_manifest(&meta(1), METADATA_SIZE, manifest(metadata_policy(), &[KAS]))
            .await;
        assert_eq!(
            refusal(&h, doc2()).await,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} manifest is not stored", payload(1))
            )
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
            refusal(&h, doc2()).await,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("metadata {} manifest is unreadable", meta(1))
            )
        );

        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(refusal(&h, doc2()).await.0, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn the_metadata_policy_is_minimal_and_matches_the_recording() {
        let mut classified = metadata_policy();
        classified["arkavo:classification"] = serde_json::json!("flagged");
        let h = harness(true);
        ingest_pair(&h, 1, classified, &[KAS]).await;
        assert_eq!(
            refusal(&h, doc2()).await,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("metadata {} policy may only hold uuid and body", meta(1))
            )
        );

        let other_campaign = serde_json::json!({ "uuid": "u", "body": {
            "dataAttributes": [{ "attribute": CAMPAIGN.replace("12345678", "1") }], "dissem": [] } });
        let open =
            serde_json::json!({ "uuid": "u", "body": { "dataAttributes": [], "dissem": [] } });
        for (policy, kas) in [
            (other_campaign, &[KAS][..]),
            (open, &[KAS][..]),
            (metadata_policy(), &["https://other.example/kas"][..]),
        ] {
            let h = harness(true);
            ingest_pair(&h, 1, policy.clone(), kas).await;
            assert_eq!(
                refusal(&h, doc2()).await,
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "metadata {} policy does not match payload {}",
                        meta(1),
                        payload(1)
                    )
                ),
                "{policy} {kas:?}"
            );
        }
    }

    #[tokio::test]
    async fn each_manifest_is_read_once_per_publish() {
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        h.store
            .ingest_with_manifest(&meta(2), METADATA_SIZE, manifest(metadata_policy(), &[KAS]))
            .await;
        // Two entries share one recording.
        let body = catalog2(
            SUB,
            vec![
                entry2("rec-1", &payload(1), &meta(1)),
                entry2("rec-2", &payload(1), &meta(2)),
            ],
        );
        let r = put_catalog(&h.app, SUB, Some(&creator()), body).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            h.store
                .manifest_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    async fn put_tag(h: &Harness, hash: &str) -> Reply {
        send(
            &h.app,
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/tags/catalog/{SUB}"))
                .header("authorization", format!("Bearer {}", creator()))
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"hash\":\"{hash}\"}}")))
                .unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn after_the_cutover_v1_is_refused_on_upload_and_rollback() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let v1 = put_catalog(&h.app, SUB, Some(&creator()), doc())
            .await
            .json()["hash"]
            .as_str()
            .unwrap()
            .to_string();

        // The same store, past the cutover.
        let after = harness_with(
            true,
            CatalogRules {
                accept_schema_1: false,
                ..Default::default()
            },
        );
        after.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        let want = (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid catalog: schema must be \"arkavo.creator-catalog/2\"".to_string(),
        );
        assert_eq!(refusal(&after, doc()).await, want);
        let stored = h.store.catalog_documents.lock().await.clone();
        *after.store.catalog_documents.lock().await = stored;
        let r = put_tag(&after, &v1).await;
        assert_eq!((r.status, r.error()), want);

        // `/2` still publishes.
        ingest_pair(&after, 1, metadata_policy(), &[KAS]).await;
        let r = put_catalog(&after.app, SUB, Some(&creator()), doc2()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn a_v2_rollback_passes_the_metadata_checks_again() {
        let h = harness(true);
        ingest_pair(&h, 1, metadata_policy(), &[KAS]).await;
        let first = put_catalog(&h.app, SUB, Some(&creator()), doc2())
            .await
            .json()["hash"]
            .as_str()
            .unwrap()
            .to_string();
        h.moderation.block_for_test(&meta(1));
        let r = put_tag(&h, &first).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "content is blocked")
        );
    }

    #[tokio::test]
    async fn the_tag_route_rolls_back_to_a_published_catalog() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store.ingest(&payload(2), PAYLOAD_SIZE).await;
        let first = put_catalog(&h.app, SUB, Some(&creator()), doc())
            .await
            .json()["hash"]
            .as_str()
            .unwrap()
            .to_string();
        let second = catalog(SUB, vec![entry("rec-1", &payload(2))]);
        let r = put_catalog(&h.app, SUB, Some(&creator()), second).await;
        assert_ne!(r.json()["hash"], first);

        let r = send(
            &h.app,
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/tags/catalog/{SUB}"))
                .header("authorization", format!("Bearer {}", creator()))
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"hash\":\"{first}\"}}")))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        assert_eq!(
            get(&h.app, &format!("/tags/catalog/{SUB}")).await.json()["hash"],
            first
        );

        // A payload blob is not a catalog document.
        let r = send(
            &h.app,
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/tags/catalog/{SUB}"))
                .header("authorization", format!("Bearer {}", creator()))
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"hash\":\"{}\"}}", payload(1))))
                .unwrap(),
        )
        .await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "hash does not reference a catalog document of this subject"
            )
        );
    }
}
