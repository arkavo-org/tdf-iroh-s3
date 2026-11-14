//! Creator catalog routes shared by every catalog (`docs/creator-catalogs.md`).
//!
//! - `GET /catalog-documents/{hash}` — public, immutable read of a stored
//!   catalog document: the envelope ZTDF, ciphertext to anyone without the
//!   catalog's attribute.
//! - `GET /blobs/{hash}` — public ingest confirmation: the size of an
//!   ingested, unblocked TDF.
//! - `GET /publish/recordings/{hash}` — a publisher's pre-check: whether a
//!   recording is theirs, another account's, or nobody's.
//!
//! [`check_payloads`] holds the per-entry publish checks `PUT
//! /v2/catalogs/{sub}` runs on a catalog's index: the recordings it lists. On an ungated node
//! (`[publishing] required = false`) nothing is blocked (moderation records
//! are only loaded when gated) and recordings' owners are not checked (no
//! owner records are written there).

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

use crate::catalog_metadata;
use crate::creator_catalog::{CreatorCatalogEntry, is_lower_hex_hash};
use crate::moderation::canonical_subject;
use crate::ownership::{OwnerView, parse_owner};
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

/// Why [`check_payloads`] refuses an index: the status, the `error` string
/// and, for the two owner refusals only, every offending entry's
/// `contentID`, sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadRefusal {
    pub status: StatusCode,
    pub error: String,
    pub content_ids: Option<Vec<String>>,
}

impl From<(StatusCode, String)> for PayloadRefusal {
    fn from((status, error): (StatusCode, String)) -> Self {
        Self {
            status,
            error,
            content_ids: None,
        }
    }
}

impl PayloadRefusal {
    /// The reply: `{"error": …}`, with `"contentIDs": […]` when the refusal
    /// names entries.
    pub(crate) fn into_response_parts(self) -> ApiError {
        let mut body = serde_json::json!({ "error": self.error });
        if let Some(ids) = self.content_ids {
            body["contentIDs"] = serde_json::json!(ids);
        }
        (self.status, Json(body))
    }
}

pub fn router<S: TagStore>(state: Arc<ApiState<S>>) -> Router {
    Router::new()
        .route("/catalog-documents/{hash}", get(get_catalog_document::<S>))
        .route("/blobs/{hash}", get(get_blob::<S>))
        .route("/publish/recordings/{hash}", get(recording_owner::<S>))
        .with_state(state)
}

/// The checks for a catalog's index entries, in the contract's order:
/// - no recording blocked (403 `content is blocked`);
/// - every one ingested (422 `payload <hash> is not ingested`, the first
///   missing one in entry order);
/// - every entry's size equal to that blob's (422 `payload <hash> size does
///   not match`);
/// - on a gated node, every recording owned by `publisher` (403 `recording
///   belongs to another account`, else 422 `recording has no owner: push it
///   again`, each with `contentIDs`; see [`check_owners`]);
/// - every recording's manifest stored at ingest (422 `payload <hash>
///   manifest is not stored`) and readable (`… manifest is unreadable`);
/// - every recording's policy names `attribute`, the envelope's (422 `entry
///   <contentID> policy does not include the catalog attribute`): a viewer
///   who can open an entry can open the catalog.
///
/// Each entry's metadata TDF is inside the envelope; Creator checks it.
/// Each distinct hash is looked up once, at most
/// [`INGEST_CHECK_CONCURRENCY`] at a time.
pub(crate) async fn check_payloads<S: TagStore>(
    state: &ApiState<S>,
    entries: &[CreatorCatalogEntry],
    attribute: &str,
    publisher: &str,
) -> Result<(), PayloadRefusal> {
    if entries.iter().any(|e| is_blocked(state, &e.payload_hash)) {
        return Err((StatusCode::FORBIDDEN, "content is blocked".to_string()).into());
    }

    let sizes = look_up(state, hashes(entries), |store, hash| async move {
        match store.blob_size(&hash).await {
            Ok(Some(size)) => Ok(size),
            Ok(None) => Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {hash} is not ingested"),
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
        )
            .into());
    }

    if state.publishing.is_some() {
        check_owners(state, entries, publisher).await?;
    }

    let manifests = look_up(state, hashes(entries), |store, hash| async move {
        match store.get_manifest(&hash).await {
            Ok(Some(bytes)) => catalog_metadata::read_manifest(&bytes).ok_or_else(|| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("payload {hash} manifest is unreadable"),
                )
            }),
            Ok(None) => Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {hash} manifest is not stored"),
            )),
            Err(e) => {
                warn!(error = %e, "Manifest read failed");
                Err((StatusCode::BAD_GATEWAY, "storage unavailable".to_string()))
            }
        }
    })
    .await?;
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
        )
            .into());
    }
    Ok(())
}

/// Every entry's recording is `publisher`'s, by its owner record
/// (`moderation/publishers/<hash>`), comparing canonical subjects. Any entry
/// of another account gives 403 `recording belongs to another account`;
/// only when there is none, any entry without an owner gives 422 `recording
/// has no owner: push it again` (a push claims it). Both name every such
/// entry's `contentID`, sorted. A record that can't be read or parsed is 502
/// `storage unavailable`.
async fn check_owners<S: TagStore>(
    state: &ApiState<S>,
    entries: &[CreatorCatalogEntry],
    publisher: &str,
) -> Result<(), PayloadRefusal> {
    let owners = look_up(state, hashes(entries), |store, hash| async move {
        let unavailable = || (StatusCode::BAD_GATEWAY, "storage unavailable".to_string());
        match store.get_blob_owner(&hash).await {
            Ok(Some(bytes)) => match parse_owner(&hash, &bytes) {
                Ok(owner) => Ok(Some(owner.subject)),
                Err(e) => {
                    warn!(%hash, error = format!("{e:#}"), "Owner record unreadable");
                    Err(unavailable())
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                warn!(%hash, error = %e, "Owner record read failed");
                Err(unavailable())
            }
        }
    })
    .await?;

    let publisher = canonical_subject(publisher);
    let mut another = Vec::new();
    let mut unowned = Vec::new();
    for e in entries {
        match owners.get(&e.payload_hash).and_then(Option::as_deref) {
            Some(owner) if canonical_subject(owner) == publisher => {}
            Some(_) => another.push(e.content_id.clone()),
            None => unowned.push(e.content_id.clone()),
        }
    }
    let (status, error, mut content_ids) = if !another.is_empty() {
        (
            StatusCode::FORBIDDEN,
            "recording belongs to another account",
            another,
        )
    } else if !unowned.is_empty() {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "recording has no owner: push it again",
            unowned,
        )
    } else {
        return Ok(());
    };
    content_ids.sort();
    content_ids.dedup();
    Err(PayloadRefusal {
        status,
        error: error.to_string(),
        content_ids: Some(content_ids),
    })
}

/// The distinct recording hashes `entries` name, in entry order.
fn hashes(entries: &[CreatorCatalogEntry]) -> Vec<String> {
    let mut seen = HashSet::new();
    entries
        .iter()
        .map(|e| e.payload_hash.as_str())
        .filter(|h| seen.insert(*h))
        .map(str::to_string)
        .collect()
}

/// Run `f` for each hash, at most [`INGEST_CHECK_CONCURRENCY`] at a time,
/// and stop at the first refusal in `hashes` order.
pub(crate) async fn look_up<S, T, F, Fut>(
    state: &ApiState<S>,
    hashes: Vec<String>,
    f: F,
) -> Result<HashMap<String, T>, (StatusCode, String)>
where
    S: TagStore,
    F: Fn(Arc<S>, String) -> Fut,
    Fut: Future<Output = Result<T, (StatusCode, String)>>,
{
    let mut found = HashMap::with_capacity(hashes.len());
    let mut checks = futures::stream::iter(hashes)
        .map(|hash| {
            let lookup = f(Arc::clone(&state.store), hash.clone());
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

/// `GET /publish/recordings/{hash}`: whose a recording is, by its owner
/// record, for a publisher to ask before signing a catalog that lists it
/// and after a refused push (an iroh refusal carries no reason). Authorized
/// as `PUT /v2/catalogs/{sub}` is ([`authorize_publisher`]), before the
/// hash is looked at. The answer never names another account. An ungated
/// node writes no owner records, so it always answers `none`.
async fn recording_owner<S: TagStore>(
    State(state): State<Arc<ApiState<S>>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let claims = authorize_publisher(&state, &headers)
        .await
        .map_err(|(status, msg)| fail(status, msg))?;
    if !is_lower_hex_hash(&hash) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid hash"));
    }
    let owner = if state.publishing.is_none() {
        OwnerView::None
    } else {
        match state.store.get_blob_owner(&hash).await {
            Ok(None) => OwnerView::None,
            Ok(Some(bytes)) => match parse_owner(&hash, &bytes) {
                Ok(owner)
                    if canonical_subject(&owner.subject) == canonical_subject(&claims.sub) =>
                {
                    OwnerView::You
                }
                Ok(_) => OwnerView::Another,
                Err(e) => return Err(storage_unavailable("Owner record parse", e)),
            },
            Err(e) => return Err(storage_unavailable("Owner record read", e)),
        }
    };
    Ok(Json(serde_json::json!({ "hash": hash, "owner": owner })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CwtVerifier;
    use crate::auth::test_support::{keypair, mint_with_aud};
    use crate::catalog_metadata::test_support::{CAMPAIGN, KAS, manifest, recording_policy};
    use crate::creator_catalog::test_support::{PAYLOAD_SIZE, entry};
    use crate::creator_catalog::{self, CreatorCatalogEntry};
    use crate::moderation::{DEFAULT_PUBLISH_ENTITLEMENT, Moderation, PublishPolicy, now_secs};
    use crate::tags_api::test_support::MemStore;
    use crate::tags_api::{StoredDocument, TagPublishing};
    use axum::body::Body;
    use axum::http::Request;
    use bytes::Bytes;
    use ciborium::value::Value;
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

    /// Ingest payload(n), a campaign recording, with its stored manifest,
    /// owned by the publisher (`SUB`).
    async fn ingest(h: &Harness, n: u8) {
        ingest_unowned(h, n).await;
        h.store.own(&payload(n), SUB).await;
    }

    /// As [`ingest`], with no owner record.
    async fn ingest_unowned(h: &Harness, n: u8) {
        h.store
            .ingest_with_manifest(
                &payload(n),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
    }

    fn index(entries: Vec<serde_json::Value>) -> Vec<CreatorCatalogEntry> {
        creator_catalog::parse_index(json!(entries)).unwrap()
    }

    /// One entry: rec-1, payload(1).
    fn one() -> Vec<CreatorCatalogEntry> {
        index(vec![entry("rec-1", &payload(1))])
    }

    /// `entries` checked against the campaign, published by `SUB`.
    async fn check(h: &Harness, entries: &[CreatorCatalogEntry]) -> Result<(), PayloadRefusal> {
        check_as(h, entries, SUB).await
    }

    async fn check_as(
        h: &Harness,
        entries: &[CreatorCatalogEntry],
        publisher: &str,
    ) -> Result<(), PayloadRefusal> {
        check_payloads(&h.state, entries, CAMPAIGN, publisher).await
    }

    fn refused(status: StatusCode, msg: impl Into<String>) -> Result<(), PayloadRefusal> {
        Err((status, msg.into()).into())
    }

    fn unprocessable(msg: String) -> Result<(), PayloadRefusal> {
        refused(StatusCode::UNPROCESSABLE_ENTITY, msg)
    }

    /// An owner refusal naming `content_ids`.
    fn refused_naming(
        status: StatusCode,
        msg: &str,
        content_ids: &[&str],
    ) -> Result<(), PayloadRefusal> {
        Err(PayloadRefusal {
            status,
            error: msg.to_string(),
            content_ids: Some(content_ids.iter().map(|id| id.to_string()).collect()),
        })
    }

    const ANOTHER: &str = "recording belongs to another account";
    const NO_OWNER: &str = "recording has no owner: push it again";

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

    async fn send(app: &Router, req: axum::http::request::Builder) -> Reply {
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

    async fn get_with(app: &Router, uri: &str, if_none_match: Option<&str>) -> Reply {
        let mut req = Request::get(uri);
        if let Some(tag) = if_none_match {
            req = req.header(header::IF_NONE_MATCH, tag);
        }
        send(app, req).await
    }

    async fn get(app: &Router, uri: &str) -> Reply {
        get_with(app, uri, None).await
    }

    /// A person token for `sub` (audience `arkavo`), carrying the publishing
    /// entitlement when `entitled`.
    fn token(sub: &str, entitled: bool) -> String {
        let (sk, _) = keypair();
        let entitlements = (
            "arkavo_entitlements",
            Value::Array(vec![Value::Text(DEFAULT_PUBLISH_ENTITLEMENT.into())]),
        );
        let extras = if entitled { vec![entitlements] } else { vec![] };
        mint_with_aud(
            &sk,
            b"kid-1",
            "https://identity.test",
            sub,
            "arkavo",
            now_secs(),
            now_secs() + 3600,
            &extras,
        )
    }

    /// `GET /publish/recordings/{hash}`, with `token` as the bearer if given.
    async fn owner_of(app: &Router, hash: &str, token: Option<&str>) -> Reply {
        let mut req = Request::get(format!("/publish/recordings/{hash}"));
        if let Some(token) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        send(app, req).await
    }

    fn json_body(r: &Reply) -> serde_json::Value {
        serde_json::from_slice(&r.body).unwrap_or_default()
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
    async fn an_index_of_ingested_campaign_recordings_passes() {
        let h = harness(true);
        ingest(&h, 1).await;
        assert_eq!(check(&h, &one()).await, Ok(()));
        assert_eq!(check(&h, &[]).await, Ok(()));
    }

    #[tokio::test]
    async fn blocked_content_is_refused_before_the_ingest_check() {
        // payload(1) blocked and never ingested: the block answers.
        let h = harness(true);
        h.moderation.block_for_test(&payload(1));
        assert_eq!(
            check(&h, &one()).await,
            refused(StatusCode::FORBIDDEN, "content is blocked")
        );
        // An ungated node blocks nothing.
        let h = harness(false);
        ingest(&h, 1).await;
        h.moderation.block_for_test(&payload(1));
        assert_eq!(check(&h, &one()).await, Ok(()));
    }

    #[tokio::test]
    async fn every_payload_must_be_ingested() {
        let h = harness(true);
        for n in [1, 3] {
            ingest(&h, n).await;
        }
        let entries = index(vec![
            entry("rec-1", &payload(1)),
            entry("rec-2", &payload(2)),
            entry("rec-3", &payload(3)),
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
            ingest(&h, n).await;
        }
        h.store.ingest(&payload(2), PAYLOAD_SIZE - 1).await;
        h.store.ingest(&payload(3), PAYLOAD_SIZE + 1).await;
        // The first mismatching entry, in entry order, is reported.
        let entries = index(vec![
            entry("rec-1", &payload(1)),
            entry("rec-3", &payload(3)),
            entry("rec-2", &payload(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!("payload {} size does not match", payload(3)))
        );
        // Two entries naming one payload are each checked.
        let mut wrong = entry("rec-1b", &payload(1));
        wrong["payloadSize"] = json!(PAYLOAD_SIZE + 1);
        let entries = index(vec![entry("rec-1", &payload(1)), wrong]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable(format!("payload {} size does not match", payload(1)))
        );
        // An ingest failure is reported before any size mismatch.
        let entries = index(vec![
            entry("rec-3", &payload(3)),
            entry("rec-4", &payload(4)),
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
        ingest(&h, 1).await;
        ingest(&h, 2).await;
        let entries = index(vec![
            entry("rec-1", &payload(1)),
            entry("rec-1b", &payload(1)),
            entry("rec-2", &payload(2)),
        ]);
        assert_eq!(check(&h, &entries).await, Ok(()));
        assert_eq!(h.store.blob_lookups.load(Relaxed), 2);
        assert_eq!(h.store.owner_reads.load(Relaxed), 2);
        assert_eq!(h.store.manifest_reads.load(Relaxed), 2);
    }

    #[tokio::test]
    async fn every_manifest_must_be_stored_and_readable() {
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store.own(&payload(1), SUB).await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("payload {} manifest is not stored", payload(1)))
        );
        h.store
            .ingest_with_manifest(&payload(1), PAYLOAD_SIZE, b"not a manifest".to_vec())
            .await;
        assert_eq!(
            check(&h, &one()).await,
            unprocessable(format!("payload {} manifest is unreadable", payload(1)))
        );
        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            check(&h, &one()).await,
            refused(StatusCode::BAD_GATEWAY, "storage unavailable")
        );
    }

    #[tokio::test]
    async fn every_recording_carries_the_catalog_attribute() {
        let h = harness(true);
        ingest(&h, 1).await;
        let other = "https://patreon.arkavo.com/attr/campaign/value/99";
        assert_eq!(
            check_payloads(&h.state, &one(), other, SUB).await,
            unprocessable("entry rec-1 policy does not include the catalog attribute".into())
        );

        // The first entry whose recording lacks it is named.
        let other_policy = json!({ "uuid": "r2", "body": {
            "dataAttributes": [{ "attribute": other }], "dissem": [] } });
        h.store
            .ingest_with_manifest(&payload(2), PAYLOAD_SIZE, manifest(other_policy, &[KAS]))
            .await;
        h.store.own(&payload(2), SUB).await;
        let entries = index(vec![
            entry("rec-1", &payload(1)),
            entry("rec-2", &payload(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            unprocessable("entry rec-2 policy does not include the catalog attribute".into())
        );
    }

    #[tokio::test]
    async fn a_recording_of_another_account_is_refused() {
        let h = harness(true);
        ingest_unowned(&h, 1).await;
        h.store.own(&payload(1), "u2").await;
        ingest(&h, 2).await;
        // Every entry naming it, sorted: one hash under two contentIDs.
        let entries = index(vec![
            entry("rec-b", &payload(1)),
            entry("rec-a", &payload(1)),
            entry("rec-c", &payload(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            refused_naming(StatusCode::FORBIDDEN, ANOTHER, &["rec-a", "rec-b"])
        );
    }

    #[tokio::test]
    async fn an_unowned_recording_must_be_pushed_again() {
        let h = harness(true);
        ingest_unowned(&h, 1).await;
        assert_eq!(
            check(&h, &one()).await,
            refused_naming(StatusCode::UNPROCESSABLE_ENTITY, NO_OWNER, &["rec-1"])
        );
        // Every entry naming it, sorted.
        let entries = index(vec![
            entry("rec-z", &payload(1)),
            entry("rec-1", &payload(1)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            refused_naming(
                StatusCode::UNPROCESSABLE_ENTITY,
                NO_OWNER,
                &["rec-1", "rec-z"]
            )
        );
    }

    #[tokio::test]
    async fn another_owner_outranks_no_owner() {
        let h = harness(true);
        ingest_unowned(&h, 1).await;
        ingest_unowned(&h, 2).await;
        h.store.own(&payload(2), "u2").await;
        // The unowned entry comes first; the other account's still answers.
        let entries = index(vec![
            entry("rec-1", &payload(1)),
            entry("rec-2", &payload(2)),
        ]);
        assert_eq!(
            check(&h, &entries).await,
            refused_naming(StatusCode::FORBIDDEN, ANOTHER, &["rec-2"])
        );
    }

    #[tokio::test]
    async fn the_owner_check_is_canonical() {
        // `arkavo:<uuid>` and `<uuid>` are one account, either way round.
        let h = harness(true);
        ingest(&h, 1).await;
        assert_eq!(check_as(&h, &one(), &format!("arkavo:{SUB}")).await, Ok(()));

        let h = harness(true);
        ingest_unowned(&h, 1).await;
        h.store.own(&payload(1), &format!("arkavo:{SUB}")).await;
        assert_eq!(check(&h, &one()).await, Ok(()));
    }

    #[tokio::test]
    async fn an_unreadable_owner_is_502() {
        let h = harness(true);
        ingest_unowned(&h, 1).await;
        h.store
            .owners
            .lock()
            .await
            .insert(payload(1), Bytes::from_static(b"x"));
        assert_eq!(
            check(&h, &one()).await,
            refused(StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        // A record naming another hash is not this recording's.
        let h = harness(true);
        ingest_unowned(&h, 1).await;
        h.store.own(&payload(9), SUB).await;
        let misfiled = h.store.owners.lock().await[&payload(9)].clone();
        h.store.owners.lock().await.insert(payload(1), misfiled);
        assert_eq!(
            check(&h, &one()).await,
            refused(StatusCode::BAD_GATEWAY, "storage unavailable")
        );
    }

    #[tokio::test]
    async fn an_ungated_node_skips_the_owner_check() {
        let h = harness(false);
        ingest_unowned(&h, 1).await;
        assert_eq!(check(&h, &one()).await, Ok(()));
        h.store.own(&payload(1), "u2").await;
        assert_eq!(check(&h, &one()).await, Ok(()));
        assert_eq!(
            h.store
                .owner_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn the_owner_check_follows_the_size_check() {
        let h = harness(true);
        ingest_unowned(&h, 1).await;
        let mut wrong = entry("rec-1", &payload(1));
        wrong["payloadSize"] = json!(PAYLOAD_SIZE + 1);
        assert_eq!(
            check(&h, &index(vec![wrong])).await,
            unprocessable(format!("payload {} size does not match", payload(1)))
        );
    }

    #[tokio::test]
    async fn the_owner_check_precedes_the_manifest_check() {
        // Another account's recording with no stored manifest: the owner
        // refusal answers.
        let h = harness(true);
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h.store.own(&payload(1), "u2").await;
        assert_eq!(
            check(&h, &one()).await,
            refused_naming(StatusCode::FORBIDDEN, ANOTHER, &["rec-1"])
        );
    }

    #[test]
    fn only_an_owner_refusal_carries_content_ids() {
        let refusal = PayloadRefusal {
            status: StatusCode::FORBIDDEN,
            error: ANOTHER.to_string(),
            content_ids: Some(vec!["rec-a".into(), "rec-b".into()]),
        };
        let (status, Json(body)) = refusal.into_response_parts();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            json!({ "error": ANOTHER, "contentIDs": ["rec-a", "rec-b"] })
        );

        let refusal = PayloadRefusal::from((StatusCode::FORBIDDEN, "content is blocked".into()));
        let (status, Json(body)) = refusal.into_response_parts();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({ "error": "content is blocked" }));
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

    #[tokio::test]
    async fn recording_owner_answers_you_another_or_none() {
        let h = harness(true);
        h.store.own(&payload(1), SUB).await;
        h.store.own(&payload(2), "u2").await;
        let tok = token(SUB, true);
        for (n, owner) in [(1, "you"), (2, "another account"), (3, "none")] {
            let r = owner_of(&h.app, &payload(n), Some(&tok)).await;
            assert_eq!(r.status, StatusCode::OK, "{owner}");
            assert_eq!(
                json_body(&r),
                json!({ "hash": payload(n), "owner": owner }),
                "{owner}"
            );
            // The other account is never named.
            assert!(!String::from_utf8_lossy(&r.body).contains("u2"), "{owner}");
        }

        // `arkavo:<uuid>` and `<uuid>` are one account, either way round.
        h.store.own(&payload(4), &format!("arkavo:{SUB}")).await;
        let r = owner_of(&h.app, &payload(4), Some(&tok)).await;
        assert_eq!(json_body(&r), json!({ "hash": payload(4), "owner": "you" }));
        let prefixed = token(&format!("arkavo:{SUB}"), true);
        let r = owner_of(&h.app, &payload(1), Some(&prefixed)).await;
        assert_eq!(json_body(&r), json!({ "hash": payload(1), "owner": "you" }));
    }

    #[tokio::test]
    async fn recording_owner_needs_a_publisher_token() {
        let h = harness(true);
        h.store.own(&payload(1), SUB).await;
        let r = owner_of(&h.app, &payload(1), None).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::UNAUTHORIZED, "missing bearer token")
        );
        let r = owner_of(&h.app, &payload(1), Some(&token(SUB, false))).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "publishing entitlement required")
        );
        h.moderation.suspend_for_test(SUB, false);
        let r = owner_of(&h.app, &payload(1), Some(&token(SUB, true))).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "publishing suspended")
        );
        // The token is checked before the hash.
        let r = owner_of(&h.app, "xyz", None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            h.store
                .owner_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn recording_owner_refuses_an_invalid_hash() {
        let h = harness(true);
        let tok = token(SUB, true);
        for bad in ["AB".repeat(32), "xyz".to_string()] {
            let r = owner_of(&h.app, &bad, Some(&tok)).await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::BAD_REQUEST, "invalid hash"),
                "{bad}"
            );
        }
        assert_eq!(
            h.store
                .owner_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn recording_owner_storage_failure_is_502() {
        let h = harness(true);
        let tok = token(SUB, true);
        h.store
            .down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let r = owner_of(&h.app, &payload(1), Some(&tok)).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        // A record that can't be parsed is a storage fault too.
        let h = harness(true);
        h.store
            .owners
            .lock()
            .await
            .insert(payload(1), Bytes::from_static(b"x"));
        let r = owner_of(&h.app, &payload(1), Some(&tok)).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
    }

    #[tokio::test]
    async fn recording_owner_on_an_ungated_node_is_none() {
        // No owner records are written on an ungated node; one that is
        // there anyway is not read. The token must still verify.
        let h = harness(false);
        h.store.own(&payload(1), SUB).await;
        let r = owner_of(&h.app, &payload(1), Some(&token(SUB, false))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            json_body(&r),
            json!({ "hash": payload(1), "owner": "none" })
        );
        assert_eq!(
            h.store
                .owner_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let r = owner_of(&h.app, &payload(1), None).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::UNAUTHORIZED, "missing bearer token")
        );
    }
}
