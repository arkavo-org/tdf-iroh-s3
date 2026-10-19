//! Catalog v2 routes (tdf-iroh-s3#27, `docs/creator-catalogs.md`).
//!
//! - `PUT /v2/catalogs/{sub}` — publish: the catalog document and the
//!   creator's passkey-signed pointer bundle. The document is stored under
//!   `catalog-documents/<blake3>` with its BAO outboard, so it is served
//!   over iroh; the bundle replaces `catalog-pointers/<sub>` only when its
//!   `seq` is greater than the stored one's, and only when the stored
//!   pointer is still the base named by `If-Match` / `If-None-Match`, if
//!   given (tdf-iroh-s3#29; 412 otherwise).
//! - `GET /v2/catalogs/{sub}` — public: the stored bundle, with
//!   `ETag: "<seq>"`, which readers verify themselves before fetching the
//!   document over iroh by hash.
//!
//! Publishing takes the same token checks as v1 (`authorize_publisher`).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use iroh_blobs::Hash;
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::catalog_v2::{self, Bundle, BundleError, Passkeys};
use crate::catalogs_api::{
    CATALOG_DOCUMENT_CACHE_CONTROL, check_payloads, if_none_match, is_json, owner_hidden,
};
use crate::creator_catalog::{self, MAX_CATALOG_BYTES, MAX_OWNER_BYTES, valid_identifier};
use crate::moderation::now_secs;
use crate::tags_api::{ApiState, TagStore, authorize_publisher, is_blocked};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn fail(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

fn storage_unavailable(what: &str, e: anyhow::Error) -> ApiError {
    warn!(error = %e, "{what} failed");
    fail(StatusCode::BAD_GATEWAY, "storage unavailable")
}

/// Largest publish body: a 256 KiB document in base64url (about 350 KiB)
/// plus a bundle of a few KiB.
pub const MAX_PUT_BYTES: usize = 512 * 1024;

/// Why the IdP's credential status refuses a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusRefusal {
    /// Revoked, unknown, or registered to another subject: 403.
    Refused(&'static str),
    /// The IdP did not answer: 502.
    Unavailable,
}

/// Asks the IdP whether a passkey credential is still the subject's.
pub trait CredentialStatus: Send + Sync + 'static {
    fn check<'a>(
        &'a self,
        credential_id: &'a [u8],
        sub: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StatusRefusal>> + Send + 'a>>;
}

/// `GET <passkey_status_url>` with `{credentialId}` filled in. 200
/// `{"sub","revoked"}` for the subject and not revoked passes; a 404 is an
/// unknown credential (refused, never taken as "not revoked"); anything
/// else, or no answer within 10 s, is unavailable.
pub struct IdpCredentialStatus {
    url_template: String,
    http: reqwest::Client,
}

impl IdpCredentialStatus {
    pub fn new(url_template: String) -> Self {
        Self {
            url_template,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl CredentialStatus for IdpCredentialStatus {
    fn check<'a>(
        &'a self,
        credential_id: &'a [u8],
        sub: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StatusRefusal>> + Send + 'a>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct Status {
                sub: String,
                revoked: bool,
            }
            let url = self
                .url_template
                .replace("{credentialId}", &URL_SAFE_NO_PAD.encode(credential_id));
            let resp = self.http.get(&url).send().await.map_err(|e| {
                warn!(error = %e, "Passkey credential status unreachable");
                StatusRefusal::Unavailable
            })?;
            match resp.status() {
                reqwest::StatusCode::OK => {}
                reqwest::StatusCode::NOT_FOUND => {
                    return Err(StatusRefusal::Refused("passkey credential unknown"));
                }
                other => {
                    warn!(status = %other, "Passkey credential status failed");
                    return Err(StatusRefusal::Unavailable);
                }
            }
            let status: Status = resp.json().await.map_err(|e| {
                warn!(error = %e, "Passkey credential status unreadable");
                StatusRefusal::Unavailable
            })?;
            if status.revoked {
                return Err(StatusRefusal::Refused("passkey credential revoked"));
            }
            if status.sub != sub {
                return Err(StatusRefusal::Refused(
                    "passkey credential belongs to another subject",
                ));
            }
            Ok(())
        })
    }
}

/// No status check (`passkey_status_url = ""`, development only).
pub struct NoCredentialStatus;

impl CredentialStatus for NoCredentialStatus {
    fn check<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StatusRefusal>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

pub struct V2State<S: TagStore> {
    pub api: Arc<ApiState<S>>,
    pub passkeys: Passkeys,
    pub status: Arc<dyn CredentialStatus>,
}

pub fn router<S: TagStore>(state: Arc<V2State<S>>) -> Router {
    Router::new()
        .route(
            "/v2/catalogs/{sub}",
            get(get_pointer::<S>).put(put_catalog::<S>),
        )
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutRequest {
    document: String,
    bundle: Bundle,
}

/// The `seq` of a stored bundle. The node wrote it after verifying it, so
/// failing to read it back is a storage fault.
fn stored_seq(body: &[u8]) -> anyhow::Result<(u64, String)> {
    let bundle: Bundle = serde_json::from_slice(body)?;
    let bytes = URL_SAFE_NO_PAD.decode(&bundle.pointer)?;
    let pointer = catalog_v2::parse_pointer(&bytes).map_err(anyhow::Error::msg)?;
    Ok((pointer.seq, pointer.catalog_hash))
}

/// A stored pointer's entity tag: its `seq`, quoted. A stored seq only
/// increases, so it is a strong validator.
fn pointer_etag(seq: u64) -> String {
    format!("\"{seq}\"")
}

/// Whether the request's preconditions (RFC 9110 §13.1) hold for the stored
/// pointer's tag (`None`: no pointer stored). `If-Match` takes strong
/// comparison, so a weak or unquoted tag never matches; `*` needs a stored
/// pointer. `If-None-Match` is evaluated only without `If-Match`, and fails
/// on `*` or the tag while a pointer is stored. No header: no condition.
fn preconditions_hold(headers: &HeaderMap, stored: Option<&str>) -> bool {
    let mut if_match = headers
        .get_all(header::IF_MATCH)
        .iter()
        .map(|v| v.to_str().unwrap_or_default())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .peekable();
    if if_match.peek().is_some() {
        return stored.is_some_and(|etag| if_match.any(|t| t == "*" || t == etag));
    }
    match stored {
        Some(etag) => !if_none_match(headers, etag),
        None => true,
    }
}

async fn put_catalog<S: TagStore>(
    State(state): State<Arc<V2State<S>>>,
    Path(sub): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    let api = &state.api;
    let reject = |status: StatusCode, msg: String| {
        warn!(%sub, %status, reason = %msg, "Catalog v2 publish rejected");
        fail(status, msg)
    };

    // 1. The publishing token, for this subject only (byte for byte).
    let claims = authorize_publisher(api, &headers)
        .await
        .map_err(|(status, msg)| reject(status, msg.to_string()))?;
    if sub != claims.sub {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "catalog does not match token subject".into(),
        ));
    }
    if !is_json(&headers) {
        return Err(fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type must be application/json",
        ));
    }

    // 2. The body, bounded, read only after the token checks.
    let bytes = axum::body::to_bytes(body, MAX_PUT_BYTES)
        .await
        .map_err(|e| {
            let too_large = std::error::Error::source(&e)
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            if too_large {
                fail(StatusCode::PAYLOAD_TOO_LARGE, "request too large")
            } else {
                fail(StatusCode::BAD_REQUEST, "unreadable request body")
            }
        })?;
    let req: PutRequest = serde_json::from_slice(&bytes)
        .map_err(|e| fail(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    let document = URL_SAFE_NO_PAD
        .decode(&req.document)
        .ok()
        .filter(|d| !d.is_empty() && d.len() <= MAX_CATALOG_BYTES)
        .ok_or_else(|| {
            fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("invalid request: document must be 1-{MAX_CATALOG_BYTES} bytes of unpadded base64url"),
            )
        })?;

    // 3. The signed chain: IdP attestation → passkey → pointer for `sub`.
    let verified = catalog_v2::verify_bundle(
        &req.bundle,
        &sub,
        &api.verifier,
        &state.passkeys,
        now_secs(),
    )
    .await
    .map_err(|e| match e {
        BundleError::Invalid(why) => reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid bundle: {why}"),
        ),
        BundleError::KeySet(why) => {
            warn!(why, "IdP key set unavailable for a catalog v2 publish");
            fail(StatusCode::BAD_GATEWAY, "key set unavailable")
        }
    })?;
    let pointer = &verified.pointer;

    // 4. The pointer names exactly this document, a valid catalog of `sub`.
    let hash = blake3::hash(&document).to_hex().to_string();
    if hash != pointer.catalog_hash || document.len() as u64 != pointer.catalog_size {
        return Err(reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid bundle: catalogHash or catalogSize does not match the document".into(),
        ));
    }
    let doc = creator_catalog::parse(&document).map_err(|why| {
        reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid catalog: {why}"),
        )
    })?;
    if doc.owner != sub {
        return Err(reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid catalog: owner does not match the catalog subject".into(),
        ));
    }

    // 5. Nothing blocked, every payload ingested at its size (as v1).
    if is_blocked(api, &hash) {
        return Err(reject(StatusCode::FORBIDDEN, "content is blocked".into()));
    }
    check_payloads(api, &doc.entries)
        .await
        .map_err(|(status, msg)| reject(status, msg))?;

    // 6. The passkey is still this subject's.
    state
        .status
        .check(&verified.credential_id, &sub)
        .await
        .map_err(|r| match r {
            StatusRefusal::Refused(why) => reject(StatusCode::FORBIDDEN, why.into()),
            StatusRefusal::Unavailable => {
                fail(StatusCode::BAD_GATEWAY, "credential status unavailable")
            }
        })?;

    // 7. Merged from the stored pointer, if the request names its base,
    //    and newer than it.
    let current = api
        .store
        .get_catalog_pointer(&sub)
        .await
        .map_err(|e| storage_unavailable("Catalog pointer read", e))?;
    let current_seq = current
        .as_ref()
        .map(|stored| stored_seq(&stored.body).map(|(seq, _)| seq))
        .transpose()
        .map_err(|e| storage_unavailable("Catalog pointer parse", e))?;
    if !preconditions_hold(&headers, current_seq.map(pointer_etag).as_deref()) {
        return Err(reject(
            StatusCode::PRECONDITION_FAILED,
            "catalog changed since it was read".into(),
        ));
    }
    if let Some(current_seq) = current_seq
        && pointer.seq <= current_seq
    {
        return Err(reject(
            StatusCode::CONFLICT,
            format!("seq must be greater than {current_seq}"),
        ));
    }
    let expected = current.as_ref().map(|stored| stored.etag.as_str());

    // 8. The document and its outboard first, so a stored pointer never
    //    names a document that cannot be served; then the pointer, only if
    //    nobody else moved it meanwhile.
    let outboard = crate::ingest::compute_outboard(
        &document[..],
        document.len() as u64,
        Hash::from_bytes(*blake3::hash(&document).as_bytes()),
    )
    .map_err(|e| storage_unavailable("Catalog outboard", e))?;
    let size = document.len();
    let entries = doc.entries.len();
    api.store
        .put_catalog_document(&hash, Bytes::from(document), &sub)
        .await
        .map_err(|e| storage_unavailable("Catalog document write", e))?;
    api.store
        .put_catalog_outboard(&hash, Bytes::from(outboard))
        .await
        .map_err(|e| storage_unavailable("Catalog outboard write", e))?;
    let bundle = serde_json::to_vec(&req.bundle).expect("bundle serializes");
    let written = api
        .store
        .put_catalog_pointer(&sub, Bytes::from(bundle), expected)
        .await
        .map_err(|e| storage_unavailable("Catalog pointer write", e))?;
    if !written {
        return Err(reject(
            StatusCode::CONFLICT,
            "seq must be greater than the stored seq: another publish won".into(),
        ));
    }

    info!(%sub, seq = pointer.seq, %hash, size, entries, "Catalog v2 published");
    Ok(Json(serde_json::json!({
        "owner": sub,
        "seq": pointer.seq,
        "hash": hash,
        "size": size,
    })))
}

async fn get_pointer<S: TagStore>(
    State(state): State<Arc<V2State<S>>>,
    Path(sub): Path<String>,
) -> Result<Response, ApiError> {
    let api = &state.api;
    if !valid_identifier(&sub, MAX_OWNER_BYTES) {
        return Err(fail(StatusCode::BAD_REQUEST, "invalid subject"));
    }
    let not_found = || fail(StatusCode::NOT_FOUND, "catalog not found");
    if owner_hidden(api, Some(&sub)) {
        return Err(not_found());
    }
    let stored = match api.store.get_catalog_pointer(&sub).await {
        Ok(Some(stored)) => stored,
        Ok(None) => return Err(not_found()),
        Err(e) => return Err(storage_unavailable("Catalog pointer read", e)),
    };
    let (seq, catalog_hash) =
        stored_seq(&stored.body).map_err(|e| storage_unavailable("Catalog pointer parse", e))?;
    if is_blocked(api, &catalog_hash) {
        return Err(not_found());
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CACHE_CONTROL,
                CATALOG_DOCUMENT_CACHE_CONTROL.to_string(),
            ),
            (header::ETAG, pointer_etag(seq)),
        ],
        stored.body,
    )
        .into_response())
}

/// Build the v2 state from the API state and `[http]` settings.
pub fn state<S: TagStore>(api: Arc<ApiState<S>>, rp_id: &str, status_url: &str) -> Arc<V2State<S>> {
    let status: Arc<dyn CredentialStatus> = if status_url.is_empty() {
        warn!(
            "[http] passkey_status_url empty: catalog v2 publishes skip the credential status check"
        );
        Arc::new(NoCredentialStatus)
    } else {
        Arc::new(IdpCredentialStatus::new(status_url.to_string()))
    };
    Arc::new(V2State {
        api,
        passkeys: Passkeys::for_rp(rp_id),
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CwtVerifier;
    use crate::auth::test_support::{keypair, mint_with_aud};
    use crate::catalog_v2::test_support as v2;
    use crate::creator_catalog::test_support::{catalog, entry};
    use crate::moderation::{DEFAULT_PUBLISH_ENTITLEMENT, Moderation, PublishPolicy};
    use crate::tags_api::TagPublishing;
    use crate::tags_api::test_support::MemStore;
    use axum::http::{Method, Request};
    use ciborium::value::Value;
    use http_body_util::BodyExt;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    const SUB: &str = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";
    const PAYLOAD_SIZE: u64 = 7_342_067;

    struct StubStatus(Mutex<Result<(), StatusRefusal>>);

    impl CredentialStatus for StubStatus {
        fn check<'a>(
            &'a self,
            credential_id: &'a [u8],
            sub: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), StatusRefusal>> + Send + 'a>> {
            assert_eq!(credential_id, v2::CREDENTIAL_ID);
            assert_eq!(sub, SUB);
            let answer = self.0.lock().unwrap().clone();
            Box::pin(async move { answer })
        }
    }

    struct Harness {
        app: Router,
        store: Arc<MemStore>,
        moderation: Arc<Moderation>,
        status: Arc<StubStatus>,
    }

    /// The v2 routes on a gated node whose key set holds both the token key
    /// and the IdP attestation key.
    fn harness() -> Harness {
        let (_, token_vk) = keypair();
        let store = Arc::new(MemStore::new());
        let moderation = Arc::new(Moderation::default());
        let api = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![
                (b"kid-1".to_vec(), token_vk),
                (v2::IDP_KID.to_vec(), *v2::idp_key().verifying_key()),
            ])),
            tag_prefix: "catalog/".to_string(),
            catalog_documents: Default::default(),
            publishing: Some(TagPublishing {
                policy: Arc::new(PublishPolicy {
                    entitlement: Some(DEFAULT_PUBLISH_ENTITLEMENT.into()),
                    audience: Some("arkavo".into()),
                    session_ttl: Duration::from_secs(60),
                    operator_client_ids: Default::default(),
                }),
                moderation: Arc::clone(&moderation),
            }),
        });
        let status = Arc::new(StubStatus(Mutex::new(Ok(()))));
        let state = Arc::new(V2State {
            api,
            passkeys: v2::passkeys(),
            status: Arc::clone(&status) as Arc<dyn CredentialStatus>,
        });
        Harness {
            app: router(state),
            store,
            moderation,
            status,
        }
    }

    fn token(sub: &str) -> String {
        let (sk, _) = keypair();
        mint_with_aud(
            &sk,
            b"kid-1",
            "https://identity.test",
            sub,
            "arkavo",
            now_secs(),
            now_secs() + 3600,
            &[(
                "arkavo_entitlements",
                Value::Array(vec![Value::Text(DEFAULT_PUBLISH_ENTITLEMENT.into())]),
            )],
        )
    }

    fn payload(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn doc() -> Vec<u8> {
        catalog(SUB, vec![entry("rec-1", &payload(1))])
    }

    fn body(document: &[u8], bundle: &Bundle) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "document": URL_SAFE_NO_PAD.encode(document),
            "bundle": bundle,
        }))
        .unwrap()
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

    async fn send(app: &Router, req: Request<Body>) -> Reply {
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

    async fn put(h: &Harness, sub: &str, bearer: &str, body: Vec<u8>) -> Reply {
        put_with(h, sub, bearer, body, &[]).await
    }

    async fn put_with(
        h: &Harness,
        sub: &str,
        bearer: &str,
        body: Vec<u8>,
        extra: &[(header::HeaderName, &str)],
    ) -> Reply {
        let mut req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/catalogs/{sub}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"));
        for (name, value) in extra {
            req = req.header(name, *value);
        }
        send(&h.app, req.body(Body::from(body)).unwrap()).await
    }

    /// Publishes `seq` with one precondition header.
    async fn publish_if(
        h: &Harness,
        seq: u64,
        document: &[u8],
        name: header::HeaderName,
        value: &str,
    ) -> Reply {
        let body = body(document, &v2::bundle(SUB, seq, document));
        put_with(h, SUB, &token(SUB), body, &[(name, value)]).await
    }

    async fn publish(h: &Harness, seq: u64, document: &[u8]) -> Reply {
        put(
            h,
            SUB,
            &token(SUB),
            body(document, &v2::bundle(SUB, seq, document)),
        )
        .await
    }

    async fn get(h: &Harness, sub: &str) -> Reply {
        send(
            &h.app,
            Request::get(format!("/v2/catalogs/{sub}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn ingested() -> Harness {
        let h = harness();
        h.store.ingest(&payload(1), PAYLOAD_SIZE).await;
        h
    }

    #[tokio::test]
    async fn publish_stores_document_outboard_and_bundle() {
        let h = ingested().await;
        let document = doc();
        let hash = blake3::hash(&document).to_hex().to_string();
        let bundle = v2::bundle(SUB, 1, &document);

        let r = put(&h, SUB, &token(SUB), body(&document, &bundle)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            r.json(),
            serde_json::json!({"owner": SUB, "seq": 1, "hash": hash, "size": document.len()})
        );
        {
            let docs = h.store.catalog_documents.lock().await;
            assert_eq!(docs[&hash].body, Bytes::from(document.clone()));
            assert_eq!(docs[&hash].owner.as_deref(), Some(SUB));
        }
        assert!(h.store.catalog_outboards.lock().await.contains_key(&hash));

        let r = get(&h, SUB).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(
            r.headers[header::CACHE_CONTROL],
            CATALOG_DOCUMENT_CACHE_CONTROL
        );
        let served: Bundle = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(served, bundle, "readers get the bundle as published");
    }

    #[tokio::test]
    async fn a_document_over_16_kib_gets_a_real_outboard() {
        let h = harness();
        let entries: Vec<_> = (0..120u8)
            .map(|i| {
                h.store
                    .blobs
                    .try_lock()
                    .unwrap()
                    .insert(payload(i), PAYLOAD_SIZE);
                entry(&format!("rec-{i}"), &payload(i))
            })
            .collect();
        let document = catalog(SUB, entries);
        assert!(document.len() > 16 * 1024, "{}", document.len());
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let hash = blake3::hash(&document).to_hex().to_string();
        let outboard = h.store.catalog_outboards.lock().await[&hash].clone();
        let want =
            bao_tree::BaoTree::new(document.len() as u64, iroh_blobs::store::IROH_BLOCK_SIZE)
                .outboard_size();
        assert_eq!(outboard.len() as u64, want);
        assert!(want > 0);
    }

    #[tokio::test]
    async fn seq_must_increase() {
        let h = ingested().await;
        assert_eq!(publish(&h, 2, &doc()).await.status, StatusCode::OK);
        for seq in [2, 1] {
            let r = publish(&h, seq, &doc()).await;
            assert_eq!(r.status, StatusCode::CONFLICT);
            assert_eq!(r.error(), "seq must be greater than 2");
        }
        assert_eq!(publish(&h, 3, &doc()).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_pointer_is_tagged_with_its_seq() {
        let h = ingested().await;
        assert_eq!(publish(&h, 7, &doc()).await.status, StatusCode::OK);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"7\"");
    }

    /// A refused precondition stores nothing: not the refused document, not
    /// its outboard, and no pointer beyond the `pointers` already there.
    async fn assert_precondition_failed(h: &Harness, r: Reply, document: &[u8], pointers: usize) {
        assert_eq!(r.status, StatusCode::PRECONDITION_FAILED, "{}", r.error());
        assert_eq!(r.error(), "catalog changed since it was read");
        let hash = blake3::hash(document).to_hex().to_string();
        assert!(!h.store.catalog_documents.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert_eq!(h.store.catalog_pointers.lock().await.len(), pointers);
    }

    #[tokio::test]
    async fn if_match_names_the_base_the_publish_was_merged_from() {
        let h = ingested().await;
        assert_eq!(publish(&h, 6, &doc()).await.status, StatusCode::OK);
        // Another device saves seq 7 from the same base.
        let theirs = catalog(SUB, vec![]);
        let r = publish_if(&h, 7, &theirs, header::IF_MATCH, "\"6\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());

        // Ours, merged from seq 6 but signed with a higher seq: 412, not a
        // silent overwrite of seq 7, and not a 409 either.
        let ours = catalog(
            SUB,
            vec![entry("rec-1", &payload(1)), entry("rec-2", &payload(1))],
        );
        for seq in [11, 7] {
            let r = publish_if(&h, seq, &ours, header::IF_MATCH, "\"6\"").await;
            assert_precondition_failed(&h, r, &ours, 1).await;
        }
        for stale in ["W/\"7\"", "7", "\"6\", W/\"7\""] {
            let r = publish_if(&h, 11, &ours, header::IF_MATCH, stale).await;
            assert_precondition_failed(&h, r, &ours, 1).await;
        }
        let served: Bundle = serde_json::from_slice(&get(&h, SUB).await.body).unwrap();
        assert_eq!(served, v2::bundle(SUB, 7, &theirs));

        let r = publish_if(&h, 11, &ours, header::IF_MATCH, "\"6\", \"7\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let r = publish_if(&h, 12, &doc(), header::IF_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        // A matching base still needs a greater seq.
        let r = publish_if(&h, 12, &doc(), header::IF_MATCH, "\"12\"").await;
        assert_eq!(r.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn if_match_needs_a_stored_pointer() {
        let h = ingested().await;
        for tag in ["\"1\"", "*"] {
            let r = publish_if(&h, 1, &doc(), header::IF_MATCH, tag).await;
            assert_precondition_failed(&h, r, &doc(), 0).await;
        }
    }

    #[tokio::test]
    async fn if_none_match_star_publishes_only_the_first_pointer() {
        let h = ingested().await;
        let r = publish_if(&h, 1, &doc(), header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let other = catalog(SUB, vec![]);
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "*").await;
        assert_precondition_failed(&h, r, &other, 1).await;
        // The tag itself (or its weak form) also fails; another tag passes.
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "W/\"1\"").await;
        assert_precondition_failed(&h, r, &other, 1).await;
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "\"9\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn if_match_is_evaluated_before_if_none_match() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &doc()).await.status, StatusCode::OK);
        let other = catalog(SUB, vec![]);
        let body = body(&other, &v2::bundle(SUB, 2, &other));
        let both = [(header::IF_MATCH, "\"1\""), (header::IF_NONE_MATCH, "*")];
        let r = put_with(&h, SUB, &token(SUB), body, &both).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn a_publish_that_loses_the_race_is_a_conflict() {
        let h = ingested().await;
        h.store
            .lose_next_pointer_race
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 1, &doc()).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        assert!(r.error().contains("another publish won"));
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    #[tokio::test]
    async fn only_the_subject_publishes_its_catalog() {
        let h = ingested().await;
        let document = doc();
        let r = put(
            &h,
            SUB,
            &token("someone-else"),
            body(&document, &v2::bundle(SUB, 1, &document)),
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(r.error(), "catalog does not match token subject");
    }

    #[tokio::test]
    async fn the_pointer_must_name_this_document() {
        let h = ingested().await;
        let document = doc();
        let other = catalog(SUB, vec![]);
        let r = put(
            &h,
            SUB,
            &token(SUB),
            body(&document, &v2::bundle(SUB, 1, &other)),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("catalogHash"), "{}", r.error());
    }

    #[tokio::test]
    async fn a_tampered_bundle_is_refused() {
        let h = ingested().await;
        let document = doc();
        let mut bundle = v2::bundle(SUB, 1, &document);
        // Re-point a validly signed bundle at seq 9: the passkey signed seq 1.
        let pointer = v2::pointer_bytes(SUB, 9, &document);
        bundle.pointer = URL_SAFE_NO_PAD.encode(pointer);
        let r = put(&h, SUB, &token(SUB), body(&document, &bundle)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().starts_with("invalid bundle: "), "{}", r.error());
    }

    #[tokio::test]
    async fn the_document_must_be_a_catalog_of_the_subject() {
        let h = ingested().await;
        let document = catalog("someone-else", vec![entry("rec-1", &payload(1))]);
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            r.error(),
            "invalid catalog: owner does not match the catalog subject"
        );
    }

    #[tokio::test]
    async fn payloads_must_be_ingested() {
        let h = harness();
        let r = publish(&h, 1, &doc()).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(r.error(), format!("payload {} is not ingested", payload(1)));
    }

    #[tokio::test]
    async fn a_revoked_or_unknown_credential_is_refused() {
        let h = ingested().await;
        *h.status.0.lock().unwrap() = Err(StatusRefusal::Refused("passkey credential revoked"));
        let r = publish(&h, 1, &doc()).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(r.error(), "passkey credential revoked");

        *h.status.0.lock().unwrap() = Err(StatusRefusal::Unavailable);
        let r = publish(&h, 1, &doc()).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
        assert_eq!(r.error(), "credential status unavailable");
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    #[tokio::test]
    async fn blocked_catalogs_are_neither_published_nor_served() {
        let h = ingested().await;
        let document = doc();
        let hash = blake3::hash(&document).to_hex().to_string();
        h.moderation.block_for_test(&hash);
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(r.error(), "content is blocked");

        let h = ingested().await;
        assert_eq!(publish(&h, 1, &document).await.status, StatusCode::OK);
        h.moderation.block_for_test(&hash);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_hidden_creator_has_no_catalog() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &doc()).await.status, StatusCode::OK);
        h.moderation.suspend_for_test(SUB, true);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reads_of_unknown_and_invalid_subjects() {
        let h = harness();
        let r = get(&h, SUB).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
        assert_eq!(get(&h, "a..b").await.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn padded_or_oversized_documents_are_refused() {
        let h = ingested().await;
        let document = doc();
        let bundle = v2::bundle(SUB, 1, &document);
        let mut b: serde_json::Value = serde_json::from_slice(&body(&document, &bundle)).unwrap();
        b["document"] = serde_json::Value::String(
            base64::engine::general_purpose::URL_SAFE.encode(&document[..10]) + "=",
        );
        let r = put(&h, SUB, &token(SUB), serde_json::to_vec(&b).unwrap()).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("unpadded base64url"), "{}", r.error());
        b["extra"] = serde_json::json!(1);
        let r = put(&h, SUB, &token(SUB), serde_json::to_vec(&b).unwrap()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
}
