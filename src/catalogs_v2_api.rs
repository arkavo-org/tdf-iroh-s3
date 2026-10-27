//! Catalog v2 routes (tdf-iroh-s3#27, #39, `docs/creator-catalogs.md`).
//!
//! - `PUT /v2/catalogs/{sub}` — publish: the catalog document, the
//!   creator's passkey-signed pointer bundle and the catalog's clear index.
//!   The document is a ZTDF envelope whose payload is the
//!   `arkavo.creator-catalog/2` document, under one attribute
//!   (`catalog_metadata::check_envelope`); the node never decrypts it and
//!   checks the entries through the index, which it stores at
//!   `catalog-indexes/<hash>` and never serves. The document is stored
//!   under `catalog-documents/<blake3>` with its BAO outboard, so it is
//!   served over iroh; the bundle replaces `catalog-pointers/<sub>` only
//!   when its `seq` is greater than the stored one's, and only when the
//!   stored pointer is still the base named by `If-Match` /
//!   `If-None-Match`, if given (tdf-iroh-s3#29; 412 otherwise).
//! - `GET /v2/catalogs/{sub}` — a token, then the catalog decision: whether
//!   the reader may open the envelope's attribute (403 otherwise). The
//!   stored bundle, with `ETag: "<seq>"`, which readers verify themselves
//!   before fetching the document over iroh by hash.
//!
//! Publishing takes the publishing token checks (`authorize_publisher`).

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

use crate::authz::{DecisionProvider, DecisionRequest, ResourceType, SharedDecisionProvider};
use crate::catalog_metadata::{self, CAMPAIGN_FQN_PREFIX, EnvelopeRefusal};
use crate::catalog_v2::{self, Bundle, BundleError, Passkeys};
use crate::catalogs_api::{check_payloads, is_json, owner_hidden};
use crate::creator_catalog::{
    self, MAX_CATALOG_BYTES, MAX_OWNER_BYTES, NoDuplicateKeys, valid_identifier,
};
use crate::moderation::{bearer, now_secs};
use crate::tags_api::{
    ApiState, TagStore, authorize_catalog_reader, authorize_publisher, is_blocked,
};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn fail(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

fn storage_unavailable(what: &str, e: anyhow::Error) -> ApiError {
    warn!(error = %e, "{what} failed");
    fail(StatusCode::BAD_GATEWAY, "storage unavailable")
}

/// A pointer is resolved per caller (it may need a token), so only the
/// caller may reuse it, unlike a catalog document fetched by hash.
pub const CATALOG_POINTER_CACHE_CONTROL: &str = "private, max-age=300";

/// Largest publish body: a 512 KiB envelope in base64url (about 700 KiB),
/// an index of 1000 entries (about 300 KiB, up to 500 KiB with the longest
/// contentIDs) and a bundle of a few KiB.
pub const MAX_PUT_BYTES: usize = 2 * 1024 * 1024;

/// How many catalogs' attributes a node remembers; the map is cleared when
/// it reaches this many. A stored catalog's attribute never changes.
const ATTRIBUTE_CACHE_CAPACITY: usize = 100_000;

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
    pub readers: Readers,
    /// catalog hash → its envelope's attribute, read from its index record.
    attributes: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

/// How `GET /v2/catalogs/{sub}` decides whether a reader may open a
/// catalog: the `[catalog.authz]` decision service, asked as `GET
/// /catalog/{group}` asks it.
pub struct Readers {
    /// `None` (no decision service configured): every person is refused
    /// with 502 `decision unavailable`.
    pub provider: Option<SharedDecisionProvider>,
    pub action: String,
    /// Environment claims this node asserts, appended to the chain.
    pub environment: Option<serde_json::Value>,
}

/// A catalog's index record (`catalog-indexes/<hash>`): what the node
/// checked at publish. Moderation reads it to find an entry's hashes.
#[derive(serde::Serialize, Deserialize)]
struct IndexRecord {
    owner: String,
    attribute: String,
    entries: serde_json::Value,
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
    index: serde_json::Value,
}

/// The `seq` of a stored bundle. The node wrote it after verifying it, so
/// failing to read it back is a storage fault.
pub(crate) fn stored_seq(body: &[u8]) -> anyhow::Result<(u64, String)> {
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

/// The comma-separated entity tags of every `name` header line: `None`
/// without one, `Err` when a value is not visible ASCII.
fn entity_tags(headers: &HeaderMap, name: header::HeaderName) -> Option<Result<Vec<&str>, ()>> {
    let mut values = headers.get_all(name).iter().peekable();
    values.peek()?;
    let mut tags = Vec::new();
    for value in values {
        let Ok(value) = value.to_str() else {
            return Some(Err(()));
        };
        tags.extend(value.split(',').map(str::trim));
    }
    Some(Ok(tags))
}

/// Whether the request's preconditions (RFC 9110 §13.2.2) hold for the
/// served pointer's tag (`None`: no pointer served). `If-Match` takes strong
/// comparison, so a weak or unquoted tag never matches, and `*` needs a
/// pointer; `If-None-Match` takes weak comparison and fails on `*` or the
/// tag while a pointer is served. Both are evaluated when both are sent. A
/// value that is not visible ASCII fails. No header: no condition.
fn preconditions_hold(headers: &HeaderMap, served: Option<&str>) -> bool {
    if let Some(tags) = entity_tags(headers, header::IF_MATCH) {
        let Ok(tags) = tags else { return false };
        if !served.is_some_and(|etag| tags.iter().any(|&t| t == "*" || t == etag)) {
            return false;
        }
    }
    if let Some(tags) = entity_tags(headers, header::IF_NONE_MATCH) {
        let Ok(tags) = tags else { return false };
        if let Some(etag) = served
            && tags
                .iter()
                .any(|&t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag)
        {
            return false;
        }
    }
    true
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
    // serde_json keeps the last of two equal keys, so a separate pass
    // refuses them (the index included) before the typed parse.
    let invalid =
        |e: serde_json::Error| fail(StatusCode::BAD_REQUEST, format!("invalid request: {e}"));
    serde_json::from_slice::<NoDuplicateKeys>(&bytes).map_err(invalid)?;
    let req: PutRequest = serde_json::from_slice(&bytes).map_err(invalid)?;
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

    // 4. The pointer names exactly this document: an envelope of `sub`'s
    //    catalog under one attribute.
    let hash = blake3::hash(&document).to_hex().to_string();
    if hash != pointer.catalog_hash || document.len() as u64 != pointer.catalog_size {
        return Err(reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid bundle: catalogHash or catalogSize does not match the document".into(),
        ));
    }
    let attribute = envelope_attribute(&document, &sub)
        .map_err(|why| reject(StatusCode::UNPROCESSABLE_ENTITY, why.into()))?;
    // A campaign's catalog comes from its creator, as identity asserts it.
    let campaign = attribute
        .strip_prefix(CAMPAIGN_FQN_PREFIX)
        .map(str::to_string);
    if let Some(id) = &campaign
        && !owns_campaign(&claims, id)
    {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "catalog campaign is not the publisher's".into(),
        ));
    }

    // 5. The index: the entries the envelope holds, which the node can't
    //    read. Nothing blocked, every payload and metadata TDF ingested at
    //    its size, each metadata TDF fitting its recording, each recording
    //    carrying the envelope's attribute.
    let index = req.index.clone();
    let entries = creator_catalog::parse_index(req.index).map_err(|why| {
        reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid index: {why}"),
        )
    })?;
    if is_blocked(api, &hash) {
        return Err(reject(StatusCode::FORBIDDEN, "content is blocked".into()));
    }
    check_payloads(api, &entries, &attribute)
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
    let current = current
        .map(|stored| stored_seq(&stored.body).map(|parsed| (stored, parsed)))
        .transpose()
        .map_err(|e| storage_unavailable("Catalog pointer parse", e))?;
    // A pointer at a catalog with no index record names a document from
    // before envelopes, which `GET` never serves: it reads as none, so the
    // first envelope may start at any seq. The conditional write below
    // still replaces exactly that pointer.
    let live = match &current {
        Some((_, (_, hash))) => api
            .store
            .get_catalog_index(hash)
            .await
            .map_err(|e| storage_unavailable("Catalog index read", e))?
            .is_some(),
        None => false,
    };
    let current_seq = current.as_ref().filter(|_| live).map(|(_, (seq, _))| *seq);
    // Preconditions see what `GET` serves: a pointer whose catalog is
    // blocked reads as none, so a client that got the 404 can publish with
    // `If-None-Match: *`.
    let served_seq = current
        .as_ref()
        .filter(|(_, (_, hash))| live && !is_blocked(api, hash))
        .map(|(_, (seq, _))| *seq);
    if !preconditions_hold(&headers, served_seq.map(pointer_etag).as_deref()) {
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
    let expected = current.as_ref().map(|(stored, _)| stored.etag.as_str());

    // 8. The document, its outboard and its index first, so a stored
    //    pointer never names a document that cannot be served or decided;
    //    then the pointer, only if nobody else moved it meanwhile.
    let outboard = crate::ingest::compute_outboard(
        &document[..],
        document.len() as u64,
        Hash::from_bytes(*blake3::hash(&document).as_bytes()),
    )
    .map_err(|e| storage_unavailable("Catalog outboard", e))?;
    let size = document.len();
    let record = IndexRecord {
        owner: sub.clone(),
        attribute: attribute.clone(),
        entries: index,
    };
    let entries = entries.len();
    api.store
        .put_catalog_document(&hash, Bytes::from(document), &sub)
        .await
        .map_err(|e| storage_unavailable("Catalog document write", e))?;
    api.store
        .put_catalog_outboard(&hash, Bytes::from(outboard))
        .await
        .map_err(|e| storage_unavailable("Catalog outboard write", e))?;
    api.store
        .put_catalog_index(
            &hash,
            Bytes::from(serde_json::to_vec(&record).expect("record serializes")),
        )
        .await
        .map_err(|e| storage_unavailable("Catalog index write", e))?;
    if let Some(id) = &campaign {
        api.store
            .put_campaign_creator(id, &sub)
            .await
            .map_err(|e| storage_unavailable("Campaign creator write", e))?;
    }
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

    info!(%sub, seq = pointer.seq, %hash, size, entries, %attribute, "Catalog v2 published");
    Ok(Json(serde_json::json!({
        "owner": sub,
        "seq": pointer.seq,
        "hash": hash,
        "size": size,
    })))
}

/// The envelope's one attribute, or the 422 reason `document` is not an
/// envelope of `sub`'s catalog.
fn envelope_attribute(document: &[u8], sub: &str) -> Result<String, &'static str> {
    let not_tdf = "document is not a TDF";
    let manifest = crate::validation::structure::validate_tdf_structure(document)
        .map_err(|_| not_tdf)?
        .to_json()
        .map_err(|_| not_tdf)?;
    let manifest = catalog_metadata::read_manifest(manifest.as_bytes()).ok_or(not_tdf)?;
    catalog_metadata::check_envelope(&manifest, sub).map_err(|why| match why {
        EnvelopeRefusal::NotCatalog => "document is not a catalog",
        EnvelopeRefusal::NoPolicyId => "catalog policy has no uuid",
        EnvelopeRefusal::Policy => "catalog policy must be one campaign or the creator attribute",
    })
}

/// Whether the token's `arkavo_patreon` names its subject the creator of
/// campaign `id`: role `creator` and that `campaign_id`, which identity
/// sets only for the campaign the account owns.
fn owns_campaign(claims: &crate::auth::VerifiedClaims, id: &str) -> bool {
    claims.arkavo_patreon.as_ref().is_some_and(|p| {
        p.get("role").and_then(serde_json::Value::as_str) == Some("creator")
            && p.get("campaign_id").and_then(serde_json::Value::as_str) == Some(id)
    })
}

/// An operator's service CWT, admitted as the moderation API admits one
/// (`PublishPolicy::operator`): `client:<id>` with role `service-account`,
/// `aud` naming the client, and the client in `[publishing]
/// operator_client_ids`. It carries no campaign values, so it reads
/// catalogs without a decision. An ungated node admits none.
fn is_operator<S: TagStore>(api: &ApiState<S>, claims: &crate::auth::VerifiedClaims) -> bool {
    let Some(publishing) = &api.publishing else {
        return false;
    };
    let Some(client) = claims.sub.strip_prefix("client:").filter(|c| !c.is_empty()) else {
        return false;
    };
    publishing.policy.operator_client_ids.contains(client)
        && claims.aud.contains(client)
        && claims
            .arkavo_roles
            .as_ref()
            .is_some_and(|r| r.iter().any(|x| x == "service-account"))
}

impl<S: TagStore> V2State<S> {
    /// The attribute of the stored catalog `hash`, from its index record;
    /// `None` for a catalog stored without one.
    async fn catalog_attribute(&self, hash: &str) -> Result<Option<String>, ApiError> {
        if let Some(attribute) = self.known_attributes().get(hash) {
            return Ok(Some(attribute.clone()));
        }
        let Some(body) = self
            .api
            .store
            .get_catalog_index(hash)
            .await
            .map_err(|e| storage_unavailable("Catalog index read", e))?
        else {
            return Ok(None);
        };
        let record: IndexRecord = serde_json::from_slice(&body)
            .map_err(|e| storage_unavailable("Catalog index parse", e.into()))?;
        let mut known = self.known_attributes();
        if known.len() >= ATTRIBUTE_CACHE_CAPACITY {
            known.clear();
        }
        known.insert(hash.to_string(), record.attribute.clone());
        Ok(Some(record.attribute))
    }

    fn known_attributes(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, String>> {
        self.attributes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the reader of `headers` may open the catalog `hash`, whose
    /// envelope is under `attribute`: Permit, or 403 `not entitled to
    /// catalog`; 502 `decision unavailable` without an answer.
    async fn decide_reader(
        &self,
        claims: &crate::auth::VerifiedClaims,
        headers: &HeaderMap,
        hash: &str,
        attribute: &str,
    ) -> Result<(), ApiError> {
        let unavailable = || fail(StatusCode::BAD_GATEWAY, "decision unavailable");
        let Some(provider) = &self.readers.provider else {
            return Err(unavailable());
        };
        let token = bearer(headers).expect("the reader's token was verified");
        let chain = crate::entity_chain::person_chain(
            &self.api.verifier,
            claims,
            token,
            headers,
            self.readers.environment.as_ref(),
            now_secs(),
        )
        .await
        .map_err(|(status, msg)| fail(status, msg))?;
        let req = DecisionRequest {
            chain,
            action: self.readers.action.clone(),
            resource_type: ResourceType::CatalogItem,
            resources: vec![(hash.to_string(), vec![attribute.to_string()])],
        };
        match provider.decide(req).await {
            Ok(verdicts) if verdicts.get(hash) == Some(&true) => Ok(()),
            Ok(_) => {
                info!(sub = %claims.sub, %hash, %attribute, "Catalog read not entitled");
                Err(fail(StatusCode::FORBIDDEN, "not entitled to catalog"))
            }
            Err(e) => {
                warn!(%hash, error = %e, "Catalog read decision failed; failing closed");
                Err(unavailable())
            }
        }
    }
}

async fn get_pointer<S: TagStore>(
    State(state): State<Arc<V2State<S>>>,
    Path(sub): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let api = &state.api;
    let claims = authorize_catalog_reader(&api.verifier, &headers)
        .await
        .map_err(|(status, msg)| fail(status, msg))?;
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
    // A pointer at a catalog from before envelopes has no attribute to
    // decide on: no catalog.
    let Some(attribute) = state.catalog_attribute(&catalog_hash).await? else {
        return Err(not_found());
    };
    if !is_operator(api, &claims) {
        state
            .decide_reader(&claims, &headers, &catalog_hash, &attribute)
            .await?;
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CACHE_CONTROL,
                CATALOG_POINTER_CACHE_CONTROL.to_string(),
            ),
            (header::ETAG, pointer_etag(seq)),
        ],
        stored.body,
    )
        .into_response())
}

/// Build the v2 state from the API state, `[http]` settings and the
/// catalog decision service.
pub fn state<S: TagStore>(
    api: Arc<ApiState<S>>,
    rp_id: &str,
    status_url: &str,
    readers: Readers,
) -> Arc<V2State<S>> {
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
        readers,
        attributes: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CwtVerifier;
    use crate::auth::test_support::{keypair, mint_with_aud};
    use crate::authz::Decisions;
    use crate::catalog_metadata::CATALOG_MIME_TYPE;
    use crate::catalog_metadata::test_support::{
        CAMPAIGN, KAS, envelope_policy, envelope_tdf, manifest, metadata_manifest, metadata_policy,
        recording_policy,
    };
    use crate::catalog_v2::test_support as v2;
    use crate::creator_catalog::test_support::{METADATA_SIZE, PAYLOAD_SIZE, entry};
    use crate::moderation::{DEFAULT_PUBLISH_ENTITLEMENT, Moderation, PublishPolicy};
    use crate::tags_api::TagPublishing;
    use crate::tags_api::test_support::MemStore;
    use axum::http::{Method, Request};
    use ciborium::value::Value;
    use http_body_util::BodyExt;
    use serde_json::json;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    const SUB: &str = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";
    const READER: &str = "0b5e7c1d-8a2f-4c3e-9d10-7f6a5b4c3d2e";

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

    /// The catalog decision service: Permit (`Some(true)`), Deny
    /// (`Some(false)`) or down (`None`), recording what it was asked.
    struct StubDecider {
        answer: Mutex<Option<bool>>,
        asked: Mutex<Vec<DecisionRequest>>,
    }

    impl DecisionProvider for StubDecider {
        async fn decide(&self, req: DecisionRequest) -> anyhow::Result<Decisions> {
            let answer = *self.answer.lock().unwrap();
            let ids: Vec<String> = req.resources.iter().map(|(id, _)| id.clone()).collect();
            self.asked.lock().unwrap().push(req);
            match answer {
                Some(permit) => Ok(ids.into_iter().map(|id| (id, permit)).collect()),
                None => anyhow::bail!("decision service down"),
            }
        }
    }

    struct Harness {
        app: Router,
        store: Arc<MemStore>,
        moderation: Arc<Moderation>,
        status: Arc<StubStatus>,
        decider: Arc<StubDecider>,
    }

    /// The v2 routes on a gated node whose key set holds both the token key
    /// and the IdP attestation key, and whose decision service permits.
    fn harness() -> Harness {
        harness_with(true)
    }

    fn harness_with(decisions: bool) -> Harness {
        let (_, token_vk) = keypair();
        let store = Arc::new(MemStore::new());
        let moderation = Arc::new(Moderation::default());
        let api = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![
                (b"kid-1".to_vec(), token_vk),
                (v2::IDP_KID.to_vec(), *v2::idp_key().verifying_key()),
            ])),
            publishing: Some(TagPublishing {
                policy: Arc::new(PublishPolicy {
                    entitlement: Some(DEFAULT_PUBLISH_ENTITLEMENT.into()),
                    audience: Some("arkavo".into()),
                    session_ttl: Duration::from_secs(60),
                    operator_client_ids: ["moderation".to_string()].into(),
                    decider: Default::default(),
                }),
                moderation: Arc::clone(&moderation),
            }),
        });
        let status = Arc::new(StubStatus(Mutex::new(Ok(()))));
        let decider = Arc::new(StubDecider {
            answer: Mutex::new(Some(true)),
            asked: Mutex::new(Vec::new()),
        });
        let state = Arc::new(V2State {
            api,
            passkeys: v2::passkeys(),
            status: Arc::clone(&status) as Arc<dyn CredentialStatus>,
            readers: Readers {
                provider: decisions.then(|| Arc::clone(&decider) as SharedDecisionProvider),
                action: "read".into(),
                environment: None,
            },
            attributes: Default::default(),
        });
        Harness {
            app: router(state),
            store,
            moderation,
            status,
            decider,
        }
    }

    fn token_with(sub: &str, extras: &[(&str, Value)]) -> String {
        token_for(sub, "arkavo", extras)
    }

    fn token_for(sub: &str, aud: &str, extras: &[(&str, Value)]) -> String {
        let (sk, _) = keypair();
        mint_with_aud(
            &sk,
            b"kid-1",
            "https://identity.test",
            sub,
            aud,
            now_secs(),
            now_secs() + 3600,
            extras,
        )
    }

    /// A publisher's token: entitled, and the creator of campaign
    /// 12345678 (`CAMPAIGN`).
    fn token(sub: &str) -> String {
        token_with(
            sub,
            &publisher_claims(Some(patreon("creator", Some("12345678")))),
        )
    }

    fn patreon(role: &str, campaign_id: Option<&str>) -> Value {
        let mut map = vec![(Value::Text("role".into()), Value::Text(role.into()))];
        if let Some(id) = campaign_id {
            map.push((Value::Text("campaign_id".into()), Value::Text(id.into())));
        }
        Value::Map(map)
    }

    fn publisher_claims(patreon: Option<Value>) -> Vec<(&'static str, Value)> {
        let mut claims = vec![(
            "arkavo_entitlements",
            Value::Array(vec![Value::Text(DEFAULT_PUBLISH_ENTITLEMENT.into())]),
        )];
        claims.extend(patreon.map(|p| ("arkavo_patreon", p)));
        claims
    }

    fn payload(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn meta(n: u8) -> String {
        format!("{:02x}", 0x80 + n).repeat(32)
    }

    /// A campaign envelope; `n` varies the bytes (and so the hash).
    fn envelope(n: u8) -> Vec<u8> {
        envelope_tdf(envelope_policy(CAMPAIGN), CATALOG_MIME_TYPE, &[n; 64])
    }

    /// The index naming payload(1) and meta(1).
    fn index() -> serde_json::Value {
        json!([entry("rec-1", &payload(1), &meta(1))])
    }

    fn body_with(document: &[u8], bundle: &Bundle, index: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "document": URL_SAFE_NO_PAD.encode(document),
            "bundle": bundle,
            "index": index,
        }))
        .unwrap()
    }

    fn body(document: &[u8], bundle: &Bundle) -> Vec<u8> {
        body_with(document, bundle, index())
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
        publish_index(h, seq, document, index()).await
    }

    async fn publish_index(
        h: &Harness,
        seq: u64,
        document: &[u8],
        index: serde_json::Value,
    ) -> Reply {
        let body = body_with(document, &v2::bundle(SUB, seq, document), index);
        put(h, SUB, &token(SUB), body).await
    }

    async fn get_as(h: &Harness, sub: &str, bearer: Option<&str>) -> Reply {
        let mut req = Request::get(format!("/v2/catalogs/{sub}"));
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        send(&h.app, req.body(Body::empty()).unwrap()).await
    }

    /// A signed-in viewer's read.
    async fn get(h: &Harness, sub: &str) -> Reply {
        get_as(h, sub, Some(&token(READER))).await
    }

    /// payload(n) (a campaign recording) and meta(n) (its metadata TDF),
    /// each with a stored manifest.
    async fn ingest_pair(h: &Harness, n: u8) {
        h.store
            .ingest_with_manifest(
                &payload(n),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        let mut policy = metadata_policy();
        policy["uuid"] = json!(format!("meta-{n}"));
        h.store
            .ingest_with_manifest(&meta(n), METADATA_SIZE, metadata_manifest(policy, &[KAS]))
            .await;
    }

    async fn ingested() -> Harness {
        let h = harness();
        ingest_pair(&h, 1).await;
        h
    }

    fn hash_of(document: &[u8]) -> String {
        blake3::hash(document).to_hex().to_string()
    }

    #[tokio::test]
    async fn reads_need_a_token() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let r = get_as(&h, SUB, None).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::UNAUTHORIZED, "token required")
        );
        let r = get_as(&h, SUB, Some("not-a-cwt")).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::UNAUTHORIZED, "invalid token")
        );
        // Checked before the lookup: an unknown subject answers the same.
        let r = get_as(&h, "someone-else", None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(h.decider.asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn publish_stores_document_outboard_index_and_bundle() {
        let h = ingested().await;
        let document = envelope(1);
        let hash = hash_of(&document);
        let bundle = v2::bundle(SUB, 1, &document);

        let r = put(&h, SUB, &token(SUB), body(&document, &bundle)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            r.json(),
            json!({"owner": SUB, "seq": 1, "hash": hash, "size": document.len()})
        );
        {
            let docs = h.store.catalog_documents.lock().await;
            assert_eq!(docs[&hash].body, Bytes::from(document.clone()));
            assert_eq!(docs[&hash].owner.as_deref(), Some(SUB));
        }
        assert!(h.store.catalog_outboards.lock().await.contains_key(&hash));
        let record: serde_json::Value =
            serde_json::from_slice(&h.store.catalog_indexes.lock().await[&hash]).unwrap();
        assert_eq!(
            record,
            json!({ "owner": SUB, "attribute": CAMPAIGN, "entries": index() })
        );

        let r = get(&h, SUB).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            r.headers[header::CACHE_CONTROL],
            CATALOG_POINTER_CACHE_CONTROL
        );
        let served: Bundle = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(served, bundle, "readers get the bundle as published");
    }

    #[tokio::test]
    async fn resolution_asks_whether_the_reader_may_open_the_catalog() {
        let h = ingested().await;
        let document = envelope(1);
        let hash = hash_of(&document);
        assert_eq!(publish(&h, 1, &document).await.status, StatusCode::OK);

        assert_eq!(get(&h, SUB).await.status, StatusCode::OK);
        {
            let asked = h.decider.asked.lock().unwrap();
            let req = &asked[0];
            assert_eq!(req.action, "read");
            assert_eq!(req.resource_type, ResourceType::CatalogItem);
            assert_eq!(
                req.resources,
                vec![(hash.clone(), vec![CAMPAIGN.to_string()])]
            );
            assert_eq!(req.chain.len(), 1);
            assert_eq!(req.chain[0].claims["sub"], READER);
        }

        *h.decider.answer.lock().unwrap() = Some(false);
        let r = get(&h, SUB).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::FORBIDDEN, "not entitled to catalog")
        );
        *h.decider.answer.lock().unwrap() = None;
        let r = get(&h, SUB).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "decision unavailable")
        );
        // The attribute was read from the index record once.
        h.store.catalog_indexes.lock().await.clear();
        *h.decider.answer.lock().unwrap() = Some(true);
        assert_eq!(get(&h, SUB).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn without_a_decision_service_reads_fail_closed() {
        let h = harness_with(false);
        ingest_pair(&h, 1).await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let r = get(&h, SUB).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "decision unavailable")
        );
    }

    #[tokio::test]
    async fn an_operator_token_reads_without_a_decision() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        *h.decider.answer.lock().unwrap() = Some(false);
        let roles = |r: &str| [("arkavo_roles", Value::Array(vec![Value::Text(r.into())]))];
        // As the moderation API admits an operator: allowlisted client, `aud`
        // naming it, role service-account.
        let operator = token_for("client:moderation", "moderation", &roles("service-account"));
        assert_eq!(
            get_as(&h, SUB, Some(&operator)).await.status,
            StatusCode::OK
        );
        assert!(h.decider.asked.lock().unwrap().is_empty());
        // Anything less is decided like a person.
        for other in [
            token_for("client:moderation", "arkavo", &roles("service-account")),
            token_for("client:other", "other", &roles("service-account")),
            token_for("client:moderation", "moderation", &roles("viewer")),
        ] {
            assert_eq!(
                get_as(&h, SUB, Some(&other)).await.status,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(h.decider.asked.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_pointer_from_before_envelopes_reads_as_none() {
        let h = ingested().await;
        // seq 12 at a document with no index record, as `/1` left it.
        let old = b"{\"schema\":\"arkavo.creator-catalog/1\"}".to_vec();
        let bundle = serde_json::to_vec(&v2::bundle(SUB, 12, &old)).unwrap();
        h.store
            .catalog_pointers
            .lock()
            .await
            .insert(SUB.into(), (Bytes::from(bundle), 99));
        let r = get(&h, SUB).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::NOT_FOUND, "catalog not found")
        );
        // The first envelope starts at any seq and replaces it, as a first
        // publish would.
        let r = publish_if(&h, 1, &envelope(1), header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");
    }

    #[tokio::test]
    async fn the_document_must_be_an_envelope_of_the_subject() {
        let h = ingested().await;
        let refused = |document: Vec<u8>, why: &'static str| {
            let h = &h;
            async move {
                let r = publish(h, 1, &document).await;
                assert_eq!(
                    (r.status, r.error().as_str()),
                    (StatusCode::UNPROCESSABLE_ENTITY, why)
                );
            }
        };
        refused(
            b"{\"schema\":\"arkavo.creator-catalog/2\"}".to_vec(),
            "document is not a TDF",
        )
        .await;
        refused(
            envelope_tdf(envelope_policy(CAMPAIGN), "application/json", b"x"),
            "document is not a catalog",
        )
        .await;
        let policy_refusal = "catalog policy must be one campaign or the creator attribute";
        let two = json!({ "uuid": "e", "body": { "dataAttributes": [
            { "attribute": CAMPAIGN },
            { "attribute": format!("https://arkavo.net/attr/creator/value/{SUB}") } ] } });
        let mut classified = envelope_policy(CAMPAIGN);
        classified["arkavo:classification"] = json!("general");
        for policy in [
            two,
            classified,
            envelope_policy("https://arkavo.net/attr/creator/value/someone-else"),
        ] {
            refused(
                envelope_tdf(policy, CATALOG_MIME_TYPE, b"x"),
                policy_refusal,
            )
            .await;
        }
        let mut no_id = envelope_policy(CAMPAIGN);
        no_id["uuid"] = json!("");
        refused(
            envelope_tdf(no_id, CATALOG_MIME_TYPE, b"x"),
            "catalog policy has no uuid",
        )
        .await;
        assert!(h.store.catalog_documents.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_creator_without_a_campaign_publishes_under_their_creator_attribute() {
        let h = harness();
        let creator = format!("https://arkavo.net/attr/creator/value/{SUB}");
        let policy = json!({ "uuid": "r", "body": {
            "dataAttributes": [{ "attribute": creator }], "dissem": [] } });
        h.store
            .ingest_with_manifest(&payload(1), PAYLOAD_SIZE, manifest(policy.clone(), &[KAS]))
            .await;
        let mut meta_policy = policy;
        meta_policy["uuid"] = json!("m");
        h.store
            .ingest_with_manifest(
                &meta(1),
                METADATA_SIZE,
                metadata_manifest(meta_policy, &[KAS]),
            )
            .await;
        let document = envelope_tdf(envelope_policy(&creator), CATALOG_MIME_TYPE, b"x");
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(get(&h, SUB).await.status, StatusCode::OK);
        assert!(h.store.campaign_creators.lock().await.is_empty());
        let asked = h.decider.asked.lock().unwrap();
        assert_eq!(asked[0].resources[0].1, vec![creator]);
    }

    #[tokio::test]
    async fn a_campaign_catalog_comes_from_the_campaign_creator() {
        let h = ingested().await;
        let document = envelope(1);
        let bundle = || body(&document, &v2::bundle(SUB, 1, &document));
        for patreon in [
            None,
            Some(patreon("consumer", None)),
            Some(patreon("creator", Some("99"))),
            Some(patreon("consumer", Some("12345678"))),
            Some(Value::Map(vec![
                (Value::Text("role".into()), Value::Text("creator".into())),
                (
                    Value::Text("campaign_id".into()),
                    Value::Integer(12345678.into()),
                ),
            ])),
        ] {
            let t = token_with(SUB, &publisher_claims(patreon.clone()));
            let r = put(&h, SUB, &t, bundle()).await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (
                    StatusCode::FORBIDDEN,
                    "catalog campaign is not the publisher's"
                ),
                "{patreon:?}"
            );
        }
        assert!(h.store.campaign_creators.lock().await.is_empty());

        // The creator publishes, and is recorded as the campaign's.
        let r = put(&h, SUB, &token(SUB), bundle()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            h.store
                .campaign_creators
                .lock()
                .await
                .get("12345678")
                .map(String::as_str),
            Some(SUB)
        );
    }

    #[tokio::test]
    async fn the_index_is_checked() {
        let h = ingested().await;
        let r = publish_index(&h, 1, &envelope(1), json!({ "entries": [] })).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid index: must be an array of at most 1000 entries"
            )
        );
        let mut v1 = entry("rec-1", &payload(1), &meta(1));
        v1["title"] = json!("Studio session");
        let r = publish_index(&h, 1, &envelope(1), json!([v1])).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            r.error().starts_with("invalid index: entries[0]."),
            "{}",
            r.error()
        );

        let r = publish_index(
            &h,
            1,
            &envelope(1),
            json!([entry("rec-2", &payload(2), &meta(2))]),
        )
        .await;
        assert_eq!(
            (r.status, r.error()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} is not ingested", payload(2))
            )
        );

        // Every recording carries the envelope's attribute.
        let other = "https://patreon.arkavo.com/attr/campaign/value/99";
        let document = envelope_tdf(envelope_policy(other), CATALOG_MIME_TYPE, b"x");
        let creator_of_99 =
            token_with(SUB, &publisher_claims(Some(patreon("creator", Some("99")))));
        let r = put(
            &h,
            SUB,
            &creator_of_99,
            body(&document, &v2::bundle(SUB, 1, &document)),
        )
        .await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "entry rec-1 policy does not include the catalog attribute"
            )
        );

        // An empty catalog publishes.
        let r = publish_index(&h, 1, &envelope(1), json!([])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert!(h.store.catalog_pointers.lock().await.contains_key(SUB));
    }

    #[tokio::test]
    async fn a_document_over_16_kib_gets_a_real_outboard() {
        let h = ingested().await;
        let document = envelope_tdf(envelope_policy(CAMPAIGN), CATALOG_MIME_TYPE, &[7; 20_000]);
        assert!(document.len() > 16 * 1024, "{}", document.len());
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let outboard = h.store.catalog_outboards.lock().await[&hash_of(&document)].clone();
        let want =
            bao_tree::BaoTree::new(document.len() as u64, iroh_blobs::store::IROH_BLOCK_SIZE)
                .outboard_size();
        assert_eq!(outboard.len() as u64, want);
        assert!(want > 0);
    }

    #[tokio::test]
    async fn seq_must_increase() {
        let h = ingested().await;
        assert_eq!(publish(&h, 2, &envelope(1)).await.status, StatusCode::OK);
        for seq in [2, 1] {
            let r = publish(&h, seq, &envelope(1)).await;
            assert_eq!(r.status, StatusCode::CONFLICT);
            assert_eq!(r.error(), "seq must be greater than 2");
        }
        assert_eq!(publish(&h, 3, &envelope(1)).await.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_pointer_is_tagged_with_its_seq() {
        let h = ingested().await;
        assert_eq!(publish(&h, 7, &envelope(1)).await.status, StatusCode::OK);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"7\"");
    }

    /// A refused precondition stores nothing: not the refused document, not
    /// its outboard or index, and no pointer beyond the `pointers` already
    /// there.
    async fn assert_precondition_failed(h: &Harness, r: Reply, document: &[u8], pointers: usize) {
        assert_eq!(r.status, StatusCode::PRECONDITION_FAILED, "{}", r.error());
        assert_eq!(r.error(), "catalog changed since it was read");
        let hash = hash_of(document);
        assert!(!h.store.catalog_documents.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_indexes.lock().await.contains_key(&hash));
        assert_eq!(h.store.catalog_pointers.lock().await.len(), pointers);
    }

    #[tokio::test]
    async fn if_match_names_the_base_the_publish_was_merged_from() {
        let h = ingested().await;
        assert_eq!(publish(&h, 6, &envelope(1)).await.status, StatusCode::OK);
        // Another device saves seq 7 from the same base.
        let theirs = envelope(2);
        let r = publish_if(&h, 7, &theirs, header::IF_MATCH, "\"6\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());

        // Ours, merged from seq 6 but signed with a higher seq: 412, not a
        // silent overwrite of seq 7, and not a 409 either.
        let ours = envelope(3);
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
        let r = publish_if(&h, 12, &envelope(1), header::IF_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        // A matching base still needs a greater seq.
        let r = publish_if(&h, 12, &envelope(1), header::IF_MATCH, "\"12\"").await;
        assert_eq!(r.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn if_match_needs_a_stored_pointer() {
        let h = ingested().await;
        for tag in ["\"1\"", "*"] {
            let r = publish_if(&h, 1, &envelope(1), header::IF_MATCH, tag).await;
            assert_precondition_failed(&h, r, &envelope(1), 0).await;
        }
    }

    #[tokio::test]
    async fn if_none_match_star_publishes_only_the_first_pointer() {
        let h = ingested().await;
        let r = publish_if(&h, 1, &envelope(1), header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let other = envelope(2);
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "*").await;
        assert_precondition_failed(&h, r, &other, 1).await;
        // The tag itself (or its weak form) also fails; another tag passes.
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "W/\"1\"").await;
        assert_precondition_failed(&h, r, &other, 1).await;
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "\"9\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn a_blocked_catalog_reads_as_none_to_preconditions() {
        let h = ingested().await;
        let blocked = envelope(1);
        assert_eq!(publish(&h, 3, &blocked).await.status, StatusCode::OK);
        h.moderation.block_for_test(&hash_of(&blocked));
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);

        // The 404 path: `If-None-Match: *` passes; `If-Match` on the hidden
        // pointer fails. The seq must still exceed the stored one.
        let fresh = envelope(2);
        let r = publish_if(&h, 4, &fresh, header::IF_MATCH, "\"3\"").await;
        assert_precondition_failed(&h, r, &fresh, 1).await;
        let r = publish_if(&h, 3, &fresh, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.error());
        let r = publish_if(&h, 4, &fresh, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"4\"");
    }

    #[tokio::test]
    async fn both_preconditions_must_hold() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let other = envelope(2);
        let put = |none_match: &'static str| {
            let body = body(&other, &v2::bundle(SUB, 2, &other));
            let both = [
                (header::IF_MATCH, "\"1\""),
                (header::IF_NONE_MATCH, none_match),
            ];
            let h = &h;
            async move { put_with(h, SUB, &token(SUB), body, &both).await }
        };
        assert_precondition_failed(&h, put("*").await, &other, 1).await;
        let r = put("\"9\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn a_precondition_that_is_not_ascii_fails() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let other = envelope(2);
        for name in [header::IF_MATCH, header::IF_NONE_MATCH] {
            let req = Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2/catalogs/{SUB}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token(SUB)))
                .header(name, header::HeaderValue::from_bytes(b"\"1\xff\"").unwrap())
                .body(Body::from(body(&other, &v2::bundle(SUB, 2, &other))))
                .unwrap();
            let r = send(&h.app, req).await;
            assert_precondition_failed(&h, r, &other, 1).await;
        }
    }

    #[tokio::test]
    async fn a_publish_that_loses_the_race_is_a_conflict() {
        let h = ingested().await;
        h.store
            .lose_next_pointer_race
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        assert!(r.error().contains("another publish won"));
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    #[tokio::test]
    async fn only_the_subject_publishes_its_catalog() {
        let h = ingested().await;
        let document = envelope(1);
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
        let r = put(
            &h,
            SUB,
            &token(SUB),
            body(&envelope(1), &v2::bundle(SUB, 1, &envelope(2))),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("catalogHash"), "{}", r.error());
    }

    #[tokio::test]
    async fn a_tampered_bundle_is_refused() {
        let h = ingested().await;
        let document = envelope(1);
        let mut bundle = v2::bundle(SUB, 1, &document);
        // Re-point a validly signed bundle at seq 9: the passkey signed seq 1.
        let pointer = v2::pointer_bytes(SUB, 9, &document);
        bundle.pointer = URL_SAFE_NO_PAD.encode(pointer);
        let r = put(&h, SUB, &token(SUB), body(&document, &bundle)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().starts_with("invalid bundle: "), "{}", r.error());
    }

    #[tokio::test]
    async fn a_revoked_or_unknown_credential_is_refused() {
        let h = ingested().await;
        *h.status.0.lock().unwrap() = Err(StatusRefusal::Refused("passkey credential revoked"));
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(r.error(), "passkey credential revoked");

        *h.status.0.lock().unwrap() = Err(StatusRefusal::Unavailable);
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY);
        assert_eq!(r.error(), "credential status unavailable");
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    #[tokio::test]
    async fn blocked_catalogs_are_neither_published_nor_served() {
        let h = ingested().await;
        let document = envelope(1);
        let hash = hash_of(&document);
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
    async fn a_hidden_or_blocked_creator_has_no_catalog() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        h.moderation.suspend_for_test(SUB, true);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);

        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        h.moderation.block_catalog_for_test(SUB);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
        assert!(h.decider.asked.lock().unwrap().is_empty());
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
    async fn malformed_requests_are_refused() {
        let h = ingested().await;
        let document = envelope(1);
        let bundle = v2::bundle(SUB, 1, &document);
        let mut b: serde_json::Value = serde_json::from_slice(&body(&document, &bundle)).unwrap();
        b["document"] = serde_json::Value::String(
            base64::engine::general_purpose::URL_SAFE.encode(&document[..10]) + "=",
        );
        let r = put(&h, SUB, &token(SUB), serde_json::to_vec(&b).unwrap()).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("unpadded base64url"), "{}", r.error());
        b["extra"] = json!(1);
        let r = put(&h, SUB, &token(SUB), serde_json::to_vec(&b).unwrap()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);

        // A repeated key, here inside the index, is refused before parsing.
        let good = String::from_utf8(body(&document, &bundle)).unwrap();
        let repeated = good.replacen("\"version\":1", "\"version\":1,\"version\":2", 1);
        assert_ne!(good, repeated);
        let r = put(&h, SUB, &token(SUB), repeated.into_bytes()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(
            r.error().contains("duplicate key `version`"),
            "{}",
            r.error()
        );

        // No index: 400.
        let mut b: serde_json::Value = serde_json::from_slice(&body(&document, &bundle)).unwrap();
        b.as_object_mut().unwrap().remove("index");
        let r = put(&h, SUB, &token(SUB), serde_json::to_vec(&b).unwrap()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }
}
