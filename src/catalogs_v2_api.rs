//! Catalog v2 routes (tdf-iroh-s3#27, #39, `docs/creator-catalogs.md`).
//!
//! - `PUT /v2/catalogs/{sub}` — publish: the catalog document, the
//!   creator's passkey-signed pointer bundle and the catalog's clear index.
//!   The pointer is `arkavo.catalog-pointer/2`, whose `indexHash` is the
//!   SHA-256 of the canonical index sent with it, so the passkey signs the
//!   index too. The document is a ZTDF envelope whose payload is the
//!   `arkavo.creator-catalog/2` document, under one attribute
//!   (`catalog_metadata::check_envelope`); the node never decrypts it and
//!   checks the recordings it lists through the index, which it stores
//!   once per envelope at `catalog-indexes/<hash>` (`If-None-Match: *`;
//!   another index for the same envelope is a 409, and nothing is written)
//!   and never serves. Once the checks pass, a publish writes in five
//!   steps: the index record; its transition (`deletion::Transition`, never
//!   served: what it dropped from the served base catalog and what it
//!   added); the document under `catalog-documents/<blake3>`; its BAO
//!   outboard, so it is served over iroh; then the bundle, which replaces
//!   `catalog-pointers/<sub>` only when its `seq` is greater than the
//!   stored one's, and only when the stored pointer is still the base the
//!   request names (tdf-iroh-s3#29; 412 otherwise), with exactly one of
//!   `If-Match: "<seq>"` or `If-None-Match: *` (428 for anything else, or
//!   neither).
//! - `GET /v2/catalogs/{sub}` — a token, then the catalog decision: whether
//!   the reader may open the envelope's attribute (403 otherwise). The
//!   stored bundle, with `ETag: "<seq>"`, which readers verify themselves
//!   before fetching the document over iroh by hash.
//!
//! Publishing takes the publishing token checks (`authorize_publisher`).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use iroh_blobs::Hash;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::authz::{DecisionProvider, DecisionRequest, ResourceType, SharedDecisionProvider};
use crate::catalog_metadata::{self, CAMPAIGN_FQN_PREFIX, EnvelopeRefusal};
use crate::catalog_v2::{self, Bundle, BundleError, POINTER_SCHEMA, Passkeys};
use crate::catalogs_api::{check_payloads, is_json, owner_hidden, owner_subjects};
use crate::creator_catalog::{
    self, CreatorCatalogEntry, MAX_CATALOG_BYTES, MAX_OWNER_BYTES, NoDuplicateKeys,
    valid_identifier,
};
use crate::deletion::{Transition, TransitionBase, transition_name};
use crate::moderation::{bearer, canonical_subject, now_secs};
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

/// Largest publish body: a 4 MiB envelope (its entries' metadata TDFs
/// inline) in base64url, about 5.6 MiB, an index of 1000 entries (up to
/// about 400 KiB with the longest contentIDs) and a bundle of a few KiB,
/// with room to spare.
pub const MAX_PUT_BYTES: usize = 10 * 1024 * 1024;

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
/// catalog: the `[catalog.authz]` decision service.
pub struct Readers {
    /// `None` (no decision service configured): every person is refused
    /// with 502 `decision unavailable`.
    pub provider: Option<SharedDecisionProvider>,
    pub action: String,
    /// Environment claims this node asserts, appended to the chain.
    pub environment: Option<serde_json::Value>,
}

/// A catalog's index record (`catalog-indexes/<hash>`): what the node
/// checked at publish. Moderation reads it to find an entry's hashes, and
/// so do the offline commands (`catalog_scan`).
#[derive(serde::Serialize, Deserialize)]
pub(crate) struct IndexRecord {
    /// The publisher's `sub`, byte for byte.
    pub owner: String,
    pub attribute: String,
    /// The index as received (`creator_catalog::parse_index` reads it).
    pub entries: serde_json::Value,
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

/// What a stored bundle's pointer says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredPointerInfo {
    pub seq: u64,
    pub catalog_hash: String,
    /// The pointer's `indexHash`: `Some` for `/2`, `None` for `/1`.
    pub index_hash: Option<String>,
    /// Lowercase hex SHA-256 of the signed pointer bytes.
    pub digest: String,
}

/// Read a stored bundle's pointer. The node wrote it after verifying it,
/// so failing to read it back is a storage fault.
pub(crate) fn stored_pointer(body: &[u8]) -> anyhow::Result<StoredPointerInfo> {
    let bundle: Bundle = serde_json::from_slice(body)?;
    let bytes = URL_SAFE_NO_PAD.decode(&bundle.pointer)?;
    let pointer = catalog_v2::parse_pointer(&bytes).map_err(anyhow::Error::msg)?;
    Ok(StoredPointerInfo {
        seq: pointer.seq,
        catalog_hash: pointer.catalog_hash,
        index_hash: pointer.index_hash,
        digest: pointer_digest(&bytes),
    })
}

/// Lowercase hex SHA-256 of signed pointer bytes: what names a pointer's
/// transition (`deletion::transition_name`).
fn pointer_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A stored pointer's entity tag: its `seq`, quoted. A stored seq only
/// increases, so it is a strong validator.
fn pointer_etag(seq: u64) -> String {
    format!("\"{seq}\"")
}

/// Whether `GET /v2/catalogs/{sub}` hides `sub`'s stored pointer at
/// `catalog_hash` from every reader: its owner is hidden (an active catalog
/// block, or a suspension with `hideCatalog`), or its catalog is blocked.
/// `GET` serves no pointer at a catalog without an index record either
/// (from before envelopes). `PUT`'s preconditions see what `GET` serves, so
/// both decide with this.
fn pointer_hidden<S: TagStore>(api: &ApiState<S>, sub: &str, catalog_hash: &str) -> bool {
    owner_hidden(api, Some(sub)) || is_blocked(api, catalog_hash)
}

/// The base a publish names, in one of the two forms Creator sends
/// (`docs/creator-catalogs.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precondition<'a> {
    /// `If-Match: "<seq>"`: merged from the pointer `GET` served with this
    /// `ETag`.
    IfMatch(&'a str),
    /// `If-None-Match: *`: merged from no catalog (`GET` answered 404).
    IfNoneMatchAny,
}

impl<'a> Precondition<'a> {
    /// Exactly one of `If-Match: "<seq>"` (one strong entity tag of ASCII
    /// decimal digits) or `If-None-Match: *`, each one header line with
    /// that one value. `None`, a 428, for anything else: neither header or
    /// both, `If-Match: *`, a list, a weak, unquoted, empty or non-digit
    /// tag, any other `If-None-Match`, a repeated line, or a value that is
    /// not visible ASCII.
    fn read(headers: &'a HeaderMap) -> Option<Self> {
        let if_match: Vec<&HeaderValue> = headers.get_all(header::IF_MATCH).iter().collect();
        let if_none_match: Vec<&HeaderValue> =
            headers.get_all(header::IF_NONE_MATCH).iter().collect();
        match (if_match.as_slice(), if_none_match.as_slice()) {
            ([tag], []) => tag
                .to_str()
                .ok()
                .filter(|tag| is_seq_tag(tag))
                .map(Self::IfMatch),
            ([], [any]) if any.as_bytes() == b"*" => Some(Self::IfNoneMatchAny),
            _ => None,
        }
    }

    /// Whether the base is still what `GET` serves: `served` is the served
    /// pointer's tag, `None` when it serves none.
    fn holds(self, served: Option<&str>) -> bool {
        match self {
            Self::IfMatch(tag) => served == Some(tag),
            Self::IfNoneMatchAny => served.is_none(),
        }
    }
}

/// `"<digits>"`: a strong entity tag whose content is one or more ASCII
/// decimal digits, the form [`pointer_etag`] writes.
fn is_seq_tag(tag: &str) -> bool {
    tag.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
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
    // A publish carries `/2`, whose `indexHash` binds the index to the
    // passkey. Stored `/1` pointers are still read and served.
    if pointer.schema != POINTER_SCHEMA {
        return Err(reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid bundle: pointer schema must be \"{POINTER_SCHEMA}\""),
        ));
    }
    // Names this publish's transition. `verify_bundle` decoded the same
    // field, so this can't fail.
    let digest = URL_SAFE_NO_PAD
        .decode(&req.bundle.pointer)
        .map(|bytes| pointer_digest(&bytes))
        .map_err(|_| {
            reject(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid bundle: pointer is not unpadded base64url".into(),
            )
        })?;

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

    // 5. The index: the recordings the envelope lists, which the node can't
    //    read. It must be the index the passkey signed (`indexHash`, over
    //    its canonical form), checked before anything is looked up. Nothing
    //    blocked, every payload ingested at its size, owned by the
    //    publisher (gated only), with a stored manifest, each recording
    //    carrying the envelope's attribute. The metadata TDFs inside the
    //    envelope are Creator's to check.
    let index = req.index.clone();
    let entries = creator_catalog::parse_index(req.index).map_err(|why| {
        reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid index: {why}"),
        )
    })?;
    let index_hash = creator_catalog::index_hash(&entries);
    if pointer.index_hash.as_deref() != Some(index_hash.as_str()) {
        return Err(reject(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid bundle: indexHash does not match the index".into(),
        ));
    }
    if is_blocked(api, &hash) {
        return Err(reject(StatusCode::FORBIDDEN, "content is blocked".into()));
    }
    check_payloads(api, &entries, &attribute, &claims.sub)
        .await
        .map_err(|refusal| {
            warn!(%sub, status = %refusal.status, reason = %refusal.error, "Catalog v2 publish rejected");
            refusal.into_response_parts()
        })?;

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

    // 7. Merged from the stored pointer the request names as its base, in
    //    one of the two forms (428 otherwise, before the stored pointer is
    //    read), and newer than it.
    let Some(precondition) = Precondition::read(&headers) else {
        return Err(reject(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition required".into(),
        ));
    };
    let current = api
        .store
        .get_catalog_pointer(&sub)
        .await
        .map_err(|e| storage_unavailable("Catalog pointer read", e))?;
    let current = current
        .map(|stored| stored_pointer(&stored.body).map(|parsed| (stored, parsed)))
        .transpose()
        .map_err(|e| storage_unavailable("Catalog pointer parse", e))?;
    // A pointer at a catalog with no index record names a document from
    // before envelopes, which `GET` never serves: it reads as none, so the
    // first envelope may start at any seq. The conditional write below
    // still replaces exactly that pointer. The base's recordings decide
    // what this publish drops and adds (its transition, step 8).
    let base_hashes = match &current {
        Some((_, info)) => base_hashes(api, info).await?,
        None => None,
    };
    let live = base_hashes.is_some();
    let current_seq = current.as_ref().filter(|_| live).map(|(_, info)| info.seq);
    // Preconditions see what `GET` serves: a pointer it hides (a hidden
    // owner, a blocked catalog) reads as none, so a client that got the 404
    // can publish with `If-None-Match: *`. The seq above is still the
    // stored one's.
    let served_seq = current
        .as_ref()
        .filter(|(_, info)| live && !pointer_hidden(api, &sub, &info.catalog_hash))
        .map(|(_, info)| info.seq);
    if !precondition.holds(served_seq.map(pointer_etag).as_deref()) {
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

    // 8. Five writes, in this order: the index record, the transition, the
    //    document, its outboard, then the pointer. Everything that can
    //    refuse comes first: the 412 and 409 above (so a retry of a publish
    //    that committed can't rewrite its transition), the owner reads the
    //    transition needs (an unreadable one is a 502 with nothing written),
    //    then the index record's create. That record is created once: one
    //    envelope has one index, so a publish that lost can't rewrite the
    //    committed pointer's index, nor the envelope's owner metadata, and
    //    its 409 or 502 writes nothing else, no transition either. The
    //    transition is created only if none is under its key; one there is
    //    replaced only while the stored pointer is still the one this
    //    publish read (`write_transition`), so a stalled copy over another
    //    base can't rewrite a transition another copy committed. (Two
    //    copies over the same base can leave the last writer's `at` and
    //    `dropped`; the base is the same.) `write_transition`'s refusals (a
    //    moved pointer, a lost replace, an unreadable transition) come after
    //    the index create, which is harmless: each needs a transition
    //    already under this key, so these pointer bytes were sent before,
    //    and the pointer signs the envelope's hash and its `indexHash`, so
    //    that attempt created or found this same record and this create was
    //    a retry that wrote nothing. A failed transition write is a storage
    //    error like any later write's. The document and its
    //    outboard come before the pointer, so a stored
    //    pointer never names a document that cannot be served or decided;
    //    the pointer is written only if nobody else moved it meanwhile.
    //    What a publish wrote before a later write failed, or before its
    //    pointer write lost, is not named by its pointer: the sweep never
    //    folds such a transition, and the same publish sent again after a
    //    failed write completes it (after a lost pointer write, it gets the
    //    412).
    let outboard = crate::ingest::compute_outboard(
        &document[..],
        document.len() as u64,
        Hash::from_bytes(*blake3::hash(&document).as_bytes()),
    )
    .map_err(|e| storage_unavailable("Catalog outboard", e))?;
    // Dropped only from a base `GET` served: `served_seq`, which the
    // shared `pointer_hidden` decided (its catalog not blocked, its owner
    // not hidden).
    let served = served_seq.is_some();
    let new_hashes: BTreeSet<String> = entries.iter().map(|e| e.payload_hash.clone()).collect();
    let transition = Transition {
        subject: sub.clone(),
        seq: pointer.seq,
        catalog_hash: hash.clone(),
        pointer: digest,
        base: current.as_ref().map(|(_, info)| TransitionBase {
            seq: info.seq,
            catalog_hash: info.catalog_hash.clone(),
            pointer: info.digest.clone(),
        }),
        at: now_secs(),
        dropped: dropped(
            api,
            &sub,
            base_hashes.as_ref().filter(|_| served),
            &new_hashes,
        )
        .await?,
        added: new_hashes
            .iter()
            .filter(|h| !base_hashes.as_ref().is_some_and(|base| base.contains(*h)))
            .cloned()
            .collect(),
    };
    let size = document.len();
    let record = IndexRecord {
        owner: sub.clone(),
        attribute: attribute.clone(),
        entries: index,
    };
    let entries = entries.len();
    let created = api
        .store
        .create_catalog_index(
            &hash,
            Bytes::from(serde_json::to_vec(&record).expect("record serializes")),
        )
        .await
        .map_err(|e| storage_unavailable("Catalog index write", e))?;
    if !created {
        // The envelope already has a record: a retry of this publish goes
        // on, another index is a 409, and none there to read (deleted since
        // the create lost) is a 502. A create still answered 409 after its
        // retries (`send_conditional`) was an `Err`: a 502 above.
        let existing = api
            .store
            .get_catalog_index(&hash)
            .await
            .map_err(|e| storage_unavailable("Catalog index read", e))?
            .ok_or_else(|| {
                storage_unavailable(
                    "Catalog index read",
                    anyhow::anyhow!("index record {hash} exists but can't be read"),
                )
            })?;
        let retry = is_retry(&existing, &sub, &index_hash)
            .map_err(|e| storage_unavailable("Catalog index parse", e))?;
        if !retry {
            return Err(reject(
                StatusCode::CONFLICT,
                "catalog document already published with another index".into(),
            ));
        }
    }
    write_transition(api, &sub, &transition, expected).await?;
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
    info!(%sub, seq = pointer.seq, %hash, size, entries, %attribute, "Catalog v2 published");
    Ok(Json(serde_json::json!({
        "owner": sub,
        "seq": pointer.seq,
        "hash": hash,
        "size": size,
    })))
}

/// Store this publish's `transition` under its key
/// (`catalog-transitions/<sub>/<seq>-<pointer digest>`), only if none is
/// there. The key names one signed pointer, so one already there came from
/// the same pointer bytes, sent before: a retry, a duplicate, or an
/// attempt over a base that has moved since. Which base it names doesn't
/// say whether to keep it (seqs don't order bases across a pointer from
/// before envelopes); the stored pointer does:
/// - still `expected`, the ETag this publish's pointer write is
///   conditioned on (`None`: no pointer): replace it with this publish's
///   transition (its base, a fresh `at`, its `dropped`), only if it is
///   still what was read (`If-Match`). This publish's pointer commits only
///   if the stored one is still `expected` then too, so when it commits,
///   the transition under its key names its base.
/// - moved (perhaps to this very pointer, through a duplicate that
///   committed): keep it, and answer as a lost write. This publish's
///   pointer write would lose anyway.
///
/// The transition is read before the pointer, so a transition another
/// copy of this publish writes after the pointer check makes the replace
/// lose. One that can't be read, the pointer unreadable, a moved pointer
/// or a replace that loses is 502 `storage unavailable`.
async fn write_transition<S: TagStore>(
    api: &ApiState<S>,
    sub: &str,
    transition: &Transition,
    expected: Option<&str>,
) -> Result<(), ApiError> {
    let name = transition_name(transition.seq, &transition.pointer);
    let body = Bytes::from(serde_json::to_vec(transition).expect("transition serializes"));
    let write = |e| storage_unavailable("Catalog transition write", e);
    if api
        .store
        .put_catalog_transition(sub, &name, body.clone(), None)
        .await
        .map_err(write)?
    {
        return Ok(());
    }
    let read = |e| storage_unavailable("Catalog transition read", e);
    let stored = api
        .store
        .get_catalog_transition(sub, &name)
        .await
        .map_err(read)?
        .ok_or_else(|| {
            read(anyhow::anyhow!(
                "transition {sub}/{name} exists but can't be read"
            ))
        })?;
    let pointer = api
        .store
        .get_catalog_pointer(sub)
        .await
        .map_err(|e| storage_unavailable("Catalog pointer read", e))?;
    if pointer.as_ref().map(|p| p.etag.as_str()) != expected {
        return Err(write(anyhow::anyhow!(
            "transition {sub}/{name} kept: the pointer moved since this publish read it"
        )));
    }
    let replaced = api
        .store
        .put_catalog_transition(sub, &name, body, Some(&stored.etag))
        .await
        .map_err(write)?;
    if !replaced {
        return Err(write(anyhow::anyhow!(
            "transition {sub}/{name} was replaced since it was read"
        )));
    }
    Ok(())
}

/// Whether a stored index record is a retry of this publish: `sub`'s
/// (subjects compared canonically), and its entries' canonical hash is
/// `index_hash`. `Err` when the record doesn't parse: the node wrote it, so
/// that is a storage fault.
fn is_retry(record: &[u8], sub: &str, index_hash: &str) -> anyhow::Result<bool> {
    let (owner, entries) = read_index_record(record)?;
    Ok(canonical_subject(&owner) == canonical_subject(sub)
        && creator_catalog::index_hash(&entries) == index_hash)
}

/// A stored index record's owner and parsed entries.
fn read_index_record(record: &[u8]) -> anyhow::Result<(String, Vec<CreatorCatalogEntry>)> {
    let record: IndexRecord = serde_json::from_slice(record)?;
    let entries = creator_catalog::parse_index(record.entries)
        .map_err(|why| anyhow::anyhow!("invalid index: {why}"))?;
    Ok((record.owner, entries))
}

/// The recordings of the stored pointer `base`, from its index record;
/// `None` when it has none (a pointer from before envelopes). The node
/// wrote the record, so one that doesn't parse, or whose canonical hash
/// isn't a `/2` base's `indexHash`, is a storage fault: 502, and the
/// publish writes nothing.
async fn base_hashes<S: TagStore>(
    api: &ApiState<S>,
    base: &StoredPointerInfo,
) -> Result<Option<BTreeSet<String>>, ApiError> {
    let Some(record) = api
        .store
        .get_catalog_index(&base.catalog_hash)
        .await
        .map_err(|e| storage_unavailable("Catalog index read", e))?
    else {
        return Ok(None);
    };
    let (_, entries) =
        read_index_record(&record).map_err(|e| storage_unavailable("Catalog index parse", e))?;
    if let Some(signed) = &base.index_hash
        && creator_catalog::index_hash(&entries) != *signed
    {
        error!(
            catalog = %base.catalog_hash,
            seq = base.seq,
            "Stored catalog index does not match its pointer's indexHash"
        );
        return Err(fail(StatusCode::BAD_GATEWAY, "storage unavailable"));
    }
    Ok(Some(entries.into_iter().map(|e| e.payload_hash).collect()))
}

/// What a publish drops (spec 3.1): the recordings of the `served` base
/// (`None` when the base isn't served) that `new` doesn't list, less those
/// blocked now and those whose owner record doesn't name `sub` (subjects
/// compared canonically; no record is not `sub`'s). Sorted. An owner record
/// that can't be read is 502 `storage unavailable`.
async fn dropped<S: TagStore>(
    api: &ApiState<S>,
    sub: &str,
    served: Option<&BTreeSet<String>>,
    new: &BTreeSet<String>,
) -> Result<Vec<String>, ApiError> {
    let Some(base) = served else {
        return Ok(Vec::new());
    };
    let gone: Vec<String> = base
        .difference(new)
        .filter(|h| !is_blocked(api, h))
        .cloned()
        .collect();
    let owners = owner_subjects(api, gone.clone())
        .await
        .map_err(|(status, msg)| fail(status, msg))?;
    let publisher = canonical_subject(sub);
    Ok(gone
        .into_iter()
        .filter(|h| {
            owners
                .get(h)
                .and_then(Option::as_deref)
                .is_some_and(|owner| canonical_subject(owner) == publisher)
        })
        .collect())
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
    let stored = match api.store.get_catalog_pointer(&sub).await {
        Ok(Some(stored)) => stored,
        Ok(None) => return Err(not_found()),
        Err(e) => return Err(storage_unavailable("Catalog pointer read", e)),
    };
    let StoredPointerInfo {
        seq, catalog_hash, ..
    } = stored_pointer(&stored.body)
        .map_err(|e| storage_unavailable("Catalog pointer parse", e))?;
    if pointer_hidden(api, &sub, &catalog_hash) {
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
        CAMPAIGN, KAS, envelope_policy, envelope_tdf, manifest, recording_policy,
    };
    use crate::catalog_v2::test_support as v2;
    use crate::creator_catalog::test_support::{PAYLOAD_SIZE, entry};
    use crate::deletion::{Transition, TransitionBase, transition_name};
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

    /// Something to run once when the IdP is asked (step 6): a moderation
    /// change that lands after the token checks.
    type OnCheck = Box<dyn FnOnce() + Send>;

    /// The IdP's credential status: `answer`, asked only about `subject`.
    struct StubStatus {
        answer: Mutex<Result<(), StatusRefusal>>,
        /// The subject the test's token and path name: `SUB`, unless a test
        /// publishes as another account.
        subject: Mutex<&'static str>,
        on_check: Mutex<Option<OnCheck>>,
    }

    impl CredentialStatus for StubStatus {
        fn check<'a>(
            &'a self,
            credential_id: &'a [u8],
            sub: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), StatusRefusal>> + Send + 'a>> {
            assert_eq!(credential_id, v2::CREDENTIAL_ID);
            assert_eq!(sub, *self.subject.lock().unwrap(), "the path's subject");
            if let Some(on_check) = self.on_check.lock().unwrap().take() {
                on_check();
            }
            let answer = self.answer.lock().unwrap().clone();
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
        build(decisions, true)
    }

    /// As [`harness`], on an ungated node (`publishing: None`, development
    /// only): tokens are verified, nothing else.
    fn harness_ungated() -> Harness {
        build(true, false)
    }

    fn build(decisions: bool, gated: bool) -> Harness {
        let (_, token_vk) = keypair();
        let store = Arc::new(MemStore::new());
        let moderation = Arc::new(Moderation::default());
        let api = Arc::new(ApiState {
            store: Arc::clone(&store),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![
                (b"kid-1".to_vec(), token_vk),
                (v2::IDP_KID.to_vec(), *v2::idp_key().verifying_key()),
            ])),
            publishing: gated.then(|| TagPublishing {
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
        let status = Arc::new(StubStatus {
            answer: Mutex::new(Ok(())),
            subject: Mutex::new(SUB),
            on_check: Mutex::new(None),
        });
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

    /// An operator's service CWT, as the moderation API admits one:
    /// allowlisted client, `aud` naming it, role service-account.
    fn operator_token() -> String {
        let roles = Value::Array(vec![Value::Text("service-account".into())]);
        token_for(
            "client:moderation",
            "moderation",
            &[("arkavo_roles", roles)],
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

    /// A campaign envelope; `n` varies the bytes (and so the hash).
    fn envelope(n: u8) -> Vec<u8> {
        envelope_tdf(envelope_policy(CAMPAIGN), CATALOG_MIME_TYPE, &[n; 64])
    }

    /// The index naming payload(1).
    fn index() -> serde_json::Value {
        json!([entry("rec-1", &payload(1))])
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

    /// The `indexHash` of `index`. An index that doesn't parse is refused
    /// before its hash is compared, so it gets any well-formed hash.
    fn hash_of_index(index: &serde_json::Value) -> String {
        creator_catalog::parse_index(index.clone())
            .map(|entries| creator_catalog::index_hash(&entries))
            .unwrap_or_else(|_| "0".repeat(64))
    }

    /// `SUB`'s `/2` bundle for `document` at `seq`, signed over `index`.
    fn signed(seq: u64, document: &[u8], index: &serde_json::Value) -> Bundle {
        v2::bundle(SUB, seq, document, Some(&hash_of_index(index)))
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

    /// The precondition a client sends after reading `sub`'s catalog with
    /// `GET`: `If-Match` with its `ETag`, or `If-None-Match: *` after a 404.
    /// It reads with an operator token. On a gated harness that skips the
    /// reader decision; `harness_ungated` admits no operator, so the stub
    /// decider is asked (and counts the read in `asked`), and it permits
    /// unless the test changed its answer.
    async fn read_precondition(h: &Harness, sub: &str) -> (header::HeaderName, String) {
        let r = get_as(h, sub, Some(&operator_token())).await;
        match r.status {
            StatusCode::OK => (
                header::IF_MATCH,
                r.headers[header::ETAG].to_str().unwrap().into(),
            ),
            StatusCode::NOT_FOUND => (header::IF_NONE_MATCH, "*".into()),
            other => panic!("GET /v2/catalogs/{sub}: {other} {}", r.error()),
        }
    }

    /// A publish with the precondition of [`read_precondition`].
    async fn put(h: &Harness, sub: &str, bearer: &str, body: Vec<u8>) -> Reply {
        let (name, value) = read_precondition(h, sub).await;
        put_with(h, sub, bearer, body, &[(name, &value)]).await
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

    /// Publishes `seq` with exactly one precondition header.
    async fn publish_if(
        h: &Harness,
        seq: u64,
        document: &[u8],
        name: header::HeaderName,
        value: &str,
    ) -> Reply {
        let body = body(document, &signed(seq, document, &index()));
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
        let body = body_with(document, &signed(seq, document, &index), index);
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

    /// payload(n), a campaign recording, with its stored manifest, owned by
    /// the publisher (`SUB`).
    async fn ingest(h: &Harness, n: u8) {
        h.store
            .ingest_with_manifest(
                &payload(n),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        h.store.own(&payload(n), SUB).await;
    }

    async fn ingested() -> Harness {
        let h = harness();
        ingest(&h, 1).await;
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
        let bundle = signed(1, &document, &index());

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
            // The reader's entitlements travel with the decision (#51).
            assert_eq!(
                req.chain[0].claims["arkavo_entitlements"],
                json!([DEFAULT_PUBLISH_ENTITLEMENT])
            );
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
        ingest(&h, 1).await;
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
        let operator = operator_token();
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
        let bundle = serde_json::to_vec(&v2::bundle(SUB, 12, &old, None)).unwrap();
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
            .ingest_with_manifest(&payload(1), PAYLOAD_SIZE, manifest(policy, &[KAS]))
            .await;
        h.store.own(&payload(1), SUB).await;
        let document = envelope_tdf(envelope_policy(&creator), CATALOG_MIME_TYPE, b"x");
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(get(&h, SUB).await.status, StatusCode::OK);
        let asked = h.decider.asked.lock().unwrap();
        assert_eq!(asked[0].resources[0].1, vec![creator]);
    }

    #[tokio::test]
    async fn a_campaign_catalog_comes_from_the_campaign_creator() {
        let h = ingested().await;
        let document = envelope(1);
        let bundle = || body(&document, &signed(1, &document, &index()));
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
        assert!(h.store.catalog_pointers.lock().await.is_empty());

        // The campaign's creator publishes.
        let r = put(&h, SUB, &token(SUB), bundle()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
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
        let mut v1 = entry("rec-1", &payload(1));
        v1["title"] = json!("Studio session");
        let r = publish_index(&h, 1, &envelope(1), json!([v1])).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            r.error().starts_with("invalid index: entries[0]."),
            "{}",
            r.error()
        );

        let r = publish_index(&h, 1, &envelope(1), json!([entry("rec-2", &payload(2))])).await;
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
            body(&document, &signed(1, &document, &index())),
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
    async fn a_publish_refusal_carries_content_ids() {
        let h = harness();
        ingest(&h, 1).await;
        // MemStore's `own` replaces the record: payload(1) is READER's.
        h.store.own(&payload(1), READER).await;
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(
            r.json(),
            json!({ "error": "recording belongs to another account", "contentIDs": ["rec-1"] })
        );

        h.store.owners.lock().await.clear();
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            r.json(),
            json!({ "error": "recording has no owner: push it again", "contentIDs": ["rec-1"] })
        );

        // Any other refusal is `error` alone.
        let r = publish_index(&h, 1, &envelope(1), json!([entry("rec-2", &payload(2))])).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            r.json(),
            json!({ "error": format!("payload {} is not ingested", payload(2)) })
        );
        assert!(h.store.catalog_documents.lock().await.is_empty());
        assert!(h.store.catalog_pointers.lock().await.is_empty());
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
    async fn an_envelope_of_up_to_4_mib_publishes() {
        let h = ingested().await;
        // Metadata TDFs travel inside the envelope, so it may hold megabytes.
        let big = envelope_tdf(
            envelope_policy(CAMPAIGN),
            CATALOG_MIME_TYPE,
            &vec![7; MAX_CATALOG_BYTES - 4096],
        );
        assert!(big.len() > 2 * 1024 * 1024 && big.len() <= MAX_CATALOG_BYTES);
        let r = publish(&h, 1, &big).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());

        let over = envelope_tdf(
            envelope_policy(CAMPAIGN),
            CATALOG_MIME_TYPE,
            &vec![7; MAX_CATALOG_BYTES],
        );
        let r = publish(&h, 2, &over).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("1-4194304 bytes"), "{}", r.error());

        let r = put(&h, SUB, &token(SUB), vec![b' '; MAX_PUT_BYTES + 1]).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::PAYLOAD_TOO_LARGE, "request too large")
        );
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

    /// Nothing of a refused publish of `document` is stored: not the
    /// document, its outboard or its index record, and no pointer beyond the
    /// `pointers` already there.
    async fn assert_unstored(h: &Harness, document: &[u8], pointers: usize) {
        let hash = hash_of(document);
        assert!(!h.store.catalog_documents.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_indexes.lock().await.contains_key(&hash));
        assert_eq!(h.store.catalog_pointers.lock().await.len(), pointers);
    }

    /// A refused precondition: 412, and nothing of the publish stored.
    async fn assert_precondition_failed(h: &Harness, r: Reply, document: &[u8], pointers: usize) {
        assert_eq!(r.status, StatusCode::PRECONDITION_FAILED, "{}", r.error());
        assert_eq!(r.error(), "catalog changed since it was read");
        assert_unstored(h, document, pointers).await;
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
        // silent overwrite of seq 7, and not a 409 either. So is any tag
        // that is not exactly the served one.
        let ours = envelope(3);
        for (seq, tag) in [(11, "\"6\""), (7, "\"6\""), (11, "\"07\""), (11, "\"8\"")] {
            let r = publish_if(&h, seq, &ours, header::IF_MATCH, tag).await;
            assert_precondition_failed(&h, r, &ours, 1).await;
        }
        let served: Bundle = serde_json::from_slice(&get(&h, SUB).await.body).unwrap();
        assert_eq!(served, signed(7, &theirs, &index()));

        let r = publish_if(&h, 11, &ours, header::IF_MATCH, "\"7\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        // A matching base still needs a greater seq.
        let r = publish_if(&h, 11, &envelope(1), header::IF_MATCH, "\"11\"").await;
        assert_eq!(r.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn if_match_needs_a_stored_pointer() {
        let h = ingested().await;
        let r = publish_if(&h, 1, &envelope(1), header::IF_MATCH, "\"1\"").await;
        assert_precondition_failed(&h, r, &envelope(1), 0).await;
    }

    #[tokio::test]
    async fn if_none_match_star_publishes_only_the_first_pointer() {
        let h = ingested().await;
        let r = publish_if(&h, 1, &envelope(1), header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let other = envelope(2);
        let r = publish_if(&h, 2, &other, header::IF_NONE_MATCH, "*").await;
        assert_precondition_failed(&h, r, &other, 1).await;
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

    /// The stored pointer's seq, as the node stored it.
    async fn stored_seq(h: &Harness) -> u64 {
        stored_pointer(&h.store.catalog_pointers.lock().await[SUB].0)
            .unwrap()
            .seq
    }

    /// A creator whose catalog is blocked, unsuspended, still publishes:
    /// `GET` answers 404, so preconditions see no pointer, but the seq must
    /// still exceed the stored one.
    #[tokio::test]
    async fn a_catalog_blocked_creator_reads_as_none_to_preconditions() {
        let fresh = envelope(2);
        // Unblocked, the stored pointer is the base.
        let h = ingested().await;
        assert_eq!(publish(&h, 3, &envelope(1)).await.status, StatusCode::OK);
        let r = publish_if(&h, 4, &fresh, header::IF_NONE_MATCH, "*").await;
        assert_precondition_failed(&h, r, &fresh, 1).await;
        let r = publish_if(&h, 4, &fresh, header::IF_MATCH, "\"3\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(stored_seq(&h).await, 4);

        // Blocked: the 404 path.
        let h = ingested().await;
        assert_eq!(publish(&h, 3, &envelope(1)).await.status, StatusCode::OK);
        h.moderation.block_catalog_for_test(SUB);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
        let r = publish_if(&h, 4, &fresh, header::IF_MATCH, "\"3\"").await;
        assert_precondition_failed(&h, r, &fresh, 1).await;
        for seq in [2, 3] {
            let r = publish_if(&h, seq, &fresh, header::IF_NONE_MATCH, "*").await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::CONFLICT, "seq must be greater than 3")
            );
        }
        let r = publish_if(&h, 4, &fresh, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(stored_seq(&h).await, 4);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
    }

    /// Exactly one of `If-Match: "<seq>"` or `If-None-Match: *`, each one
    /// header line with that one value. Anything else is 428, before the
    /// stored pointer is read: here seq 1 over the stored seq 1 would
    /// otherwise be a 412 or a 409.
    #[tokio::test]
    async fn only_the_two_precondition_forms_are_accepted() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let other = envelope(2);
        let (m, n) = (header::IF_MATCH, header::IF_NONE_MATCH);
        let v = header::HeaderValue::from_static;
        let not_ascii = |bytes: &[u8]| header::HeaderValue::from_bytes(bytes).unwrap();
        let refused = [
            vec![],
            vec![(m.clone(), v("\"1\"")), (n.clone(), v("*"))],
            vec![(m.clone(), v("*"))],
            vec![(m.clone(), v("\"1\", \"2\""))],
            vec![(m.clone(), v("W/\"1\""))],
            vec![(m.clone(), v("1"))],
            vec![(m.clone(), v("\"1a\""))],
            vec![(m.clone(), v("\"\""))],
            vec![(n.clone(), v("W/\"1\""))],
            vec![(n.clone(), v("\"9\""))],
            vec![(n.clone(), v("*, \"9\""))],
            vec![(m.clone(), v("\"1\"")), (m.clone(), v("\"1\""))],
            vec![(n.clone(), v("*")), (n.clone(), v("*"))],
            vec![(m.clone(), not_ascii(b"\"1\xff\""))],
            vec![(n.clone(), not_ascii(b"*\xff"))],
        ];
        for headers in refused {
            let mut req = Request::builder()
                .method(Method::PUT)
                .uri(format!("/v2/catalogs/{SUB}"))
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token(SUB)));
            for (name, value) in &headers {
                req = req.header(name, value);
            }
            let body = Body::from(body(&other, &signed(1, &other, &index())));
            let r = send(&h.app, req.body(body).unwrap()).await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::PRECONDITION_REQUIRED, "precondition required"),
                "{headers:?}"
            );
            assert_unstored(&h, &other, 1).await;
        }
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");
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
            body(&document, &signed(1, &document, &index())),
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
            body(&envelope(1), &signed(1, &envelope(2), &index())),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().contains("catalogHash"), "{}", r.error());
    }

    #[tokio::test]
    async fn a_tampered_bundle_is_refused() {
        let h = ingested().await;
        let document = envelope(1);
        let mut bundle = signed(1, &document, &index());
        // Re-point a validly signed bundle at seq 9: the passkey signed seq 1.
        let pointer = v2::pointer_bytes(SUB, 9, &document, Some(&hash_of_index(&index())));
        bundle.pointer = URL_SAFE_NO_PAD.encode(pointer);
        let r = put(&h, SUB, &token(SUB), body(&document, &bundle)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.error().starts_with("invalid bundle: "), "{}", r.error());
    }

    #[tokio::test]
    async fn a_revoked_or_unknown_credential_is_refused() {
        let h = ingested().await;
        *h.status.answer.lock().unwrap() =
            Err(StatusRefusal::Refused("passkey credential revoked"));
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(r.error(), "passkey credential revoked");

        *h.status.answer.lock().unwrap() = Err(StatusRefusal::Unavailable);
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
        assert!(h.decider.asked.lock().unwrap().is_empty());

        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        h.moderation.block_catalog_for_test(SUB);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
        assert!(h.decider.asked.lock().unwrap().is_empty());
    }

    /// Nothing of a refused publish is stored: no transition, document,
    /// outboard, index record or pointer.
    async fn assert_nothing_stored(h: &Harness) {
        assert!(h.store.transitions.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());
        assert!(h.store.catalog_outboards.lock().await.is_empty());
        assert!(h.store.catalog_indexes.lock().await.is_empty());
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    /// An index record for `index` as `owner` published it.
    fn index_record(owner: &str, index: serde_json::Value) -> Bytes {
        let record = IndexRecord {
            owner: owner.into(),
            attribute: CAMPAIGN.into(),
            entries: index,
        };
        Bytes::from(serde_json::to_vec(&record).unwrap())
    }

    #[tokio::test]
    async fn a_1_publish_is_refused() {
        let h = ingested().await;
        let document = envelope(1);
        let r = put(
            &h,
            SUB,
            &token(SUB),
            body(&document, &v2::bundle(SUB, 1, &document, None)),
        )
        .await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                r#"invalid bundle: pointer schema must be "arkavo.catalog-pointer/2""#
            )
        );
        assert_nothing_stored(&h).await;
    }

    #[tokio::test]
    async fn the_index_must_match_its_hash() {
        let h = ingested().await;
        let document = envelope(1);
        let bundle = signed(1, &document, &index());
        // An empty index publishes on its own, and so does rec-1 at another
        // version; neither is the index the passkey signed.
        let mut bumped = entry("rec-1", &payload(1));
        bumped["version"] = json!(2);
        for sent in [json!([]), json!([bumped])] {
            let r = put(&h, SUB, &token(SUB), body_with(&document, &bundle, sent)).await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid bundle: indexHash does not match the index"
                )
            );
        }
        assert_nothing_stored(&h).await;
    }

    #[tokio::test]
    async fn the_index_hash_is_checked_before_the_payloads() {
        let h = ingested().await;
        let document = envelope(1);
        let unknown = json!([entry("rec-2", &payload(2))]);
        let mismatched = body_with(&document, &signed(1, &document, &index()), unknown.clone());
        let refused = (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid bundle: indexHash does not match the index",
        );
        let r = put(&h, SUB, &token(SUB), mismatched.clone()).await;
        assert_eq!((r.status, r.error().as_str()), refused);
        assert_eq!(h.store.blob_lookups.load(Ordering::Relaxed), 0);
        // Before the block check too.
        h.moderation.block_for_test(&hash_of(&document));
        let r = put(&h, SUB, &token(SUB), mismatched).await;
        assert_eq!((r.status, r.error().as_str()), refused);

        // Signed over the index it carries, the payloads are checked.
        let other = envelope(2);
        let r = put(
            &h,
            SUB,
            &token(SUB),
            body_with(&other, &signed(1, &other, &unknown), unknown.clone()),
        )
        .await;
        assert_eq!(
            (r.status, r.error()),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("payload {} is not ingested", payload(2))
            )
        );
    }

    #[tokio::test]
    async fn a_publish_needs_a_precondition() {
        let gated = ingested().await;
        // Ungated: no owner records, and the precondition still applies.
        let ungated = harness_ungated();
        ungated
            .store
            .ingest_with_manifest(
                &payload(1),
                PAYLOAD_SIZE,
                manifest(recording_policy(), &[KAS]),
            )
            .await;
        for h in [gated, ungated] {
            let document = envelope(1);
            let bare = |seq: u64| {
                let body = body(&document, &signed(seq, &document, &index()));
                let h = &h;
                async move { put_with(h, SUB, &token(SUB), body, &[]).await }
            };
            let required = (StatusCode::PRECONDITION_REQUIRED, "precondition required");
            let r = bare(1).await;
            assert_eq!((r.status, r.error().as_str()), required);
            assert_nothing_stored(&h).await;

            let r = publish(&h, 1, &document).await;
            assert_eq!(r.status, StatusCode::OK, "{}", r.error());
            // Over a stored pointer too, before the seq is compared.
            for seq in [1, 2] {
                let r = bare(seq).await;
                assert_eq!((r.status, r.error().as_str()), required);
            }
            assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");
        }
    }

    #[tokio::test]
    async fn one_envelope_has_one_index() {
        let h = ingested().await;
        ingest(&h, 2).await;
        let document = envelope(1);
        let hash = hash_of(&document);
        assert_eq!(publish(&h, 1, &document).await.status, StatusCode::OK);
        let first = h.store.catalog_indexes.lock().await[&hash].clone();

        // The same envelope at seq 2 with another index, signed over it.
        let conflict = (
            StatusCode::CONFLICT,
            "catalog document already published with another index",
        );
        let r = publish_index(&h, 2, &document, json!([entry("rec-2", &payload(2))])).await;
        assert_eq!((r.status, r.error().as_str()), conflict);
        assert_eq!(h.store.catalog_indexes.lock().await[&hash], first);
        assert_eq!(h.store.transitions.lock().await.len(), 1, "no transition");
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");

        // Another account's record of the envelope is no retry, even with
        // the same index.
        let h = ingested().await;
        let theirs = index_record(READER, index());
        h.store
            .catalog_indexes
            .lock()
            .await
            .insert(hash.clone(), theirs.clone());
        let r = publish(&h, 1, &document).await;
        assert_eq!((r.status, r.error().as_str()), conflict);
        assert_eq!(h.store.catalog_indexes.lock().await[&hash], theirs);
        // Refused before the transition, the envelope and its outboard are
        // written.
        assert!(h.store.transitions.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());
        assert!(h.store.catalog_outboards.lock().await.is_empty());
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    /// Another account publishing the same envelope bytes with its own index
    /// gets the 409 before anything of its publish is written: the envelope
    /// keeps its publisher as owner, which `owner_hidden` and the deletion
    /// sweep read.
    #[tokio::test]
    async fn another_accounts_index_leaves_the_envelope_as_published() {
        let h = ingested().await;
        let document = envelope(1);
        let hash = hash_of(&document);
        assert_eq!(publish(&h, 1, &document).await.status, StatusCode::OK);
        let outboard = h.store.catalog_outboards.lock().await[&hash].clone();
        let record = h.store.catalog_indexes.lock().await[&hash].clone();

        // READER's token also names campaign 12345678 as its creator's, and
        // its index lists a recording of its own.
        ingest(&h, 2).await;
        h.store.own(&payload(2), READER).await;
        *h.status.subject.lock().unwrap() = READER;
        let theirs = json!([entry("rec-2", &payload(2))]);
        let bundle = v2::bundle(READER, 1, &document, Some(&hash_of_index(&theirs)));
        let r = put(
            &h,
            READER,
            &token(READER),
            body_with(&document, &bundle, theirs),
        )
        .await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::CONFLICT,
                "catalog document already published with another index"
            )
        );

        {
            let docs = h.store.catalog_documents.lock().await;
            assert_eq!(docs[&hash].body, Bytes::from(document.clone()));
            assert_eq!(docs[&hash].owner.as_deref(), Some(SUB));
        }
        assert_eq!(h.store.catalog_outboards.lock().await[&hash], outboard);
        assert_eq!(h.store.catalog_indexes.lock().await[&hash], record);
        assert!(!h.store.catalog_pointers.lock().await.contains_key(READER));
        let transitions = h.store.transitions.lock().await;
        assert_eq!(transitions.len(), 1, "no transition of READER's");
        assert!(transitions.keys().all(|key| key.starts_with(SUB)));
        drop(transitions);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");
    }

    /// The index record is created first, so a document write that fails
    /// after it leaves a record no pointer names, which nothing serves, and
    /// the same publish sent again completes.
    #[tokio::test]
    async fn a_publish_whose_document_write_failed_completes_on_retry() {
        let h = ingested().await;
        let document = envelope(1);
        let hash = hash_of(&document);
        h.store
            .fail_next_document_write
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 1, &document).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        let record = h
            .store
            .catalog_indexes
            .lock()
            .await
            .get(&hash)
            .cloned()
            .expect("the index record is created before the document");
        assert_eq!(
            h.store.transitions.lock().await.len(),
            1,
            "the transition is written before the document"
        );
        assert!(h.store.catalog_documents.lock().await.is_empty());
        assert!(h.store.catalog_outboards.lock().await.is_empty());
        assert!(h.store.catalog_pointers.lock().await.is_empty());
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);

        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            h.store.catalog_documents.lock().await[&hash]
                .owner
                .as_deref(),
            Some(SUB)
        );
        assert!(h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert_eq!(h.store.catalog_indexes.lock().await[&hash], record);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");
    }

    /// An outboard write that fails after the document's leaves the
    /// stored pointer as it was; the same publish sent again completes.
    #[tokio::test]
    async fn a_publish_whose_outboard_write_failed_completes_on_retry() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let stored = h.store.catalog_pointers.lock().await[SUB].clone();
        let second = envelope(2);
        let hash = hash_of(&second);
        h.store
            .fail_next_outboard_write
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 2, &second).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        assert!(h.store.catalog_indexes.lock().await.contains_key(&hash));
        assert!(h.store.catalog_documents.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");

        let r = publish(&h, 2, &second).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert!(h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert_eq!(h.store.transitions.lock().await.len(), 2);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"2\"");
    }

    #[tokio::test]
    async fn a_retry_with_the_same_index_publishes() {
        let h = ingested().await;
        ingest(&h, 2).await;
        let document = envelope(1);
        let hash = hash_of(&document);
        let (a, b) = (entry("rec-1", &payload(1)), entry("rec-2", &payload(2)));
        let r = publish_index(&h, 1, &document, json!([a.clone(), b.clone()])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let first = h.store.catalog_indexes.lock().await[&hash].clone();

        // The same entries in another order are the same canonical index.
        let r = publish_index(&h, 2, &document, json!([b, a])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(
            h.store.catalog_indexes.lock().await[&hash],
            first,
            "the first record stays"
        );
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"2\"");

        // A record under the account's other form of its subject is its own.
        let h = ingested().await;
        h.store
            .catalog_indexes
            .lock()
            .await
            .insert(hash, index_record(&format!("arkavo:{SUB}"), index()));
        let r = publish(&h, 1, &document).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
    }

    #[tokio::test]
    async fn an_index_record_that_cannot_be_read_back_is_unavailable() {
        let unavailable = (StatusCode::BAD_GATEWAY, "storage unavailable");
        // The create loses, yet no record is there to read.
        let h = ingested().await;
        h.store
            .lose_next_index_create
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!((r.status, r.error().as_str()), unavailable);
        assert_nothing_stored(&h).await;

        // The create fails: S3's 409 on every attempt, say.
        let h = ingested().await;
        h.store
            .fail_next_index_create
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!((r.status, r.error().as_str()), unavailable);
        assert_nothing_stored(&h).await;

        // The record there doesn't parse.
        let h = ingested().await;
        let hash = hash_of(&envelope(1));
        let garbage = Bytes::from_static(b"not a record");
        h.store
            .catalog_indexes
            .lock()
            .await
            .insert(hash.clone(), garbage.clone());
        let r = publish(&h, 1, &envelope(1)).await;
        assert_eq!((r.status, r.error().as_str()), unavailable);
        assert_eq!(h.store.catalog_indexes.lock().await[&hash], garbage);
        assert!(h.store.transitions.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());
        assert!(h.store.catalog_outboards.lock().await.is_empty());
        assert!(h.store.catalog_pointers.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_2_publish_replaces_a_stored_1_pointer() {
        let h = ingested().await;
        let old = envelope(1);
        let stored = Bytes::from(serde_json::to_vec(&v2::bundle(SUB, 3, &old, None)).unwrap());
        h.store
            .catalog_pointers
            .lock()
            .await
            .insert(SUB.into(), (stored.clone(), 99));
        h.store
            .catalog_indexes
            .lock()
            .await
            .insert(hash_of(&old), index_record(SUB, index()));
        let r = get(&h, SUB).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert_eq!(r.headers[header::ETAG], "\"3\"");
        assert_eq!(r.body, stored, "GET serves the stored /1 bytes");

        let new = envelope(2);
        let r = publish_if(&h, 4, &new, header::IF_MATCH, "\"3\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let r = get(&h, SUB).await;
        assert_eq!(r.headers[header::ETAG], "\"4\"");
        let served: Bundle = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(served, signed(4, &new, &index()));
    }

    /// Hex SHA-256 of a bundle's signed pointer bytes.
    fn digest_of(bundle: &Bundle) -> String {
        hex::encode(Sha256::digest(
            URL_SAFE_NO_PAD.decode(&bundle.pointer).unwrap(),
        ))
    }

    /// The transition recorded by `SUB`'s publish of `document` at `seq`
    /// over `index`.
    async fn transition(
        h: &Harness,
        seq: u64,
        document: &[u8],
        index: &serde_json::Value,
    ) -> Transition {
        let digest = digest_of(&signed(seq, document, index));
        let key = format!("{SUB}/{}", transition_name(seq, &digest));
        let body = h.store.transitions.lock().await.get(&key).cloned();
        serde_json::from_slice(&body.expect("transition recorded")).unwrap()
    }

    /// Publishes `seq` over `index` with exactly the `precondition` header.
    async fn publish_index_if(
        h: &Harness,
        seq: u64,
        document: &[u8],
        index: &serde_json::Value,
        precondition: (header::HeaderName, &str),
    ) -> Reply {
        let body = body_with(document, &signed(seq, document, index), index.clone());
        put_with(h, SUB, &token(SUB), body, &[precondition]).await
    }

    fn base(seq: u64, document: &[u8], index: &serde_json::Value) -> Option<TransitionBase> {
        Some(TransitionBase {
            seq,
            catalog_hash: hash_of(document),
            pointer: digest_of(&signed(seq, document, index)),
        })
    }

    /// rec-n naming payload(n).
    fn rec(n: u8) -> serde_json::Value {
        entry(&format!("rec-{n}"), &payload(n))
    }

    #[tokio::test]
    async fn the_first_publish_records_every_hash_as_added() {
        let h = ingested().await;
        let document = envelope(1);
        let bundle = signed(1, &document, &index());
        let before = now_secs();
        let r = put(&h, SUB, &token(SUB), body(&document, &bundle)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());

        let transitions = h.store.transitions.lock().await;
        let key = format!("{SUB}/00000000000000000001-{}", digest_of(&bundle));
        assert_eq!(transitions.keys().collect::<Vec<_>>(), [&key]);
        let recorded: serde_json::Value = serde_json::from_slice(&transitions[&key]).unwrap();
        let at = recorded["at"].as_i64().unwrap();
        assert!((before..=now_secs()).contains(&at));
        assert_eq!(
            recorded,
            json!({
                "subject": SUB,
                "seq": 1,
                "catalogHash": hash_of(&document),
                "pointer": digest_of(&bundle),
                "base": null,
                "at": at,
                "dropped": [],
                "added": [payload(1)],
            })
        );
    }

    #[tokio::test]
    async fn a_hide_records_the_dropped_recording() {
        let h = ingested().await;
        ingest(&h, 2).await;
        let (first, both) = (envelope(1), json!([rec(1), rec(2)]));
        let r = publish_index(&h, 1, &first, both.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let (second, kept) = (envelope(2), json!([rec(1)]));
        let r = publish_index(&h, 2, &second, kept.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());

        let t = transition(&h, 2, &second, &kept).await;
        assert_eq!(t.subject, SUB);
        assert_eq!(t.catalog_hash, hash_of(&second));
        assert_eq!(t.base, base(1, &first, &both));
        assert_eq!(t.dropped, [payload(2)]);
        assert!(t.added.is_empty());
        assert_eq!(h.store.transitions.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn a_blocked_recording_is_not_dropped() {
        let h = ingested().await;
        ingest(&h, 2).await;
        let r = publish_index(&h, 1, &envelope(1), json!([rec(1), rec(2)])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        h.moderation.block_for_test(&payload(2));
        let (second, kept) = (envelope(2), json!([rec(1)]));
        let r = publish_index(&h, 2, &second, kept.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        assert!(transition(&h, 2, &second, &kept).await.dropped.is_empty());
    }

    #[tokio::test]
    async fn a_recording_the_publisher_does_not_own_is_not_dropped() {
        let h = ingested().await;
        for n in 2..=4 {
            ingest(&h, n).await;
        }
        let all = json!([rec(1), rec(2), rec(3), rec(4)]);
        let r = publish_index(&h, 1, &envelope(1), all).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        // payload(2) is another account's now, payload(3) is the publisher's
        // under its other form of the subject, payload(4) has no owner.
        h.store.own(&payload(2), READER).await;
        h.store.own(&payload(3), &format!("arkavo:{SUB}")).await;
        h.store.owners.lock().await.remove(&payload(4));
        let (second, kept) = (envelope(2), json!([rec(1)]));
        let r = publish_index(&h, 2, &second, kept.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 2, &second, &kept).await;
        assert_eq!(t.dropped, [payload(3)]);
    }

    #[tokio::test]
    async fn an_unreadable_owner_record_of_a_dropped_recording_is_unavailable() {
        let h = ingested().await;
        ingest(&h, 2).await;
        let first = envelope(1);
        let r = publish_index(&h, 1, &first, json!([rec(1), rec(2)])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let stored = h.store.catalog_pointers.lock().await[SUB].clone();
        h.store
            .owners
            .lock()
            .await
            .insert(payload(2), Bytes::from_static(b"not a record"));

        let second = envelope(2);
        let r = publish_index(&h, 2, &second, json!([rec(1)])).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        // Read before any write: nothing of the publish is stored, not even
        // its index record.
        assert_eq!(h.store.transitions.lock().await.len(), 1);
        assert_unstored(&h, &second, 1).await;
        assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
    }

    #[tokio::test]
    async fn nothing_is_dropped_from_a_base_that_is_not_served() {
        #[derive(Debug, Clone, Copy)]
        enum Hidden {
            EnvelopeBlocked,
            CatalogBlocked,
            /// A suspended subject can't publish: this one is suspended
            /// after its token checks, mid-publish.
            HideCatalogSuspension,
        }
        // `GET` serves none of these bases, and preconditions see what
        // `GET` serves: the base's tag is a 412 that writes no transition,
        // and the client publishes as after a 404.
        let tag = (header::IF_MATCH, "\"1\"");
        let none = (header::IF_NONE_MATCH, "*");
        for hidden in [
            Hidden::EnvelopeBlocked,
            Hidden::CatalogBlocked,
            Hidden::HideCatalogSuspension,
        ] {
            for precondition in [tag.clone(), none.clone()] {
                let h = ingested().await;
                ingest(&h, 2).await;
                ingest(&h, 3).await;
                let (first, both) = (envelope(1), json!([rec(1), rec(2)]));
                let r = publish_index(&h, 1, &first, both.clone()).await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.error());
                match hidden {
                    Hidden::EnvelopeBlocked => h.moderation.block_for_test(&hash_of(&first)),
                    Hidden::CatalogBlocked => h.moderation.block_catalog_for_test(SUB),
                    Hidden::HideCatalogSuspension => {
                        let moderation = Arc::clone(&h.moderation);
                        *h.status.on_check.lock().unwrap() =
                            Some(Box::new(move || moderation.suspend_for_test(SUB, true)));
                    }
                }

                let (second, next) = (envelope(2), json!([rec(1), rec(3)]));
                let is_tag = precondition == tag;
                let r = publish_index_if(&h, 2, &second, &next, precondition).await;
                if is_tag {
                    assert_eq!(
                        r.status,
                        StatusCode::PRECONDITION_FAILED,
                        "{hidden:?}: {}",
                        r.error()
                    );
                    assert_eq!(h.store.transitions.lock().await.len(), 1, "{hidden:?}");
                    assert_unstored(&h, &second, 1).await;
                    continue;
                }
                assert_eq!(r.status, StatusCode::OK, "{hidden:?}: {}", r.error());
                let t = transition(&h, 2, &second, &next).await;
                assert!(t.dropped.is_empty(), "{hidden:?}");
                assert_eq!(
                    t.added,
                    [payload(3)],
                    "{hidden:?}: against the base's index"
                );
                assert_eq!(t.base, base(1, &first, &both), "{hidden:?}");
            }
        }
    }

    /// The index record is created before the transition, so a failed
    /// transition write leaves only that record, which no pointer names and
    /// nothing serves; the same publish sent again completes.
    #[tokio::test]
    async fn a_failed_transition_write_leaves_only_the_index_record() {
        let unavailable = (StatusCode::BAD_GATEWAY, "storage unavailable");
        let h = ingested().await;
        let first = envelope(1);
        h.store.fail_next_transition.store(true, Ordering::Relaxed);
        let r = publish(&h, 1, &first).await;
        assert_eq!((r.status, r.error().as_str()), unavailable);
        assert!(h.store.transitions.lock().await.is_empty());
        assert!(h.store.catalog_documents.lock().await.is_empty());
        assert!(h.store.catalog_outboards.lock().await.is_empty());
        assert!(h.store.catalog_pointers.lock().await.is_empty());
        let record = h
            .store
            .catalog_indexes
            .lock()
            .await
            .get(&hash_of(&first))
            .cloned();
        let record = record.expect("the index record is created before the transition");
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);

        // Sent again: completes, over the same record.
        assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
        assert_eq!(h.store.transitions.lock().await.len(), 1);
        assert_eq!(
            h.store.catalog_indexes.lock().await[&hash_of(&first)],
            record
        );

        // Over a stored pointer: none of the new publish's other writes.
        let stored = h.store.catalog_pointers.lock().await[SUB].clone();
        h.store.fail_next_transition.store(true, Ordering::Relaxed);
        let second = envelope(2);
        let r = publish(&h, 2, &second).await;
        assert_eq!((r.status, r.error().as_str()), unavailable);
        let hash = hash_of(&second);
        assert!(!h.store.catalog_documents.lock().await.contains_key(&hash));
        assert!(!h.store.catalog_outboards.lock().await.contains_key(&hash));
        assert!(h.store.catalog_indexes.lock().await.contains_key(&hash));
        assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
        assert_eq!(h.store.transitions.lock().await.len(), 1);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"1\"");

        assert_eq!(publish(&h, 2, &second).await.status, StatusCode::OK);
        assert_eq!(h.store.transitions.lock().await.len(), 2);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"2\"");
    }

    #[tokio::test]
    async fn a_retry_after_a_commit_keeps_the_committed_transition() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let second = envelope(2);
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let committed = h.store.transitions.lock().await.clone();
        assert_eq!(committed.len(), 2);

        // The reply was lost and the client resends: refused before the
        // transition is written, so the committed one keeps its base.
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::PRECONDITION_FAILED, "{}", r.error());
        assert_eq!(*h.store.transitions.lock().await, committed);
        // Sent with the committed pointer's own tag: past the 412, the 409.
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"2\"").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::CONFLICT, "seq must be greater than 2")
        );
        assert_eq!(*h.store.transitions.lock().await, committed);
    }

    /// The key `SUB`'s publish of `document` at `seq` over `index` writes
    /// its transition under, as `MemStore` keeps it.
    fn transition_key(seq: u64, document: &[u8], index: &serde_json::Value) -> String {
        let digest = digest_of(&signed(seq, document, index));
        format!("{SUB}/{}", transition_name(seq, &digest))
    }

    /// A pointer from before envelopes at `seq` (no index record), stored
    /// at version 99, and the `base` a publish over it records.
    async fn store_pre_envelope_pointer(h: &Harness, seq: u64) -> Option<TransitionBase> {
        let old = b"{\"schema\":\"arkavo.creator-catalog/1\"}".to_vec();
        let stored = serde_json::to_vec(&v2::bundle(SUB, seq, &old, None)).unwrap();
        h.store
            .catalog_pointers
            .lock()
            .await
            .insert(SUB.into(), (Bytes::from(stored), 99));
        Some(TransitionBase {
            seq,
            catalog_hash: hash_of(&old),
            pointer: hex::encode(Sha256::digest(v2::pointer_bytes(SUB, seq, &old, None))),
        })
    }

    /// Copies of one publish over the same base. A first copy wrote its
    /// transition and is still in flight. A second finds it with the
    /// pointer still the base all read: it replaces it (a fresh `at`, the
    /// same base) and commits. A third copy, stalled since its step-7 read,
    /// before its transition write, then finds the pointer moved to that
    /// same pointer: it keeps the transition and answers 502, and a read of
    /// the pointer shows its own `pointer` served.
    #[tokio::test]
    async fn concurrent_duplicates_over_the_same_base_both_end_correct() {
        let h = ingested().await;
        let first = envelope(1);
        assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
        // What both copies read at their step 7.
        let read = h.store.catalog_pointers.lock().await[SUB].clone();

        // The original wrote its transition and is still writing the rest.
        let second = envelope(2);
        let original = Transition {
            subject: SUB.into(),
            seq: 2,
            catalog_hash: hash_of(&second),
            pointer: digest_of(&signed(2, &second, &index())),
            base: base(1, &first, &index()),
            at: 1_000,
            dropped: vec![],
            added: vec![],
        };
        let key = transition_key(2, &second, &index());
        h.store.transitions.lock().await.insert(
            key.clone(),
            Bytes::from(serde_json::to_vec(&original).unwrap()),
        );

        let before = now_secs();
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 2, &second, &index()).await;
        assert_eq!(t.base, base(1, &first, &index()));
        assert!(t.at >= before, "the duplicate's own `at`");
        let committed = h.store.transitions.lock().await.clone();

        // The third copy resumes from its step-7 read.
        *h.store.stale_next_pointer_read.lock().unwrap() = Some(read);
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        assert_eq!(*h.store.transitions.lock().await, committed);
        let served: Bundle = serde_json::from_slice(&get(&h, SUB).await.body).unwrap();
        assert_eq!(served.pointer, signed(2, &second, &index()).pointer);
    }

    /// The same signed pointer sent again over a base that moved since its
    /// first attempt lost the pointer race: its transition is replaced, so
    /// the pointer it commits names its real base.
    #[tokio::test]
    async fn the_same_pointer_over_a_moved_base_replaces_its_transition() {
        let h = ingested().await;
        let first = envelope(1);
        assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
        let ours = envelope(3);
        h.store
            .lose_next_pointer_race
            .store(true, Ordering::Relaxed);
        let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.error());
        let t = transition(&h, 3, &ours, &index()).await;
        assert_eq!(t.base, base(1, &first, &index()));

        // Another device publishes seq 2; ours is re-sent over it, the
        // same pointer bytes with the new tag.
        let theirs = envelope(2);
        let r = publish_if(&h, 2, &theirs, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"2\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 3, &ours, &index()).await;
        assert_eq!(t.base, base(2, &theirs, &index()));
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"3\"");
    }

    /// The re-review's equal-seq trace. Over a pointer from before
    /// envelopes at seq 5 there is no seq floor: ours (seq 6) loses its
    /// pointer race to theirs at seq 5 too, then is sent again over theirs.
    /// Its transition is replaced and names its actual predecessor, theirs,
    /// not the pointer from before envelopes at the same seq.
    #[tokio::test]
    async fn over_a_pre_envelope_base_the_transition_names_the_actual_predecessor() {
        let h = ingested().await;
        let old = store_pre_envelope_pointer(&h, 5).await;
        let (theirs, ours) = (envelope(2), envelope(3));
        h.store
            .lose_next_pointer_race
            .store(true, Ordering::Relaxed);
        let r = publish_if(&h, 6, &ours, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.error());
        assert_eq!(transition(&h, 6, &ours, &index()).await.base, old);

        let r = publish_if(&h, 5, &theirs, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let r = publish_if(&h, 6, &ours, header::IF_MATCH, "\"5\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 6, &ours, &index()).await;
        assert_eq!(t.base, base(5, &theirs, &index()));
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"6\"");
    }

    /// A publish stalled since it read seq 1 resumes after the same signed
    /// pointer was sent again over seq 2 and committed. The pointer moved
    /// from what it read, so the committed transition stays as it is, the
    /// stalled publish is answered as a lost transition write (502), and
    /// the pointer stays.
    #[tokio::test]
    async fn a_stalled_publish_keeps_the_committed_transition() {
        let h = ingested().await;
        let first = envelope(1);
        assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
        // What the stalled publish read at its step 7.
        let read = h.store.catalog_pointers.lock().await[SUB].clone();

        let (theirs, ours) = (envelope(2), envelope(3));
        let r = publish_if(&h, 2, &theirs, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"2\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let committed = h.store.transitions.lock().await.clone();
        assert_eq!(
            transition(&h, 3, &ours, &index()).await.base,
            base(2, &theirs, &index())
        );
        let stored = h.store.catalog_pointers.lock().await[SUB].clone();

        *h.store.stale_next_pointer_read.lock().unwrap() = Some(read);
        let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"1\"").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        assert_eq!(*h.store.transitions.lock().await, committed);
        assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
        assert_eq!(get(&h, SUB).await.headers[header::ETAG], "\"3\"");
    }

    /// The re-review's stall trace: a publish stalled since it read a
    /// pointer from before envelopes at seq 12 resumes after theirs (seq 1)
    /// and then the same signed pointer, sent again over theirs, committed.
    /// Its base seq is the higher, but the pointer moved from what it read:
    /// the committed transition stays, and the stalled publish gets 502.
    #[tokio::test]
    async fn a_stalled_publish_over_a_pre_envelope_base_keeps_the_committed_transition() {
        let h = ingested().await;
        store_pre_envelope_pointer(&h, 12).await;
        let read = h.store.catalog_pointers.lock().await[SUB].clone();

        let (theirs, ours) = (envelope(2), envelope(3));
        let r = publish_if(&h, 1, &theirs, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let committed = h.store.transitions.lock().await.clone();
        assert_eq!(
            transition(&h, 3, &ours, &index()).await.base,
            base(1, &theirs, &index())
        );
        let stored = h.store.catalog_pointers.lock().await[SUB].clone();

        *h.store.stale_next_pointer_read.lock().unwrap() = Some(read);
        let r = publish_if(&h, 3, &ours, header::IF_NONE_MATCH, "*").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::BAD_GATEWAY, "storage unavailable")
        );
        assert_eq!(*h.store.transitions.lock().await, committed);
        assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
    }

    /// A publish whose document write failed, sent again days later: its
    /// transition is replaced with a fresh `at`, so the creator's grace to
    /// undo a drop runs from the publish that commits.
    #[tokio::test]
    async fn a_resend_after_a_502_refreshes_the_transitions_at() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let second = envelope(2);
        h.store
            .fail_next_document_write
            .store(true, Ordering::Relaxed);
        let r = publish(&h, 2, &second).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{}", r.error());

        // Days pass: the stored transition is as old as that attempt.
        let key = transition_key(2, &second, &index());
        let mut first_attempt = transition(&h, 2, &second, &index()).await;
        first_attempt.at -= 3 * 24 * 60 * 60;
        h.store.transitions.lock().await.insert(
            key.clone(),
            Bytes::from(serde_json::to_vec(&first_attempt).unwrap()),
        );

        let before = now_secs();
        let r = publish(&h, 2, &second).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 2, &second, &index()).await;
        assert!(t.at >= before, "{} < {before}", t.at);
        assert_eq!(t.base, first_attempt.base);
    }

    /// The setup of the interleaving tests: seq 1 stored, and a first
    /// attempt of ours (seq 3) over it that lost its pointer race, leaving
    /// its transition. Returns ours, the key and that transition's body.
    async fn ours_lost_a_race(h: &Harness) -> (Vec<u8>, String, Bytes) {
        assert_eq!(publish(h, 1, &envelope(1)).await.status, StatusCode::OK);
        let ours = envelope(3);
        h.store
            .lose_next_pointer_race
            .store(true, Ordering::Relaxed);
        let r = publish_if(h, 3, &ours, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.error());
        let key = transition_key(3, &ours, &index());
        let first = h.store.transitions.lock().await[&key].clone();
        (ours, key, first)
    }

    /// `SUB`'s transition of `document` at `seq` over `base`, as stored.
    fn transition_body(seq: u64, document: &[u8], base: Option<TransitionBase>, at: i64) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&Transition {
                subject: SUB.into(),
                seq,
                catalog_hash: hash_of(document),
                pointer: digest_of(&signed(seq, document, &index())),
                base,
                at,
                dropped: vec![],
                added: vec![],
            })
            .unwrap(),
        )
    }

    /// The bundle `SUB` signs for `document` at `seq`, as stored.
    fn bundle_body(seq: u64, document: &[u8]) -> Bytes {
        Bytes::from(serde_json::to_vec(&signed(seq, document, &index())).unwrap())
    }

    /// Another copy's write landing between `write_transition`'s
    /// transition read and its pointer re-read (the `MemStore` hook) ends
    /// in 502, from the moved pointer or a lost replace, and the transition
    /// is left as that copy wrote it: never this copy's base over it.
    /// - another copy commits ours over seq 1;
    /// - theirs commits seq 2, then another copy of ours replaces the
    ///   transition with base 2 and commits;
    /// - another copy replaces the transition, the pointer unchanged.
    #[tokio::test]
    async fn writes_between_the_transition_read_and_the_pointer_check_end_in_502() {
        #[derive(Debug, Clone, Copy)]
        enum Between {
            Commit,
            NewerBaseCommit,
            Replace,
        }
        for between in [Between::Commit, Between::NewerBaseCommit, Between::Replace] {
            let h = ingested().await;
            let (ours, key, first) = ours_lost_a_race(&h).await;
            let theirs = envelope(2);
            let (hook_key, ours_bundle, theirs_bundle) =
                (key.clone(), bundle_body(3, &ours), bundle_body(2, &theirs));
            let left = match between {
                Between::Commit => first.clone(),
                Between::NewerBaseCommit => {
                    transition_body(3, &ours, base(2, &theirs, &index()), 2_000)
                }
                Between::Replace => {
                    transition_body(3, &ours, base(1, &envelope(1), &index()), 2_000)
                }
            };
            let written = left.clone();
            *h.store.after_next_transition_read.lock().unwrap() =
                Some(Box::new(move |store: &MemStore| match between {
                    Between::Commit => store.commit_pointer(SUB, ours_bundle),
                    Between::NewerBaseCommit => {
                        store.commit_pointer(SUB, theirs_bundle);
                        store.store_transition(&hook_key, written);
                        store.commit_pointer(SUB, ours_bundle);
                    }
                    Between::Replace => store.store_transition(&hook_key, written),
                }));

            let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"1\"").await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::BAD_GATEWAY, "storage unavailable"),
                "{between:?}"
            );
            assert_eq!(h.store.transitions.lock().await[&key], left, "{between:?}");
        }
    }

    /// The interleaving that leaves the losing copy's `at`: copy B wrote
    /// the transition; copy A reads it and its pointer check passes; B
    /// commits; A's replace succeeds, and A's pointer write loses (409).
    /// The transition names B's predecessor, the base both read, with A's
    /// `at`.
    #[tokio::test]
    async fn a_copy_that_replaces_as_the_other_commits_ends_at_409() {
        let h = ingested().await;
        let first = envelope(1);
        assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
        let second = envelope(2);
        let key = transition_key(2, &second, &index());
        h.store.transitions.lock().await.insert(
            key.clone(),
            transition_body(2, &second, base(1, &first, &index()), 1_000),
        );
        let b_commits = bundle_body(2, &second);
        // B commits right after A's pointer check: the hook after A's
        // transition read sets one after the pointer read that follows.
        *h.store.after_next_transition_read.lock().unwrap() =
            Some(Box::new(move |store: &MemStore| {
                *store.after_next_pointer_read.lock().unwrap() =
                    Some(Box::new(move |store: &MemStore| {
                        store.commit_pointer(SUB, b_commits)
                    }));
            }));

        let before = now_secs();
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (
                StatusCode::CONFLICT,
                "seq must be greater than the stored seq: another publish won"
            )
        );
        let t = transition(&h, 2, &second, &index()).await;
        assert_eq!(t.base, base(1, &first, &index()));
        assert!(t.at >= before, "A's `at`, the losing copy's");
        let served: Bundle = serde_json::from_slice(&get(&h, SUB).await.body).unwrap();
        assert_eq!(served, signed(2, &second, &index()));
    }

    /// A resend whose stored pointer `GET` hides (a catalog block): sent
    /// with `If-None-Match: *` after the 404, its `expected` is still the
    /// hidden pointer's ETag, so the transition is replaced with that
    /// pointer as its base, and the publish commits.
    #[tokio::test]
    async fn a_resend_over_a_hidden_pointer_replaces_the_transition() {
        let h = ingested().await;
        let (ours, _, _) = ours_lost_a_race(&h).await;
        let theirs = envelope(2);
        let r = publish_if(&h, 2, &theirs, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        h.moderation.block_catalog_for_test(SUB);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);

        let r = publish_if(&h, 3, &ours, header::IF_NONE_MATCH, "*").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 3, &ours, &index()).await;
        assert_eq!(t.base, base(2, &theirs, &index()));
        assert!(t.dropped.is_empty(), "a hidden base drops nothing");
        let stored = h.store.catalog_pointers.lock().await[SUB].0.clone();
        assert_eq!(stored, bundle_body(3, &ours));
    }

    /// A transition under this publish's key, the pointer still what it
    /// read. One replaced since it was read: the replace loses, 502, and
    /// neither it nor the pointer changes. One that doesn't parse (the node
    /// wrote it, so a storage fault): replaced like any other.
    #[tokio::test]
    async fn a_lost_transition_replace_is_502() {
        for garbled in [false, true] {
            let h = ingested().await;
            let first = envelope(1);
            assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
            let ours = envelope(3);
            h.store
                .lose_next_pointer_race
                .store(true, Ordering::Relaxed);
            let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"1\"").await;
            assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.error());
            let theirs = envelope(2);
            let r = publish_if(&h, 2, &theirs, header::IF_MATCH, "\"1\"").await;
            assert_eq!(r.status, StatusCode::OK, "{}", r.error());

            let key = transition_key(3, &ours, &index());
            if garbled {
                h.store
                    .transitions
                    .lock()
                    .await
                    .insert(key.clone(), Bytes::from_static(b"not a transition"));
            } else {
                h.store
                    .lose_next_transition_replace
                    .store(true, Ordering::Relaxed);
            }
            let before = h.store.transitions.lock().await.clone();
            let stored = h.store.catalog_pointers.lock().await[SUB].clone();
            let r = publish_if(&h, 3, &ours, header::IF_MATCH, "\"2\"").await;
            if garbled {
                assert_eq!(r.status, StatusCode::OK, "{}", r.error());
                let t = transition(&h, 3, &ours, &index()).await;
                assert_eq!(t.base, base(2, &theirs, &index()));
                continue;
            }
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::BAD_GATEWAY, "storage unavailable")
            );
            assert_eq!(*h.store.transitions.lock().await, before);
            assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
        }
    }

    /// A committed publish sent again after a catalog block hid its pointer:
    /// `If-None-Match: *` holds then (`GET` serves none), so only the seq
    /// floor, the stored pointer's whatever its visibility, stops it, before
    /// its transition is written again.
    #[tokio::test]
    async fn a_retry_over_a_hidden_commit_meets_the_seq_floor() {
        let h = ingested().await;
        assert_eq!(publish(&h, 1, &envelope(1)).await.status, StatusCode::OK);
        let second = envelope(2);
        let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let committed = h.store.transitions.lock().await.clone();
        let stored = h.store.catalog_pointers.lock().await[SUB].clone();

        h.moderation.block_catalog_for_test(SUB);
        assert_eq!(get(&h, SUB).await.status, StatusCode::NOT_FOUND);
        let r = publish_if(&h, 2, &second, header::IF_NONE_MATCH, "*").await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (StatusCode::CONFLICT, "seq must be greater than 2")
        );
        assert_eq!(*h.store.transitions.lock().await, committed);
        assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
    }

    #[tokio::test]
    async fn a_2_base_with_a_tampered_index_is_502() {
        for tampered in [
            // Parses, but isn't the index the `/2` pointer's indexHash binds.
            index_record(SUB, json!([rec(2)])),
            index_record(SUB, json!([rec(1), rec(2)])),
            // Doesn't parse.
            index_record(SUB, json!([{"contentID": "rec-1"}])),
            Bytes::from_static(b"not a record"),
        ] {
            // Each case on its own node, with the tag a client read before
            // the record was tampered with: no `GET` (or its attribute
            // cache) between the cases.
            let h = ingested().await;
            ingest(&h, 2).await;
            let first = envelope(1);
            assert_eq!(publish(&h, 1, &first).await.status, StatusCode::OK);
            let stored = h.store.catalog_pointers.lock().await[SUB].clone();
            h.store
                .catalog_indexes
                .lock()
                .await
                .insert(hash_of(&first), tampered.clone());
            let second = envelope(2);
            let r = publish_if(&h, 2, &second, header::IF_MATCH, "\"1\"").await;
            assert_eq!(
                (r.status, r.error().as_str()),
                (StatusCode::BAD_GATEWAY, "storage unavailable"),
                "{tampered:?}"
            );
            assert_eq!(h.store.transitions.lock().await.len(), 1);
            assert_unstored(&h, &second, 1).await;
            assert_eq!(h.store.catalog_pointers.lock().await[SUB], stored);
        }
    }

    #[tokio::test]
    async fn a_publish_over_a_1_base_records_its_digest() {
        let h = ingested().await;
        ingest(&h, 2).await;
        let old = envelope(1);
        let stored = serde_json::to_vec(&v2::bundle(SUB, 3, &old, None)).unwrap();
        h.store
            .catalog_pointers
            .lock()
            .await
            .insert(SUB.into(), (Bytes::from(stored), 99));
        h.store
            .catalog_indexes
            .lock()
            .await
            .insert(hash_of(&old), index_record(SUB, json!([rec(1), rec(2)])));

        let (new, kept) = (envelope(2), json!([rec(1)]));
        let r = publish_index_if(&h, 4, &new, &kept, (header::IF_MATCH, "\"3\"")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 4, &new, &kept).await;
        let pointer = hex::encode(Sha256::digest(v2::pointer_bytes(SUB, 3, &old, None)));
        assert_eq!(
            t.base,
            Some(TransitionBase {
                seq: 3,
                catalog_hash: hash_of(&old),
                pointer,
            })
        );
        assert_eq!(t.dropped, [payload(2)]);
        assert!(t.added.is_empty());
    }

    #[tokio::test]
    async fn a_publish_over_a_pointer_from_before_envelopes_adds_everything() {
        let h = ingested().await;
        let old = b"{\"schema\":\"arkavo.creator-catalog/1\"}".to_vec();
        let stored = serde_json::to_vec(&v2::bundle(SUB, 12, &old, None)).unwrap();
        h.store
            .catalog_pointers
            .lock()
            .await
            .insert(SUB.into(), (Bytes::from(stored), 99));

        let document = envelope(1);
        let r = publish_index_if(&h, 1, &document, &index(), (header::IF_NONE_MATCH, "*")).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 1, &document, &index()).await;
        let pointer = hex::encode(Sha256::digest(v2::pointer_bytes(SUB, 12, &old, None)));
        assert_eq!(
            t.base,
            Some(TransitionBase {
                seq: 12,
                catalog_hash: hash_of(&old),
                pointer,
            })
        );
        assert!(t.dropped.is_empty());
        assert_eq!(t.added, [payload(1)]);
    }

    #[tokio::test]
    async fn an_ungated_node_drops_nothing() {
        // No owner records are written there.
        let h = harness_ungated();
        for n in [1, 2] {
            h.store
                .ingest_with_manifest(
                    &payload(n),
                    PAYLOAD_SIZE,
                    manifest(recording_policy(), &[KAS]),
                )
                .await;
        }
        let r = publish_index(&h, 1, &envelope(1), json!([rec(1), rec(2)])).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let (second, kept) = (envelope(2), json!([rec(1)]));
        let r = publish_index(&h, 2, &second, kept.clone()).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.error());
        let t = transition(&h, 2, &second, &kept).await;
        assert!(t.dropped.is_empty());
        assert!(t.added.is_empty());
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
        let bundle = signed(1, &document, &index());
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
