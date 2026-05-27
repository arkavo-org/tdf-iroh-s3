//! COSE_Sign1 / CWT verification for the **read** path.
//!
//! The verifier enforces the Arkavo CWT v1 contract (Appendix A of the
//! reader-side spec). Signature verification is delegated to
//! [`super::pep_check::verify_cose_sign1`] so the bytes-on-the-wire shape
//! stays aligned with the upstream reference implementation. Everything
//! after the signature check — claim shape, channel binding, action
//! allowlist — lives in this module.
//!
//! v1 contract summary:
//! - alg ES256 only (pep_check enforces by being P-256-only)
//! - `iss` exact match; `sub` non-empty; `iat`/`exp` window <= 3600s
//! - `scope` (text claim 9) must contain `catalog.read`
//! - `cnf.iroh_node_id` (claim 8 → `"iroh_node_id"`) is REQUIRED on
//!   iroh-authenticated channels and must equal the QUIC peer NodeId
//!   (compared after hex-decoding the connection side)
//! - `authorization_details` (text claim) must be a non-empty array.
//!   Grant `type` allowlist: `"tdf_attribute"` (others skipped silently).
//!   Grant `actions` allowlist: `"read"` (others reject the **whole**
//!   token).

use bytes::Bytes;
use ciborium::Value as CborValue;
use coset::{CborSerializable, CoseSign1};
use std::sync::Arc;
use thiserror::Error;

use super::cose_keys::CoseKeyCache;
use super::pep_check;
use super::{ACTION_READ, SCOPE_CATALOG_READ};

/// CBOR tag prefix for a `tag(61)` ("CWT") wrapping a COSE_Sign1.
/// Stripped before handing the inner bytes to coset.
const CWT_TAG_PREFIX: [u8; 2] = [0xd8, 0x3d];

/// Maximum allowed `exp - iat` window per the v1 contract.
const MAX_TOKEN_LIFETIME_SECS: i64 = 3600;

/// Grant `type` discriminator per the Arkavo CWT v1 contract §3.
///
/// Note: vendored `pep_check.rs` defines `GRANT_TYPE_ATTRIBUTE = "opentdf_attribute"`
/// from an earlier draft. The contract is the source of truth here; we
/// deliberately do NOT call `pep_check::parse_authorization_details` (which
/// would filter on the legacy constant) and instead re-parse in
/// `parse_authorization_details` below using this contract-correct value.
///
/// Anything else MUST be skipped silently (forward compat for new grant types
/// added by the issuer).
const GRANT_TYPE_TDF_ATTRIBUTE: &str = "tdf_attribute";

// IANA CWT claim keys (RFC 8392 + RFC 8747).
const CLAIM_ISS: i64 = 1;
const CLAIM_SUB: i64 = 2;
const CLAIM_EXP: i64 = 4;
const CLAIM_IAT: i64 = 6;
const CLAIM_CTI: i64 = 7;
const CLAIM_CNF: i64 = 8;
const CLAIM_SCOPE: i64 = 9;

const CLAIM_AUTHORIZATION_DETAILS: &str = "authorization_details";
const CNF_IROH_NODE_ID: &str = "iroh_node_id";

/// Channel binding: NodeId is the 32-byte ed25519 public key per iroh.
const IROH_NODE_ID_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    pub subject: String,
    pub raw_cwt: Bytes,
    pub cti: String,
    pub exp: i64,
    pub iat: i64,
    pub issuer: String,
    /// Surviving grants after filtering by `type == "tdf_attribute"` and
    /// validating the action allowlist. Non-empty by construction.
    pub grants: Vec<Grant>,
}

/// Decoded v1 `authorization_details[]` entry, in the shape the read path
/// actually consumes. The fields map to the contract example in spec
/// Appendix A.3:
/// - `fqn`: the canonical OpenTDF attribute-value URL
/// - `actions`: filtered to the v1 allowlist (`["read"]`)
/// - `locations` / `obligations`: surfaced verbatim for future use
#[derive(Debug, Clone)]
pub struct Grant {
    pub fqn: String,
    pub actions: Vec<String>,
    pub locations: Vec<String>,
    pub obligations: Vec<String>,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("cwt: parse: {0}")]
    Parse(String),
    #[error("cwt: signature verification failed")]
    BadSignature,
    #[error("cwt: wrong issuer (expected '{expected}', got '{got:?}')")]
    WrongIssuer {
        expected: String,
        got: Option<String>,
    },
    #[error("cwt: expired (exp={exp}, now={now})")]
    Expired { exp: i64, now: i64 },
    #[error("cwt: issued in the future (iat={iat}, now={now})")]
    NotYetValid { iat: i64, now: i64 },
    #[error("cwt: iat-exp window too wide (exp-iat={diff}, max={max})")]
    WindowTooWide { diff: i64, max: i64 },
    #[error("cwt: missing or empty claim '{0}'")]
    MissingClaim(&'static str),
    #[error("cwt: scope missing required '{0}'")]
    MissingScope(&'static str),
    #[error("cwt: cnf.iroh_node_id mismatch (token='{token}', connection='{connection}')")]
    NodeIdMismatch { token: String, connection: String },
    #[error("cwt: cnf.iroh_node_id missing or malformed")]
    MissingNodeIdBinding,
    #[error("cwt: connection node id is not 32-byte hex (programmer bug at the ALPN handler)")]
    MalformedConnectionBinding,
    #[error("cwt: authorization_details missing or empty")]
    MissingAuthDetails,
    #[error("cwt: unknown action name in authorization_details")]
    UnknownAction,
    #[error("cwt: COSE_KeySet not yet loaded")]
    KeySetUnavailable,
}

pub struct Verifier {
    keys: Arc<CoseKeyCache>,
    issuer: String,
    clock_skew_secs: i64,
}

impl Verifier {
    pub fn new(keys: Arc<CoseKeyCache>, issuer: String, clock_skew_secs: i64) -> Self {
        Self {
            keys,
            issuer,
            clock_skew_secs,
        }
    }

    /// Verify a CWT and channel-bind it to `bound_node_id` (the hex-encoded
    /// QUIC peer NodeId from the ALPN handler).
    ///
    /// Returns `VerifiedClaims` only when the v1 contract is satisfied end
    /// to end — callers may forward the surviving grants to the PDP
    /// without re-checking shape.
    pub async fn verify(
        &self,
        cwt: &[u8],
        bound_node_id: &str,
    ) -> Result<VerifiedClaims, VerifyError> {
        // 1. Strip optional CWT tag prefix; pep_check / coset want a bare
        //    COSE_Sign1 array.
        let inner = if cwt.starts_with(&CWT_TAG_PREFIX) {
            &cwt[2..]
        } else {
            cwt
        };

        // 2. Parse the COSE_Sign1 envelope.
        let sign1 =
            CoseSign1::from_slice(inner).map_err(|e| VerifyError::Parse(e.to_string()))?;

        // 3. Signature verification via the vendored pep_check primitive.
        //    The cache hands us the raw bytes that produced the parsed key
        //    map; pep_check iterates the array itself and tries every key.
        //    This keeps our verifier byte-compatible with the upstream
        //    reference implementation.
        let raw_keyset = self
            .keys
            .raw_bytes()
            .ok_or(VerifyError::KeySetUnavailable)?;

        // pep_check will internally retry against any key — but only the
        // currently-cached set. If verification fails and we have a URL,
        // force a refresh and try once more in case the keyset rotated.
        let first_attempt = pep_check::verify_cose_sign1(&sign1, &raw_keyset);
        if first_attempt.is_err() {
            if self.keys.force_refresh().await {
                let refreshed = self
                    .keys
                    .raw_bytes()
                    .ok_or(VerifyError::KeySetUnavailable)?;
                pep_check::verify_cose_sign1(&sign1, &refreshed)
                    .map_err(|_| VerifyError::BadSignature)?;
            } else {
                return Err(VerifyError::BadSignature);
            }
        }

        let payload = sign1
            .payload
            .as_ref()
            .ok_or_else(|| VerifyError::Parse("missing payload".into()))?;

        // 4. Walk the CWT claims map directly. We avoid coset's ClaimsSet
        //    because it doesn't surface arbitrary text claims in a stable
        //    shape and the contract pins specific text-keyed claims
        //    (`scope`, `authorization_details`).
        let claims = decode_claims_map(payload)?;
        let now = now_unix();

        let got_issuer = claims.issuer.clone();
        if got_issuer.as_deref() != Some(self.issuer.as_str()) {
            return Err(VerifyError::WrongIssuer {
                expected: self.issuer.clone(),
                got: got_issuer,
            });
        }

        let iat = claims.iat.ok_or(VerifyError::MissingClaim("iat"))?;
        if iat - self.clock_skew_secs > now {
            return Err(VerifyError::NotYetValid { iat, now });
        }

        let exp = claims.exp.ok_or(VerifyError::MissingClaim("exp"))?;
        if now >= exp {
            return Err(VerifyError::Expired { exp, now });
        }

        let diff = exp - iat;
        if diff > MAX_TOKEN_LIFETIME_SECS {
            return Err(VerifyError::WindowTooWide {
                diff,
                max: MAX_TOKEN_LIFETIME_SECS,
            });
        }

        let subject = claims
            .subject
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or(VerifyError::MissingClaim("sub"))?;

        // scope (text key per IANA registry) — space-separated, must list
        // catalog.read. Reject if claim is absent OR present but missing
        // the required scope; both shapes mean "no read intent".
        let scope = claims
            .scope
            .as_deref()
            .ok_or(VerifyError::MissingScope(SCOPE_CATALOG_READ))?;
        if !scope.split(' ').any(|s| s == SCOPE_CATALOG_READ) {
            return Err(VerifyError::MissingScope(SCOPE_CATALOG_READ));
        }

        // cnf.iroh_node_id binding. The contract treats *every* read-side
        // call as iroh-authenticated (the ALPN handler always provides a
        // node id), so the binding is unconditionally required.
        check_node_id_binding(claims.cnf.as_ref(), bound_node_id)?;

        // 5. authorization_details — must be present and yield at least
        //    one usable grant after filtering. We re-parse from the
        //    payload bytes because pep_check::Grant doesn't carry the
        //    contract's `fqn` field (it only surfaces RFC 9396
        //    `locations`).
        let raw_grants = parse_authorization_details(payload)?;
        let grants = filter_and_validate_grants(raw_grants)?;
        if grants.is_empty() {
            return Err(VerifyError::MissingAuthDetails);
        }

        Ok(VerifiedClaims {
            subject,
            raw_cwt: Bytes::copy_from_slice(cwt),
            cti: claims.cti.map(hex::encode).unwrap_or_default(),
            exp,
            iat,
            issuer: self.issuer.clone(),
            grants,
        })
    }
}

// --- claim decoding ---------------------------------------------------------

/// Parsed shape of the CWT claims we care about. Anything not listed here
/// is intentionally discarded.
#[derive(Default)]
struct ClaimsView {
    issuer: Option<String>,
    subject: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    cti: Option<Vec<u8>>,
    scope: Option<String>,
    cnf: Option<CborValue>,
}

fn decode_claims_map(payload: &[u8]) -> Result<ClaimsView, VerifyError> {
    let value: CborValue = ciborium::de::from_reader(payload)
        .map_err(|e| VerifyError::Parse(format!("CWT claims CBOR: {e}")))?;
    let map = match value {
        CborValue::Map(m) => m,
        _ => return Err(VerifyError::Parse("CWT claims is not a CBOR map".into())),
    };

    let mut out = ClaimsView::default();
    for (key, val) in map {
        match key {
            CborValue::Integer(i) => {
                let n: i64 = i
                    .try_into()
                    .map_err(|_| VerifyError::Parse("claim key overflow".into()))?;
                match n {
                    CLAIM_ISS => {
                        if let CborValue::Text(s) = val {
                            out.issuer = Some(s);
                        }
                    }
                    CLAIM_SUB => {
                        if let CborValue::Text(s) = val {
                            out.subject = Some(s);
                        }
                    }
                    CLAIM_IAT => out.iat = cbor_to_i64(&val),
                    CLAIM_EXP => out.exp = cbor_to_i64(&val),
                    CLAIM_CTI => {
                        if let CborValue::Bytes(b) = val {
                            out.cti = Some(b);
                        }
                    }
                    CLAIM_CNF => out.cnf = Some(val),
                    CLAIM_SCOPE => {
                        if let CborValue::Text(s) = val {
                            out.scope = Some(s);
                        }
                    }
                    _ => {}
                }
            }
            CborValue::Text(_) => {
                // The contract pins `scope` exclusively to IANA integer key 9
                // (CLAIM_SCOPE). Text-keyed claims are not part of the v1
                // contract; accepting a "scope" text key would let a
                // non-compliant issuer bypass the integer-keyed check.
                // All contract-relevant claims use integer keys — ignore
                // any text-keyed entries here.
            }
            _ => {}
        }
    }
    Ok(out)
}

fn cbor_to_i64(v: &CborValue) -> Option<i64> {
    match v {
        CborValue::Integer(i) => (*i).try_into().ok(),
        // RFC 8392 permits fractional-second timestamps. Defensive bounds:
        // reject NaN/Inf and anything outside i64 range so an attacker
        // can't backdate/forward-date a token by encoding the time field
        // as a special float.
        CborValue::Float(f) => {
            if !f.is_finite() {
                return None;
            }
            let lo = i64::MIN as f64;
            let hi = i64::MAX as f64;
            if *f < lo || *f > hi {
                return None;
            }
            Some(*f as i64)
        }
        _ => None,
    }
}

// --- channel binding --------------------------------------------------------

fn check_node_id_binding(
    cnf: Option<&CborValue>,
    bound_node_id: &str,
) -> Result<(), VerifyError> {
    let cnf = cnf.ok_or(VerifyError::MissingNodeIdBinding)?;
    let map = match cnf {
        CborValue::Map(m) => m,
        _ => return Err(VerifyError::MissingNodeIdBinding),
    };

    let mut token_bytes: Option<&Vec<u8>> = None;
    for (k, v) in map {
        if let CborValue::Text(s) = k
            && s == CNF_IROH_NODE_ID
            && let CborValue::Bytes(b) = v
        {
            token_bytes = Some(b);
            break;
        }
    }
    let token_bytes = token_bytes.ok_or(VerifyError::MissingNodeIdBinding)?;
    if token_bytes.len() != IROH_NODE_ID_LEN {
        return Err(VerifyError::MissingNodeIdBinding);
    }

    let connection_bytes = hex::decode(bound_node_id)
        .map_err(|_| VerifyError::MalformedConnectionBinding)?;
    if connection_bytes.len() != 32 {
        return Err(VerifyError::MalformedConnectionBinding);
    }

    if connection_bytes.as_slice() != token_bytes.as_slice() {
        return Err(VerifyError::NodeIdMismatch {
            token: hex::encode(token_bytes),
            connection: bound_node_id.to_string(),
        });
    }
    Ok(())
}

// --- authorization_details --------------------------------------------------

/// In-flight grant shape pulled from CWT CBOR. Carries the contract-level
/// `fqn` field that pep_check's `Grant` does not surface.
#[derive(Debug, Default)]
struct RawGrant {
    grant_type: String,
    fqn: Option<String>,
    actions: Vec<String>,
    locations: Vec<String>,
    obligations: Vec<String>,
}

/// Decode the `authorization_details` array out of the CWT payload.
///
/// We do this here (instead of calling `pep_check::parse_authorization_details`)
/// because the v1 contract uses a top-level `fqn` field that pep_check
/// drops on the floor — its `Grant` only retains the RFC 9396 standard
/// fields. Touching `pep_check` is forbidden by Task 10, so we re-implement
/// the walk and keep `fqn`.
fn parse_authorization_details(payload: &[u8]) -> Result<Vec<RawGrant>, VerifyError> {
    let value: CborValue = ciborium::de::from_reader(payload)
        .map_err(|e| VerifyError::Parse(format!("authorization_details: {e}")))?;
    let map = match value {
        CborValue::Map(m) => m,
        _ => return Ok(Vec::new()),
    };

    for (k, v) in map {
        if let CborValue::Text(name) = k
            && name == CLAIM_AUTHORIZATION_DETAILS
        {
            return parse_grants_array(v);
        }
    }
    Ok(Vec::new())
}

fn parse_grants_array(v: CborValue) -> Result<Vec<RawGrant>, VerifyError> {
    let arr = match v {
        CborValue::Array(a) => a,
        _ => {
            return Err(VerifyError::Parse(
                "authorization_details is not a CBOR array".into(),
            ));
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        if let Some(g) = parse_one_grant(entry) {
            out.push(g);
        }
    }
    Ok(out)
}

fn parse_one_grant(v: CborValue) -> Option<RawGrant> {
    let map = match v {
        CborValue::Map(m) => m,
        _ => return None,
    };
    let mut g = RawGrant::default();
    for (k, val) in map {
        let key = match k {
            CborValue::Text(s) => s,
            _ => continue,
        };
        match key.as_str() {
            "type" => {
                if let CborValue::Text(s) = val {
                    g.grant_type = s;
                }
            }
            "fqn" => {
                if let CborValue::Text(s) = val {
                    g.fqn = Some(s);
                }
            }
            "actions" => g.actions = cbor_string_array(&val),
            "locations" => g.locations = cbor_string_array(&val),
            "obligations" => g.obligations = cbor_string_array(&val),
            _ => {}
        }
    }
    Some(g)
}

fn cbor_string_array(v: &CborValue) -> Vec<String> {
    match v {
        CborValue::Array(a) => a
            .iter()
            .filter_map(|e| match e {
                CborValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Apply the v1 type / action allowlist.
///
/// - Drop grants whose `type` is not `"tdf_attribute"` — silently, per
///   contract A.7 (additive new types should not break v1 clients).
/// - Drop grants without a parseable `fqn` — per contract A.6 ("fqn not
///   parseable as a URL: skip that entry"). We only check non-empty here;
///   strict URL validation lives in the PDP layer.
/// - Reject the **whole token** if any surviving grant lists an action
///   not in the v1 allowlist (`["read"]`).
fn filter_and_validate_grants(raw: Vec<RawGrant>) -> Result<Vec<Grant>, VerifyError> {
    let mut out = Vec::with_capacity(raw.len());
    for g in raw {
        if g.grant_type != GRANT_TYPE_TDF_ATTRIBUTE {
            continue;
        }
        for action in &g.actions {
            if action != ACTION_READ {
                return Err(VerifyError::UnknownAction);
            }
        }
        let Some(fqn) = g.fqn.filter(|s| !s.is_empty()) else {
            continue;
        };
        out.push(Grant {
            fqn,
            actions: g.actions,
            locations: g.locations,
            obligations: g.obligations,
        });
    }
    Ok(out)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
