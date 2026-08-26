//! CWT (RFC 8392) bearer-token verification against identity.arkavo.net.
//!
//! Tag writes on the HTTP API are authenticated with Arkavo-issued CWTs:
//! CBOR tag #6.61 wrapping a COSE_Sign1 (ES256), transported as unpadded
//! base64url. Verification keys are fetched from the IdP's
//! `/.well-known/cose-keys` endpoint (a CBOR array of COSE_Keys, the same
//! key set advertised via `arkavo_cose_keys_uri` in the OIDC discovery
//! document) and cached; an unknown `kid` triggers one rate-limited
//! refetch in case the IdP rotated keys.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use coset::{AsCborValue, CborSerializable};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// CBOR encoding of tag #6.61 (CWT, RFC 8392 §6).
const CWT_TAG_PREFIX: [u8; 2] = [0xD8, 0x3D];

/// Clock-skew tolerance for exp/iat checks. Expiry is `exp <= now - 60`.
const SKEW_SECS: i64 = 60;

/// DeviceCheck assertion audience (draft-arkavo-authzen-cwt-00).
pub const DEVICECHECK_AUD: &str = "arkavo:devicecheck";

/// Strip a single leading `arkavo:` prefix. Does not strip `apple:` or `client:`.
pub fn subject_id_bind(s: &str) -> &str {
    s.strip_prefix("arkavo:").unwrap_or(s)
}

/// Minimum interval between key-set refetches, so a flood of bad-kid
/// tokens cannot turn this node into an IdP load generator.
const KEY_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Hard bound on the IdP key-set fetch — a hung IdP must not wedge
/// token verification.
const KEY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm (ES256 required)")]
    Algorithm,
    #[error("unknown key id")]
    UnknownKid,
    #[error("signature verification failed")]
    Signature,
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("required claim missing: {0}")]
    MissingClaim(&'static str),
    #[error("issuer mismatch")]
    Issuer,
    #[error("audience mismatch")]
    Audience,
    #[error("duplicate claim key")]
    DuplicateKey,
    #[error("key set unavailable: {0}")]
    KeySet(String),
}

/// CWT `aud` (RFC 8392): a single tstr or an array of tstr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aud {
    One(String),
    Many(Vec<String>),
}

impl Aud {
    pub fn contains(&self, want: &str) -> bool {
        match self {
            Aud::One(s) => s == want,
            Aud::Many(v) => v.iter().any(|s| s == want),
        }
    }

    /// String form used by the device allowlist (`aud` is a JSON string).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Aud::One(s) => Some(s.as_str()),
            Aud::Many(v) if v.len() == 1 => Some(v[0].as_str()),
            _ => None,
        }
    }
}

/// Optional checks layered on top of signature / required-claim verification.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyOpts<'a> {
    pub expected_aud: Option<&'a str>,
}

/// The subset of CWT claims the tag and catalog APIs need.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Aud,
    pub exp: i64,
    pub iat: i64,
    pub cti: Vec<u8>,
    /// unpadded base64url of `cnf.kid`, when the token carries a confirmation key.
    pub kid: Option<String>,
    /// `arkavo_patreon.patreon_user_id`, when the token carries the
    /// membership claim — the identifier the platform's Patreon ERS
    /// resolves directly.
    pub patreon_user_id: Option<String>,
    /// `email` claim, when present (the ERS's fallback lookup key).
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub idp: Option<String>,
    pub arkavo_account_id: Option<String>,
    pub arkavo_roles: Option<Vec<String>>,
    pub arkavo_entitlements: Option<Vec<String>>,
    pub client_id: Option<String>,
    /// The full verified `arkavo_patreon` claim as JSON (role,
    /// patreon_user_id, campaign_id, memberships[…]), so the catalog node
    /// can forward it verbatim to the platform's claims-passthrough — which
    /// derives campaign-qualified entitlements from the memberships array.
    /// None when the token carries no Patreon claim.
    pub arkavo_patreon: Option<serde_json::Value>,
}

struct KeyCache {
    keys: HashMap<Vec<u8>, VerifyingKey>,
    last_fetch: Option<Instant>,
}

pub struct CwtVerifier {
    cose_keys_url: Option<String>,
    expected_iss: Option<String>,
    http: reqwest::Client,
    cache: RwLock<KeyCache>,
}

fn bounded_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(KEY_FETCH_TIMEOUT)
        .build()
        .expect("reqwest client")
}

impl CwtVerifier {
    /// Verifier that fetches (and refreshes) keys from a COSE key set URL.
    /// When `expected_iss` is set, tokens minted by any other issuer are
    /// rejected even if their signature verifies.
    pub fn new(cose_keys_url: String, expected_iss: Option<String>) -> Self {
        Self {
            cose_keys_url: Some(cose_keys_url),
            expected_iss,
            http: bounded_http_client(),
            cache: RwLock::new(KeyCache {
                keys: HashMap::new(),
                last_fetch: None,
            }),
        }
    }

    /// Verifier with a fixed key set and no network fetching (tests, or
    /// air-gapped deployments with pinned keys).
    pub fn with_static_keys(keys: Vec<(Vec<u8>, VerifyingKey)>) -> Self {
        Self {
            cose_keys_url: None,
            expected_iss: None,
            http: bounded_http_client(),
            cache: RwLock::new(KeyCache {
                keys: keys.into_iter().collect(),
                last_fetch: None,
            }),
        }
    }

    /// Require a specific `iss` claim on every accepted token.
    #[must_use]
    pub fn with_expected_issuer(mut self, iss: String) -> Self {
        self.expected_iss = Some(iss);
        self
    }

    /// Verify a base64url(no pad) CWT and return its claims.
    /// PE tokens use this path: issuer pin only, no audience pin.
    pub async fn verify(&self, token_b64: &str, now: i64) -> Result<VerifiedClaims, AuthError> {
        self.verify_with(token_b64, now, VerifyOpts::default())
            .await
    }

    /// DeviceCheck CWT: after signature verify, `aud` MUST be
    /// `arkavo:devicecheck` and `cnf.kid` MUST be present.
    pub async fn verify_device(
        &self,
        token_b64: &str,
        now: i64,
    ) -> Result<VerifiedClaims, AuthError> {
        let claims = self
            .verify_with(
                token_b64,
                now,
                VerifyOpts {
                    expected_aud: Some(DEVICECHECK_AUD),
                },
            )
            .await?;
        // Device schema `aud` is a single string equal to the DeviceCheck audience.
        match claims.aud.as_str() {
            Some(a) if a == DEVICECHECK_AUD => {}
            _ => return Err(AuthError::Audience),
        }
        if claims.kid.as_ref().is_none_or(|k| k.is_empty()) {
            return Err(AuthError::MissingClaim("kid"));
        }
        Ok(claims)
    }

    pub async fn verify_with(
        &self,
        token_b64: &str,
        now: i64,
        opts: VerifyOpts<'_>,
    ) -> Result<VerifiedClaims, AuthError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token_b64.trim())
            .map_err(|_| AuthError::Malformed)?;

        // Strict: input MUST carry the CWT tag, mirroring authnz-rs.
        let inner = bytes
            .strip_prefix(&CWT_TAG_PREFIX[..])
            .ok_or(AuthError::Malformed)?;
        let sign1 = coset::CoseSign1::from_slice(inner).map_err(|_| AuthError::Malformed)?;

        match sign1.protected.header.alg {
            Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256)) => {}
            _ => return Err(AuthError::Algorithm),
        }
        let kid = sign1.protected.header.key_id.clone();
        if kid.is_empty() {
            return Err(AuthError::UnknownKid);
        }

        let key = match self.lookup(&kid).await {
            Some(k) => k,
            None => {
                // Unknown kid — the IdP may have rotated keys.
                self.refresh_keys().await?;
                self.lookup(&kid).await.ok_or(AuthError::UnknownKid)?
            }
        };

        sign1
            .verify_signature(b"", |sig, data| {
                let sig = Signature::from_slice(sig).map_err(|_| ())?;
                key.verify(data, &sig).map_err(|_| ())
            })
            .map_err(|_| AuthError::Signature)?;

        let payload = sign1.payload.as_deref().ok_or(AuthError::Malformed)?;
        let claims = parse_claims(payload)?;

        if let Some(expected) = &self.expected_iss
            && &claims.iss != expected
        {
            return Err(AuthError::Issuer);
        }
        if let Some(want) = opts.expected_aud
            && !claims.aud.contains(want)
        {
            return Err(AuthError::Audience);
        }
        if claims.iat > claims.exp {
            return Err(AuthError::Malformed);
        }
        if claims.exp <= now - SKEW_SECS {
            return Err(AuthError::Expired);
        }
        if claims.iat > now + SKEW_SECS {
            return Err(AuthError::NotYetValid);
        }
        Ok(claims)
    }

    async fn lookup(&self, kid: &[u8]) -> Option<VerifyingKey> {
        self.cache.read().await.keys.get(kid).copied()
    }

    async fn refresh_keys(&self) -> Result<(), AuthError> {
        let Some(url) = &self.cose_keys_url else {
            // Static key set — nothing to refresh.
            return Ok(());
        };

        // Claim the refresh slot under the write lock, but do NOT hold the
        // lock across the network fetch — concurrent verifications must keep
        // reading the current key set, and a slow/hung IdP must not wedge
        // the whole API. The rate-limit stamp doubles as the stampede guard.
        {
            let mut cache = self.cache.write().await;
            if let Some(last) = cache.last_fetch
                && last.elapsed() < KEY_REFRESH_MIN_INTERVAL
            {
                return Ok(());
            }
            cache.last_fetch = Some(Instant::now());
        }

        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| AuthError::KeySet(format!("GET {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(AuthError::KeySet(format!(
                "GET {url}: HTTP {}",
                resp.status()
            )));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| AuthError::KeySet(format!("read body: {e}")))?;

        let keys = parse_cose_key_set(&body)
            .map_err(|e| AuthError::KeySet(format!("parse key set: {e}")))?;
        info!(count = keys.len(), "Refreshed COSE key set from IdP");
        self.cache.write().await.keys = keys.into_iter().collect();
        Ok(())
    }
}

/// Parse a CBOR COSE_Key Set (array of COSE_Keys) into kid → P-256 key.
fn parse_cose_key_set(bytes: &[u8]) -> anyhow::Result<Vec<(Vec<u8>, VerifyingKey)>> {
    let value: Value = ciborium::de::from_reader(bytes)?;
    let Value::Array(entries) = value else {
        anyhow::bail!("key set is not a CBOR array");
    };

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = match coset::CoseKey::from_cbor_value(entry) {
            Ok(k) => k,
            Err(e) => {
                warn!("Skipping unparseable COSE key in set: {e:?}");
                continue;
            }
        };
        match p256_from_cose_key(&key) {
            Ok(vk) if !key.key_id.is_empty() => out.push((key.key_id.clone(), vk)),
            Ok(_) => warn!("Skipping COSE key without kid"),
            Err(e) => warn!("Skipping non-P-256 COSE key: {e}"),
        }
    }
    if out.is_empty() {
        anyhow::bail!("no usable P-256 keys in key set");
    }
    Ok(out)
}

/// Extract a P-256 verifying key from an EC2 COSE_Key.
fn p256_from_cose_key(key: &coset::CoseKey) -> anyhow::Result<VerifyingKey> {
    use coset::iana::{Ec2KeyParameter, EnumI64};

    if key.kty != coset::KeyType::Assigned(coset::iana::KeyType::EC2) {
        anyhow::bail!("kty is not EC2");
    }

    let mut x: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    let mut crv_ok = false;
    for (label, value) in &key.params {
        match label {
            coset::Label::Int(l) if *l == Ec2KeyParameter::Crv as i64 => {
                crv_ok = matches!(
                    value,
                    Value::Integer(i)
                        if i128::from(*i) == i128::from(coset::iana::EllipticCurve::P_256.to_i64())
                );
            }
            coset::Label::Int(l) if *l == Ec2KeyParameter::X as i64 => {
                if let Value::Bytes(b) = value {
                    x = Some(b);
                }
            }
            coset::Label::Int(l) if *l == Ec2KeyParameter::Y as i64 => {
                if let Value::Bytes(b) = value {
                    y = Some(b);
                }
            }
            _ => {}
        }
    }
    if !crv_ok {
        anyhow::bail!("crv is not P-256");
    }
    let (x, y) = (
        x.ok_or_else(|| anyhow::anyhow!("missing x"))?,
        y.ok_or_else(|| anyhow::anyhow!("missing y"))?,
    );
    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!("x/y are not 32 bytes");
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    Ok(VerifyingKey::from_sec1_bytes(&sec1)?)
}

/// Parse the CWT claims map (RFC 8392 integer labels + Arkavo text claims).
fn parse_claims(payload: &[u8]) -> Result<VerifiedClaims, AuthError> {
    let value: Value = ciborium::de::from_reader(payload).map_err(|_| AuthError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(AuthError::Malformed);
    };

    let mut seen = HashSet::new();
    let mut iss = None;
    let mut sub = None;
    let mut aud = None;
    let mut exp = None;
    let mut iat = None;
    let mut cti = None;
    let mut kid = None;
    let mut patreon_user_id = None;
    let mut email = None;
    let mut email_verified = None;
    let mut idp = None;
    let mut arkavo_account_id = None;
    let mut arkavo_roles = None;
    let mut arkavo_entitlements = None;
    let mut client_id = None;
    let mut arkavo_patreon = None;
    for (k, v) in entries {
        let key_id = match &k {
            Value::Integer(i) => format!("i:{}", i128::from(*i)),
            Value::Text(t) => format!("t:{t}"),
            _ => return Err(AuthError::Malformed),
        };
        if !seen.insert(key_id) {
            return Err(AuthError::DuplicateKey);
        }
        match k {
            Value::Integer(key) => match (i128::from(key), v) {
                (1, Value::Text(s)) => iss = Some(s),
                (2, Value::Text(s)) => sub = Some(s),
                (3, Value::Text(s)) => aud = Some(Aud::One(s)),
                (3, Value::Array(a)) => {
                    let mut members = Vec::with_capacity(a.len());
                    for item in a {
                        let Value::Text(s) = item else {
                            return Err(AuthError::Malformed);
                        };
                        members.push(s);
                    }
                    if members.is_empty() {
                        return Err(AuthError::MissingClaim("aud"));
                    }
                    aud = Some(Aud::Many(members));
                }
                (4, Value::Integer(n)) => exp = i64::try_from(i128::from(n)).ok(),
                (6, Value::Integer(n)) => iat = i64::try_from(i128::from(n)).ok(),
                (7, Value::Bytes(b)) => cti = Some(b),
                (8, Value::Map(m)) => kid = parse_cnf_kid(&m)?,
                _ => {}
            },
            Value::Text(key) => match (key.as_str(), v) {
                ("email", Value::Text(s)) => email = Some(s),
                ("email_verified", Value::Bool(b)) => email_verified = Some(b),
                ("idp", Value::Text(s)) => idp = Some(s),
                ("arkavo_account_id", Value::Text(s)) => arkavo_account_id = Some(s),
                ("client_id", Value::Text(s)) => client_id = Some(s),
                ("arkavo_roles", Value::Array(a)) => arkavo_roles = Some(text_array(a)?),
                ("arkavo_entitlements", Value::Array(a)) => {
                    arkavo_entitlements = Some(text_array(a)?);
                }
                ("arkavo_patreon", patreon @ Value::Map(_)) => {
                    // Keep the whole claim as JSON for forwarding, and pull
                    // patreon_user_id out of it for the token-mode fallback.
                    let json = cbor_to_json(&patreon);
                    patreon_user_id = json
                        .get("patreon_user_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    arkavo_patreon = Some(json);
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(VerifiedClaims {
        iss: iss.ok_or(AuthError::MissingClaim("iss"))?,
        sub: sub.ok_or(AuthError::MissingClaim("sub"))?,
        aud: aud.ok_or(AuthError::MissingClaim("aud"))?,
        exp: exp.ok_or(AuthError::MissingClaim("exp"))?,
        iat: iat.ok_or(AuthError::MissingClaim("iat"))?,
        cti: cti.ok_or(AuthError::MissingClaim("cti"))?,
        kid,
        patreon_user_id,
        email,
        email_verified,
        idp,
        arkavo_account_id,
        arkavo_roles,
        arkavo_entitlements,
        client_id,
        arkavo_patreon,
    })
}

fn text_array(a: Vec<Value>) -> Result<Vec<String>, AuthError> {
    a.into_iter()
        .map(|v| match v {
            Value::Text(s) => Ok(s),
            _ => Err(AuthError::Malformed),
        })
        .collect()
}

/// `cnf` (claim 8): confirmation kid as unpadded base64url.
/// authnz-rs encodes kid at map key 2 (bytes); RFC 8747 kid is 3.
fn parse_cnf_kid(map: &[(Value, Value)]) -> Result<Option<String>, AuthError> {
    let mut seen = HashSet::new();
    let mut kid_bytes: Option<Vec<u8>> = None;
    let mut cose_kid: Option<Vec<u8>> = None;
    for (k, v) in map {
        let Value::Integer(i) = k else {
            continue;
        };
        let key_id = format!("i:{}", i128::from(*i));
        if !seen.insert(key_id) {
            return Err(AuthError::DuplicateKey);
        }
        match (k, v) {
            (Value::Integer(n), Value::Bytes(b)) if matches!(i128::from(*n), 2 | 3) => {
                kid_bytes = Some(b.clone());
            }
            (Value::Integer(n), val) if i128::from(*n) == 1 => {
                if let Ok(key) = coset::CoseKey::from_cbor_value(val.clone())
                    && !key.key_id.is_empty()
                {
                    cose_kid = Some(key.key_id);
                }
            }
            _ => {}
        }
    }
    let bytes = kid_bytes.or(cose_kid).filter(|b| !b.is_empty());
    Ok(bytes.map(|b| URL_SAFE_NO_PAD.encode(b)))
}

/// Convert a CBOR value (as it appears in a CWT claim) to JSON for
/// forwarding. Conversions are lossless: integers outside i64 fall back to
/// u64 then to a decimal string (rather than silently becoming null), and an
/// unexpected CBOR type (bytes, float, tag) is preserved as a string with a
/// warning so a future schema change surfaces instead of dropping data.
fn cbor_to_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Text(s) => J::String(s.clone()),
        Value::Integer(n) => {
            let i: i128 = (*n).into();
            if let Ok(small) = i64::try_from(i) {
                J::from(small)
            } else if let Ok(big) = u64::try_from(i) {
                J::from(big)
            } else {
                // Beyond u64 (rare): keep the exact value as a string.
                J::String(i.to_string())
            }
        }
        Value::Bool(b) => J::Bool(*b),
        Value::Null => J::Null,
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(J::Number)
            .unwrap_or(J::Null),
        Value::Bytes(b) => {
            use base64::Engine;
            J::String(base64::engine::general_purpose::STANDARD.encode(b))
        }
        Value::Array(a) => J::Array(a.iter().map(cbor_to_json).collect()),
        Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in m {
                if let Value::Text(key) = k {
                    obj.insert(key.clone(), cbor_to_json(val));
                }
            }
            J::Object(obj)
        }
        other => {
            warn!("cbor_to_json: unexpected CBOR type in claim, stringifying: {other:?}");
            J::String(format!("{other:?}"))
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Mint Arkavo-compatible CWTs for tests, mirroring authnz-rs `cwt::mint`.

    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use coset::{CoseSign1Builder, HeaderBuilder, iana};
    use p256::ecdsa::{SigningKey, signature::Signer};

    pub fn mint(key: &SigningKey, kid: &[u8], iss: &str, sub: &str, iat: i64, exp: i64) -> String {
        mint_with_extras(key, kid, iss, sub, iat, exp, &[])
    }

    /// Mint with additional text-keyed claims, e.g. an `arkavo_patreon` map.
    /// `aud` defaults to `"arkavo"`; `cti` is 16 zero bytes.
    pub fn mint_with_extras(
        key: &SigningKey,
        kid: &[u8],
        iss: &str,
        sub: &str,
        iat: i64,
        exp: i64,
        extras: &[(&str, Value)],
    ) -> String {
        mint_with_aud(key, kid, iss, sub, "arkavo", iat, exp, extras)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint_with_aud(
        key: &SigningKey,
        kid: &[u8],
        iss: &str,
        sub: &str,
        aud: &str,
        iat: i64,
        exp: i64,
        extras: &[(&str, Value)],
    ) -> String {
        let mut entries = standard_claims(iss, sub, aud, iat, exp, &[0u8; 16]);
        for (k, v) in extras {
            entries.push((Value::Text((*k).into()), v.clone()));
        }
        mint_map(key, kid, entries)
    }

    /// DeviceCheck assertion CWT: `aud=arkavo:devicecheck` and `cnf.kid`.
    pub fn mint_devicecheck(
        key: &SigningKey,
        kid: &[u8],
        iss: &str,
        sub: &str,
        iat: i64,
        exp: i64,
        cnf_kid: &[u8],
    ) -> String {
        let mut entries = standard_claims(iss, sub, DEVICECHECK_AUD, iat, exp, &[0u8; 16]);
        let cnf = Value::Map(vec![(
            Value::Integer(2.into()),
            Value::Bytes(cnf_kid.to_vec()),
        )]);
        entries.push((Value::Integer(8.into()), cnf));
        mint_map(key, kid, entries)
    }

    fn standard_claims(
        iss: &str,
        sub: &str,
        aud: &str,
        iat: i64,
        exp: i64,
        cti: &[u8],
    ) -> Vec<(Value, Value)> {
        vec![
            (Value::Integer(1.into()), Value::Text(iss.into())),
            (Value::Integer(2.into()), Value::Text(sub.into())),
            (Value::Integer(3.into()), Value::Text(aud.into())),
            (Value::Integer(4.into()), Value::Integer(exp.into())),
            (Value::Integer(6.into()), Value::Integer(iat.into())),
            (Value::Integer(7.into()), Value::Bytes(cti.to_vec())),
        ]
    }

    pub fn mint_map(key: &SigningKey, kid: &[u8], entries: Vec<(Value, Value)>) -> String {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut payload).unwrap();

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(kid.to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |to_sign| {
                let sig: Signature = key.sign(to_sign);
                sig.to_bytes().to_vec()
            })
            .build();

        let inner = sign1.to_vec().unwrap();
        let mut out = Vec::with_capacity(CWT_TAG_PREFIX.len() + inner.len());
        out.extend_from_slice(&CWT_TAG_PREFIX);
        out.extend_from_slice(&inner);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// Deterministic test keypair (p256 0.13 wants rand_core 0.6, which the
    /// crate's rand 0.9 doesn't provide — fixed scalars avoid the mismatch).
    pub fn keypair_from(seed: u8) -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_slice(&[seed; 32]).expect("valid scalar");
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    pub fn keypair() -> (SigningKey, VerifyingKey) {
        keypair_from(0x17)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::{keypair, mint, mint_devicecheck, mint_map, mint_with_aud};

    const NOW: i64 = 1_900_000_000;

    fn verifier(kid: &[u8], vk: VerifyingKey) -> CwtVerifier {
        CwtVerifier::with_static_keys(vec![(kid.to_vec(), vk)])
    }

    #[tokio::test]
    async fn verify_roundtrip() {
        let (sk, vk) = keypair();
        let token = mint(
            &sk,
            b"kid-1",
            "https://identity.test",
            "arkavo:u1",
            NOW,
            NOW + 3600,
        );
        let claims = verifier(b"kid-1", vk).verify(&token, NOW).await.unwrap();
        assert_eq!(claims.sub, "arkavo:u1");
        assert_eq!(claims.iss, "https://identity.test");
    }

    #[tokio::test]
    async fn rejects_expired() {
        let (sk, vk) = keypair();
        let token = mint(&sk, b"kid-1", "i", "s", NOW - 7200, NOW - 3600);
        let err = verifier(b"kid-1", vk)
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Expired));
    }

    #[tokio::test]
    async fn rejects_wrong_issuer() {
        let (sk, vk) = keypair();
        let token = mint(
            &sk,
            b"kid-1",
            "https://evil.test",
            "arkavo:u1",
            NOW,
            NOW + 3600,
        );
        let err = verifier(b"kid-1", vk)
            .with_expected_issuer("https://identity.test".into())
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Issuer));

        // Matching issuer still verifies.
        let token = mint(
            &sk,
            b"kid-1",
            "https://identity.test",
            "arkavo:u1",
            NOW,
            NOW + 3600,
        );
        let claims = verifier(b"kid-1", vk)
            .with_expected_issuer("https://identity.test".into())
            .verify(&token, NOW)
            .await
            .unwrap();
        assert_eq!(claims.sub, "arkavo:u1");
    }

    #[tokio::test]
    async fn parses_patreon_and_email_claims() {
        let (sk, vk) = keypair();
        let patreon = Value::Map(vec![
            (Value::Text("role".into()), Value::Text("consumer".into())),
            (
                Value::Text("patreon_user_id".into()),
                Value::Text("p-9000".into()),
            ),
        ]);
        let token = test_support::mint_with_extras(
            &sk,
            b"kid-1",
            "https://identity.test",
            "arkavo:u1",
            NOW,
            NOW + 3600,
            &[
                ("arkavo_patreon", patreon),
                ("email", Value::Text("a@b.test".into())),
            ],
        );
        let claims = verifier(b"kid-1", vk).verify(&token, NOW).await.unwrap();
        assert_eq!(claims.patreon_user_id.as_deref(), Some("p-9000"));
        assert_eq!(claims.email.as_deref(), Some("a@b.test"));
        // The full claim is surfaced as JSON for forwarding.
        let ap = claims.arkavo_patreon.as_ref().expect("arkavo_patreon json");
        assert_eq!(ap["role"], "consumer");
        assert_eq!(ap["patreon_user_id"], "p-9000");

        // Memberships array (incl. tier_slugs) round-trips through CBOR->JSON.
        let memberships = Value::Array(vec![Value::Map(vec![
            (
                Value::Text("campaign_id".into()),
                Value::Text("11111111".into()),
            ),
            (
                Value::Text("patron_status".into()),
                Value::Text("active_patron".into()),
            ),
            (
                Value::Text("tier_slugs".into()),
                Value::Array(vec![Value::Text("gold-tier".into())]),
            ),
        ])]);
        let full = Value::Map(vec![
            (Value::Text("role".into()), Value::Text("consumer".into())),
            (
                Value::Text("patreon_user_id".into()),
                Value::Text("p-1".into()),
            ),
            (Value::Text("memberships".into()), memberships),
        ]);
        let token = test_support::mint_with_extras(
            &sk,
            b"kid-1",
            "i",
            "s",
            NOW,
            NOW + 3600,
            &[("arkavo_patreon", full)],
        );
        let claims = verifier(b"kid-1", vk).verify(&token, NOW).await.unwrap();
        let ap = claims.arkavo_patreon.unwrap();
        assert_eq!(ap["memberships"][0]["campaign_id"], "11111111");
        assert_eq!(ap["memberships"][0]["patron_status"], "active_patron");
        assert_eq!(ap["memberships"][0]["tier_slugs"][0], "gold-tier");

        // Tokens without the claim parse with None — not an error.
        let plain = mint(&sk, b"kid-1", "i", "s", NOW, NOW + 3600);
        let claims = verifier(b"kid-1", vk).verify(&plain, NOW).await.unwrap();
        assert!(claims.patreon_user_id.is_none());
        assert!(claims.email.is_none());
    }

    #[test]
    fn cbor_to_json_is_lossless_for_large_ints() {
        use ciborium::value::Value as C;
        // u64 beyond i64::MAX must not become null.
        let big = C::Integer((u64::MAX).into());
        assert_eq!(cbor_to_json(&big), serde_json::json!(u64::MAX));
        // small int, bool, nested map.
        let m = C::Map(vec![
            (C::Text("n".into()), C::Integer(42.into())),
            (C::Text("b".into()), C::Bool(true)),
        ]);
        let j = cbor_to_json(&m);
        assert_eq!(j["n"], 42);
        assert_eq!(j["b"], true);
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let (sk, vk) = keypair();
        let token = mint(&sk, b"other-kid", "i", "s", NOW, NOW + 3600);
        let err = verifier(b"kid-1", vk)
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::UnknownKid));
    }

    #[tokio::test]
    async fn rejects_wrong_key_signature() {
        let (sk, _) = keypair();
        let (_, other_vk) = test_support::keypair_from(0x42);
        let token = mint(&sk, b"kid-1", "i", "s", NOW, NOW + 3600);
        let err = verifier(b"kid-1", other_vk)
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Signature));
    }

    #[tokio::test]
    async fn rejects_untagged_cose_sign1() {
        use base64::Engine;
        let (sk, vk) = keypair();
        let token = mint(&sk, b"kid-1", "i", "s", NOW, NOW + 3600);
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .unwrap();
        // Strip the CWT tag → bare COSE_Sign1 must be rejected.
        let untagged = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[2..]);
        let err = verifier(b"kid-1", vk)
            .verify(&untagged, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Malformed));
    }

    #[test]
    fn key_set_roundtrip() {
        // Build a key set the way authnz-rs's /.well-known/cose-keys does:
        // CBOR array of COSE_Keys (EC2, P-256, ES256, kid).
        use coset::AsCborValue;
        let (_, vk) = keypair();
        let point = vk.to_encoded_point(false);
        let cose_key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .key_id(b"kid-1".to_vec())
        .build();

        let set = Value::Array(vec![cose_key.to_cbor_value().unwrap()]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&set, &mut bytes).unwrap();

        let keys = parse_cose_key_set(&bytes).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, b"kid-1".to_vec());
        assert_eq!(keys[0].1, vk);
    }

    #[test]
    fn subject_id_bind_strips_only_arkavo_prefix() {
        assert_eq!(
            subject_id_bind("arkavo:550e8400-e29b-41d4-a716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            subject_id_bind("550e8400-e29b-41d4-a716-446655440000"),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(subject_id_bind("apple:abc"), "apple:abc");
        assert_eq!(
            subject_id_bind("client:catalog-node"),
            "client:catalog-node"
        );
    }

    #[tokio::test]
    async fn verify_requires_aud_and_cti() {
        let (sk, vk) = keypair();
        let v = verifier(b"kid-1", vk);
        let missing_aud = mint_map(
            &sk,
            b"kid-1",
            vec![
                (Value::Integer(1.into()), Value::Text("i".into())),
                (Value::Integer(2.into()), Value::Text("s".into())),
                (
                    Value::Integer(4.into()),
                    Value::Integer((NOW + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(NOW.into())),
                (Value::Integer(7.into()), Value::Bytes(vec![0u8; 16])),
            ],
        );
        assert!(matches!(
            v.verify(&missing_aud, NOW).await.unwrap_err(),
            AuthError::MissingClaim("aud")
        ));
        let missing_cti = mint_map(
            &sk,
            b"kid-1",
            vec![
                (Value::Integer(1.into()), Value::Text("i".into())),
                (Value::Integer(2.into()), Value::Text("s".into())),
                (Value::Integer(3.into()), Value::Text("arkavo".into())),
                (
                    Value::Integer(4.into()),
                    Value::Integer((NOW + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(NOW.into())),
            ],
        );
        assert!(matches!(
            v.verify(&missing_cti, NOW).await.unwrap_err(),
            AuthError::MissingClaim("cti")
        ));
    }

    #[tokio::test]
    async fn rejects_expired_at_inclusive_skew() {
        let (sk, vk) = keypair();
        let token = mint(&sk, b"kid-1", "i", "s", NOW - 120, NOW - 60);
        let err = verifier(b"kid-1", vk)
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Expired));
    }

    #[tokio::test]
    async fn rejects_iat_after_exp() {
        let (sk, vk) = keypair();
        let token = mint(&sk, b"kid-1", "i", "s", NOW + 10, NOW);
        let err = verifier(b"kid-1", vk)
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Malformed));
    }

    #[tokio::test]
    async fn rejects_duplicate_claim_keys() {
        let (sk, vk) = keypair();
        let token = mint_map(
            &sk,
            b"kid-1",
            vec![
                (
                    Value::Integer(1.into()),
                    Value::Text("https://identity.test".into()),
                ),
                (
                    Value::Integer(1.into()),
                    Value::Text("https://evil.test".into()),
                ),
                (Value::Integer(2.into()), Value::Text("arkavo:u1".into())),
                (Value::Integer(3.into()), Value::Text("arkavo".into())),
                (
                    Value::Integer(4.into()),
                    Value::Integer((NOW + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(NOW.into())),
                (Value::Integer(7.into()), Value::Bytes(vec![1u8; 16])),
            ],
        );
        let err = verifier(b"kid-1", vk)
            .verify(&token, NOW)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::DuplicateKey));
    }

    #[tokio::test]
    async fn pe_cnf_ignores_unknown_keys() {
        let (sk, vk) = keypair();
        let cnf = Value::Map(vec![(
            Value::Text("x".into()),
            Value::Text("ignored".into()),
        )]);
        let token = mint_map(
            &sk,
            b"kid-1",
            vec![
                (Value::Integer(1.into()), Value::Text("i".into())),
                (Value::Integer(2.into()), Value::Text("s".into())),
                (Value::Integer(3.into()), Value::Text("arkavo".into())),
                (
                    Value::Integer(4.into()),
                    Value::Integer((NOW + 3600).into()),
                ),
                (Value::Integer(6.into()), Value::Integer(NOW.into())),
                (Value::Integer(7.into()), Value::Bytes(vec![0u8; 16])),
                (Value::Integer(8.into()), cnf),
            ],
        );
        let claims = verifier(b"kid-1", vk).verify(&token, NOW).await.unwrap();
        assert!(claims.kid.is_none());
    }

    #[tokio::test]
    async fn device_token_requires_devicecheck_aud_and_kid() {
        let (sk, vk) = keypair();
        let v = verifier(b"kid-1", vk);
        let ok = mint_devicecheck(
            &sk,
            b"kid-1",
            "https://identity.test",
            "550e8400-e29b-41d4-a716-446655440000",
            NOW,
            NOW + 3600,
            b"phone-kid",
        );
        let claims = v.verify_device(&ok, NOW).await.unwrap();
        assert_eq!(claims.aud.as_str(), Some(DEVICECHECK_AUD));
        assert_eq!(claims.kid.as_deref(), Some("cGhvbmUta2lk"));

        let wrong_aud = mint_with_aud(
            &sk,
            b"kid-1",
            "https://identity.test",
            "550e8400-e29b-41d4-a716-446655440000",
            "arkavo",
            NOW,
            NOW + 3600,
            &[],
        );
        assert!(matches!(
            v.verify_device(&wrong_aud, NOW).await.unwrap_err(),
            AuthError::Audience
        ));

        let no_cnf = mint_with_aud(
            &sk,
            b"kid-1",
            "https://identity.test",
            "550e8400-e29b-41d4-a716-446655440000",
            DEVICECHECK_AUD,
            NOW,
            NOW + 3600,
            &[],
        );
        assert!(matches!(
            v.verify_device(&no_cnf, NOW).await.unwrap_err(),
            AuthError::MissingClaim("kid")
        ));
    }
}
