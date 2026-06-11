//! CWT (RFC 8392) bearer-token verification against identity.arkavo.net.
//!
//! Tag writes on the HTTP API are authenticated with Arkavo-issued CWTs:
//! CBOR tag #6.61 wrapping a COSE_Sign1 (ES256), transported as unpadded
//! base64url. Verification keys are fetched from the IdP's
//! `/.well-known/cose-keys` endpoint (a CBOR array of COSE_Keys, the same
//! key set advertised via `arkavo_cose_keys_uri` in the OIDC discovery
//! document) and cached; an unknown `kid` triggers one rate-limited
//! refetch in case the IdP rotated keys.

use ciborium::value::Value;
use coset::{AsCborValue, CborSerializable};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// CBOR encoding of tag #6.61 (CWT, RFC 8392 §6).
const CWT_TAG_PREFIX: [u8; 2] = [0xD8, 0x3D];

/// Clock-skew tolerance for exp/iat checks.
const SKEW_SECS: i64 = 60;

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
    #[error("key set unavailable: {0}")]
    KeySet(String),
}

/// The subset of CWT claims the tag and catalog APIs need.
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    pub iss: String,
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    /// `arkavo_patreon.patreon_user_id`, when the token carries the
    /// membership claim — the identifier the platform's Patreon ERS
    /// resolves directly.
    pub patreon_user_id: Option<String>,
    /// `email` claim, when present (the ERS's fallback lookup key).
    pub email: Option<String>,
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
    pub async fn verify(&self, token_b64: &str, now: i64) -> Result<VerifiedClaims, AuthError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
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

        if claims.exp < now - SKEW_SECS {
            return Err(AuthError::Expired);
        }
        if claims.iat > now + SKEW_SECS {
            return Err(AuthError::NotYetValid);
        }
        // Issuer pinning: a key in the trusted set is necessary but not
        // sufficient — tokens minted by a different issuer (or for an
        // unrelated purpose by a co-located IdP) are refused.
        if let Some(expected) = &self.expected_iss
            && &claims.iss != expected
        {
            return Err(AuthError::Issuer);
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

/// Parse the CWT claims map: 1 = iss, 2 = sub, 4 = exp, 6 = iat.
fn parse_claims(payload: &[u8]) -> Result<VerifiedClaims, AuthError> {
    let value: Value = ciborium::de::from_reader(payload).map_err(|_| AuthError::Malformed)?;
    let Value::Map(entries) = value else {
        return Err(AuthError::Malformed);
    };

    let mut iss = None;
    let mut sub = None;
    let mut exp = None;
    let mut iat = None;
    let mut patreon_user_id = None;
    let mut email = None;
    for (k, v) in entries {
        match k {
            Value::Integer(key) => match (i128::from(key), v) {
                (1, Value::Text(s)) => iss = Some(s),
                (2, Value::Text(s)) => sub = Some(s),
                (4, Value::Integer(n)) => exp = i64::try_from(i128::from(n)).ok(),
                (6, Value::Integer(n)) => iat = i64::try_from(i128::from(n)).ok(),
                _ => {}
            },
            Value::Text(key) => match (key.as_str(), v) {
                ("email", Value::Text(s)) => email = Some(s),
                ("arkavo_patreon", Value::Map(patreon)) => {
                    for (pk, pv) in patreon {
                        if let (Value::Text(pk), Value::Text(pv)) = (pk, pv)
                            && pk == "patreon_user_id"
                        {
                            patreon_user_id = Some(pv);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(VerifiedClaims {
        iss: iss.ok_or(AuthError::MissingClaim("iss"))?,
        sub: sub.ok_or(AuthError::MissingClaim("sub"))?,
        exp: exp.ok_or(AuthError::MissingClaim("exp"))?,
        iat: iat.ok_or(AuthError::MissingClaim("iat"))?,
        patreon_user_id,
        email,
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Mint Arkavo-compatible CWTs for tests, mirroring authnz-rs `cwt::mint`.

    use super::*;
    use coset::{CoseSign1Builder, HeaderBuilder, iana};
    use p256::ecdsa::{SigningKey, signature::Signer};

    pub fn mint(key: &SigningKey, kid: &[u8], iss: &str, sub: &str, iat: i64, exp: i64) -> String {
        mint_with_extras(key, kid, iss, sub, iat, exp, &[])
    }

    /// Mint with additional text-keyed claims, e.g. an `arkavo_patreon` map.
    pub fn mint_with_extras(
        key: &SigningKey,
        kid: &[u8],
        iss: &str,
        sub: &str,
        iat: i64,
        exp: i64,
        extras: &[(&str, Value)],
    ) -> String {
        use base64::Engine;
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Integer(1.into()), Value::Text(iss.into())),
            (Value::Integer(2.into()), Value::Text(sub.into())),
            (Value::Integer(4.into()), Value::Integer(exp.into())),
            (Value::Integer(6.into()), Value::Integer(iat.into())),
        ];
        for (k, v) in extras {
            entries.push((Value::Text((*k).into()), v.clone()));
        }
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
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
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
    use test_support::{keypair, mint};

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

        // Tokens without the claim parse with None — not an error.
        let plain = mint(&sk, b"kid-1", "i", "s", NOW, NOW + 3600);
        let claims = verifier(b"kid-1", vk).verify(&plain, NOW).await.unwrap();
        assert!(claims.patreon_user_id.is_none());
        assert!(claims.email.is_none());
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
}
