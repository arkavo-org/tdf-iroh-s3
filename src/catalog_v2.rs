//! Catalog v2 (tdf-iroh-s3#27): a creator's current catalog is named by a
//! pointer the creator signs with their passkey, and the IdP attests which
//! passkey belongs to which subject.
//!
//! - **Pointer**: the exact bytes of an `arkavo.catalog-pointer/1` JSON
//!   object naming the catalog document's BLAKE3 hash and size, with a
//!   sequence number. Signed as-is, never re-serialized.
//! - **Assertion**: a WebAuthn assertion (RP `identity.arkavo.net`) whose
//!   challenge is SHA-256 of the pointer bytes.
//! - **Credential**: the IdP's COSE_Sign1 attestation binding the
//!   assertion's credential ID and public key to a subject.
//!
//! Readers check the same chain, so neither this node nor its storage can
//! forge a creator's catalog. This module is the checks only: no storage,
//! no HTTP.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use coset::{AsCborValue, CborSerializable, TaggedCborSerializable};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::auth::{AuthError, CwtVerifier, PASSKEY_CREDENTIAL_TYP, p256_from_cose_key};
use crate::creator_catalog::{
    MAX_CATALOG_BYTES, MAX_OWNER_BYTES, NoDuplicateKeys, is_lower_hex_hash, is_utc_timestamp,
    valid_identifier,
};

pub const POINTER_SCHEMA: &str = "arkavo.catalog-pointer/1";

/// Content type an attestation may carry in its protected header.
pub const CREDENTIAL_CONTENT_TYPE: &str = "application/arkavo-passkey-credential+cbor";

/// Largest `seq`: the largest integer every JSON reader holds exactly.
pub const MAX_SEQ: u64 = 9_007_199_254_740_991;

/// Bounds on what a bundle carries, so a request cannot make the node
/// decode or hash arbitrary amounts.
const MAX_POINTER_BYTES: usize = 1024;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 4096;
const MAX_CLIENT_DATA_BYTES: usize = 4096;
const MAX_SIGNATURE_BYTES: usize = 80;
const MAX_ATTESTATION_BYTES: usize = 4096;

/// WebAuthn authenticator data flags (WebAuthn L2 §6.1).
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// Clock skew allowed on the attestation's `iat`.
const SKEW_SECS: i64 = 60;

/// The relying party creators sign with.
#[derive(Debug, Clone)]
pub struct Passkeys {
    /// `identity.arkavo.net`: authenticator data names its SHA-256.
    pub rp_id: String,
    /// `https://identity.arkavo.net`: the origin in `clientDataJSON`.
    pub origin: String,
}

impl Passkeys {
    pub fn for_rp(rp_id: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            origin: format!("https://{rp_id}"),
        }
    }
}

/// A parsed `arkavo.catalog-pointer/1`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pointer {
    pub schema: String,
    pub owner: String,
    pub seq: u64,
    pub catalog_hash: String,
    pub catalog_size: u64,
    pub issued_at: String,
}

/// Parse and validate pointer bytes. The error is the reason reported as
/// `invalid bundle: <reason>`.
pub fn parse_pointer(bytes: &[u8]) -> Result<Pointer, String> {
    if bytes.len() > MAX_POINTER_BYTES {
        return Err(format!("pointer larger than {MAX_POINTER_BYTES} bytes"));
    }
    std::str::from_utf8(bytes).map_err(|_| "pointer is not UTF-8".to_string())?;
    serde_json::from_slice::<NoDuplicateKeys>(bytes).map_err(|e| format!("pointer: {e}"))?;
    let p: Pointer = serde_json::from_slice(bytes).map_err(|e| format!("pointer: {e}"))?;
    if p.schema != POINTER_SCHEMA {
        return Err(format!("pointer schema must be \"{POINTER_SCHEMA}\""));
    }
    if !valid_identifier(&p.owner, MAX_OWNER_BYTES) {
        return Err(format!(
            "pointer owner must be 1-{MAX_OWNER_BYTES} bytes of [A-Za-z0-9:._@-] without \"..\""
        ));
    }
    if !(1..=MAX_SEQ).contains(&p.seq) {
        return Err(format!("pointer seq must be 1-{MAX_SEQ}"));
    }
    if !is_lower_hex_hash(&p.catalog_hash) {
        return Err("pointer catalogHash must be 64 lowercase hex characters".to_string());
    }
    if !(1..=MAX_CATALOG_BYTES as u64).contains(&p.catalog_size) {
        return Err(format!("pointer catalogSize must be 1-{MAX_CATALOG_BYTES}"));
    }
    if !is_utc_timestamp(&p.issued_at) {
        return Err("pointer issuedAt must be YYYY-MM-DDTHH:MM:SSZ".to_string());
    }
    Ok(p)
}

/// The signed bundle, as stored and served. Every binary field is unpadded
/// base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub pointer: String,
    pub assertion: Assertion,
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
}

/// Why a bundle is refused.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The bundle does not hold: reported as 422 `invalid bundle: <reason>`.
    #[error("{0}")]
    Invalid(String),
    /// The IdP's key set could not be fetched: 502.
    #[error("key set unavailable: {0}")]
    KeySet(String),
}

fn invalid(reason: impl Into<String>) -> BundleError {
    BundleError::Invalid(reason.into())
}

/// The IdP's attestation, after its signature verified.
#[derive(Debug, Clone)]
pub struct Credential {
    pub sub: String,
    pub credential_id: Vec<u8>,
    pub public_key: VerifyingKey,
    pub rp_id: String,
    pub iss: String,
    pub iat: i64,
}

/// A bundle whose whole chain verified.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub pointer: Pointer,
    pub credential_id: Vec<u8>,
}

fn b64(field: &str, value: &str, max: usize) -> Result<Vec<u8>, BundleError> {
    // A decoded length of at most `max` needs at most 4/3 of it encoded.
    if value.len() > max.div_ceil(3) * 4 {
        return Err(invalid(format!("{field} too large")));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid(format!("{field} is not unpadded base64url")))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(invalid(format!("{field} must be 1-{max} bytes")));
    }
    Ok(bytes)
}

/// Verify the whole chain for `expected_owner`: the IdP attestation's
/// signature, its binding of the credential to the pointer's owner, the
/// passkey assertion over the pointer bytes, and the pointer itself. The
/// document and `seq` are the caller's to check against the pointer.
pub async fn verify_bundle(
    bundle: &Bundle,
    expected_owner: &str,
    verifier: &CwtVerifier,
    passkeys: &Passkeys,
    now: i64,
) -> Result<VerifiedBundle, BundleError> {
    let pointer_bytes = b64("pointer", &bundle.pointer, MAX_POINTER_BYTES)?;
    let pointer = parse_pointer(&pointer_bytes).map_err(invalid)?;
    if pointer.owner != expected_owner {
        return Err(invalid("pointer owner does not match the catalog subject"));
    }

    let attestation = b64("credential", &bundle.credential, MAX_ATTESTATION_BYTES)?;
    let credential = verify_credential(&attestation, verifier, now).await?;
    check_credential(&credential, &pointer, passkeys)?;

    let credential_id = b64(
        "assertion.credentialId",
        &bundle.assertion.credential_id,
        MAX_CREDENTIAL_ID_BYTES,
    )?;
    if credential_id != credential.credential_id {
        return Err(invalid(
            "assertion credentialId does not match the attested credential",
        ));
    }
    verify_assertion(
        &pointer_bytes,
        &bundle.assertion,
        &credential.public_key,
        passkeys,
    )?;
    Ok(VerifiedBundle {
        pointer,
        credential_id,
    })
}

/// The attestation's claims must name this pointer's owner, this relying
/// party, and the configured issuer.
fn check_credential(
    credential: &Credential,
    pointer: &Pointer,
    passkeys: &Passkeys,
) -> Result<(), BundleError> {
    if credential.sub != pointer.owner {
        return Err(invalid(
            "credential subject does not match the pointer owner",
        ));
    }
    if credential.rp_id != passkeys.rp_id {
        return Err(invalid("credential rpId is not this relying party"));
    }
    Ok(())
}

/// Verify the IdP's COSE_Sign1 attestation (tagged 18 or untagged) against
/// the key set and parse its claims.
pub async fn verify_credential(
    bytes: &[u8],
    verifier: &CwtVerifier,
    now: i64,
) -> Result<Credential, BundleError> {
    let sign1 = if bytes.first() == Some(&0xD2) {
        coset::CoseSign1::from_tagged_slice(bytes)
    } else {
        coset::CoseSign1::from_slice(bytes)
    }
    .map_err(|_| invalid("credential is not a COSE_Sign1"))?;
    // Required: one of the checks that keep a CWT, signed with the same
    // keys, from passing as an attestation.
    if sign1.protected.header.content_type
        != Some(coset::ContentType::Text(
            CREDENTIAL_CONTENT_TYPE.to_string(),
        ))
    {
        return Err(invalid(format!(
            "credential content type must be \"{CREDENTIAL_CONTENT_TYPE}\""
        )));
    }
    verifier.verify_sign1(&sign1).await.map_err(|e| match e {
        AuthError::KeySet(why) => BundleError::KeySet(why),
        AuthError::UnknownKid => invalid("credential signed by an unknown key"),
        AuthError::Algorithm => invalid("credential must be ES256"),
        _ => invalid("credential signature does not verify"),
    })?;
    let payload = sign1
        .payload
        .as_deref()
        .ok_or_else(|| invalid("credential has no payload"))?;
    let credential = parse_credential(payload).map_err(invalid)?;
    if let Some(iss) = verifier.expected_issuer()
        && credential.iss != iss
    {
        return Err(invalid("credential issuer mismatch"));
    }
    if credential.iat > now + SKEW_SECS {
        return Err(invalid("credential issued in the future"));
    }
    Ok(credential)
}

/// The attestation payload: a CBOR map with exactly the text keys `typ`,
/// `iss`, `sub`, `credentialId`, `publicKey`, `rpId` and `iat`.
fn parse_credential(payload: &[u8]) -> Result<Credential, String> {
    let value: Value =
        ciborium::de::from_reader(payload).map_err(|_| "credential payload is not CBOR")?;
    let Value::Map(entries) = value else {
        return Err("credential payload is not a map".to_string());
    };
    let mut seen = HashSet::new();
    let (mut typ, mut iss, mut sub, mut id, mut key, mut rp, mut iat) =
        (None, None, None, None, None, None, None);
    for (k, v) in entries {
        let Value::Text(k) = k else {
            return Err("credential keys must be text".to_string());
        };
        if !seen.insert(k.clone()) {
            return Err(format!("credential repeats {k}"));
        }
        match (k.as_str(), v) {
            ("typ", Value::Text(s)) => typ = Some(s),
            ("iss", Value::Text(s)) => iss = Some(s),
            ("sub", Value::Text(s)) => sub = Some(s),
            ("credentialId", Value::Bytes(b)) => id = Some(b),
            ("publicKey", m @ Value::Map(_)) => {
                let cose = coset::CoseKey::from_cbor_value(m)
                    .map_err(|_| "credential publicKey is not a COSE_Key")?;
                let vk =
                    p256_from_cose_key(&cose).map_err(|e| format!("credential publicKey: {e}"))?;
                key = Some(vk);
            }
            ("rpId", Value::Text(s)) => rp = Some(s),
            ("iat", Value::Integer(n)) => {
                iat = Some(i64::try_from(i128::from(n)).map_err(|_| "credential iat")?);
            }
            (other, _) => return Err(format!("credential has unexpected or mistyped {other}")),
        }
    }
    if typ.as_deref() != Some(PASSKEY_CREDENTIAL_TYP) {
        return Err(format!(
            "credential typ must be \"{PASSKEY_CREDENTIAL_TYP}\""
        ));
    }
    let missing = |name: &str| format!("credential is missing {name}");
    Ok(Credential {
        iss: iss.ok_or_else(|| missing("iss"))?,
        sub: sub
            .filter(|s| !s.is_empty())
            .ok_or_else(|| missing("sub"))?,
        credential_id: id
            .filter(|b| !b.is_empty())
            .ok_or_else(|| missing("credentialId"))?,
        public_key: key.ok_or_else(|| missing("publicKey"))?,
        rp_id: rp.ok_or_else(|| missing("rpId"))?,
        iat: iat.ok_or_else(|| missing("iat"))?,
    })
}

/// Verify a WebAuthn assertion over `pointer_bytes` (WebAuthn L2 §7.2,
/// steps that apply to a stored-key check): `webauthn.get`, challenge =
/// SHA-256(pointer bytes), this origin, not cross-origin, this RP's ID
/// hash, user present and verified, and an ES256 (DER) signature over
/// `authenticatorData || SHA-256(clientDataJSON)`. The signature counter
/// is ignored: synced passkeys report 0.
pub fn verify_assertion(
    pointer_bytes: &[u8],
    assertion: &Assertion,
    key: &VerifyingKey,
    passkeys: &Passkeys,
) -> Result<(), BundleError> {
    let auth_data = b64(
        "assertion.authenticatorData",
        &assertion.authenticator_data,
        MAX_AUTHENTICATOR_DATA_BYTES,
    )?;
    let client_data = b64(
        "assertion.clientDataJSON",
        &assertion.client_data_json,
        MAX_CLIENT_DATA_BYTES,
    )?;
    let signature = b64(
        "assertion.signature",
        &assertion.signature,
        MAX_SIGNATURE_BYTES,
    )?;

    let cd: serde_json::Value =
        serde_json::from_slice(&client_data).map_err(|_| invalid("clientDataJSON is not JSON"))?;
    if cd.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(invalid("clientDataJSON type must be webauthn.get"));
    }
    let challenge = cd
        .get("challenge")
        .and_then(|v| v.as_str())
        .and_then(|c| URL_SAFE_NO_PAD.decode(c).ok())
        .ok_or_else(|| invalid("clientDataJSON challenge missing or not base64url"))?;
    if challenge != Sha256::digest(pointer_bytes).as_slice() {
        return Err(invalid("assertion challenge is not SHA-256 of the pointer"));
    }
    if cd.get("origin").and_then(|v| v.as_str()) != Some(passkeys.origin.as_str()) {
        return Err(invalid("clientDataJSON origin is not this relying party"));
    }
    if cd.get("crossOrigin").and_then(|v| v.as_bool()) == Some(true) {
        return Err(invalid("cross-origin assertions are refused"));
    }

    // rpIdHash (32) | flags (1) | signCount (4) | extensions...
    if auth_data.len() < 37 {
        return Err(invalid("authenticatorData too short"));
    }
    if auth_data[..32] != Sha256::digest(passkeys.rp_id.as_bytes())[..] {
        return Err(invalid(
            "authenticatorData rpIdHash is not this relying party",
        ));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(invalid(
            "assertion must have user presence and verification",
        ));
    }

    let signature = Signature::from_der(&signature)
        .map_err(|_| invalid("assertion signature is not DER ECDSA"))?;
    let mut signed = auth_data;
    signed.extend_from_slice(&Sha256::digest(&client_data));
    // `verify` hashes `signed` with SHA-256 itself (ES256).
    key.verify(&signed, &signature)
        .map_err(|_| invalid("assertion signature does not verify"))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Signed fixtures: an IdP key, a passkey, and bundles built from them
    //! the way Creator and authnz-rs build them.
    use super::*;
    use coset::{CoseSign1Builder, HeaderBuilder, iana};
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    pub const IDP_KID: &[u8] = b"idp-test";
    pub const ISS: &str = "https://identity.arkavo.net";
    pub const RP: &str = "identity.arkavo.net";

    pub fn idp_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    pub fn passkey(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    pub fn verifier() -> CwtVerifier {
        CwtVerifier::with_static_keys(vec![(IDP_KID.to_vec(), *idp_key().verifying_key())])
            .with_expected_issuer(ISS.to_string())
    }

    pub fn passkeys() -> Passkeys {
        Passkeys::for_rp(RP)
    }

    pub fn cose_key(vk: &VerifyingKey) -> Value {
        let point = vk.to_encoded_point(false);
        Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ])
    }

    /// The attestation payload with the given fields; `extra` entries are
    /// appended as-is.
    pub fn credential_payload(
        sub: &str,
        credential_id: &[u8],
        key: &VerifyingKey,
        extra: Vec<(Value, Value)>,
    ) -> Vec<u8> {
        let mut map = vec![
            (
                Value::Text("typ".into()),
                Value::Text(PASSKEY_CREDENTIAL_TYP.into()),
            ),
            (Value::Text("iss".into()), Value::Text(ISS.into())),
            (Value::Text("sub".into()), Value::Text(sub.into())),
            (
                Value::Text("credentialId".into()),
                Value::Bytes(credential_id.to_vec()),
            ),
            (Value::Text("publicKey".into()), cose_key(key)),
            (Value::Text("rpId".into()), Value::Text(RP.into())),
            (
                Value::Text("iat".into()),
                Value::Integer(1_700_000_000.into()),
            ),
        ];
        map.extend(extra);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    /// A COSE_Sign1 over `payload`, tagged 18, signed by `signer` as `kid`.
    pub fn sign_credential(payload: Vec<u8>, signer: &SigningKey, kid: &[u8]) -> Vec<u8> {
        sign_credential_as(payload, signer, kid, Some(CREDENTIAL_CONTENT_TYPE))
    }

    /// As [`sign_credential`], with the given content type (or none).
    pub fn sign_credential_as(
        payload: Vec<u8>,
        signer: &SigningKey,
        kid: &[u8],
        content_type: Option<&str>,
    ) -> Vec<u8> {
        let mut protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(kid.to_vec());
        if let Some(ct) = content_type {
            protected = protected.content_type(ct.to_string());
        }
        let protected = protected.build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |data| {
                let sig: Signature = signer.sign(data);
                sig.to_bytes().to_vec()
            })
            .build()
            .to_tagged_vec()
            .unwrap()
    }

    pub fn pointer_bytes(owner: &str, seq: u64, document: &[u8]) -> Vec<u8> {
        format!(
            r#"{{"schema":"arkavo.catalog-pointer/1","owner":"{owner}","seq":{seq},"catalogHash":"{}","catalogSize":{},"issuedAt":"2026-10-19T01:02:03Z"}}"#,
            blake3::hash(document).to_hex(),
            document.len()
        )
        .into_bytes()
    }

    /// Fields of a passkey assertion, overridable per test.
    pub struct AssertionParts {
        pub client_data: Vec<u8>,
        pub auth_data: Vec<u8>,
    }

    impl AssertionParts {
        pub fn for_pointer(pointer: &[u8]) -> Self {
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pointer));
            let client_data = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{RP}"}}"#
            )
            .into_bytes();
            let mut auth_data = Sha256::digest(RP.as_bytes()).to_vec();
            auth_data.push(FLAG_UP | FLAG_UV);
            auth_data.extend_from_slice(&[0, 0, 0, 0]);
            Self {
                client_data,
                auth_data,
            }
        }

        pub fn sign(&self, key: &SigningKey, credential_id: &[u8]) -> Assertion {
            let mut signed = self.auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&self.client_data));
            let sig: Signature = key.sign(&signed);
            Assertion {
                credential_id: URL_SAFE_NO_PAD.encode(credential_id),
                authenticator_data: URL_SAFE_NO_PAD.encode(&self.auth_data),
                client_data_json: URL_SAFE_NO_PAD.encode(&self.client_data),
                signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
            }
        }
    }

    pub const CREDENTIAL_ID: &[u8] = b"cred-1";

    /// A complete, valid bundle for `owner`'s `document` at `seq`.
    pub fn bundle(owner: &str, seq: u64, document: &[u8]) -> Bundle {
        let pk = passkey(9);
        let pointer = pointer_bytes(owner, seq, document);
        let assertion = AssertionParts::for_pointer(&pointer).sign(&pk, CREDENTIAL_ID);
        let credential = sign_credential(
            credential_payload(owner, CREDENTIAL_ID, pk.verifying_key(), vec![]),
            &idp_key(),
            IDP_KID,
        );
        Bundle {
            pointer: URL_SAFE_NO_PAD.encode(pointer),
            assertion,
            credential: URL_SAFE_NO_PAD.encode(credential),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DOC: &[u8] = br#"{"schema":"arkavo.creator-catalog/1","owner":"u1","entries":[]}"#;

    async fn verify(b: &Bundle) -> Result<VerifiedBundle, BundleError> {
        verify_bundle(b, "u1", &verifier(), &passkeys(), NOW).await
    }

    fn reason(r: Result<VerifiedBundle, BundleError>) -> String {
        match r {
            Err(BundleError::Invalid(why)) => why,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// A bundle whose assertion is re-signed after `edit` changes its parts.
    fn with_assertion(edit: impl FnOnce(&mut AssertionParts)) -> Bundle {
        let mut b = bundle("u1", 1, DOC);
        let pointer = pointer_bytes("u1", 1, DOC);
        let mut parts = AssertionParts::for_pointer(&pointer);
        edit(&mut parts);
        b.assertion = parts.sign(&passkey(9), CREDENTIAL_ID);
        b
    }

    fn with_credential(payload: Vec<u8>) -> Bundle {
        let mut b = bundle("u1", 1, DOC);
        b.credential = URL_SAFE_NO_PAD.encode(sign_credential(payload, &idp_key(), IDP_KID));
        b
    }

    #[tokio::test]
    async fn a_valid_chain_verifies() {
        let v = verify(&bundle("u1", 7, DOC)).await.unwrap();
        assert_eq!(v.pointer.seq, 7);
        assert_eq!(
            v.pointer.catalog_hash,
            blake3::hash(DOC).to_hex().to_string()
        );
        assert_eq!(v.pointer.catalog_size, DOC.len() as u64);
        assert_eq!(v.credential_id, CREDENTIAL_ID);
    }

    #[tokio::test]
    async fn an_untagged_attestation_verifies() {
        let mut b = bundle("u1", 1, DOC);
        let tagged = URL_SAFE_NO_PAD.decode(&b.credential).unwrap();
        assert_eq!(tagged[0], 0xD2);
        b.credential = URL_SAFE_NO_PAD.encode(&tagged[1..]);
        verify(&b).await.unwrap();
    }

    #[tokio::test]
    async fn the_pointer_owner_must_be_the_subject() {
        let b = bundle("u2", 1, DOC);
        assert!(reason(verify(&b).await).contains("pointer owner"));
    }

    #[tokio::test]
    async fn the_attestation_must_name_the_owner() {
        let b = with_credential(credential_payload(
            "u2",
            CREDENTIAL_ID,
            passkey(9).verifying_key(),
            vec![],
        ));
        assert!(reason(verify(&b).await).contains("credential subject"));
    }

    #[tokio::test]
    async fn the_assertion_must_use_the_attested_credential() {
        let mut b = bundle("u1", 1, DOC);
        b.assertion.credential_id = URL_SAFE_NO_PAD.encode(b"cred-2");
        assert!(reason(verify(&b).await).contains("credentialId"));
    }

    #[tokio::test]
    async fn a_different_passkey_does_not_verify() {
        let mut b = bundle("u1", 1, DOC);
        let pointer = pointer_bytes("u1", 1, DOC);
        b.assertion = AssertionParts::for_pointer(&pointer).sign(&passkey(10), CREDENTIAL_ID);
        assert!(reason(verify(&b).await).contains("signature does not verify"));
    }

    #[tokio::test]
    async fn the_challenge_must_be_the_pointer_hash() {
        let other = pointer_bytes("u1", 2, DOC);
        let b = with_assertion(|p| *p = AssertionParts::for_pointer(&other));
        assert!(reason(verify(&b).await).contains("challenge"));
    }

    #[tokio::test]
    async fn the_origin_type_and_cross_origin_are_checked() {
        let pointer = pointer_bytes("u1", 1, DOC);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(&pointer));
        for (cd, want) in [
            (
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://evil.example"}}"#
                ),
                "origin",
            ),
            (
                format!(
                    r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://{RP}"}}"#
                ),
                "type",
            ),
            (
                format!(
                    r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{RP}","crossOrigin":true}}"#
                ),
                "cross-origin",
            ),
        ] {
            let b = with_assertion(|p| p.client_data = cd.into_bytes());
            assert!(reason(verify(&b).await).contains(want), "{want}");
        }
    }

    #[tokio::test]
    async fn rp_id_hash_and_flags_are_checked() {
        let b = with_assertion(|p| p.auth_data[0] ^= 1);
        assert!(reason(verify(&b).await).contains("rpIdHash"));
        let b = with_assertion(|p| p.auth_data[32] = FLAG_UP);
        assert!(reason(verify(&b).await).contains("verification"));
        let b = with_assertion(|p| p.auth_data[32] = FLAG_UV);
        assert!(reason(verify(&b).await).contains("presence"));
        let b = with_assertion(|p| p.auth_data.truncate(36));
        assert!(reason(verify(&b).await).contains("too short"));
    }

    #[tokio::test]
    async fn extension_data_after_the_counter_is_allowed() {
        let b = with_assertion(|p| p.auth_data.extend_from_slice(&[0xA0]));
        verify(&b).await.unwrap();
    }

    #[tokio::test]
    async fn a_raw_signature_is_not_der() {
        let mut b = bundle("u1", 1, DOC);
        let der = URL_SAFE_NO_PAD.decode(&b.assertion.signature).unwrap();
        let raw = Signature::from_der(&der).unwrap().to_bytes();
        b.assertion.signature = URL_SAFE_NO_PAD.encode(raw);
        assert!(reason(verify(&b).await).contains("DER"));
    }

    #[tokio::test]
    async fn an_attestation_from_another_key_is_refused() {
        let mut b = bundle("u1", 1, DOC);
        let pk = passkey(9);
        let forged = sign_credential(
            credential_payload("u1", CREDENTIAL_ID, pk.verifying_key(), vec![]),
            &passkey(3),
            IDP_KID,
        );
        b.credential = URL_SAFE_NO_PAD.encode(forged);
        assert!(reason(verify(&b).await).contains("signature"));
        let unknown = sign_credential(
            credential_payload("u1", CREDENTIAL_ID, pk.verifying_key(), vec![]),
            &idp_key(),
            b"other-kid",
        );
        b.credential = URL_SAFE_NO_PAD.encode(unknown);
        assert!(reason(verify(&b).await).contains("unknown key"));
    }

    #[tokio::test]
    async fn the_attestation_content_type_is_required() {
        let pk = passkey(9);
        for ct in [None, Some("application/cwt")] {
            let mut b = bundle("u1", 1, DOC);
            b.credential = URL_SAFE_NO_PAD.encode(sign_credential_as(
                credential_payload("u1", CREDENTIAL_ID, pk.verifying_key(), vec![]),
                &idp_key(),
                IDP_KID,
                ct,
            ));
            assert!(reason(verify(&b).await).contains("content type"), "{ct:?}");
        }
    }

    #[tokio::test]
    async fn the_attestation_payload_is_strict() {
        let pk = passkey(9);
        let extra = credential_payload(
            "u1",
            CREDENTIAL_ID,
            pk.verifying_key(),
            vec![(Value::Text("exp".into()), Value::Integer(1.into()))],
        );
        assert!(reason(verify(&with_credential(extra)).await).contains("exp"));
        let dup = credential_payload(
            "u1",
            CREDENTIAL_ID,
            pk.verifying_key(),
            vec![(Value::Text("sub".into()), Value::Text("u1".into()))],
        );
        assert!(reason(verify(&with_credential(dup)).await).contains("repeats"));
    }

    #[tokio::test]
    async fn a_cwt_shaped_payload_is_not_an_attestation() {
        let mut map = Vec::new();
        ciborium::ser::into_writer(
            &Value::Map(vec![(Value::Integer(1.into()), Value::Text(ISS.into()))]),
            &mut map,
        )
        .unwrap();
        assert!(reason(verify(&with_credential(map)).await).contains("text"));
    }

    #[test]
    fn pointer_rules() {
        let ok = pointer_bytes("u1", 1, DOC);
        parse_pointer(&ok).unwrap();
        let cases: [(&str, &str); 6] = [
            (r#""seq":1"#, r#""seq":0"#),
            (r#""seq":1"#, r#""seq":1.0"#),
            ("2026-10-19T01:02:03Z", "2026-10-19T01:02:03.000Z"),
            (r#""owner":"u1""#, r#""owner":"a/b""#),
            (r#"{"schema""#, r#"{"extra":1,"schema""#),
            (r#""seq":1"#, r#""seq":1,"seq":2"#),
        ];
        let text = String::from_utf8(ok).unwrap();
        for (from, to) in cases {
            let bad = text.replacen(from, to, 1);
            assert_ne!(bad, text, "{to}");
            assert!(parse_pointer(bad.as_bytes()).is_err(), "{to}");
        }
    }

    #[test]
    fn base64_must_be_unpadded() {
        let err = b64("pointer", "YQ==", 10).unwrap_err();
        assert!(err.to_string().contains("unpadded"));
        assert_eq!(b64("pointer", "YQ", 10).unwrap(), b"a");
    }
}
