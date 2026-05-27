//! In-process CWT issuer used by unit and integration tests.
//!
//! Generates a P-256 keypair, exposes the public half as JWKS JSON, and
//! mints COSE_Sign1 CWTs signed by the private half. Not behind a
//! `feature = "test-fixtures"` switch in the public API because nothing
//! outside of tests links it.

use ciborium::Value;
use coset::cwt::{ClaimsSetBuilder, Timestamp};
use coset::{CborSerializable, CoseKeyBuilder, CoseKeySet, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Arc;

use super::CoseKeyCache;

pub struct TestSigner {
    signing_key: SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
    pub kid: Vec<u8>,
    pub issuer: String,
}

impl TestSigner {
    pub fn new(issuer: impl Into<String>) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            kid: b"test-kid-1".to_vec(),
            issuer: issuer.into(),
        }
    }

    /// Encode this signer's public key as a CBOR COSE_KeySet, the format
    /// served by the production identity endpoint.
    pub fn cose_key_set(&self) -> Vec<u8> {
        let point = self.verifying_key.to_encoded_point(false);
        let x = point.x().expect("uncompressed point has x").to_vec();
        let y = point.y().expect("uncompressed point has y").to_vec();
        let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .algorithm(iana::Algorithm::ES256)
            .key_id(self.kid.clone())
            .build();
        CoseKeySet(vec![key])
            .to_vec()
            .expect("CoseKeySet serializes")
    }

    /// Build an in-memory `CoseKeyCache` populated with this signer's public
    /// key. Skips the HTTP path entirely. The raw CBOR keyset is seeded
    /// alongside the parsed map so [`crate::auth::Verifier`] (which calls
    /// `pep_check::verify_cose_sign1` with the raw bytes) can verify
    /// signatures without an HTTP fetch.
    pub fn cose_key_cache(&self) -> Arc<CoseKeyCache> {
        let mut map = HashMap::new();
        map.insert(self.kid.clone(), self.verifying_key);
        CoseKeyCache::new_static(map, bytes::Bytes::from(self.cose_key_set()))
    }

    /// Mint a CWT for the given claims.
    pub fn mint(&self, claims: TestClaims) -> Vec<u8> {
        let mut builder = ClaimsSetBuilder::new()
            .issuer(claims.issuer.unwrap_or_else(|| self.issuer.clone()))
            .subject(claims.subject)
            .issued_at(Timestamp::WholeSeconds(claims.iat))
            .expiration_time(Timestamp::WholeSeconds(claims.exp));
        if let Some(cti) = claims.cti {
            builder = builder.cwt_id(cti);
        }
        // scope claim (9, RFC 8693)
        builder = builder.claim(iana::CwtClaimName::Scope, Value::Text(claims.scope));
        // campaign_id (text claim, project-specific)
        builder = builder.text_claim(
            "campaign_id".to_string(),
            Value::Text(claims.campaign_id),
        );
        if let Some(node_id) = claims.cnf_iroh_node_id {
            let cnf = Value::Map(vec![(
                Value::Text("iroh_node_id".to_string()),
                Value::Text(node_id),
            )]);
            builder = builder.claim(iana::CwtClaimName::Cnf, cnf);
        }
        let claims_set = builder.build();
        let payload = claims_set
            .to_vec()
            .expect("ClaimsSet serializes to CBOR");

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(self.kid.clone())
            .build();

        let signing_key = self.signing_key.clone();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(&[], move |tbs| {
                let sig: Signature = signing_key.sign(tbs);
                sig.to_bytes().to_vec()
            })
            .build();

        sign1.to_vec().expect("COSE_Sign1 serializes")
    }
}

pub struct TestClaims {
    pub subject: String,
    pub campaign_id: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub cti: Option<Vec<u8>>,
    pub cnf_iroh_node_id: Option<String>,
    pub issuer: Option<String>,
}

impl TestClaims {
    /// Sensible default: catalog.write scope, valid for the next 5 minutes.
    pub fn defaults(subject: impl Into<String>, campaign_id: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Self {
            subject: subject.into(),
            campaign_id: campaign_id.into(),
            scope: "catalog.write".to_string(),
            iat: now,
            exp: now + 300,
            cti: Some(b"test-cti-001".to_vec()),
            cnf_iroh_node_id: None,
            issuer: None,
        }
    }
}
