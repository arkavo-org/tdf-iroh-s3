use anyhow::{Context, Result};
use ciborium::value::Value;
use coset::{CborSerializable, CoseKey, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};

/// COSE_Sign1 transparency receipt over a signed statement, shaped after
/// `application/scitt-receipt+cose` (draft-ietf-cose-merkle-tree-proofs
/// direction): the payload is the statement digest, and the protected header
/// carries the algorithm, key id, tree size and root hash the issuer
/// committed to at registration time.
///
/// Spike scope: the Merkle inclusion proof itself lives in [`crate::log`];
/// this type binds "statement was registered by the log with root R at size
/// N" into a verifiable, offline-checkable COSE object.
#[derive(Debug, Clone)]
pub struct TransparencyReceipt {
    pub sign1: CoseSign1,
}

/// Protected-header labels (private range for the spike; an I-D would use
/// registered CWT/SCITT claims).
pub const LABEL_TREE_SIZE: i64 = -65000;
pub const LABEL_ROOT_HASH: i64 = -65001;
pub const LABEL_STATEMENT_DIGEST: i64 = -65002;

impl TransparencyReceipt {
    /// Issue a receipt committing to `statement_digest` inside a log whose
    /// current state is (`tree_size`, `root_hash`).
    pub fn issue(
        signing_key: &SigningKey,
        key_id: &[u8],
        statement_digest: [u8; 32],
        tree_size: u64,
        root_hash: &[u8; 32],
    ) -> Result<Self> {
        let mut protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(key_id.to_vec())
            .build();
        protected.rest.push((
            coset::Label::Int(LABEL_TREE_SIZE),
            Value::Bytes(tree_size.to_be_bytes().to_vec()),
        ));
        protected.rest.push((
            coset::Label::Int(LABEL_ROOT_HASH),
            Value::Bytes(root_hash.to_vec()),
        ));
        protected.rest.push((
            coset::Label::Int(LABEL_STATEMENT_DIGEST),
            Value::Bytes(statement_digest.to_vec()),
        ));

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(statement_digest.to_vec())
            .create_signature(b"", |to_sign| {
                use p256::ecdsa::signature::Signer;
                let sig: Signature = signing_key.sign(to_sign);
                sig.to_bytes().to_vec()
            })
            .build();

        // Fail fast on encoding bugs at issuance time.
        let _ = sign1
            .clone()
            .to_vec()
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(Self { sign1 })
    }

    /// Tree size the issuing log had committed to.
    pub fn tree_size(&self) -> Result<u64> {
        let bytes = self.protected_bytes(LABEL_TREE_SIZE)?;
        Ok(u64::from_be_bytes(bytes.as_slice().try_into()?))
    }

    /// Root hash the issuing log had committed to.
    pub fn root_hash(&self) -> Result<[u8; 32]> {
        Ok(self
            .protected_bytes(LABEL_ROOT_HASH)?
            .as_slice()
            .try_into()?)
    }

    /// The statement digest this receipt commits to.
    pub fn statement_digest(&self) -> Result<[u8; 32]> {
        Ok(self
            .protected_bytes(LABEL_STATEMENT_DIGEST)?
            .as_slice()
            .try_into()?)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.sign1
            .clone()
            .to_vec()
            .map_err(|e| anyhow::anyhow!("COSE encoding failed: {e:?}"))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            sign1: CoseSign1::from_slice(bytes)
                .map_err(|e| anyhow::anyhow!("COSE decode failed: {e:?}"))?,
        })
    }

    /// Verify the receipt signature against `key`, that the embedded labels
    /// are consistent with the payload, and return the committed digest.
    pub fn verify(&self, key: &CoseKey) -> Result<[u8; 32]> {
        let payload = self
            .sign1
            .payload
            .clone()
            .context("receipt has detached payload")?;
        self.sign1
            .verify_signature(b"", |sig, data| {
                let vk = verifying_key_from_cose(key).map_err(|_| ())?;
                let sig = Signature::from_slice(sig).map_err(|_| ())?;
                vk.verify(data, &sig).map_err(|_| ())
            })
            .map_err(|e| anyhow::anyhow!("receipt signature verification failed: {e:?}"))?;

        let digest = self.statement_digest()?;
        if payload != digest.to_vec() {
            anyhow::bail!("payload does not match committed statement digest");
        }
        Ok(digest)
    }

    fn protected_bytes(&self, label: i64) -> Result<Vec<u8>> {
        for (l, v) in &self.sign1.protected.header.rest {
            if *l == coset::Label::Int(label) {
                return match v {
                    Value::Bytes(b) => Ok(b.clone()),
                    _ => anyhow::bail!("label {label} is not bytes"),
                };
            }
        }
        anyhow::bail!("missing protected-header label {label}")
    }
}

fn verifying_key_from_cose(key: &CoseKey) -> Result<VerifyingKey> {
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
    let x = x.ok_or_else(|| anyhow::anyhow!("missing x"))?;
    let y = y.ok_or_else(|| anyhow::anyhow!("missing y"))?;
    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!("x/y are not 32 bytes");
    }

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&point).context("invalid P-256 public key")
}

/// Build a COSE EC2 P-256 key from a verifying key (test/bundle helper).
pub fn cose_key_from(verifying_key: &VerifyingKey) -> CoseKey {
    use coset::CoseKeyBuilder;
    let point = verifying_key.to_encoded_point(false);
    CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        point.x().unwrap().to_vec(),
        point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{MerkleLog, SignedTreeHead};
    use sha2::{Digest, Sha256};

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let key = test_key(5);
        let cose_key = cose_key_from(key.verifying_key());

        let mut log = MerkleLog::new();
        let statement_digest: [u8; 32] = Sha256::digest(b"permit-123 closure").into();
        log.append(&statement_digest);
        let head = log.sign_tree_head(&key).unwrap();

        let receipt = TransparencyReceipt::issue(
            &key,
            b"test-log-key",
            statement_digest,
            head.tree_size,
            &head.root_hash,
        )
        .unwrap();

        assert_eq!(receipt.tree_size().unwrap(), head.tree_size);
        assert_eq!(receipt.root_hash().unwrap(), head.root_hash);

        let encoded = receipt.to_vec().unwrap();
        let decoded = TransparencyReceipt::from_slice(&encoded).unwrap();
        assert_eq!(decoded.verify(&cose_key).unwrap(), statement_digest);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = test_key(9);
        let other_key = test_key(10);
        let cose_other = cose_key_from(other_key.verifying_key());

        let digest: [u8; 32] = Sha256::digest(b"stmt").into();
        let receipt = TransparencyReceipt::issue(&key, b"k", digest, 1, &[7u8; 32]).unwrap();
        assert!(receipt.verify(&cose_other).is_err());
    }

    #[test]
    fn tampered_payload_detected_via_label_mismatch() {
        let key = test_key(11);
        let cose_key = cose_key_from(key.verifying_key());
        let digest: [u8; 32] = Sha256::digest(b"real").into();
        let mut receipt = TransparencyReceipt::issue(&key, b"k", digest, 3, &[9u8; 32]).unwrap();

        receipt.sign1.payload = Some(b"fake".to_vec());
        assert!(receipt.verify(&cose_key).is_err());
    }

    #[test]
    fn receipt_bundle_survives_binary_round_trip_with_log_context() {
        let key = test_key(12);
        let mut log = MerkleLog::new();
        let d1: [u8; 32] = Sha256::digest(b"first").into();
        let d2: [u8; 32] = Sha256::digest(b"second").into();
        log.append(&d1);
        log.append(&d2);
        let head = log.sign_tree_head(&key).unwrap();

        let r1 =
            TransparencyReceipt::issue(&key, b"k", d1, head.tree_size, &head.root_hash).unwrap();
        let r2 =
            TransparencyReceipt::issue(&key, b"k", d2, head.tree_size, &head.root_hash).unwrap();

        let bundle = vec![r1.to_vec().unwrap(), r2.to_vec().unwrap()];
        let cose_key = cose_key_from(key.verifying_key());
        for bytes in &bundle {
            TransparencyReceipt::from_slice(bytes)
                .unwrap()
                .verify(&cose_key)
                .expect("bundled receipt must verify");
        }
    }

    #[test]
    fn receipt_labels_consistent_with_signed_tree_head() {
        let key = test_key(13);
        let mut log = MerkleLog::new();
        let d: [u8; 32] = Sha256::digest(b"x").into();
        log.append(&d);
        let head: SignedTreeHead = log.sign_tree_head(&key).unwrap();
        let receipt =
            TransparencyReceipt::issue(&key, b"k", d, head.tree_size, &head.root_hash).unwrap();
        assert_eq!(receipt.tree_size().unwrap(), head.tree_size);
        assert_eq!(receipt.root_hash().unwrap(), head.root_hash);
        assert_eq!(receipt.statement_digest().unwrap(), d);
    }
}
