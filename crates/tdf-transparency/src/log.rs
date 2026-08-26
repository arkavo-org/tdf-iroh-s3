use anyhow::{Context, Result};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Append-only Merkle tree log with RFC 6962-style node hashing
/// (leaf: H(0x00 || data), node: H(0x01 || left || right)) and signed tree
/// heads. This is the transparency-log core for the customer-operated
/// evidence service (Epic 4.2); inclusion proofs land with the receipt
/// format in `crate::receipt`.
#[derive(Debug)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

impl Default for MerkleLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn tree_size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Append a leaf (typically the digest of a signed statement) and return
    /// the new root.
    pub fn append(&mut self, data: &[u8]) -> [u8; 32] {
        self.leaves.push(leaf_hash(data));
        self.root_hash()
    }

    /// Current Merkle root over all leaves. Empty log roots to SHA-256("").
    pub fn root_hash(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return Sha256::digest(b"").into();
        }
        subtree_root(&self.leaves)
    }

    /// Sign the current state of the log. The signing key never needs to be
    /// online after this call returns — the head is self-contained.
    pub fn sign_tree_head(&self, key: &SigningKey) -> Result<SignedTreeHead> {
        SignedTreeHead::new(self.tree_size(), self.root_hash(), key)
    }

    /// Verify an inclusion proof for `data` at 0-based `index` against a
    /// signed tree head.
    pub fn inclusion_proof(&self, index: u64) -> Result<MerkleProof> {
        let idx = usize::try_from(index).context("index exceeds usize")?;
        if index >= self.tree_size() {
            anyhow::bail!("index {index} out of range (size {})", self.tree_size());
        }
        let mut path = Vec::new();
        collect_path(&self.leaves, idx, &mut path);
        Ok(MerkleProof { index, path })
    }
}

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of the minimal perfect subtree covering `leaves` (RFC 6962 MTH).
fn subtree_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        1 => leaves[0],
        n => {
            // Largest power of two < n splits the tree.
            let split = n.next_power_of_two() / 2;
            let left = subtree_root(&leaves[..split]);
            let right = subtree_root(&leaves[split..]);
            node_hash(&left, &right)
        }
    }
}

fn collect_path(leaves: &[[u8; 32]], index: usize, path: &mut Vec<ProofStep>) {
    if leaves.len() == 1 {
        return;
    }
    let split = leaves.len().next_power_of_two() / 2;
    if index < split {
        collect_path(&leaves[..split], index, path);
        path.push(ProofStep {
            sibling: subtree_root(&leaves[split..]),
            sibling_is_right: true,
        });
    } else {
        collect_path(&leaves[split..], index - split, path);
        path.push(ProofStep {
            sibling: subtree_root(&leaves[..split]),
            sibling_is_right: false,
        });
    }
}

/// Proof that a leaf at `index` commits to `root`. Each entry pairs a
/// sibling subtree root with whether the sibling sits on the right of the
/// node under verification — explicit sides are required because RFC 6962
/// splits unbalanced trees at the largest power of two, so leaf-index
/// parity alone does not determine ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index: u64,
    pub path: Vec<ProofStep>,
}

/// One sibling along the inclusion path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    /// true = sibling is the RIGHT-hand input to the parent hash.
    pub sibling_is_right: bool,
}

impl MerkleProof {
    /// Recompute the root implied by this proof for `leaf_hash`.
    pub fn evaluate(&self, leaf: [u8; 32]) -> [u8; 32] {
        let mut current = leaf;
        for step in &self.path {
            current = if step.sibling_is_right {
                node_hash(&current, &step.sibling)
            } else {
                node_hash(&step.sibling, &current)
            };
        }
        current
    }

    /// Verify that `data` at this proof's index is included in `head`.
    pub fn verify(&self, data: &[u8], head: &SignedTreeHead) -> Result<()> {
        let computed = self.evaluate(leaf_hash(data));
        if computed != head.root_hash {
            anyhow::bail!("inclusion proof failed: computed root does not match signed head");
        }
        head.verify()?;
        Ok(())
    }
}

/// A signed statement committing to the log state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Number of leaves committed to.
    pub tree_size: u64,
    /// Root hash over all `tree_size` leaves.
    pub root_hash: [u8; 32],
    /// Unix seconds when the head was signed.
    pub timestamp: i64,
    /// DER-encoded ECDSA P-256 signature over the serialized head fields.
    pub signature: Vec<u8>,
    /// Hex-encoded verifying key so heads are verifiable offline without a
    /// key directory (production: key resolved from customer KMS / DID log).
    #[serde(with = "hex_serde")]
    pub verifying_key: Vec<u8>,
}

impl SignedTreeHead {
    pub fn new(tree_size: u64, root_hash: [u8; 32], signing_key: &SigningKey) -> Result<Self> {
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let signature = sign_head(tree_size, root_hash, timestamp, signing_key)?;
        Ok(Self {
            tree_size,
            root_hash,
            timestamp,
            signature,
            verifying_key: encoding_key(signing_key),
        })
    }

    /// Verify the signature using the embedded verifying key.
    pub fn verify(&self) -> Result<()> {
        let key_bytes: [u8; 33] = self.verifying_key.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("invalid verifying key length {}", self.verifying_key.len())
        })?;
        let key = VerifyingKey::from_sec1_bytes(&key_bytes)
            .context("invalid verifying key in signed tree head")?;
        let sig = Signature::from_slice(&self.signature)
            .context("invalid signature encoding in signed tree head")?;
        use p256::ecdsa::signature::Verifier as _;
        key.verify(
            &head_bytes(self.tree_size, self.root_hash, self.timestamp),
            &sig,
        )
        .context("signed tree head signature verification failed")?;
        Ok(())
    }
}

fn head_bytes(tree_size: u64, root: [u8; 32], timestamp: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&root);
    buf
}

fn sign_head(tree_size: u64, root: [u8; 32], timestamp: i64, key: &SigningKey) -> Result<Vec<u8>> {
    let sig: Signature = key.sign(&head_bytes(tree_size, root, timestamp));
    Ok(sig.to_vec())
}

fn encoding_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    #[test]
    fn empty_log_roots_to_sha256_empty_string() {
        let log = MerkleLog::new();
        assert_eq!(log.tree_size(), 0);
        let expected: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(log.root_hash(), expected);
    }

    #[test]
    fn single_leaf_matches_leaf_hash() {
        let mut log = MerkleLog::new();
        let root = log.append(b"a");
        assert_eq!(root, leaf_hash(b"a"));
    }

    #[test]
    fn append_order_changes_root() {
        let mut l1 = MerkleLog::new();
        let mut l2 = MerkleLog::new();
        l1.append(b"a");
        l1.append(b"b");
        l2.append(b"b");
        l2.append(b"a");
        assert_ne!(l1.root_hash(), l2.root_hash());
    }

    #[test]
    fn deterministic_across_instances() {
        let items: Vec<&str> = vec!["a", "b", "c", "d", "e", "f", "g"];
        let mut l1 = MerkleLog::new();
        let mut l2 = MerkleLog::new();
        for i in &items {
            l1.append(i.as_bytes());
            l2.append(i.as_bytes());
        }
        assert_eq!(l1.root_hash(), l2.root_hash());
    }

    #[test]
    fn inclusion_proof_holds_for_every_leaf_odd_and_even_sizes() {
        for size in [1usize, 2, 3, 4, 5, 7, 8, 9] {
            let mut log = MerkleLog::new();
            let data: Vec<String> = (0..size).map(|i| format!("leaf-{i}")).collect();
            for d in &data {
                log.append(d.as_bytes());
            }
            let head = log.sign_tree_head(&test_key(1)).unwrap();
            assert!(head.verify().is_ok(), "size {size}: head must verify");
            for (i, d) in data.iter().enumerate() {
                let proof = log.inclusion_proof(i as u64).unwrap();
                proof
                    .verify(d.as_bytes(), &head)
                    .unwrap_or_else(|e| panic!("size {size} index {i}: {e}"));
            }
        }
    }

    #[test]
    fn tampered_data_fails_inclusion() {
        let mut log = MerkleLog::new();
        log.append(b"honest");
        let head = log.sign_tree_head(&test_key(1)).unwrap();
        let proof = log.inclusion_proof(0).unwrap();
        assert!(proof.verify(b"tampered", &head).is_err());
    }

    #[test]
    fn proof_from_other_log_fails() {
        let mut log_a = MerkleLog::new();
        log_a.append(b"a");
        let mut log_b = MerkleLog::new();
        log_b.append(b"x");
        let head_b = log_b.sign_tree_head(&test_key(1)).unwrap();
        let proof = log_a.inclusion_proof(0).unwrap();
        assert!(proof.verify(b"a", &head_b).is_err());
    }

    #[test]
    fn head_signature_is_key_bound() {
        let mut log = MerkleLog::new();
        log.append(b"data");
        let head_good = log.sign_tree_head(&test_key(7)).unwrap();
        assert!(head_good.verify().is_ok());

        // Head re-signed by a different key must not pass under its own
        // embedded key check — forge one and confirm rejection.
        let mut forged = log.sign_tree_head(&test_key(7)).unwrap();
        let other = test_key(8);
        forged.signature =
            super::sign_head(forged.tree_size, forged.root_hash, forged.timestamp, &other).unwrap();
        assert!(forged.verify().is_err());
    }

    #[test]
    fn head_serialization_round_trip() {
        let mut log = MerkleLog::new();
        log.append(b"payload");
        let head = log.sign_tree_head(&test_key(3)).unwrap();
        let json = serde_json::to_string(&head).unwrap();
        let back: SignedTreeHead = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tree_size, head.tree_size);
        assert_eq!(back.root_hash, head.root_hash);
        assert!(back.verify().is_ok());
    }

    #[test]
    fn out_of_range_index_rejected() {
        let mut log = MerkleLog::new();
        log.append(b"only");
        assert!(log.inclusion_proof(1).is_err());
        assert!(log.inclusion_proof(u64::MAX).is_err());
    }
}
