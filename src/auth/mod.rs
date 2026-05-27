//! CWT (COSE_Sign1) verification against an issuer-published COSE_KeySet.
//!
//! Supported algorithms: ES256 only. Supported COSE_Key shapes:
//! `kty = EC2`, `crv = P-256`. Other shapes are dropped at parse time, not
//! at verify time.
//!
//! Replay protection is intentionally minimal — the verifier records `cti`
//! values in [`VerifiedClaims`] for audit logging but does not maintain a
//! seen-set. Issuers are expected to keep `exp` short and bind tokens via
//! `cnf.iroh_node_id` when single-use semantics matter.

pub mod cose_keys;
pub mod cwt;
pub mod pep_check;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_signer;

pub use cose_keys::CoseKeyCache;
pub use cwt::{Grant, VerifiedClaims, VerifyError, Verifier};

/// Required `scope` value at the catalog read ALPN per Arkavo CWT v1
/// (Appendix A.2 of the reader-side spec).
pub const SCOPE_CATALOG_READ: &str = "catalog.read";

/// Only `authorization_details[].actions` name accepted in v1
/// (Appendix A.3). Unknown action names reject the **whole token**.
pub const ACTION_READ: &str = "read";

/// Legacy publisher-side scope retained until Task 12 rewrites
/// `test_signer`. Do not consume from new code — read paths require
/// [`SCOPE_CATALOG_READ`] and the publisher path is being reworked.
pub const SCOPE_CATALOG_WRITE: &str = "catalog.write";
