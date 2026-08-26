# Decision: tdf-iroh-s3 as host for the customer-operated transparency service (Epic 4.2)

Status: recommendation (spike outcome, Epic 0.3 input)
Date: 2026-08-25

## Question

For the in-cluster SCITT-style transparency service (Merkle log, COSE receipts, keys in
customer KMS, no outbound network): extend `tdf-iroh-s3` or build greenfield?

## What tdf-iroh-s3 already provides

- **CWT/COSE auth stack**: `src/auth.rs` (`CwtVerifier`) verifies COSE_Sign1 CWTs against
  a fetched-and-refreshed COSE key set URL or injected static keys, with issuer checks;
  `src/authz.rs` mints service tokens via client_credentials with cached refresh.
- **Attribute validation**: `src/attributes.rs` loads OpenTDF-shaped attribute definitions
  (`AttributeSet`), validates FQNs against the platform's endpoint
  (`fetch_attribute_fqns`), and serves them over an axum router.
- **Content addressing**: BLAKE3 hashes computed at ingest (`src/ingest.rs`) using
  iroh-blobs' `FsStore`; manifests stored in S3 by hash.
- **Catalog layer**: `src/catalog.rs` extracts attribute FQNs from policy JSON and derives
  per-group artifacts; `src/catalog_api.rs` defines the pluggable `CatalogStore` trait
  (implemented by `src/store/s3.rs::S3Client`, with an in-memory impl for tests), a TTL
  cache, and the `/catalog` + decision endpoints.
- **Deployment shape**: config-driven (`src/config.rs`), no UI, runs headless; SSM-backed
  node key (`src/ssm.rs`, `src/secret_key.rs`).

## What is missing for a transparency service

1. Merkle tree / log structure with inclusion proofs (the current catalog is a flat
   S3-backed entry list, not hash-chained).
2. RFC 9162-style signed tree heads and consistency proofs.
3. COSE Receipt issuance per draft-ietf-cose-merkle-tree-proofs.
4. KMS/HSM signing (PKCS#11 or cloud KMS) — current key handling is local/SSM only
   (`src/ssm.rs`).
5. Air-gapped operation guarantees (no outbound HTTP at runtime; today `src/auth.rs`
   refreshes keys and `src/attributes.rs` fetches FQNs from remote URLs).

## Recommendation: extend, as a new sibling crate

Reuse this repo's auth/catalog crates but implement the log service as a separate
binary/crate (e.g. `tdf-transparency`) rather than growing `main.rs`:

- The auth stack (`CwtVerifier`, client_credentials flow) and the `CatalogStore`
  abstraction are exactly what 4.2 needs; rewriting them greenfield duplicates well over
  a thousand lines of tested code.
- The transparency service must run air-gapped with no S3 dependency, so it cannot share
  the main binary's config surface; isolation keeps the existing S3 peer node simple.
- Greenfield was rejected because the hard parts (COSE verification, key caching,
  attribute handling) are done and tested here.

## Prerequisite work before starting

- Extract `auth.rs`, `authz.rs`, `catalog.rs`, `catalog_api.rs`, and `attributes.rs`
  into workspace crates so both binaries share them.
- Replace URL-based key/FQN refresh with a pluggable source (file/KMS) for offline use.
- Keep any new crate on the same iroh line this repo builds against (iroh 1.0.x /
  iroh-blobs 0.103).
