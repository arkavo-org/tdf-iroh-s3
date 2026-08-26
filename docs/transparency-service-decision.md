# Decision: tdf-iroh-s3 as host for the customer-operated transparency service (Epic 4.2)

Status: recommendation (spike outcome, Epic 0.3 input)
Date: 2026-08-25

## Question

For the in-cluster SCITT-style transparency service (Merkle log, COSE receipts, keys in
customer KMS, no outbound network): extend `tdf-iroh-s3` or build greenfield?

## What tdf-iroh-s3 already provides

- **CWT/COSE auth stack**: verifier with key cache (`auth/cwt.rs`, `auth/cose_keys.rs`),
  PEP-style attribute checks (`auth/pep_check.rs`), fail-closed boot semantics.
- **PDP integration**: cached attribute definitions from a policy endpoint (`pdp/`).
- **Content addressing**: BLAKE3 hashes via iroh-blobs; manifests stored in S3 by hash.
- **Append-only event log**: redb-backed single-author event store (`catalog/store.rs`)
  already used for content events.
- **Protocol scaffolding**: ALPN-based `ProtocolHandler` pattern (`protocol/catalog_read.rs`)
  with per-peer identity, subscription limits, cancellation.
- **Deployment shape**: config-driven, no UI, runs headless; SSM-backed node key.

## What is missing for a transparency service

1. Merkle tree / log structure with inclusion proofs (redb log is flat, not hash-chained).
2. RFC 9162-style signed tree heads and consistency proofs.
3. COSE Receipt issuance per draft-ietf-cose-merkle-tree-proofs.
4. KMS/HSM signing (PKCS#11 or cloud KMS) — current key handling is local/SSM only.
5. Air-gapped operation guarantees (no reqwest fetches at runtime; today the COSE key and
   PDP caches poll remote URLs).

## Recommendation: extend, as a new sibling crate

Reuse this repo's auth/PDP/catalog crates but implement the log service as a separate
binary/crate (e.g. `tdf-transparency`) rather than growing `main.rs`:

- The auth stack (CWT verification, key caching) and event-store patterns are exactly what
  4.2 needs; rewriting them greenfield duplicates ~1.5k lines of tested code.
- The transparency service must run air-gapped with no S3 dependency, so it cannot share
  the main binary's config surface; isolation keeps the existing S3 peer node simple.
- Greenfield was rejected because the hard parts (COSE, fail-closed caching, protocol
  handlers) are done and tested here.

## Prerequisite work before starting

- Extract `auth/` and `catalog/` into workspace crates so both binaries share them.
- Replace URL-polling key refresh with a pluggable source (file/KMS) for offline use.
- Bump note: this repo now builds against iroh 1.0.x / iroh-blobs 0.103; keep any new
  crate on the same line.
