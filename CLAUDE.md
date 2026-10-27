# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A persistent Iroh peer node that validates incoming blobs as OpenTDF files, stores them in Amazon S3 and serves them back from S3. Blobs are keyed by BLAKE3 content hash. Read access to content is controlled by the TDF encryption layer. The node controls who may *publish*: an entitlement plus a publish session for pushes, operator suspensions and content blocks. See `docs/publishing-and-moderation.md` and `src/moderation.rs`.

Creators publish a catalog of their recordings as an `arkavo.creator-catalog/2` document, encrypted as the payload of a ZTDF envelope under the creator's campaign attribute; each entry names a metadata TDF holding the title and attributes under the recording's policy (#39). The node stores the envelope by hash, behind the creator's passkey-signed pointer (catalog v2), never decrypts it, and checks the entries through a clear index the publisher sends alongside. `docs/creator-catalogs.md` is the contract between this node, the Creator app and the iOS viewer: routes, status codes, error strings and validation rules there are authoritative.

## Build & Test Commands

```bash
cargo build                     # Debug build
cargo build --release           # Release build
cargo test                      # All tests
cargo test <test_name>          # Single test by name
cargo test --test e2e_test      # Single test file from tests/
cargo fmt && cargo clippy --all-targets   # Both must be clean
```

The binary `tdf-iroh-s3-test` is the test CLI (not the main service):
```bash
cargo run --bin tdf-iroh-s3-test -- <subcommand>
```

## Architecture

**Single crate** (not a workspace). Library modules in `src/`, integration tests in `tests/`.

### Data Flow

```
Push:
Iroh peer (QUIC) → Endpoint → BlobsHandler → iroh-blobs provider → FsStore
  (staging only; single-blob pushes only; publish gate on push; pending until
  ingest is done with it; a push whose declared size exceeds max_blob_bytes
  has its connection closed, and so does one that stalls)
  → export to <data_dir>/ingest scratch file → size check
  → validation from the file in spawn_blocking (structure → attributes → assertion)
  → BAO outboard from the file (iroh block size, root checked against the hash)
  → S3 outboards/<hash> → S3 existence check → S3 blobs/<hash> streamed from
  the file (upload retried twice, after 1 s and 5 s) → manifest + catalog index
  (refused or failed → no blob in S3, so `GET /blobs/<hash>` stays 404; the publisher pushes again)
  The store's GC (every gc_interval_secs) deletes every stored blob no pending
  push needs, so the staged copy goes once ingest is done.
Fetch (get/get_many, single blobs only, at most 64 hashes per get_many):
BlobsHandler → S3Server: blocked? → HEAD blobs/<hash> and outboards/<hash>
  (remembered) → the blob's size, then the BAO encoding of the requested ranges
  read through range GETs from both objects. The node keeps no copy.
  Observe and hash-sequence requests are refused.
  A blob without an outboard (ingested before outboards) is refused as "try
  again" while the node computes the outboard by streaming it from S3 once.
  Refusals: Permission (ERR 1) is final (blocked, or not in S3);
  ERR_LIMIT (ERR 2) is "try again" (S3 silent, outboard being computed, 256
  fetches at once, or a transfer S3 broke off)
```

### Key Modules

- **`node.rs`** — `TdfIrohNode`: Iroh endpoint lifecycle, binds QUIC port, loads the FsStore with staging's GC config, runs the node's own blobs protocol handler (`BlobsHandler`) and the ingest loop. The handler keeps open connections by `stable_id`, so an oversize or stalled push's connection can be closed. A push goes to iroh-blobs' provider into the store and raises events: the loop refuses a hash-sequence push, and with a gate also a push without a publish session; `connected` is intercepted only with a gate, to learn the pusher's endpoint ID. A get or get_many never reaches the store: the handler answers it from `S3Server`, after the blocked-hash check (get_many over 64 hashes, hash-sequence gets and observe are refused; at most 256 fetches at once, else `ERR_LIMIT`). Each request type follows its own `EventMask` field (iroh-blobs#270), and push is `Disabled` by default. `wait_and_ingest` waits for the push to end (watching it for size and `push_stall_secs`); `ingest_stored` validates, then uploads with two retries. A push whose connection stalls (`push_stall_secs`) or declares more than max_blob_bytes is closed; a stalled one is then checked like an aborted transfer. S3 client and config shared via `Arc`.
- **`s3_serve.rs`** — `S3Server`: serves a get from `blobs/<hash>` and `outboards/<hash>`, or else a catalog v2 document from `catalog-documents/<hash>` and `catalog-outboards/<hash>` (`Object` says which; a document's owner is remembered so the handler can apply `hideCatalog`). `check()` HEADs both (10 s timeout) and remembers the size of each servable blob (bounded); `send()` writes the size, then the BAO encoding of the requested ranges (`encode_ranges_validated`) through one sequential range GET per object (a GET that sends nothing for 30 s fails). `Refusal::Gone` (final) is a missing blob; `Refusal::Busy` (try again) is an S3 error or timeout, or an outboard being computed. A blob with no outboard, or one of the wrong size, gets its outboard computed from S3 in the background (at most 2 at once, root checked against the hash) and stored. A send that breaks off forgets the blob, so the next fetch asks S3 again (a blob deleted from S3 is then `Gone`). A hash mismatch (the object no longer matches its key), found while sending or computing an outboard, is never sent, logged as an error, and makes the hash `Gone` until restart. A failed outboard computation is not retried for 10 min. A write to a fetcher that makes no progress for 60 s (`PEER_STALL`) fails the send, so a peer that stops reading cannot hold a serve slot.
- **`ingest.rs`** — `validate_from_store()` (export to a scratch file, validate it off the runtime, compute the outboard from the same file) then `upload()` (outboard first, then the blob streamed to S3, then derived artifacts); `IngestError::Refused` vs `Failed`. A blob of 16 KiB or less has a zero-length outboard. The BLAKE3 hash is the push's; it is not recomputed, but the outboard's root is checked against it.
- **`staging.rs`** — the local store as push staging. A push is pending (`Staging::track`, a `PendingPush` guard) from acceptance until ingest is done with it. The store's garbage collector (the only deletion iroh-blobs exposes), run every `[iroh] gc_interval_secs`, keeps exactly the pending pushes (read before and after listing the store) and deletes every other stored blob. Nothing local is served, so nothing is withheld or persisted. iroh-blobs ends the collector's loop for good after a failed run, so `Staging::collector_stopped` watches the protect callback (called at the start of every run): after 5 intervals + 60 s without one, and once no push is pending, `main` shuts the node down and exits non-zero, and systemd restarts it with a fresh collector. The store never inlines outboards (`max_outboard_inlined: 0`): iroh-blobs leaves the `.obao4` file of an inlined outboard behind for good.
- **`validation/`** — `max_blob_bytes` check, then three stages: `structure.rs` (ZIP central directory + manifest via the `zip` crate from any `Read + Seek`: at most 65,535 members, checked on every ZIP64 end record before the reader reserves, and at most 16 MiB read while opening; manifest bounded to 4 MiB; payload member read to its end so its CRC is checked, and refused if it would inflate past the archive; spec layout `manifest.json` + the member `payload.url` names, or legacy `0.manifest.json` + `0.payload`), `attributes.rs` (required FQN lookup in policy), `assertion.rs` (policy binding hash + optional signature verification).
- **`catalog.rs`** / **`catalog_api.rs`** — ingest-time index (`manifests/`, `catalog-index/<group>/`) and the entitled `GET /catalog/{group}` listing (AuthZEN decisions via `authz.rs`; for a campaign group, the campaign's `creator` from `campaign-creators/`, only to a reader entitled to the campaign FQN). Policies come in the spec form (`{"attribute": "<FQN>"}`) and opentdf-rs's structured form; both are read.
- **`creator_catalog.rs`** — pure parser/validator for a catalog's clear index (`PUT /v2/catalogs` `index`): at most 1000 `/2` entries, strict (unknown and duplicate keys rejected), unique `contentID`s, metadata hashes unique and never a payload. Runs ArkavoKit's shared vectors (`tests/fixtures/arkavo-catalog-vectors.json`).
- **`catalog_metadata.rs`** — pure manifest checks: a metadata TDF against its recording (policy `uuid` + `body` only, catalog-entry type, same attributes, dissem and KAS) and the catalog envelope (`check_envelope`: catalog type, `uuid` + `body`, exactly one campaign or the subject's creator attribute).
- **`catalog_metadata.rs`** — pure: a `/2` entry's metadata TDF against its recording, on the stored manifests (`manifests/<hash>`): policy only `uuid` + `body`, `payload.mimeType` `application/vnd.arkavo.catalog-entry+json` (`CATALOG_ENTRY_MIME_TYPE`; `catalog::derive_artifacts` indexes no blob of that type), same `dataAttributes`/`dissem` (as sets) and KAS URLs.
- **`catalogs_api.rs`** — `GET /catalog-documents/{hash}` (the envelope, `application/zip`), `GET /blobs/{hash}`, and `check_payloads`: the per-entry publish checks on an index, ending with the invariant that every recording names the envelope's attribute.
- **`catalog_v2.rs`** / **`catalogs_v2_api.rs`** — catalog v2 (tdf-iroh-s3#27): the creator's passkey-signed pointer, the IdP's COSE_Sign1 credential attestation (authnz-rs#104) and the WebAuthn assertion check (pure, in `catalog_v2.rs`); `PUT /v2/catalogs/{sub}`, the only catalog publish (`{document, bundle, index}`: verify the bundle, the envelope (`check_envelope`), the index and its entries (`check_payloads`), IdP credential status, `If-Match`/`If-None-Match` base check (412, tdf-iroh-s3#29), `seq` greater than stored, a campaign envelope only from that campaign's creator (`arkavo_patreon` role `creator` + `campaign_id`, else 403), then envelope + outboard + `catalog-indexes/<hash>` (never served) + `campaign-creators/<id>`, then a conditional pointer write; a stored pointer with no index record, from before envelopes, reads as none) and `GET /v2/catalogs/{sub}` (a token, then the `[catalog.authz]` decision on the envelope's attribute: 403 `not entitled to catalog`, 502 `decision unavailable`; an operator's service CWT, as the moderation API admits one, skips it; `ETag: "<seq>"`). The envelope itself is served over iroh by `S3Server`.
- **`tags_api.rs`** — the catalog APIs' shared `ApiState` and `TagStore` trait, `/healthz`, `authorize_publisher` (gated: `PublishPolicy::publisher`; ungated: token verification only) and `authorize_catalog_reader` (a verified token, checked first on `GET /v2/catalogs/*`). The tag routes were retired with catalog `/1`.
- **`node_api.rs`** — `GET /node`: endpoint ID and relay from the running endpoint, `directAddresses` from `[iroh] public_addresses`.
- **`moderation.rs`** — publishing gate, publish sessions (`POST /publish/sessions`, signed by the endpoint key; held in memory and stored at `moderation/sessions/<endpoint>`, which a push on another instance or after a restart reads back, #32), suspensions, blocks, catalog blocks by subject (`moderation/catalog-blocks/<sub>`, hiding the tag, v2 pointer and the subject's catalog documents), audit records.
- **`publish_decision.rs`** — `[publishing] decisions = local | shadow | pdp` (#35): whether a subject may publish, asked of the platform's decision service (AuthZEN, `publisher` resource, the person + `X-Entity-Token` devices + environment chain). `pdp` fails closed. Asked at session open only: a session the PDP permitted stores the token-free chain, and its pushes are accepted until it expires (#44).
- **`entity_chain.rs`** — the verified entity chain (person, DeviceCheck devices, environment) shared by the catalog and publish decisions.
- **`auth.rs`** — CWT (COSE_Sign1 ES256) verification against the IdP's COSE key set.
- **`store/s3.rs`** — `S3Client` wrapping AWS SDK (`from_config` honors `[s3] endpoint_url` / `force_path_style`). S3 key layout under `{prefix}` (empty in production): `blobs/<hash>`, `outboards/<hash>` (the BAO hash tree, written before the blob), `manifests/<hash>`, `catalog-index/<group>/<hash>`, `catalog-documents/<hash>` (envelopes), `catalog-outboards/<hash>`, `catalog-indexes/<hash>` (never served), `campaign-creators/<campaign id>`, `catalog-pointers/<sub>` (catalog v2), `moderation/...`. `S3Client::new_mock` only builds keys; route tests use in-memory stores implementing the store traits (`tags_api::test_support::MemStore`).
- **`config.rs`** — TOML config with sections: `[iroh]` (incl. `gc_interval_secs`, `push_stall_secs`), `[s3]`, `[validation]` (incl. `max_blob_bytes`, `max_concurrent_ingests`), `[validation.assertion]`, `[http]` (incl. `passkey_rp_id`, `passkey_status_url`, `catalog_token` (optional | required: a token on `GET /catalog/{group}`)), `[catalog]`, `[catalog.authz]` (also the publish decisions' client), `[publishing]` (incl. `decisions`). Default iroh port 11204, HTTP 8090.
- **`test_cli/`** — Separate binary for manual testing: `create-tdf`, `push`, `push-raw`, `fetch`, `publish-session`, `publish` (`--secret-key-file` keeps one endpoint key across a session and its push).

### Key Dependencies

- `iroh` 1.3 / `iroh-blobs` 0.103.1 — P2P networking
- `opentdf` 0.16 (crates.io, `default-features = false`) — TDF parsing/validation
- `aws-sdk-s3` — Blob storage
- `axum` 0.8 — HTTP API
- `tokio` (full) — Async runtime

## Deployment

Packer AMI build (`packer/ami.pkr.hcl`) for Amazon Linux 2023 arm64; it pulls the gzipped binary from `binary_s3_uri` using `iam_instance_profile`, both required variables (Arkavo's values: `production/ami.pkrvars.hcl`, gitignored). Systemd service runs the binary with `--config /etc/tdf-iroh-s3/config.toml`. Bootstrap script fetches config from EC2 user-data (IMDSv2) if no config file exists. The CloudWatch agent ships the `tdf-iroh-s3` and `tdf-iroh-s3-cert-sync` journal to the log group `tdf-iroh-s3` (stream per instance ID), creating the group with a 90-day retention; the instance role's `logs:` permissions are set up outside the AMI. Full procedure, TLS and smoke checks: `production/deploy-runbook.md` (Arkavo-specific, gitignored: local only, never commit it; the repo is public).

## Rust Toolchain

Pinned to `stable` via `rust-toolchain.toml`. Minimum supported version: 1.91 (edition 2024).
