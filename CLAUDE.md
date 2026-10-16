# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A persistent Iroh peer node that validates incoming blobs as OpenTDF files and stores them in Amazon S3. Blobs are keyed by BLAKE3 content hash. Read access to content is controlled by the TDF encryption layer. The node controls who may *publish*: an entitlement plus a publish session for pushes, operator suspensions and content blocks. See `docs/publishing-and-moderation.md` and `src/moderation.rs`.

Creators publish a catalog of their recordings as a JSON document (`arkavo.creator-catalog/1`) the node stores by hash behind the tag `catalog/<sub>`. `docs/creator-catalogs.md` is the contract between this node, the Creator app and the iOS viewer: routes, status codes, error strings and validation rules there are authoritative.

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
Iroh peer (QUIC) → Endpoint → FsStore (publish gate on push; pending, withheld;
  a push whose declared size exceeds max_blob_bytes has its connection closed)
  → export to <data_dir>/ingest scratch file → size check
  → validation from the file in spawn_blocking (structure → attributes → assertion)
  → S3 existence check → S3 upload streamed from the file → manifest + catalog index
  (refused → withheld, deleted by the store's GC via quarantine.rs)
```

### Key Modules

- **`node.rs`** — `TdfIrohNode`: Iroh endpoint lifecycle, binds QUIC port, registers BlobsProtocol (wrapped to keep open connections by `stable_id`, so an oversize push's connection can be closed), loads the FsStore with the quarantine's GC config, runs the ingest loop: it intercepts push, get, get_many and observe gated or not (withheld hashes refused; with a gate also the push session check and blocked-hash refusal). Each request type follows its own `EventMask` field (iroh-blobs#270), and push is `Disabled` by default. S3 client and config shared via `Arc`.
- **`ingest.rs`** — `validate_from_store()` (export to a scratch file, validate it off the runtime) then `upload()` (stream to S3, derived artifacts); `IngestError::Refused` vs `Failed`. The BLAKE3 hash is the push's; it is not recomputed.
- **`quarantine.rs`** — pending (tracked, not yet validated) and refused pushes; both withheld from get/get_many/observe. Refused blobs are deleted by the FsStore garbage collector (the only deletion iroh-blobs exposes) through its protect callback; persisted in `<data_dir>/refused-blobs`. A push of a hash the node already holds is not tracked, a validated hash is never refused, and S3-ingested hashes are never deleted.
- **`validation/`** — `max_blob_bytes` check, then three stages: `structure.rs` (ZIP central directory + manifest via the `zip` crate from any `Read + Seek`, manifest bounded to 4 MiB, payload member must exist; spec layout `manifest.json` + the member `payload.url` names, or legacy `0.manifest.json` + `0.payload`), `attributes.rs` (required FQN lookup in policy), `assertion.rs` (policy binding hash + optional signature verification).
- **`catalog.rs`** / **`catalog_api.rs`** — ingest-time index (`manifests/`, `catalog-index/<group>/`) and the entitled `GET /catalog/{group}` listing (AuthZEN decisions via `authz.rs`). Policies come in the spec form (`{"attribute": "<FQN>"}`) and opentdf-rs's structured form; both are read.
- **`creator_catalog.rs`** — pure parser/validator for creator catalog documents (strict: unknown and duplicate keys rejected, exact timestamps, limits).
- **`catalogs_api.rs`** — `PUT /catalogs/{sub}`, `GET /catalog-documents/{hash}`, `GET /blobs/{hash}`; shares `ApiState` and the `TagStore` trait with `tags_api.rs`.
- **`tags_api.rs`** — `GET/PUT /tags/{name}`, `/healthz`, and `authorize_publisher` (gated: `PublishPolicy::publisher`; ungated: token verification only). A catalog tag may only point at a stored catalog document of its subject.
- **`node_api.rs`** — `GET /node`: endpoint ID and relay from the running endpoint, `directAddresses` from `[iroh] public_addresses`.
- **`moderation.rs`** — publishing gate, publish sessions (`POST /publish/sessions`, signed by the endpoint key), suspensions, blocks, audit records.
- **`auth.rs`** — CWT (COSE_Sign1 ES256) verification against the IdP's COSE key set.
- **`store/s3.rs`** — `S3Client` wrapping AWS SDK (`from_config` honors `[s3] endpoint_url` / `force_path_style`). S3 key layout under `{prefix}`: `blobs/<hash>`, `outboards/<hash>`, `manifests/<hash>`, `catalog-index/<group>/<hash>`, `catalog-documents/<hash>`, `tags/<name>`, `moderation/...`. `S3Client::new_mock` only builds keys; route tests use in-memory stores implementing the store traits (`tags_api::test_support::MemStore`).
- **`config.rs`** — TOML config with sections: `[iroh]` (incl. `gc_interval_secs`), `[s3]`, `[validation]` (incl. `max_blob_bytes`, `max_concurrent_ingests`), `[validation.assertion]`, `[http]`, `[catalog]`, `[catalog.authz]`, `[publishing]`. Default iroh port 11204, HTTP 8090.
- **`test_cli/`** — Separate binary for manual testing: `create-tdf`, `push`, `push-raw`, `fetch`, `publish-session`, `publish`, `put-catalog` (`--secret-key-file` keeps one endpoint key across a session and its push).

### Key Dependencies

- `iroh` 1.3 / `iroh-blobs` 0.103.1 — P2P networking
- `opentdf` 0.16 (crates.io, `default-features = false`) — TDF parsing/validation
- `aws-sdk-s3` — Blob storage
- `axum` 0.8 — HTTP API
- `tokio` (full) — Async runtime

## Deployment

Packer AMI build (`packer/ami.pkr.hcl`) for Amazon Linux 2023 arm64; it pulls the gzipped binary from `s3://arkavo-report/packer/tdf-iroh-s3.gz`. Systemd service runs the binary with `--config /etc/tdf-iroh-s3/config.toml`. Bootstrap script fetches config from EC2 user-data (IMDSv2) if no config file exists. Full procedure, TLS and smoke checks: `docs/deploy-runbook.md`.

## Rust Toolchain

Pinned to `stable` via `rust-toolchain.toml`. Minimum supported version: 1.91 (edition 2024).
