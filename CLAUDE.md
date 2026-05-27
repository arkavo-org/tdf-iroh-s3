# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A persistent Iroh peer node that validates incoming blobs as OpenTDF files and stores them in Amazon S3. Blobs are keyed by BLAKE3 content hash. A CWT-gated read path lets authorized peers query the redb event-log catalog over the `tdf/catalog/1` ALPN.

Reader-side CWT + redb event log — see [`docs/superpowers/specs/2026-05-26-reader-side-cwt-and-redb-event-log-design.md`](docs/superpowers/specs/2026-05-26-reader-side-cwt-and-redb-event-log-design.md) and the implementation plan alongside it.

## Build & Test Commands

```bash
cargo build                     # Debug build
cargo build --release           # Release build
cargo test                      # All tests
cargo test <test_name>          # Single test by name
cargo test --test e2e_test      # Single test file from tests/
```

The binary `tdf-iroh-s3-test` is the test CLI (not the main service):
```bash
cargo run --bin tdf-iroh-s3-test -- <subcommand>
```

## Architecture

**Single crate** (not a workspace). Library modules in `src/`, integration tests in `tests/`.

### Data Flow

Write path (ingest):
```
Iroh peer (QUIC) → Endpoint → MemStore buffer
  → Validation pipeline (structure → attributes → assertion)
  → BLAKE3 hash → S3 existence check → S3 upload
  → EventStore (redb) ← catalog event appended
```

Read path (catalog):
```
Peer connects via tdf/catalog/1 ALPN
  → CWT token extracted and verified (pep_check)
  → AccessPdpCache checks attribute entitlements
  → EventStore queried → filtered event log returned
```

### Key Modules

- **`node.rs`** — `TdfIrohNode`: Iroh endpoint lifecycle, binds QUIC port, registers BlobsProtocol and `tdf/catalog/1` handler. S3 client and config shared via `Arc`.
- **`ingest.rs`** — `ingest_blob()`: orchestrates validate → hash → deduplicate → upload → catalog append.
- **`validation/`** — Three-stage pipeline: `structure.rs` (ZIP/manifest via `opentdf::TdfArchive`), `attributes.rs` (required FQN lookup in policy), `assertion.rs` (policy binding hash + optional signature verification).
- **`store/s3.rs`** — `S3Client` wrapping AWS SDK. S3 key layout: `{prefix}blobs/<hash>`, `{prefix}outboards/<hash>`, `{prefix}tags/<name>`. Has mock support for tests.
- **`catalog/store.rs`** — `EventStore` backed by redb. Appends ingest events; queries return a filtered, time-bounded list for authorized peers.
- **`pdp/cache.rs`** — `AccessPdpCache`: fetches attribute definitions from `pdp.attribute_defs_url`, caches them, and evaluates entitlements for incoming read requests.
- **`auth/cwt.rs`** — `Verifier`: validates CWT tokens against the rotating COSE_KeySet fetched from `auth.cose_keys_url`, enforcing issuer and expiry.
- **`auth/pep_check.rs`** — Policy Enforcement Point logic, vendored from opentdf-rs; called by `Verifier` to decide permit/deny.
- **`protocol/catalog_read.rs`** — `tdf/catalog/1` ALPN handler: accepts a peer connection, extracts the CWT bearer token, enforces PDP, and streams matching catalog events.
- **`config.rs`** — TOML config with sections: `[iroh]`, `[s3]`, `[validation]`, `[validation.assertion]`, `[catalog]`, `[auth]`, `[pdp]`. Default port 11204.
- **`test_cli/`** — Separate binary for manual testing: `create-tdf`, `push`, `push-raw`, `fetch` subcommands.

### Key Dependencies

- `iroh` 0.97 / `iroh-blobs` 0.99 — P2P networking (iroh-docs and iroh-gossip are not used)
- `opentdf` 0.12 (git dep from arkavo-org/opentdf-rs) — TDF parsing/validation; `pep_check` module vendored locally in `src/auth/pep_check.rs`
- `redb` 2 — embedded key-value store for the catalog event log (`events.redb`)
- `aws-sdk-s3` — Blob storage
- `tokio` (full) — Async runtime

## Deployment

Packer AMI build (`packer/ami.pkr.hcl`) for Amazon Linux 2023. Systemd service runs the binary with `--config /etc/tdf-iroh-s3/config.toml`. Bootstrap script (`packer/files/bootstrap.sh`) fetches the config from EC2 user-data (IMDSv2) if no config file exists — it does **not** write a default template.

`Config::validate()` is fail-closed: the service will crash-loop unless all of the following are present and non-empty in the user-data config.toml:

```toml
[s3]
bucket = "..."
region = "..."

[catalog]
data_dir = "/var/lib/tdf-iroh-s3/catalog"   # default; directory must exist

[auth]
cose_keys_url = "https://identity.arkavo.net/.well-known/cose-keys"
issuer        = "https://identity.arkavo.net"

[pdp]
attribute_defs_url = "https://identity.arkavo.net/.well-known/attributes"
```

The `packer/scripts/install.sh` creates `/var/lib/tdf-iroh-s3/catalog` (owned by `tdf-iroh-s3`) so that the default `catalog.data_dir` is writable on first boot.

## Rust Toolchain

Pinned to `stable` via `rust-toolchain.toml`. Minimum supported version: 1.91 (edition 2024).
