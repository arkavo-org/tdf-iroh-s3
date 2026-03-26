# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A persistent Iroh peer node that validates incoming blobs as OpenTDF files and stores them in Amazon S3. Blobs are keyed by BLAKE3 content hash. Access control is handled by the TDF encryption layer, not the node itself.

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

```
Iroh peer (QUIC) → Endpoint → MemStore buffer
  → Validation pipeline (structure → attributes → assertion)
  → BLAKE3 hash → S3 existence check → S3 upload
```

### Key Modules

- **`node.rs`** — `TdfIrohNode`: Iroh endpoint lifecycle, binds QUIC port, registers BlobsProtocol. S3 client and config shared via `Arc`.
- **`ingest.rs`** — `ingest_blob()`: orchestrates validate → hash → deduplicate → upload.
- **`validation/`** — Three-stage pipeline: `structure.rs` (ZIP/manifest via `opentdf::TdfArchive`), `attributes.rs` (required FQN lookup in policy), `assertion.rs` (policy binding hash + optional signature verification).
- **`store/s3.rs`** — `S3Client` wrapping AWS SDK. S3 key layout: `{prefix}blobs/<hash>`, `{prefix}outboards/<hash>`, `{prefix}tags/<name>`. Has mock support for tests.
- **`config.rs`** — TOML config with sections: `[iroh]`, `[s3]`, `[validation]`, `[validation.assertion]`. Default port 11204.
- **`test_cli/`** — Separate binary for manual testing: `create-tdf`, `push`, `push-raw`, `fetch` subcommands.

### Key Dependencies

- `iroh` 0.97 / `iroh-blobs` 0.99 — P2P networking
- `opentdf` (git dep from arkavo-org/opentdf-rs) — TDF parsing/validation
- `aws-sdk-s3` — Blob storage
- `tokio` (full) — Async runtime

## Deployment

Packer AMI build (`packer/ami.pkr.hcl`) for Amazon Linux 2023. Systemd service runs the binary with `--config /etc/tdf-iroh-s3/config.toml`. Bootstrap script fetches config from EC2 user-data (IMDSv2) if no config file exists.

## Rust Toolchain

Pinned to `stable` via `rust-toolchain.toml`. Minimum supported version: 1.91 (edition 2024).
