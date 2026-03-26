# tdf-iroh-s3: TDF-Validated Iroh Peer with S3 Blob Storage

## Overview

A Rust binary that runs as a persistent Iroh peer node on EC2. It accepts blobs from Iroh peers, validates they are legitimate OpenTDF files with required attributes, and stores them permanently on S3. Stored blobs are served back to any requesting Iroh peer — access control is handled by the TDF encryption layer, not the node.

## Goals

- Accept blobs over Iroh's P2P QUIC protocol
- Validate each blob is a valid TDF with configurable required attributes
- Optionally verify TDF assertion signatures against trusted public keys
- Store accepted blobs durably in S3, keyed by BLAKE3 content hash
- Serve stored blobs back to Iroh peers, streamed from S3
- Run as a systemd service on a custom Amazon Linux 2023 AMI
- Support multiple deployment configurations from a single AMI

## Non-Goals

- No KAS (Key Access Service) interaction — validation is structural only
- No payload decryption
- No access control on blob retrieval (TDF encryption handles this)
- No local disk cache (stateless instance, S3 is sole store)
- No multi-region replication (use S3-native replication if needed)

## Architecture

```
+---------------+     QUIC      +-------------------------------+
|  Iroh Peer    |<------------>|  tdf-iroh-s3 (EC2)            |
|  (sender)     |               |                               |
+---------------+               |  +-------------------------+  |
                                |  | Iroh Endpoint           |  |
+---------------+     QUIC      |  |  + Blob Protocol        |  |
|  Iroh Peer    |<------------>|  +-----------+--------------+  |
|  (consumer)   |               |             |                 |
+---------------+               |  +-----------v--------------+ |
                                |  | TDF Validation Pipeline  | |
                                |  |  1. ZIP structure        | |
                                |  |  2. Attribute policy     | |
                                |  |  3. Assertion signature  | |
                                |  +-----------+--------------+ |
                                |             |                 |
                                |  +-----------v--------------+ |
                                |  | S3 Blob Store            | |
                                |  |  PUT/GET by BLAKE3 hash  | |
                                |  +-----------+--------------+ |
                                +-------------|--+--------------+
                                              |
                                     +--------v--------+
                                     |   Amazon S3     |
                                     | s3://bucket/    |
                                     |  blobs/<hash>   |
                                     |  outboards/<h>  |
                                     |  tags/<name>    |
                                     +-----------------+
```

### Data Flow: Ingest

1. Iroh peer connects over QUIC and pushes a blob
2. Iroh protocol receives blob data incrementally, buffered to a temporary in-memory or temp-file location
3. Once fully received, TDF validation pipeline runs against the complete blob (see Validation section)
4. If valid: blob + BLAKE3 outboard written to S3, permanent tag created
5. If invalid: blob rejected, temporary data discarded, peer receives error

### Data Flow: Retrieval

1. Iroh peer requests a blob by BLAKE3 hash
2. S3 blob store checks existence via HEAD request
3. Blob data and outboard streamed from S3 to peer
4. Iroh handles verified streaming using the outboard hash tree

## TDF Validation Pipeline

Validation is a chain of configurable checks. Each must pass for the blob to be accepted.

### Step 1: Structure Validation (always on)

- Parse the blob as a ZIP archive
- Verify it contains `manifest.json` and a payload file
- Deserialize the manifest using `opentdf-rs` types

### Step 2: Attribute Policy Check (configured at deploy)

- Extract attributes from the TDF manifest
- Evaluate against the configured required attributes using `opentdf-rs` `AttributePolicy::evaluate()`
- Reject if any required attributes are missing

### Step 3: Assertion Signature Check (optional, configured at deploy)

- If enabled, check that the manifest contains a signed assertion
- Verify the assertion signature against configured trusted public key(s) using `opentdf-rs`
- Reject if no assertion is present or signature verification fails

## S3 Storage Layout

```
s3://<bucket>/<prefix>
  blobs/<blake3-hash>        # TDF blob data
  outboards/<blake3-hash>    # BLAKE3 outboard (hash tree for verified streaming)
  tags/<tag-name>            # Tag -> BLAKE3 hash mapping
```

### Key Operations

| Operation | S3 API | Purpose |
|-----------|--------|---------|
| Write blob | PutObject | Store TDF data after validation |
| Write outboard | PutObject | Store BLAKE3 hash tree |
| Read blob | GetObject | Stream to requesting peer |
| Check existence | HeadObject | Fast lookup by hash |
| Delete blob | DeleteObject | Garbage collection of untagged blobs |
| List tags | ListObjectsV2 | Tag management |

### S3 Client

- Uses `aws-sdk-s3` (official AWS Rust SDK)
- Credentials via EC2 instance IAM role — no keys in config
- Region configured in `config.toml`

## Configuration

Configuration loaded from `/etc/tdf-iroh-s3/config.toml` with fallback to EC2 instance user-data.

```toml
[iroh]
bind_port = 11204
secret_key_path = "/var/lib/tdf-iroh-s3/secret.key"

[s3]
bucket = "my-tdf-store"
region = "us-east-1"
prefix = ""

[validation]
required_attributes = [
  "https://example.com/attr/storage/value/permanent"
]

[validation.assertion]
enabled = false
trusted_public_keys = [
  "/etc/tdf-iroh-s3/trusted-keys/publisher1.pem"
]
```

### Configuration Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `iroh.bind_port` | No | 11204 | UDP port for QUIC connections |
| `iroh.secret_key_path` | No | `/var/lib/tdf-iroh-s3/secret.key` | Iroh node identity key (auto-generated if absent) |
| `s3.bucket` | Yes | — | S3 bucket name |
| `s3.region` | Yes | — | AWS region |
| `s3.prefix` | No | `""` | Key prefix for all S3 objects |
| `validation.required_attributes` | No | `[]` | Attributes that must be present in TDF manifest |
| `validation.assertion.enabled` | No | `false` | Enable assertion signature verification |
| `validation.assertion.trusted_public_keys` | No | `[]` | Paths to trusted public key files |

### Same AMI, Different Deployments

The AMI contains the binary and systemd service but no environment-specific config. Each EC2 launch provides its own configuration via user-data or a boot script that fetches config from S3. Examples:

| Deployment | Bucket | Required Attributes | Assertion Check |
|------------|--------|-------------------|-----------------|
| Prod archive | `prod-tdf-archive` | `storage/permanent` | Enabled, 2 trusted keys |
| Dev sandbox | `dev-tdf-sandbox` | (none) | Disabled |
| Partner ingest | `partner-tdf-ingest` | `org/partner-a` | Enabled, partner key |

## Crate Structure

```
tdf-iroh-s3/
├── Cargo.toml
├── src/
│   ├── main.rs                    # CLI entry, config loading, service startup
│   ├── config.rs                  # Config struct, TOML parsing, user-data fallback
│   ├── node.rs                    # Iroh endpoint setup, protocol router
│   ├── store/
│   │   ├── mod.rs                 # S3 blob store implementation
│   │   ├── s3.rs                  # S3 client wrapper (put/get/head/delete/list)
│   │   └── outboard.rs           # BLAKE3 outboard computation and storage
│   └── validation/
│       ├── mod.rs                 # Validation pipeline orchestrator
│       ├── structure.rs           # ZIP + manifest parsing via opentdf-rs
│       ├── attributes.rs          # Attribute policy check via opentdf-rs
│       └── assertion.rs           # Assertion signature verification via opentdf-rs
├── packer/
│   ├── ami.pkr.hcl                # Packer template for Amazon Linux 2023 AMI
│   ├── scripts/
│   │   ├── install.sh             # Install binary + systemd unit
│   │   └── setup-user.sh          # Create service user, directories
│   └── files/
│       ├── tdf-iroh-s3.service    # Systemd unit file
│       └── bootstrap.sh           # First-boot config loader
└── tests/
    ├── integration/
    │   ├── validation_test.rs     # TDF validation with sample TDFs
    │   ├── store_test.rs          # S3 store with LocalStack/MinIO
    │   └── e2e_test.rs            # Full flow: peer -> validate -> store -> retrieve
    └── fixtures/
        ├── valid.tdf              # Valid TDF with required attributes
        ├── valid_signed.tdf       # Valid TDF with signed assertion
        ├── missing_attr.tdf       # TDF missing required attribute
        └── not_a_tdf.bin          # Random bytes (rejected)
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `opentdf-rs` | TDF parsing, manifest types, attribute policy evaluation, assertion verification |
| `iroh` 0.97+ | Endpoint, connections, QUIC |
| `iroh-blobs` 0.99+ | Blob protocol, store interface |
| `aws-sdk-s3` | S3 operations via IAM role |
| `tokio` | Async runtime |
| `blake3` | Hash computation + outboard |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `serde` / `toml` | Config deserialization |

## AMI Build (Packer)

**Base**: Amazon Linux 2023 (AWS-optimized, lightweight)

### AMI Contents

1. Binary: `/usr/local/bin/tdf-iroh-s3`
2. Systemd unit: `/etc/systemd/system/tdf-iroh-s3.service`
3. Config directory: `/etc/tdf-iroh-s3/` (empty, populated at launch)
4. Data directory: `/var/lib/tdf-iroh-s3/` (Iroh node secret key)
5. Service user: `tdf-iroh-s3` (non-root)
6. Bootstrap script: `/usr/local/bin/tdf-iroh-s3-bootstrap` (first-boot config loader)

### Systemd Unit

- Runs as `tdf-iroh-s3` user
- `Restart=on-failure` with `RestartSec=5`
- `After=network-online.target`
- Reads config from `/etc/tdf-iroh-s3/config.toml`
- Bootstrap runs as `ExecStartPre` to fetch config from user-data or S3 if no local config exists

### EC2 Requirements

| Resource | Requirement |
|----------|-------------|
| IAM role | `s3:PutObject`, `s3:GetObject`, `s3:HeadObject`, `s3:DeleteObject`, `s3:ListBucket` on configured bucket |
| Security group | UDP inbound on Iroh bind port (default 11204) for QUIC |
| EBS | Root volume only (no additional storage needed) |
| Instance type | Depends on throughput needs; `t3.medium` sufficient for moderate load |

## Novelty

This is a genuinely novel system. No existing implementation combines:
- S3-backed blob store for `iroh-blobs` 0.9x+ (current RPC-based API)
- TDF validation as an ingest gate
- Assertion signature verification

Existing S3 work (n0-computer/iroh-experiments, HIRO-MicroDataCenters/rhio) targets the obsolete 0.34.x trait-based API and is incompatible with the current architecture.

## Testing Strategy

1. **Unit tests**: Config parsing, validation logic (using `opentdf-rs` test utilities)
2. **Integration tests**: S3 store operations against LocalStack or MinIO in Docker
3. **End-to-end tests**: Full flow with an Iroh peer sending TDFs, verifying storage in S3 and retrieval
4. **Test fixtures**: Pre-built TDF files covering valid, invalid, signed, and unsigned cases
