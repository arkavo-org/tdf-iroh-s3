# tdf-iroh-s3

A persistent Iroh peer node that validates incoming blobs as OpenTDF files
and stores them in Amazon S3. Serves stored blobs back to any requesting peer.

## How It Works

1. Peers send blobs over Iroh's P2P QUIC protocol
2. Each blob is validated as a valid TDF (Trusted Data Format):
   - ZIP structure with manifest.json and payload
   - Required attributes present in the policy
   - Optional assertion signature verification
3. Valid blobs are stored in S3, keyed by BLAKE3 content hash
4. Any peer can retrieve blobs by hash — the TDF encryption layer handles access control

## Build

```bash
cargo build --release
```

## Configuration

Create a config file (TOML):

```toml
[iroh]
bind_port = 11204

[s3]
bucket = "my-tdf-store"
region = "us-east-1"

[validation]
required_attributes = [
    "https://example.com/attr/storage/value/permanent"
]

[validation.assertion]
enabled = false
trusted_public_keys = []

# Optional: HTTP tag API for catalog discovery. Tags are stable names
# pointing at the latest blob hash (e.g. a creator's content catalog).
# GET /tags/<name> is public; PUT /tags/<name> requires an Arkavo CWT
# whose subject owns the tag (name must equal "<tag_prefix><sub>").
[http]
enabled = true
bind_port = 8090
cose_keys_url = "https://identity.arkavo.net/.well-known/cose-keys"
expected_issuer = "https://identity.arkavo.net"
tag_prefix = "catalog/"

# Optional: ingest-time catalog index (see issue #5). Each ingested blob
# gets a catalog-index/<group>/<hash> entry per value of the grouping
# attribute in its TDF policy; the extracted manifest.json is stored at
# manifests/<hash> so indexing/UIs never re-download content blobs.
[catalog]
enabled = true
# Grouping attribute (must be defined in the attribute source). Items
# labeled with campaign X are indexed and served under /catalog/X.
group_attribute_fqn = "https://patreon.arkavo.com/attr/campaign"
# Attribute definitions: exactly one of the following.
# Production — the platform's public attributes endpoint is the single
# source of truth (served from the snapshot the PDP evaluates); this node
# validates group_attribute_fqn against it at startup and serves nothing:
attributes_url = "https://platform.arkavo.net/attributes"
# Offline/test alternative — local artifact, served by this node on
# /attributes and FQN-resolving /attr/... routes:
# attributes_file = "/etc/tdf-iroh-s3/attributes.json"
cache_ttl_secs = 30

# OpenTDF authorization service for per-item catalog decisions. Empty
# endpoint = fail closed (catalog lists, nothing entitled).
#
# The platform REQUIRES an authenticated caller. Production: register a
# confidential OIDC client on the IdP and configure client_credentials —
# the node mints and refreshes its own short-lived service CWT (access
# tokens live ~1h; a static token would silently fail-close the catalog
# an hour after boot).
[catalog.authz]
endpoint = "https://platform.arkavo.net"
action = "read"
token_url = "https://identity.arkavo.net/oauth/token"
client_id = "catalog-node"
# The secret is read from the CATALOG_AUTHZ_CLIENT_SECRET environment
# variable when client_secret is unset here — preferred, so the
# long-lived credential never sits in the config file. (No shell-style
# ${VAR} expansion happens inside this file.)
# client_secret = "..."
# environment_region is asserted by this node as an environment NPE in the
# decision entity chain; clients can never supply environment claims.
environment_region = "us-east-1"
# Entity presentation, contract-verified against the platform source:
# "claims" (default) sends an entityChain of claims-bearing entities built
# from claims this node extracts from verified CWTs (arkavo_patreon.
# patreon_user_id, email) — the platform PDP resolves every chain entity
# through the ERS, and the Patreon ERS resolves exactly those claims.
# "token" sends entityIdentifier.token, which only works for JWT IdPs
# (the ERS token parser rejects CWTs). Environment entities are filtered
# by the platform's decision flow today; they are forwarded for
# forward-compatibility.
#
# UPGRADE NOTE: "claims" is the default. Deployments fronted by a
# JWT-issuing IdP (not Arkavo CWTs) must set entity_mode = "token"
# explicitly — claims mode extracts arkavo_patreon/email claims that a
# generic JWT IdP may not mint.
entity_mode = "claims"
```

The IAM role needs the same S3 write permissions on `manifests/` and
`catalog-index/` as on `blobs/` — derived-artifact writes are best-effort
(a failure is logged and never masks a successful blob ingest; re-pushing
the content repairs the index).

## Entitled catalog

`GET /catalog/{group}` lists the group's ingested items, each annotated
with whether the requesting entity chain is entitled to it:

```bash
# Anonymous: full listing, nothing entitled (public storefront)
curl https://iroh.arkavo.net/catalog/12345678

# With a person entity (Arkavo CWT) — decisions come from the OpenTDF
# authorization service over the full chain PE -> NPE -> NPE:
curl https://iroh.arkavo.net/catalog/12345678 \
  -H "Authorization: Bearer <pe-cwt>" \
  -H "X-Entity-Token: <attested-device-cwt>"
```

Response: `{"group": "...", "decision": "evaluated|anonymous|unavailable",
"items": [{"hash", "size", "attribute_fqns", "ingested_at", "entitled"}]}`.
NPE tokens must carry the same subject as the PE; the node appends its own
observed environment entity. All failure modes degrade to
`entitled: false`, never to access.

Attribute definitions resolve as URLs: `GET /attributes` (the full set),
`GET /attr/tier`, `GET /attr/tier/value/supporter` — so an FQN like
`https://patreon.arkavo.com/attr/tier/value/supporter` dereferences when
the namespace host points at this node. See
`attributes/patreon.arkavo.com.json` for the example artifact.

## Tag API (catalog discovery)

Content blobs are immutable, so consumers need a stable pointer to a
creator's *latest* catalog. With `[http]` enabled:

```bash
# Resolve a creator's catalog pointer (public)
curl https://iroh.arkavo.net/tags/catalog/arkavo:<user-id>
# -> {"name":"catalog/arkavo:<user-id>","hash":"<blake3-hex>"}

# Move your own pointer (requires Arkavo CWT; hash must be an ingested blob)
curl -X PUT https://iroh.arkavo.net/tags/catalog/arkavo:<user-id> \
  -H "Authorization: Bearer <cwt>" \
  -H "Content-Type: application/json" \
  -d '{"hash":"<blake3-hex>"}'
```

The blob itself is then fetched over the Iroh blobs protocol by hash.
TLS terminates in front of the listener (ALB / reverse proxy).

## Run

```bash
./target/release/tdf-iroh-s3 --config config.toml
```

## Deploy (AMI)

Build the AMI with Packer:

```bash
cargo build --release
cd packer
packer build -var "binary_path=../target/release/tdf-iroh-s3" ami.pkr.hcl
```

Launch an EC2 instance from the AMI, passing config as user-data.

## Test

```bash
cargo test
```
