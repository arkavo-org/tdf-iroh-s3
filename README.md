# tdf-iroh-s3

A persistent Iroh peer node that validates incoming blobs as OpenTDF files
and stores them in Amazon S3. Serves stored blobs back to any requesting
peer, straight from S3.

## How It Works

1. Peers send blobs over Iroh's P2P QUIC protocol
2. Each blob is validated as a valid TDF (Trusted Data Format):
   - At most `[validation] max_blob_bytes` (default 4 GiB − 1); a larger
     push is stopped while it transfers
   - A ZIP holding an OpenTDF manifest: `manifest.json` with the payload in
     the member `payload.url` names (other members, such as HLS playlists
     and fMP4 segments, are allowed), or the legacy `0.manifest.json` +
     `0.payload`
   - Required attributes present in the policy
   - Optional assertion signature verification
3. Valid blobs are stored in S3, keyed by BLAKE3 content hash. Ingest reads
   the blob from a file and streams it to S3; it never holds it in memory.
   It also computes the blob's BAO outboard (the hash tree that lets a peer
   verify each chunk group of a ranged read) and uploads it to
   `outboards/<hash>` before the blob. So `GET /blobs/<hash>` answering 200
   means the blob can be served. An upload that fails is retried twice (after
   1 s and 5 s) before the publish fails; the publisher pushes again.
4. Any peer can retrieve blobs by hash — the TDF encryption layer handles access control.
   A fetch (get or get_many) is answered straight from S3: the node writes
   the blob's size, then the BAO encoding of the requested ranges, read from
   `blobs/<hash>` and `outboards/<hash>` through range GETs. The node keeps
   no copy of what it serves, and the peer verifies every chunk group
   against the hash. Only single blobs are pushed or fetched; hash sequences
   are refused, and so are observe requests and a get_many over 64 hashes.
5. The local iroh store only stages pushes. A push is pending until ingest
   is done with it, and the store's garbage collector (every `[iroh]
   gc_interval_secs`, default 60) deletes every stored blob no pending push
   needs. Nothing local is ever served.

A fetch is refused with an iroh-blobs error code:

- `ERR_PERMISSION` (1) is final: the hash is blocked, S3 has no such blob, or
  its S3 object turned out not to match the hash.
- `ERR_LIMIT` (2) means try again: S3 did not answer (a HEAD takes over 10 s,
  or a GET sends nothing for 30 s), the blob's outboard is being computed, or
  256 fetches are running. A transfer S3 breaks off part-way is reset with
  `ERR_LIMIT` too, and so is one whose fetcher stops reading for 60 s.

A blob ingested before outboards were stored has none. The first fetch of it
is answered `ERR_LIMIT` while the node computes the outboard by streaming the
blob from S3 once and stores it; the next fetch is served.

Creators publish a catalog of their recordings as a JSON document the node
stores by hash, behind the tag `catalog/<sub>`. The contract between the
node, the Creator app and the iOS viewer is
[docs/creator-catalogs.md](docs/creator-catalogs.md).

## Build

```bash
cargo build --release
```

## Configuration

Create a config file (TOML):

```toml
[iroh]
bind_port = 11204
# Public ip:port addresses peers can dial directly, reported by GET /node
# (the node cannot see its elastic IP itself). Default: none.
public_addresses = ["3.91.18.97:11204"]
# A push whose connection receives less than 64 KiB in this many seconds is
# closed, then checked like an aborted transfer: a peer can stop sending
# without closing.
push_stall_secs = 120
# How often the store's garbage collector deletes staged pushes that ingest
# is done with. Default 60.
# gc_interval_secs = 60

[s3]
bucket = "my-tdf-store"
region = "us-east-1"
# S3-compatible stores (LocalStack, MinIO). AWS_ENDPOINT_URL also works.
# endpoint_url = "http://127.0.0.1:4566"
# force_path_style = true

[validation]
required_attributes = [
    "https://example.com/attr/storage/value/permanent"
]
# Larger pushes are refused, and stopped while they transfer. Memory does
# not bound this; disk does (see Deploy). Default 4294967295
# (4 GiB − 1, the viewer's limit).
max_blob_bytes = 4294967295
# Pushes validated and uploaded at once, each with a scratch copy on disk.
max_concurrent_ingests = 1

[validation.assertion]
enabled = false
trusted_public_keys = []

# HTTP API: creator catalogs, ingest confirmation, node identity. Catalog
# writes need an Arkavo CWT whose subject is the catalog's.
[http]
enabled = true
# 127.0.0.1 behind a TLS proxy on the same host (default 0.0.0.0).
bind_address = "127.0.0.1"
bind_port = 8090
cose_keys_url = "https://identity.arkavo.net/.well-known/cose-keys"
expected_issuer = "https://identity.arkavo.net"
# Catalog v2: the WebAuthn RP creators sign pointers with, and the IdP's
# passkey credential status route ("" skips the check; development only).
passkey_rp_id = "identity.arkavo.net"
passkey_status_url = "https://identity.arkavo.net/passkeys/credentials/{credentialId}/status"
# GET /catalog/{group}: "optional" verifies a presented token, "required"
# refuses none (tdf-iroh-s3#39). GET /v2/catalogs always needs one.
catalog_token = "optional"

# Optional: HTTPS terminated by the node itself (rustls, TLS 1.3 only).
# The plain listener above then binds to 127.0.0.1 only. On EC2,
# tdf-iroh-s3-cert-sync exports the exportable ACM certificate into these
# files at boot, right after the node starts, and then every 12h; the node
# reloads them when they change.
[http.tls]
bind_port = 443
cert_path = "/etc/tdf-iroh-s3/tls/fullchain.pem"
key_path = "/etc/tdf-iroh-s3/tls/privkey.pem"
acm_certificate_arn = "arn:aws:acm:us-east-1:<account>:certificate/<id>"

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
# Decision protocol. Default is AuthZEN Access Evaluations
# (GET {endpoint}/.well-known/authzen-configuration, then POST
# access_evaluations_endpoint with the catalog-node service CWT).
# No users on this catalog — hard cutover. Rollback:
# protocol = "opentdf-v2"
protocol = "authzen"
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

The IAM role needs read and write on `blobs/` and `outboards/` (fetches
read both; ingest writes both). It needs the same S3 write permissions on
`manifests/` and `catalog-index/` as on `blobs/` — derived-artifact writes are best-effort
(a failure is logged and never masks a successful blob ingest; re-pushing
the content repairs the index). Creator catalogs need `s3:PutObject` and
`s3:GetObject` on `catalog-documents/`, and for catalog v2 also on
`catalog-outboards/` and `catalog-pointers/` (pointer writes are
conditional: `If-Match` / `If-None-Match`). It needs `s3:PutObject`,
`s3:GetObject` on `moderation/` when the publishing gate is on. It also
needs `s3:ListBucket` on the bucket itself, without a prefix condition:
without it S3 answers a missing key with 403, and the node reports unknown
hashes as 502 `storage unavailable` instead of 404.

## Entitled catalog

`GET /catalog/{group}` lists the group's ingested items, each annotated
with whether the requesting entity chain is entitled to it. Catalog `/2`
metadata TDFs (`payload.mimeType` `application/vnd.arkavo.catalog-entry+json`)
are not items and are never listed:

```bash
# Anonymous: full listing, nothing entitled (public storefront)
curl https://iroh.arkavo.net/catalog/12345678

# With a person entity (Arkavo CWT) — decisions come from AuthZEN
# /access/v1/evaluations on platform.arkavo.net (catalog-node service CWT
# is the PEP Bearer; the PE CWT is SARC subject). Repeat X-Entity-Token
# once per DeviceCheck CWT (not comma-separated):
curl https://iroh.arkavo.net/catalog/12345678 \
  -H "Authorization: Bearer <pe-cwt>" \
  -H "X-Entity-Token: <devicecheck-cwt>" \
  -H "X-Entity-Token: <second-devicecheck-cwt>"
```

Response: `{"group": "...", "decision": "evaluated|anonymous|unavailable",
"items": [{"hash", "size", "attribute_fqns", "ingested_at", "entitled"}],
"creator"?: "<account uuid>"}`. When groups are Patreon campaigns, `creator`
names the campaign's creator, as recorded at their last catalog publish, so a
viewer can find `GET /v2/catalogs/<creator>`. It is sent only to a reader the
PDP entitles to the campaign attribute itself (asked with the items, as one
more resource), and left out for anonymous readers, readers not entitled, an
unknown creator, or a failed lookup.
Each device CWT must have `aud=arkavo:devicecheck` and bind to the PE via
`subject_id_bind` (strip a single leading `arkavo:` only; `apple:` and
`client:` are not stripped). The node sends each one on to the PDP as the
device's `token`, which the platform verifies. Empty listings return `items: []` without
calling the PDP. The node appends its own observed environment entity.
All failure modes degrade to `entitled: false`, never to access.

Attribute definitions resolve as URLs: `GET /attributes` (the full set),
`GET /attr/tier`, `GET /attr/tier/value/supporter` — so an FQN like
`https://patreon.arkavo.com/attr/tier/value/supporter` dereferences when
the namespace host points at this node. See
`attributes/patreon.arkavo.com.json` for the example artifact.

## HTTP API

With `[http]` enabled the node serves the routes below. TLS terminates in
the node when `[http.tls]` is set (below), or in a proxy in front of it.
Every error body is `{"error":"<message>"}`, except that an ungated node
answers `POST /publish/sessions` with 404 and an empty body. The creator catalog routes are
specified in [docs/creator-catalogs.md](docs/creator-catalogs.md).

| Route | Access | Purpose |
|---|---|---|
| `GET /healthz` | public | Liveness. |
| `GET /node` | public | `{"endpointId","relayUrl","directAddresses","maxBlobBytes"}`: the iroh endpoint publishers push to, and the largest archive ingest accepts. |
| `GET /blobs/{hash}` | public | `{"hash","size"}` once a pushed TDF is ingested and servable; 404 until then, or if refused or blocked. |
| `GET /catalog-documents/{hash}` | public | A stored catalog envelope (a ZTDF), byte for byte (`ETag`, cached 5 minutes, `If-None-Match` → 304). |
| `PUT /v2/catalogs/{sub}` | publisher CWT + passkey | Publish a catalog: the envelope, its passkey-signed pointer bundle and its clear index ([docs/creator-catalogs.md](docs/creator-catalogs.md#catalog-v2-passkey-signed-catalogs-over-iroh)). |
| `GET /v2/catalogs/{sub}` | any Arkavo CWT | The creator's signed pointer bundle, if the decision service entitles the reader to the envelope's attribute (403 otherwise); the envelope is then fetched over iroh by hash. |
| `POST /publish/sessions` | publisher CWT | Gated nodes only (404, empty body, when ungated); see below. |

```bash
# Resolve a creator's catalog (the signed pointer bundle), then fetch the
# envelope it names
curl -H "Authorization: Bearer <cwt>" https://iroh.arkavo.net/v2/catalogs/<sub>
curl https://iroh.arkavo.net/catalog-documents/<catalogHash>
```

`<sub>` is the CWT's `sub` exactly as minted; the node never canonicalizes
it. Recordings themselves are fetched over the Iroh blobs protocol by hash.

On a node with `[publishing] required = false`, writes still need a token
that verifies; the entitlement, service-token and suspension checks are
skipped, and nothing is blocked.

TLS terminates in the node when `[http.tls]` is set, and only TLS 1.3 is
offered: a TLS 1.2 client is refused in the handshake. The ACM certificate
must be requested with `--options Export=ENABLED`, and the instance role
needs `acm:ExportCertificate` on it. The systemd unit grants
`CAP_NET_BIND_SERVICE` so the service user can bind 443.

## Publishing and moderation

Publishing is gated by default (`[publishing] required = true`).

- A tag or catalog write needs the Arkavo creator-publishing entitlement in the CWT.
- An iroh push is accepted only from an endpoint that first opened a publish session with `POST /publish/sessions`.
- Operators suspend creators and block content hashes through `/moderation/*`.

See [docs/publishing-and-moderation.md](docs/publishing-and-moderation.md).

## Run

```bash
./target/release/tdf-iroh-s3 --config config.toml
```

## Deploy

`packer/ami.pkr.hcl` builds an Amazon Linux 2023 arm64 AMI around a
prebuilt binary. It requires `binary_s3_uri` (the gzipped binary in S3)
and `iam_instance_profile` (a build-instance profile that can read it),
for example from a `-var-file`. A systemd unit runs it with
`--config /etc/tdf-iroh-s3/config.toml`; on first boot the bootstrap
script writes that file from EC2 user-data when it does not exist.

The AMI also runs the CloudWatch agent, which sends the journal of
`tdf-iroh-s3` and `tdf-iroh-s3-cert-sync`, including systemd's lines about
them (exits, restarts), to the CloudWatch Logs group `tdf-iroh-s3`, one
stream per instance ID, so the logs outlive the instance. The agent creates
the group with a 90-day retention, so the instance role needs
`logs:CreateLogGroup`, `logs:PutRetentionPolicy`, `logs:CreateLogStream`,
`logs:PutLogEvents` and `logs:DescribeLogStreams` on it. Without them the
node runs as before and the agent logs its own errors.

Everything the node serves lives in S3, so replacing an instance loses
nothing, and several nodes can serve one bucket. The data volume only
stages pushes: keep at least (pushes expected at once +
`max_concurrent_ingests`) × `max_blob_bytes` free. On a reflink-capable
filesystem (XFS with `reflink=1`) the ingest scratch copies take no space,
so drop the `max_concurrent_ingests` term. The endpoint ID
comes from `[iroh] secret_key_param`, not the instance; keep it stable if
clients pin it.

Operator runbooks for a particular deployment live outside this
repository (`production/` is gitignored).

## Test

```bash
cargo test
```

The test CLI drives a running node:

```bash
cargo run --bin tdf-iroh-s3-test -- --help
# create-tdf, push, push-raw, fetch, publish-session, publish

# Creator's flow against a node: session (if gated), push, wait for ingest
cargo run --bin tdf-iroh-s3-test -- publish -n <endpointId> --addr <ip:port> \
  --url http://127.0.0.1:8090 --token-file token.txt -d recording.tdf
```

`publish-session` and `push-raw` take `--secret-key-file` so both use the
same endpoint key, which a gated node's publish session requires.
`examples/mint_test_idp.rs` emits a local key set and creator token for
running against a node with `cose_keys_url` pointed at it, and
`[s3] endpoint_url` + `force_path_style` run the node against LocalStack.
