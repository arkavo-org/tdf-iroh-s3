# iroh-docs Catalog with CWT-Gated Writes — Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the S3-backed publish event log with an `iroh-docs`
replica, and gate every write to that replica with a CWT (COSE_Sign1)
verified against a JWKS URL in config.

**Architecture:** One node-local `iroh-docs` replica holds all publish
events under `creators/{creator_id}/events/{seq:020}` keys. The node owns
a single iroh-docs author identity. A `crate::auth::Verifier` checks
incoming CWTs (algorithm ES256, issuer from config, claims pinned to
`creator_id` + `campaign_id` + `catalog.write` scope). On success the node
authors the event and embeds the raw CWT in the event payload for audit.
Catalogs are materialized on demand from replica contents; nothing is
written back.

**Tech Stack:** `iroh-docs` 0.99, `coset` 0.3 (COSE_Sign1), `ciborium`
(CBOR), `p256` (ES256 verify), `arc-swap` (JWKS cache), `reqwest` (JWKS
fetch), `base64`.

**Spec:** `docs/superpowers/specs/2026-05-26-iroh-docs-catalog-and-cwt.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `Cargo.toml` | Modify | Add `iroh-docs`, `coset`, `ciborium`, `p256`, `arc-swap`, `base64` |
| `src/config.rs` | Modify | New `[catalog]` and `[auth]` config sections |
| `src/auth/mod.rs` | Create | Re-export `Verifier`, `VerifiedClaims` |
| `src/auth/cwt.rs` | Create | COSE_Sign1 parse + signature verify + claim checks |
| `src/auth/jwks.rs` | Create | JWKS fetch, parse, cache, JWK→COSE-key |
| `src/auth/test_signer.rs` | Create (cfg test/feature) | Test fixture that mints valid CWTs |
| `src/catalog/types.rs` | Modify | Add `EventAuthorization`; extend `PublishEvent` |
| `src/catalog/mod.rs` | Modify | Re-export; `build_catalog` unchanged |
| `src/catalog/keys.rs` | Modify | Add replica-key helpers; remove catalog-snapshot S3 keys |
| `src/catalog/replica.rs` | Create | `CatalogReplica` wrapper: open, write event, list events |
| `src/catalog/publish.rs` | Rewrite | Take `VerifiedClaims`, write to replica, drop S3 event-log writes |
| `src/node.rs` | Modify | Open replica, hold `Verifier` and `CatalogReplica`, persist author + namespace |
| `src/secret_key.rs` | Modify | Generalize so author key + namespace id are persisted via the same SSM/file pattern |
| `src/lib.rs` | Modify | Add `pub mod auth;` |
| `src/test_cli/push.rs` | Modify | Mint test CWT, pass to publish |
| `tests/catalog_event_log_test.rs` | Rewrite | Replica-based assertions instead of S3 |
| `tests/auth_cwt_test.rs` | Create | Verifier accepts valid, rejects wrong issuer/sig/exp |
| `tests/catalog_publish_auth_test.rs` | Create | Publish rejected without CWT; accepted with valid; rejected when CWT `sub` mismatches |

---

## Phase A — Auth module (depends on nothing else)

### Task A1: Wire dependencies

**Files:** `Cargo.toml`

- [ ] **Step 1: Add crates**

  In `[dependencies]`, add:
  ```toml
  coset = "0.3"
  ciborium = "0.2"
  p256 = { version = "0.13", features = ["ecdsa"] }
  arc-swap = "1"
  base64 = "0.22"
  iroh-docs = "0.99"
  ```
  If `reqwest` is not already present, add `reqwest = { version = "0.12",
  features = ["rustls-tls", "json"], default-features = false }`.

- [ ] **Step 2: Verify it builds**

  Run `cargo build`. Must compile with no code changes yet.

### Task A2: Config sections

**Files:** `src/config.rs`, `tests/config_test.rs`

- [ ] **Step 1: Failing tests for `[auth]` and `[catalog]` parsing**

  Add tests that load a TOML containing `[auth] jwks_url = "..."`,
  `issuer = "..."`, and `[catalog] data_dir = "..."`. Assert fields parse;
  assert defaults (`refresh_interval_secs = 300`, `clock_skew_secs = 60`,
  `data_dir = "/var/lib/tdf-iroh-s3/docs"`).

- [ ] **Step 2: Add `AuthConfig` and `CatalogConfig` structs**

  ```rust
  #[derive(Debug, Deserialize, Clone)]
  pub struct AuthConfig {
      pub jwks_url: String,
      pub issuer: String,
      #[serde(default = "default_refresh_interval_secs")]
      pub refresh_interval_secs: u64,
      #[serde(default = "default_clock_skew_secs")]
      pub clock_skew_secs: i64,
  }
  ```
  Add `pub catalog: CatalogConfig` and `pub auth: AuthConfig` to `Config`.

- [ ] **Step 3: Tests pass**

### Task A3: COSE_Sign1 verify

**Files:** `src/auth/cwt.rs`, `src/auth/mod.rs`, `src/lib.rs`,
`src/auth/test_signer.rs`, `tests/auth_cwt_test.rs`

- [ ] **Step 1: Implement `test_signer`**

  Behind `#[cfg(any(test, feature = "test-fixtures"))]`. Generates a
  P-256 keypair, exposes:
  ```rust
  pub fn jwks_json(&self) -> String;
  pub fn mint(&self, claims: TestClaims) -> Vec<u8>;
  ```
  `mint` builds a COSE_Sign1 with protected header `alg = ES256`,
  `kid = <test-kid>`, and CBOR-encoded claims map per RFC 8392.

- [ ] **Step 2: Failing test — verifier accepts a freshly minted CWT**

  In `tests/auth_cwt_test.rs`, spin up the test signer, publish its JWKS
  via a `httptest::Server`, point a `Verifier` at it, mint a CWT, call
  `verify`, assert claims.

- [ ] **Step 3: Implement `Verifier::verify`**

  - Parse with `coset::CoseSign1::from_slice`.
  - Pull `kid` from protected header; look up COSE key in JWKS cache;
    refresh-once on miss.
  - Verify signature with `p256::ecdsa::VerifyingKey` over the
    `Sig_structure` bytes (`coset` builds these for you).
  - Decode payload CBOR map with `ciborium::de`.
  - Check `iss == config.issuer`, `exp > now - clock_skew`,
    `iat < now + clock_skew`, `scope.contains("catalog.write")`,
    `sub` and `campaign_id` present and non-empty.
  - If `cnf.iroh_node_id` present and `bound_node_id` provided, require
    equality.
  - Return `VerifiedClaims`.

- [ ] **Step 4: Failing tests — verifier rejects bad cases**

  Wrong issuer; expired; tampered signature; missing scope; `sub` empty;
  unknown `kid` (after one refresh attempt). Add each as a separate
  `#[test]` so failure messages are precise.

- [ ] **Step 5: Implement rejections; tests pass**

### Task A4: JWKS cache and refresh

**Files:** `src/auth/jwks.rs`

- [ ] **Step 1: Background refresh task**

  `JwksCache::spawn(url, interval, http_client) -> Arc<Self>` returns a
  handle; an internal tokio task refreshes on the configured interval and
  swaps the parsed `HashMap<Kid, CoseKey>` via `ArcSwap`.

- [ ] **Step 2: On-demand refresh**

  `force_refresh()` rate-limited to one-per-second using
  `tokio::sync::Mutex<Instant>`. Called by the verifier when `kid` is not
  in the current snapshot.

- [ ] **Step 3: Test — `force_refresh` rate-limit**

  Hammer 10 concurrent `force_refresh` calls; assert at most 2 HTTP
  requests landed (one immediate, one after the 1s gate).

---

## Phase B — Catalog replica (parallelizable with Phase A)

### Task B1: Persist author + namespace identity

**Files:** `src/secret_key.rs`, `src/node.rs`, `src/config.rs`

- [ ] **Step 1: Generalize parameter helper**

  Rename `load_or_create` to take a `kind: KeyKind` (NodeSecret,
  CatalogAuthor, CatalogNamespace) and route each kind to a distinct SSM
  parameter name / dev file. Encode/decode as needed per kind
  (NodeSecret = 32 bytes; CatalogAuthor = iroh-docs author secret;
  CatalogNamespace = iroh-docs `NamespaceSecret`).

- [ ] **Step 2: Test — round-trip each kind**

  In-process file-backed test asserting create-then-load returns the
  same key for each kind.

### Task B2: `CatalogReplica` wrapper

**Files:** `src/catalog/replica.rs`, `src/catalog/mod.rs`

- [ ] **Step 1: Skeleton**

  ```rust
  pub struct CatalogReplica { /* iroh-docs Doc + Author */ }

  impl CatalogReplica {
      pub async fn open_or_create(
          docs: &iroh_docs::Docs,
          namespace: NamespaceSecret,
          author: AuthorId,
      ) -> Result<Self>;
      pub async fn append_event(&self, event: &PublishEvent) -> Result<u64>;
      pub async fn list_events(&self, creator_id: &str) -> Result<Vec<PublishEvent>>;
      pub fn namespace_id(&self) -> NamespaceId;
  }
  ```

- [ ] **Step 2: Failing test — append then list round-trips**

  In `tests/catalog_event_log_test.rs` (rewrite), use a temp-dir iroh-docs
  store, append three events with different `creator_id`s, assert
  `list_events("creator_1")` returns exactly the ones with that id, in
  seq order.

- [ ] **Step 3: Implement `append_event`**

  - Compute `next_seq` = `max(parse_event_seq(key)) + 1` over existing
    keys under `creators/{creator_id}/events/`.
  - Build key with `keys::replica_event_key(creator_id, next_seq)`.
  - Serialize event JSON.
  - Write via `Doc::set_bytes(author, key, value)`.
  - On `iroh-docs` author-collision (concurrent writer chose the same
    `seq`) retry up to 32 times — mirrors `MAX_EVENT_APPEND_RETRIES`.

- [ ] **Step 4: Implement `list_events`**

  `Doc::get_many` with prefix `creators/{creator_id}/events/`, deserialize
  each entry's bytes into `PublishEvent`, return sorted by `seq`.

- [ ] **Step 5: All tests pass**

### Task B3: Rewrite `publish_content`

**Files:** `src/catalog/publish.rs`, `src/catalog/types.rs`

- [ ] **Step 1: Add `EventAuthorization`**

  ```rust
  pub struct EventAuthorization {
      pub cwt_b64: String,
      pub issuer: String,
      pub cti: String,
  }
  ```
  Add `pub authorization: EventAuthorization` to `PublishEvent`.

- [ ] **Step 2: Rewrite signature**

  ```rust
  pub async fn publish_content(
      metadata: ContentMetadata,
      payload: Bytes,
      auth: &VerifiedClaims,
      replica: &CatalogReplica,
      s3: &S3Client,
  ) -> Result<PublishOutcome>;
  ```
  The `creator_id` is `auth.creator_id` — no longer a free parameter.

- [ ] **Step 3: Body**

  1. Write payload to S3 (idempotent, as today).
  2. Write per-content manifest to S3 (as today).
  3. Build `CatalogEntry` (as today).
  4. Build `PublishEvent` with `authorization = EventAuthorization {
     cwt_b64: base64(auth.raw_cwt), issuer: ..., cti: auth.cti }`.
  5. `replica.append_event(&event)` → returns `seq`.
  6. Return `PublishOutcome { content_id, seq, version: seq }`. (No more
     in-bucket catalog snapshot; `version` is just the seq the event
     landed at — `regenerate_catalog` is now called by readers, not the
     publisher.)

- [ ] **Step 4: Delete obsolete code**

  Remove `load_events`, `next_event_seq`, S3 event-key writes,
  `catalog_snapshot_key`, `catalog_latest_key` write paths from
  `publish.rs` and `keys.rs`. Keep `content_payload_key`,
  `content_manifest_key`.

- [ ] **Step 5: Failing tests, then passing**

  Tests in `tests/catalog_publish_auth_test.rs`:
  - Publish with valid CWT for `creator_1` → succeeds, event in replica.
  - Publish with CWT whose `sub = creator_2` but caller passes
    `creator_1` → reject (the new signature makes this representationally
    impossible; assert at the verifier-bound boundary instead — i.e.
    `auth.creator_id` is the source of truth).
  - Publish with expired CWT → verifier rejects before `publish_content`
    is reached. Cover this in `tests/auth_cwt_test.rs` not here.

---

## Phase C — Integration (depends on A + B)

### Task C1: Wire `Verifier` and `CatalogReplica` into `TdfIrohNode`

**Files:** `src/node.rs`, `src/config.rs`

- [ ] **Step 1: Hold both on the node**

  ```rust
  pub struct TdfIrohNode {
      // ...existing...
      pub catalog: Arc<CatalogReplica>,
      pub verifier: Arc<Verifier>,
  }
  ```

- [ ] **Step 2: Spawn-time setup**

  Inside `TdfIrohNode::spawn`:
  - Load/create the catalog `NamespaceSecret` and `AuthorId` via the
    generalized `secret_key` helper.
  - Open `iroh-docs::Docs::persistent(&config.catalog.data_dir)`.
  - Open the replica via `CatalogReplica::open_or_create`.
  - Build the HTTP client + spawn `JwksCache`.
  - Build `Verifier { jwks: cache, issuer: config.auth.issuer.clone(),
    clock_skew_secs: config.auth.clock_skew_secs }`.

- [ ] **Step 3: Smoke test**

  `tests/node_ingest_test.rs` already exists; add an assertion that the
  spawned node exposes a non-empty `catalog.namespace_id()`.

### Task C2: Update test CLI

**Files:** `src/test_cli/push.rs`

- [ ] **Step 1: Mint CWT path**

  `--cwt <PATH>` accepts a path to a CWT file (raw bytes). For dev
  convenience, `--cwt-test` activates the test signer behind a
  feature-gated path that prints a warning and mints a CWT inline using a
  fixture key.

- [ ] **Step 2: Pass through to publish**

  `push` calls `verifier.verify(&cwt_bytes, None)` then forwards the
  resulting `VerifiedClaims` to `publish_content`.

- [ ] **Step 3: `cargo run --bin tdf-iroh-s3-test -- push --cwt-test ...`
  succeeds end-to-end against a local node**

---

## Phase D — Tests + tidy

### Task D1: Rewrite catalog integration tests

**Files:** `tests/catalog_event_log_test.rs`,
`tests/catalog_publish_auth_test.rs` (new)

- [ ] All existing S3-event-log assertions are gone. New assertions exercise
  the replica directly: append, list, sequence allocation under concurrent
  writers, prefix-scoping by creator.

### Task D2: Audit dead code

- [ ] `cargo build` clean.
- [ ] `cargo clippy -- -D warnings` clean (or document any deferred lint).
- [ ] No `dead_code` warnings on the catalog/snapshot helpers we kept (if
  any of them are now unused, delete them).
- [ ] Confirm `keys::events_prefix`, `keys::event_key`,
  `keys::parse_event_seq` are either deleted or repurposed for the
  replica's in-replica key layout — do not leave both an S3 version and a
  replica version with the same name.

### Task D3: Doc strings

- [ ] Top-of-module doc on `src/catalog/replica.rs` explaining the
  one-replica-per-node model and the `creators/{creator_id}/events/{seq}`
  key layout, with the same level of detail as the current `mod.rs` doc.
- [ ] Top-of-module doc on `src/auth/mod.rs` listing supported algorithms
  (ES256 only) and explicitly noting the unverified surface (no `cti`
  replay cache).

---

## Verification (manual, before pushing)

- [ ] `cargo test` — all green.
- [ ] `cargo test --test catalog_publish_auth_test` — verifies the gate.
- [ ] Run `cargo run --bin tdf-iroh-s3-test -- push --cwt-test ...`
  against a local node configured with a JWKS URL serving the test
  signer's public key; confirm the event appears under
  `creators/<sub>/events/00000000000000000001` in the replica.
- [ ] Restart the node and confirm the replica persists (namespace +
  author keys reload, event still readable).

## Rollback

The replica state is node-local and disposable. Rolling back amounts to:
delete `config.catalog.data_dir`, revert the commit, deploy. No S3 cleanup
needed — the S3 event-log keys we stop writing were unreleased, and the
S3 keys we keep writing (payload + manifest) are unchanged.
