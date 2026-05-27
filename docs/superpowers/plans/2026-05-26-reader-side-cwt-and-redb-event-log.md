# Reader-side CWT + redb event log — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the unwired write-side CWT path with a reader-side `tdf/catalog/1` ALPN that filters a local redb event log via `opentdf::pdp::AccessPdp`, per the Arkavo CWT v1 contract. Closes all 15 review findings.

**Architecture:** Node ingests TDF blobs on its own authority (existing pipeline). On success it appends a `ContentEvent` (content_id, manifest_ref, denormalized attribute-value FQNs) to a local redb log. Readers connect on `tdf/catalog/1`, present a CWT, get a CWT-bound live subscription of allowed entries via PDP filtering. iroh-docs and iroh-gossip are removed for v1; CWT verification routes through opentdf-rs `pep_check` (vendored).

**Tech Stack:** Rust 2024, tokio, iroh 0.97 + iroh-blobs 0.99 (kept), redb 2 (added), opentdf 0.12 (bumped, `pdp` module + vendored `pep_check`), serde_cbor via ciborium, redb.

**Spec:** [`docs/superpowers/specs/2026-05-26-reader-side-cwt-and-redb-event-log-design.md`](../specs/2026-05-26-reader-side-cwt-and-redb-event-log-design.md)

---

## File map

**New files:**
- `src/catalog/store.rs` — `EventStore` (redb wrapper, broadcast for live tail)
- `src/catalog/types.rs` — rewritten: `ContentEvent` only
- `src/pdp/mod.rs` — module root
- `src/pdp/cache.rs` — `AccessPdpCache` (ArcSwap + stale-while-revalidate)
- `src/pdp/policy_extract.rs` — `manifest_attr_value_fqns`
- `src/auth/entitlements.rs` — `cwt_to_entitlements`
- `src/auth/pep_check.rs` — vendored from opentdf-rs
- `src/protocol/mod.rs` — module root for ALPN protocols
- `src/protocol/catalog_read.rs` — `tdf/catalog/1` ALPN handler + wire types
- `tests/catalog_store_test.rs` — EventStore unit tests
- `tests/pdp_cache_test.rs` — AccessPdpCache tests
- `tests/catalog_read_alpn_test.rs` — end-to-end subscribe test

**Modified files:**
- `Cargo.toml` — bump `opentdf` to `v0.12.0`, add `redb`, remove `iroh-docs`/`iroh-gossip`
- `src/lib.rs` — drop `catalog::publish`, add `pdp`, `protocol`
- `src/config.rs` — `Default` for `AuthConfig`; new `PdpConfig`; reject `refresh_interval_secs == 0`; `CatalogConfig.data_dir` semantics
- `src/auth/mod.rs` — drop `SCOPE_CATALOG_WRITE`, add `SCOPE_CATALOG_READ`, `ACTION_READ`; expose new modules
- `src/auth/cwt.rs` — rewrite as thin wrapper over `pep_check`; `verify(&[u8], &str)` (non-Option node id)
- `src/auth/cose_keys.rs` — replaced by `pep_check` JWKS handling; deleted
- `src/auth/test_signer.rs` — mint v1 contract tokens (`authorization_details`, `catalog.read`, optional `cnf.iroh_node_id`)
- `src/catalog/mod.rs` — drop `publish`/`replica`/`keys`, add `store`; rebuild `build_catalog` (or remove if unused)
- `src/node.rs` — drop `Docs`/`Gossip`; add `EventStore`, `AccessPdpCache`; register `tdf/catalog/1` ALPN; hook ingest → append event
- `src/ingest.rs` — extract manifest FQNs and surface them so node can append
- `packer/files/bootstrap.sh` — config template includes new sections
- `CLAUDE.md` — update dependency line; new ALPN; redb path

**Deleted files:**
- `src/catalog/publish.rs`
- `src/catalog/replica.rs`
- `src/catalog/keys.rs`
- `src/auth/cose_keys.rs`
- `tests/catalog_event_log_test.rs` (subsumed by new tests)
- `tests/catalog_test.rs` (subsumed by EventStore + integration tests)

---

## Task 1: Bump opentdf, add redb (keep iroh-docs/iroh-gossip for now)

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Edit Cargo.toml**

Replace the `opentdf` line:
```toml
opentdf = { git = "https://github.com/arkavo-org/opentdf-rs", tag = "v0.12.0", default-features = false }
```

Add to `[dependencies]`:
```toml
redb = "2"
```

Leave `iroh-docs`, `iroh-gossip` for now — Task 19 removes them after the replacement lands.

- [ ] **Step 2: Verify build still works**

Run: `cargo build`
Expected: PASS (existing code still references iroh-docs; that's fine, we haven't refactored yet).

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: bump opentdf to v0.12.0, add redb"
```

---

## Task 2: Config — Default impls, PdpConfig, refresh_interval validation

**Files:**
- Modify: `src/config.rs`
- Test: `tests/config_test.rs`

- [ ] **Step 1: Write failing tests**

Append to `tests/config_test.rs`:
```rust
#[test]
fn missing_auth_section_uses_default_with_empty_urls() {
    let toml = r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
    "#;
    let cfg: tdf_iroh_s3::config::Config = toml::from_str(toml).expect("parses");
    assert_eq!(cfg.auth.cose_keys_url, "");
    assert_eq!(cfg.auth.issuer, "");
    assert_eq!(cfg.pdp.attribute_defs_url, "");
}

#[test]
fn refresh_interval_zero_is_rejected() {
    let toml = r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
        [auth]
        cose_keys_url = "https://x"
        issuer = "https://x"
        refresh_interval_secs = 0
    "#;
    let err = toml::from_str::<tdf_iroh_s3::config::Config>(toml).unwrap_err();
    assert!(err.to_string().contains("refresh_interval_secs"));
}

#[test]
fn auth_and_pdp_url_required_at_validate() {
    let cfg: tdf_iroh_s3::config::Config = toml::from_str(r#"
        [s3]
        bucket = "b"
        region = "us-east-1"
    "#).unwrap();
    let err = cfg.validate().unwrap_err();
    let s = err.to_string();
    assert!(s.contains("auth.cose_keys_url") || s.contains("auth.issuer"), "got: {s}");
}
```

- [ ] **Step 2: Run tests, expect failure**

Run: `cargo test --test config_test missing_auth_section_uses_default_with_empty_urls -- --nocapture`
Expected: FAIL (`pdp` field, `Default` impl, `validate` method don't exist yet).

- [ ] **Step 3: Implement**

Replace the relevant parts of `src/config.rs`. The full new file:

```rust
use serde::{Deserialize, Deserializer};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub iroh: IrohConfig,
    pub s3: S3Config,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub catalog: CatalogConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub pdp: PdpConfig,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Fail-closed checks for required URL fields (kept out of serde so that
    /// `toml::from_str` can succeed when the user supplies them later).
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.auth.cose_keys_url.is_empty() {
            anyhow::bail!("config: auth.cose_keys_url is required");
        }
        if self.auth.issuer.is_empty() {
            anyhow::bail!("config: auth.issuer is required");
        }
        if self.pdp.attribute_defs_url.is_empty() {
            anyhow::bail!("config: pdp.attribute_defs_url is required");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct IrohConfig {
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default = "default_secret_key_param")]
    pub secret_key_param: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            bind_port: default_bind_port(),
            secret_key_param: default_secret_key_param(),
            data_dir: default_data_dir(),
        }
    }
}

fn default_bind_port() -> u16 { 11204 }
fn default_secret_key_param() -> String { "/tdf-iroh-s3/node-secret-key".to_string() }
fn default_data_dir() -> String { "/var/lib/tdf-iroh-s3/data".to_string() }

#[derive(Debug, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub prefix: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ValidationConfig {
    #[serde(default)]
    pub required_attributes: Vec<String>,
    #[serde(default)]
    pub assertion: AssertionConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct AssertionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub trusted_public_keys: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CatalogConfig {
    /// Directory holding `events.redb`. Parent must be writable.
    #[serde(default = "default_catalog_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_max_subs_per_peer")]
    pub max_subscriptions_per_peer: u32,
    #[serde(default = "default_max_subs_total")]
    pub max_subscriptions_total: u32,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            data_dir: default_catalog_data_dir(),
            max_subscriptions_per_peer: default_max_subs_per_peer(),
            max_subscriptions_total: default_max_subs_total(),
        }
    }
}

fn default_catalog_data_dir() -> String { "/var/lib/tdf-iroh-s3/catalog".to_string() }
fn default_max_subs_per_peer() -> u32 { 4 }
fn default_max_subs_total() -> u32 { 256 }

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub cose_keys_url: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default = "default_refresh_interval_secs", deserialize_with = "nonzero_u64")]
    pub refresh_interval_secs: u64,
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: i64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PdpConfig {
    #[serde(default)]
    pub attribute_defs_url: String,
    #[serde(default = "default_refresh_interval_secs", deserialize_with = "nonzero_u64")]
    pub refresh_interval_secs: u64,
}

fn default_refresh_interval_secs() -> u64 { 300 }
fn default_clock_skew_secs() -> i64 { 60 }

fn nonzero_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    use serde::de::Error;
    let v = u64::deserialize(d)?;
    if v == 0 {
        return Err(D::Error::custom("refresh_interval_secs must be > 0"));
    }
    Ok(v)
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `cargo test --test config_test`
Expected: PASS (all new + existing config tests).

Run: `cargo build`
Expected: PASS — node.rs still references old `auth.cose_keys_url` etc., which are now `String::new()` by default. The boot path will fail-closed at `validate()` until the user supplies them; that's the design.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs tests/config_test.rs
git commit -m "config: AuthConfig/PdpConfig defaults; reject refresh_interval=0; fail-closed validate"
```

---

## Task 3: New ContentEvent type (alongside old types, not yet wired)

**Files:**
- Modify: `src/catalog/types.rs`

- [ ] **Step 1: Add new types without deleting old**

Append to `src/catalog/types.rs`:

```rust
/// Node-authored event in the local log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentEvent {
    pub seq: u64,
    pub content_id: String,
    pub manifest_ref: String,
    pub attribute_value_fqns: Vec<String>,
    pub ingested_at: String,
}

/// Input to `EventStore::append`; seq is assigned by the store.
#[derive(Debug, Clone)]
pub struct NewContentEvent {
    pub content_id: String,
    pub manifest_ref: String,
    pub attribute_value_fqns: Vec<String>,
    pub ingested_at: String,
}
```

- [ ] **Step 2: Build check**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/catalog/types.rs
git commit -m "catalog: add ContentEvent + NewContentEvent types"
```

---

## Task 4: EventStore — open, append, current_tail

**Files:**
- Create: `src/catalog/store.rs`
- Modify: `src/catalog/mod.rs`
- Test: `tests/catalog_store_test.rs`

- [ ] **Step 1: Write failing test**

Create `tests/catalog_store_test.rs`:

```rust
use tdf_iroh_s3::catalog::store::EventStore;
use tdf_iroh_s3::catalog::types::NewContentEvent;

fn sample(content_id: &str) -> NewContentEvent {
    NewContentEvent {
        content_id: content_id.to_string(),
        manifest_ref: format!("manifests/{content_id}.json"),
        attribute_value_fqns: vec!["https://example/attr/a/value/x".to_string()],
        ingested_at: "2026-05-26T00:00:00Z".to_string(),
    }
}

#[tokio::test]
async fn append_assigns_monotonic_seq_starting_at_1() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(&dir.path().join("events.redb")).await.unwrap();

    let e1 = store.append(sample("aaa")).await.unwrap();
    let e2 = store.append(sample("bbb")).await.unwrap();
    let e3 = store.append(sample("ccc")).await.unwrap();

    assert_eq!(e1.seq, 1);
    assert_eq!(e2.seq, 2);
    assert_eq!(e3.seq, 3);
    assert_eq!(store.current_tail(), 3);
}

#[tokio::test]
async fn current_tail_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.redb");

    {
        let s = EventStore::open(&path).await.unwrap();
        s.append(sample("x")).await.unwrap();
        s.append(sample("y")).await.unwrap();
    }

    let reopened = EventStore::open(&path).await.unwrap();
    assert_eq!(reopened.current_tail(), 2);

    let e3 = reopened.append(sample("z")).await.unwrap();
    assert_eq!(e3.seq, 3);
}
```

- [ ] **Step 2: Run test, expect failure**

Run: `cargo test --test catalog_store_test append_assigns_monotonic_seq_starting_at_1`
Expected: FAIL — `EventStore` doesn't exist.

- [ ] **Step 3: Implement EventStore (no subscribe yet)**

Create `src/catalog/store.rs`:

```rust
//! Local redb-backed event log. Single-author (the node itself).

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::catalog::types::{ContentEvent, NewContentEvent};

const EVENTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events_v1");
const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("meta_v1");
const META_LAST_SEQ: &str = "last_seq";
const BROADCAST_CAPACITY: usize = 1024;

pub struct EventStore {
    db: Arc<Database>,
    tx: broadcast::Sender<ContentEvent>,
}

impl EventStore {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create catalog dir {}", parent.display()))?;
        }
        let path = path.to_path_buf();
        let db = tokio::task::spawn_blocking(move || -> Result<Database> {
            let db = Database::create(&path)
                .with_context(|| format!("open redb at {}", path.display()))?;
            // Ensure both tables exist so subsequent read transactions don't ENOENT.
            let w = db.begin_write()?;
            { let _ = w.open_table(EVENTS_TABLE)?; let _ = w.open_table(META_TABLE)?; }
            w.commit()?;
            Ok(db)
        })
        .await??;
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self { db: Arc::new(db), tx })
    }

    pub fn current_tail(&self) -> u64 {
        let db = Arc::clone(&self.db);
        // Sync read — redb reads are cheap and don't block the runtime.
        let r = match db.begin_read() {
            Ok(r) => r,
            Err(_) => return 0,
        };
        let table = match r.open_table(META_TABLE) {
            Ok(t) => t,
            Err(_) => return 0,
        };
        table.get(META_LAST_SEQ).ok().flatten().map(|v| v.value()).unwrap_or(0)
    }

    pub async fn append(&self, new: NewContentEvent) -> Result<ContentEvent> {
        let db = Arc::clone(&self.db);
        let event = tokio::task::spawn_blocking(move || -> Result<ContentEvent> {
            let w = db.begin_write()?;
            let next_seq = {
                let meta = w.open_table(META_TABLE)?;
                meta.get(META_LAST_SEQ)?.map(|v| v.value()).unwrap_or(0) + 1
            };
            let event = ContentEvent {
                seq: next_seq,
                content_id: new.content_id,
                manifest_ref: new.manifest_ref,
                attribute_value_fqns: new.attribute_value_fqns,
                ingested_at: new.ingested_at,
            };
            let mut buf = Vec::with_capacity(256);
            ciborium::ser::into_writer(&event, &mut buf)
                .context("encode ContentEvent as CBOR")?;
            {
                let mut events = w.open_table(EVENTS_TABLE)?;
                events.insert(next_seq, buf.as_slice())?;
            }
            {
                let mut meta = w.open_table(META_TABLE)?;
                meta.insert(META_LAST_SEQ, next_seq)?;
            }
            w.commit()?;
            Ok(event)
        })
        .await??;
        // Lossy broadcast: slow subscribers' Lagged error is handled in their handler.
        let _ = self.tx.send(event.clone());
        Ok(event)
    }
}
```

Modify `src/catalog/mod.rs` — add `pub mod store;` alongside the existing modules. Leave the existing modules untouched for now.

- [ ] **Step 4: Run tests, expect pass**

Run: `cargo test --test catalog_store_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/catalog/store.rs src/catalog/mod.rs tests/catalog_store_test.rs
git commit -m "catalog: EventStore with redb backing (open/append/current_tail)"
```

---

## Task 5: EventStore::list_from

**Files:**
- Modify: `src/catalog/store.rs`
- Test: `tests/catalog_store_test.rs`

- [ ] **Step 1: Failing test**

Append to `tests/catalog_store_test.rs`:

```rust
use futures_lite::StreamExt;

#[tokio::test]
async fn list_from_returns_events_in_seq_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(&dir.path().join("events.redb")).await.unwrap();
    for id in ["a", "b", "c", "d"] {
        store.append(sample(id)).await.unwrap();
    }

    let mut stream = store.list_from(0).await.unwrap();
    let mut seen = Vec::new();
    while let Some(evt) = stream.next().await {
        seen.push(evt.unwrap());
    }
    assert_eq!(seen.iter().map(|e| e.content_id.as_str()).collect::<Vec<_>>(),
               vec!["a", "b", "c", "d"]);

    let mut stream = store.list_from(2).await.unwrap();
    let mut after = Vec::new();
    while let Some(evt) = stream.next().await { after.push(evt.unwrap()); }
    assert_eq!(after.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4]);
}
```

- [ ] **Step 2: Run test, expect failure**

Run: `cargo test --test catalog_store_test list_from_returns_events_in_seq_order`
Expected: FAIL — `list_from` doesn't exist.

- [ ] **Step 3: Implement**

Add to `impl EventStore` in `src/catalog/store.rs`:

```rust
/// Stream all events with `seq > after_seq` in ascending order.
pub async fn list_from(
    &self,
    after_seq: u64,
) -> Result<impl futures_lite::Stream<Item = Result<ContentEvent>> + Send + 'static> {
    let db = Arc::clone(&self.db);
    let events: Vec<Result<ContentEvent>> = tokio::task::spawn_blocking(move || {
        let r = db.begin_read()?;
        let table = r.open_table(EVENTS_TABLE)?;
        let range = table.range((after_seq.saturating_add(1))..)?;
        let mut out = Vec::new();
        for entry in range {
            let (_seq, bytes) = match entry {
                Ok(pair) => pair,
                Err(e) => {
                    out.push(Err(anyhow::anyhow!("read events table: {e}")));
                    break;
                }
            };
            let decoded: Result<ContentEvent> = ciborium::de::from_reader(bytes.value())
                .context("decode ContentEvent CBOR");
            out.push(decoded);
        }
        Ok::<Vec<Result<ContentEvent>>, anyhow::Error>(out)
    })
    .await??;
    Ok(futures_lite::stream::iter(events))
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `cargo test --test catalog_store_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/catalog/store.rs tests/catalog_store_test.rs
git commit -m "catalog: EventStore::list_from streams events past a cursor"
```

---

## Task 6: EventStore::subscribe + live tail

**Files:**
- Modify: `src/catalog/store.rs`
- Test: `tests/catalog_store_test.rs`

- [ ] **Step 1: Failing test**

Append to `tests/catalog_store_test.rs`:

```rust
#[tokio::test]
async fn subscribe_receives_events_appended_after_subscription() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(&dir.path().join("events.redb")).await.unwrap();
    store.append(sample("pre")).await.unwrap();

    let mut rx = store.subscribe();
    let store2 = std::sync::Arc::new(store);
    let s2 = store2.clone();
    let handle = tokio::spawn(async move {
        s2.append(sample("post1")).await.unwrap();
        s2.append(sample("post2")).await.unwrap();
    });
    handle.await.unwrap();

    let a = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
    let b = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
    assert_eq!(a.content_id, "post1");
    assert_eq!(b.content_id, "post2");
}
```

- [ ] **Step 2: Run test, expect failure**

Run: `cargo test --test catalog_store_test subscribe_receives_events_appended_after_subscription`
Expected: FAIL — `subscribe` doesn't exist.

- [ ] **Step 3: Implement**

Add to `impl EventStore`:

```rust
pub fn subscribe(&self) -> broadcast::Receiver<ContentEvent> {
    self.tx.subscribe()
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `cargo test --test catalog_store_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/catalog/store.rs tests/catalog_store_test.rs
git commit -m "catalog: EventStore::subscribe for live tail"
```

---

## Task 7: Manifest FQN extractor

**Files:**
- Create: `src/pdp/mod.rs`
- Create: `src/pdp/policy_extract.rs`
- Modify: `src/lib.rs`
- Test: `tests/pdp_policy_extract_test.rs`

- [ ] **Step 1: Failing test**

Create `tests/pdp_policy_extract_test.rs`:

```rust
use opentdf::policy::{AttributeIdentifier, AttributePolicy, Policy};
use opentdf::TdfManifestExt;
use tdf_iroh_s3::pdp::policy_extract::manifest_attr_value_fqns;

#[test]
fn extracts_all_attribute_value_fqns_from_manifest_policy() {
    // Build a manifest with a policy carrying two attributes.
    let mut manifest = opentdf::TdfManifest::default_with_payload("payload-key");
    let a = AttributePolicy::condition(
        AttributeIdentifier::new("https://example/attr/dept", "value/eng"),
        opentdf::policy::Operator::Present,
        None,
    );
    let b = AttributePolicy::condition(
        AttributeIdentifier::new("https://example/attr/clearance", "value/secret"),
        opentdf::policy::Operator::Present,
        None,
    );
    let policy = Policy::new(uuid::Uuid::nil(), AttributePolicy::and(vec![a, b]), vec![]);
    manifest.set_policy(&policy).expect("set policy");

    let mut fqns = manifest_attr_value_fqns(&manifest).expect("extract");
    fqns.sort();
    assert_eq!(
        fqns,
        vec![
            "https://example/attr/clearance/value/secret".to_string(),
            "https://example/attr/dept/value/eng".to_string(),
        ]
    );
}
```

> **Note:** the exact `Policy::new` / `AttributePolicy` constructor names and `TdfManifest::default_with_payload` may differ slightly between opentdf v0.11.x and v0.12.0. If they do, look in the opentdf source at the locally checked-out git dep (`~/.cargo/git/checkouts/opentdf-rs-*/<rev>/src/policy.rs`) and adjust the test inputs. The behavior under test — extracting attribute-value FQNs from a manifest's policy — is unchanged.

- [ ] **Step 2: Run test, expect failure**

Run: `cargo test --test pdp_policy_extract_test`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

Create `src/pdp/mod.rs`:
```rust
pub mod cache;
pub mod policy_extract;
```

Create `src/pdp/policy_extract.rs`:
```rust
//! Pull attribute-value FQNs out of a TDF manifest's policy. Used at ingest
//! time to denormalize the resource side of the PDP check onto the event,
//! so reads don't need to round-trip to S3.

use anyhow::{Context, Result};
use opentdf::TdfManifest;
use opentdf::TdfManifestExt;
use opentdf::policy::AttributePolicy;

/// Walk the manifest's policy and collect every attribute-value FQN
/// referenced by a condition node.
pub fn manifest_attr_value_fqns(manifest: &TdfManifest) -> Result<Vec<String>> {
    let policy = manifest.get_policy().context("read TDF policy")?;
    let mut out = Vec::new();
    collect(&policy.body.conditions, &mut out);
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect(node: &AttributePolicy, out: &mut Vec<String>) {
    match node {
        AttributePolicy::Condition { identifier, .. } => {
            // Identifier shape: namespace + value-name, joined to canonical FQN.
            out.push(format!("{}/{}", identifier.namespace(), identifier.name()));
        }
        AttributePolicy::And(children) | AttributePolicy::Or(children) => {
            for c in children { collect(c, out); }
        }
        AttributePolicy::Not(inner) => collect(inner, out),
    }
}
```

> **Adapter note:** the exact variant names and accessor methods of `AttributePolicy` depend on the opentdf version. If the build fails, inspect the local checkout (`~/.cargo/git/checkouts/opentdf-rs-*/<rev>/src/policy.rs`) and adapt the match arms. The contract: every leaf condition contributes one FQN string; nested boolean nodes recurse.

Modify `src/lib.rs` — add `pub mod pdp;` after `pub mod node;`.

- [ ] **Step 4: Run test, expect pass**

Run: `cargo test --test pdp_policy_extract_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pdp/ src/lib.rs tests/pdp_policy_extract_test.rs
git commit -m "pdp: extract attribute-value FQNs from TDF manifest policy"
```

---

## Task 8: AccessPdpCache — fetch + ArcSwap

**Files:**
- Modify: `src/pdp/cache.rs`
- Test: `tests/pdp_cache_test.rs`

- [ ] **Step 1: Failing test**

Create `tests/pdp_cache_test.rs`:

```rust
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tdf_iroh_s3::pdp::cache::AccessPdpCache;

async fn serve_attribute_defs(body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let h = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(h.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    (format!("http://{addr}"), counter)
}

#[tokio::test]
async fn loads_attribute_definitions_at_boot() {
    // Empty array is valid input for AccessPdp::new.
    let (url, counter) = serve_attribute_defs(b"[]".to_vec()).await;
    let cache = AccessPdpCache::spawn(url, Duration::from_secs(3600), reqwest::Client::new())
        .await
        .expect("initial fetch");
    let _pdp = cache.load(); // Arc<AccessPdp>
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn boot_fails_when_initial_fetch_errors() {
    // Non-routable URL guarantees connect error.
    let res = AccessPdpCache::spawn(
        "http://127.0.0.1:1".to_string(),
        Duration::from_secs(3600),
        reqwest::Client::builder().timeout(Duration::from_millis(500)).build().unwrap(),
    ).await;
    assert!(res.is_err(), "boot must fail-closed on initial fetch error");
}
```

- [ ] **Step 2: Run test, expect failure**

Run: `cargo test --test pdp_cache_test loads_attribute_definitions_at_boot`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

Create `src/pdp/cache.rs`:

```rust
//! AccessPdp cache with stale-while-revalidate background refresh.

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use opentdf::pdp::{AccessPdp, Attribute, PdpOptions};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

const FORCE_REFRESH_MIN_GAP: Duration = Duration::from_secs(1);

pub struct AccessPdpCache {
    url: String,
    http: reqwest::Client,
    pdp: ArcSwap<AccessPdp>,
    last_force_refresh: Mutex<Option<Instant>>,
}

impl AccessPdpCache {
    /// Build the cache. On initial fetch failure, returns Err — callers MUST
    /// fail-closed (panic-loop, exit, etc.). Without attribute definitions
    /// the PDP would deny every check silently.
    pub async fn spawn(
        url: String,
        refresh_interval: Duration,
        http: reqwest::Client,
    ) -> Result<Arc<Self>> {
        let initial = fetch_and_build(&http, &url)
            .await
            .with_context(|| format!("initial PDP fetch from {url}"))?;
        let cache = Arc::new(Self {
            url: url.clone(),
            http: http.clone(),
            pdp: ArcSwap::from_pointee(initial),
            last_force_refresh: Mutex::new(None),
        });
        let weak = Arc::downgrade(&cache);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // initial tick already covered by boot fetch
            loop {
                ticker.tick().await;
                let Some(cache) = weak.upgrade() else {
                    debug!("AccessPdpCache dropped, exiting refresh task");
                    return;
                };
                if let Err(e) = cache.refresh().await {
                    warn!(error = %e, url = %cache.url, "scheduled PDP refresh failed; keeping stale");
                }
            }
        });
        Ok(cache)
    }

    pub fn load(&self) -> Arc<AccessPdp> {
        self.pdp.load_full()
    }

    /// Out-of-band refresh, rate-limited to one per [`FORCE_REFRESH_MIN_GAP`].
    /// Records the timestamp ONLY on a successful fetch so a transient
    /// upstream error does not consume the budget.
    pub async fn force_refresh(&self) -> bool {
        let mut guard = self.last_force_refresh.lock().await;
        let now = Instant::now();
        if let Some(prev) = *guard
            && now.duration_since(prev) < FORCE_REFRESH_MIN_GAP {
            return false;
        }
        drop(guard);
        match fetch_and_build(&self.http, &self.url).await {
            Ok(new_pdp) => {
                self.pdp.store(Arc::new(new_pdp));
                *self.last_force_refresh.lock().await = Some(now);
                true
            }
            Err(e) => {
                warn!(error = %e, "force PDP refresh failed");
                false
            }
        }
    }

    async fn refresh(&self) -> Result<()> {
        let new_pdp = fetch_and_build(&self.http, &self.url).await?;
        self.pdp.store(Arc::new(new_pdp));
        Ok(())
    }
}

async fn fetch_and_build(http: &reqwest::Client, url: &str) -> Result<AccessPdp> {
    let bytes = http
        .get(url)
        .send().await.with_context(|| format!("GET {url}"))?
        .error_for_status().with_context(|| format!("status from {url}"))?
        .bytes().await.with_context(|| format!("body from {url}"))?;
    let attrs: Vec<Attribute> = serde_json::from_slice(&bytes)
        .context("decode attribute definitions JSON")?;
    AccessPdp::new(attrs, PdpOptions::default())
        .map_err(|e| anyhow!("build AccessPdp: {e}"))
}
```

- [ ] **Step 4: Run tests, expect pass**

Run: `cargo test --test pdp_cache_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pdp/cache.rs tests/pdp_cache_test.rs
git commit -m "pdp: AccessPdpCache with fail-closed boot and stale-while-revalidate refresh"
```

---

## Task 9: Vendor pep_check from opentdf-rs

**Files:**
- Create: `src/auth/pep_check.rs`
- Modify: `src/auth/mod.rs`

- [ ] **Step 1: Fetch and vendor**

Pull the contents of `examples/pep_check.rs` from the locally checked-out opentdf-rs git dep. Find it:

```bash
find ~/.cargo/git/checkouts/opentdf-rs-* -name pep_check.rs -path "*examples*" | head -1
```

Copy that file's contents into `src/auth/pep_check.rs`, prepending an attribution header:

```rust
//! Vendored from arkavo-org/opentdf-rs, examples/pep_check.rs (tag v0.12.0).
//! Reproduced under the upstream license (MIT). See LICENSE-OPENTDF for the
//! original notice. Local modifications: removed `fn main`/CLI bits; expose
//! `verify_cwt` and `parse_authorization_details` as `pub`.
//!
//! Per the Arkavo CWT v1 contract, callers MUST NOT roll their own COSE_Sign1
//! parser. Use the entry points here.

// <vendored contents follow>
```

Trim any `fn main`, `#[derive(Parser)]`, and CLI scaffolding. Keep:
- `verify_cwt(cwt_bytes, jwks, expected_issuer, expected_node_id) -> Result<Claims, PepError>`
- `parse_authorization_details(payload_bytes) -> Result<Vec<Grant>, PepError>`
- supporting types (`Claims`, `Grant`, `PepError`, JWKS handling)

If the upstream signature differs, keep the upstream names and adapt our caller to them in Task 10 — don't rename upstream code.

If a JWKS-cache helper is part of pep_check, vendor that too. If not, we keep our own `auth/cose_keys.rs` cache for now (we delete it in Task 21 if pep_check fully covers it).

Modify `src/auth/mod.rs`:
```rust
pub mod pep_check;
```

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: PASS (or compile errors only inside pep_check.rs — fix import paths and `pub` visibility; do not rewrite logic).

- [ ] **Step 3: Smoke test**

Run: `cargo test --no-run` (build all tests).
Expected: PASS.

- [ ] **Step 4: Add LICENSE-OPENTDF**

Create `LICENSE-OPENTDF` at repo root containing the MIT license text from the opentdf-rs repo (copy `LICENSE` from `~/.cargo/git/checkouts/opentdf-rs-*/<rev>/LICENSE`).

- [ ] **Step 5: Commit**

```bash
git add src/auth/pep_check.rs src/auth/mod.rs LICENSE-OPENTDF
git commit -m "auth: vendor pep_check from opentdf-rs v0.12.0"
```

---

## Task 10: Verifier rewrite — non-Option node id, v1 contract

**Files:**
- Modify: `src/auth/cwt.rs`
- Modify: `src/auth/mod.rs`

- [ ] **Step 1: Capture the new public shape**

Replace `src/auth/cwt.rs` entirely:

```rust
//! Thin wrapper over the vendored `pep_check`. Enforces the Arkavo CWT v1
//! contract: ES256 COSE_Sign1, `iss` exact-match, `iat`/`exp` windowing,
//! `scope` must contain `catalog.read`, mandatory `cnf.iroh_node_id` bound
//! to the QUIC peer, and a non-empty `authorization_details` array.

use bytes::Bytes;
use std::sync::Arc;
use thiserror::Error;

use super::SCOPE_CATALOG_READ;
use super::cose_keys::CoseKeyCache;
use super::pep_check;

#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    pub subject: String,
    pub raw_cwt: Bytes,
    pub cti: String,
    pub exp: i64,
    pub iat: i64,
    pub issuer: String,
    /// Pre-parsed grants — caller maps to `Entitlements` via `cwt_to_entitlements`.
    pub grants: Vec<pep_check::Grant>,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("cwt: signature/parse: {0}")]
    BadCwt(String),
    #[error("cwt: wrong issuer (expected '{expected}', got '{got:?}')")]
    WrongIssuer { expected: String, got: Option<String> },
    #[error("cwt: expired (exp={exp}, now={now})")]
    Expired { exp: i64, now: i64 },
    #[error("cwt: issued in the future (iat={iat}, now={now})")]
    NotYetValid { iat: i64, now: i64 },
    #[error("cwt: iat-exp window too wide (max 3600s)")]
    WindowTooWide,
    #[error("cwt: missing claim '{0}'")]
    MissingClaim(&'static str),
    #[error("cwt: scope missing '{0}'")]
    MissingScope(&'static str),
    #[error("cwt: cnf.iroh_node_id mismatch (token='{token}', connection='{connection}')")]
    NodeIdMismatch { token: String, connection: String },
    #[error("cwt: cnf.iroh_node_id missing")]
    MissingNodeIdBinding,
    #[error("cwt: authorization_details missing or empty")]
    MissingAuthDetails,
    #[error("cwt: unknown action name in authorization_details")]
    UnknownAction,
}

pub struct Verifier {
    keys: Arc<CoseKeyCache>,
    issuer: String,
    clock_skew_secs: i64,
}

impl Verifier {
    pub fn new(keys: Arc<CoseKeyCache>, issuer: String, clock_skew_secs: i64) -> Self {
        Self { keys, issuer, clock_skew_secs }
    }

    /// Verify a CWT and channel-bind it to the connection's peer NodeId.
    /// `bound_node_id` is REQUIRED — the iroh ALPN handler always knows
    /// the peer; deliberately not Option to make the bypass impossible.
    pub async fn verify(
        &self,
        cwt: &[u8],
        bound_node_id: &str,
    ) -> Result<VerifiedClaims, VerifyError> {
        let claims = pep_check::verify_cwt(
            cwt,
            self.keys.snapshot().as_ref(),
            &self.issuer,
            self.clock_skew_secs,
            bound_node_id,
            SCOPE_CATALOG_READ,
        )
        .map_err(map_pep_error)?;

        let grants = pep_check::parse_authorization_details(claims.payload_bytes())
            .map_err(map_pep_error)?;
        if grants.is_empty() {
            return Err(VerifyError::MissingAuthDetails);
        }
        for g in &grants {
            for action in &g.actions {
                if action != super::ACTION_READ {
                    return Err(VerifyError::UnknownAction);
                }
            }
        }

        Ok(VerifiedClaims {
            subject: claims.subject,
            raw_cwt: Bytes::copy_from_slice(cwt),
            cti: claims.cti.unwrap_or_default(),
            exp: claims.exp,
            iat: claims.iat,
            issuer: self.issuer.clone(),
            grants,
        })
    }
}

fn map_pep_error(e: pep_check::PepError) -> VerifyError {
    use pep_check::PepError as P;
    // Map upstream variant names to our shape. Names may shift between opentdf
    // versions; adapt the LHS arms when re-vendoring.
    match e {
        P::Parse(s) => VerifyError::BadCwt(s),
        P::WrongIssuer { expected, got } => VerifyError::WrongIssuer { expected, got },
        P::Expired { exp, now } => VerifyError::Expired { exp, now },
        P::NotYetValid { iat, now } => VerifyError::NotYetValid { iat, now },
        P::WindowTooWide => VerifyError::WindowTooWide,
        P::MissingClaim(c) => VerifyError::MissingClaim(c),
        P::MissingScope(s) => VerifyError::MissingScope(s),
        P::NodeIdMismatch { token, connection } => VerifyError::NodeIdMismatch { token, connection },
        P::MissingNodeIdBinding => VerifyError::MissingNodeIdBinding,
        P::Signature(s) => VerifyError::BadCwt(format!("signature: {s}")),
    }
}
```

> **If pep_check's API names differ** from the calls above (e.g. `verify_cwt` takes different args, returns a different struct), match the upstream signatures and adapt this wrapper. Do NOT modify pep_check.

Modify `src/auth/mod.rs`:
```rust
//! CWT verification per the Arkavo CWT v1 contract.
//!
//! Verifies COSE_Sign1 tokens against issuer keys cached locally, enforces
//! the contract's required claims, and exposes `authorization_details`
//! grants for the PDP layer to translate to `Entitlements`.

pub mod cose_keys;
pub mod cwt;
pub mod entitlements;
pub mod pep_check;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_signer;

pub use cose_keys::CoseKeyCache;
pub use cwt::{VerifiedClaims, Verifier, VerifyError};
pub use entitlements::cwt_to_entitlements;

/// Required `scope` value at the catalog read ALPN.
pub const SCOPE_CATALOG_READ: &str = "catalog.read";

/// Only action name accepted in `authorization_details[].actions` for v1.
pub const ACTION_READ: &str = "read";
```

- [ ] **Step 2: Adapt CoseKeyCache to provide `snapshot()`**

Open `src/auth/cose_keys.rs` and add:
```rust
impl CoseKeyCache {
    /// Snapshot of the current key map as the type pep_check expects.
    /// (If pep_check accepts &HashMap<Kid, VerifyingKey> directly, return that
    /// via load_full() shaped to its expected type.)
    pub fn snapshot(&self) -> Arc<HashMap<Kid, VerifyingKey>> {
        self.keys.load_full()
    }
}
```

(Existing `get`/`force_refresh`/`spawn` stay — we will retire this whole file in Task 21 if pep_check fully covers JWKS, but for now we adapt.)

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: PASS once the `map_pep_error` arms align with the actual `pep_check::PepError` variants.

- [ ] **Step 4: Commit (no test yet — tests come with the test_signer rewrite next)**

```bash
git add src/auth/cwt.rs src/auth/mod.rs src/auth/cose_keys.rs
git commit -m "auth: rewrite Verifier as pep_check wrapper; verify takes &str node id"
```

---

## Task 11: cwt_to_entitlements

**Files:**
- Create: `src/auth/entitlements.rs`
- Test: `tests/auth_entitlements_test.rs`

- [ ] **Step 1: Failing test**

Create `tests/auth_entitlements_test.rs`:

```rust
use std::collections::HashMap;
use tdf_iroh_s3::auth::cwt::VerifiedClaims;
use tdf_iroh_s3::auth::cwt_to_entitlements;
use tdf_iroh_s3::auth::pep_check::Grant;

fn vc_with_grants(grants: Vec<Grant>) -> VerifiedClaims {
    VerifiedClaims {
        subject: "alice".into(),
        raw_cwt: Default::default(),
        cti: String::new(),
        exp: 0, iat: 0,
        issuer: "iss".into(),
        grants,
    }
}

#[test]
fn collapses_grants_to_fqn_to_actions_map() {
    let grants = vec![
        Grant { r#type: "tdf_attribute".into(),
                fqn: "https://x/attr/a/value/1".into(),
                actions: vec!["read".into()] },
        Grant { r#type: "tdf_attribute".into(),
                fqn: "https://x/attr/b/value/2".into(),
                actions: vec!["read".into()] },
    ];
    let ents = cwt_to_entitlements(&vc_with_grants(grants));
    assert_eq!(ents.len(), 2);
    assert_eq!(ents["https://x/attr/a/value/1"], vec!["read".to_string()]);
}

#[test]
fn skips_unknown_grant_types_silently() {
    let grants = vec![
        Grant { r#type: "tdf_attribute".into(),
                fqn: "https://x/attr/a/value/1".into(),
                actions: vec!["read".into()] },
        Grant { r#type: "future_thing".into(),
                fqn: "https://x/attr/b/value/2".into(),
                actions: vec!["read".into()] },
    ];
    let ents = cwt_to_entitlements(&vc_with_grants(grants));
    assert_eq!(ents.len(), 1);
    assert!(ents.contains_key("https://x/attr/a/value/1"));
}

#[test]
fn skips_grants_with_unparseable_fqn() {
    let grants = vec![
        Grant { r#type: "tdf_attribute".into(),
                fqn: "not-a-url".into(),
                actions: vec!["read".into()] },
    ];
    let ents = cwt_to_entitlements(&vc_with_grants(grants));
    assert!(ents.is_empty());
}
```

- [ ] **Step 2: Run test, expect failure**

Run: `cargo test --test auth_entitlements_test`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement**

Create `src/auth/entitlements.rs`:

```rust
//! Translate the verifier's `Vec<Grant>` into `opentdf::pdp::Entitlements`.

use opentdf::pdp::Entitlements;
use crate::auth::pep_check::Grant;
use crate::auth::cwt::VerifiedClaims;

const TYPE_TDF_ATTRIBUTE: &str = "tdf_attribute";

pub fn cwt_to_entitlements(claims: &VerifiedClaims) -> Entitlements {
    let mut out = Entitlements::new();
    for g in &claims.grants {
        if g.r#type != TYPE_TDF_ATTRIBUTE { continue; }
        if url::Url::parse(&g.fqn).is_err() { continue; }
        out.entry(g.fqn.clone()).or_default().extend(g.actions.iter().cloned());
    }
    out
}
```

If `url` is not yet a dependency, add it: `cargo add url@2`, then `git add Cargo.toml Cargo.lock`. If you'd rather avoid the dep, a manual check like `g.fqn.starts_with("https://") && g.fqn.contains("/attr/")` is acceptable.

- [ ] **Step 4: Run test, expect pass**

Run: `cargo test --test auth_entitlements_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auth/entitlements.rs tests/auth_entitlements_test.rs Cargo.toml Cargo.lock
git commit -m "auth: cwt_to_entitlements maps grants to opentdf Entitlements"
```

---

## Task 12: Update test_signer for the v1 contract

**Files:**
- Modify: `src/auth/test_signer.rs`

- [ ] **Step 1: Rewrite test_signer**

Replace `TestClaims` and the `mint` body so they emit v1-contract tokens.

```rust
use ciborium::Value;
use coset::cwt::{ClaimsSetBuilder, Timestamp};
use coset::{CborSerializable, CoseKeyBuilder, CoseKeySet, CoseSign1Builder, HeaderBuilder, iana};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Arc;

use super::CoseKeyCache;

pub struct TestSigner {
    signing_key: SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
    pub kid: Vec<u8>,
    pub issuer: String,
}

impl TestSigner {
    pub fn new(issuer: impl Into<String>) -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key, verifying_key,
            kid: b"test-kid-1".to_vec(),
            issuer: issuer.into(),
        }
    }

    pub fn cose_key_set(&self) -> Vec<u8> {
        let point = self.verifying_key.to_encoded_point(false);
        let x = point.x().expect("uncompressed point has x").to_vec();
        let y = point.y().expect("uncompressed point has y").to_vec();
        let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .algorithm(iana::Algorithm::ES256)
            .key_id(self.kid.clone())
            .build();
        CoseKeySet(vec![key]).to_vec().expect("CoseKeySet serializes")
    }

    pub fn cose_key_cache(&self) -> Arc<CoseKeyCache> {
        let mut map = HashMap::new();
        map.insert(self.kid.clone(), self.verifying_key);
        CoseKeyCache::new_static(map)
    }

    /// Mint a v1-contract CWT.
    pub fn mint(&self, claims: TestClaims) -> Vec<u8> {
        let auth_details = Value::Array(
            claims.grants.into_iter().map(|g| {
                Value::Map(vec![
                    (Value::Text("type".into()),    Value::Text(g.grant_type)),
                    (Value::Text("fqn".into()),     Value::Text(g.fqn)),
                    (Value::Text("actions".into()), Value::Array(
                        g.actions.into_iter().map(Value::Text).collect()
                    )),
                ])
            }).collect()
        );

        let mut builder = ClaimsSetBuilder::new()
            .issuer(claims.issuer.unwrap_or_else(|| self.issuer.clone()))
            .subject(claims.subject)
            .issued_at(Timestamp::WholeSeconds(claims.iat))
            .expiration_time(Timestamp::WholeSeconds(claims.exp));
        if let Some(cti) = claims.cti { builder = builder.cwt_id(cti); }
        builder = builder.claim(iana::CwtClaimName::Scope, Value::Text(claims.scope));
        builder = builder.text_claim("authorization_details".into(), auth_details);
        if let Some(node_id) = claims.cnf_iroh_node_id {
            let cnf = Value::Map(vec![(
                Value::Text("iroh_node_id".into()),
                Value::Bytes(node_id.into_bytes()),
            )]);
            builder = builder.claim(iana::CwtClaimName::Cnf, cnf);
        }
        let claims_set = builder.build();
        let payload = claims_set.to_vec().expect("ClaimsSet serializes");

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(self.kid.clone())
            .build();

        let sk = self.signing_key.clone();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(&[], move |tbs| {
                let sig: Signature = sk.sign(tbs);
                sig.to_bytes().to_vec()
            })
            .build();
        sign1.to_vec().expect("COSE_Sign1 serializes")
    }
}

pub struct TestGrant {
    pub grant_type: String,
    pub fqn: String,
    pub actions: Vec<String>,
}

impl TestGrant {
    pub fn read(fqn: impl Into<String>) -> Self {
        Self { grant_type: "tdf_attribute".into(), fqn: fqn.into(), actions: vec!["read".into()] }
    }
}

pub struct TestClaims {
    pub subject: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub cti: Option<Vec<u8>>,
    pub cnf_iroh_node_id: Option<String>,
    pub issuer: Option<String>,
    pub grants: Vec<TestGrant>,
}

impl TestClaims {
    /// Defaults: `catalog.read` scope, valid for 5 minutes, one grant.
    pub fn defaults(subject: impl Into<String>, fqn: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Self {
            subject: subject.into(),
            scope: "catalog.read".into(),
            iat: now,
            exp: now + 300,
            cti: Some(b"test-cti-001".to_vec()),
            cnf_iroh_node_id: None,
            issuer: None,
            grants: vec![TestGrant::read(fqn.into())],
        }
    }
}
```

- [ ] **Step 2: Build**

Run: `cargo build --tests`
Expected: FAIL — old `auth_cwt_test.rs` calls `TestClaims::defaults(creator, campaign)` and accesses `claims.campaign_id`/`claims.creator_id`. Fixing those is Task 13.

- [ ] **Step 3: Commit (incomplete tests — fixed in Task 13)**

```bash
git add src/auth/test_signer.rs
git commit -m "auth: test_signer mints Arkavo CWT v1 contract tokens"
```

---

## Task 13: Rewrite auth_cwt_test for v1

**Files:**
- Modify: `tests/auth_cwt_test.rs`

- [ ] **Step 1: Rewrite the test file**

Replace `tests/auth_cwt_test.rs` entirely:

```rust
//! Verifier acceptance/rejection tests against the Arkavo CWT v1 contract.

use std::sync::Arc;
use std::time::Duration;
use tdf_iroh_s3::auth::test_signer::{TestClaims, TestGrant, TestSigner};
use tdf_iroh_s3::auth::{CoseKeyCache, Verifier, VerifyError};

const ISSUER: &str = "https://issuer.example";
const FQN_A: &str = "https://example/attr/dept/value/eng";
const NODE_ID_A: &str = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";

fn verifier(signer: &TestSigner) -> Verifier {
    Verifier::new(signer.cose_key_cache(), ISSUER.to_string(), 60)
}

#[tokio::test]
async fn verifies_a_freshly_minted_cwt() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    let cwt = signer.mint(claims);

    let vc = v.verify(&cwt, NODE_ID_A).await.expect("valid CWT must verify");
    assert_eq!(vc.subject, "alice");
    assert_eq!(vc.issuer, ISSUER);
    assert!(vc.exp > 0);
    assert_eq!(vc.grants.len(), 1);
    assert_eq!(vc.grants[0].fqn, FQN_A);
}

#[tokio::test]
async fn rejects_expired_cwt() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    claims.iat -= 7200;
    claims.exp -= 3600;
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::Expired { .. }) => {}
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_wrong_issuer() {
    let signer = TestSigner::new("https://attacker.example");
    let v = Verifier::new(signer.cose_key_cache(), ISSUER.to_string(), 60);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::WrongIssuer { .. }) => {}
        other => panic!("expected WrongIssuer, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_missing_scope_catalog_read() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    claims.scope = "openid profile".into();
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::MissingScope(_)) => {}
        other => panic!("expected MissingScope, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_node_id_mismatch() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    let cwt = signer.mint(claims);
    let other_id = "ffff".repeat(16);
    match v.verify(&cwt, &other_id).await {
        Err(VerifyError::NodeIdMismatch { .. }) => {}
        other => panic!("expected NodeIdMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_missing_cnf_when_iroh_bound() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let claims = TestClaims::defaults("alice", FQN_A); // no cnf
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::MissingNodeIdBinding) => {}
        other => panic!("expected MissingNodeIdBinding, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_empty_authorization_details() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    claims.grants.clear();
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::MissingAuthDetails) => {}
        other => panic!("expected MissingAuthDetails, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_unknown_action_in_grants() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    claims.grants[0].actions.push("write".into());
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::UnknownAction) => {}
        other => panic!("expected UnknownAction, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_iat_too_far_in_future() {
    let signer = TestSigner::new(ISSUER);
    let v = verifier(&signer);
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID_A.into());
    claims.iat += 3600;
    claims.exp += 3600;
    let cwt = signer.mint(claims);
    match v.verify(&cwt, NODE_ID_A).await {
        Err(VerifyError::NotYetValid { .. }) => {}
        other => panic!("expected NotYetValid, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run tests, expect pass**

Run: `cargo test --test auth_cwt_test`
Expected: PASS. If any case fails because the upstream pep_check doesn't surface a matching error variant, adjust the `map_pep_error` arms in `src/auth/cwt.rs`, then re-run.

- [ ] **Step 3: Commit**

```bash
git add tests/auth_cwt_test.rs
git commit -m "auth: rewrite verifier tests against Arkavo CWT v1 contract"
```

---

## Task 14: tdf/catalog/1 wire types + frame codec

**Files:**
- Create: `src/protocol/mod.rs`
- Create: `src/protocol/catalog_read.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the wire types and codec**

Create `src/protocol/mod.rs`:
```rust
pub mod catalog_read;
```

Create `src/protocol/catalog_read.rs`:

```rust
//! `tdf/catalog/1` ALPN — reader-side CWT-gated catalog stream.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::catalog::types::ContentEvent;

pub const ALPN: &[u8] = b"tdf/catalog/1";

const MAX_REQUEST_BYTES: u32 = 64 * 1024;
const MAX_FRAME_BYTES: u32 = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct CatalogSubscribe {
    pub cwt: ByteBuf,
    pub after_seq: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CatalogStreamMsg {
    Entry(ContentEvent),
    CaughtUp { seq: u64 },
    Heartbeat,
    TokenExpiringSoon { exp: i64 },
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    PdpUnavailable,
    Internal,
    TooManySubscriptions,
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<()> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(msg, &mut buf).context("encode frame as CBOR")?;
    if buf.len() as u32 > MAX_FRAME_BYTES {
        bail!("frame too large ({} bytes)", buf.len());
    }
    w.write_u32(buf.len() as u32).await.context("write frame length")?;
    w.write_all(&buf).await.context("write frame body")?;
    w.flush().await.ok();
    Ok(())
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<CatalogSubscribe> {
    let len = r.read_u32().await.context("read request length")?;
    if len > MAX_REQUEST_BYTES {
        bail!("request too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await.context("read request body")?;
    let req: CatalogSubscribe = ciborium::de::from_reader(buf.as_slice())
        .context("decode CatalogSubscribe CBOR")?;
    Ok(req)
}
```

Modify `src/lib.rs` — add `pub mod protocol;` after `pub mod pdp;`.

Add `serde_bytes = "0.11"` to `Cargo.toml` if not present (used for `ByteBuf`).

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 3: Smoke test (roundtrip)**

Append to `tests/catalog_store_test.rs` (we don't need a dedicated wire test file yet):

```rust
use tdf_iroh_s3::protocol::catalog_read::{CatalogStreamMsg, ErrorCode, write_frame, read_request, CatalogSubscribe};

#[tokio::test]
async fn write_then_read_request_roundtrip() {
    use std::io::Cursor;
    let req = CatalogSubscribe { cwt: serde_bytes::ByteBuf::from(b"hi".to_vec()), after_seq: Some(7) };
    let mut buf = Vec::new();
    write_frame(&mut buf, &req).await.unwrap();
    let mut cur = Cursor::new(buf);
    let parsed = read_request(&mut cur).await.unwrap();
    assert_eq!(&parsed.cwt[..], b"hi");
    assert_eq!(parsed.after_seq, Some(7));
}
```

Run: `cargo test --test catalog_store_test write_then_read_request_roundtrip`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/protocol/ src/lib.rs Cargo.toml Cargo.lock tests/catalog_store_test.rs
git commit -m "protocol: tdf/catalog/1 wire types and CBOR frame codec"
```

---

## Task 15: tdf/catalog/1 ALPN handler

**Files:**
- Modify: `src/protocol/catalog_read.rs`

- [ ] **Step 1: Implement the handler**

Append to `src/protocol/catalog_read.rs`:

```rust
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU32, Ordering};
use std::collections::HashMap;
use parking_lot::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::auth::{Verifier, cwt_to_entitlements};
use crate::catalog::store::EventStore;
use crate::pdp::cache::AccessPdpCache;
use opentdf::pdp::Action;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const TOKEN_WARNING_LEAD: i64 = 60;

#[derive(Default)]
pub struct SubscriptionLimits {
    pub max_per_peer: u32,
    pub max_total: u32,
    per_peer: Mutex<HashMap<String, u32>>,
    total: AtomicU32,
}

impl SubscriptionLimits {
    pub fn new(max_per_peer: u32, max_total: u32) -> Arc<Self> {
        Arc::new(Self { max_per_peer, max_total, ..Default::default() })
    }
    fn try_acquire(&self, peer: &str) -> bool {
        if self.total.load(Ordering::SeqCst) >= self.max_total { return false; }
        let mut map = self.per_peer.lock();
        let count = map.entry(peer.to_string()).or_insert(0);
        if *count >= self.max_per_peer { return false; }
        *count += 1;
        self.total.fetch_add(1, Ordering::SeqCst);
        true
    }
    fn release(&self, peer: &str) {
        let mut map = self.per_peer.lock();
        if let Some(c) = map.get_mut(peer) {
            *c = c.saturating_sub(1);
            if *c == 0 { map.remove(peer); }
        }
        self.total.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct CatalogReadDeps {
    pub verifier: Arc<Verifier>,
    pub store: Arc<EventStore>,
    pub pdp: Arc<AccessPdpCache>,
    pub limits: Arc<SubscriptionLimits>,
    pub cancel: CancellationToken,
}

/// ALPN handler. Drives one subscriber's full lifecycle. Returns Ok(()) on
/// graceful close; returns Err only on unexpected I/O. Auth failures
/// silently close the connection (per contract §4).
pub async fn handle<R, W>(
    mut read: R,
    mut write: W,
    remote_node_id: String,
    deps: CatalogReadDeps,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let req = match read_request(&mut read).await {
        Ok(r) => r,
        Err(e) => {
            warn!(peer = %remote_node_id, err = %e, "catalog subscribe: bad request");
            return Ok(());
        }
    };

    let claims = match deps.verifier.verify(&req.cwt, &remote_node_id).await {
        Ok(c) => c,
        Err(e) => {
            warn!(peer = %remote_node_id, err = %e, "catalog subscribe: cwt rejected; closing silently");
            return Ok(()); // close without emitting any frame
        }
    };
    info!(sub = %claims.subject, peer = %remote_node_id, "catalog subscribe opened");

    let entitlements = cwt_to_entitlements(&claims);
    if entitlements.is_empty() {
        warn!(peer = %remote_node_id, "catalog subscribe: empty entitlements; closing");
        return Ok(());
    }

    if !deps.limits.try_acquire(&remote_node_id) {
        let _ = write_frame(&mut write, &CatalogStreamMsg::Error {
            code: ErrorCode::TooManySubscriptions,
            message: "subscription cap reached".into(),
        }).await;
        return Ok(());
    }
    let _guard = ReleaseOnDrop::new(&deps.limits, remote_node_id.clone());

    let pdp = deps.pdp.load();
    let action = Action::new("read");

    // Backfill
    let after = req.after_seq.unwrap_or(0);
    let mut bf = deps.store.list_from(after).await.context("list_from")?;
    while let Some(ev) = futures_lite::StreamExt::next(&mut bf).await {
        let ev = ev?;
        if pdp.check(&entitlements, &action, &ev.attribute_value_fqns)
            .map(|d| d.is_allow()).unwrap_or(false)
        {
            write_frame(&mut write, &CatalogStreamMsg::Entry(ev)).await?;
        }
    }
    let tail = deps.store.current_tail();
    write_frame(&mut write, &CatalogStreamMsg::CaughtUp { seq: tail }).await?;

    // Live
    let mut live = deps.store.subscribe();
    let mut hb = tokio::time::interval(HEARTBEAT_INTERVAL);
    hb.tick().await;
    let mut warned = false;
    loop {
        tokio::select! {
            biased;
            _ = deps.cancel.cancelled() => {
                debug!(peer = %remote_node_id, "catalog subscribe: server cancelled");
                return Ok(());
            }
            ev = live.recv() => match ev {
                Ok(ev) => {
                    if pdp.check(&entitlements, &action, &ev.attribute_value_fqns)
                        .map(|d| d.is_allow()).unwrap_or(false)
                    {
                        write_frame(&mut write, &CatalogStreamMsg::Entry(ev)).await?;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    warn!(peer = %remote_node_id, dropped = n, "subscriber lagged; closing");
                    let _ = write_frame(&mut write, &CatalogStreamMsg::Error {
                        code: ErrorCode::Internal,
                        message: format!("lagged, {n} events dropped"),
                    }).await;
                    return Ok(());
                }
                Err(RecvError::Closed) => return Ok(()),
            },
            _ = hb.tick() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
                if now >= claims.exp {
                    let _ = write_frame(&mut write, &CatalogStreamMsg::Error {
                        code: ErrorCode::BadRequest,
                        message: "cwt expired".into(),
                    }).await;
                    return Ok(());
                }
                if !warned && now >= claims.exp - TOKEN_WARNING_LEAD {
                    write_frame(&mut write, &CatalogStreamMsg::TokenExpiringSoon { exp: claims.exp }).await?;
                    warned = true;
                }
                write_frame(&mut write, &CatalogStreamMsg::Heartbeat).await?;
            }
        }
    }
}

struct ReleaseOnDrop<'a> {
    limits: &'a SubscriptionLimits,
    peer: String,
}
impl<'a> ReleaseOnDrop<'a> {
    fn new(limits: &'a SubscriptionLimits, peer: String) -> Self {
        Self { limits, peer }
    }
}
impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        self.limits.release(&self.peer);
    }
}
```

Add `parking_lot = "0.12"` to `Cargo.toml` if not present (cheap, sync mutex for the limits map).

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/protocol/catalog_read.rs Cargo.toml Cargo.lock
git commit -m "protocol: tdf/catalog/1 handler — verify, backfill, live, heartbeat, expiry, caps"
```

---

## Task 16: Wire EventStore + PDP + verifier into TdfIrohNode (additive, keep old fields temporarily)

**Files:**
- Modify: `src/node.rs`
- Modify: `src/auth/cose_keys.rs` (verify `snapshot()` still compiles)

- [ ] **Step 1: Add new fields and constructors to TdfIrohNode**

Open `src/node.rs`. Replace the struct and `spawn` body:

```rust
pub struct TdfIrohNode {
    router: Router,
    store: FsStore,
    endpoint: Endpoint,
    pub s3_client: Arc<S3Client>,
    pub config: Arc<Config>,
    pub catalog: Arc<crate::catalog::store::EventStore>,
    pub verifier: Arc<crate::auth::Verifier>,
    pub pdp: Arc<crate::pdp::cache::AccessPdpCache>,
    cancel: CancellationToken,
}

impl TdfIrohNode {
    pub async fn spawn(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        config.validate().context("config validation failed")?;

        let s3_client = Arc::new(
            S3Client::new(&config.s3.bucket, &config.s3.region, &config.s3.prefix)
                .await.context("Failed to create S3 client")?,
        );

        let store = FsStore::load(&config.iroh.data_dir)
            .await.context("Failed to load FsStore")?;

        let mut builder = Endpoint::builder(presets::N0);
        if !config.iroh.secret_key_param.is_empty() {
            let secret_key = secret_key::load_or_create(
                &config.iroh.secret_key_param,
                &config.s3.region,
            ).await.context("Failed to load or create node secret key")?;
            builder = builder.secret_key(secret_key);
        }

        let endpoint = builder
            .bind_addr((Ipv4Addr::UNSPECIFIED, config.iroh.bind_port))
            .context("Invalid bind address")?
            .bind().await.context("Failed to bind Iroh endpoint")?;
        info!("Iroh endpoint bound on port {}", config.iroh.bind_port);
        endpoint.online().await;
        info!("Iroh endpoint online");

        let cancel = CancellationToken::new();

        let mask = EventMask { get: RequestMode::Notify, ..EventMask::DEFAULT };
        let (event_sender, event_rx) = EventSender::channel(64, mask);
        let blobs = BlobsProtocol::new(&store, Some(event_sender));

        // Catalog (redb event log)
        let catalog_path = std::path::PathBuf::from(&config.catalog.data_dir).join("events.redb");
        let catalog = Arc::new(
            crate::catalog::store::EventStore::open(&catalog_path)
                .await.context("Failed to open EventStore")?,
        );

        // PDP cache (fail-closed on boot if attribute defs URL is down)
        let http_client = reqwest::Client::builder()
            .build().context("Failed to build reqwest client")?;
        let pdp = crate::pdp::cache::AccessPdpCache::spawn(
            config.pdp.attribute_defs_url.clone(),
            Duration::from_secs(config.pdp.refresh_interval_secs),
            http_client.clone(),
        ).await.context("Failed to spawn PDP cache")?;

        // CWT verifier
        let keys = crate::auth::CoseKeyCache::spawn(
            config.auth.cose_keys_url.clone(),
            Duration::from_secs(config.auth.refresh_interval_secs),
            http_client,
        ).await.context("Failed to spawn COSE key cache")?;
        let verifier = Arc::new(crate::auth::Verifier::new(
            keys, config.auth.issuer.clone(), config.auth.clock_skew_secs,
        ));

        // Catalog read ALPN
        let limits = crate::protocol::catalog_read::SubscriptionLimits::new(
            config.catalog.max_subscriptions_per_peer,
            config.catalog.max_subscriptions_total,
        );
        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .accept(
                crate::protocol::catalog_read::ALPN,
                CatalogReadProtocol {
                    verifier: Arc::clone(&verifier),
                    store: Arc::clone(&catalog),
                    pdp: Arc::clone(&pdp),
                    limits,
                    cancel: cancel.clone(),
                },
            )
            .spawn();

        let addr = endpoint.addr();
        info!("Node ID: {}", addr.id);

        {
            let store = store.clone();
            let s3_client = Arc::clone(&s3_client);
            let config = Arc::clone(&config);
            let catalog = Arc::clone(&catalog);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                run_ingest_loop(event_rx, store, s3_client, catalog, config, cancel).await;
            });
        }

        Ok(Self { router, store, endpoint, s3_client, config, catalog, verifier, pdp, cancel })
    }
    // … existing addr, store, shutdown methods unchanged …
}
```

Add a `CatalogReadProtocol` adapter further down in the same file:

```rust
#[derive(Clone)]
struct CatalogReadProtocol {
    verifier: Arc<crate::auth::Verifier>,
    store: Arc<crate::catalog::store::EventStore>,
    pdp: Arc<crate::pdp::cache::AccessPdpCache>,
    limits: Arc<crate::protocol::catalog_read::SubscriptionLimits>,
    cancel: CancellationToken,
}

impl iroh::protocol::ProtocolHandler for CatalogReadProtocol {
    fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> iroh::protocol::AcceptFuture {
        let deps = crate::protocol::catalog_read::CatalogReadDeps {
            verifier: Arc::clone(&self.verifier),
            store: Arc::clone(&self.store),
            pdp: Arc::clone(&self.pdp),
            limits: Arc::clone(&self.limits),
            cancel: self.cancel.clone(),
        };
        Box::pin(async move {
            let peer = connection.remote_node_id().map(|n| n.to_string()).unwrap_or_default();
            let (send, recv) = connection.accept_bi().await
                .map_err(|e| anyhow::anyhow!("accept_bi: {e}"))?;
            crate::protocol::catalog_read::handle(recv, send, peer, deps).await?;
            Ok(())
        })
    }
}
```

> **Iroh API note:** the exact `ProtocolHandler` trait signature in `iroh = "0.97"` may use `Box<dyn Future>`, an associated type, or an `async fn` signature. Adapt the impl to whichever shape compiles — the body is the same.

Also update the ingest loop signature:

```rust
async fn run_ingest_loop(
    mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    store: FsStore,
    s3_client: Arc<S3Client>,
    catalog: Arc<crate::catalog::store::EventStore>,
    config: Arc<Config>,
    cancel: CancellationToken,
) {
    // existing body, but pass `catalog` into wait_and_ingest
    // (next task wires the catalog hook).
}
```

- [ ] **Step 2: Build**

Run: `cargo build`
Expected: PASS. Old `catalog: Arc<CatalogReplica>` field is gone; any test still referencing it will fail at the next test step (Task 19's cleanup).

- [ ] **Step 3: Commit**

```bash
git add src/node.rs src/auth/cose_keys.rs
git commit -m "node: wire EventStore + AccessPdpCache + verifier; register tdf/catalog/1 ALPN"
```

---

## Task 17: Hook ingest → append ContentEvent

**Files:**
- Modify: `src/node.rs`
- Modify: `src/ingest.rs`

- [ ] **Step 1: Extend ingest_blob to return the parsed manifest**

In `src/ingest.rs`, add a new helper that returns both result and parsed manifest:

```rust
pub struct IngestOutcome {
    pub result: IngestResult,
    pub manifest: opentdf::TdfManifest,
}

pub async fn ingest_from_store_with_manifest(
    hash: Hash,
    store: &FsStore,
    validation_config: &crate::config::ValidationConfig,
    s3_client: &S3Client,
) -> Result<Option<IngestOutcome>> {
    let data = match store.get_bytes(hash).await {
        Ok(b) => b,
        Err(e) => { tracing::trace!(%hash, error = %e, "blob not yet readable"); return Ok(None); }
    };
    validation::validate_blob(&data, validation_config).context("Blob rejected by validation")?;
    let manifest = opentdf::TdfArchive::read(&data)
        .context("re-parse manifest")?
        .manifest;
    let bhash = blake3::hash(&data);
    let hash_hex = bhash.to_hex().to_string();
    let size = data.len() as u64;
    if !s3_client.has_blob(&hash_hex).await? {
        s3_client.put_blob(&hash_hex, Bytes::copy_from_slice(&data))
            .await.context("Failed to upload blob to S3")?;
    }
    Ok(Some(IngestOutcome {
        result: IngestResult { hash_hex, size },
        manifest,
    }))
}
```

Keep `ingest_from_store` and `ingest_blob` (unchanged signatures) so existing tests keep compiling.

- [ ] **Step 2: Modify `wait_and_ingest` in `src/node.rs`**

Replace the call inside the retry loop:

```rust
async fn wait_and_ingest(
    hash: iroh_blobs::Hash,
    mut rx: irpc::channel::mpsc::Receiver<RequestUpdate>,
    store: &FsStore,
    s3_client: &S3Client,
    catalog: &crate::catalog::store::EventStore,
    config: &Config,
) {
    // ... existing rx loop unchanged until the ingest retry block ...

    for attempt in 0..10 {
        match crate::ingest::ingest_from_store_with_manifest(
            hash, store, &config.validation, s3_client,
        ).await {
            Ok(Some(outcome)) => {
                let fqns = match crate::pdp::policy_extract::manifest_attr_value_fqns(&outcome.manifest) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(hash = %outcome.result.hash_hex, error = %e,
                              "policy extract failed; appending event with empty FQNs");
                        Vec::new()
                    }
                };
                let ingested_at = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
                let manifest_ref = format!("{}blobs/{}.manifest", s3_client.prefix(), outcome.result.hash_hex);
                if let Err(e) = catalog.append(crate::catalog::types::NewContentEvent {
                    content_id: outcome.result.hash_hex.clone(),
                    manifest_ref,
                    attribute_value_fqns: fqns,
                    ingested_at,
                }).await {
                    error!(hash = %outcome.result.hash_hex, error = %e, "EventStore append failed");
                }
                info!(hash = %outcome.result.hash_hex, size = outcome.result.size, "Blob ingested + event appended");
                return;
            }
            Ok(None) => {
                debug!(%hash, attempt, "Blob not yet readable, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                error!(%hash, error = %e, "Ingest failed");
                return;
            }
        }
    }
    error!(%hash, "Blob not readable after transfer completed");
}
```

Update the `tokio::spawn` call sites in `run_ingest_loop` to thread `catalog` through.

- [ ] **Step 3: Build**

Run: `cargo build && cargo test --test catalog_store_test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/ingest.rs src/node.rs
git commit -m "node: append ContentEvent on successful ingest"
```

---

## Task 18: End-to-end ALPN test

**Files:**
- Create: `tests/catalog_read_alpn_test.rs`

- [ ] **Step 1: Write the test**

Create `tests/catalog_read_alpn_test.rs`:

```rust
//! End-to-end: spawn EventStore + verifier + PDP + ALPN handler, drive a
//! subscriber over an in-memory bidi pipe (no real iroh endpoint needed for
//! the protocol-level test).

use std::sync::Arc;
use std::time::Duration;
use tdf_iroh_s3::auth::test_signer::{TestClaims, TestGrant, TestSigner};
use tdf_iroh_s3::auth::Verifier;
use tdf_iroh_s3::catalog::store::EventStore;
use tdf_iroh_s3::catalog::types::NewContentEvent;
use tdf_iroh_s3::pdp::cache::AccessPdpCache;
use tdf_iroh_s3::protocol::catalog_read::{
    CatalogReadDeps, CatalogStreamMsg, CatalogSubscribe, SubscriptionLimits, handle, write_frame,
};
use tokio::io::duplex;
use tokio_util::sync::CancellationToken;

const ISSUER: &str = "https://issuer.test";
const NODE_ID: &str = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
const FQN_A: &str = "https://example/attr/dept/value/eng";
const FQN_B: &str = "https://example/attr/dept/value/legal";

async fn empty_pdp() -> Arc<AccessPdpCache> {
    // Minimal: serve `[]` (no attribute defs → PDP allows nothing) — but we
    // need at least one attr-def so check() can evaluate FQN_A/FQN_B. Build
    // by hand instead:
    panic!("test must use a non-empty PDP; see helper below");
}

async fn pdp_with_dept_attribute() -> Arc<AccessPdpCache> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let body = serde_json::json!([
        {
            "fqn": "https://example/attr/dept",
            "rule": "AnyOf",
            "values": [
                {"fqn": "https://example/attr/dept/value/eng",   "value": "eng"},
                {"fqn": "https://example/attr/dept/value/legal", "value": "legal"}
            ]
        }
    ]).to_string();

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    let body_bytes = body.into_bytes();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let body = body_bytes.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let h = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(h.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    AccessPdpCache::spawn(format!("http://{addr}"), Duration::from_secs(3600), reqwest::Client::new())
        .await.unwrap()
}

#[tokio::test]
async fn subscriber_receives_only_granted_entries() {
    let signer = TestSigner::new(ISSUER);
    let v = Arc::new(Verifier::new(signer.cose_key_cache(), ISSUER.to_string(), 60));
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(EventStore::open(&dir.path().join("e.redb")).await.unwrap());
    let pdp = pdp_with_dept_attribute().await;

    store.append(NewContentEvent {
        content_id: "x1".into(), manifest_ref: "m1".into(),
        attribute_value_fqns: vec![FQN_A.into()], ingested_at: "t".into(),
    }).await.unwrap();
    store.append(NewContentEvent {
        content_id: "x2".into(), manifest_ref: "m2".into(),
        attribute_value_fqns: vec![FQN_B.into()], ingested_at: "t".into(),
    }).await.unwrap();

    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID.into());
    let cwt = signer.mint(claims);

    let deps = CatalogReadDeps {
        verifier: v,
        store: Arc::clone(&store),
        pdp,
        limits: SubscriptionLimits::new(4, 256),
        cancel: CancellationToken::new(),
    };

    let (client_side, server_side) = duplex(64 * 1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_side);
    let (server_read, server_write) = tokio::io::split(server_side);

    let server = tokio::spawn(async move {
        handle(server_read, server_write, NODE_ID.into(), deps).await
    });

    let req = CatalogSubscribe { cwt: serde_bytes::ByteBuf::from(cwt), after_seq: None };
    write_frame(&mut client_write, &req).await.unwrap();

    // Read frames until CaughtUp
    let mut entries = Vec::new();
    loop {
        let len = tokio::io::AsyncReadExt::read_u32(&mut client_read).await.unwrap();
        let mut buf = vec![0u8; len as usize];
        tokio::io::AsyncReadExt::read_exact(&mut client_read, &mut buf).await.unwrap();
        let msg: CatalogStreamMsg = ciborium::de::from_reader(buf.as_slice()).unwrap();
        match msg {
            CatalogStreamMsg::Entry(e) => entries.push(e),
            CatalogStreamMsg::CaughtUp { .. } => break,
            other => panic!("unexpected during backfill: {other:?}"),
        }
    }
    assert_eq!(entries.len(), 1, "only the eng-tagged entry should pass");
    assert_eq!(entries[0].content_id, "x1");

    drop(client_write); // close stream → server exits via Closed broadcast
    let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
}
```

- [ ] **Step 2: Run test, expect pass**

Run: `cargo test --test catalog_read_alpn_test`
Expected: PASS. If the PDP rejects FQN_A unexpectedly, inspect the JSON shape this test serves vs what opentdf v0.12.0 `serde_json::from_slice::<Vec<Attribute>>` expects — adapt the JSON in `pdp_with_dept_attribute`.

- [ ] **Step 3: Commit**

```bash
git add tests/catalog_read_alpn_test.rs
git commit -m "test: end-to-end tdf/catalog/1 subscriber receives only granted entries"
```

---

## Task 19: Delete CatalogReplica, publish.rs, EventAuthorization, old tests

**Files:**
- Delete: `src/catalog/publish.rs`
- Delete: `src/catalog/replica.rs`
- Delete: `src/catalog/keys.rs`
- Delete: `tests/catalog_event_log_test.rs`
- Delete: `tests/catalog_test.rs`
- Modify: `src/catalog/mod.rs`
- Modify: `src/catalog/types.rs`

- [ ] **Step 1: Remove deprecated module references**

Replace `src/catalog/mod.rs`:
```rust
//! Local event log.
//!
//! v1 design: the node ingests TDFs on its own authority and appends a
//! `ContentEvent` to a redb-backed log. Readers subscribe via
//! `tdf/catalog/1` and get a CWT-filtered live stream.

pub mod store;
pub mod types;

pub use types::{ContentEvent, NewContentEvent};
```

Replace `src/catalog/types.rs` (drop all the publisher-side types):
```rust
use serde::{Deserialize, Serialize};

/// Node-authored event in the local log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentEvent {
    pub seq: u64,
    pub content_id: String,
    pub manifest_ref: String,
    pub attribute_value_fqns: Vec<String>,
    pub ingested_at: String,
}

#[derive(Debug, Clone)]
pub struct NewContentEvent {
    pub content_id: String,
    pub manifest_ref: String,
    pub attribute_value_fqns: Vec<String>,
    pub ingested_at: String,
}
```

- [ ] **Step 2: Delete files**

```bash
git rm src/catalog/publish.rs src/catalog/replica.rs src/catalog/keys.rs \
       tests/catalog_event_log_test.rs tests/catalog_test.rs
```

- [ ] **Step 3: Build + test**

Run: `cargo build && cargo test`
Expected: PASS. If any other module imports from the deleted files (e.g. `S3Client::put_object_bytes_if_none_match` callers from the old publish flow), surface those in the build errors and remove them too.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "catalog: remove iroh-docs replica + publish path (superseded by EventStore)"
```

---

## Task 20: Remove iroh-docs and iroh-gossip dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Remove deps**

Delete from `Cargo.toml`:
```toml
iroh-docs = "0.97"
iroh-gossip = "0.97"
```

- [ ] **Step 2: Build**

Run: `cargo build && cargo test`
Expected: PASS — nothing should reference these after Task 19.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: drop iroh-docs and iroh-gossip (v1 has no federation)"
```

---

## Task 21: Retire cose_keys.rs if pep_check covers JWKS

**Files:**
- Investigate first; only delete if pep_check provides a complete JWKS-fetch+cache primitive.

- [ ] **Step 1: Check pep_check's JWKS API**

Read `src/auth/pep_check.rs`. If it exposes a `JwksCache::spawn(url, interval)` or equivalent, proceed to Step 2. Otherwise skip this task — `cose_keys.rs` stays as the wrapped cache, with the force_refresh-stamp-on-success fix from Task 8 already applied (it's the same shape).

- [ ] **Step 2 (if applicable): Replace CoseKeyCache with pep_check's**

Update `src/auth/mod.rs`, `src/auth/cwt.rs`, and any test using `CoseKeyCache::new_static` / `spawn` to use the pep_check equivalent. Delete `src/auth/cose_keys.rs`.

If pep_check's JWKS cache lacks the `force_refresh-stamp-on-success` semantics, file an upstream issue and keep our wrapper as a thin adapter that fixes it locally.

- [ ] **Step 3: Build + test**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 4: Commit (if you changed anything)**

```bash
git add -A
git commit -m "auth: defer JWKS handling to pep_check"
```

---

## Task 22: bootstrap.sh + CLAUDE.md updates

**Files:**
- Modify: `packer/files/bootstrap.sh`
- Modify: `CLAUDE.md`

- [ ] **Step 1: bootstrap.sh template**

Open `packer/files/bootstrap.sh`. If the user-data template includes a default config.toml, ensure it carries `[auth]` and `[pdp]` sections:

```toml
[s3]
bucket = "..."
region = "..."

[catalog]
data_dir = "/var/lib/tdf-iroh-s3/catalog"

[auth]
cose_keys_url = "https://identity.arkavo.net/.well-known/cose-keys"
issuer = "https://identity.arkavo.net"

[pdp]
attribute_defs_url = "https://identity.arkavo.net/.well-known/attributes"
```

If bootstrap.sh just writes user-data verbatim, instead update the deployment runbook to require these sections. Either way, the boot validate() will fail-closed with a clear error if they're missing.

- [ ] **Step 2: CLAUDE.md updates**

Open `CLAUDE.md`. Update:
- Architecture section: mention `tdf/catalog/1` ALPN, redb event log, reader-side CWT
- Dependencies list: add `redb`, `opentdf 0.12 (pep_check vendored, pdp module)`, remove `iroh-docs`
- Add a note: "Reader-side CWT — see `docs/superpowers/specs/2026-05-26-reader-side-cwt-and-redb-event-log-design.md`"

- [ ] **Step 3: Commit**

```bash
git add packer/files/bootstrap.sh CLAUDE.md
git commit -m "docs: update bootstrap + CLAUDE.md for reader-side catalog flow"
```

---

## Task 23: Final smoke + self-review

- [ ] **Step 1: Full build + test**

Run: `cargo build && cargo test`
Expected: PASS for all 14+ test files.

- [ ] **Step 2: cargo clippy (warning-clean)**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: PASS. Fix any warnings inline (most likely: unused imports from the deleted modules).

- [ ] **Step 3: Verify no orphan references**

Run:
```bash
grep -rn "iroh_docs\|iroh_gossip\|CatalogReplica\|publish_content\|EventAuthorization\|SCOPE_CATALOG_WRITE\|campaign_id" src/ tests/ || echo "OK — all references removed"
```
Expected: `OK — all references removed`. (Some tracking comments in docs/ are fine; src/ and tests/ must be clean.)

- [ ] **Step 4: Verify finding closure**

Spot-check each finding number against the corresponding section of `docs/superpowers/specs/2026-05-26-reader-side-cwt-and-redb-event-log-design.md` § "Findings resolution". If any row claims "Closed" but the test for it doesn't exist, write one before declaring done.

- [ ] **Step 5: Commit any last cleanups**

```bash
git add -A
git commit -m "chore: post-refactor clippy + grep cleanup"
```
