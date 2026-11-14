# Ownership, pointer /2 and deletion requests: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One account owns each recording, the passkey signs the index through pointer `/2`, and recordings and envelopes their owner dropped are deleted from S3 (every version) by an operator-run sweep.

**Architecture:** Three stacked PRs, deployed together on the switch day. Part 1 makes `moderation/publishers/<hash>` write-once and enforces it at push and at publish. Part 2 adds pointer `/2` with `indexHash` and makes the publish path `/2`-only. Part 3 writes a transition record per publish; offline subcommands fold committed transitions into requests, delete what is due and verify tombstones. They work through an `ObjectStore` trait that has an S3 implementation and a versioned in-memory one.

**Tech Stack:** Rust 2024 (MSRV 1.91), axum 0.8, aws-sdk-s3, clap 4, sha2, serde_json, tokio.

**Spec:** `docs/superpowers/specs/2026-11-13-deletion-requests-design.md` (approved 2026-11-13). Section references such as "3.4 step 5" point into it. Read it before starting any task.

## Global Constraints

- Wire strings are copied from the spec's "Contract changes" table byte for byte. Creator matches them exactly.
- `GRACE` = 7 days = `604_800` s. Tombstones are verified after 1 hour = `3_600` s. Owner lookups at push time: 5 s timeout, bounded by the session lookups' semaphore (`SESSION_LOOKUPS`).
- Subjects are compared through `moderation::canonical_subject` in owner records, in request keys (`deletion-requests/*/<sub>/…`, `subjects/<sub>`), and in every comparison. Pointer keys (`catalog-pointers/<sub>`) and transition keys (`catalog-transitions/<sub>/…`) use the token's `sub` byte for byte, as today.
- Deletion logic takes `now: i64` (Unix seconds) as a parameter. Only `main.rs` calls `now_secs()` for it.
- Anything the sweep reads and can't parse aborts the run with `Err` and a nonzero exit, before it writes anything.
- No new crate dependencies.
- Every task ends with `cargo fmt && cargo clippy --all-targets` clean and `cargo test` green. Every commit leaves the suite green.
- Branches: PR 1 `feat/ownership` (from `feat/deletion-requests`, which carries the spec and this plan), PR 2 `feat/pointer-2` stacked on it, PR 3 `feat/deletion-sweep` stacked on that. **None merges to `main` until all three are approved.** They merge together on the switch day, because a deploy of Part 1 alone would refuse every publish before `claim-owners --write` has run.
- `production/deploy-runbook.md` is local only and never committed.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XAvDR28r93kKYWnA4YLSnf
  ```

## Calls this plan makes (the spec leaves them open)

1. **Ungated node** (`publishing: None`, development only). No owner records are written there, so `check_payloads` skips the owner check, the pre-check answers `none`, and the push gate doesn't exist. 428, `/2` and `indexHash` still apply.
2. **The push owner check runs last** in `authorize_push`, after the session, suspension, block and decision checks, so a refused session costs no S3 read. When `PublishGate` has no owner store (`owners: None`), the check is skipped. `main.rs` always sets one.
3. **Refusal precedence in `check_payloads`:** blocked → not ingested → size → **owner** → manifest → attribute. Inside the owner check, any entry owned by another account gives the 403; only when there is none, an entry with no owner gives the 422. An owner record that can't be read or parsed gives 502 `storage unavailable`.
4. **The pre-check accepts lowercase hex only** (`is_lower_hex_hash`), like index entries.
5. **428 sits at the precondition row** of the `PUT` table, immediately before the 412 check. The table's order stays as it is.
6. **The index record's create can lose.** If the create returns `false` and the read then finds nothing (a concurrent create still in flight), the node answers 502 `storage unavailable`. An existing record is a retry only if its `owner` equals `{sub}` and its entries' canonical hash equals the pointer's `indexHash`; anything else is 409.
7. **When the base index fails its `indexHash` at publish** (a `/2` base whose stored index no longer matches), the node answers 502 `storage unavailable` and logs an error. The node fails closed and writes nothing.
8. **Where the transition is written:** after the 412 and 409 checks of step 7, immediately before the document write. A retry of a publish that already committed is refused before it can rewrite its committed transition.
9. **Re-folding is idempotent.** A crash between writing requests and deleting transitions makes the next run fold the same transitions again. So:
   - a `dropped` hash makes a request pending only if it has no record, a pending record, or a `deleted` record whose `deletedAt` is earlier than the transition's `at`;
   - an `added` hash cancels a pending record only, by deleting it.
10. **`claim-owners` exits nonzero** when it finds any conflict. The owner records it creates carry `"endpointId":"claim-owners"`.
11. **`release-owner`'s `--reason`** is printed, not stored.
12. **Deleting a key's versions:** list its versions with the exact key as the prefix, keep exact matches only, then send one `DeleteObject` with `VersionId` per version and delete marker.

## Review Focus

1. **The first `/2` publish over a stored `/1` pointer, or over a pre-envelope pointer**, is accepted under the existing precondition rules. Its transition's `base.pointer` is the SHA-256 of the `/1` bytes. `GET` keeps serving the `/1` pointer until then. Pinned in Tasks 10 and 12.
2. **One hash under two `contentID`s owned by another account:** `contentIDs` lists both, sorted, and the same holds for the 422. Pinned in Task 4.
3. **A retry of the same signed pointer after its pointer write succeeded but the reply was lost** gets 412 or 409 before any transition write. The committed transition is unchanged. Pinned in Task 12.
4. **Two pointer keys for one canonical subject** (`arkavo:<uuid>` and `<uuid>`):
   - `claim-owners` counts one lister, not a conflict;
   - a subject request covers both pointers;
   - request keys are canonical.
   Pinned in Tasks 7 and 15.
5. **An ungated node:** a publish passes without owner records, the pre-check answers `none`, and 428 still applies. Pinned in Tasks 4, 5 and 10.

---

## Interfaces (all tasks)

Names and signatures every task relies on. A task's own block lists only what it adds or uses from here.

```rust
// src/ownership.rs (Part 1)
pub use crate::moderation::BlobOwner;                        // {hash, subject, endpointId, at}
pub const PUBLISHERS: &str = "publishers";                   // moderation/publishers/<hash>
pub fn parse_owner(hash: &str, bytes: &[u8]) -> anyhow::Result<BlobOwner>; // strict: JSON, hash == key, valid_subject
pub enum OwnerView { You, Another, None }                    // serializes "you" | "another account" | "none"
pub trait OwnerStore: Send + Sync + 'static {                // object-safe, like SessionStore
    fn get_owner<'a>(&'a self, hash: &'a str) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>>;
    fn create_owner<'a>(&'a self, hash: &'a str, body: Bytes) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>>; // false: exists
}
impl OwnerStore for S3Client;
pub async fn claim_owners<O: ObjectStore>(store: &O, write: bool, now: i64) -> anyhow::Result<ClaimReport>;
pub struct ClaimReport { pub owned: usize, pub claimed: Vec<(String, String)>, pub conflicts: Vec<Conflict> }
pub struct Conflict { pub hash: String, pub listers: Vec<String>, pub owner: Option<String> }
pub async fn release_owner<O: ObjectStore>(store: &O, hash: &str, subject: &str) -> anyhow::Result<Released>;
pub enum Released { Deleted(usize), NotOwner(String), NoRecord }

// src/store/s3.rs
impl S3Client {
    pub async fn create_moderation_record(&self, kind: &str, key: &str, body: Bytes) -> Result<bool>; // If-None-Match: *, 409|412 → false
    pub async fn create_catalog_index(&self, hash_hex: &str, body: Bytes) -> Result<bool>;          // Part 2
    pub fn catalog_transition_key(&self, sub: &str, name: &str) -> String;                          // Part 3
    pub async fn put_catalog_transition(&self, sub: &str, name: &str, body: Bytes) -> Result<()>;   // Part 3
    pub fn with_list_page_size(self, n: i32) -> Self;                                               // tests
}

// src/tags_api.rs: TagStore grows (MemStore too)
fn get_blob_owner(&self, hash_hex: &str) -> impl Future<Output = anyhow::Result<Option<Bytes>>> + Send;            // Part 1
fn create_catalog_index(&self, hash_hex: &str, body: Bytes) -> impl Future<Output = anyhow::Result<bool>> + Send;  // Part 2, replaces put_catalog_index
fn put_catalog_transition(&self, sub: &str, name: &str, body: Bytes) -> impl Future<Output = anyhow::Result<()>> + Send; // Part 3

// src/moderation.rs
pub enum PushRefusal { NoSession, Suspended, Blocked, OwnedByAnother, OwnerUnknown }
impl PublishGate { pub fn with_owner_store(self, store: Arc<dyn OwnerStore>) -> Self; }

// src/catalogs_api.rs
pub(crate) struct PayloadRefusal { pub status: StatusCode, pub error: String, pub content_ids: Option<Vec<String>> }
impl PayloadRefusal { pub(crate) fn into_response_parts(self) -> (StatusCode, Json<serde_json::Value>); } // {"error", "contentIDs"?}
pub(crate) async fn check_payloads<S: TagStore>(state: &ApiState<S>, entries: &[CreatorCatalogEntry], attribute: &str, publisher: &str) -> Result<(), PayloadRefusal>;
pub(crate) async fn look_up<S, T, F, Fut>(…) // made pub(crate), unchanged

// src/object_store.rs (Part 1, Task 6)
pub struct ObjectInfo { pub key: String, pub modified: i64 }
pub struct VersionInfo { pub key: String, pub version_id: String, pub delete_marker: bool, pub modified: i64 }
pub trait ObjectStore: Send + Sync + 'static {   // keys are relative to [s3] prefix
    fn list(&self, prefix: &str) -> impl Future<Output = anyhow::Result<Vec<ObjectInfo>>> + Send;
    fn list_versions(&self, prefix: &str) -> impl Future<Output = anyhow::Result<Vec<VersionInfo>>> + Send;
    fn get(&self, key: &str) -> impl Future<Output = anyhow::Result<Option<Bytes>>> + Send;
    fn head_owner(&self, key: &str) -> impl Future<Output = anyhow::Result<Option<Option<String>>>> + Send; // None: no object
    fn put(&self, key: &str, body: Bytes) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn create(&self, key: &str, body: Bytes) -> impl Future<Output = anyhow::Result<bool>> + Send;
    fn delete_all_versions(&self, key: &str) -> impl Future<Output = anyhow::Result<usize>> + Send;
}
impl ObjectStore for S3Client;
#[cfg(test)] pub(crate) mod mem { pub struct MemObjects; /* versioned; set_now(i64); fail_on(key, Op); */ }

// src/catalog_scan.rs (Part 1, Task 7; Part 2 adds indexHash verification)
pub struct ScannedPointer { pub key: String, pub subject: String /* canonical */, pub seq: u64, pub catalog_hash: String, pub index_hash: Option<String>, pub digest: String /* hex SHA-256 of pointer bytes */ }
pub struct ScannedIndex { pub owner: String, pub hashes: BTreeSet<String> }
pub struct Catalogs { pub pointers: Vec<ScannedPointer>, pub indexes: HashMap<String, ScannedIndex> } // indexes: every catalog-indexes/ record
pub async fn scan<O: ObjectStore>(store: &O) -> anyhow::Result<Catalogs>;
impl Catalogs { pub fn live_hashes(&self, p: &ScannedPointer) -> Option<&BTreeSet<String>>; }

// src/creator_catalog.rs (Part 2)
pub fn canonical_index(entries: &[CreatorCatalogEntry]) -> String;
pub fn index_hash(entries: &[CreatorCatalogEntry]) -> String; // lowercase hex SHA-256

// src/catalog_v2.rs (Part 2)
pub const POINTER_SCHEMA: &str = "arkavo.catalog-pointer/2";   // what a publish must carry
pub const POINTER_SCHEMA_1: &str = "arkavo.catalog-pointer/1"; // still read
pub struct Pointer { …, pub index_hash: Option<String> }      // Some iff schema is /2

// src/catalogs_v2_api.rs
pub(crate) struct IndexRecord { pub owner: String, pub attribute: String, pub entries: serde_json::Value } // made pub(crate)
pub(crate) struct StoredPointerInfo { pub seq: u64, pub catalog_hash: String, pub index_hash: Option<String>, pub digest: String }
pub(crate) fn stored_pointer(body: &[u8]) -> anyhow::Result<StoredPointerInfo>; // replaces stored_seq (Task 7; index_hash from Task 9)

// src/deletion/ (Part 3)
pub const GRACE: i64 = 604_800;
pub const VERIFY_AFTER: i64 = 3_600;
pub fn transition_name(seq: u64, digest: &str) -> String;     // format!("{seq:020}-{digest}")
pub struct Transition { pub subject: String, pub seq: u64, pub catalog_hash: String, pub pointer: String, pub base: Option<TransitionBase>, pub at: i64, pub dropped: Vec<String>, pub added: Vec<String> }
pub struct TransitionBase { pub seq: u64, pub catalog_hash: String, pub pointer: String }
pub enum State { Pending, Deleted }  pub enum Source { Transition, Observed }  pub enum Scope { Hash, Subject }
pub struct RecordingRequest { pub hash, pub subject, pub requested_at: i64, pub seq: u64, pub state: State, pub deleted_at: Option<i64> }
pub struct EnvelopeRequest  { pub hash, pub owner: Option<String>, pub superseded_at: i64, pub source: Source, pub state: State, pub deleted_at: Option<i64> }
pub struct OperatorRequest  { pub hash, pub subject, pub requested_at: i64, pub reason: String, pub scope: Scope, pub state: State, pub deleted_at: Option<i64> }
pub struct SubjectRequest   { pub subject, pub requested_at: i64, pub reason: String, pub state: State, pub deleted_at: Option<i64> }
// all: #[serde(rename_all = "camelCase", deny_unknown_fields)], enums lowercase; deleted_at skipped when None
pub fn recording_key(sub: &str, hash: &str) -> String;  // "deletion-requests/recordings/<sub>/<hash>"
pub fn envelope_key(hash: &str) -> String;              // "deletion-requests/envelopes/<hash>"
pub fn operator_key(sub: &str, hash: &str) -> String;   // "deletion-requests/operator/<sub>/<hash>"
pub fn subject_key(sub: &str) -> String;                // "deletion-requests/subjects/<sub>"
// snapshot.rs
pub struct Snapshot { pub catalogs: Catalogs, pub transitions: BTreeMap<String, Transition>, pub requests: Requests, pub moderation: ModerationView, pub owners: HashMap<String, String>, pub envelope_objects: BTreeSet<String> }
pub struct Requests { pub recordings: BTreeMap<(String, String), RecordingRequest>, pub envelopes: BTreeMap<String, EnvelopeRequest>, pub operator: BTreeMap<(String, String), OperatorRequest>, pub subjects: BTreeMap<String, SubjectRequest> }
pub struct ModerationView { pub blocked: HashSet<String>, pub catalog_blocked: HashSet<String>, pub hidden: HashSet<String> } // hidden = catalog block or hideCatalog suspension
pub async fn read<O: ObjectStore>(store: &O) -> anyhow::Result<Snapshot>;
// fold.rs
pub struct Fold { pub requests: Requests /* after folding */, pub cancelled: Vec<(String, String)>, pub folded: Vec<String> /* transition keys, oldest first */, pub lost: Vec<String>, pub kept: Vec<(String, &'static str)> }
pub fn fold(snapshot: &Snapshot, now: i64) -> Fold;
// due.rs
pub struct View { pub s: BTreeSet<String> /* pointer keys */, pub l: HashSet<String>, pub c: HashSet<String> }
pub fn view(catalogs: &Catalogs, requests: &Requests, moderation: &ModerationView) -> View;
pub fn observe(snapshot: &Snapshot, requests: &Requests, view: &View, now: i64) -> Vec<EnvelopeRequest>;
pub enum Item { Recording { hash: String, requests: Vec<String> /* request keys */ }, Subject(String), Envelope(String) }
pub struct Decision { pub due: Vec<Item>, pub kept: Vec<(String, String)> }
pub fn due(snapshot: &Snapshot, requests: &Requests, view: &View, now: i64) -> Decision;
// sweep.rs
pub struct Report { pub lines: Vec<String>, pub failures: usize }  // Display: lines, then counts
pub async fn sweep<O: ObjectStore>(store: &O, delete: bool, now: i64) -> anyhow::Result<Report>;
// operator.rs
pub async fn request_hashes<O: ObjectStore>(store: &O, subject: &str, hashes: &[String], reason: &str, now: i64) -> anyhow::Result<Vec<String>>; // written keys
pub async fn request_all<O: ObjectStore>(store: &O, subject: &str, reason: &str, now: i64) -> anyhow::Result<Vec<String>>;
```

---

# PR 1: Ownership (`feat/ownership`)

### Task 1: Owner records are strict and created only once

**Files:**
- Create: `src/ownership.rs` (and `pub mod ownership;` in `src/lib.rs`)
- Modify: `src/store/s3.rs` (add `create_moderation_record` after `put_moderation_record`, ~line 629)
- Test: `src/ownership.rs` unit tests; `tests/s3_client_test.rs`

**Interfaces:** Produces `PUBLISHERS`, `parse_owner`, `OwnerStore` + `impl OwnerStore for S3Client`, `S3Client::create_moderation_record`, and `ownership::test_support::MemOwners` (`#[cfg(test)]`): a `Mutex<HashMap<String, Bytes>>` with `down: AtomicBool` and `hang: AtomicBool`.

- [ ] **Step 1: Write the failing tests**
  - `parse_owner_is_strict`: `parse_owner(h, br#"{"hash":h,"subject":"u1","endpointId":"e","at":1}"#)` is Ok. These are Err: a body whose `hash` differs from `h`; `"subject":"a/b"`; non-JSON; a missing `at`.
  - `create_owner_never_overwrites` (MemOwners): a first `create_owner` returns `true` and a second returns `false`, and `get_owner` returns the first body.
  - In `tests/s3_client_test.rs`, extend `metadata_s3()`: a `PUT` with `if-none-match: *` on an existing key answers `412` with body `<Error><Code>PreconditionFailed</Code><Message>x</Message></Error>`. Then `test_create_moderation_record_is_conditional`: the first call is `Ok(true)`, the second is `Ok(false)`, and the stored body is still the first.
- [ ] **Step 2: Run** `cargo test ownership && cargo test --test s3_client_test create_moderation`. Expected: compile errors / FAIL.
- [ ] **Step 3: Implement** `create_moderation_record`, a `put_object` with `.if_none_match("*")` that maps 409/412 to `Ok(false)` as `put_catalog_pointer` does. Then implement `parse_owner`, `OwnerStore for S3Client` (`get_moderation_record(PUBLISHERS, h)` / `create_moderation_record`) and `MemOwners`.
- [ ] **Step 4: Run** the step 2 commands and `cargo clippy --all-targets`. Expected: PASS, clean.
- [ ] **Step 5: Commit** `feat(ownership): write-once owner records`

### Task 2: Ingest creates the owner record and never overwrites it

**Files:**
- Modify: `src/node.rs:349-368` (`record_owner`) and its call at `:293`
- Test: `src/node.rs` unit test

**Interfaces:** Consumes `OwnerStore`. Changes `record_owner(owners: &dyn OwnerStore, hash, subject, endpoint)`; `ingester.s3_client` is passed as `&dyn OwnerStore`.

- [ ] **Step 1: Write the failing test** `record_owner_keeps_the_first_owner` (MemOwners): record `u1`, then `u2`, for the same hash. `parse_owner` of the stored record has `subject == "u1"`. A store that is `down` only logs: the test asserts no panic and that nothing is stored.
- [ ] **Step 2: Run** `cargo test record_owner`. Expected: FAIL.
- [ ] **Step 3: Implement.** `record_owner` builds the same `BlobOwner` and calls `create_owner`: `Ok(false)` → `debug!`, `Err` → `warn!` "Recording the blob's owner failed; it stays unowned until pushed again".
- [ ] **Step 4: Run** `cargo test record_owner && cargo test --test node_ingest_test`. Expected: PASS. `wait_for_put("moderation/publishers/…")` still sees a PUT.
- [ ] **Step 5: Commit** `feat(ownership): ingest claims an unowned recording, never overwrites`

### Task 3: A push of another account's recording is refused

**Files:**
- Modify: `src/moderation.rs` (`PublishGate` fields, `new`, `with_owner_store`, `PushRefusal`, `authorize_push` ~`:725`)
- Modify: `src/main.rs` (where the gate gets `with_session_store`, add `.with_owner_store(Arc::clone(&store) as Arc<dyn OwnerStore>)`)
- Test: `src/moderation.rs` tests

**Interfaces:** Consumes `OwnerStore`, `parse_owner`, `MemOwners`. Produces `PushRefusal::{OwnedByAnother, OwnerUnknown}` and `with_owner_store`.

- [ ] **Step 1: Write the failing tests** (gate with an open session for `arkavo:<uuid>`):
  - `a_push_of_another_accounts_recording_is_refused`: the record names `u2` → `Err(OwnedByAnother)`.
  - `the_owner_may_push_again`: the record names the bare `<uuid>` (canonical match) → `Ok`.
  - `an_unowned_recording_may_be_pushed`: no record → `Ok`.
  - `an_unreadable_owner_refuses_the_push`: the store is `down`, or the body is garbage → `Err(OwnerUnknown)`.
  - `a_slow_owner_lookup_refuses_the_push` (`#[tokio::test(start_paused = true)]`): with `hang` set → `Err(OwnerUnknown)` after 5 s.
  - `busy_owner_lookups_refuse_the_push`: all `SESSION_LOOKUPS` permits held (as the existing test at `:1928` does) → `Err(OwnerUnknown)`.
  - `without_an_owner_store_the_check_is_skipped`: `Ok`.
- [ ] **Step 2: Run** `cargo test --lib moderation::`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Add `owners: Option<Arc<dyn OwnerStore>>` to `PublishGate`.
  - At the end of `authorize_push`, after `decided_session`, call `self.owner_allows(&subject, hash_hex)`:
    - `try_acquire` on `self.lookups`, else `OwnerUnknown`;
    - `tokio::time::timeout(SESSION_LOOKUP_TIMEOUT, get_owner)`;
    - parse with `parse_owner`;
    - compare `canonical_subject`.
  - Log each refusal with `warn!`.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ownership): refuse pushes of another account's recording`

### Task 4: A publish may list only the publisher's recordings

**Files:**
- Modify: `src/tags_api.rs` (`TagStore::get_blob_owner`; S3 impl delegates to `get_moderation_record(PUBLISHERS, h)`; `MemStore.owners: Mutex<HashMap<String, Bytes>>` + `pub async fn own(&self, hash: &str, subject: &str)`)
- Modify: `src/catalogs_api.rs` (`PayloadRefusal`, `check_payloads(…, publisher)`, `look_up` → `pub(crate)`)
- Modify: `src/catalogs_v2_api.rs` (pass `&claims.sub`; map `PayloadRefusal`; test helper `ingest()` also calls `h.store.own(&payload(n), SUB)`)
- Modify: `src/catalogs_api.rs` tests (`ingest()` helper owns for the harness's publisher)
- Modify: `docs/creator-catalogs.md` (`PUT` table: two rows after the size row; a short "Ownership" paragraph under "Publishing a recording")
- Test: `src/catalogs_api.rs`, `src/catalogs_v2_api.rs` tests

**Interfaces:** Consumes `parse_owner`, `canonical_subject`. Produces `PayloadRefusal`, the new `check_payloads` signature and `MemStore::own`.

- [ ] **Step 1: Write the failing tests** (catalogs_api):
  - `a_recording_of_another_account_is_refused`: `p1` is owned by `u2`, and the index lists `rec-b` and `rec-a` both naming `p1`, plus `rec-c` naming `p2` owned by the publisher. Expect `status == 403`, `error == "recording belongs to another account"`, `content_ids == Some(vec!["rec-a","rec-b"])`.
  - `an_unowned_recording_must_be_pushed_again`: `p1` has no record → `422`, `"recording has no owner: push it again"`, `Some(vec!["rec-1"])`.
  - `another_owner_outranks_no_owner`: one entry owned by `u2` and one unowned → 403, listing only the first.
  - `the_owner_check_is_canonical`: the record names `<uuid>` and the publisher is `arkavo:<uuid>` → Ok.
  - `an_unreadable_owner_is_502`: the record body is `b"x"` → `502`, `"storage unavailable"`.
  - `an_ungated_node_skips_the_owner_check`: `harness(false)` with no owner records → Ok.
  - `the_owner_check_follows_the_size_check`: an unowned entry with a wrong size → the size 422.
  - In catalogs_v2_api, `a_publish_refusal_carries_content_ids`: the reply JSON has `"contentIDs":["rec-1"]`.
- [ ] **Step 2: Run** `cargo test --lib catalogs_`. Expected: FAIL.
- [ ] **Step 3: Implement.** In `check_payloads`, after the size check and only when `state.publishing.is_some()`:
  - `look_up` each distinct hash's `get_blob_owner`;
  - bucket the entries into another/none, collecting `content_id`s, then sort and dedupe them;
  - existing refusals become `PayloadRefusal { content_ids: None, .. }`.
  `put_catalog` logs the refusal and returns `into_response_parts()`, adding `contentIDs` only when `Some`.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ownership): a catalog lists only its publisher's recordings`

### Task 5: `GET /publish/recordings/{hash}`

**Files:**
- Modify: `src/catalogs_api.rs` (route + handler `recording_owner::<S>`)
- Modify: `docs/creator-catalogs.md` (a new `### GET /publish/recordings/{hash}: who owns a recording` after `GET /blobs/{hash}`)
- Test: `src/catalogs_api.rs` tests

**Interfaces:** Consumes `authorize_publisher`, `TagStore::get_blob_owner`, `parse_owner`, `OwnerView`.

- [ ] **Step 1: Write the failing tests**:
  - `recording_owner_answers_you_another_or_none`: three hashes → `200 {"hash":h,"owner":"you"}`, `"another account"`, `"none"`. The body never contains `u2`.
  - `recording_owner_needs_a_publisher_token`: no token → `401 "missing bearer token"`; a token without the entitlement → `403 "publishing entitlement required"`; a suspended subject → `403 "publishing suspended"`.
  - `recording_owner_refuses_an_invalid_hash`: `ABC…` (uppercase) and `xyz` → `400 "invalid hash"`.
  - `recording_owner_storage_failure_is_502`: `down` → `502 "storage unavailable"`.
  - `recording_owner_on_an_ungated_node_is_none`: owner → `"none"`.
- [ ] **Step 2: Run** `cargo test --lib recording_owner`. Expected: FAIL.
- [ ] **Step 3: Implement** the handler:
  1. `authorize_publisher` (its errors pass through as `fail(status, msg)`);
  2. `is_lower_hex_hash`;
  3. `None` when ungated, else `get_blob_owner` → `parse_owner` → `OwnerView`, comparing canonically.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ownership): GET /publish/recordings/{hash}`

### Task 6: `ObjectStore` for the offline commands

**Files:**
- Create: `src/object_store.rs` (trait, `ObjectInfo`, `VersionInfo`, `#[cfg(test)] pub(crate) mod mem`)
- Modify: `src/store/s3.rs` (`impl ObjectStore for S3Client`, `list_page_size: i32` field defaulting to 1000, `with_list_page_size`)
- Create: `tests/s3_versioned_test.rs` (`#[ignore]`, real bucket)
- Test: `src/object_store.rs` unit tests

**Interfaces:** Produces `ObjectStore`, `MemObjects` (versioned).
- `MemObjects::set_now(i64)` sets the `modified` time of later writes.
- `MemObjects::fail_on(key: &str, op: Op)` with `Op::{Get, Put, Delete, List}` injects one failure.
- `MemObjects::delete_current(key)` (a plain DeleteObject, adding a delete marker) is for tests.
- `MemObjects::deletes()` returns the keys deleted so far, in order; `MemObjects::on_before_delete(key, f)` runs `f(&MemObjects)` once, just before that key's first delete (Task 16's re-check tests).

- [ ] **Step 1: Write the failing tests** (MemObjects):
  - `create_after_every_version_is_deleted_succeeds`: create → `true`; put (2 versions); `delete_all_versions` → `2`; `list_versions(key)` is empty; create → `true`.
  - `delete_all_versions_removes_delete_markers`: put, then `delete_current` → 2 versions (one a marker); `delete_all_versions` → `2`.
  - `list_versions_matches_only_the_prefix`: `blobs/aa` and `blobs/ab`; `list_versions("blobs/aa")` returns only `blobs/aa`'s versions.
  - `list_returns_current_objects_with_their_write_time`: `set_now(100)`, put → `modified == 100`; a key whose current version is a marker is not listed.
- [ ] **Step 2: Write** `tests/s3_versioned_test.rs`, `#[ignore]`, reading `TDF_IROH_S3_VERSIONED_BUCKET` and `AWS_REGION`, skipping when unset, and using a random prefix:
  - `conditional_create_after_version_deletion`: create, then create again (`false`), then `delete_all_versions`, then create (`true`);
  - `version_listing_paginates`: `with_list_page_size(2)` and 5 versions → all 5 listed;
  - `a_concurrent_conditional_create_reports_false`: two concurrent creates → exactly one `true`.
  Each test cleans up its prefix.
- [ ] **Step 3: Run** `cargo test --lib object_store`. Expected: FAIL.
- [ ] **Step 4: Implement.** In the S3 impl, `list` uses `list_objects_v2` and `list_versions` uses `list_object_versions` (with key/version-id markers), both paginated with `list_page_size` and filtered by prefix. Also:
  - prepend the `[s3] prefix` to keys and strip it from listed ones;
  - `head_owner` reads `x-amz-meta-owner` as `head_catalog_document` does;
  - `delete_all_versions` follows call 12.
- [ ] **Step 5: Run** `cargo test --lib object_store && cargo test --test s3_versioned_test`. Expected: PASS (the real-bucket tests are ignored).
- [ ] **Step 6: Commit** `feat(store): versioned object store for the offline commands`

### Task 7: `claim-owners` and `release-owner`

**Files:**
- Create: `src/catalog_scan.rs`
- Modify: `src/catalogs_v2_api.rs` (`IndexRecord` → `pub(crate)` with `pub` fields; `stored_seq` → `stored_pointer` returning `StoredPointerInfo { seq, catalog_hash, digest }`, its callers updated; Task 9 adds `index_hash`)
- Modify: `src/ownership.rs` (`claim_owners`, `release_owner`)
- Modify: `src/main.rs` (subcommands `ClaimOwners { #[arg(long)] write: bool }` and `ReleaseOwner { --hash, --subject, --reason }`, dispatched before the node starts, as `purge-catalogs-1` was in c48ec9d)
- Modify: `docs/publishing-and-moderation.md` (new `## Ownership` section: first push owns, refusals, pre-check, `claim-owners`, `release-owner`, IAM `s3:PutObject` with conditional creates on `moderation/publishers/*`)
- Modify: `CLAUDE.md` (Key Modules: `ownership.rs`, `object_store.rs`, `catalog_scan.rs`; `moderation/publishers` write-once)
- Test: unit tests in `catalog_scan.rs` and `ownership.rs`

**Interfaces:**
- Consumes `ObjectStore`, `MemObjects`, `parse_index`, `parse_owner`.
- Produces `stored_pointer` (used by `scan`, and by the publish path from Task 12).
- Produces `catalog_scan::{scan, Catalogs, ScannedPointer, ScannedIndex}`, `claim_owners`, `release_owner`.

- [ ] **Step 1: Write the failing tests** (MemObjects seeded with pointer bundles from `v2::bundle`, index records and owner records):
  - `scan_reads_pointers_and_indexes_strictly`: two pointers → two `ScannedPointer`s with `subject` canonical and `digest` = hex SHA-256 of the pointer bytes. A garbage pointer, a garbage index record or an index whose `entries` fail `parse_index` → `Err`.
  - `claim_owners_creates_a_record_for_the_only_lister`: `write = true` → the record names `u1`, with `endpointId == "claim-owners"`. `write = false` writes nothing but reports the claim.
  - `two_pointer_keys_of_one_subject_are_one_lister`: `arkavo:<uuid>` and `<uuid>` both list `h` → one claim, no conflict.
  - `two_listers_are_a_conflict`: `u1` and `u2` both list `h` → a `Conflict` with listers `["u1","u2"]`, nothing written.
  - `an_owner_who_does_not_list_it_is_a_conflict`: the record names `u2` and only `u1` lists `h` → a conflict with `owner == Some("u2")`.
  - `an_owner_who_lists_it_is_owned`: `owned == 1`.
  - `release_owner_deletes_only_the_named_subjects_record`: wrong subject → `NotOwner("u1")` with the record kept; right subject (canonical) → `Deleted(n)` and `list_versions` empty; none → `NoRecord`.
- [ ] **Step 2: Run** `cargo test --lib catalog_scan ownership`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - `scan` lists `catalog-pointers/` and `catalog-indexes/`, then gets and parses each.
  - `claim_owners` reads every owner record of a listed hash through `get` + `parse_owner` (unreadable → `Err`) and creates records with `create`; a `false` is reported as a conflict on the next run.
  - In `main.rs`, print one line per claim (`claimed <hash> <subject>` / `would claim …`), each conflict (`conflict <hash>: listed by a, b; owner c`), then counts. Exit `1` on any conflict.
  - `release-owner` prints `released <hash> from <subject> (<n> versions): <reason>`, or why not and exits `1`.
- [ ] **Step 4: Run** `cargo test`, and `cargo run -- --help` lists both subcommands. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ownership): claim-owners backfill and release-owner`

---

# PR 2: Pointer /2 (`feat/pointer-2`)

### Task 8: The canonical index and `indexHash`

**Files:**
- Modify: `src/creator_catalog.rs` (`canonical_index`, `index_hash`)
- Test: `src/creator_catalog.rs` tests

**Interfaces:** Produces `canonical_index`, `index_hash`.

- [ ] **Step 1: Write the failing test** `index_hash_vectors`, with the spec's three vectors inline:
  - `index_hash(&[]) == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"`;
  - "two" in input order `rec-b` (v1, `"bb"×32`, 2048), `rec-a` (v3, `"aa"×32`, 1024): `canonical_index` equals the spec's canonical bytes and the hash is `"03f745d8d08d9e9e11cabf33d85e8beb452eb3a2b2e541f92e1703c1f4152df4"`;
  - "byte-order" with input `a_1, a@1, A, a:1, a.1, a-1`, where entry *n* has hash `format!("{n:02x}").repeat(32)`, size *n*+1 and v1: the hash is `"79129b9fa70e8ab5d0894d07098294de6dec2677c9df538b3eb05df98bd8ef18"`, and `canonical_index` starts with `[{"contentID":"A",`.
- [ ] **Step 2: Run** `cargo test --lib index_hash`. Expected: FAIL.
- [ ] **Step 3: Implement.** Sort a copy by `content_id.as_bytes()` and `format!` each entry with keys in the spec's order (no serde, so key order is fixed). Hash with `sha2::Sha256` and `hex::encode`.
- [ ] **Step 4: Run** `cargo test --lib index_hash`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(catalog): canonical index and indexHash`

### Task 9: Pointer `/2` parses; `/1` still reads

**Files:**
- Modify: `src/catalog_v2.rs` (constants, `Pointer.index_hash` with `#[serde(default)]`, `parse_pointer`, test helpers `pointer_bytes` / `bundle` gain `index_hash: Option<&str>`, where `None` gives `/1`)
- Modify: every caller of `v2::pointer_bytes` / `v2::bundle` (pass `None` for now; Task 10 switches publishes to `/2`)
- Modify: `src/catalog_scan.rs` (a `/2` pointer whose index entries don't hash to `indexHash` → `Err`) and `StoredPointerInfo` (adds `index_hash`)
- Modify: `src/catalog_v2.rs` doc comment (`/1` and `/2`)
- Test: `src/catalog_v2.rs`, `src/catalog_scan.rs` tests

**Interfaces:** Produces `POINTER_SCHEMA` (= `/2`), `POINTER_SCHEMA_1`, `Pointer.index_hash`, and the helpers' new signature.

- [ ] **Step 1: Write the failing tests**:
  - `pointer_2_rules`: a `/2` with `indexHash` parses with `index_hash == Some(..)`. These are Err: `/2` without `indexHash`; `/2` with an uppercase or 63-character `indexHash`; `/1` with `indexHash`; a schema `/3` (error `pointer schema must be "arkavo.catalog-pointer/2"`); a repeated `indexHash`; 1025 bytes.
  - `pointer_1_still_parses`: the existing `pointer_rules` cases, with `index_hash == None`.
  - `arkavo_kit_pointer_vectors_agree` is unchanged: the fixture's `/1` vectors keep their validity.
  - `scan_refuses_a_2_pointer_whose_index_does_not_match`.
- [ ] **Step 2: Run** `cargo test --lib catalog_v2 catalog_scan`. Expected: FAIL.
- [ ] **Step 3: Implement** the per-schema key rule after the typed parse: `/1` ⇒ `index_hash.is_none()`, `/2` ⇒ `is_lower_hex_hash`. Any other schema gets the message above.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS (`verify_bundle` accepts both; nothing publishes `/2` yet).
- [ ] **Step 5: Commit** `feat(catalog): parse pointer /2 alongside /1`

### Task 10: Publishes are `/2`, signed over the index, with a precondition

**Files:**
- Modify: `src/catalogs_v2_api.rs` (`put_catalog`: `/2` required after `verify_bundle`; `indexHash` check after `parse_index`, before the block check; 428 before the 412 check; index record via `create_catalog_index`)
- Modify: `src/tags_api.rs` (`put_catalog_index` → `create_catalog_index`; MemStore keeps the first body and returns `false`)
- Modify: `src/store/s3.rs` (`create_catalog_index`: `If-None-Match: *`, 409/412 → `false`)
- Modify: `src/catalogs_v2_api.rs` tests:
  - `fn signed(seq, document, index: &Value) -> Bundle` computes the `/2` bundle with `index_hash(&parse_index(index))`;
  - `publish` / `publish_index` / `body` use it;
  - publish helpers send `If-None-Match: *` when `h.store` holds no pointer for the subject, else `If-Match: *`;
  - tests that exercise preconditions keep `publish_if`.
- Modify: `docs/creator-catalogs.md`:
  - "The pointer": `/2`, the `indexHash` rules and the vectors table; `/1` is still served;
  - the `PUT` table gets rows for the `/2` schema 422, the `indexHash` 422, the 428 and the 409;
  - the "for now; … may become a 428" sentence goes;
  - "The index" (`:111-113`) now says the passkey signs it through `indexHash`.
- Test: `src/catalogs_v2_api.rs` tests; `tests/s3_client_test.rs` (`test_create_catalog_index_is_conditional`)

**Interfaces:** Consumes `index_hash`, `POINTER_SCHEMA`, `Pointer.index_hash`. Produces `TagStore::create_catalog_index`.

- [ ] **Step 1: Write the failing tests**:
  - `a_1_publish_is_refused`: a `/1` bundle → `422`, error exactly `invalid bundle: pointer schema must be "arkavo.catalog-pointer/2"`.
  - `the_index_must_match_its_hash`: a `/2` signed over `index()`, sent with a different index → `422 "invalid bundle: indexHash does not match the index"`, with nothing stored.
  - `the_index_hash_is_checked_before_the_payloads`: a mismatching index naming an uningested payload → the `indexHash` 422, not "not ingested".
  - `a_publish_needs_a_precondition`: no `If-Match` or `If-None-Match` → `428 "precondition required"`. An ungated harness (add `harness_ungated()`: `publishing: None`) → also 428.
  - `one_envelope_has_one_index`: publish seq 1 with envelope E and index I. Then seq 2 with the same E, an index J and its own hash, sent with `If-Match: *` → `409 "catalog document already published with another index"`, and the stored index is still I.
  - `a_retry_with_the_same_index_publishes`: the stored index I for E, then a publish of E with I at a higher seq → 200.
  - `a_2_publish_replaces_a_stored_1_pointer`: store a `/1` bundle at seq 3 (`v2::bundle(.., None)`) with an index record. A `/2` at seq 4 with `If-Match: "3"` → 200, and `GET` serves the new `/2` bytes. Before the publish, `GET` serves the `/1`.
  - `test_create_catalog_index_is_conditional` (stand-in): `true`, then `false`.
- [ ] **Step 2: Run** `cargo test --lib catalogs_v2_api && cargo test --test s3_client_test`. Expected: FAIL.
- [ ] **Step 3: Implement** in the positions given by calls 5 and 6. A create that returns `false` reads the record: if absent → 502; if its owner differs, or the canonical hash of its parsed entries differs from the pointer's `indexHash` → 409; otherwise continue.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(catalog): pointer /2 binds the index; publishes need a precondition`

### Task 11: ArkavoKit's vectors (gated on its release tag)

**Files:**
- Modify: `tests/fixtures/arkavo-catalog-vectors.json` (copied verbatim from ArkavoKit's tag: `Tests/ArkavoCatalogTests/Vectors/catalog-vectors.json`)
- Test: `src/catalog_v2.rs`, `src/creator_catalog.rs` tests

**Interfaces:** Consumes `parse_pointer`, `index_hash`, `creator_catalog::test_support::vectors`.

- [ ] **Step 1: Copy the file** from the tag arkavokit-da sends. Don't start until it arrives; PR 2 can be reviewed without it, but it doesn't merge without it.
- [ ] **Step 2: Run** `cargo test arkavo_kit`. Expected: PASS for the pointer kind (`/1` and `/2` validity). If it fails, report the vector to ArkavoKit and don't edit the file.
- [ ] **Step 3: Write the test** `arkavo_kit_index_hash_vectors_agree`. For each index vector carrying an expected `indexHash`, in the file's shape for it: `index_hash(&parse_index(text)) == expected`.
- [ ] **Step 4: Run** `cargo test arkavo_kit`. Expected: PASS.
- [ ] **Step 5: Commit** `test(catalog): ArkavoKit <tag> pointer /2 and indexHash vectors`

---

# PR 3: Deletion (`feat/deletion-sweep`)

### Task 12: Each publish records its transition

**Files:**
- Create: `src/deletion/mod.rs` (with `Transition`, `TransitionBase`, `transition_name`, `GRACE`, `VERIFY_AFTER`; `pub mod deletion;` in lib.rs)
- Modify: `src/catalogs_v2_api.rs`:
  - step 7 reads and parses the base's index record, and verifies a `/2` base against its `indexHash` (call 7);
  - the transition is written after the 412 and 409 checks and before the document (call 8).
- Modify: `src/tags_api.rs` (`TagStore::put_catalog_transition`; MemStore `transitions: Mutex<BTreeMap<String, Bytes>>` keyed `"<sub>/<name>"`, with `fail_next_transition: AtomicBool`)
- Modify: `src/store/s3.rs` (`catalog_transition_key`, `put_catalog_transition`)
- Modify: `docs/creator-catalogs.md` (the step 8 paragraph names the transition)
- Test: `src/catalogs_v2_api.rs` tests

**Interfaces:**
- Consumes `index_hash`, `stored_pointer`, `look_up`, `is_blocked`, `owner_hidden`, `get_blob_owner`, `parse_owner`.
- Produces `Transition` (`#[serde(rename_all = "camelCase", deny_unknown_fields)]`) and `TagStore::put_catalog_transition`.

- [ ] **Step 1: Write the failing tests**:
  - `the_first_publish_records_every_hash_as_added`: the key is `"<SUB>/00000000000000000001-<sha256 hex of pointer bytes>"`, with `base == None`, `dropped == []` and `added == [payload(1)]`.
  - `a_hide_records_the_dropped_recording`: publish `[p1, p2]`, then `[p1]` → `dropped == [p2]`, `added == []`, and `base` = `{seq 1, catalogHash, pointer digest}`.
  - `a_blocked_recording_is_not_dropped`: `p2` blocked after seq 1, then seq 2 drops it → `dropped == []`.
  - `a_recording_the_publisher_does_not_own_is_not_dropped`: the owner record of `p2` is replaced with `u2` before seq 2 → `dropped == []`.
  - `nothing_is_dropped_from_a_base_that_is_not_served`: the base envelope is blocked, or the subject has a catalog block, or the subject is suspended with `hideCatalog` → `dropped == []`. In each case `added` is still computed against the base's index.
  - `a_failed_transition_write_stores_nothing`: `fail_next_transition` → `502 "storage unavailable"`, and no new document, index or pointer.
  - `a_retry_after_a_commit_keeps_the_committed_transition`: publish seq 2 through `publish_if` with `If-Match: "1"`, record the transition body, then resend the identical request → 412, and the transition body is unchanged.
  - `a_2_base_with_a_tampered_index_is_502`: overwrite the stored index record of a `/2` base with other entries → the next publish gets `502 "storage unavailable"`.
  - `a_publish_over_a_1_base_records_its_digest`: with a stored `/1` base, `base.pointer` is the SHA-256 of the `/1` pointer bytes.
- [ ] **Step 2: Run** `cargo test --lib catalogs_v2_api`. Expected: FAIL.
- [ ] **Step 3: Implement** the spec's 3.1 rules:
  - `served` = live && !blocked(base) && !owner_hidden(sub);
  - `dropped` = (served ? base − new : ∅) − blocked-now − not-owned-by-publisher (canonical, via `look_up`; unreadable → 502);
  - `added` = new − base live index;
  - both sorted; `at = now_secs()`.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(deletion): record a transition per publish`

### Task 13: Request records and the strict snapshot

**Files:**
- Modify: `src/deletion/mod.rs` (record types, enums, key functions)
- Create: `src/deletion/snapshot.rs`
- Test: unit tests in both

**Interfaces:**
- Consumes `ObjectStore`, `catalog_scan::scan`, `parse_owner`, `moderation::{Suspension, Block, CatalogBlock}`.
- Produces `Snapshot`, `Requests`, `ModerationView`, `read`.
- `read` lists and parses: `catalog-transitions/`, `deletion-requests/{recordings,envelopes,operator,subjects}/`, `moderation/{suspensions,blocks,catalog-blocks,publishers}/`, and the keys (only) under `catalog-documents/`, `catalog-outboards/` and `catalog-indexes/`.
- Active means `lifted_at.is_none()`.

- [ ] **Step 1: Write the failing tests**:
  - `records_round_trip_in_the_spec_shape`: `serde_json::to_value(RecordingRequest{..pending..})` has exactly the keys `hash, subject, requestedAt, seq, state` with `"state":"pending"`, and `deletedAt` is present only when set. The same holds for the other three records.
  - `an_unknown_field_is_unreadable`.
  - `read_builds_the_view`: a lifted block isn't in `blocked`. A `hideCatalog` suspension is in `hidden`, not in `catalog_blocked`. A catalog block is in both.
  - `read_aborts_on_anything_unreadable`: one garbage object at a time, in each of transitions, the four request kinds, suspensions, blocks, catalog blocks, owner records and pointers → `Err` naming the key.
  - `read_does_not_read_sessions_or_audit`: garbage under `moderation/sessions/` and `moderation/audit/` → Ok.
  - `a_request_key_must_match_its_body`: `recordings/u1/<h>` whose body says `u2` → `Err`.
- [ ] **Step 2: Run** `cargo test --lib deletion::`. Expected: FAIL.
- [ ] **Step 3: Implement.** Subjects in request keys must already be canonical; a non-canonical key is unreadable.
- [ ] **Step 4: Run** `cargo test --lib deletion::`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(deletion): request records and the strict snapshot`

### Task 14: Folding committed transitions

**Files:**
- Create: `src/deletion/fold.rs`
- Test: unit tests (pure, building `Snapshot` values directly)

**Interfaces:** Consumes `Snapshot`, `Transition`, `GRACE`. Produces `fold`, `Fold`.

- [ ] **Step 1: Write the failing tests**:
  - `a_chain_is_folded_oldest_first`: t1 (add p1), t2 (drop p1, at 200), t3 (add p1) reachable from the pointer → no pending `p1`, and `folded == [t1, t2, t3]`.
  - `the_newest_drop_wins`: drops at 100 and 300 with an add between → pending with `requested_at == 300` and `seq` of the second drop.
  - `requests_are_keyed_canonically`: a transition under `arkavo:<uuid>` → `recordings` key `(<uuid>, p)`.
  - `a_superseded_envelope_becomes_pending`: `base.catalogHash != catalogHash` → `envelopes[base]` pending with `superseded_at == at`, `source == Transition` and `owner == Some(subject)`.
  - `the_walk_stops_at_a_missing_transition`: t2 and t3 present, t1 missing → folds t2 and t3 only.
  - `refolding_is_idempotent`: a `deleted` record with `deleted_at == 500` and a re-folded drop at 200 → still `deleted`; a drop at 600 → pending.
  - `an_add_does_not_cancel_a_tombstone`.
  - `a_lost_transition_is_deleted_after_grace`: unreachable, `at + GRACE <= now`, current seq ≥ its seq → in `lost`.
  - `an_unreachable_transition_is_kept_otherwise`: younger than `GRACE`, or seq above the current pointer's, or no pointer → in `kept`.
- [ ] **Step 2: Run** `cargo test --lib deletion::fold`. Expected: FAIL.
- [ ] **Step 3: Implement** the walk:
  - start at `transition_name(p.seq, &p.digest)` under `p.key`;
  - follow `base` to `transition_name(base.seq, &base.pointer)`;
  - stop when the transition is missing, or after `catalogs.pointers.len() + transitions.len()` steps, which guards against cycles.
  Apply oldest first under call 9.
- [ ] **Step 4: Run** `cargo test --lib deletion::fold`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(deletion): fold committed transitions into requests`

### Task 15: What is due

**Files:**
- Create: `src/deletion/due.rs`
- Test: unit tests (pure)

**Interfaces:** Consumes `Snapshot`, `Requests`, `ModerationView`, `GRACE`. Produces `view`, `observe`, `due`, `Item`, `Decision`.

- [ ] **Step 1: Write the failing tests** (3.4 steps 3–5):
  - `s_holds_every_pointer_of_a_subject_being_deleted`: `subjects/<uuid>` pending, a catalog block active, pointers `arkavo:<uuid>` and `<uuid>` → both in `s`, and their hashes not in `l` or `c`. With the block lifted → `s` is empty.
  - `l_counts_hidden_catalogs`: a pointer whose owner is catalog-blocked (not in S) still adds its hashes to `l`.
  - `untracked_envelopes_are_observed`: a hash under `catalog-outboards/` only, not in `c` and with no record → one `EnvelopeRequest` with `source == Observed` and `superseded_at == now`. One in `c` isn't observed.
  - `a_dropped_recording_is_due_after_grace`. Pending at `requested_at = now - GRACE` → due. These are kept, with reasons: one second earlier; a hash in `l`; a blocked hash; the owner record naming `u2` ("owner is not the requester"); no owner record.
  - `one_item_per_recording`: `recordings/u1/h` and `operator/u1/h` both due → one `Item::Recording` naming both request keys.
  - `operator_hash_scope_needs_only_its_block`: block active → due at once, even in `l`. Block lifted → kept.
  - `operator_subject_scope_needs_the_catalog_block`: due when the catalog block is active, `h ∉ l` and the owner names the subject. With the block lifted → kept and reported ("catalog block lifted").
  - `a_subject_is_due_while_its_catalog_block_stands`.
  - `an_envelope_is_due_after_grace`. Pending past `GRACE`, not in `c`, not blocked, owner not hidden → due. Kept: owner hidden (catalog block or `hideCatalog`). Due: owner hidden but with a pending `subjects/` request. Kept: no owner known ("unknown owner").
- [ ] **Step 2: Run** `cargo test --lib deletion::due`. Expected: FAIL.
- [ ] **Step 3: Implement.** An envelope's owner is `EnvelopeRequest.owner`, else the index record's `owner` from `catalogs.indexes`. The document's `x-amz-meta-owner` is read by the sweep (Task 16) and passed in through `EnvelopeRequest.owner` when observed.
- [ ] **Step 4: Run** `cargo test --lib deletion::due`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(deletion): decide what is due`

### Task 16: `sweep-deletions`: delete with a re-check

**Files:**
- Create: `src/deletion/sweep.rs`
- Modify: `src/main.rs` (`SweepDeletions { #[arg(long)] delete: bool }`; prints `Report`, exits `1` on `Err` or `failures > 0`)
- Test: unit tests on `MemObjects`

**Interfaces:**
- Consumes `read`, `fold`, `view`, `observe`, `due`, `ObjectStore`.
- Produces `sweep`, `Report`.
- Order: read → fold (write requests, delete cancelled, delete folded transitions oldest first, delete lost ones) → observe (`head_owner` on `catalog-documents/<h>` fills `owner`) → due → delete each item → verify (Task 17) → report.
- With `delete == false`, the run writes and deletes nothing, and the report says `would delete`.

- [ ] **Step 1: Write the failing tests**:
  - `a_dry_run_changes_nothing`: one due recording; `sweep(store, false, now)` → the line `would delete recording <h>`, and every object and version is unchanged (compare `list_versions("")` before and after).
  - `a_due_recording_loses_every_version_in_order`: `blobs/h` (2 versions), `outboards/h`, `manifests/h` and `moderation/publishers/h` → all gone, with the delete order recorded by MemObjects being `blobs`, `outboards`, `manifests`, `publishers`. The request is `deleted` with `deleted_at == now`.
  - `a_due_envelope_is_deleted`: `catalog-documents/h`, `catalog-outboards/h` and `catalog-indexes/h` are gone and `envelopes/h` is `deleted`.
  - `a_due_subject_loses_its_pointers`: both pointer keys are deleted and `subjects/<uuid>` is `deleted`.
  - `a_relisted_recording_is_dropped_at_the_recheck`: inject, between `due` and the delete (via a MemObjects hook `on_before_delete(key, fn)`), another pointer listing `h` → `kept <h>: listed again`, nothing deleted.
  - `a_moved_pointer_defers_the_item`: the hook advances the requester's pointer → `deferred <h>: catalog changed`, nothing deleted, the request still pending.
  - `a_failed_delete_leaves_the_item_pending`: `fail_on("outboards/h", Delete)` → `failures == 1`, the request still `pending`, and the run continues to the next item.
  - `an_unreadable_record_aborts_before_any_write`: garbage under `deletion-requests/` → `Err`, with the version listing unchanged.
  - `transitions_are_deleted_only_after_their_requests_are_written`: `fail_on(recording_key(..), Put)` → `Err`/failure, and the transition still exists.
- [ ] **Step 2: Run** `cargo test --lib deletion::sweep`. Expected: FAIL.
- [ ] **Step 3: Implement** the re-check before each item:
  - re-read its request records (gone or no longer pending → drop);
  - re-read the moderation records it depends on (block, catalog block, suspension, owner record);
  - re-run `scan` → recompute `l`/`c` with `view` → drop when the due rule no longer holds;
  - defer when the requester's pointer `(seq, catalog_hash)` differs from the snapshot.
  Report lines: `deleted <kind> <id>`, `would delete <kind> <id>`, `kept <id>: <why>`, `deferred <id>: catalog changed`, `failed <id>: <error>`, then `N deleted, N kept, N deferred, N failed`. The report also lists any deleted recording now in `l` and any deleted envelope now in `c`.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(deletion): sweep-deletions`

### Task 17: Verifying tombstones

**Files:**
- Modify: `src/deletion/sweep.rs` (`verify` step)
- Test: unit tests on `MemObjects`

**Interfaces:** Consumes `VERIFY_AFTER`, `ObjectStore::list_versions`, and the re-check from Task 16.

- [ ] **Step 1: Write the failing tests** (a `deleted` recording tombstone, `deleted_at = 1000`, `now = 1000 + VERIFY_AFTER`):
  - `a_clean_tombstone_is_removed`: no versions of any item key → the tombstone is gone (every version) and the line reads `verified <h>`.
  - `a_fresh_push_keeps_everything`: `blobs/h` written at `1000 + VERIFY_AFTER + 1` (`set_now`) → the tombstone is removed, the blob kept, the line reads `fresh <h>`.
  - `a_relisted_recording_keeps_its_objects`: `h` in `l` → the tombstone is removed and the objects kept.
  - `a_late_write_is_deleted_again`: `outboards/h` written at `1000 + 10` → deleted, `recreated <h>` reported, the tombstone kept.
  - `a_young_tombstone_waits`: `now = 1000 + VERIFY_AFTER - 1` → untouched.
  - `envelope_and_subject_tombstones_verify_the_same_way`: one case each. For a subject, a new pointer written after `deleted_at + VERIFY_AFTER` counts as fresh.
- [ ] **Step 2: Run** `cargo test --lib deletion::sweep::verify`. Expected: FAIL.
- [ ] **Step 3: Implement** 3.4 step 7 in the spec's order. Only non-delete-marker versions count as objects. With `delete == false`, report what would happen and change nothing.
- [ ] **Step 4: Run** `cargo test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(deletion): verify tombstones before forgetting them`

### Task 18: `request-deletion`, docs and the switch

**Files:**
- Create: `src/deletion/operator.rs`
- Modify: `src/main.rs`: `RequestDeletion { #[arg(long)] subject: String, #[arg(long, num_args = 1.., conflicts_with = "all")] hash: Vec<String>, #[arg(long)] all: bool, #[arg(long)] reason: String }`. Exactly one of `--hash` and `--all` is required.
- Modify: `docs/creator-catalogs.md`:
  - "Publishing a recording" (`:174`): the stored TDF is deleted 7 to 30 days after the publish that dropped it; re-listing within 7 days cancels; after deletion, re-listing needs a fresh push; a replaced payload is deleted the same way; a superseded envelope is deleted 7 to 30 days after it was replaced;
  - account deletion: publish an empty catalog first.
- Modify: `docs/publishing-and-moderation.md` (`## Deletion requests (operators)`):
  - the four commands, with the weekly sweep;
  - the decision-6 procedure for creators who can't publish;
  - the moderation exception;
  - IAM for the instance (`s3:PutObject` on `catalog-transitions/*`) and for operators (`ListBucket`, `ListBucketVersions`, `GetObject`, `PutObject`, `DeleteObject`, `DeleteObjectVersion`);
  - the lifecycle rule (`NoncurrentVersionExpiration` 7 days + `ExpiredObjectDeleteMarker`, keeping the `moderation/sessions/` rule);
  - the switch-day order from the spec's rollout, including the ignored `s3_versioned_test` run against a scratch versioned bucket in step 3.
- Modify: `CLAUDE.md`: the key layout gains `catalog-transitions/<sub>/…` and `deletion-requests/…`; Key Modules gains `deletion/`; Build & Test gains `cargo test --test s3_versioned_test -- --ignored` with its env vars.
- Test: `src/deletion/operator.rs` unit tests

**Interfaces:** Consumes `ObjectStore`, `snapshot::read` (for blocks, catalog blocks, catalogs and owners), and the record types.

- [ ] **Step 1: Write the failing tests**:
  - `hash_requests_need_an_active_block`: one of two hashes unblocked → `Err` naming it, nothing written. Both blocked → two `operator/<sub>/<h>` records with `scope == Hash`.
  - `all_needs_an_active_catalog_block`: no block → `Err`, nothing written.
  - `all_covers_live_indexes_and_owner_records`: pointers `arkavo:<uuid>` and `<uuid>`, plus an owner record for an unlisted `h3` → scope-`Subject` requests for every hash, then `subjects/<uuid>` written last. The returned keys list all of them.
  - `subjects_in_keys_are_canonical`: `--subject arkavo:<uuid>` writes under `<uuid>`.
- [ ] **Step 2: Run** `cargo test --lib deletion::operator`. Expected: FAIL.
- [ ] **Step 3: Implement.** In `main.rs`, print each written key with the reason, then the closing line `coverage: live indexes and owner records; add --hash for anything else`.
- [ ] **Step 4: Run** `cargo fmt && cargo clippy --all-targets && cargo test`, then `cargo run -- --help`. Expected: clean, PASS, with four new subcommands listed.
- [ ] **Step 5: Commit** `feat(deletion): request-deletion; docs for ownership, pointer /2 and deletion`

### Final check (each PR, and the stack before the switch)

- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` on each branch.
- [ ] Grep the docs and code for every string in the spec's contract table. Each appears exactly as written.
- [ ] `TDF_IROH_S3_VERSIONED_BUCKET=<scratch> cargo test --test s3_versioned_test -- --ignored` passes against a real versioned bucket (Paul or an operator, rollout step 3).
