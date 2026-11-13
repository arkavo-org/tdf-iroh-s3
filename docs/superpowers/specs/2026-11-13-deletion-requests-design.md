# Deleting published recordings on request

**Status:** proposal, 2026-11-13. Must ship before Creator 2.0. Two decisions pending (marked **Pending**).
**Scope:** tdf-iroh-s3. Creator's side (Hide copy, empty catalog before account deletion) is built in Creator.
**Read at:** tdf-iroh-s3 `02caef2`.

## Why

Arkavo's privacy policy will promise that a published recording is deleted from Arkavo's servers within 30 days of the creator's request, backups and old object versions included ("30 days flat"). Deleting an Arkavo account deletes that account's published recordings within the same 30 days. The creator's passkey is the proof of the request; there is no email step.

Today the node never deletes anything a creator published. Hiding a recording republishes the catalog without its entry, and "the TDF stays on the node" (`docs/creator-catalogs.md`). A moderation block stops distribution and leaves the bytes. `S3Client::delete_blob` exists and has no caller.

## Decisions already made (Paul)

- **Mechanism (c):** Hide from Catalog *is* the deletion request. The node records it at the passkey-signed publish; an operator-run sweep deletes after a grace period. No new client route.
- **Account deletion:** before `DELETE /account`, Creator publishes an empty catalog (index `[]`), which records a request for every listed recording. If that publish fails, Creator stops and offers Try Again or Delete Anyway. On a 404 pointer Creator skips the publish.
- **Exceptions in the policy:** only the 90-day service logs. A recording the creator asks to delete is deleted even when it is under report or blocked. (See **Pending B** for drops a block forces.)
- **Creators who can't publish** (entitlement lapsed, suspended, PDP denies, catalog blocked): handled manually by an operator.
- **The sweep deletes every S3 version** of each object, so deletion is permanent when the sweep runs.

## Goals

- A recording the creator dropped from their catalog (Hide, a replaced payload, an empty catalog) is gone from S3, every version, within 30 days of the publish that dropped it.
- Superseded catalog envelopes (which carry each entry's metadata TDF, including titles) are gone within the same budget, and no earlier than 7 days after being superseded.
- The 30-day clock starts at a time the node recorded from a passkey-signed publish.
- A creator can undo a Hide by publishing the entry again during the grace period.
- An operator can carry out a deletion for a creator who can't publish.

## Non-goals

- Deleting the catalog pointer or the current (possibly empty) envelope when a creator deletes their account through Creator. Nothing tells the node an account was deleted. Known gap, accepted.
- Recordings pushed but never listed in a catalog, outside the operator path. Leftovers of removed features other than envelopes (`/1` tags, `catalog-index/`, `campaign-creators/`).
- A scheduled, automatic sweep. The operator runs it (at least weekly, see Timing).
- Copies outside the node: what viewers or other iroh peers already fetched, the KAS, identity, CloudWatch logs.

## Anti-goals

- **Never delete a recording nobody asked to delete.** No rule of the form "not listed in any catalog ⇒ delete" for recordings. A creator whose pointer predates envelopes has no index record (`catalogs_v2_api.rs:420`), so every one of their recordings is listed nowhere, and such a rule would delete them all.
- **Never delete on an uncertain view.** Any error reading pointers, indexes, moderation records or requests aborts the sweep before it deletes anything.
- **Never resurrect what was deleted.** Delete order must not let the node's outboard backfill recreate an object.

## Facts the design rests on

- `put_catalog` already reads the stored pointer and its index record before writing (`catalogs_v2_api.rs:411-433`); the previous index's entries are available to diff. Its `live` flag ignores blocks; `served_seq` (`:437-440`) is what `GET` would serve, minus the owner's catalog hide.
- `GET /v2/catalogs/{sub}` answers 404 for a blocked envelope, for an owner with a catalog block or a `hideCatalog` suspension, and for a pre-envelope pointer. A 404 does not mean the pointer is absent.
- `check_payloads` has no ownership check: any subject whose envelope attribute the recording's manifest names may list it (`catalogs_api.rs:65`). It refuses blocked hashes first (403 `content is blocked`, `:70`), then HEADs `blobs/<hash>` (422 `payload <hash> is not ingested`).
- `moderation/publishers/<hash>` is last-pusher-wins, rewritten on every ingested push (`node.rs:293`, written at `:363`), with the pusher's subject.
- Catalog blocks are keyed by canonical subject (`moderation.rs:1360`); pointers by the token's `sub` byte for byte, so one account can have `catalog-pointers/<uuid>` and `catalog-pointers/arkavo:<uuid>`.
- `S3Server` recomputes and stores a missing outboard for a blob or envelope that exists (`s3_serve.rs:318-321`). Deleting the outboard before the object can bring it back.
- After a blob is deleted, a running node's cached size gives one fetch "try again" (`ERR_LIMIT`), then "gone" (`Permission`).
- Blobs are uploaded with a single `PutObject` (`store/s3.rs:141`), never multipart.
- Moderation history is append-only under `moderation/audit/<kind>/<key>/<nanos>`; nothing reads old S3 versions.
- `/1` documents were stored under `catalog-documents/` (c48ec9d).
- Production bucket (checked 2026-11-13): versioned; no replication, no Object Lock, no AWS Backup plans or recovery points; only lifecycle rule is the 1-day rule on `moderation/sessions/`. So today a delete by key leaves the bytes forever as a noncurrent version.

## Approaches considered

| | Trigger | Cost | Picked |
|---|---|---|---|
| (a) | Hide is the request; a sweep deletes whatever no catalog lists | No node route; but no request time to start the clock, and "unlisted" sweeps pre-envelope creators' recordings and in-flight pushes | No |
| (b) | A passkey-signed `DELETE` route Creator calls | New signed message format, replay protection, contract section, Creator UI; still needs the same sweep | No |
| (c) | Hide is the request, **recorded by the node at publish**; the sweep acts only on recorded requests | A diff in `put_catalog`, a record prefix, two subcommands | **Yes** |

Every option needs a sweep (superseded envelopes, account deletion); the choice is only the trigger. (c) keeps the client unchanged, gives each request a time and a passkey-signed origin, and never infers a recording deletion. Its cost: any entry Creator drops becomes a deletion, a Creator bug included. The grace period is the undo.

## Design

### 1. Deletion requests

Records in S3 under `{prefix}deletion-requests/`. Publish and operator requests use separate keys, so neither overwrites the other.

| Key | Written by | Body |
|---|---|---|
| `recordings/<hash>` | publish | `{"hash", "subject", "requestedAt", "seq"}` |
| `catalogs/<hash>` | publish | `{"hash", "subject", "requestedAt", "seq"}` (a superseded envelope) |
| `operator/<hash>` | `request-deletion` | `{"hash", "subject", "requestedAt", "reason", "scope": "hash" \| "subject"}` |
| `subjects/<canonical sub>` | `request-deletion --all` | `{"subject", "requestedAt", "reason"}` |

`requestedAt` is Unix seconds. A new publish request for the same hash overwrites the old one: the latest drop is the request in force (hide on day 0, re-list on day 3, hide on day 5 ⇒ the clock starts on day 5).

### 2. Requests at publish (`PUT /v2/catalogs/{sub}`)

After the precondition and `seq` checks (step 7) and before any write (step 8):

- **Diff base: the catalog `GET` would serve.** The stored pointer counts only if it is live (has an index record), its envelope is not blocked, and its owner has no catalog block or `hideCatalog` suspension. Otherwise there is nothing to diff and no request is written. This keeps a moderation block on a creator's envelope from turning into a deletion of every recording it listed when the creator next publishes over the 404.
- Parse the base's stored index. A stored index that doesn't parse fails the publish: 502 `storage unavailable`, logged as an error.
- `dropped` = payload hashes in the base index − payload hashes in the new index. This covers Hide, an entry whose payload was replaced (the old payload is no longer published), and an empty catalog. **Pending B** decides whether a dropped hash that is blocked at publish time counts.
- Write a `recordings/` request for each dropped hash, and a `catalogs/` request for the base's `catalogHash` (it is being superseded), each with the subject, now and the new pointer's `seq`. If any write fails, the publish fails with 502 `storage unavailable` and nothing else is written.

Requests are written before the pointer, so a committed publish always has its requests. If the pointer write then loses (409) or fails, the requests remain for objects that are still listed or current; the sweep skips those, so they're harmless, and a later drop overwrites them.

Any lister's drop counts, whoever pushed the recording: the sweep's check that no served catalog lists the hash protects every other lister.

The response and the contract's status codes are unchanged (502 `storage unavailable` already exists).

### 3. Operator requests: `tdf-iroh-s3 request-deletion`

For a creator who can't publish. Runs with operator AWS credentials and the node's config file. The operator places the block first through the existing moderation API; verifying the creator's identity for a manual request is the operator's process, outside the node.

```
tdf-iroh-s3 --config <path> request-deletion --subject <sub> --reason <text> --hash <h> [--hash <h> ...]
tdf-iroh-s3 --config <path> request-deletion --subject <sub> --reason <text> --all
```

- `--reason` is required (e.g. a support ticket reference). `--subject` is compared canonically (`canonical_subject`).
- `--hash`: each hash must have an active block (`moderation/blocks/<hash>`), else the command refuses and writes nothing. Writes `operator/<hash>` with `scope: "hash"`.
- `--all`: the subject must have an active catalog block (`moderation/catalog-blocks/<sub>`), else it refuses. Writes `operator/<hash>` with `scope: "subject"` for every payload hash in the live index of each pointer whose key is canonically the subject, and for every hash whose `moderation/publishers/<hash>` names the subject canonically (covers pre-envelope creators and never-listed pushes). Writes `subjects/<sub>`, which deletes those pointers (§4).
- It prints what it wrote.

### 4. The sweep: `tdf-iroh-s3 sweep-deletions`

```
tdf-iroh-s3 --config <path> sweep-deletions            # dry run: report only
tdf-iroh-s3 --config <path> sweep-deletions --delete
```

Same pattern as the removed `purge-catalogs-1` (c48ec9d): a subcommand of the node binary, dry run unless `--delete`. Grace is a constant, `GRACE = 7 days`, not a flag: the contract promises creators the 7-day undo.

**Snapshot.** Read every pointer under `catalog-pointers/`, its index record, and the moderation records (blocks, catalog blocks, suspensions).
- `S` = pointers to delete this run: those whose key is canonically a subject with a due `subjects/` request (rule S).
- `L` = every payload hash in every **served** catalog: pointer not in `S`, live, envelope not blocked, owner without a catalog block or `hideCatalog` suspension.
- `C` = every `catalogHash` named by a pointer not in `S`, in any state.
- Any listing, read or parse error aborts the run, nonzero exit, nothing deleted.

**What is due.**
- **Rule R (recordings).** Hash `h` is due when either request for it is due:
  - `recordings/h`: `requestedAt + GRACE ≤ now` and `h ∉ L`.
  - `operator/h`, scope `hash`: `h`'s block is still active. No grace, no `L` check (the operator decided; the block already stops all distribution).
  - `operator/h`, scope `subject`: the subject's catalog block is still active, and `h ∉ L` (another creator's served catalog still lists it).
- **Rule S (subjects).** `subjects/s` is due while `s`'s catalog block is still active.
- **Rule C (envelopes).** Enumerate hashes under `catalog-documents/`, `catalog-outboards/` and `catalog-indexes/` (so a partial earlier failure is retried). `h` is due when `h ∉ C` and:
  - a `catalogs/h` request exists and `requestedAt + GRACE ≤ now`; or
  - no request exists and the newest `LastModified` of its objects `+ GRACE ≤ now` (envelopes superseded before this ships, envelopes stored by a publish whose pointer write lost, non-current `/1` documents).
  - **Pending B** decides whether a blocked envelope is kept.
- A request whose gate (block, catalog block) was lifted, or a record that doesn't parse, is skipped and reported.

**Re-check.** Take the snapshot again (same `S`). Drop any rule-R candidate that is now in `L` and needs the `L` check, and any envelope now in `C`.

**Delete** (with `--delete`): every version and delete marker of each key.
- Recording `h`: `blobs/h`, then `outboards/h`, `manifests/h`, `moderation/publishers/h`, then `recordings/h` and `operator/h`.
- Subject `s`: each pointer in `S` for `s`, then `subjects/s`. Its envelopes then fall to rule C (already excluded from `C`).
- Envelope `h`: `catalog-documents/h`, then `catalog-outboards/h`, `catalog-indexes/h`, then `catalogs/h`.
- A failure stops that item: its requests stay for the next run. The run continues with other items and exits nonzero.
- Block, suspension, catalog-block and audit records are kept.

**After.** For each deleted recording or envelope, check `outboards/h` or `catalog-outboards/h` again; if a node's backfill recreated it, delete its versions again. Take the snapshot once more; a deleted hash now in `L` is reported as "re-listed during the sweep: the creator must push it again".

**Report.** One line per item (`deleted` / `would delete` / `kept: <why>`), then counts. Stdout only; the node keeps no deletion log.

### 5. Timing

- With version deletion and no backups, an item is gone at the first sweep after it falls due: `requestedAt + 7 days` for creator requests. A weekly sweep makes the worst case about 14 days, inside 30.
- The operator runbook schedules the sweep weekly. The 30-day promise depends on it running.

### 6. Operations (outside the code)

- **Lifecycle rule** (devsecops' proposal, Paul applies): bucket-wide `NoncurrentVersionExpiration` 7 days and `ExpiredObjectDeleteMarker`; keep the `moderation/sessions/` rule. Needed because overwrites keep old versions forever: old catalog pointers (naming old envelopes and credential IDs), manifests, publisher records. (`AbortIncompleteMultipartUpload` is harmless; the node never uses multipart.)
- **Instance role:** `s3:PutObject` on `deletion-requests/*` if the role is prefix-scoped.
- **Operator credentials:** `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`.

### 7. Documentation

- `docs/creator-catalogs.md` (the contract): Hide/removal (line 174) now deletes the stored TDF at least 7 and at most 30 days after the publish; re-listing within 7 days cancels; after deletion, re-listing needs a fresh push. A replaced payload is deleted the same way. A superseded envelope is deleted 7 to 30 days after it was superseded (`GET /catalog-documents/<old>` then 404, iroh fetch gone). Account deletion: publish an empty catalog first.
- `docs/publishing-and-moderation.md`: replace "Not included: deleting stored bytes" with deletion requests, the two subcommands, the manual procedure for creators who can't publish, IAM and the lifecycle rule. The block record outlives the bytes.
- `CLAUDE.md`: key layout (`deletion-requests/`), the new module, Hide semantics.

## Known gaps (accepted)

- After account deletion through Creator, the pointer and the empty envelope stay (no signal reaches the node).
- A creator whose catalog `GET` answers 404 (pre-envelope pointer, blocked envelope, catalog block, `hideCatalog`) gets no requests from an empty-catalog publish; Creator skips it on 404. These go through the operator path on request.
- A catalog-blocked creator who isn't suspended gets 412 on `If-None-Match: *`, because `PUT`'s preconditions ignore the owner's catalog hide while `GET` honours it. Pre-existing, separate fix.
- Hiding a recording from a Mac without its archive can be undone only within the 7 days.
- A publish that re-lists a hash in the seconds between the sweep's re-check and its delete leaves a listed recording that answers "gone"; the sweep reports it.

## Pending (Paul)

- **A. Hides before this ships.** Drops before this ships have no request, and rule C's first deleting run removes the superseded indexes, the only record of what each creator once listed. Either the promise covers only requests from 2.0 on (nothing to do), or a one-time backfill before the first deleting sweep writes `recordings/` requests for every hash in a superseded index that no served catalog lists.
- **B. Drops a block forces.** `check_payloads` refuses any publish that lists a blocked hash, so after a takedown the creator must drop it to publish again. Either such a drop is a request (every takedown's bytes are gone 7–14 days after the creator's next publish), or §2 skips hashes blocked at publish time and rule C keeps blocked envelopes (the bytes stay until an operator deletes them; the policy then needs a moderation exception).

## Left to the builder

- Module layout (suggested: `src/deletion.rs` for request records, the diff and the sweep's pure decisions, behind a small store trait with an S3 implementation and an in-memory one for tests).
- How `TagStore` grows to write requests (`MemStore` must implement it).
- Concurrency limits for request writes and deletions.
- The report's exact wording.
- How to test version listing and batch deletion against S3 (extend the in-test S3 stand-in in `tests/s3_client_test.rs`, or test through the trait).
