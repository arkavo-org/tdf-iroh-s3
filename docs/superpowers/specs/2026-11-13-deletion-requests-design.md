# Deleting published recordings on request

**Status:** proposal, 2026-11-13. Must ship before Creator 2.0.
**Scope:** tdf-iroh-s3. Creator's side (Hide copy, empty catalog before account deletion) is built in Creator.
**Read at:** tdf-iroh-s3 `02caef2`.

## Why

Arkavo's privacy policy will promise that a published recording is deleted from Arkavo's servers within 30 days of the creator's request, backups and old object versions included ("30 days flat"). Deleting an Arkavo account deletes that account's published recordings within the same 30 days. The creator's passkey is the proof of the request; there is no email step.

Today the node never deletes anything a creator published. Hiding a recording republishes the catalog without its entry, and "the TDF stays on the node" (`docs/creator-catalogs.md`). A moderation block stops distribution and leaves the bytes. `S3Client::delete_blob` exists and has no caller.

## Decisions already made

- **Mechanism (c):** Hide from Catalog *is* the deletion request. The node records it at the passkey-signed publish; an operator-run sweep deletes after a grace period. No new client route.
- **Account deletion:** before `DELETE /account`, Creator publishes an empty catalog (index `[]`), which records a request for every listed recording. If that publish fails, Creator stops and offers Try Again or Delete Anyway. On a 404 pointer Creator skips the publish.
- **Exceptions in the policy:** only the 90-day service logs. No carve-out for reported, blocked or legally held recordings: a requested deletion proceeds even when the recording is under report or blocked.
- **Creators who can't publish** (entitlement lapsed, suspended, PDP denies): handled manually by an operator.
- **The sweep deletes every S3 version** of each object, so deletion is permanent when the sweep runs.

## Goals

- A recording the creator dropped from their catalog (Hide, a replaced payload, an empty catalog) is gone from S3, every version, within 30 days of the publish that dropped it.
- Superseded catalog envelopes (which carry each entry's metadata TDF, including titles) are gone within the same budget.
- The 30-day clock starts at a time the node recorded from a passkey-signed publish.
- A creator can undo a Hide by publishing the entry again during the grace period.
- An operator can carry out a deletion for a creator who can't publish.

## Non-goals

- Deleting the catalog pointer or the current (possibly empty) envelope when a creator deletes their account through Creator. Nothing tells the node an account was deleted. Known gap, accepted.
- Recordings pushed but never listed in a catalog, and leftovers of removed features (`/1` documents and tags, `catalog-index/`, `campaign-creators/`). Separate clean-up, not driven by a creator's request.
- A scheduled, automatic sweep. The operator runs it (at least weekly, see Timing).
- Copies outside the node: what viewers or other iroh peers already fetched, the KAS, identity, CloudWatch logs.

## Anti-goals

- **Never delete a recording nobody asked to delete.** No rule of the form "not listed in any catalog ⇒ delete" for recordings. A creator whose pointer predates envelopes has no index record (`catalogs_v2_api.rs:420`), so every one of their recordings is listed nowhere, and such a rule would delete them all.
- **Never delete on an uncertain view.** Any error reading pointers, indexes or requests aborts the sweep before it deletes anything.
- **Never resurrect what was deleted.** Delete order must not let the node's outboard backfill recreate an object.

## Facts the design rests on

- `put_catalog` already reads the stored pointer and its index record before writing (`catalogs_v2_api.rs:411-433`); the previous index's entries are available to diff.
- `check_payloads` has no ownership check: any subject whose envelope attribute the recording's manifest names may list it (`catalogs_api.rs:65`). Whether a hash is still listed must be checked across **every** subject's current catalog.
- `moderation/publishers/<hash>` is last-pusher-wins, rewritten on every ingested push (`node.rs:293`).
- `check_payloads` HEADs `blobs/<hash>` first: once the blob is gone, a publish naming it gets 422 `payload <hash> is not ingested`.
- `S3Server` recomputes and stores a missing outboard for a blob that exists (`s3_serve.rs`). Deleting the outboard before the blob can bring it back.
- After a blob is deleted, a running node's cached size gives one fetch "try again" (`ERR_LIMIT`), then "gone" (`Permission`).
- Moderation history is append-only under `moderation/audit/<kind>/<key>/<nanos>`; nothing reads old S3 versions.
- Production bucket (checked 2026-11-13): versioned; no replication, no Object Lock, no AWS Backup plans or recovery points; only lifecycle rule is the 1-day rule on `moderation/sessions/`. So today a delete by key leaves the bytes forever as a noncurrent version.

## Approaches considered

| | Trigger | Cost | Picked |
|---|---|---|---|
| (a) | Hide is the request; a sweep deletes whatever no catalog lists | No node route; but no request time to start the clock, and "unlisted" sweeps pre-envelope creators' recordings and in-flight pushes | No |
| (b) | A passkey-signed `DELETE` route Creator calls | New signed message format, replay protection, contract section, Creator UI; still needs the same sweep | No |
| (c) | Hide is the request, **recorded by the node at publish**; the sweep acts only on recorded requests | ~50 lines in `put_catalog`, a record prefix, two subcommands | **Yes** |

Every option needs a sweep (superseded envelopes, account deletion); the choice is only the trigger. (c) keeps the client unchanged, gives each request a time and a passkey-signed origin, and never infers a deletion. Its cost: any entry Creator drops becomes a deletion, a Creator bug included. The grace period is the undo.

## Design

### 1. Deletion requests

Two record kinds in S3, under `{prefix}`:

- `deletion-requests/recordings/<hash>`:
  `{"hash", "subject", "requestedAt", "source": "publish", "seq"}` or
  `{"hash", "subject", "requestedAt", "source": "operator", "reason"}`
- `deletion-requests/subjects/<sub>` (operator only):
  `{"subject", "requestedAt", "source": "operator", "reason"}`

`requestedAt` is Unix seconds. A new request for the same hash overwrites the old one: the latest drop is the request in force (hide on day 0, re-list on day 3, hide on day 5 ⇒ the clock starts on day 5).

Catalog envelopes get no request records (see §4, rule C).

### 2. Recording requests at publish (`PUT /v2/catalogs/{sub}`)

After the precondition and `seq` checks (step 7) and before any write (step 8):

- If the stored pointer is live (its index record exists), parse the stored index's entries. A stored index that doesn't parse fails the publish: 502 `storage unavailable`, logged as an error.
- `dropped` = payload hashes in the stored index − payload hashes in the new index. This covers Hide, an entry whose payload was replaced (the old payload is no longer published), and an empty catalog.
- Write a `source: "publish"` request for each dropped hash, with the subject, now and the new pointer's `seq`. If any write fails, the publish fails with 502 `storage unavailable` and nothing else is written.
- No stored pointer, or one without an index record (pre-envelope): nothing to diff, no requests.

Requests are written before the pointer, so a committed publish always has its requests. If the pointer write then loses (409) or fails, the requests remain for hashes that are still listed; the sweep skips listed hashes, so they're harmless, and a later drop overwrites them.

The response and the contract's status codes are unchanged (502 `storage unavailable` already exists).

### 3. Operator requests: `tdf-iroh-s3 request-deletion`

For a creator who can't publish. Runs with operator AWS credentials and the node's config file.

```
tdf-iroh-s3 --config <path> request-deletion --subject <sub> --reason <text> --hash <h> [--hash <h> ...]
tdf-iroh-s3 --config <path> request-deletion --subject <sub> --reason <text> --all
```

- `--hash`: each hash must have an active block (`moderation/blocks/<hash>`, not lifted), else the command refuses and writes nothing. The block stops distribution now; the request removes the bytes.
- `--all`: the subject must have an active catalog block (`moderation/catalog-blocks/<sub>`). Writes an operator request for every payload hash in the subject's live index, and a subject request (which deletes the pointer, §4).
- `--reason` is required (e.g. a support ticket reference).

The operator places the block first through the existing moderation API. Verifying the creator's identity for a manual request is the operator's process, outside the node.

### 4. The sweep: `tdf-iroh-s3 sweep-deletions`

```
tdf-iroh-s3 --config <path> sweep-deletions            # dry run: report only
tdf-iroh-s3 --config <path> sweep-deletions --delete
```

Same pattern as the removed `purge-catalogs-1` (c48ec9d): a subcommand of the node binary, dry run unless `--delete`. Grace is a constant, `GRACE = 7 days`, not a flag: the contract promises creators the 7-day undo.

**Snapshot.** List `catalog-pointers/`. For each pointer, read its `catalogHash`, then `catalog-indexes/<catalogHash>`.
- `L` = every payload hash in every live index.
- `C` = every pointer's `catalogHash`, live or not.
- A pointer without an index record contributes its `catalogHash` to `C` and nothing to `L` (`GET` doesn't serve it).
- Any listing, read or parse error aborts the run, nonzero exit, nothing deleted.

**What is due.**
- **Rule R (recordings):** a `recordings/` request is due when
  - `source: "publish"`, `requestedAt + GRACE ≤ now`, and the hash is not in `L`; or
  - `source: "operator"` and the hash's block is still active (no grace: the operator decided).
- **Rule S (subjects):** a `subjects/` request is due when the subject's catalog block is still active.
- **Rule C (catalog envelopes):** every `catalog-documents/<h>` whose `LastModified + GRACE ≤ now` and `h ∉ C`. No request needed: "current" is well defined by the pointers, and this also clears envelopes superseded before this ships and envelopes stored by a publish whose pointer write lost. Pointers deleted by rule S in this run are removed from `C` first.
- An operator request whose block was lifted, or a request record that doesn't parse, is skipped and reported.

**Re-check.** Take the snapshot again and drop any publish-sourced candidate now in `L`, and any envelope now in `C`.

**Delete** (with `--delete`), every version and delete marker of each key:
- Recording `h`: `blobs/h`, then `outboards/h`, then `manifests/h`, then `moderation/publishers/h`, then the request.
- Subject `s`: `catalog-pointers/s`, then the request. (Its envelope then falls to rule C.)
- Envelope `h`: `catalog-documents/h`, `catalog-outboards/h`, `catalog-indexes/h`.
- A failure stops that item: its request stays for the next run. The run continues with other items and exits nonzero.
- Block, suspension and catalog-block records are kept.

**After.** For each deleted recording, check `outboards/h` again; if a node's backfill recreated it, delete its versions again. Take the snapshot once more; any deleted hash now in `L` is reported as "re-listed during the sweep: the creator must push it again".

**Report.** One line per item (`deleted` / `would delete` / `kept: <why>`), then counts. Stdout only; the node keeps no deletion log.

### 5. Timing

- With version deletion and no backups, a recording is gone at the first sweep after `requestedAt + 7 days`. A weekly sweep makes the worst case about 14 days, inside 30.
- The operator runbook schedules the sweep weekly. The 30-day promise depends on it running.

### 6. Operations (outside the code)

- **Lifecycle rule** (devsecops' proposal, Paul applies): bucket-wide `NoncurrentVersionExpiration` 7 days, `ExpiredObjectDeleteMarker`, `AbortIncompleteMultipartUpload` 7 days; keep the `moderation/sessions/` rule. Needed because overwrites keep old versions forever: old catalog pointers (naming old envelopes and credential IDs), manifests, publisher records; and an interrupted multipart upload holds recording bytes.
- **Instance role:** `s3:PutObject` on `deletion-requests/*` if the role is prefix-scoped.
- **Operator credentials:** `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`.

### 7. Documentation

- `docs/creator-catalogs.md` (the contract): Hide/removal (line 174) now deletes the stored TDF at least 7 and at most 30 days after the publish; re-listing within 7 days cancels; after deletion, re-listing needs a fresh push. A replaced payload is deleted the same way. Superseded envelopes are deleted 7+ days after being replaced (`GET /catalog-documents/<old>` and iroh fetches then answer 404 / gone). Account deletion: publish an empty catalog first.
- `docs/publishing-and-moderation.md`: replace "Not included: deleting stored bytes" with deletion requests, the two subcommands, the manual procedure for blocked creators, IAM and the lifecycle rule. A block does not stop a requested deletion; the block record outlives the bytes.
- `CLAUDE.md`: key layout (`deletion-requests/`), the new module, Hide semantics.

## Known gaps (accepted)

- After account deletion through Creator, the pointer and the empty envelope stay (no signal reaches the node).
- A creator whose pointer predates envelopes has no index to diff; their recordings need a publish under Creator 2.0, or the operator path.
- Recordings pushed but never listed are not covered.
- Hiding a recording from a Mac without its archive can be undone only within the 7 days.
- A publish that re-lists a hash in the seconds between the sweep's re-check and its delete leaves a listed recording that answers "gone"; the sweep reports it.

## Left to the builder

- Module layout (suggested: `src/deletion.rs` for request records, the diff and the sweep's pure decisions, behind a small store trait with an S3 implementation and an in-memory one for tests).
- How `TagStore` grows to write requests (`MemStore` must implement it).
- Concurrency limits for request writes and deletions.
- The report's exact wording.
- How to test version listing and batch deletion against S3 (extend the in-test S3 stand-in in `tests/s3_client_test.rs`, or test through the trait).
