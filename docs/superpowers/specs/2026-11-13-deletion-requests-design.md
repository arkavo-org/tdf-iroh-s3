# Recording ownership, a signed catalog index, and deletion on request

**Status:** proposal, 2026-11-13, revised after two builder checks and reviews by Codex and Kimi. Must ship before Creator 2.0, on the pointer /2 switch day.
**Scope:** tdf-iroh-s3. Contract changes reach Creator (rc.3), ArkavoKit (ArkavoCatalog) and the iOS viewer.
**Read at:** tdf-iroh-s3 `02caef2`; Creator `feat/2.0-rc3` and ArkavoKit `0.22.0` as reported by their sessions.

## Why

Arkavo's privacy policy will promise that a published recording is deleted from Arkavo's servers within 30 days of the creator's request, backups and old object versions included. Deleting an Arkavo account deletes that account's published recordings within the same 30 days. The creator's passkey is the proof of the request.

Today the node never deletes anything a creator published. Hiding a recording republishes the catalog without its entry, and "the TDF stays on the node" (`docs/creator-catalogs.md:174`). A moderation block stops distribution and leaves the bytes. Two things also keep "the passkey is the proof" and "only the creator deletes their recordings" from being true: the passkey signs the pointer but not the clear index the node reads, and any creator may list a recording whose policy names their attribute.

## Decisions (Paul)

1. **Mechanism (c).** Hide from Catalog is the deletion request, recorded at the passkey-signed publish; an operator-run sweep deletes after a grace period. No new client route for deletion.
2. **Account deletion.** Before `DELETE /account`, Creator publishes an empty catalog. If that fails, Creator stops and offers Try Again or Delete Anyway. On a 404 pointer Creator skips the publish.
3. **Policy exceptions:** the 90-day service logs, and content removed by moderation (a blocked recording or envelope is kept while the block stands). A report alone does not hold a deletion.
4. **A drop a block forces is not a request.** `check_payloads` refuses any publish that lists a blocked hash, so a takedown makes the creator drop it.
5. **Not retroactive.** Drops before this ships are not requests.
6. **Creators who can't publish** (entitlement lapsed, suspended, PDP denies, catalog blocked) are handled by an operator.
7. **The sweep deletes every S3 version.**
8. **The index is bound into what the passkey signs, now:** pointer `/2` carries `indexHash`. **Hard switch:** from the switch day the node refuses `/1` publishes; it never accepts both.
9. **No cross-account recordings.** Only a recording's owner can list it or delete it.
10. **Ownership ends** when the sweep deletes the recording, or when an operator releases it.

## Goals

- A recording its owner dropped from their catalog (Hide, a replaced payload, an empty catalog) is gone from S3, every version, within 30 days of the publish that dropped it.
- Superseded catalog envelopes (they carry each entry's metadata TDF, titles included) are gone within the same budget, and no earlier than 7 days after being superseded.
- Every request traces to a committed, passkey-signed publish whose index the passkey covered.
- A creator can undo a Hide by publishing the entry again within 7 days.
- One account owns each recording; nobody else can list it, push it, or cause its deletion.

## Non-goals

- Deleting the pointer or the current (possibly empty) envelope when a creator deletes their account through Creator. Nothing tells the node an account was deleted.
- Recordings pushed but never listed, outside the operator path. Leftovers of removed features other than envelopes (`/1` tags, `catalog-index/`, `campaign-creators/`).
- A scheduled, automatic sweep. The operator runs it, at least weekly.
- Copies outside the node: what viewers or iroh peers already fetched, the KAS, identity, CloudWatch logs.

## Anti-goals

- **Never delete a recording its owner didn't ask to delete.** No "listed nowhere ⇒ delete" rule for recordings: a pre-envelope creator's recordings are listed nowhere (`catalogs_v2_api.rs:420`).
- **Never act on uncommitted or unreadable state.** Requests derive only from publishes whose pointer committed. Any unreadable record aborts the sweep before it deletes anything.
- **Never leave a deleted object to come back.** A deletion stays recorded until a later run confirms every object is still gone.

## Facts the design rests on

- `put_catalog` reads the stored pointer and its index record before writing (`catalogs_v2_api.rs:411-433`), and writes the pointer conditionally on that pointer's ETag (`:455`, `:489`). So a committed publish replaced exactly the pointer it read.
- `GET /v2/catalogs/{sub}` answers 404 for a blocked envelope, an owner with a catalog block or `hideCatalog` suspension, and a pre-envelope pointer. A 404 does not mean no pointer.
- The passkey's challenge is SHA-256 of the pointer bytes (`catalog_v2.rs:9`, `:390`). Pointer `/1` is exactly `schema, owner, seq, catalogHash, catalogSize, issuedAt` (`:77-84`); `issuedAt` has no freshness check. The index is not signed (`creator-catalogs.md:113`).
- `check_payloads` has no ownership check (`catalogs_api.rs:65`): it refuses blocked hashes (403, `:70`), unknown blobs (422, `:74`), and entries whose manifest lacks the envelope's attribute (`:120`).
- `moderation/publishers/<hash>` is written after each ingested push, overwriting (`node.rs:293`, `:363`), only on a gated node.
- Ingest writes the outboard first, then uploads the blob if absent (`ingest.rs:170-191`). `S3Server` recomputes a missing outboard for an existing blob or envelope (`s3_serve.rs:302-321`). Blobs are a single `PutObject` (`store/s3.rs:141`).
- The moderation loader skips unreadable records (`moderation.rs:427`). Catalog blocks are keyed by canonical subject (`:1360`); pointers by the token's `sub`.
- Production bucket (2026-11-13): versioned, no replication, no Object Lock; no AWS Backup plans or recovery points and no DLM policies; only lifecycle rule is the 1-day rule on `moderation/sessions/`.
- Every pointer reader today (ArkavoKit `CatalogPointer.decode` 0.22.0; the viewer's own parser at 3.0.0-beta.5) refuses anything but `/1` with exactly six keys. Only Creator writes pointers.

## Approaches considered

| | Trigger | Cost | Picked |
|---|---|---|---|
| (a) | Hide is the request; a sweep deletes whatever no catalog lists | No request time; sweeps pre-envelope creators' recordings and in-flight pushes | No |
| (b) | A passkey-signed `DELETE` route | New signed format, replay protection, Creator UI; same sweep | No |
| (c) | Hide is the request, recorded by the node at publish | A record per publish and two subcommands | **Yes** |

The first version of (c) wrote request objects before the pointer committed. Reviews found that a publish whose pointer write lost could still trigger or back-date a deletion, and that re-listing didn't cancel a request. This version records a **transition** per publish and lets the sweep fold only committed transitions, in order. A sweep that instead compared each catalog with what it saw last run was rejected: a recording listed and hidden between two runs would never be seen, so never deleted.

## Design

Three parts, built as three PRs in this order and deployed together on the switch day.

### Part 1. Ownership

**The owner record.** `moderation/publishers/<hash>` (`{"hash","subject","endpointId","at"}`, `subject` canonical) becomes write-once: created with `If-None-Match: *`, never overwritten. The first account to push a hash owns it.

**Push.** When a push arrives, the node knows the pusher's subject from the publish session. Before accepting the transfer it reads the owner record (5 s timeout, bounded concurrency, as session lookups are):
- names another subject → refuse the push (Permission);
- names the pusher, or absent → accept;
- unreadable or timed out → refuse (fail closed).

After a successful ingest it creates the record if absent. If two first pushes race, the first create wins; the loser's bytes are the same bytes, and the loser can't list them. If the create fails, the node logs it and the blob stays unowned; the publisher's next listing gets 422 `recording has no owner: push it again`, and that push (which skips the upload, the blob being present) claims it.

**Publish.** `check_payloads` gets the publisher's subject and reads each distinct hash's owner record, alongside its existing HEAD and manifest reads:
- another subject → 403 `recording belongs to another account`;
- absent → 422 `recording has no owner: push it again` (a push claims it);
- both refusals carry `"contentIDs"`: every offending entry's `contentID`, sorted.

**Pre-check.** `GET /publish/recordings/{hash}`, authorized exactly as `POST /publish/sessions` and `PUT /v2/catalogs` are (`authorize_publisher`: the bearer CWT, plus `X-Entity-Token` devices when decisions are `shadow` or `pdp`), with their statuses: 401 `missing bearer token` / `invalid token`, 403 `publishing entitlement required` / `publishing suspended` / `publishing not permitted`, 503 `decision service unavailable`, 502 when the key set is unavailable. Then 200 `{"hash":"<hash>","owner":"you" | "another account" | "none"}`, 400 `invalid hash`, or 502 `storage unavailable`. It never names the other account. Creator calls it before the passkey prompt, and again after a failed push to explain it: an iroh push refusal carries only an error code.

`recording has no owner: push it again` arises only when the blob exists without an owner record: the record's create failed, an operator released it, or the blob predates publish sessions and no catalog listed it at the backfill. No catalog that exists at the switch meets it.

**Backfill.** `tdf-iroh-s3 claim-owners [--write]`, dry run by default, run once before the switch. For each payload hash listed in any live index:
- an owner record exists and names the only lister → nothing to do;
- no record, and exactly one subject lists it → create the record for that subject;
- listed by more than one subject, or a record naming someone who doesn't list it → conflict, reported, nothing written.

The switch waits until the dry run reports no conflicts. Hashes listed nowhere and without a record are left; the next push claims them.

**Release.** The sweep deletes the owner record with the recording (Part 3). `tdf-iroh-s3 release-owner --hash <h> --subject <sub> --reason <text>` deletes it (every version) only if it names `<sub>`, for an account deleted without emptying its catalog. A released recording is claimed by the next push. (Testing confirms that `If-None-Match: *` succeeds once every version is gone.)

### Part 2. Pointer /2 and the signed index

**Pointer `/2`.** Exactly seven keys, the `/1` rules otherwise unchanged (no repeated key, nothing after it, at most 1024 bytes):

```json
{"schema":"arkavo.catalog-pointer/2","owner":"<sub>","seq":7,"catalogHash":"<64 hex>","catalogSize":1234,"indexHash":"<64 hex>","issuedAt":"2026-10-19T01:02:03Z"}
```

A `/1` pointer is exactly its six keys; a `/1` with `indexHash`, or a `/2` without it, is invalid. `indexHash` is **SHA-256**, while `catalogHash` and `payloadHash` are BLAKE3.

**`indexHash`** is the lowercase hex SHA-256 of the canonical index, built from the parsed entries, never from the bytes received:
- entries sorted by `contentID`, comparing the UTF-8 bytes;
- each written as `{"contentID":"<id>","version":<n>,"payloadHash":"<hex>","payloadSize":<n>}`, keys in exactly that order;
- joined with `,` inside `[` `]`, no whitespace. The empty index is `[]`.
- No escaping arises: `contentID` is `[A-Za-z0-9:._@-]`.

The wire `index` in `PUT` is unchanged (Creator's `encodedIndex()` writes keys alphabetically in document order; the node re-canonicalizes).

**Vectors** (the shared file is ArkavoKit's `Tests/ArkavoCatalogTests/Vectors/catalog-vectors.json`, copied to `tests/fixtures/arkavo-catalog-vectors.json`; ArkavoKit adds these and the invalid pointers):

| Name | Input order of `contentID` | `indexHash` |
|---|---|---|
| empty | — | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| two | `rec-b` (v1, `bb…`, 2048), `rec-a` (v3, `aa…`, 1024) | `03f745d8d08d9e9e11cabf33d85e8beb452eb3a2b2e541f92e1703c1f4152df4` |
| byte-order | `a_1`, `a@1`, `A`, `a:1`, `a.1`, `a-1` (entry *n*, counting from 0 in this order, has hash byte `n` ×32, size *n*+1, v1; so `a_1` is `00`×32, size 1) | `79129b9fa70e8ab5d0894d07098294de6dec2677c9df538b3eb05df98bd8ef18` |

The vector file spells out each full `index` text with its expected hash. Canonical bytes of "two": `[{"contentID":"rec-a","version":3,"payloadHash":"aa…aa","payloadSize":1024},{"contentID":"rec-b","version":1,"payloadHash":"bb…bb","payloadSize":2048}]` (64 hex characters each). "byte-order" sorts to `A`, `a-1`, `a.1`, `a:1`, `a@1`, `a_1`.

**The node, from the switch.** `PUT /v2/catalogs/{sub}` accepts only `/2`:
- `/1` → 422 `invalid bundle: pointer schema must be "arkavo.catalog-pointer/2"` (the existing message with the new schema);
- `indexHash` differs from the canonical index → 422 `invalid bundle: indexHash does not match the index`, checked after the bundle verifies and before `check_payloads`;
- neither `If-Match` nor `If-None-Match` sent → 428 `precondition required` (the contract already reserves it). Without a precondition, a device whose own highest `seq` exceeds the stored one could publish over a base it never read, and everything the other device added would count as dropped;
- the index record `catalog-indexes/<catalogHash>` is written with `If-None-Match: *`. If one exists, its canonical hash must equal this pointer's `indexHash` (a retry), else 409 `catalog document already published with another index`. One envelope has one index; this keeps a losing publish from rewriting the committed pointer's index.

Readers (the sweep, the diff at publish) check a `/2` pointer's stored index against its `indexHash`; a mismatch aborts the sweep.

`GET` still serves stored `/1` pointers; ArkavoKit keeps decoding `/1` while any are stored.

**Rollout (hard switch).**
1. ArkavoKit release: reads `/1` and `/2`, writes `/2`; `CatalogPublishRequest` refuses a `/2` whose `indexHash` doesn't match its catalog. Optionally the viewer checks `indexHash` against the decrypted entries.
2. A viewer build that accepts `/2` reaches users (or a patch to the viewer's own parser).
3. `claim-owners` reports no conflicts, then runs with `--write`. A dry run of `sweep-deletions` completes (no unreadable record; see 3.4 step 1).
4. Node deploy (Parts 1–3), with **no overlap**: no instance running the old code serves after the new one does. An old instance would overwrite owner records and accept `/1` publishes that write no transition, breaking the chain. Then `claim-owners` dry run again. From here `/1` publishes are refused; rc.2 and earlier TestFlight builds can't publish, update or hide (accepted).
5. Creator rc.3 publishes `/2`. Before the switch, rc.3 is tested against this branch run outside production.

### Part 3. Deletion requests

#### 3.1 Transitions, written at publish

Each publish writes `catalog-transitions/<sub>/<seq, 20 digits>-<pointer digest>` (`<sub>` as the pointer key; the digest is the lowercase hex SHA-256 of the signed pointer bytes, so the key is unique to one signed pointer) **before** the document, index and pointer (step 8), and fails with 502 `storage unavailable` if it can't:

```json
{"subject":"<sub>","seq":8,"catalogHash":"<new>","pointer":"<digest>","base":{"seq":7,"catalogHash":"<old>","pointer":"<digest>"},"at":<unix secs>,
 "dropped":["<hash>",...],"added":["<hash>",...]}
```

- `base` is the stored pointer this publish replaces, whatever its visibility; `null` when there is none.
- `dropped` = hashes in the **served** base's index (live, envelope not blocked, owner without a catalog block or `hideCatalog` suspension) − hashes in the new index, minus hashes blocked at publish time (decision 4), minus hashes whose owner record doesn't name the publisher. Empty when the base isn't served.
- `added` = hashes in the new index − hashes in the base's live index (any visibility); all new hashes when the base has no index.

A transition is **committed** when it is reachable from a current pointer by following `base` links. Because the pointer write is conditional on the base's ETag, a transition from a publish that lost is never reachable. The publish path writes no requests.

#### 3.2 Records the sweep keeps

Under `deletion-requests/`, written only by the sweep and the operator commands. Subjects are canonical.

| Key | Body |
|---|---|
| `recordings/<sub>/<hash>` | `{"hash","subject","requestedAt","seq","state":"pending"\|"deleted","deletedAt"?}` |
| `envelopes/<hash>` | `{"hash","owner"?,"supersededAt","source":"transition"\|"observed","state","deletedAt"?}` |
| `operator/<sub>/<hash>` | `{"hash","subject","requestedAt","reason","scope":"hash"\|"subject","state","deletedAt"?}` |
| `subjects/<sub>` | `{"subject","requestedAt","reason","state","deletedAt"?}` |

#### 3.3 Operator commands

Each needs operator AWS credentials and the node's config; `--reason` is required; subjects compare canonically. They print what they wrote.

- `request-deletion --subject <s> --hash <h>...`: each hash must have an active block. Writes `operator/<s>/<h>`, scope `hash`.
- `request-deletion --subject <s> --all`: `<s>` must have an active catalog block. Writes scope-`subject` requests for every hash in the live index of each pointer canonically `<s>`, and every hash whose owner record names `<s>`, then `subjects/<s>`. It reports these sources as its whole coverage; the operator adds `--hash` for anything else.
- `release-owner` (Part 1).

#### 3.4 The sweep: `tdf-iroh-s3 sweep-deletions [--delete]`

Dry run unless `--delete` (the pattern of the removed `purge-catalogs-1`, c48ec9d): a dry run reads and reports, and writes nothing. `GRACE` is a constant, 7 days.

1. **Read strictly.** Every pointer, index record, transition and request, and the moderation records it decides on: suspensions, blocks, catalog blocks and owner records (not sessions or audit), with its own strict parser, not the loader that skips (`moderation.rs:423-443`). A `/2` pointer's index must match its `indexHash`. Anything unreadable aborts the run, nonzero, nothing written. The rollout's dry run surfaces any such record before the switch.
2. **Fold committed transitions.** For each pointer, walk back from its current `(seq, catalogHash)` through transition records until one is missing (start of history, or already folded). Apply them oldest first:
   - each `added` hash cancels a pending `recordings/<sub>/<hash>`;
   - each `dropped` hash sets `recordings/<sub>/<hash>` pending with `requestedAt` = the transition's `at` (the newest drop wins);
   - a `base.catalogHash` different from the new one sets `envelopes/<base>` pending, `supersededAt` = `at`, `source: "transition"`.
   Then delete the folded transitions, oldest first. A transition not reachable from any pointer, older than `GRACE`, whose subject's current pointer has a `seq` at least its own, lost its publish and is deleted unfolded. Any other unreachable transition is kept and reported.
3. **Snapshot.**
   - `S` = pointers canonically a subject with an active `subjects/` request whose catalog block is still active.
   - `L` = every payload hash in every live index of a pointer not in `S`, **whatever its visibility**.
   - `C` = every pointer's `catalogHash`, for pointers not in `S`.
4. **Observe untracked envelopes.** A hash under `catalog-documents/`, `catalog-outboards/` or `catalog-indexes/` that is not in `C` and has no `envelopes/` record gets one: `source: "observed"`, `supersededAt` = now.
5. **Due.**
   - `recordings/<sub>/<h>` pending: `requestedAt + GRACE ≤ now`, `h ∉ L`, `h` not blocked, and `h`'s owner record names `<sub>`. A different or missing owner is kept and reported for manual handling.
   - `operator/<sub>/<h>`: scope `hash` while `h`'s block is active (no grace, no `L`); scope `subject` while `<sub>`'s catalog block is active, `h ∉ L`, and `h`'s owner record names `<sub>` (absent or another owner: kept, reported). If the block is lifted, pending scope-`subject` items are kept and reported each run.
   - `subjects/<sub>`: while its catalog block is active.
   - `envelopes/<h>` pending: `supersededAt + GRACE ≤ now`, `h ∉ C`, `h` not blocked, and its owner (the document's `owner` metadata, else the index record's `owner`) has no catalog block or `hideCatalog` suspension, **unless** the owner has a `subjects/` request (the operator asked for everything; the block was its precondition). Unknown owner while any object exists: kept, reported.
6. **Delete** (with `--delete`), item by item. Immediately before each item, re-read its request record and the moderation records it depends on, and re-read the pointers to recheck `L`/`C`; drop the item if anything changed. If the request's subject's pointer has moved since step 1, defer the item to the next run, where its new transitions are folded first. Then delete every version and delete marker:
   - recording `h`: `blobs/h`, then `outboards/h`, `manifests/h`, `moderation/publishers/h` (ownership ends); then mark its request(s) `deleted` with `deletedAt`;
   - subject `s`: each pointer in `S` for `s`; mark `subjects/s` `deleted` (its envelopes fall to step 4 next run);
   - envelope `h`: `catalog-documents/h`, then `catalog-outboards/h`, `catalog-indexes/h`; mark `envelopes/h` `deleted`.
   A failure leaves that item pending for the next run; the run continues and exits nonzero. Block, suspension, catalog-block and audit records are kept.
7. **Verify tombstones.** For each record marked `deleted` at least an hour earlier (any in-flight push, backfill or publish has finished), with the pointers re-read:
   - an object written more than an hour after `deletedAt` is **fresh**: a new push (it carries a new owner record), a new publish, a returning creator's new pointer. Remove the tombstone and keep everything; the recording's new owner controls it now;
   - else, recording `h` in `L`, or envelope `h` in `C`: remove the tombstone, keep the objects;
   - else, any object written by `deletedAt` + 1 hour exists (an in-flight write that landed after the delete): run step 6's re-check, delete it again, report "recreated", keep the tombstone;
   - else: remove the tombstone, every version.
8. **Report.** One line per item (`deleted`, `would delete`, `kept: <why>`, `recreated`), then counts; also any deleted recording now in `L` and any deleted envelope now in `C`. Stdout only.

#### 3.5 Timing

A drop's clock is the time of the `PUT` that dropped the entry, recorded in its transition. With a weekly sweep, the drop is folded within 7 days, falls due at publish + 7 days, and is deleted by the first sweep after that: about 14 days worst case. With no backups and version deletion, that is final. The runbook schedules the sweep weekly; the promise depends on it.

### Operations

- **Lifecycle rule** (devsecops' proposal, Paul applies): bucket-wide `NoncurrentVersionExpiration` 7 days and `ExpiredObjectDeleteMarker`, keeping the `moderation/sessions/` rule, so overwrites (old pointers, manifests) don't keep old versions forever.
- **Instance role:** `s3:PutObject` on `catalog-transitions/*`; conditional creates on `moderation/publishers/*`.
- **Operator credentials:** `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`.

## Contract changes (`docs/creator-catalogs.md`)

Wire strings are matched exactly by Creator and stay stable.

| Route | Status | `error` | Extra |
|---|---|---|---|
| `PUT /v2/catalogs/{sub}` | 422 | `invalid bundle: pointer schema must be "arkavo.catalog-pointer/2"` | |
| `PUT /v2/catalogs/{sub}` | 422 | `invalid bundle: indexHash does not match the index` | |
| `PUT /v2/catalogs/{sub}` | 403 | `recording belongs to another account` | `contentIDs` |
| `PUT /v2/catalogs/{sub}` | 422 | `recording has no owner: push it again` | `contentIDs` |
| `PUT /v2/catalogs/{sub}` | 428 | `precondition required` | |
| `PUT /v2/catalogs/{sub}` | 409 | `catalog document already published with another index` | |
| `GET /publish/recordings/{hash}` | 200 | | `{"hash","owner"}` |

None starts with `invalid bundle: credential` or equals a passkey or entitlement refusal Creator already handles.

Also in the contract: pointer `/2` and `indexHash` with the vectors; ownership (first push owns; others' pushes refused); removal (line 174): the stored TDF is deleted 7 to 30 days after the publish that dropped it, re-listing within 7 days cancels, after deletion re-listing needs a fresh push; a replaced payload is deleted the same way; a superseded envelope is deleted 7 to 30 days after it was replaced; account deletion: publish an empty catalog first. `docs/publishing-and-moderation.md`: ownership on push, the operator commands and procedure, IAM, the lifecycle rule. `CLAUDE.md`: key layout and modules.

## Known gaps (accepted)

- After account deletion through Creator, the pointer and the empty envelope stay.
- A creator whose catalog reads 404 (pre-envelope pointer, blocked envelope, catalog block, `hideCatalog`) gets no requests from an empty-catalog publish; Creator skips it on 404. Operator path on request.
- An account deleted without emptying its catalog keeps owning its recordings, so a new account can't push the same files until an operator runs `release-owner` or `request-deletion`.
- A catalog-blocked creator who isn't suspended gets 412 on `If-None-Match: *` (`PUT` preconditions ignore the owner's hide). Pre-existing, separate fix.
- Recordings hidden before this ships stay stored, also after their creator deletes their account.
- A Hide from a Mac without the archive can be undone only within the 7 days.
- A publish that re-lists a hash between an item's re-check and its delete leaves a listed recording that answers "gone"; the sweep reports it.

## Left to the builder

- Module layout (suggested: `src/ownership.rs`, `src/deletion.rs` for transitions, folding and the sweep's decisions behind a small store trait with an S3 and an in-memory implementation).
- How `TagStore` grows (`MemStore` implements it), and how the push path's owner lookup shares the session lookup's bounds.
- Concurrency limits, report wording, and how to test version listing and batch deletion against S3 (extend the stand-in in `tests/s3_client_test.rs`, or test through the trait).
