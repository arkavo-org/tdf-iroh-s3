# Recording ownership, a signed catalog index, and deletion on request

**Status:** approved by Paul, 2026-11-13, after two builder checks and reviews by Codex and Kimi. Plan: `docs/superpowers/plans/2026-11-13-deletion-requests.md`. Must ship before Creator 2.0, on the pointer /2 switch day.
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
- neither `If-Match` nor `If-None-Match` sent → 428 `precondition required` (the contract already reserves it). Without a precondition, a device whose own highest `seq` exceeds the stored one could publish over a base it never read, and everything the other device added would count as dropped. *Updated 2026-11-14:* only exactly one of `If-Match: "<seq>"` or `If-None-Match: *` is accepted, and any other form is 428 too; the base check sees what `GET` serves, the owner's hide included;
- the index record `catalog-indexes/<catalogHash>` is written with `If-None-Match: *`. If one exists, its canonical hash must equal this pointer's `indexHash` (a retry), else 409 `catalog document already published with another index`. One envelope has one index; this keeps a losing publish from rewriting the committed pointer's index.

Readers (the sweep, the diff at publish) check a `/2` pointer's stored index against its `indexHash`; a mismatch aborts the sweep.

`GET` still serves stored `/1` pointers; ArkavoKit keeps decoding `/1` while any are stored.

**Rollout (hard switch).**
1. ArkavoKit release: reads `/1` and `/2`, writes `/2`; `CatalogPublishRequest` refuses a `/2` whose `indexHash` doesn't match its catalog. Optionally the viewer checks `indexHash` against the decrypted entries.
2. A viewer build that accepts `/2` reaches users (or a patch to the viewer's own parser).
3. `claim-owners` reports no conflicts, then runs with `--write`. A dry run of `sweep-deletions` completes (no unreadable record; see 3.4 step 1). It reports each envelope superseded before the switch as observed; their grace starts at the first `--delete` run (3.4 step 4).
4. Node deploy (Parts 1–3), with **no overlap**: no instance running the old code serves after the new one does. An old instance would overwrite owner records and accept `/1` publishes that write no transition, breaking the chain. Then `claim-owners` dry run again. From here `/1` publishes are refused; rc.2 and earlier TestFlight builds can't publish, update or hide (accepted).
5. Creator rc.3 publishes `/2`. Before the switch, rc.3 is tested against this branch run outside production.

### Part 3. Deletion requests

#### 3.1 Transitions, written at publish

Each publish writes `catalog-transitions/<sub>/<seq, 20 digits>-<pointer digest>` (`<sub>` as the pointer key; the digest is the lowercase hex SHA-256 of the signed pointer bytes, so the key is unique to one signed pointer) in step 8, after the index record and **before** the document, outboard and pointer (index → transition → document → outboard → pointer), and fails with 502 `storage unavailable` if it can't. *(Updated 2026-11-14.)* It is created only if none is under its key (`If-None-Match: *`). One already there came from the same signed pointer, sent before: a retry, a duplicate, or an attempt over a base that has moved since. The node then reads the stored pointer: still the one this publish read, the transition is replaced with this publish's (its base, its `dropped`, a fresh `at`), only if unchanged since read (`If-Match`); moved, it is kept, and the publish answers 502. The pointer write is conditional on that same pointer, so the transition a committed pointer reaches names the base it replaced:

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

- `request-deletion --subject <s> --hash <h>...`: recordings only. Each hash must have an active block, and must not be a catalog envelope's (an object under `catalog-documents/`, `catalog-outboards/` or `catalog-indexes/`): a blocked envelope is kept while its block stands. Writes `operator/<s>/<h>`, scope `hash`.
- `request-deletion --subject <s> --all`: `<s>` must have an active catalog block and an active suspension (3.4, the first change listed after step 8). Writes scope-`subject` requests for every hash in the live index of each pointer canonically `<s>`, and every hash whose owner record names `<s>`, then `subjects/<s>`. It reports these sources as its whole coverage; the operator adds `--hash` for anything else, the subject's blocked recordings included: scope `subject` keeps a blocked hash (decision 3).
- `release-owner` (Part 1).

*(Updated 2026-11-14.)* Both `request-deletion` forms read the bucket as strictly as the sweep and check every precondition before any write; `<s>`'s canonical form must be canonical itself (not `arkavo:arkavo:<uuid>`), as the sweep's read requires of a request key. Don't run `request-deletion` during a `sweep-deletions --delete` run: the sweep deletes a request record (a close, the fold's cancel) with whatever versions it has then.

#### 3.4 The sweep: `tdf-iroh-s3 sweep-deletions [--delete]`

**Updated after implementation and review (2026-11-14).** The steps below are what the sweep does. They replace the text approved on 2026-11-13 where the two differ; the changes are listed after step 8.

Dry run unless `--delete` (the pattern of the removed `purge-catalogs-1`, c48ec9d): a dry run reads and reports, and writes nothing. `GRACE` is a constant, 7 days; `VERIFY_AFTER`, 1 hour. One sweep runs at a time, and no `request-deletion` runs during a `--delete` run (3.3). The operator's host and the node keep NTP-synced clocks: the hour checks compare S3's write times with the host's clock, and step 6's push check compares them with a drop's `requestedAt`, which the node's clock set.

1. **Read strictly.** Every pointer, index record, transition and request, the envelope objects (listed only), and the moderation records it decides on: suspensions, blocks, catalog blocks and owner records (not sessions or audit), with its own strict parser, not the loader that skips (`moderation.rs:423-443`). A `/2` pointer's index must match its `indexHash`. A key must be what the node writes, and a body must name its key: request keys and suspension and catalog-block keys carry canonical subjects (the moderation API and `request-deletion` refuse, before writing, a subject whose canonical form isn't canonical, such as `arkavo:arkavo:<uuid>`); a transition's subject must canonicalize to one, since step 2 keys requests by it; hashes are lowercase hex; a tombstone carries `deletedAt`. Envelope objects are listed before pointers, and pointers read before index records and transitions, so a publish in flight never reads as a fault. Anything unreadable aborts the run, nonzero, nothing written. The rollout's dry run surfaces any such record before the switch.
2. **Fold committed transitions.** For each pointer, walk back from its current `(seq, catalogHash)` through transition records until one is missing (start of history, or already folded). One canonical subject's chains (pointer keys `arkavo:<uuid>` and `<uuid>`) are applied together, in time order. Apply them oldest first:
   - each `added` hash cancels a pending `recordings/<sub>/<hash>`. Nothing else cancels a drop;
   - each `dropped` hash sets `recordings/<sub>/<hash>` pending with `requestedAt` = the transition's `at` (the newest drop wins: `requestedAt` never moves back);
   - a `base.catalogHash` different from the new one sets `envelopes/<base>` pending, `supersededAt` = `at`, `source: "transition"`, `owner` the subject.
   With `--delete`, the changed requests are written, then the cancelled requests and the folded transitions deleted, oldest first; a failure here aborts the run, and the next run folds them again. A transition not reachable from any pointer, older than `GRACE`, whose subject's current pointer has a `seq` at least its own, lost its publish and is deleted unfolded. So is one, of any age, whose subject has a `deleted` `subjects/` record and no pointer under either key: a publish in flight when step 6 deleted the account. Any other unreachable transition, and one in a `base` cycle, is kept and reported.
3. **Snapshot.**
   - `S` = pointers canonically a subject with a pending `subjects/` request whose catalog block and suspension are still active.
   - `L` = every payload hash in every live index of a pointer not in `S`, **whatever its visibility**.
   - `C` = every pointer's `catalogHash`, for pointers not in `S`.
4. **Observe untracked envelopes.** A hash under `catalog-documents/`, `catalog-outboards/` or `catalog-indexes/` that is not in `C` and has no `envelopes/` record gets one: `source: "observed"`, `supersededAt` = now, `owner` from the document's owner metadata. It is reported `kept: observed`. Only a `--delete` run writes it, so only a `--delete` run starts its grace: every dry run observes it again.
5. **Due.** A recording's pending requests, `recordings/` and `operator/` of every subject, are decided per hash: one due makes the hash due, and its delete satisfies them all.
   - `recordings/<sub>/<h>` pending: `requestedAt + GRACE ≤ now`, `h ∉ L`, `h` not blocked, and `h`'s owner record names `<sub>`. A different or missing owner is kept and reported for manual handling.
   - `operator/<sub>/<h>`: scope `hash` while `h`'s block is active (no grace, no `L`, any owner); scope `subject` while `<sub>`'s catalog block and suspension are active, `h ∉ L`, `h` not blocked (moderation keeps it: only scope `hash` deletes a blocked recording), and `h`'s owner record names `<sub>` (absent or another owner: kept, reported). If either precondition is lifted, pending scope-`subject` items are kept and reported each run.
   - `subjects/<sub>`: while its catalog block and suspension are active.
   - `envelopes/<h>` pending: `supersededAt + GRACE ≤ now`, `h ∉ C`, `h` not blocked, and its owner (the request's `owner`, else the index record's) has no catalog block or `hideCatalog` suspension, **unless** the owner has a `subjects/` record, pending or deleted (the operator asked for everything), and its preconditions, the block and the suspension, are still active. Unknown owner while any object exists: kept, reported; with none left, due, deleting nothing.
6. **Delete** (with `--delete`), item by item: subjects, then recordings, then envelopes, so a subject's pointers go before its envelopes. For each item:
   - **List, then re-check.** List every version and delete marker of the item's keys: a recording's four, an envelope's three, a subject's two pointer keys and every transition under either of its keys. Then read everything again (step 1) and decide again (steps 3 to 5). An item no longer due is kept, with the fresh reason. An envelope any stored pointer names is kept, even one in `S` (its subject's pointer delete may have failed): deleting the index record a `/2` pointer names would make every later strict read fail. An item whose requester's pointers moved since step 1 is deferred to the next run, where its new transitions are folded first.
   - **A push after the drop restarts the grace.** For a recording, list its blob, manifest and owner record again after the read. A version written after the `requestedAt` of a pending `recordings/` request of the hash (not a delete marker, and never an outboard, which the node writes itself) means the owner pushed it again; Creator pushes before it publishes, so a publish that failed leaves exactly this. Each such request moves its `requestedAt` forward to that S3 write time, never back, and stays pending; nothing of the recording is deleted this run (`pushed again`; a dry run reports it and writes nothing). Only a listing cancels a drop. If another request still has the hash due without the moved ones (an operator's, or a drop after the push), the recording is deleted as below.
   - **Delete exactly what was listed:** every version and delete marker listed before the re-read, key by key, each key's current version last, so a delete that stops part way never brings an older version back. A version written after the listing stays; step 7's hour covers it. A failure leaves the item pending for the next run; the run goes on, and exits nonzero.
     - recording `h`: `blobs/h` (nothing is served once anything is gone), then `outboards/h`, `manifests/h`, `moderation/publishers/h` (ownership ends); mark every request of the hash `deleted`, `deletedAt` the run's start;
     - subject `s`: its pointers in the fresh `S`, then each listed transition under `catalog-transitions/s/` and `catalog-transitions/arkavo:s/` (its publish history); mark `subjects/s` `deleted`. Its envelopes left `C` with `S`, so step 4 of the same run observed them;
     - envelope `h`: `catalog-documents/h`, then `catalog-outboards/h`, `catalog-indexes/h`; mark `envelopes/h` `deleted`.
   - **Close stale requests.** A recording whose pending requests are kept only because its owner record is missing (they pass every other rule), and that has nothing left but outboard versions written before the earliest request's `requestedAt`: an earlier run deleted it and failed to write the tombstone, or a push failed after its outboard, before the drop. After the same re-read, and a second listing that still finds nothing newer (a blob, manifest, owner record or newer outboard written meanwhile keeps it: an upload may be in progress), delete those outboard versions and the request records, writing no tombstone (`closed`): a tombstone's hour would read a new push by the requester as in flight and delete it again.

   A failed listing or re-read aborts the run. Block, suspension, catalog-block and audit records are kept.
7. **Verify tombstones.** With the bucket read again, once for all of them: for each item whose newest tombstone record was written at least `VERIFY_AFTER` ago, by S3's clock (the record's last-modified time, not `deletedAt`, which is the run's start on the operator's clock: a long run deletes items well after it starts), a recording's tombstones of every subject together, list the item's keys: a recording's four, an envelope's three, a subject's two pointer keys (never its transitions: a transition without a pointer is a publish in flight, which step 2 deletes as lost). Then:
   - an object a new push or publish writes (a blob, manifest or owner record; a document or index record; a pointer), written more than `VERIFY_AFTER` after the tombstone, is **fresh**: remove the tombstone and keep everything; the recording's new owner controls it now. An outboard is never fresh: the node writes one itself when it serves a blob or envelope that lacks it;
   - else, recording `h` in `L`, or envelope `h` in `C`: remove the tombstone, keep the objects. `L` and `C` here leave out a deleted subject's late pointers (its catalog block and suspension standing, the pointer's current version written by the tombstone's write time + `VERIFY_AFTER`): the next rule deletes them again, and what they list must not outlive them;
   - else, any object (written within the hour, by a write in flight during the delete, or an outboard): re-check the item on a fresh read as step 6 does (without its push check, since a write within the hour is in flight; a missing owner record doesn't count, since the sweep deleted it), delete again exactly the versions listed before that read, report `recreated`, keep the tombstone;
   - else: remove the tombstone, every version.
   A subject's tombstone stays while an envelope request of that owner is pending and its catalog block and suspension stand (`envelopes pending`): it releases those envelopes from the hidden catalog (step 5).
8. **Report.** Stdout carries the report alone; logs go to stderr. One line per lost transition, per due item (`deleted`, `would delete`, `kept: <why>`, `pushed again`, `deferred`, `failed`), per closed recording (`closed`, `would close`), per tombstone checked (`verified`, `fresh`, `listed again`, `current again`, `recreated`, `kept: <why>`), per pending request and kept transition (not one the run deleted with its subject), then any deleted recording now in `L` and deleted envelope now in `C`, from a final read whose failure counts as a failure. Then the counts: deleted, closed, kept, deferred, failed. A run that aborts after it began writing prints its lines so far, then the error.

**Changed from the text approved on 2026-11-13:**
- `--all` needs an active suspension as well as the catalog block, and the sweep re-checks both wherever it acted on the block alone (`S`, step 5, and step 7's checks of a deleted subject's tombstone). A catalog block hides the catalog but doesn't stop publishing: once step 6 had deleted the account's pointers, it could publish with `If-None-Match: *`, and step 7 would forget the `subjects/` tombstone as fresh. A suspended account can't publish while the node gates publishing (`[publishing] required = true`, as in production; with it off, a suspension refuses nothing). Lifting the suspension later is the operator's decision to let it publish again.
- Deleting a subject deletes its transitions after its pointers, and step 2 deletes a later one as lost, whatever its age. Before, step 2 kept a transition whose subject had no pointer forever, so a deleted account's history (its recordings and when it dropped them) stayed. Step 7 still counts only pointers as a subject's objects.
- Step 6 reads the whole bucket again before each item, not only the records the item depends on, and decides again. It lists an item's versions before that read and deletes only those, not every version present at delete time, so everything it deletes existed when the read judged the item. It defers an item when any pointer of its requester moved, and keeps an envelope a stored pointer names. Items go subjects, then recordings, then envelopes.
- A push after the drop restarts the drop's grace from the push; it doesn't cancel it, and it doesn't leave the request due. Only a listing cancels a drop.
- Step 7 measures the hour from the tombstone record's S3 write time, not `deletedAt`; only objects a push or publish writes can be fresh, never outboards; and a deleted subject's late pointers don't count for rule 2.
- Stale requests with nothing left are closed (step 6), and the report counts closes apart from deletes.
- Step 4's observed envelopes are reported `observed`; a dry run starts no grace.
- Step 1 refuses keys that aren't canonical, and a transition whose subject's canonical form isn't canonical.

#### 3.5 Timing

A drop's clock is the time of the `PUT` that dropped the entry, recorded in its transition. With a weekly sweep, the drop is folded within 7 days, falls due at publish + 7 days, and is deleted by the first sweep after that: about 14 days worst case. With no backups and version deletion, that is final. *Updated 2026-11-14:* a push after the drop restarts the 7 days from the push (step 6), so a recording pushed again and not listed is deleted at most about 14 days after the push, or 21 days after the drop when the push came within its first 7 days. The operator runs the sweep weekly; nothing runs it automatically, and the promise depends on it.

### Operations

- **Lifecycle rule** (devsecops' proposal, Paul applies): bucket-wide `NoncurrentVersionExpiration` 7 days and `ExpiredObjectDeleteMarker`, keeping the `moderation/sessions/` rule, so overwrites (old pointers, manifests) don't keep old versions forever.
- **Instance role:** `s3:PutObject` on `catalog-transitions/*`, and `s3:GetObject` there for a resend that finds its transition stored (updated 2026-11-14); conditional creates on `moderation/publishers/*`.
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

Also in the contract: pointer `/2` and `indexHash` with the vectors; ownership (first push owns; others' pushes refused); removal (line 174): the stored TDF is deleted 7 to 30 days after the publish that dropped it, re-listing within 7 days cancels, a push after the drop restarts the 7 days (updated 2026-11-14), after deletion re-listing needs a fresh push; a replaced payload is deleted the same way; a superseded envelope is deleted 7 to 30 days after it was replaced; account deletion: publish an empty catalog first. `docs/publishing-and-moderation.md`: ownership on push, the operator commands and procedure, IAM, the lifecycle rule. `CLAUDE.md`: key layout and modules.

## Known gaps (accepted)

- After account deletion through Creator, the pointer and the empty envelope stay.
- A creator whose catalog reads 404 (pre-envelope pointer, blocked envelope, catalog block, `hideCatalog`) gets no requests from an empty-catalog publish; Creator skips it on 404. Operator path on request.
- An account deleted without emptying its catalog keeps owning its recordings, so a new account can't push the same files until an operator runs `release-owner` or `request-deletion`.
- ~~A catalog-blocked creator who isn't suspended gets 412 on `If-None-Match: *` (`PUT` preconditions ignore the owner's hide). Pre-existing, separate fix.~~ *Superseded (2026-11-14): `PUT`'s preconditions now see what `GET` serves, the owner's hide included, so such a creator publishes with `If-None-Match: *` after `GET`'s 404. The catalog stays hidden, and the publish drops nothing (3.1).*
- Recordings hidden before this ships stay stored, also after their creator deletes their account.
- A Hide from a Mac without the archive can be undone only within the 7 days.
- A publish that re-lists a hash between an item's re-check and its delete leaves a listed recording that answers "gone"; the sweep reports it.

## Left to the builder

- Module layout (suggested: `src/ownership.rs`, `src/deletion.rs` for transitions, folding and the sweep's decisions behind a small store trait with an S3 and an in-memory implementation).
- How `TagStore` grows (`MemStore` implements it), and how the push path's owner lookup shares the session lookup's bounds.
- Concurrency limits, report wording, and how to test version listing and batch deletion against S3 (extend the stand-in in `tests/s3_client_test.rs`, or test through the trait).
