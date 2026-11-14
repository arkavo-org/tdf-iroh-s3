# Creator publishing and moderation

This covers [tdf-iroh-s3#17](https://github.com/arkavo-org/tdf-iroh-s3/issues/17). The decisions behind it are recorded on that issue:

- Publishing needs the Arkavo creator-publishing entitlement.
- Pushes are authenticated, not only tag writes.
- Operators can suspend creators and block content.

The settings live under `[publishing]`. The gate is **on by default**.

## Publishing

A publisher's CWT must:

- be verified against the node's key set and `[http] expected_issuer`;
- carry `aud` = `[publishing] audience` (default `arkavo`, the identity.arkavo.net passkey token);
- list `[publishing] entitlement` in `arkavo_entitlements`. The default is `https://patreon.arkavo.com/attr/arkavo-creator/value/publish`, issued by authnz-rs#91;
- name a person, not a service client (`client:*`);
- name a subject that is not suspended.

### Who decides: `[publishing] decisions`

The node always authenticates the publisher (the checks above, except the entitlement). Who decides whether the subject may publish depends on `decisions`:

| Value | Who decides |
|---|---|
| `local` (default) | This node: the entitlement must be in `arkavo_entitlements`. |
| `shadow` | Both. The local answer is enforced, and the decision service's answer is logged next to it (`Publish decision shadow: agrees` / `disagrees`). |
| `pdp` | The platform's decision service at `[catalog.authz] endpoint` (tdf-iroh-s3#35). Its answer replaces the entitlement check. Refusals: deny is 403 `publishing not permitted`; no decision (error, timeout) is 503 `decision service unavailable`. Publishing fails closed. |

**The request.** The node sends one AuthZEN evaluation through the same client as the catalog: action `publish` (not the catalog's `[catalog.authz] action`) on a resource of type `publisher`, carrying `[publishing] entitlement` as its `attribute_value_fqns`. Per draft-arkavo-authzen-cwt-00, the entity chain is:

1. the verified person;
2. each device presented in repeated `X-Entity-Token` headers (DeviceCheck CWTs: `aud` `arkavo:devicecheck`, bound to the person), sent with its CWT as `token` for the platform to verify (arkavo-rs#97). A device token that fails verification is 401 in `pdp`; in `shadow` it only means the decision service isn't asked (`Publish decision shadow: chain refused`); in `local` they are ignored;
3. the environment (`[catalog.authz] environment_region`).

At most 8 entities. The platform withholds the grant from a suspended account, and devices narrow it as its policy says.

**Pushes.** The decision service is asked when a session opens, not for each push (tdf-iroh-s3#44). A session it permitted stores the chain it was decided with, never a token; one it denied or wasn't asked about stores none. A push on a permitted session is accepted until the session expires, at most `session_ttl_secs` later, whatever the platform says in between. So a suspension made at the platform, a device revoked or an entitlement changed stops pushes from the next session; a local suspension or a block stops them at once. A session read back from the store is held at most `session_ttl_secs`, whatever its record's `expiresAt`, and in `pdp` its stored chain's person must be its subject. Since a stored session record alone authorizes pushes, the node tags it with a key only it holds, so write access to the store can't make one (tdf-iroh-s3#46; see below). In `pdp` a push is refused when its session has no stored chain (`NoSession`): it was opened while decisions were local, or is missing or expired.

**Configuration.** `shadow` or `pdp` without a `[catalog.authz] endpoint` is a startup error. Local suspensions still apply in every mode until the platform's suspension check is live. In `shadow` a suspended subject's session request is still asked and logged before the suspension refuses it, so the platform's answer for a suspended account can be checked.

### 1. Open a publish session for the iroh endpoint that will push

The caller must prove it holds the endpoint's key. It signs the following bytes with its iroh secret key (Ed25519, `SecretKey::sign`):

```text
tdf-iroh-s3 publish-session v1\n<endpointId>\n<blake3-hex of the bearer token string>\n<timestamp>
```

`timestamp` is Unix seconds and must be within 300 s of the node's clock. Binding the bearer token means a captured signature can't be reused with another subject's token.

```bash
curl -X POST https://iroh.arkavo.net/publish/sessions \
  -H "Authorization: Bearer <cwt>" -H "Content-Type: application/json" \
  -d '{"endpointId":"<endpoint id>","timestamp":<unix>,"signature":"<128 hex chars>"}'
# 201 {"endpointId":"…","subject":"<sub>","expiresAt":<unix>}
```

A signature that doesn't match `endpointId` returns 403. A stale timestamp or a malformed signature returns 400.

The session lasts `[publishing] session_ttl_secs` (default 900).

- The node accepts iroh pushes only from an endpoint with a live session, and only while its subject is not suspended.
- Any other push is refused with a permission error, and nothing is stored.
- Once a push is ingested, the first pusher's subject is recorded at `moderation/publishers/<hash>`, and a push of another account's recording is refused (see [Ownership](#ownership)).
- Each session is also stored at `moderation/sessions/<endpointId>` as `{"kid", "record", "tag"}`. `record` is `{"endpointId", "subject", "expiresAt"}`, plus `chain` when decisions aren't local (see above). A node that receives a push from an endpoint it holds no session for reads this record (5 s timeout) before refusing. So a session opened on one instance holds for a push that reaches another, during an instance replacement or after a restart (#32). A record that has expired, names another endpoint, can't be read, or can't be fetched in time counts as no session.
- `tag` is the keyed BLAKE3 hash, in hex, of `record`'s exact bytes. The key is derived from the node's secret key (`[iroh] secret_key_param`, shared by every instance and never rotated), and `kid` is the first 8 bytes of the key's BLAKE3 hash, in hex. A record without a tag, tagged by another key, or edited after tagging counts as no session, and the node logs a warning with the endpoint ID only (#46). So records written before #46 are refused once: a session opened on an older node must be opened again on a newer one. A node with an empty `secret_key_param` has a new key each start, so its stored sessions don't survive a restart. At most 16 lookups run at once; a push that finds them all busy is refused. An endpoint whose lookup found no live session is refused for 10 s without another lookup. So a peer without a session can't make the node send S3 a request per push.
- If the node can't store a session, `POST /publish/sessions` still succeeds. The session then holds only on the instance that opened it, and the node logs `Publish session not stored`.
- Session records are overwritten per endpoint and never deleted. An S3 lifecycle rule on `moderation/sessions/` keeps the prefix small: expire objects after 1 day. On a versioned bucket, every overwrite also keeps the old version, so expire noncurrent versions after 1 day as well.

### 2. Publish the catalog

Use `PUT /v2/catalogs/<sub>` ([creator-catalogs.md](creator-catalogs.md)). It requires the entitlement, an unsuspended subject, and content that is not blocked.

### When a membership lapses

When the membership lapses, the entitlement disappears from new tokens (authnz-rs#91). New sessions and tag writes are then refused. Published content stays up until a moderator blocks it.

### Creator app impact

The Creator app must open a session before each push. Until it does, pushes to a gated node are refused. Set `required = false` only on development nodes.

## Ownership

The first account to push a recording owns it. Its owner record is `moderation/publishers/<hash>`, `{"hash","subject","endpointId","at"}` with `subject` in canonical form. It is created only if none exists (`If-None-Match: *`) and never overwritten. On a node with `required = false` no owner is recorded and nothing in this section applies.

- **First push owns.** Once a push is ingested, the node creates the record for the session's subject. If two first pushes race, the first create wins. A create S3 answers 409 (another create of the record still in progress) is sent again, three attempts in all; still 409, it has failed. If the create fails, the node logs it and the recording stays unowned; its next push claims it (that push skips the upload, since the blob is already there).
- **Push refusal.** Before accepting a push, the node reads the hash's owner record, after the session, suspension, block and decision checks. A record naming another subject refuses the push with a permission error. So does a record that can't be read or parsed, or a check over 5 s: the check fails closed. At most 16 owner lookups run at once (a bound of their own, apart from the session lookups'); a push that finds them all busy waits for one, and the wait counts toward the 5 s. A record naming the pusher, or no record, lets the push through.
- **Publish refusals.** `PUT /v2/catalogs/<sub>` reads each listed recording's owner record ([creator-catalogs.md](creator-catalogs.md#put-v2catalogssub-publish)):
  - an entry another account owns: 403 `recording belongs to another account`;
  - else an entry with no owner: 422 `recording has no owner: push it again`, and pushing it again claims it;
  - both carry `contentIDs`, the `contentID` of every entry refused, sorted;
  - an owner record that can't be read or parsed: 502 `storage unavailable`.
- **Pre-check.** `GET /publish/recordings/<hash>` ([creator-catalogs.md](creator-catalogs.md#get-publishrecordingshash-who-owns-a-recording)), authorized as `POST /publish/sessions` and `PUT /v2/catalogs` are, answers `{"hash":"<hash>","owner":"you" | "another account" | "none"}`. It never names the other account. Creator asks it before the passkey prompt, and after a failed push to explain it.

A recording without an owner arises only when its record's create failed, an operator released it, or it predates publish sessions and no catalog listed it at the backfill.

### `claim-owners`: the backfill

Run it before ownership is enforced, so existing catalogs keep publishing. It reads every pointer (`catalog-pointers/`) and every index record (`catalog-indexes/`); a live index is the index record of the catalog a pointer names. For each payload hash a live index lists:

- an owner record names the only account that lists it: owned, nothing to do;
- no record, and exactly one account lists it: claim it, creating the record for that account with `"endpointId":"claim-owners"`;
- more than one account lists it, or the record names an account that doesn't list it: a conflict, reported, nothing written.

Accounts compare in canonical form, so the pointers `arkavo:<uuid>` and `<uuid>` are one account. Hashes no live index lists are left alone: the next push claims them. Anything it can't read or parse (a pointer, an index record, an owner record) stops it before it writes anything.

```bash
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml claim-owners          # dry run
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml claim-owners --write  # creates the records
```

It prints one line per claim (`would claim <hash> <subject>`, or `claimed <hash> <subject>` with `--write`), one per conflict (`conflict <hash>: listed by <a>, <b>; owner <c>`, or `; no owner record`), then the counts (`<n> owned, <n> would claim, <n> conflicts`, with `claimed` under `--write`). It exits 1 if there is any conflict. With `--write` it still claims every hash that isn't a conflict. A record that appears between the read and the create (a push claimed the hash meanwhile) is logged, not claimed; the next run reads it.

The switch waits until the dry run reports no conflicts. To resolve one, whichever applies:

- the record names an account that doesn't list the hash: release it, `release-owner --hash <hash> --subject <owner> --reason <why>` ([`release-owner`](#release-owner));
- more than one account lists the hash: have all but one of them drop it from their catalogs, keeping the account the record names if it names one of them.

Then run the dry run again. Once it reports no conflicts, run it with `--write`, and once the node is deployed, the dry run again.

### `release-owner`

```bash
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml release-owner \
  --hash <hash> --subject <sub> --reason "account deleted, catalog not emptied"
```

It deletes the hash's owner record, every version and delete marker, only if the record names `<sub>` (compared in canonical form). The next push of the recording claims it. Use it for an account deleted without emptying its catalog. `--reason` is required, and printed, not stored.

- Released: `released <hash> from <sub> (<n> versions): <reason>`.
- Not released, exit 1: `not released: <hash> is owned by <owner>, not <sub>`, or `not released: <hash> has no owner record`. A record it can't parse is kept, and the command fails.

### IAM

- **The instance role** needs `s3:PutObject` on `<prefix>moderation/publishers/*` for the owner records' conditional creates (`If-None-Match: *`), and `s3:GetObject` there for the push and publish checks.
- **Operators running `claim-owners` or `release-owner`** need `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObject`, `s3:PutObject` and `s3:DeleteObjectVersion`, and the node's config for the bucket and prefix.

## Moderation (operators)

Operators authenticate with a service CWT:

- `sub = client:<id>`;
- role `service-account`;
- `aud` containing `<id>`;
- `<id>` listed in `[publishing] operator_client_ids`.

The authnz-rs `client_credentials` grant mints such tokens. If the list is empty, these routes answer 503.

| Route | Effect |
|---|---|
| `PUT /moderation/suspensions/{subject}` `{"reason","reportId"?,"hideCatalog"?}` | Refuses the subject's sessions, pushes and catalog publishes. With `hideCatalog`, `GET /v2/catalogs/{subject}` and `GET /catalog-documents/{hash}` for the subject's documents return 404. |
| `DELETE /moderation/suspensions/{subject}` | Lifts the suspension. |
| `PUT /moderation/blocks/{hash}` `{"reason","reportId"?}` | Takedown: iroh pushes of the hash are refused, and so are iroh get and get-many requests for it (a get-many that names it among other hashes is refused whole). Observe requests are always refused. No catalog may list it (403 `content is blocked` on `PUT /v2/catalogs`), and a blocked catalog envelope reads as no catalog (404). |
| `DELETE /moderation/blocks/{hash}` | Lifts the block. |
| `PUT /moderation/blocks/catalogs/{subject}` `{"reason","reportId"?}` | Blocks the creator's catalog: `GET /v2/catalogs/{subject}` returns 404, and so does `GET /catalog-documents/{hash}` for any document the subject owns; iroh fetches of those documents are refused. The moderation client writes one when it suspends a creator (tdf-iroh-s3#35). Stored at `moderation/catalog-blocks/<subject>`. |
| `DELETE /moderation/blocks/catalogs/{subject}` | Lifts the catalog block. |
| `GET /moderation/suspensions`, `GET /moderation/blocks`, `GET /moderation/blocks/catalogs` | Active records. |

```bash
curl -X PUT https://iroh.arkavo.net/moderation/blocks/<hash> \
  -H "Authorization: Bearer <service cwt>" -H "Content-Type: application/json" \
  -d '{"reason":"hate speech","reportId":"6f9619ff-8b86-d011-b42d-00c04fc964ff"}'
```

Subjects compare in canonical form: `arkavo:<id>` and a bare `<id>` are the same account.

### Audit

Each suspension, block or catalog block is stored as a JSON object under `moderation/suspensions/<subject>`, `moderation/blocks/<hash>` or `moderation/catalog-blocks/<subject>`. The object records who set it, when, why and the report ID.

- Lifting one sets `liftedBy` and `liftedAt` instead of deleting it.
- Those objects hold only the current state, so every suspend, block and lift also writes an immutable event under `moderation/audit/<suspensions|blocks|catalog-blocks>/<key>/<ns timestamp>`, as `{"action", "record"}`. A re-suspension or re-block never loses the earlier record.
- Each change is also logged with an `audit` field.

### Propagation

- Records are read before the node starts, and **startup fails if they cannot be read**.
- They are then re-read every `moderation_refresh_secs` (default 30), so changes made through another node, or directly in S3, apply without a redeploy.
- A failed refresh keeps the last view, so a storage error never lifts a suspension.

### Not included

- **Deleting stored bytes on a block.** A block stops distribution and keeps the blob, its outboard and its manifest in S3 while it stands. To delete a blocked recording, an operator runs `request-deletion --hash`, then the sweep ([Deletion requests](#deletion-requests-operators)). A blocked catalog envelope is kept until its block is lifted.
- **Resolving a report's `contentId` to hashes.** That waits for the frozen catalog schema, so a takedown names payload hashes.
- **Consuming arkavo-rs's NATS `moderation.actions.*` events.** That NATS is not reachable from EC2. arkavo-rs or a moderator calls this API.

## Deletion requests (operators)

A recording its owner drops from their catalog is deleted from S3, every version, within 30 days of the publish that dropped it. So is a superseded catalog envelope, which carries every entry's metadata TDF, titles included. The creator's passkey-signed publish is the request; an operator-run sweep does the deleting. What Creator sees is in [creator-catalogs.md](creator-catalogs.md#removing-a-recording). The design is `docs/superpowers/specs/2026-11-13-deletion-requests-design.md`.

### What a publish records

Hide from Catalog publishes the catalog without the entry, and an account deletion through Creator publishes an empty one; there is no other deletion route. Each `PUT /v2/catalogs/<sub>` writes a transition at `catalog-transitions/<sub>/<seq, 20 digits>-<pointer digest>` (`<sub>` as in the pointer key; never served), after the envelope's index record and before the envelope, its outboard and the pointer ([write order](creator-catalogs.md#put-v2catalogssub-publish)):

```json
{"subject":"<sub>","seq":8,"catalogHash":"<new>","pointer":"<digest>","base":{"seq":7,"catalogHash":"<old>","pointer":"<digest>"},"at":<unix secs>,"dropped":["<hash>"],"added":["<hash>"]}
```

- `base` is the stored pointer the publish replaces, `null` when there was none. `pointer` digests are the SHA-256 of the signed pointer bytes.
- `dropped`: the recordings in the served base's index that the new index doesn't list, less those blocked at the time and those whose owner record doesn't name the publisher. A base `GET` doesn't serve (its envelope blocked, its owner catalog-blocked or suspended with `hideCatalog`, a pointer from before envelopes) drops nothing.
- `added`: the recordings the new index lists and the base's index doesn't.

The publish writes no request. The sweep acts only on a committed transition, one reachable from a current pointer through `base` links. The pointer write is conditional on the base, so a publish that lost the race leaves a transition nothing reaches. The transition is created only if none is under its key (`If-None-Match: *`), and its key names one signed pointer. A resend of the same publish over the same base, a retry or a duplicate sent while the first was in flight, keeps the transition already there, its `at` and `dropped` included, so it can't rewrite one the first commits. The same pointer sent over a newer base (a higher `seq`, no base counting as 0: its first attempt lost the race) replaces the transition, only if it is unchanged since read (`If-Match`; otherwise 502), so the transition a committed pointer reaches names its real base. A publish that stalled and resumes over an older base than the stored transition's keeps that transition and answers 502 `storage unavailable`: it can't put its stale base back.

### The grace and the weekly sweep

A dropped recording falls due 7 days after the publish that dropped it, and a superseded envelope 7 days after it was replaced. A publish that lists the recording again before then cancels the request. The first sweep after a publish folds its transition, and the first sweep once a request is due deletes it. With a weekly sweep that is about 14 days at worst.

**The 30-day promise depends on running `sweep-deletions --delete` at least weekly.** Nothing runs it automatically.

### Commands

Each command needs the node's config (`--config`, for the bucket and prefix) and operator credentials ([IAM for deletion](#iam-for-deletion)). Subjects compare in canonical form: `arkavo:<uuid>` and `<uuid>` are one account, and request keys carry `<uuid>`.

| Command | Use |
|---|---|
| `sweep-deletions [--delete]` | Weekly: fold transitions into requests and delete what is due. A dry run without `--delete`. |
| `request-deletion --subject <sub> (--hash <hash>... \| --all) --reason <text>` | What the publish path can't request: blocked recordings, and everything a creator who can't publish published. |
| `claim-owners [--write]` | The ownership backfill, before the switch: [`claim-owners`](#claim-owners-the-backfill). |
| `release-owner --hash <hash> --subject <sub> --reason <text>` | Free a recording owned by an account deleted without emptying its catalog: [`release-owner`](#release-owner). It deletes only the owner record; `request-deletion` deletes the recording too. |

#### `sweep-deletions`

```bash
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml sweep-deletions           # dry run: reads and reports
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml sweep-deletions --delete  # writes and deletes
```

A run:

1. **Reads strictly** every pointer, index record, transition and deletion request, and the suspensions, blocks, catalog blocks and owner records it decides on (not sessions or audit records). Anything it can't read or parse aborts the run before it writes anything: exit 1, with `sweep-deletions aborted: <error>`, naming the key, on stderr. So does a `/2` pointer whose index record doesn't match its `indexHash`, and a moderation record whose key isn't what the node writes: a canonical subject (`<uuid>`, not `arkavo:<uuid>`) for a suspension or catalog block, 64 lowercase hex characters for a block.
2. **Folds** each pointer's committed transitions into requests, oldest first: a dropped hash makes `recordings/<sub>/<hash>` pending from that publish's time (the newest drop wins), an added hash cancels it, and a replaced envelope makes `envelopes/<hash>` pending. The folded transitions are deleted. A transition no pointer reaches, older than 7 days, whose subject's pointer has a `seq` at least its own, lost its publish and is deleted unfolded (`deleted transition <sub>/<name>: lost its publish`); any other unreachable one is kept and reported.
3. **Observes** envelopes: a hash under `catalog-documents/`, `catalog-outboards/` or `catalog-indexes/` that no pointer names and no request tracks gets an `envelopes/` request, superseded now.
4. **Deletes** what is due (below), with `--delete`, item by item: subjects (their pointers), then recordings, then envelopes. Just before each item it reads everything again. An item no longer due is kept. One whose requester's catalog moved since the first read is deferred to the next run, which folds the new transitions first. A failed item stays pending for the next run, and the run goes on.
5. **Verifies tombstones.** A deleted item's request stays, marked `deleted` with `deletedAt`, until a run at least an hour later checks its objects. The hour counts from when the tombstone was written, by S3's clock (the request's last-modified time), not from `deletedAt`, which is the run's start on the operator's clock: a long run deletes items well after it starts.
   - an object a new push or publish writes, written more than an hour after the tombstone, is fresh: a recording's blob, manifest or owner record, an envelope's document or index record, a subject's pointer. The tombstone goes, and the objects stay. An outboard never counts: the node writes one itself when it serves a blob or envelope that lacks it;
   - a recording listed again, or an envelope current again: the tombstone goes, the objects stay;
   - any other object (one written within that hour, by a write in flight during the delete, or an outboard): deleted again (`recreated`), and the tombstone stays;
   - nothing left: the tombstone goes.

The requests live under `deletion-requests/`, written only by the sweep and `request-deletion`, subjects canonical. Below, *listed* means in the live index of any pointer, whatever its catalog's visibility, except the pointers of an account being deleted (a pending `subjects/` request whose catalog block stands).

| Request | Body | Due |
|---|---|---|
| `recordings/<sub>/<hash>`: the owner dropped it | `{"hash","subject","requestedAt","seq","state","deletedAt"?}` | 7 days after the drop, while the hash isn't listed or blocked and its owner record names `<sub>` |
| `operator/<sub>/<hash>`, scope `hash` | `{"hash","subject","requestedAt","reason","scope","state","deletedAt"?}` | while the hash's block stands: at once, listed or not, whoever owns it |
| `operator/<sub>/<hash>`, scope `subject` | as above | while `<sub>`'s catalog block stands, the hash isn't listed or blocked, and its owner record names `<sub>` |
| `subjects/<sub>` | `{"subject","requestedAt","reason","state","deletedAt"?}` | while `<sub>`'s catalog block stands |
| `envelopes/<hash>`: superseded | `{"hash","owner"?,"supersededAt","source","state","deletedAt"?}` | 7 days after it was superseded, while no pointer names it (other than an account's being deleted), it isn't blocked, and its owner's catalog isn't hidden (catalog block or `hideCatalog`), unless an operator asked for everything that owner published (`subjects/<owner>`, pending or deleted) and the owner's catalog block still stands |

`state` is `pending` or `deleted`; `source` is `transition` or `observed`. A recording whose owner record names another account, or that has none, is kept for manual handling, and so is an envelope whose owner is unknown.

Deleting removes every version and delete marker of:

- a recording: `blobs/<hash>` first, so nothing is served once anything is gone, then `outboards/<hash>`, `manifests/<hash>` and `moderation/publishers/<hash>`. Ownership ends: the next push claims the recording.
- a subject: each of its pointers, under either key (`catalog-pointers/arkavo:<uuid>`, `catalog-pointers/<uuid>`). Its envelopes are no longer current, so the same run records them, and they are due 7 days later.
- an envelope: `catalog-documents/<hash>`, then `catalog-outboards/<hash>` and `catalog-indexes/<hash>`.

Then the request is marked `deleted`. Suspension, block, catalog-block and audit records are never deleted.

**Output,** on stdout:

- one line per transition that lost its publish: `deleted transition <sub>/<name>: lost its publish` (`would delete` in a dry run), not counted;
- one line per due item, in the order taken: `deleted <item>` (`would delete` in a dry run), `kept <item>: <why>`, `deferred <item>: catalog changed`, `failed <item>: <error>`;
- one per tombstoned item checked: `verified <item>`, `fresh <item>`, `listed again <item>`, `current again <item>`, `recreated <item>`, or `kept <item>: <why>` (in a dry run `would verify <item>`, `would forget <item>: <why>`, `would delete again <item>`);
- `kept <request>: <why>` for each pending request not due, and `kept transition <sub>/<name>: <why>` for each transition kept;
- `deleted recording <hash> is listed again` or `deleted envelope <hash> is current again` for a deleted item a catalog names again, or `failed final read: <error>` if the read for these lines fails (a failure, counted: every delete is done by then);
- last, the counts: `<n> deleted, <n> kept, <n> deferred, <n> failed` (`would delete` in a dry run).

A run that aborts after its first read (a fold write fails, or a re-read before an item or for the tombstones) prints the lines of what it did until then, without counts, then `sweep-deletions aborted: <error>` on stderr.

An `<item>` is `recording <hash>`, `subject <sub>` or `envelope <hash>`; a `<request>` is `recording <sub>/<hash>`, `operator <sub>/<hash>`, `subject <sub>` or `envelope <hash>`. A `<why>` is one of `within grace`, `still listed`, `still current`, `blocked`, `owner is not the requester`, `no owner record`, `block lifted`, `catalog block lifted`, `owner hidden`, `unknown owner`, `no longer due`, `a pointer still names it`, `envelopes pending`, `catalog changed`; a transition's is `younger than grace`, `seq above the current pointer`, `no pointer` or `a cycle in its chain`. It exits 1 if the run aborts, any item failed, or the final read failed.

**Running it.**

- Run only one `sweep-deletions` at a time: two runs would fold, write, delete and verify the same records at once.
- A `--delete` run reads the whole bucket again before each due item (16 records at a time), so it costs about one full read per due item. A dry run reads it about twice.
- When a run reports `deferred`, run it again promptly: the requester published during the run, and the next run folds that publish first. A deferred item isn't deleted before then, and that wait counts against the 30 days.

#### `request-deletion`

```bash
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml request-deletion \
  --subject <sub> --hash <hash> <hash> --reason "takedown, report 6f9619ff"
tdf-iroh-s3 --config /etc/tdf-iroh-s3/config.toml request-deletion \
  --subject <sub> --all --reason "account closed; the creator can't publish"
```

Exactly one of `--hash` and `--all` (both or neither is a usage error: exit 2). `--reason` is required and stored in each request. It reads the bucket as strictly as the sweep, and checks every precondition before it writes anything:

- **`--hash`:** recordings only. Every hash, 64 lowercase hex characters, must have an active block and must not be a catalog envelope's (one with an object under `catalog-documents/`, `catalog-outboards/` or `catalog-indexes/`): `<hash> is a catalog envelope: --hash deletes recordings only`. It writes `deletion-requests/operator/<sub>/<hash>` with scope `hash` for each, due at once while the block stands. Scope `hash` doesn't check the owner; file it under the recording's owner. To delete a recording that isn't blocked, block it first (`PUT /moderation/blocks/<hash>`).
- **`--all`:** the subject must have an active catalog block. It writes a scope-`subject` `operator/<sub>/<hash>` for every hash in the live index of each of the subject's pointers (either key) and every hash whose owner record names the subject, then `deletion-requests/subjects/<sub>`, which deletes the subject's pointers. That is its whole coverage, and its last line says so.

It prints one line per key:

- `requested <key>: <reason>`: a new pending request;
- `exists <key>`: a pending request was already there, and is left as it was;
- `requested <key> (replaces a deleted request): <reason>`: the item was deleted and its tombstone not yet verified; asking again replaces it;
- `requested <key> (replaces a pending scope-subject request): <reason>`, from `--hash`: scope `subject` never deletes a blocked hash, so the request becomes scope `hash`. From `--all`, `(replaces a pending scope-hash request)`: the hash's block was lifted, so scope `hash` would never delete it.

`--all` then prints `coverage: live indexes and owner records; add --hash for anything else`. A refusal (an invalid argument, an unreadable record, a catalog envelope's hash, a hash without an active block, a subject without an active catalog block) comes before any write: it prints the error on stderr, writes nothing, and exits 1. A storage error partway through the writes also exits 1, with the error on stderr, but the requests written before it stay, unprinted, and the next sweep reads them; run the command again, and it reports them as `exists`. Operator requests have no grace: the next `sweep-deletions --delete` deletes them.

### Moderation keeps blocked content

The privacy policy excepts content removed by moderation: a blocked recording or envelope is kept while its block stands. A takedown makes the creator drop the hash (`PUT` refuses a catalog that lists it), and that forced drop is not a request. An owner's earlier drop of a hash blocked since, and a scope-`subject` request, wait while the block stands (`kept …: blocked`). Only `request-deletion --hash` deletes a blocked recording, and only while its block stands. A blocked envelope has no such path: it stays until its block is lifted. A report alone holds nothing back.

### Creators who can't publish

A creator whose entitlement lapsed, who is suspended, or whom the decision service denies can't publish the empty catalog that deletes their recordings. A creator whose catalog is blocked can publish, with `If-None-Match: *` after `GET`'s 404, but the publish drops nothing: `GET` hides the base, and a base it doesn't serve drops nothing ([What a publish records](#what-a-publish-records)). On their request, an operator:

1. **Blocks their catalog,** unless it is already: `PUT /moderation/blocks/catalogs/<sub>` ([Moderation](#moderation-operators)). This hides the catalog at once and is `--all`'s precondition. Keep it until the sweep is done, envelopes included (step 4): while it is lifted, every request waits (`catalog block lifted`), and an envelope of the subject's that a `hideCatalog` suspension still hides is kept (`owner hidden`).
2. **Runs `request-deletion --subject <sub> --all --reason <why>`.**
3. **Adds what `--all` doesn't delete** with `request-deletion --subject <sub> --hash <hash>...`, blocking each hash first if it isn't: the subject's blocked recordings, which scope `subject` keeps, and anything of theirs outside its coverage, such as a recording no live index lists that has no owner record. Scope `hash` doesn't check the owner, so make sure each hash is the subject's: a recording whose owner record names another account is not theirs to delete.
4. **Runs `sweep-deletions`, then `sweep-deletions --delete`.** That run deletes the subject's pointers and recordings and records its envelopes, which the first sweep at least 7 days later deletes.

### Known gaps

- After an account is deleted through Creator, its pointer and empty envelope stay: nothing tells the node.
- An empty-catalog publish requests nothing for a creator whose catalog reads 404 (a pointer from before envelopes, a blocked envelope, a catalog block, `hideCatalog`), and Creator skips it on a 404. On request, follow [Creators who can't publish](#creators-who-cant-publish).
- An account deleted without emptying its catalog keeps owning its recordings, so a new account can't push the same files until an operator runs `release-owner` or `request-deletion`.
- Drops before this shipped are not requests: recordings hidden then stay stored, also after their creator deletes their account. On request, use `request-deletion`.
- A creator who hides from a Mac without the recording's archive can undo the Hide only within the 7 days: afterwards re-listing needs a push.
- A publish that lists a hash again between an item's re-check and its delete leaves a listed recording that answers as gone. The sweep reports it: `deleted recording <hash> is listed again`.
- A blocked envelope is kept while its block stands: `request-deletion --hash` refuses an envelope's hash, and the sweep holds a blocked envelope (`kept envelope <hash>: blocked`).
- Not deleted at all: recordings pushed but never listed, outside `request-deletion`; leftovers of removed features other than envelopes (`/1` tags, `catalog-index/`, `campaign-creators/`); copies outside the node (what viewers or peers already fetched, the KAS, identity, CloudWatch logs).

### IAM for deletion

- **The instance role** needs `s3:PutObject` and `s3:GetObject` on `<prefix>catalog-transitions/*`: without `s3:PutObject` every publish answers 502 `storage unavailable`, and without `s3:GetObject` so does every resend of a publish whose transition is already stored. Its conditional creates on `moderation/publishers/*` are under [IAM](#iam).
- **Operators** running any of the four commands need `s3:ListBucket`, `s3:ListBucketVersions`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` and `s3:DeleteObjectVersion` on the bucket, under the prefix.

### The lifecycle rule

The sweep deletes every version of what it deletes, but an overwrite keeps the old version: old pointers, manifests, request records. So the bucket's lifecycle configuration expires noncurrent versions after 7 days and removes expired delete markers, bucket-wide, beside the existing 1-day rule on `moderation/sessions/` ([Publishing](#1-open-a-publish-session-for-the-iroh-endpoint-that-will-push)). A put replaces the whole configuration, so read the current one first and keep the sessions rule exactly as `get` returns it; the second rule below only stands in for it:

```bash
aws s3api get-bucket-lifecycle-configuration --bucket <bucket>
aws s3api put-bucket-lifecycle-configuration --bucket <bucket> --lifecycle-configuration file://lifecycle.json
```

```json
{
  "Rules": [
    {
      "ID": "noncurrent-versions-7d",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
      "Expiration": {"ExpiredObjectDeleteMarker": true}
    },
    {
      "ID": "<the existing moderation/sessions/ rule>",
      "Status": "Enabled",
      "Filter": {"Prefix": "moderation/sessions/"},
      "Expiration": {"Days": 1},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 1}
    }
  ]
}
```

With an `[s3] prefix`, the sessions rule's `Prefix` starts with it.

### Switch day

Ownership, pointer `/2` and deletion ship as three PRs that merge and deploy together: a deploy of ownership alone would refuse every publish until `claim-owners --write` had run. In order:

1. **ArkavoKit release:** reads pointer `/1` and `/2`, writes `/2`. Its `CatalogPublishRequest` refuses a `/2` whose `indexHash` doesn't match its catalog.
2. **A viewer build that accepts `/2`** reaches users, or a patch to the viewer's own pointer parser.
3. **Before the deploy,** with operator credentials and the new binary:
   1. Against a scratch versioned bucket, never production: `TDF_IROH_S3_VERSIONED_BUCKET=<scratch bucket> AWS_REGION=<region> cargo test --test s3_versioned_test -- --ignored --nocapture` passes. With either variable unset, every test passes without touching S3 and prints `<test> skipped: set TDF_IROH_S3_VERSIONED_BUCKET and AWS_REGION` (shown only with `--nocapture`). A run that prints it proves nothing.
   2. `claim-owners` reports no conflicts; then `claim-owners --write`.
   3. `sweep-deletions` (a dry run) on production completes: no unreadable record. Time it: a `--delete` run costs about one full read per due item, and a dry run about two full reads.
   4. The instance role has `s3:PutObject` and `s3:GetObject` on `catalog-transitions/*` ([IAM for deletion](#iam-for-deletion)). The lifecycle rule can go on any time.
4. **Deploy the node with no overlap:** no instance running the old code serves after a new one does. An old instance would overwrite owner records and accept `/1` publishes that write no transition, which breaks the chain the sweep follows. Then run `claim-owners` (a dry run) again. From here `/1` publishes get 422 `invalid bundle: pointer schema must be "arkavo.catalog-pointer/2"`, so Creator rc.2 and earlier TestFlight builds can't publish, update or hide.
5. **The Creator release that publishes `/2` ships.** Before the switch, test it against a node running this version outside production.
6. **The operator schedules `sweep-deletions --delete` weekly** from then on, for example in the deploy runbook: nothing in the node runs it. The first `--delete` run after the switch records every envelope superseded before it, each carrying its entries' metadata TDFs, titles included (no transition named them, so the run observes them). The first run 7 or more days later deletes them all in one wave.

## Configuration

```toml
[publishing]
required = true                    # false: open pushes and tag writes (development only)
entitlement = "https://patreon.arkavo.com/attr/arkavo-creator/value/publish"
audience = "arkavo"                # "" disables the audience check
session_ttl_secs = 900
operator_client_ids = ["moderation"]
moderation_refresh_secs = 30
decisions = "local"                # local | shadow | pdp (needs [catalog.authz] endpoint)
```

The node's IAM role needs `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on `<prefix>moderation/*`, which includes `moderation/audit/` and the conditional creates of `moderation/publishers/` (see [IAM](#iam)), and `s3:PutObject` and `s3:GetObject` on `<prefix>catalog-transitions/*` (see [IAM for deletion](#iam-for-deletion)).
