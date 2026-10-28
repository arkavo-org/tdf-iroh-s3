# Catalog schema `/2`: per-entry TDF metadata, token-gated name resolution

**Status:** amended 2026-10-27 (owner, tdf-iroh-s3#38 and #39 comments of that day); implemented in tdf-iroh-s3#49. The amendment below supersedes the 2026-10-25 design where they differ; the rest stands.
**Issue:** tdf-iroh-s3#39, tracked in #38 (design and owner decisions there).
**Read at:** `main` `bd97825`.

## Third amendment, 2026-10-27 (owner; Creator and arkavo-ios agreed)

**The clear campaign listing is gone.** `GET /catalog/{group}` listed every recording pushed under a campaign attribute, from any publisher, ignored the creator's catalog (an entry taken out stayed listed) and had no titles. It, its `catalog-index/` and `[http] catalog_token` are removed. The `creator` it returned to entitled readers moves to `GET /v2/campaigns/{id}` → `{"creator"}`: a token, then the decision on the campaign's FQN (before the lookup), then `campaign-creators/<id>`, which only the campaign's own creator's publish writes. A viewer that holds a campaign reads its recordings from the creator's catalog. `docs/creator-catalogs.md` has the contract.


**Metadata TDFs travel inside the envelope.** A document entry is `{contentID, version, payloadHash, payloadSize, metadata}`, `metadata` being the base64url of the entry's metadata ZTDF (at most 65 536 bytes). There are no metadata blobs: the node ingests none, and `metadataHash`/`metadataSize` and their rules are gone. A viewer reads a catalog with one fetch instead of 1 + N.

**The metadata check moves to Creator.** The node never sees a metadata TDF, so it can't check its policy against the recording's; Creator runs ArkavoCatalog's pre-publish check on the actual bytes. A creator who got it wrong would only show their own entry's title to more of their own patrons. The index is exactly `{contentID, version, payloadHash, payloadSize}` per entry, and the node checks only the recordings: not blocked, ingested at size, manifest stored, and the envelope's attribute in each policy.

**Caps.** The envelope and the pointer's `catalogSize` are 1–4 194 304 bytes (4 MiB), room for 1000 entries with typical 3–4 KB metadata TDFs; the `PUT /v2/catalogs` body is at most 10 MiB (a 4 MiB envelope is about 5.6 MiB in base64url). The pointer stays `arkavo.catalog-pointer/1`: it still names bytes by hash and size.

Supersedes, below: the per-entry metadata checks, D2 (`metadataSize`), D3 (metadata blobs kept out of `GET /catalog/{group}`; ingest still skips that type) and the 524 288 and 2 MiB limits.

## Amendment, 2026-10-27

**The catalog document is itself a TDF.** The `/2` document is the payload of one ZTDF, the envelope, under exactly one attribute: the creator's Patreon campaign value, or for a creator without a campaign `https://arkavo.net/attr/creator/value/<sub>`. Every entry's recording policy names that attribute, so a viewer who can open an entry can open the catalog. The pointer's `catalogHash`/`catalogSize` are over the envelope's bytes.

**The node checks what it can't read through an index.** `PUT /v2/catalogs/{sub}` takes `{document, bundle, index}`; `index` is the clear entry list, checked with the per-entry checks of the 2026-10-25 design plus the invariant, stored at `catalog-indexes/<hash>` and never served. Moderation reads it.

**Resolution asks for a decision.** `GET /v2/catalogs/{sub}` verifies the token, then asks the `[catalog.authz]` decision service whether the subject may open the envelope's attribute (one `catalog_item` resource, id the catalog hash, action `read`): 403 `not entitled to catalog` on deny, 502 `decision unavailable` without an answer. Service CWTs skip the decision: an operator's, admitted as the moderation API admits one (allowlisted in `[publishing] operator_client_ids`, `aud` naming the client, role `service-account`), so no other service client the IdP issues reads every creator's pointer.

**`/1` is removed outright** (owner, 2026-10-27): no dual-write or staged cutover, since only TestFlight users exist. `PUT /catalogs/{sub}` and the tag routes go with it, and so do `accept_catalog_schema_1`, `tag_prefix` and `purge-catalogs-1`.

Decided in the implementation, each recorded in `docs/creator-catalogs.md`:

- **No token, no catalog, in either `catalog_token` mode.** The decision needs a subject; serving a request without a token would let any client skip the 403 by dropping it. `catalog_token` now applies only to `GET /catalog/{group}`, which is unchanged.
- **The request may be 2 MiB,** not 1: the index repeats the document's entries, so a 524 288-byte envelope (about 700 KiB in base64url) plus a 1000-entry index (up to about 500 KiB) doesn't fit in 1 MiB.
- **A pointer at a catalog with no index record reads as none.** Pointers stored before envelopes name `/1` documents. `GET` answers 404 for them, and `PUT` treats them as no stored pointer for `seq` and preconditions, so a creator's first envelope may start at any `seq`; the conditional write still replaces exactly that pointer. Deleting the old `/1` objects is then hygiene, not a cutover step.
- **The envelope rules match ArkavoKit's ArkavoCatalog 0.9.1,** so a Creator publish its local check passes isn't refused, and each names only attributes the platform grants: the campaign id is one or more digits (the Patreon entity resolution grants only `^[0-9]+$`), the creator value is the subject byte for byte and must be a bare lowercase account UUID (identity grants `creator/value/<arkavo_account_id>`), the one `dataAttributes` element is read by its `attribute` string (opentdf-rs's structured form is refused), the policy `uuid` is non-empty and `dissem` empty or absent. The invariant reads each recording's attributes in either form.
- **`metadataSize` is at most 65 536** (D2), the iOS viewer's limit.
- **Each metadata policy `uuid` is non-empty and unique within the document:** the viewer unwraps every metadata TDF in one bulk rewrap, and the platform's KAS skips an entry without a policy id and refuses duplicates.
- **Campaign → creator (owner, 2026-10-27).** A campaign envelope is published only by that campaign's creator, as identity asserts it in the token (`arkavo_patreon` role `creator`, `campaign_id` equal to the envelope's; else 403 `catalog campaign is not the publisher's`), and the node then records `campaign-creators/<id>` → `sub`. `GET /catalog/<id>` names it (`creator`) to a reader the PDP entitles to the campaign FQN, so arkavo-ios can find `/v2/catalogs/<sub>` without the token listing memberships. Identity keeps `{role, campaign_id}` in creator tokens, or warns first, if Patreon claims leave tokens.
- **Shared vectors.** ArkavoKit's `index` and `pointer` vectors run against the node's parsers (`tests/fixtures/arkavo-catalog-vectors.json`).

## Problem

A creator's catalog is public. With no token, `GET /tags/catalog/<sub>` and then `GET /catalog-documents/<hash>` return every entry's title, publish time and policy attributes. The recordings are TDF-protected; the catalog that lists them isn't.

## Decisions (owner, 2026-10-25, from #38)

1. Per entry, like the content: each entry's title, `publishedAt` and attributes move into a small standard ZTDF under the recording's own policy. Not NanoTDF.
2. The node never decrypts. It checks the metadata TDF's clear manifest against the recording's.
3. A token is required only on routes that resolve a `sub` to a hash. Fetches by hash stay open, over HTTP and iroh.
4. Cutover: refuse `/1`, then delete the stored `/1` documents and outboards.

## Design

### Schema `arkavo.creator-catalog/2`

```json
{ "schema": "arkavo.creator-catalog/2", "owner": "<sub>",
  "entries": [ { "contentID": "rec-…", "version": 2,
                 "payloadHash": "<blake3>", "payloadSize": 7342067,
                 "metadataHash": "<blake3>", "metadataSize": 2148 } ] }
```

- `creator_catalog::parse` reads `schema` first, then parses the `/1` or the `/2` shape, each strict (unknown and duplicate keys rejected). Both yield one `CreatorCatalog` whose entries carry `content_id`, `version`, `payload_hash`, `payload_size` and, for `/2`, `metadata: Some { hash, size }`. Nothing on the node reads `/1`'s title, `publishedAt` or `attributeFQNs` beyond validating them.
- `/2` entry rules, beyond `/1`'s for the shared fields:
  - `metadataHash`: 64 lowercase hex; unique within the document; never equal to any entry's `payloadHash`.
  - `metadataSize`: an integer from 1 to `MAX_METADATA_SIZE` = 65 536 (D2), the iOS viewer's limit (arkavo-ios cfb048d), so the node accepts no entry the viewer would hide. The FQNs appear twice, in the encrypted payload and base64-encoded in the clear policy; an opentdf-rs metadata TDF at every entry limit (32 FQNs of 512 bytes, a 512-byte title of characters JSON escapes, a 256-byte contentID, one KAS) measures 43 042 bytes. The cap also keeps a recording from standing in for metadata.
- **Size (D1).** A compact `/2` entry is about 290 bytes with a 36-byte contentID, so 1000 entries need about 290 000 bytes. `/2` documents may be up to **524 288** bytes. `/1` keeps 262 144, because `/1` readers in the field enforce it and a document the node accepts must never be one a viewer rejects. The upload body is read up to 524 288 and a `/1` document over 262 144 is refused with today's 413 `catalog too large`.
- Error strings follow today's form, `invalid catalog: entries[<i>].<reason>`, e.g. `entries[3].metadataHash duplicates entries[1].metadataHash`, `entries[2].metadataHash equals entries[0].payloadHash`.

### Publish checks for `/2`

Run by `PUT /catalogs/{sub}`, `PUT /v2/catalogs/{sub}` and `PUT /tags/catalog/{sub}` (a rollback passes the same checks as an upload), extending `check_payloads`. In order, so each status keeps its meaning:

1. **Blocked** (403 `content is blocked`): any `payloadHash` or `metadataHash` is blocked.
2. **Ingested and sized** (422): as today for payloads; then for metadata, `metadata <hash> is not ingested` and `metadata <hash> size does not match`.
3. **Manifests** (422): both manifests are read from `manifests/<hash>` (written at ingest). A missing one is `payload <hash> manifest is not stored` or `metadata <hash> manifest is not stored`; ingest says to re-push to repair, and so does the contract.
4. **Minimal policy** (422 `metadata <hash> policy may only hold uuid and body`): the metadata manifest's decoded policy has exactly the top-level keys `uuid` and `body`. Manifests are readable by anyone holding the hash, so anything else (`arkavo:classification`, `arkavo:components`) is refused.
5. **Metadata type** (422 `metadata <hash> is not catalog metadata`, D3): the manifest's `payload.mimeType` is `application/vnd.arkavo.catalog-entry+json`.
6. **Policy match** (422 `metadata <hash> policy does not match payload <hash>`):
   - `body.dataAttributes`: equal as sets of JSON values (order ignored, each entry compared whole, so the spec form and opentdf-rs's structured form are both compared exactly);
   - `body.dissem`: equal as sets (absent and `[]` are the same);
   - KAS: the sets of `encryptionInformation.keyAccess[].url` are equal.
7. **Policy ids** (422 `metadata <hash> policy has no uuid`, `metadata <hash> policy uuid duplicates metadata <hash>`): each metadata policy's `uuid` is a non-empty string, unique within the document. A viewer unwraps a catalog's metadata in one bulk rewrap (`UnsignedRewrapRequest.requests`, one entry per policy); the platform's KAS skips an entry with no policy id and refuses duplicate ids (`service/kas/access/rewrap.go`, opentdf-platform 8f95f8de). A missing id is refused right after check 4, and duplicates after check 6, in entry order.

Distinct hashes are looked up once, at most 16 at a time, as today. Storage failures are 502 `storage unavailable`. A new `TagStore::get_manifest` reads `manifests/<hash>`.

### Metadata blobs and the group index (D3)

A metadata TDF carries the recording's attributes, so ingest indexes it under the same `catalog-index/<group>/`, and `GET /catalog/{group}` lists it next to the recording. Its policy holds only `uuid` and `body`, so nothing in it says "metadata". **Decided (owner, 2026-10-25): (a).** Per the Creator session's read of ArkavoMediaKit (not checked against Creator's pinned revision), its manifest builders already take a `mimeType`, and recordings, through the FairPlay key envelope, carry `application/json`. The two options were:

- **(a) mimeType, a Creator contract change.** Creator sets the metadata manifest's `payload.mimeType` to `application/vnd.arkavo.catalog-entry+json`. Ingest doesn't index a blob of that type, and check 5 requires it. The type reveals only that a blob is catalog metadata.
- **(b) Node only.** At catalog publish the node already holds each metadata manifest (check 3). It derives that blob's groups and deletes `catalog-index/<group>/<metadataHash>`. No Creator change, but the listing shows the metadata blob between its ingest and the catalog publish, plus the listing cache TTL.

### Token on name resolution

New `[http] catalog_token = "optional" | "required"`, default `optional`.

- Routes: `GET /tags/catalog/{sub}` (only tags under the catalog prefix; other tags are unchanged), `GET /v2/catalogs/{sub}`, `GET /catalog/{group}`.
- `optional` (D4): no token is served as today. A presented token must verify (401 `invalid token`), as `GET /catalog/{group}` already does, so clients find a bad token before `required`.
- `required`: no token is 401 `token required`.
- **The token check runs first,** before `catalog_hidden`, blocks and the 404, so a caller without a token can't probe which subjects have catalogs.
- Accepted tokens: exactly what `GET /catalog/{group}` accepts as a bearer today (`CwtVerifier::verify`: signature, issuer, expiry; no audience pin), so person and service CWTs (`arkavo-moderation`) count. No special case for DeviceCheck CWTs: one grants nothing here beyond what a hash already does.
- `GET /catalog/{group}` keeps its chain handling; `required` refuses its anonymous case.
- **Caching.** These responses are now per-caller, so they are sent `Cache-Control: private, max-age=300` instead of `public` (today `GET /v2/catalogs` reuses the document's `public` header). `/catalog-documents/{hash}` stays `public`.
- Unchanged and open: `GET /catalog-documents/{hash}`, `GET /blobs/{hash}`, `GET /node`, every iroh fetch (catalog documents keep being served over iroh, arkavo-ios ADR-0061).

### Cutover

- New `[http] accept_catalog_schema_1 = true` (default; `[http]` holds the catalog routes' settings, `[catalog]` the group index). Set to `false` once Creator publishes `/2`: `PUT /catalogs`, `PUT /v2/catalogs` and `PUT /tags/catalog` then refuse `/1` (422 `invalid catalog: schema must be "arkavo.creator-catalog/2"`; for a tag, the stored document's schema).
- Deleting stored `/1` documents (D5): a one-off subcommand of the node binary, `tdf-iroh-s3 --config <file> purge-catalogs-1 [--delete]`. It lists `catalog-documents/`, reads each, and for every `/1` document reports, and with `--delete` removes, `catalog-documents/<hash>` and `catalog-outboards/<hash>`. A document a `catalog/<sub>` tag or a v2 pointer still names is reported and kept: deleting it would leave that creator with a dangling catalog. A v2 pointer that can't be read is reported, and then nothing is deleted. Dry run by default.
- Moderation is unchanged on the node: a takedown blocks both hashes (arks writes two blocks, arkavo-rs#93). `catalog_hidden` and catalog blocks apply to `/2` documents as to `/1`.

### Contract

`docs/creator-catalogs.md` is authoritative for Creator and arkavo-ios. It gets the `/2` schema, the metadata TDF rules (minimal policy, matching policy and KAS, mimeType), the new error strings, the 524 288 limit for `/2`, and the token on the three resolution routes.

## Plan

1. `creator_catalog`: `/2` parse and validate, size limits per schema; unit tests.
2. Publish checks: `get_manifest`, metadata ingest/size/manifest/policy checks in `check_payloads`, used by all three write routes; `accept_catalog_schema_1`. The `PUT /v2/catalogs` body limit grows with the `/2` document limit (the document travels base64url-encoded in the bundle).
3. Group index for metadata blobs, per D3 (a): `catalog::derive_artifacts` indexes no blob of type `application/vnd.arkavo.catalog-entry+json` (its manifest is still stored), and publish check 5 requires the type.
4. Token on resolution routes: `[http] catalog_token`.
5. `purge-catalogs-1` subcommand.
6. Docs: `docs/creator-catalogs.md`, `CLAUDE.md`.

Rollout follows #38. **Before Creator pushes any `/2` metadata TDF,** the node with D3 (a) must be live: an older node indexes it like a recording, and nothing removes that entry later. **Before Creator republishes as `/2`:** count `blobs/` against `manifests/` in production and list recordings without a manifest. Check 3 refuses any catalog naming one, and the only repair is re-pushing the recording, so a gap may hold up #38 step 3. Then deploy with `catalog_token = "optional"` and `accept_catalog_schema_1 = true`; after Creator#102 and arkavo-ios#40 ship, set `required` and `false`, then run `purge-catalogs-1 --delete`.

## Decisions needed (owner)

Everything here is the node's proposal, not yet in #38:

- **D1. Size.** `/2` documents up to 524 288 bytes, `/1` stays at 262 144. A reader change for arkavo-ios#40.
- **D2. Metadata size cap** 65 536 bytes, matching the iOS viewer (was 262 144).
- **D3. Keeping metadata blobs out of `GET /catalog/{group}`:** decided 2026-10-25, (a) mimeType, a Creator#102 rule.
- **D4. `optional` mode** verifies a presented token (401 when bad), as `/catalog/{group}` does today.
- **D5. Purge** as a node subcommand, dry run by default, keeping documents a tag or pointer still names.

## Acceptance (from #39)

- a metadata blob whose policy differs from the payload's is refused;
- a missing, blocked or wrongly sized metadata blob is refused;
- a metadata policy with any top-level key besides `uuid` and `body` is refused;
- `/tags/catalog`, `/v2/catalogs` and `/catalog/{group}` without a token get 401 under `required`, while `/catalog-documents/{hash}` and iroh fetches still work without one;
- `/1` is refused after cutover.
