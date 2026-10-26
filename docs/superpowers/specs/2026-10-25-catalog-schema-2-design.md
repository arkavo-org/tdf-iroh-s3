# Catalog schema `/2`: per-entry TDF metadata, token-gated name resolution

**Status:** proposal, 2026-10-25.
**Issue:** tdf-iroh-s3#39, tracked in #38 (design and owner decisions there).
**Read at:** `feat/pdp-publish-decisions` `cdaf6c5`. This branch is based on #36 (catalog blocks and `catalog_hidden` are used unchanged) and rebases onto `main` once #36 merges.

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
  - `metadataSize`: an integer from 1 to `MAX_METADATA_SIZE` = 262 144 (proposed, D2). The FQNs appear twice, in the encrypted payload and base64-encoded in the clear policy, so a full metadata TDF can reach about 60 KiB; the cap only keeps a recording from standing in for metadata.
- **Size (D1).** A compact `/2` entry is about 290 bytes with a 36-byte contentID, so 1000 entries need about 290 000 bytes. `/2` documents may be up to **524 288** bytes. `/1` keeps 262 144, because `/1` readers in the field enforce it and a document the node accepts must never be one a viewer rejects. The upload body is read up to 524 288 and a `/1` document over 262 144 is refused with today's 413 `catalog too large`.
- Error strings follow today's form, `invalid catalog: entries[<i>].<reason>`, e.g. `entries[3].metadataHash duplicates entries[1].metadataHash`, `entries[2].metadataHash equals entries[0].payloadHash`.

### Publish checks for `/2`

Run by `PUT /catalogs/{sub}`, `PUT /v2/catalogs/{sub}` and `PUT /tags/catalog/{sub}` (a rollback passes the same checks as an upload), extending `check_payloads`. In order, so each status keeps its meaning:

1. **Blocked** (403 `content is blocked`): any `payloadHash` or `metadataHash` is blocked.
2. **Ingested and sized** (422): as today for payloads; then for metadata, `metadata <hash> is not ingested` and `metadata <hash> size does not match`.
3. **Manifests** (422): both manifests are read from `manifests/<hash>` (written at ingest). A missing one is `payload <hash> manifest is not stored` or `metadata <hash> manifest is not stored`; ingest says to re-push to repair, and so does the contract.
4. **Minimal policy** (422 `metadata <hash> policy may only hold uuid and body`): the metadata manifest's decoded policy has exactly the top-level keys `uuid` and `body`. Manifests are readable by anyone holding the hash, so anything else (`arkavo:classification`, `arkavo:components`) is refused.
5. **Metadata type** (422 `metadata <hash> is not catalog metadata`), only if D3 is answered with the mimeType: the manifest's `payload.mimeType` is `application/vnd.arkavo.catalog-entry+json`.
6. **Policy match** (422 `metadata <hash> policy does not match payload <hash>`):
   - `body.dataAttributes`: equal as sets of JSON values (order ignored, each entry compared whole, so the spec form and opentdf-rs's structured form are both compared exactly);
   - `body.dissem`: equal as sets (absent and `[]` are the same);
   - KAS: the sets of `encryptionInformation.keyAccess[].url` are equal.

Distinct hashes are looked up once, at most 16 at a time, as today. Storage failures are 502 `storage unavailable`. A new `TagStore::get_manifest` reads `manifests/<hash>`.

### Metadata blobs and the group index (D3)

A metadata TDF carries the recording's attributes, so ingest indexes it under the same `catalog-index/<group>/`, and `GET /catalog/{group}` lists it next to the recording. Its policy holds only `uuid` and `body`, so nothing in it says "metadata". Two ways out:

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
- Deleting stored `/1` documents (D5): a one-off subcommand of the node binary, `tdf-iroh-s3 --config <file> purge-catalogs-1 [--delete]`. It lists `catalog-documents/`, reads each, and for every `/1` document reports, and with `--delete` removes, `catalog-documents/<hash>` and `catalog-outboards/<hash>`. A document a `catalog/<sub>` tag or a v2 pointer still names is reported and kept: deleting it would leave that creator with a dangling catalog. Dry run by default.
- Moderation is unchanged on the node: a takedown blocks both hashes (arks writes two blocks, arkavo-rs#93). `catalog_hidden` and catalog blocks apply to `/2` documents as to `/1`.

### Contract

`docs/creator-catalogs.md` is authoritative for Creator and arkavo-ios. It gets the `/2` schema, the metadata TDF rules (minimal policy, matching policy and KAS, mimeType), the new error strings, the 524 288 limit for `/2`, and the token on the three resolution routes.

## Plan

1. `creator_catalog`: `/2` parse and validate, size limits per schema; unit tests.
2. Publish checks: `get_manifest`, metadata ingest/size/manifest/policy checks in `check_payloads`, used by all three write routes; `accept_catalog_schema_1`. The `PUT /v2/catalogs` body limit grows with the `/2` document limit (the document travels base64url-encoded in the bundle).
3. Group index for metadata blobs, per D3 (waits on the answer).
4. Token on resolution routes: `[http] catalog_token`.
5. `purge-catalogs-1` subcommand.
6. Docs: `docs/creator-catalogs.md`, `CLAUDE.md`.

Rollout follows #38. **Before Creator republishes as `/2`:** count `blobs/` against `manifests/` in production and list recordings without a manifest. Check 3 refuses any catalog naming one, and the only repair is re-pushing the recording, so a gap may hold up #38 step 3. Then deploy with `catalog_token = "optional"` and `accept_catalog_schema_1 = true`; after Creator#102 and arkavo-ios#40 ship, set `required` and `false`, then run `purge-catalogs-1 --delete`.

## Decisions needed (owner)

Everything here is the node's proposal, not yet in #38:

- **D1. Size.** `/2` documents up to 524 288 bytes, `/1` stays at 262 144. A reader change for arkavo-ios#40.
- **D2. Metadata size cap** 262 144 bytes.
- **D3. Keeping metadata blobs out of `GET /catalog/{group}`:** (a) mimeType, a Creator#102 rule, or (b) node-only cleanup at publish.
- **D4. `optional` mode** verifies a presented token (401 when bad), as `/catalog/{group}` does today.
- **D5. Purge** as a node subcommand, dry run by default, keeping documents a tag or pointer still names.

## Acceptance (from #39)

- a metadata blob whose policy differs from the payload's is refused;
- a missing, blocked or wrongly sized metadata blob is refused;
- a metadata policy with any top-level key besides `uuid` and `body` is refused;
- `/tags/catalog`, `/v2/catalogs` and `/catalog/{group}` without a token get 401 under `required`, while `/catalog-documents/{hash}` and iroh fetches still work without one;
- `/1` is refused after cutover.
