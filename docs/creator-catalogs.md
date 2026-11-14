# Creator catalogs and distribution

This is the contract between three parties:

- the tdf-iroh-s3 node at iroh.arkavo.net, which this repository builds;
- the Creator app, which publishes;
- the Arkavo iOS viewer, which reads.

It covers four things: how a creator's recordings are published, how a viewer finds and downloads them, the catalog document format, and the HTTP routes involved. Publishing sessions and moderation are covered in [publishing-and-moderation.md](publishing-and-moderation.md).

## Model

- **A recording is one TDF archive, addressed by the BLAKE3 hash of its bytes.**
  - The creator pushes it to the node over iroh.
  - The node validates it as a TDF, stores it in S3, and serves it to any peer by hash, straight from S3.
  - Whether a viewer may play it is decided by the TDF's key access, not by the node.
- **A creator's catalog is one `arkavo.creator-catalog/2` document listing their published recordings, encrypted as the payload of one ZTDF, the envelope.**
  - The envelope's policy names one attribute: the creator's Patreon campaign. So anyone who can play any of the creator's recordings can open the list, and nobody else.
  - Each entry names a recording and carries its **metadata TDF** inline, which holds the title, publish time and attributes under the recording's own policy. So a viewer reads exactly the entries they could play, from one fetch.
  - The node stores each envelope by the BLAKE3 hash of its exact bytes and never decrypts it.
- **The creator signs a pointer to the current envelope with their passkey** (catalog v2, below). The node serves the pointer only to a reader the platform entitles to the envelope's attribute.
- **Readers never trust a catalog because of where it came from.** They check the signed pointer, the envelope's hash and size, and, once they decrypt it, that the document's `owner` is the creator they asked for.

The format and design are tdf-iroh-s3#38 and #39 (amended 2026-10-27). Catalog `/1`, a plaintext document found through the tag `catalog/<sub>`, was removed on 2026-10-27, together with `PUT /catalogs/{sub}` and the tag routes `GET`/`PUT /tags/{name}`. So was the clear campaign listing `GET /catalog/{group}` ([below](#removed-the-campaign-listing-2026-10-27)).

## Subjects

`<sub>` is the `sub` claim of the publisher's Arkavo CWT, exactly as minted. For the passkey session token, that is the account UUID in lowercase, for example `5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10`.

- The node compares catalog names to `sub` byte for byte. It does not canonicalize them, so `<uuid>` and `arkavo:<uuid>` are different creators.
- Links carry the same string:
  - `https://app.arkavo.com/creator?sub=<sub>`
  - `https://app.arkavo.com/content?sub=<sub>&id=<contentID>`

## Catalog document, `arkavo.creator-catalog/2`

The document is UTF-8 JSON. It is the envelope's payload, so only a reader who can open the envelope sees it. The node never reads it: it checks the recordings it lists through the [index](#the-index) the publisher sends alongside.

```json
{
  "schema": "arkavo.creator-catalog/2",
  "owner": "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10",
  "entries": [
    {
      "contentID": "rec-2b9c4f1e0d8a4c7f9e1d3b5a6c8f0e2d",
      "version": 2,
      "payloadHash": "4f8a…64 lowercase hex…",
      "payloadSize": 7342067,
      "metadata": "<base64url of the metadata ZTDF's bytes>"
    }
  ]
}
```

**Top-level fields**

| Field | Rule |
|---|---|
| `schema` | Exactly `"arkavo.creator-catalog/2"`. |
| `owner` | The creator's `<sub>`: 1–248 bytes of `[A-Za-z0-9:._@-]`, not `.` and not containing `..`. |
| `entries` | An array of 0–1000 entries. An empty array is a valid catalog with nothing published. |

**Entry fields**

| Field | Rule |
|---|---|
| `contentID` | 1–256 bytes of `[A-Za-z0-9:._@-]`, not `.` and not containing `..`. It is unique within the document and stays the same when the creator republishes a recording. |
| `version` | An integer from 1 to 9007199254740991 (2⁵³−1). A republish with different bytes uses a larger version. |
| `payloadHash` | 64 lowercase hex characters: the BLAKE3 hash of the recording's TDF bytes. At publish, it must name a blob the node has ingested and not blocked. |
| `payloadSize` | An integer from 1 to 4294967295 (4 GiB − 1, the viewer's limit): the TDF's size in bytes. At publish, it must equal the size `GET /blobs/<payloadHash>` reports. |
| `metadata` | The entry's [metadata TDF](#the-metadata-tdf): its ZTDF bytes, unpadded base64url. At most 65 536 bytes before encoding (a TDF at every limit, 32 FQNs of 512 bytes and a 512-byte title, is about 43 KB; a typical one 3–4 KB). Moderation identifies it by the BLAKE3 hash of those bytes. |

**Rules for keys**

- An entry has exactly these five keys. Unknown keys are rejected, at the top level and in entries, including `/1`'s `title`, `publishedAt` and `attributeFQNs`.
- A key that appears twice in one JSON object is rejected.
- Integers are JSON integers: `1.0` and `1e0` are rejected.
- Entry order carries no meaning. Readers sort.

The rules for the decrypted document, the metadata TDF and its payload are implemented once, for Creator and the iOS viewer, in ArkavoKit's ArkavoCatalog. The node never sees them.

## The envelope

The catalog document is the payload of one ZTDF, the envelope, at most **4 194 304 bytes** (4 MiB): room for 1000 entries with their metadata TDFs inline. The pointer's `catalogHash` and `catalogSize` are over the envelope's bytes, and so are `GET /catalog-documents/<hash>` and the iroh fetch.

- Its manifest's `payload.mimeType` is exactly `application/vnd.arkavo.creator-catalog+json`.
- Its policy has **only** the top-level keys `uuid` and `body`. The `uuid` is a non-empty string, fresh for each envelope. `body.dissem` is empty or absent.
- `body.dataAttributes` is **exactly one** element whose `attribute` is:
  - `https://patreon.arkavo.com/attr/campaign/value/<id>`, `<id>` being the campaign id, one or more digits (the only values the platform's Patreon entity resolution grants), for a creator with a Patreon campaign. Creator already puts this FQN first in every non-public recording's policy;
  - or `https://arkavo.net/attr/creator/value/<sub>`, byte for byte the creator's `sub`, which must be a bare lowercase account UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, as identity grants it, never `arkavo:<uuid>`), for a creator without a campaign. Only the creator can open it. This needs opentdf-platform#67 in production; until then the platform denies everyone a TDF under it.
  - Never both: the platform ANDs across attribute definitions, so patrons couldn't open it.
- Its key access objects name a KAS the viewer rewraps with, normally the recordings'. The node doesn't check which.
- **Every entry's recording policy names the envelope's attribute.** A viewer who can open an entry can always open the catalog that lists it.

What stays in the clear is the envelope's manifest (one attribute, the KAS, a uuid). Entry count, hashes, `contentID`s, metadata and per-entry attributes are inside it, not readable by someone holding a catalog hash. A hash is still a capability to fetch bytes, but the bytes are ciphertext.

## The metadata TDF

Each entry's metadata TDF travels inside the envelope, in its entry's `metadata`. It is never pushed to the node, and **the node never checks it: Creator does**, with ArkavoCatalog's pre-publish check on the actual bytes, before every publish. The rules:

- Its payload holds the entry's title, publish time and attributes, as ArkavoCatalog defines it. Its `contentID`, `version` and `payloadHash` equal the entry's: a reader refuses metadata that names another entry.
- Its policy has **only** the top-level keys `uuid` and `body`. The `uuid` is a non-empty string, fresh for each metadata TDF, unique in the document, and never the recording's or the envelope's: a viewer unwraps all of a catalog's metadata in one bulk rewrap, and the platform's KAS skips an entry with no policy id and refuses duplicate ids. The policy must not repeat the recording's `arkavo:classification`, `arkavo:components` or any other extension.
- Its manifest's `payload.mimeType` is `application/vnd.arkavo.catalog-entry+json`.
- Its `body.dataAttributes` and `body.dissem` equal the recording's, each as a set, and its key access objects name the same KAS URLs.
- It is at most 65 536 bytes.

A creator whose metadata TDF had a weaker policy than its recording would show that entry's title to more of their own patrons. It touches neither other creators' content nor the recordings, which keep their own policies.

## The index

The node can't decrypt the envelope, so the publisher sends the document's entries in the clear alongside it, as `index` in `PUT /v2/catalogs/{sub}`: a JSON array of at most 1000 entries, each exactly `{"contentID", "version", "payloadHash", "payloadSize"}` (a JSON object: the same values as an array are rejected), the document's entry without its `metadata`, held to the same rules. **The creator's passkey signs the index** through the pointer's [`indexHash`](#indexhash), the SHA-256 of its canonical form, and the node refuses an index that doesn't match it. The node checks the recordings against what it has ingested, stores the index at `catalog-indexes/<hash>`, once per envelope, and **never serves it**. Moderation reads it to find a recording's hash from its `contentID`.

The signature binds the index to the pointer, and so to the envelope's hash, but not to the entries inside the encrypted document: those two agree only by the creator's honesty. An entry left out of the index can only hide the creator's own entry from moderation, so reports carry the `payloadHash`, not just a `contentID`.

## HTTP routes

TLS terminates in front of the node. A request's headers, the `Authorization` CWT and every `X-Entity-Token` together, may be up to 64 KiB over HTTP/2; larger ones are refused before the node reads them. Every error body is `{"error":"<message>"}`, with two exceptions: the two owner refusals of `PUT /v2/catalogs/{sub}` add `contentIDs` (see [`PUT /v2/catalogs/{sub}`](#put-v2catalogssub-publish)), and on an ungated node `POST /publish/sessions` answers 404 with an empty body (see [Publishing a recording](#publishing-a-recording-creator)).

### `GET /catalog-documents/{hash}`: read a catalog

This route is public: the bytes are an envelope, ciphertext to anyone who can't open its attribute.

- **200:** the stored bytes, with `Content-Type: application/zip`, `ETag: "<hash>"` and `Cache-Control: public, max-age=300`.
- **304:** no body, with the same `ETag` and `Cache-Control`, when `If-None-Match` names `"<hash>"` (or its weak form `W/"<hash>"`, or `*`), the document is stored, and it is not hidden.
- **400:** `invalid hash`. The hash must be 64 lowercase hex characters.
- **404:** `catalog not found`, also when the document's hash is blocked or its owner has a catalog block or a `hideCatalog` suspension, and also in answer to `If-None-Match`.

The bytes behind a hash never change, but the node may later block a document or hide its owner's catalog. So a client or proxy reuses a document for at most 5 minutes and then revalidates it, and a block or `hideCatalog` reaches readers within that time. The node records each document's `owner` alongside it when it stores it.

### `GET /blobs/{hash}`: confirm ingest

This route is public. It is how a publisher confirms ingest before naming a hash in a catalog.

- **200:** `{"hash":"<hex>","size":<bytes>}`, when the hash is an ingested TDF that is not blocked. The node stores the blob's outboard before the blob, so a 200 means the blob can be fetched.
- **404:** `blob not found`. The hash was never pushed, is still being ingested, failed validation, is blocked, or was [deleted](#removing-a-recording).
- **400:** `invalid hash`.

### `GET /publish/recordings/{hash}`: who owns a recording

Creator asks this before the passkey prompt, so the creator doesn't sign a catalog that lists another account's recording. It asks again after a failed push, to explain it: the node refuses a push of another account's recording with only an iroh error code (see [Ownership](#ownership)).

The request needs `Authorization: Bearer <Arkavo CWT>`, checked before the hash, as for [`PUT /v2/catalogs/{sub}`](#put-v2catalogssub-publish): the publishing checks in [publishing-and-moderation.md](publishing-and-moderation.md), with the `X-Entity-Token` devices when `[publishing] decisions` is `shadow` or `pdp`.

The lists below are complete. `invalid hash` and `storage unavailable` are this route's own; every other string comes from the publishing checks, as on `PUT`. Those marked *`pdp` only* arise only when `[publishing] decisions` is `pdp`: under `shadow` the node asks the decision service with the devices but enforces only its local answer, so it logs a failed device token or a denial rather than refusing.

- **200:** `{"hash":"<hash>","owner":"<owner>"}`, where `owner` is one of:
  - `"you"`: the token's subject owns the recording. Subjects are compared canonically, so `arkavo:<uuid>` and `<uuid>` are one account.
  - `"another account"`: another account owns it. The node never says which account.
  - `"none"`: no account owns it, and its next push claims it. This doesn't say the recording is ingested; `GET /blobs/<hash>` does. A node with `[publishing] required = false` records no owners, so it always answers `"none"`.
- **400:**
  - `invalid hash`: the hash isn't 64 lowercase hex characters. This is the only 400 the route adds, and it is checked after the token.
  - *`pdp` only:* `too many entities`, a chain of more than 8 (the person, the `X-Entity-Token` devices and the node's environment).
- **401:**
  - `missing bearer token`;
  - `invalid token`: the token doesn't verify (signature, expiry, issuer, or `aud` other than `[publishing] audience`);
  - *`pdp` only:* `invalid entity token`, an `X-Entity-Token` that isn't a valid DeviceCheck CWT; `entity token subject does not match bearer subject`.
- **403:**
  - `service tokens cannot publish`: the token names a service client (`client:*`), not a person;
  - `publishing suspended`;
  - `publishing entitlement required`, under `local` and `shadow` only (under `pdp` the decision replaces the entitlement check);
  - *`pdp` only:* `publishing not permitted`, the decision service's denial.
- **502:** `storage unavailable` when the owner record can't be read; `invalid token` when the node can't fetch the key set to check the token.
- **503:** *`pdp` only:* `decision service unavailable`.

On a node with `[publishing] required = false` only the token is checked, without the audience: its refusals are 401 `missing bearer token` or `invalid token`, 502 `invalid token`, and the route's own 400 `invalid hash`.

### `GET /node`: the node's iroh identity

This route is public.

- 200 `{"endpointId":"<64 lowercase hex>","relayUrl":"<url>"|null,"directAddresses":["<ip:port>", …],"maxBlobBytes":<bytes>}`.
- `directAddresses` comes from `[iroh] public_addresses`. It is empty when that setting isn't configured.
- `maxBlobBytes` is `[validation] max_blob_bytes`, the largest archive ingest accepts.

Creator reads the node to push to from this route. The iOS viewer does not. The viewer dials only the endpoint ID and addresses compiled into its release configuration, so a different value here never redirects it.

## Publishing a recording (Creator)

1. **Find the node.** `GET /node` gives the endpoint ID, relay, addresses and the largest archive the node accepts. Don't push a larger one.
2. **Open a publish session.**
   - Creator calls `POST /publish/sessions` with its iroh endpoint ID, and signs with its endpoint key (see [publishing-and-moderation.md](publishing-and-moderation.md)).
   - A 404 means the node is ungated (`required = false`). Continue without a session.
   - That 404 has an empty body, not `{"error":…}`. Check only the status.
3. **Push the TDF** to the node over iroh. The push returns the BLAKE3 hash.
   - The push's result does not say whether the node accepted it. A gated node refuses a push from an endpoint without a session by aborting the request, but the pusher may see no error: the iroh-blobs client in this repository's test CLI reports such a push as successful.
   - Only step 4 confirms that the node has the TDF.
   - A push larger than `maxBlobBytes` is stopped while it transfers: the node closes the connection with the reason `blob exceeds max_blob_bytes`.
   - A push that stops sending for `push_stall_secs`, default 120 s, is closed; push again.
   - The node serves a blob over iroh only from S3, and only once it has validated, so a refused blob is never served. The node's local store only stages the push and is cleaned up afterwards.
   - If the upload to S3 fails, the node retries it twice (after 1 s and 5 s) and then gives up; the blob stays unservable and `GET /blobs/<hash>` stays 404. Push again.
   - Push and fetch single blobs (`GetRequest::blob`). The node refuses hash-sequence requests, observe requests and a `get_many` naming more than 64 hashes.
4. **Confirm ingest.** Poll `GET /blobs/<hash>` until it returns 200 with the expected size.
   - Wait at most 120 s.
   - A 404 after that means the node refused the push or the archive.
5. **Read the current catalog.**
   - `GET /v2/catalogs/<sub>` with the creator's token, keeping its `ETag`, then fetch the envelope by `catalogHash` and decrypt it. The creator holds their campaign's attribute, so they can open their own envelope.
   - A 404 means there is no catalog yet.
6. **Merge the entry.** Find it by `contentID`.
   - If the payload hash is unchanged, keep the entry as it is.
   - Otherwise write the new payload hash and size and a new [metadata TDF](#the-metadata-tdf), with `version` one higher than the old entry's, inside the metadata as well.
7. **Publish the catalog** with `PUT /v2/catalogs/<sub>` (see [Publishing (Creator)](#publishing-creator)): a new envelope, its signed pointer and the index.

### Removing a recording

To remove a recording (Hide from Catalog), Creator publishes the catalog without its entry. That publish is the creator's request to delete the recording; there is no other deletion route. The node records what each publish drops, and an operator's weekly sweep deletes it ([publishing-and-moderation.md](publishing-and-moderation.md#deletion-requests-operators)):

- **The stored TDF is deleted 7 to 30 days after the publish that dropped it, unless pushed again (see below),** every S3 version, with its outboard, manifest and owner record. Ownership then ends: the next push of the same bytes claims the recording.
- **Re-listing the entry within 7 days of that publish cancels the deletion.** Publish the catalog with the entry again; the TDF is still there, so no push is needed. Nothing else cancels it.
- **Pushing the recording again doesn't cancel the deletion: it restarts the 7 days from the push.** A recording pushed again before it is deleted, and not listed again, is still deleted: with the weekly sweep, at most 14 days after the push, or 21 days after the drop if the push came within its first 7 days. Each later push restarts the 7 days. If the publish that was to list it again failed after the push, publish again before then.
- **After the deletion, re-listing needs a fresh push.** The node no longer has the TDF: `GET /blobs/<hash>` answers 404, and a catalog that lists it gets 422 `payload <hash> is not ingested`. Push it again (step 3), then publish.
- **A replaced payload is deleted the same way.** A new payload hash for an entry (step 6) drops the old one, which is deleted 7 to 30 days after that publish.
- **A superseded envelope is deleted 7 to 30 days after it was replaced.** Each publish replaces the previous envelope, which carries every entry's metadata TDF, titles included.

A drop counts only when the node served the catalog it was dropped from, and only for a recording the publisher [owns](#ownership): a creator whose catalog reads 404 (its envelope blocked, a catalog block or `hideCatalog`, a pointer from before envelopes) requests nothing by publishing, and a node with `[publishing] required = false`, which records no owners, deletes no recording (only superseded envelopes). The node keeps a recording while any catalog still lists it, and keeps blocked content while its block stands. A recording moderation blocked must be dropped from the catalog (`PUT` refuses it), and that drop is not a request.

**Deleting an account.** Before `DELETE /account`, Creator publishes an empty catalog (no entries, `index` `[]`), which drops every recording the catalog listed. If that publish fails, Creator stops and offers Try Again or Delete Anyway. When `GET /v2/catalogs/<sub>` answers 404, Creator skips the publish. The node is never told an account was deleted: its pointer and the empty envelope stay. Anything the empty catalog can't reach is deleted by an operator on request.

### Ownership

The first account to push a recording owns it. When the node ingests a push, it records the pusher's subject as the owner of that BLAKE3 hash, unless the hash already has an owner. It never overwrites an owner. On a node with `[publishing] required = false` nothing is owned and nothing below applies.

- **A push of another account's recording is refused,** the same way as a push without a session (step 3), so the pusher may see no error.
- **Creator can ask whose a recording is** with [`GET /publish/recordings/<hash>`](#get-publishrecordingshash-who-owns-a-recording): before the passkey prompt, and after a failed push, to explain it.
- **A catalog may list only its publisher's recordings.** `PUT /v2/catalogs/<sub>` refuses an index that names another account's recording with 403 `recording belongs to another account`. A recording with no owner gets 422 `recording has no owner: push it again`. Both name the entries in `contentIDs`.
- **A recording with no owner is claimed by its next push.** Push it again. The node records the claim once it has ingested the push, so poll `GET /publish/recordings/<hash>` as in step 4 until it answers `"you"`, then publish again.

## Reading a catalog and downloading (viewer)

1. **Find the current catalog.** `GET https://iroh.arkavo.net/v2/catalogs/<sub>` with `Authorization: Bearer <Arkavo CWT>` (see [`GET /v2/catalogs/{sub}`](#get-v2catalogssub-read-the-pointer)). A 403 `not entitled to catalog` means the viewer doesn't hold the creator's campaign: prompt them to follow it on Patreon. A viewer that knows only a campaign takes its creator from the token's `arkavo_patreon` membership (authnz-rs#128); the node has no campaign lookup.
2. **Fetch and verify it.**
   - Verify the bundle ([Verification](#verification)), then fetch `catalogHash` over iroh with a limit of `catalogSize`, or `GET /catalog-documents/<hash>`. Fetches by hash need no token.
   - The BLAKE3 hash of the bytes must equal `catalogHash`.
   - Rewrap the envelope, decrypt it, and check the payload is a valid `/2` document whose `owner` is `<sub>`.
   - Unwrap every entry's inline metadata TDF in one bulk rewrap: at most 1000 policies per rewrap, split by size as well (arks refuses an HTTP/3 body over 2 MiB). Treat a missing per-entry result as refused. Refuse metadata whose `contentID`, `version` or `payloadHash` differs from its entry's, and show only the entries that decrypt.
3. **Download a recording.** Fetch `payloadHash` over iroh, from the endpoint ID compiled into the viewer.
   - Reject the download if it is larger than `payloadSize`.
   - Verify the BLAKE3 hash before using the file.
   - Expect the transfer to fail now and then: iroh connections stall, drop and change paths. A failed transfer is worth another attempt; the node keeps nothing from it.
4. **Read the node's refusal.** The node approves or refuses each request before it sends a byte. A refused request is reset with an iroh-blobs error code:
   - `ERR_PERMISSION` (1) is final. The hash is blocked, S3 has no such blob, or its S3 object turned out not to match the hash. Do not retry. Hash-sequence requests, observe requests and a `get_many` naming more than 64 hashes get this answer before any lookup, so fetch one blob at a time.
   - `ERR_LIMIT` (2) means try again. S3 did not answer in time (a HEAD over 10 s, or a GET that sends nothing for 30 s), the blob's outboard is being computed, or the node is serving 256 fetches at once. Retry with a backoff.
   - A blob ingested before outboards were stored has none. Its first fetch is answered `ERR_LIMIT` while the node computes the outboard by streaming the blob from S3 once; the retry is served.
   - A transfer that S3 breaks off part-way is reset with `ERR_LIMIT` too. Fetch the blob again. If the blob was deleted from S3 meanwhile, the next fetch gets `ERR_PERMISSION`.
   - The Arkavo iOS viewer already maps these (ADR-0057 §5): iroh-swift reports `ERR_PERMISSION` as "permission denied", which the viewer treats as not found, and `ERR_LIMIT` as a failure it retries.

## Catalog v2: passkey-signed catalogs over iroh

Catalog v2 ([tdf-iroh-s3#27](https://github.com/arkavo-org/tdf-iroh-s3/issues/27)) is how a creator's current catalog is named and proved.

- **The envelope travels over iroh.** A reader fetches it by BLAKE3 hash from the pinned node, the same way it fetches recordings.
- **The creator signs a pointer with their passkey.** The pointer names the envelope's hash and size and the hash of its clear [index](#the-index), and carries a sequence number.
- **The IdP attests the passkey.** identity.arkavo.net signs which passkey credential belongs to which subject ([authnz-rs#104](https://github.com/arkavo-org/authnz-rs/issues/104), `docs/passkey-credential-attestation.md` there).

A reader checks the whole chain itself. So neither the node nor its storage can forge a creator's catalog, or roll back a reader that has already seen a newer `seq`. They can still withhold a catalog, or show an older signed one to a reader that has never seen a newer `seq`.

**Encoding.** Every binary value in v2 is base64url **without padding** (RFC 4648 §5, no `=`). The node refuses padded values and the standard alphabet's `+` and `/`.

### The pointer

The exact UTF-8 bytes of one JSON object (the same values as a JSON array are rejected). It is carried base64url-encoded and is never re-serialized, so the signed bytes are the bytes everyone reads.

```json
{"schema":"arkavo.catalog-pointer/2","owner":"<sub>","seq":7,"catalogHash":"<64 lowercase hex>","catalogSize":1234,"indexHash":"<64 lowercase hex>","issuedAt":"2026-10-19T01:02:03Z"}
```

| Field | Rule |
|---|---|
| `schema` | `arkavo.catalog-pointer/2` |
| `owner` | the publisher's `sub`, byte for byte (the same rules as a catalog's `owner`) |
| `seq` | integer, 1 to 9 007 199 254 740 991 |
| `catalogHash` | BLAKE3 of the envelope's bytes, 64 lowercase hex characters |
| `catalogSize` | the envelope's length in bytes, 1 to 4 194 304 |
| `indexHash` | SHA-256 of the canonical [index](#the-index) ([below](#indexhash)), 64 lowercase hex characters |
| `issuedAt` | `YYYY-MM-DDTHH:MM:SSZ` |

The object holds exactly these seven keys, with no key repeated and nothing after it, and is at most 1024 bytes. `indexHash` is **SHA-256**, while `catalogHash` and `payloadHash` are BLAKE3.

**`arkavo.catalog-pointer/1`** is the same object without `indexHash`: exactly the other six keys. A `/1` with `indexHash`, or a `/2` without it, is invalid. The node accepts only `/2` in a publish, but `GET /v2/catalogs/{sub}` still serves a stored `/1` pointer until the creator's next publish replaces it, so readers decode both.

The node refuses a pointer that breaks these rules with `invalid bundle: <reason>`. The reasons about `indexHash` are:

- `pointer "arkavo.catalog-pointer/2" requires indexHash`
- `pointer indexHash must be 64 lowercase hex characters`
- `pointer "arkavo.catalog-pointer/1" must not carry indexHash`

Any other `schema` gets `pointer schema must be "arkavo.catalog-pointer/2"`.

#### `indexHash`

`indexHash` is the lowercase hex SHA-256 of the canonical index, built from the parsed index entries, never from the bytes received:

- entries sorted by `contentID`, comparing the UTF-8 bytes;
- each written as `{"contentID":"<id>","version":<n>,"payloadHash":"<hex>","payloadSize":<n>}`, keys in exactly that order;
- joined with `,` inside `[` `]`, no whitespace. The empty index is `[]`.
- No escaping arises: `contentID` is `[A-Za-z0-9:._@-]`.

The `index` sent in `PUT` is unchanged: its key and entry order are free, and the node canonicalizes it.

**Vectors**

| Name | Input order of `contentID` | `indexHash` |
|---|---|---|
| empty | — | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` |
| two | `rec-b` (v1, `bb…`, 2048), `rec-a` (v3, `aa…`, 1024) | `03f745d8d08d9e9e11cabf33d85e8beb452eb3a2b2e541f92e1703c1f4152df4` |
| byte-order | `a_1`, `a@1`, `A`, `a:1`, `a.1`, `a-1` (entry *n*, counting from 0 in this order, has hash byte `n` ×32, size *n*+1, v1; so `a_1` is `00`×32, size 1) | `79129b9fa70e8ab5d0894d07098294de6dec2677c9df538b3eb05df98bd8ef18` |

Canonical bytes of "two": `[{"contentID":"rec-a","version":3,"payloadHash":"aa…aa","payloadSize":1024},{"contentID":"rec-b","version":1,"payloadHash":"bb…bb","payloadSize":2048}]` (64 hex characters each). "byte-order" sorts to `A`, `a-1`, `a.1`, `a:1`, `a@1`, `a_1`. ArkavoKit's shared vectors (`Tests/ArkavoCatalogTests/Vectors/catalog-vectors.json`) are to carry these, each with its full `index` text.

### The signed bundle

```json
{
  "pointer": "<base64url pointer bytes>",
  "assertion": {
    "credentialId": "<base64url>",
    "authenticatorData": "<base64url>",
    "clientDataJSON": "<base64url>",
    "signature": "<base64url DER ECDSA signature>"
  },
  "credential": "<base64url COSE_Sign1 attestation from the IdP>"
}
```

Exactly these keys. `assertion` is the WebAuthn assertion as the platform returns it.

### Verification

The node checks this on publish and readers check it on read. The rules are the same:

1. **The attestation** is a COSE_Sign1, tagged 18 or untagged:
   - signed ES256 by a `kid` in `https://identity.arkavo.net/.well-known/cose-keys`;
   - protected header content type (label 3) `application/arkavo-passkey-credential+cbor`;
   - its payload is a CBOR map with exactly the text keys `typ` (`arkavo-passkey-credential`), `iss` (`https://identity.arkavo.net`), `sub`, `credentialId` (byte string), `publicKey` (COSE_Key: EC2, P-256), `rpId` (`identity.arkavo.net`) and `iat` (at most 60 s in the future);
   - `sub` equals the pointer's `owner`, and `credentialId` equals the assertion's.
2. **The assertion,** against the attested `publicKey`:
   - `clientDataJSON.type` is `webauthn.get`;
   - `clientDataJSON.challenge`, decoded, equals SHA-256 of the pointer bytes;
   - `clientDataJSON.origin` is `https://identity.arkavo.net`, and `crossOrigin` is not `true`;
   - `authenticatorData` is at least 37 bytes, starts with SHA-256(`identity.arkavo.net`), and has the UP (0x01) and UV (0x04) flags set;
   - `signature` (ASN.1 DER) verifies with ES256 over `authenticatorData || SHA-256(clientDataJSON)`.
   - The signature counter is ignored: synced passkeys report 0.
3. **The pointer** follows the rules above, and its `owner` is the subject asked for.
4. **The envelope** hashes to `catalogHash` and is `catalogSize` bytes long. The node checks it is an [envelope](#the-envelope) of the pointer's `owner`; a reader decrypts it and checks its payload is a valid `arkavo.creator-catalog/2` whose `owner` is the pointer's `owner`.
5. **Rollback.** The node refuses a `seq` that is not greater than the stored one. A reader refuses a `seq` lower than the highest it has seen for that creator.

### `PUT /v2/catalogs/{sub}`: publish

This is the only route that publishes a catalog. The request needs `Authorization: Bearer <Arkavo CWT>` and `Content-Type: application/json`. Its body is `{"document": "<base64url envelope bytes>", "bundle": {…}, "index": [ … ]}`, at most 10 MiB (10 485 760 bytes): a 4 MiB envelope is about 5.6 MiB in base64url, and an index of 1000 entries up to about 400 KiB.

The request must name the base the client merged its document from, with exactly one of two standard conditional headers (RFC 9110), in the form below. Without one, a device whose own highest `seq` exceeds the stored one could publish over a base it never read, and replace what another device saved.

- **`If-Match: "<seq>"`:** the client merged from the stored pointer with this `seq`, as `GET /v2/catalogs/{sub}` tagged it (`ETag`). It is one strong entity tag whose content is ASCII decimal digits, sent as one header line with no list. It holds only when `GET` serves a pointer whose `ETag` is exactly that tag.
- **`If-None-Match: *`:** exactly `*`, as one header line. The client merged from "no catalog yet" (a 404). No pointer may be stored, apart from one `GET` doesn't serve: preconditions see what `GET` serves. That is a pointer whose envelope's hash is blocked, or the pointer of a creator with a [catalog block](publishing-and-moderation.md#moderation-operators), in both cases with a `seq` that must still be exceeded; or one at a catalog from before envelopes, which reads as no pointer at all, so the first envelope may start at any `seq`.

Anything else gets 428 `precondition required`, before the node reads the stored pointer, also on a node with `[publishing] required = false`. That includes neither header or both, `If-Match: *`, a list of tags, a weak (`W/"7"`), unquoted (`7`), empty or non-digit tag, any `If-None-Match` other than `*`, a repeated header line, and a value that is not visible ASCII.

If the stored pointer is no longer that base, the node answers 412 `catalog changed since it was read` and stores nothing. Read the pointer again, merge, sign and retry.

The node checks the following in order:

| Check | Failure |
|---|---|
| The token passes the publishing checks in [publishing-and-moderation.md](publishing-and-moderation.md): the audience, the entitlement, a person rather than a service, a subject that isn't suspended. On a node with `[publishing] required = false` the token still has to verify. | 401 missing or invalid; 403 |
| `{sub}` equals the token's `sub` | 403 `catalog does not match token subject` |
| `Content-Type` is `application/json` (case-insensitive, parameters allowed) | 415 `content type must be application/json` |
| The body is at most 10 MiB | 413 `request too large` |
| The body is JSON with exactly `document`, `bundle` and `index`, and no key repeated anywhere in it | 400 `invalid request: <reason>` |
| `document` is 1–4 194 304 bytes of unpadded base64url | 422 `invalid request: …` |
| Verification steps 1–3 | 422 `invalid bundle: <reason>`; 502 `key set unavailable` |
| The pointer is `arkavo.catalog-pointer/2` | 422 `invalid bundle: pointer schema must be "arkavo.catalog-pointer/2"` |
| The pointer names this document | 422 `invalid bundle: catalogHash or catalogSize does not match the document` |
| `document` is a ZTDF archive (manifest and payload member, as [ingest accepts](#archive-layout-accepted-at-ingest)) | 422 `document is not a TDF` |
| Its `payload.mimeType` is `application/vnd.arkavo.creator-catalog+json` | 422 `document is not a catalog` |
| Its policy has only `uuid` and `body`, no `dissem`, and exactly one campaign attribute or `{sub}`'s creator attribute ([The envelope](#the-envelope)) | 422 `catalog policy must be one campaign or the creator attribute` |
| Its policy's `uuid` is a non-empty string | 422 `catalog policy has no uuid` |
| For a campaign attribute: the token's `arkavo_patreon` has role `creator` and a `campaign_id` (a string) equal to the envelope's campaign id. Identity sets it only for the campaign the account owns. | 403 `catalog campaign is not the publisher's` |
| `index` is an array of at most 1000 valid [index entries](#the-index) with unique `contentID`s | 422 `invalid index: <reason>`, e.g. `invalid index: entries[3].contentID duplicates entries[1].contentID` |
| The pointer's `indexHash` is this index's ([`indexHash`](#indexhash)) | 422 `invalid bundle: indexHash does not match the index` |
| Nothing blocked: the envelope's hash, no entry's `payloadHash` | 403 `content is blocked` |
| Every `payloadHash` is an ingested blob | 422 `payload <hash> is not ingested`, the first missing one in entry order |
| Every entry's `payloadSize` equals the ingested blob's size, each entry checked, also entries that share a payload | 422 `payload <hash> size does not match` |
| No entry's recording belongs to another account: its [owner](#ownership), if it has one, is `{sub}`. Subjects are compared canonically, so `arkavo:<uuid>` and `<uuid>` are one account. Skipped on a node with `[publishing] required = false`. | 403 `recording belongs to another account`, with `contentIDs`; 502 `storage unavailable` when an owner record can't be read |
| Every entry's recording has an owner. Checked only when no entry belongs to another account; skipped on a node with `[publishing] required = false`. Push the recording again: the push claims it. | 422 `recording has no owner: push it again`, with `contentIDs` |
| Every recording's manifest is stored (at ingest) and readable. A recording ingested before the node stored manifests has none: push it again. | 422 `payload <hash> manifest is not stored` or `… manifest is unreadable` |
| Every entry's recording policy names the envelope's attribute | 422 `entry <contentID> policy does not include the catalog attribute` |
| The passkey credential is still the subject's, according to the IdP's status route | 403 `passkey credential unknown`, `… revoked` or `… belongs to another subject`; 502 `credential status unavailable` |
| exactly one of `If-Match: "<seq>"` or `If-None-Match: *` is sent | 428 `precondition required` |
| The stored pointer is the base named by `If-Match` or `If-None-Match` | 412 `catalog changed since it was read`; 502 `storage unavailable` when the stored pointer or its index record can't be read or parsed, or a stored `/2` pointer's index record doesn't match its `indexHash` |
| `seq` is greater than the stored one | 409 `seq must be greater than <n>` |
| The envelope has no index record yet, or its record is a retry of this publish: `{sub}`'s (subjects compared canonically), with the same canonical index. Checked as the record is written, before the transition, the envelope and its outboard. | 409 `catalog document already published with another index`; 502 `storage unavailable` when the record can't be created or the existing one can't be read |

The two owner refusals also carry `contentIDs`: the `contentID` of every entry refused, sorted, including every entry that names the same payload. For example: `{"error":"recording belongs to another account","contentIDs":["rec-a","rec-b"]}`. Every other refusal in the table is `{"error":"…"}` alone.

The node then writes, in this order: the index at `catalog-indexes/<blake3>` (never served), the publish's transition at `catalog-transitions/<sub>/<seq, 20 digits>-<pointer digest>` (never served), the envelope at `catalog-documents/<blake3>`, its BAO outboard at `catalog-outboards/<blake3>`, then the bundle at `catalog-pointers/<sub>`.

- **The index** is written only if the envelope has none (`If-None-Match: *`): one envelope has one index, so a publish that lost can't rewrite the index of the pointer that won. An envelope that already has another index record gets the table's last 409, and nothing of that publish is written; a fresh envelope (a new policy `uuid`) has a new hash.
- **The transition** holds the base pointer the publish replaces, and which recordings it drops from the served catalog and adds, for the [deletion of dropped recordings](#removing-a-recording). To know what the publish drops, the node reads the owner record of each recording the served base lists, the new index doesn't and no block covers (only a recording the publisher owns is dropped). It reads them before it writes anything: if one of those owner records can't be read, the node answers 502 `storage unavailable` and stores nothing. A publish sent again finds the transition its earlier attempt stored under the same key. While the stored pointer is still the one this publish read, that transition is replaced with this publish's (its base, its `dropped`, a fresh `at`); once the pointer has moved, it is kept and the publish answers 502 `storage unavailable`.
- **A failed write** of the transition, the envelope, its outboard or the pointer is 502 `storage unavailable`. A failed pointer write has an unknown outcome: S3 may have stored the pointer all the same. So read the pointer again, as after a 409: if `GET` serves this publish's own bundle (its `pointer` field is the one this publish sent), it is published. A matching `seq` alone doesn't show that: another device merging from the same base signs the same `seq`. If `GET` answers 404 (an operator hid the catalog), there is no `pointer` to compare. A publish sent with `If-None-Match: *`: send it again, and 409 `seq must be greater than <its own seq>` means a publish at its `seq` is stored, its own unless another device published that `seq` meanwhile. A publish sent with `If-Match: "<n>"` whose catalog was hidden after step 1 gets 412 on the resend, stored or not, and never that 409: go back to step 1, which is harmless. Otherwise this publish's pointer wasn't stored; send the same publish again and it completes, unless another publish moved the pointer meanwhile (412 or 409). A second 502 for the same publish: go back to step 1 of [Publishing](#publishing-creator). A new envelope gives new pointer bytes, and so a fresh start.
- **The pointer** is written only if no other publish replaced it in the meantime; otherwise 409 `seq must be greater than the stored seq: another publish won`. The same 409 answers a pointer deleted in the meantime (an operator's account deletion). Read the pointer again and retry.

200: `{"owner":"<sub>","seq":<n>,"hash":"<blake3 hex>","size":<bytes>}`.

### `GET /v2/catalogs/{sub}`: read the pointer

The request needs `Authorization: Bearer <Arkavo CWT>`, checked before anything else, so a caller without one learns nothing about which creators have a catalog: 401 `token required` without it, 401 `invalid token` when it doesn't verify. Any Arkavo CWT the node verifies counts. Then the node asks the platform's decision service (`[catalog.authz]`) whether the token's subject may open the envelope's one attribute: action `read`, one resource of type `catalog_item` whose id is the catalog's hash and whose `attribute_value_fqns` is that attribute, with the `X-Entity-Token` devices and the node's environment in the chain. An operator's service CWT, admitted as the moderation API admits one (`client:<id>` with role `service-account`, `aud` naming the client, and the client in `[publishing] operator_client_ids`), skips the decision.

- **200:** the stored bundle JSON, with `ETag: "<seq>"` and `Cache-Control: private, max-age=300`: it is decided per reader, so only the caller reuses it. A publisher reads past caches, and sends the `ETag` back as `If-Match`.
- **400:** `invalid subject`; `too many entities` for a chain over 8.
- **401:** `token required`, `invalid token`, or an `X-Entity-Token` that doesn't verify or isn't bound to the bearer.
- **403:** `not entitled to catalog`: the reader doesn't hold the attribute. Prompt them to follow the creator's campaign. Distinct from 404.
- **404:** `catalog not found`. There is no catalog, the envelope's hash is blocked, the creator has a catalog block or a `hideCatalog` suspension, or the pointer names a catalog from before envelopes. Only this 404 means "no catalog".
- **502:** `decision unavailable` when the decision service doesn't answer or isn't configured; `key set unavailable`; `storage unavailable`.

### Fetching the document over iroh

Fetch `catalogHash` from the pinned node, with a size limit of `catalogSize`. The node serves catalog documents from `catalog-documents/` and `catalog-outboards/`. These are kept apart from `blobs/`, so a catalog document is never taken for a recording. Refusals follow [Reading a catalog and downloading](#reading-a-catalog-and-downloading-viewer):

- `ERR_PERMISSION` when the hash is blocked or its creator is hidden;
- `ERR_LIMIT` while the node computes a missing outboard.

### Publishing (Creator)

1. Read the stored pointer (`GET /v2/catalogs/<sub>`), keeping its `ETag`, decrypt its envelope and merge into its document (a 404: start an empty catalog). Set `seq` to one more than the higher of its `seq` and the highest this device has used.
2. Encrypt the merged document as a new [envelope](#the-envelope), with a fresh policy `uuid`.
3. Write the `/2` pointer bytes over the envelope's hash and size and the index's [`indexHash`](#indexhash), and keep them exactly.
4. Get a passkey assertion for RP `identity.arkavo.net`, with challenge SHA-256(pointer bytes) and user verification required. Allow only the signed-in account's credentials.
5. Get the attestation for the assertion's credential: `POST https://identity.arkavo.net/passkeys/credential-attestation`.
6. `PUT /v2/catalogs/<sub>` with the envelope, the bundle and the index (the merged document's `entries`, which `indexHash` covers), and `If-Match: <the ETag>`, or `If-None-Match: *` after a 404. Send exactly one of the two, in that form. On a 412 or a 409, go back to step 1 and retry once. On a 502 `storage unavailable`, read the pointer back as [a failed write](#put-v2catalogssub-publish) says; a second 502 for the same publish means going back to step 1.

## Removed with `/1` (2026-10-27)

- `PUT /catalogs/{sub}`, `GET /tags/{name}` and `PUT /tags/{name}`: a catalog is published with `PUT /v2/catalogs/{sub}` and found with `GET /v2/catalogs/{sub}`.
- `[http] accept_catalog_schema_1`, `[http] tag_prefix` and the `purge-catalogs-1` subcommand.
- A v2 pointer stored before envelopes names a `/1` document and has no index record: `GET /v2/catalogs/{sub}` answers 404 for it, and the creator's next publish replaces it at any `seq`.

## Removed: the campaign listing (2026-10-27)

- `GET /catalog/{group}`, the clear, ingest-time listing of every recording pushed under a campaign attribute. It ignored a creator's catalog: a recording taken out of the catalog stayed listed, any publisher could add one under another creator's campaign, and it had no titles. A campaign's recordings are its creator's catalog, `GET /v2/catalogs/<creator>`.
- Its index under `catalog-index/`, and the public attribute definitions on `/attributes` and `/attr/...`.
- Its `creator` field, and `campaign-creators/<id>` behind it. A campaign-to-creator lookup, `GET /v2/campaigns/{id}`, was briefly in its place (#50) and was removed too: the viewer gets a campaign's creator from its token (authnz-rs#128).
- `[http] catalog_token` and the `[catalog]` keys `enabled`, `group_attribute_fqn`, `attributes_url`, `attributes_file` and `cache_ttl_secs`. They are ignored if still set; `[catalog.authz]` stays, the decision service for catalog reads and publish decisions.
- Ingest still stores each recording's manifest at `manifests/<hash>`, which the publish checks read.

## Archive layout accepted at ingest

A pushed blob is ingested only when it is a ZIP holding an OpenTDF manifest. Ingest accepts either of two layouts:

- **The spec layout:**
  - the manifest is `manifest.json`;
  - the payload is the member that `payload.url` names (`0.payload` in Arkavo's FairPlay key-envelope archives);
  - extra members, such as fMP4 playlists, init segments and media segments, are allowed.
- **The legacy layout:** `0.manifest.json` with `0.payload`.

The manifest must parse as an OpenTDF manifest, with every required field present, and be at most 4 MiB. The payload member must exist and read back intact: ingest reads it to its end, checking its CRC. The archive may list at most 65,535 members.

Blobs larger than `[validation] max_blob_bytes` are refused. The default is 4294967295 bytes (4 GiB − 1), the largest `payloadSize`.
