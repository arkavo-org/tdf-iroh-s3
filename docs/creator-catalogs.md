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

The node can't decrypt the envelope, so the publisher sends the document's entries in the clear alongside it, as `index` in `PUT /v2/catalogs/{sub}`: a JSON array of at most 1000 entries, each exactly `{"contentID", "version", "payloadHash", "payloadSize"}`, the document's entry without its `metadata`, held to the same rules. The node checks the recordings against what it has ingested, stores the index at `catalog-indexes/<hash>` and **never serves it**. Moderation reads it to find a recording's hash from its `contentID`.

The index and the encrypted document are bound only by the creator's honesty. An entry left out of the index can only hide the creator's own entry from moderation, so reports carry the `payloadHash`, not just a `contentID`.

## HTTP routes

TLS terminates in front of the node. Every error body is `{"error":"<message>"}`, with one exception: on an ungated node `POST /publish/sessions` answers 404 with an empty body (see [Publishing a recording](#publishing-a-recording-creator)).

### `GET /catalog-documents/{hash}`: read a catalog

This route is public: the bytes are an envelope, ciphertext to anyone who can't open its attribute.

- **200:** the stored bytes, with `Content-Type: application/zip`, `ETag: "<hash>"` and `Cache-Control: public, max-age=300`.
- **304:** no body, with the same `ETag` and `Cache-Control`, when `If-None-Match` names `"<hash>"` (or its weak form `W/"<hash>"`, or `*`), the document is stored, and it is not hidden.
- **400:** `invalid hash`. The hash must be 64 lowercase hex characters.
- **404:** `catalog not found`, also when the document's hash is blocked or its owner is suspended with `hideCatalog`, and also in answer to `If-None-Match`.

The bytes behind a hash never change, but the node may later block a document or hide its owner's catalog. So a client or proxy reuses a document for at most 5 minutes and then revalidates it, and a block or `hideCatalog` reaches readers within that time. The node records each document's `owner` alongside it when it stores it.

### `GET /blobs/{hash}`: confirm ingest

This route is public. It is how a publisher confirms ingest before naming a hash in a catalog.

- **200:** `{"hash":"<hex>","size":<bytes>}`, when the hash is an ingested TDF that is not blocked. The node stores the blob's outboard before the blob, so a 200 means the blob can be fetched.
- **404:** `blob not found`. The hash was never pushed, is still being ingested, failed validation, or is blocked.
- **400:** `invalid hash`.

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

To remove a recording, Creator publishes the catalog without its entry. The TDF stays on the node, but no catalog lists it.

## Reading a catalog and downloading (viewer)

1. **Find the current catalog.** `GET https://iroh.arkavo.net/v2/catalogs/<sub>` with `Authorization: Bearer <Arkavo CWT>` (see [`GET /v2/catalogs/{sub}`](#get-v2catalogssub-read-the-pointer)). A 403 `not entitled to catalog` means the viewer doesn't hold the creator's campaign: prompt them to follow it on Patreon. A viewer that knows only a campaign id, from the campaigns in its token, first asks [`GET /v2/campaigns/<id>`](#get-v2campaignsid-find-a-campaigns-creator) for its creator.
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
- **The creator signs a pointer with their passkey.** The pointer names the envelope's hash and size and carries a sequence number.
- **The IdP attests the passkey.** identity.arkavo.net signs which passkey credential belongs to which subject ([authnz-rs#104](https://github.com/arkavo-org/authnz-rs/issues/104), `docs/passkey-credential-attestation.md` there).

A reader checks the whole chain itself. So neither the node nor its storage can forge a creator's catalog, or roll back a reader that has already seen a newer `seq`. They can still withhold a catalog, or show an older signed one to a reader that has never seen a newer `seq`.

**Encoding.** Every binary value in v2 is base64url **without padding** (RFC 4648 §5, no `=`). The node refuses padded values and the standard alphabet's `+` and `/`.

### The pointer

The exact UTF-8 bytes of one JSON object. It is carried base64url-encoded and is never re-serialized, so the signed bytes are the bytes everyone reads.

```json
{"schema":"arkavo.catalog-pointer/1","owner":"<sub>","seq":7,"catalogHash":"<64 lowercase hex>","catalogSize":1234,"issuedAt":"2026-10-19T01:02:03Z"}
```

| Field | Rule |
|---|---|
| `schema` | `arkavo.catalog-pointer/1` |
| `owner` | the publisher's `sub`, byte for byte (the same rules as a catalog's `owner`) |
| `seq` | integer, 1 to 9 007 199 254 740 991 |
| `catalogHash` | BLAKE3 of the envelope's bytes, 64 lowercase hex characters |
| `catalogSize` | the envelope's length in bytes, 1 to 4 194 304 |
| `issuedAt` | `YYYY-MM-DDTHH:MM:SSZ` |

The object holds exactly these keys, with no key repeated and nothing after it, and is at most 1024 bytes.

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

The request should name the base the client merged its document from, with a standard conditional header (RFC 9110). Without one, a publish signed while another device saved can replace that device's catalog.

- **`If-Match: "<seq>"`:** the client merged from the stored pointer with this `seq`, as `GET /v2/catalogs/{sub}` tagged it (`ETag`). The tag is compared strongly: a weak tag (`W/"7"`) or a bare `7` never matches. `If-Match: *` matches any pointer that `GET` serves.
- **`If-None-Match: *`:** the client merged from "no catalog yet" (a 404). No pointer may be stored, apart from one `GET` doesn't serve: preconditions see what `GET` serves. That is a pointer whose catalog is blocked, whose `seq` must still be exceeded, or one at a catalog from before envelopes, which reads as no pointer at all, so the first envelope may start at any `seq`.

If the stored pointer is no longer that base, the node answers 412 `catalog changed since it was read` and stores nothing. Read the pointer again, merge, sign and retry. When both headers are sent, both must hold. A header value that is not visible ASCII fails. Without either header the node skips this check, for now; once clients send one, a missing precondition may become a 428.

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
| The pointer names this document | 422 `invalid bundle: catalogHash or catalogSize does not match the document` |
| `document` is a ZTDF archive (manifest and payload member, as [ingest accepts](#archive-layout-accepted-at-ingest)) | 422 `document is not a TDF` |
| Its `payload.mimeType` is `application/vnd.arkavo.creator-catalog+json` | 422 `document is not a catalog` |
| Its policy has only `uuid` and `body`, no `dissem`, and exactly one campaign attribute or `{sub}`'s creator attribute ([The envelope](#the-envelope)) | 422 `catalog policy must be one campaign or the creator attribute` |
| Its policy's `uuid` is a non-empty string | 422 `catalog policy has no uuid` |
| For a campaign attribute: the token's `arkavo_patreon` has role `creator` and a `campaign_id` (a string) equal to the envelope's campaign id. Identity sets it only for the campaign the account owns. | 403 `catalog campaign is not the publisher's` |
| `index` is an array of at most 1000 valid [index entries](#the-index) with unique `contentID`s | 422 `invalid index: <reason>`, e.g. `invalid index: entries[3].contentID duplicates entries[1].contentID` |
| Nothing blocked: the envelope's hash, no entry's `payloadHash` | 403 `content is blocked` |
| Every `payloadHash` is an ingested blob | 422 `payload <hash> is not ingested`, the first missing one in entry order |
| Every entry's `payloadSize` equals the ingested blob's size, each entry checked, also entries that share a payload | 422 `payload <hash> size does not match` |
| Every recording's manifest is stored (at ingest) and readable. A recording ingested before the node stored manifests has none: push it again. | 422 `payload <hash> manifest is not stored` or `… manifest is unreadable` |
| Every entry's recording policy names the envelope's attribute | 422 `entry <contentID> policy does not include the catalog attribute` |
| The passkey credential is still the subject's, according to the IdP's status route | 403 `passkey credential unknown`, `… revoked` or `… belongs to another subject`; 502 `credential status unavailable` |
| The stored pointer is the base named by `If-Match` or `If-None-Match`, if either is sent | 412 `catalog changed since it was read` |
| `seq` is greater than the stored one | 409 `seq must be greater than <n>` |

The node then stores the envelope at `catalog-documents/<blake3>` with its BAO outboard at `catalog-outboards/<blake3>`, the index at `catalog-indexes/<blake3>` (never served), then the bundle at `catalog-pointers/<sub>`, and, once that has taken effect, for a campaign envelope the creator at `campaign-creators/<campaign id>`. [`GET /v2/campaigns/<campaign id>`](#get-v2campaignsid-find-a-campaigns-creator) names that creator to a reader entitled to the campaign, so a viewer can find `GET /v2/catalogs/<creator>`. The pointer is written only if no other publish replaced it in the meantime; otherwise 409 `seq must be greater than the stored seq: another publish won`. Read the pointer again and retry.

200: `{"owner":"<sub>","seq":<n>,"hash":"<blake3 hex>","size":<bytes>}`.

### `GET /v2/catalogs/{sub}`: read the pointer

The request needs `Authorization: Bearer <Arkavo CWT>`, checked before anything else, so a caller without one learns nothing about which creators have a catalog: 401 `token required` without it, 401 `invalid token` when it doesn't verify. Any Arkavo CWT the node verifies counts. Then the node asks the platform's decision service (`[catalog.authz]`) whether the token's subject may open the envelope's one attribute: action `read`, one resource of type `catalog_item` whose id is the catalog's hash and whose `attribute_value_fqns` is that attribute, with the `X-Entity-Token` devices and the node's environment in the chain. An operator's service CWT, admitted as the moderation API admits one (`client:<id>` with role `service-account`, `aud` naming the client, and the client in `[publishing] operator_client_ids`), skips the decision.

- **200:** the stored bundle JSON, with `ETag: "<seq>"` and `Cache-Control: private, max-age=300`: it is decided per reader, so only the caller reuses it. A publisher reads past caches, and sends the `ETag` back as `If-Match`.
- **400:** `invalid subject`; `too many entities` for a chain over 8.
- **401:** `token required`, `invalid token`, or an `X-Entity-Token` that doesn't verify or isn't bound to the bearer.
- **403:** `not entitled to catalog`: the reader doesn't hold the attribute. Prompt them to follow the creator's campaign. Distinct from 404.
- **404:** `catalog not found`. There is no catalog, the creator is suspended with `hideCatalog`, the catalog is blocked, or the pointer names a catalog from before envelopes. Only this 404 means "no catalog".
- **502:** `decision unavailable` when the decision service doesn't answer or isn't configured; `key set unavailable`; `storage unavailable`.

### `GET /v2/campaigns/{id}`: find a campaign's creator

For a viewer who holds a Patreon campaign but follows no creator: the campaign's creator, whose catalog is then read with `GET /v2/catalogs/<creator>`. The creator is the account recorded at that campaign's last catalog publish, which only the campaign's own creator can make (`arkavo_patreon` role `creator` with that `campaign_id`).

The token is checked first, as on `GET /v2/catalogs/{sub}`. Then `id`, 1 to 20 ASCII digits. Then the decision service is asked whether the token's subject holds the campaign: action `read`, one resource of type `catalog_item` whose id is the campaign id and whose `attribute_value_fqns` is `https://patreon.arkavo.com/attr/campaign/value/<id>`, with the same chain. The decision comes before the lookup, so a reader who doesn't hold the campaign can't tell whether it has a creator. An operator's service CWT skips it.

- **200:** `{"creator":"<sub>"}`, with `Cache-Control: private, max-age=300`.
- **400:** `invalid campaign`; `too many entities` for a chain over 8.
- **401:** `token required`, `invalid token`, or an `X-Entity-Token` that doesn't verify or isn't bound to the bearer.
- **403:** `not entitled to campaign`.
- **404:** `campaign not found`. No catalog was ever published under the campaign, or its creator is suspended with `hideCatalog`.
- **502:** `decision unavailable`; `key set unavailable`; `storage unavailable`.

### Fetching the document over iroh

Fetch `catalogHash` from the pinned node, with a size limit of `catalogSize`. The node serves catalog documents from `catalog-documents/` and `catalog-outboards/`. These are kept apart from `blobs/`, so a catalog document is never taken for a recording. Refusals follow [Reading a catalog and downloading](#reading-a-catalog-and-downloading-viewer):

- `ERR_PERMISSION` when the hash is blocked or its creator is hidden;
- `ERR_LIMIT` while the node computes a missing outboard.

### Publishing (Creator)

1. Read the stored pointer (`GET /v2/catalogs/<sub>`), keeping its `ETag`, decrypt its envelope and merge into its document (a 404: start an empty catalog). Set `seq` to one more than the higher of its `seq` and the highest this device has used.
2. Encrypt the merged document as a new [envelope](#the-envelope), with a fresh policy `uuid`.
3. Write the pointer bytes over the envelope's hash and size, and keep them exactly.
4. Get a passkey assertion for RP `identity.arkavo.net`, with challenge SHA-256(pointer bytes) and user verification required. Allow only the signed-in account's credentials.
5. Get the attestation for the assertion's credential: `POST https://identity.arkavo.net/passkeys/credential-attestation`.
6. `PUT /v2/catalogs/<sub>` with the envelope, the bundle and the index (the merged document's `entries`), and `If-Match: <the ETag>`, or `If-None-Match: *` after a 404. On a 412 or a 409, go back to step 1 and retry once.

## Removed with `/1` (2026-10-27)

- `PUT /catalogs/{sub}`, `GET /tags/{name}` and `PUT /tags/{name}`: a catalog is published with `PUT /v2/catalogs/{sub}` and found with `GET /v2/catalogs/{sub}`.
- `[http] accept_catalog_schema_1`, `[http] tag_prefix` and the `purge-catalogs-1` subcommand.
- A v2 pointer stored before envelopes names a `/1` document and has no index record: `GET /v2/catalogs/{sub}` answers 404 for it, and the creator's next publish replaces it at any `seq`.

## Removed: the campaign listing (2026-10-27)

- `GET /catalog/{group}`, the clear, ingest-time listing of every recording pushed under a campaign attribute. It ignored a creator's catalog: a recording taken out of the catalog stayed listed, any publisher could add one under another creator's campaign, and it had no titles. A campaign's recordings are its creator's catalog: `GET /v2/campaigns/{id}`, then `GET /v2/catalogs/<creator>`.
- Its index under `catalog-index/`, and the public attribute definitions on `/attributes` and `/attr/...`.
- `[http] catalog_token` and the `[catalog]` keys `enabled`, `group_attribute_fqn`, `attributes_url`, `attributes_file` and `cache_ttl_secs`. They are ignored if still set; `[catalog.authz]` stays, the decision service for catalog and campaign reads and for publish decisions.
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
