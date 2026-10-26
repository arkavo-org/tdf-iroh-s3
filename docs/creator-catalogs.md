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
- **A creator's catalog is one JSON document listing their published recordings.**
  - The node stores each version by the BLAKE3 hash of its exact bytes.
  - The tag `catalog/<sub>` points at the current version.
- **Readers never trust a catalog because of where it came from.**
  - The document's bytes must hash to the value the tag names.
  - Its `owner` must equal the subject the reader asked for.
  - The node only accepts a document whose `owner` equals the subject of the uploader's token.

## Subjects

`<sub>` is the `sub` claim of the publisher's Arkavo CWT, exactly as minted. For the passkey session token, that is the account UUID in lowercase, for example `5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10`.

- The node compares tag and catalog names to `sub` byte for byte. It does not canonicalize them, so `catalog/<uuid>` and `catalog/arkavo:<uuid>` are different tags.
- Links carry the same string:
  - `https://app.arkavo.com/creator?sub=<sub>`
  - `https://app.arkavo.com/content?sub=<sub>&id=<contentID>`

## Catalog document, `arkavo.creator-catalog/1`

The document is UTF-8 JSON, at most **262 144 bytes**. The node stores the uploaded bytes verbatim, and the hash covers those bytes.

```json
{
  "schema": "arkavo.creator-catalog/1",
  "owner": "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10",
  "entries": [
    {
      "contentID": "rec-2b9c4f1e0d8a4c7f9e1d3b5a6c8f0e2d",
      "version": 2,
      "payloadHash": "4f8a…64 lowercase hex…",
      "payloadSize": 7342067,
      "title": "Studio session",
      "publishedAt": "2026-10-16T14:30:00Z",
      "attributeFQNs": ["https://patreon.arkavo.com/attr/campaign/value/12345678"]
    }
  ]
}
```

**Top-level fields**

| Field | Rule |
|---|---|
| `schema` | Exactly `"arkavo.creator-catalog/1"`. Readers reject any other value. |
| `owner` | Must equal the tag's `<sub>`: 1–248 bytes of `[A-Za-z0-9:._@-]`, not `.` and not containing `..`. |
| `entries` | An array of 0–1000 entries. An empty array is a valid catalog with nothing published. |

**Entry fields**

| Field | Rule |
|---|---|
| `contentID` | 1–256 bytes of `[A-Za-z0-9:._@-]`, not `.` and not containing `..`. It is unique within the document and stays the same when the creator republishes a recording. |
| `version` | An integer from 1 to 9007199254740991 (2⁵³−1). A republish with different bytes uses a larger version. |
| `payloadHash` | 64 lowercase hex characters: the BLAKE3 hash of the TDF bytes. At upload, it must name a blob the node has ingested and not blocked. |
| `payloadSize` | An integer from 1 to 4294967295 (4 GiB − 1, the viewer's limit): the TDF's size in bytes. At upload, it must equal the size `GET /blobs/<payloadHash>` reports. |
| `title` | Optional: leave the key out when there is no title (`null` is rejected). A string of 1–512 UTF-8 bytes. |
| `publishedAt` | RFC 3339 UTC to the second with a `Z` suffix (`YYYY-MM-DDTHH:MM:SSZ`). |
| `attributeFQNs` | An array of 0–32 URLs: the data attributes in the TDF's policy, for display. They grant nothing. Each URL starts with `https://` followed by a host, is at most 512 bytes, and uses only visible ASCII characters (0x21–0x7E), so it has no spaces or non-ASCII characters. |

**Rules for keys**

- Unknown keys are rejected, at the top level and in entries.
- A key that appears twice in one JSON object is rejected.
- Entry order carries no meaning. Readers sort.

## Catalog document, `arkavo.creator-catalog/2`

> **Proposed, not yet agreed (#38):** the `/2` limits (524 288 bytes per document, 262 144 per metadata TDF, pointer `catalogSize` up to 524 288) and `catalog_token = "optional"` verifying a presented token. Build against them, but expect changes until #38 records them.

Schema `/2` ([tdf-iroh-s3#39](https://github.com/arkavo-org/tdf-iroh-s3/issues/39), design in #38) protects what `/1` shows in the clear. An entry names only hashes and sizes. Its title, publish time and attributes are in a **metadata TDF**: a small standard ZTDF under the recording's own policy, so a viewer reads exactly the entries they could play. The node never decrypts it.

The document is UTF-8 JSON, at most **524 288 bytes** (a `/1` document stays at most 262 144).

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
      "metadataHash": "6d0e…64 lowercase hex…",
      "metadataSize": 2148
    }
  ]
}
```

- `schema` is exactly `"arkavo.creator-catalog/2"`. `owner` and `entries` follow the `/1` rules, and so do `contentID`, `version`, `payloadHash` and `payloadSize`.
- `metadataHash`: 64 lowercase hex characters, the BLAKE3 hash of the metadata TDF. It is unique within the document and never equals any entry's `payloadHash` (`entries[<i>].metadataHash duplicates entries[<j>].metadataHash`, `entries[<i>].metadataHash equals entries[<j>].payloadHash`).
- `metadataSize`: an integer from 1 to 262 144, the metadata TDF's size in bytes.
- An entry has exactly these six keys. `title`, `publishedAt` and `attributeFQNs` are refused as unknown keys. The `/1` key rules apply.

**The metadata TDF.**

- Its payload is the UTF-8 JSON object `{"contentID", "version", "title", "publishedAt", "attributeFQNs"}`, each field with the `/1` entry's rules (`title` optional). `contentID` and `version` equal the entry's: a reader refuses metadata that names another entry.
- Its policy has **only** the top-level keys `uuid` (fresh for each metadata TDF) and `body`. Every manifest can be read by anyone holding its hash, so the policy must not repeat the recording's `arkavo:classification`, `arkavo:components` or any other extension.
- Its manifest's `payload.mimeType` is `application/vnd.arkavo.catalog-entry+json`. The node indexes no blob of that type, so a metadata TDF never appears in `GET /catalog/{group}` although it carries the recording's attributes. The type tells a manifest's reader only that the blob is catalog metadata.
- Its `body.dataAttributes` and `body.dissem` equal the recording's, each as a set, and its key access objects name the same KAS URLs.
- It is pushed and ingested like a recording, in the same publish session.

## HTTP routes

TLS terminates in front of the node. Every error body is `{"error":"<message>"}`, with one exception: on an ungated node `POST /publish/sessions` answers 404 with an empty body (see [Publishing a recording](#publishing-a-recording-creator)).

### `PUT /catalogs/{sub}`: publish a catalog

The request:

- needs the header `Authorization: Bearer <Arkavo CWT>`;
- needs the header `Content-Type: application/json`;
- carries the document's exact bytes as its body.

The node checks the following in order. Each failure returns its own status.

1. **The token passes the publishing checks** in [publishing-and-moderation.md](publishing-and-moderation.md): the audience, the entitlement, a person rather than a service, and a subject that isn't suspended.
   - 401 when the token is missing or invalid.
   - 403 for an entitlement, service-token or suspension failure.
   - On a node with `[publishing] required = false`, the token still has to verify. The publishing checks are skipped.
2. **`{sub}` equals the token's `sub`.** Otherwise 403 `catalog does not match token subject`.
3. **The `Content-Type` is `application/json`.** Otherwise, including when the header is missing, 415 `content type must be application/json`. The media type is matched without regard to case, and parameters such as `; charset=utf-8` are allowed.
4. **The body is at most 524 288 bytes, and a `/1` document at most 262 144.** Otherwise 413 `catalog too large`.
5. **The body is a valid `arkavo.creator-catalog/1` or `/2` document whose `owner` equals `{sub}`.** Otherwise 422 `invalid catalog: <reason>`. After the cutover to `/2` a `/1` document is refused with 422 `invalid catalog: schema must be "arkavo.creator-catalog/2"`.
6. **Nothing is blocked:** no entry's `payloadHash` or `metadataHash`, and not the document's own BLAKE3 hash. Otherwise 403 `content is blocked`.
7. **Every `payloadHash`, then every `metadataHash`, is an ingested blob.** Otherwise 422 `payload <hash> is not ingested` or `metadata <hash> is not ingested`, naming the first missing one in entry order.
8. **Every entry's `payloadSize`, then every `metadataSize`, equals the ingested blob's size.** Otherwise 422 `payload <hash> size does not match` or `metadata <hash> size does not match`, naming the first mismatching entry in entry order. Each entry is checked, including entries that share a payload.
   - For `/2`, steps 8a–8d compare each metadata TDF with its recording, on the manifests the node stored at ingest:
   - **8a.** Both manifests are stored and readable. Otherwise 422 `payload <hash> manifest is not stored`, `metadata <hash> manifest is not stored`, or `… manifest is unreadable`. A recording ingested before the node stored manifests has none: push it again.
   - **8b.** The metadata policy has only `uuid` and `body`. Otherwise 422 `metadata <hash> policy may only hold uuid and body`.
   - **8c.** Its `payload.mimeType` is `application/vnd.arkavo.catalog-entry+json`. Otherwise 422 `metadata <hash> is not catalog metadata`.
   - **8d.** Its attributes, dissemination list and KAS are the recording's. Otherwise 422 `metadata <hash> policy does not match payload <hash>`.
9. **The node stores the bytes and moves the tag.**
   - It stores the bytes at `catalog-documents/<blake3>` and points the tag `catalog/<sub>` at that hash.
   - 200 `{"name":"catalog/<sub>","hash":"<blake3 hex>","size":<bytes>}`.

A catalog that hasn't changed produces the same hash. Uploading it again is harmless.

### `GET /catalog-documents/{hash}`: read a catalog

This route is public.

- **200:** the stored bytes, with `Content-Type: application/json`, `ETag: "<hash>"` and `Cache-Control: public, max-age=300`.
- **304:** no body, with the same `ETag` and `Cache-Control`, when `If-None-Match` names `"<hash>"` (or its weak form `W/"<hash>"`, or `*`), the document is stored, and it is not hidden.
- **400:** `invalid hash`. The hash must be 64 lowercase hex characters.
- **404:** `catalog not found`, also when the document's hash is blocked or its owner is suspended with `hideCatalog`, and also in answer to `If-None-Match`.

The bytes behind a hash never change, but the node may later block a document or hide its owner's catalog. So a client or proxy reuses a document for at most 5 minutes and then revalidates it, and a block or `hideCatalog` reaches readers within that time. The node records each document's `owner` alongside it when it stores it.

### `GET /tags/catalog/{sub}`: find a creator's current catalog

This route existed before this contract. It resolves a creator to their catalog, so it follows the node's token rule (`[http] catalog_token`, tdf-iroh-s3#39), checked before anything else:

- **`optional`** (until Creator and the iOS viewer send a token): no token is served as before. A presented `Authorization: Bearer <Arkavo CWT>` must verify, otherwise 401 `invalid token`.
- **`required`:** no token is 401 `token required`, whatever the subject.
- Any Arkavo CWT the node verifies counts, a service's included. It needn't be the creator's.

Then:

- **200:** `{"name":"catalog/<sub>","hash":"<hex>"}`.
- **404:** `tag not found`. There is no catalog, the creator is suspended with `hideCatalog`, the catalog is blocked, or the tag does not name a stored catalog document.

The tag `catalog/<sub>` existed before catalog documents, and an older tag may name a TDF blob instead of a catalog. The node answers such a tag with 404, as if there were no catalog. Creator then starts a new catalog, and a viewer shows that the creator has none, rather than both failing on `GET /catalog-documents`. The node checks each hash once and remembers the answer. When storage cannot answer, it returns the tag unchecked, and `GET /catalog-documents` answers for the document.

### `PUT /tags/catalog/{sub}`: point the tag at an earlier catalog

This route only moves the tag between catalogs the node already stores, for example to roll back to an earlier version. A new catalog is published with `PUT /catalogs/{sub}`.

This route needs the same token checks as `PUT /catalogs/{sub}`.

- The body is `{"hash":"<hex>"}`.
- The hash must not be blocked. Otherwise 403 `content is blocked`.
- The hash must be a stored catalog document whose `owner` equals `{sub}`. Otherwise 422 `hash does not reference a catalog document of this subject`. A TDF blob's hash is refused this way.
- The document must pass steps 5–8d of `PUT /catalogs/{sub}`: a schema still accepted, no payload or metadata blocked (403 `content is blocked`), every one ingested and of its size (422), and for `/2` every metadata TDF fitting its recording (422). So a rollback never brings back a recording blocked since that version was published, nor a `/1` catalog after the cutover.
- Success returns **204**.

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
   - `GET /tags/catalog/<sub>`, then `GET /catalog-documents/<hash>`.
   - A 404 on the tag means there is no catalog yet.
6. **Merge the entry.** Find it by `contentID`.
   - If the payload hash is unchanged, keep the entry as it is.
   - Otherwise write the new hash, size and `publishedAt`, with `version` one higher than the old entry's.
7. **Publish the catalog** with `PUT /catalogs/<sub>`.

For a `/2` catalog, steps 3–4 also push and confirm the entry's metadata TDF (see [the metadata TDF](#catalog-document-arkavocreator-catalog2)), and step 6 writes its hash and size, with the new `version` inside the metadata as well. Send a token on step 5's `GET /tags/catalog`.

To remove a recording, Creator uploads the catalog without its entry. The TDF stays on the node, but no catalog lists it.

## Reading a catalog and downloading (viewer)

1. **Find the current catalog.** `GET https://iroh.arkavo.net/tags/catalog/<sub>` with `Authorization: Bearer <Arkavo CWT>`; the node requires one after the token rollout.
2. **Fetch and verify it.**
   - `GET /catalog-documents/<hash>`, reading at most 524 288 bytes (262 144 for `/1`). Fetches by hash need no token.
   - The BLAKE3 hash of the bytes must equal `<hash>`.
   - The document must be valid, and its `owner` must equal `<sub>`.
   - For `/2`: fetch every entry's `metadataHash` over iroh (reject one larger than `metadataSize`), unwrap them in one bulk rewrap, refuse metadata whose `contentID` or `version` differs from its entry's, and show only the entries that decrypt.
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

Catalog v2 ([tdf-iroh-s3#27](https://github.com/arkavo-org/tdf-iroh-s3/issues/27)) changes how a creator's current catalog is named and proved. The document format above is unchanged.

- **The document travels over iroh.** A reader fetches it by BLAKE3 hash from the pinned node, the same way it fetches recordings.
- **The creator signs a pointer with their passkey.** The pointer names the document's hash and size and carries a sequence number.
- **The IdP attests the passkey.** identity.arkavo.net signs which passkey credential belongs to which subject ([authnz-rs#104](https://github.com/arkavo-org/authnz-rs/issues/104), `docs/passkey-credential-attestation.md` there).

A reader checks the whole chain itself. So neither the node nor its storage can forge a creator's catalog, or roll back a reader that has already seen a newer `seq`. They can still withhold a catalog, or show an older signed one to a reader that has never seen a newer `seq`.

v1 (`PUT /catalogs`, `GET /tags/catalog`, `GET /catalog-documents`) stays until Creator and the iOS viewer both ship v2.

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
| `catalogHash` | BLAKE3 of the document's bytes, 64 lowercase hex characters |
| `catalogSize` | the document's length in bytes, 1 to 524 288 |
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
4. **The document** hashes to `catalogHash`, is `catalogSize` bytes long, is a valid `arkavo.creator-catalog/1` or `/2`, and its `owner` is the pointer's `owner`.
5. **Rollback.** The node refuses a `seq` that is not greater than the stored one. A reader refuses a `seq` lower than the highest it has seen for that creator.

### `PUT /v2/catalogs/{sub}`: publish

The request needs `Authorization: Bearer <Arkavo CWT>` and `Content-Type: application/json`. Its body is `{"document": "<base64url document bytes>", "bundle": {…}}`, at most 1 MiB.

The request should name the base the client merged its document from, with a standard conditional header (RFC 9110). Without one, a publish signed while another device saved can replace that device's catalog.

- **`If-Match: "<seq>"`:** the client merged from the stored pointer with this `seq`, as `GET /v2/catalogs/{sub}` tagged it (`ETag`). The tag is compared strongly: a weak tag (`W/"7"`) or a bare `7` never matches. `If-Match: *` matches any pointer that `GET` serves.
- **`If-None-Match: *`:** the client merged from "no v2 catalog yet" (a 404, seeded from v1). No pointer may be stored, apart from one whose catalog is blocked: preconditions see what `GET` serves, and `GET` answers 404 for it. The `seq` must still be greater than the stored one's.

If the stored pointer is no longer that base, the node answers 412 `catalog changed since it was read` and stores nothing. Read the pointer again, merge, sign and retry. When both headers are sent, both must hold. A header value that is not visible ASCII fails. Without either header the node skips this check, for now; once clients send one, a missing precondition may become a 428.

The node checks the following in order:

| Check | Failure |
|---|---|
| The token passes the publishing checks (as `PUT /catalogs`) | 401 / 403 |
| `{sub}` equals the token's `sub` | 403 `catalog does not match token subject` |
| `Content-Type` is `application/json` | 415 |
| The body is at most 1 MiB | 413 `request too large` |
| The body has exactly `document` and `bundle` | 400 `invalid request: <reason>` |
| `document` is 1–524 288 bytes of unpadded base64url | 422 `invalid request: …` |
| Verification steps 1–3 | 422 `invalid bundle: <reason>`; 502 `key set unavailable` |
| The pointer names this document | 422 `invalid bundle: catalogHash or catalogSize does not match the document` |
| A valid catalog whose `owner` is `{sub}` | 422 `invalid catalog: <reason>` |
| A schema still accepted; nothing blocked; every payload and metadata TDF ingested at its size; for `/2`, each metadata TDF fitting its recording (as `PUT /catalogs`, steps 5–8d) | 403 / 422 |
| The passkey credential is still the subject's, according to the IdP's status route | 403 `passkey credential unknown`, `… revoked` or `… belongs to another subject`; 502 `credential status unavailable` |
| The stored pointer is the base named by `If-Match` or `If-None-Match`, if either is sent | 412 `catalog changed since it was read` |
| `seq` is greater than the stored one | 409 `seq must be greater than <n>` |

The node then stores the document at `catalog-documents/<blake3>` with its BAO outboard at `catalog-outboards/<blake3>`, and then the bundle at `catalog-pointers/<sub>`. The pointer is written only if no other publish replaced it in the meantime; otherwise 409 `seq must be greater than the stored seq: another publish won`. Read the pointer again and retry.

200: `{"owner":"<sub>","seq":<n>,"hash":"<blake3 hex>","size":<bytes>}`.

### `GET /v2/catalogs/{sub}`: read the pointer

This route follows the token rule of [`GET /tags/catalog/{sub}`](#get-tagscatalogsub-find-a-creators-current-catalog), checked first.

- **200:** the stored bundle JSON, with `ETag: "<seq>"` and `Cache-Control: private, max-age=300`: it may need a token, so only the caller reuses it. A publisher reads past caches, and sends the `ETag` back as `If-Match`.
- **400:** `invalid subject`.
- **404:** `catalog not found`. There is no catalog, or the creator is suspended with `hideCatalog`, or the catalog's hash is blocked. Only this 404 means "no catalog".

### Fetching the document over iroh

Fetch `catalogHash` from the pinned node, with a size limit of `catalogSize`. The node serves catalog documents from `catalog-documents/` and `catalog-outboards/`. These are kept apart from `blobs/`, so a catalog document is never taken for a recording. Refusals follow [Reading a catalog and downloading](#reading-a-catalog-and-downloading-viewer):

- `ERR_PERMISSION` when the hash is blocked or its creator is hidden;
- `ERR_LIMIT` while the node computes a missing outboard.

### Publishing (Creator)

1. Build the document as for v1.
2. Read the stored pointer (`GET /v2/catalogs/<sub>`), keeping its `ETag`, and merge into its document (a 404: seed from v1). Set `seq` to one more than the higher of its `seq` and the highest this device has used.
3. Write the pointer bytes and keep them exactly.
4. Get a passkey assertion for RP `identity.arkavo.net`, with challenge SHA-256(pointer bytes) and user verification required. Allow only the signed-in account's credentials.
5. Get the attestation for the assertion's credential: `POST https://identity.arkavo.net/passkeys/credential-attestation`.
6. `PUT /v2/catalogs/<sub>` with `If-Match: <the ETag>`, or `If-None-Match: *` after a 404. On a 412 or a 409, go back to step 2 and retry once.

## Cutover to `/2`

In the order of #38:

1. The node accepts `/2` next to `/1`, and a token on the resolution routes (`[http] catalog_token = "optional"`).
2. Creator publishes `/2` and republishes existing catalogs; the iOS viewer reads `/2` and sends a token.
3. The node sets `[http] catalog_token = "required"` and `accept_catalog_schema_1 = false`: `/1` uploads and rollbacks to `/1` are refused.
4. The operator runs `tdf-iroh-s3 --config <file> purge-catalogs-1`, a dry run, then with `--delete`. It deletes each stored `/1` document and its outboard, except one a catalog tag or v2 pointer still names, which it reports. Until it is deleted, a `/1` document, plaintext titles included, stays readable by its hash.

## Archive layout accepted at ingest

A pushed blob is ingested only when it is a ZIP holding an OpenTDF manifest. Ingest accepts either of two layouts:

- **The spec layout:**
  - the manifest is `manifest.json`;
  - the payload is the member that `payload.url` names (`0.payload` in Arkavo's FairPlay key-envelope archives);
  - extra members, such as fMP4 playlists, init segments and media segments, are allowed.
- **The legacy layout:** `0.manifest.json` with `0.payload`.

The manifest must parse as an OpenTDF manifest, with every required field present, and be at most 4 MiB. The payload member must exist and read back intact: ingest reads it to its end, checking its CRC. The archive may list at most 65,535 members.

Blobs larger than `[validation] max_blob_bytes` are refused. The default is 4294967295 bytes (4 GiB − 1), the largest `payloadSize`.
