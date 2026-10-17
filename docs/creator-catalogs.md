# Creator catalogs and distribution

This is the contract between three parties:

- the tdf-iroh-s3 node at iroh.arkavo.net, which this repository builds;
- the Creator app, which publishes;
- the Arkavo iOS viewer, which reads.

It covers four things: how a creator's recordings are published, how a viewer finds and downloads them, the catalog document format, and the HTTP routes involved. Publishing sessions and moderation are covered in [publishing-and-moderation.md](publishing-and-moderation.md).

## Model

- **A recording is one TDF archive, addressed by the BLAKE3 hash of its bytes.**
  - The creator pushes it to the node over iroh.
  - The node validates it as a TDF, stores it, and serves it to any peer by hash.
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
4. **The body is at most 262 144 bytes.** Otherwise 413 `catalog too large`.
5. **The body is a valid `arkavo.creator-catalog/1` document whose `owner` equals `{sub}`.** Otherwise 422 `invalid catalog: <reason>`.
6. **Nothing is blocked:** no entry's `payloadHash`, and not the document's own BLAKE3 hash. Otherwise 403 `content is blocked`.
7. **Every `payloadHash` is an ingested blob.** Otherwise 422 `payload <hash> is not ingested`, naming the first missing payload in entry order.
8. **Every entry's `payloadSize` equals the ingested blob's size.** Otherwise 422 `payload <hash> size does not match`, naming the first mismatching entry's payload in entry order. Each entry is checked, including entries that share a payload.
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

This route is public and existed before this contract.

- **200:** `{"name":"catalog/<sub>","hash":"<hex>"}`.
- **404:** `tag not found`. There is no catalog, the creator is suspended with `hideCatalog`, the catalog is blocked, or the tag does not name a stored catalog document.

The tag `catalog/<sub>` existed before catalog documents, and an older tag may name a TDF blob instead of a catalog. The node answers such a tag with 404, as if there were no catalog. Creator then starts a new catalog, and a viewer shows that the creator has none, rather than both failing on `GET /catalog-documents`. The node checks each hash once and remembers the answer. When storage cannot answer, it returns the tag unchecked, and `GET /catalog-documents` answers for the document.

### `PUT /tags/catalog/{sub}`: point the tag at an earlier catalog

This route only moves the tag between catalogs the node already stores, for example to roll back to an earlier version. A new catalog is published with `PUT /catalogs/{sub}`.

This route needs the same token checks as `PUT /catalogs/{sub}`.

- The body is `{"hash":"<hex>"}`.
- The hash must not be blocked. Otherwise 403 `content is blocked`.
- The hash must be a stored catalog document whose `owner` equals `{sub}`. Otherwise 422 `hash does not reference a catalog document of this subject`. A TDF blob's hash is refused this way.
- The document's entries must pass the same payload checks as an upload, steps 6–8 of `PUT /catalogs/{sub}`: no payload blocked (403 `content is blocked`), every payload ingested (422 `payload <hash> is not ingested`), and every `payloadSize` matching (422 `payload <hash> size does not match`). So a rollback never brings back a recording blocked since that version was published.
- Success returns **204**.

### `GET /blobs/{hash}`: confirm ingest

This route is public. It is how a publisher confirms ingest before naming a hash in a catalog.

- **200:** `{"hash":"<hex>","size":<bytes>}`, when the hash is an ingested TDF that is not blocked.
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
   - The node serves a pushed blob over iroh only once it validates. A blob it refuses is never served and is deleted.
   - Push and fetch single blobs (`GetRequest::blob`). The node refuses hash-sequence requests.
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

To remove a recording, Creator uploads the catalog without its entry. The TDF stays on the node, but no catalog lists it.

## Reading a catalog and downloading (viewer)

1. **Find the current catalog.** `GET https://iroh.arkavo.net/tags/catalog/<sub>`, without credentials.
2. **Fetch and verify it.**
   - `GET /catalog-documents/<hash>`, reading at most 262 144 bytes.
   - The BLAKE3 hash of the bytes must equal `<hash>`.
   - The document must be valid, and its `owner` must equal `<sub>`.
3. **Download a recording.** Fetch `payloadHash` over iroh, from the endpoint ID compiled into the viewer.
   - Reject the download if it is larger than `payloadSize`.
   - Verify the BLAKE3 hash before using the file.
   - Expect the transfer to fail now and then: iroh connections stall, drop and change paths. A failed transfer is worth another attempt; the node keeps nothing from it.
4. **Read the node's refusal.** The node approves or refuses each request before it sends a byte. A refused request is reset with an iroh-blobs error code:
   - `ERR_PERMISSION` (1) is final. The hash is blocked, or the node does not hold it as valid content. Do not retry. A `get_many` naming more than 64 hashes gets this answer before any lookup, so fetch one blob at a time.
   - `ERR_LIMIT` (2) means try again. The blob is being pushed or checked, or the node is busy or could not reach its storage. Retry with a backoff.
   - The Arkavo iOS viewer already maps these (ADR-0057 §5): iroh-swift reports `ERR_PERMISSION` as "permission denied", which the viewer treats as not found, and `ERR_LIMIT` as a failure it retries.

## Archive layout accepted at ingest

A pushed blob is ingested only when it is a ZIP holding an OpenTDF manifest. Ingest accepts either of two layouts:

- **The spec layout:**
  - the manifest is `manifest.json`;
  - the payload is the member that `payload.url` names (`0.payload` in Arkavo's FairPlay key-envelope archives);
  - extra members, such as fMP4 playlists, init segments and media segments, are allowed.
- **The legacy layout:** `0.manifest.json` with `0.payload`.

The manifest must parse as an OpenTDF manifest, with every required field present, and be at most 4 MiB. The payload member must exist and read back intact: ingest reads it to its end, checking its CRC. The archive may list at most 65,535 members.

Blobs larger than `[validation] max_blob_bytes` are refused. The default is 4294967295 bytes (4 GiB − 1), the largest `payloadSize`.
