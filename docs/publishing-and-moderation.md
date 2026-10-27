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

**Pushes.** The decision service is asked when a session opens, not for each push (tdf-iroh-s3#44). A session it permitted stores the chain it was decided with, never a token; one it denied or wasn't asked about stores none. A push on a permitted session is accepted until the session expires, at most `session_ttl_secs` later, whatever the platform says in between. So a suspension made at the platform, a device revoked or an entitlement changed stops pushes from the next session; a local suspension or a block stops them at once. A session read back from the store is held at most `session_ttl_secs`, whatever its record's `expiresAt`, and in `pdp` its stored chain's person must be its subject. Since a stored session record alone authorizes pushes, it must not be writable by anyone else (tdf-iroh-s3#46). In `pdp` a push is refused when its session has no stored chain (`NoSession`): it was opened while decisions were local, or is missing or expired.

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
- The pusher's subject is recorded at `moderation/publishers/<hash>`.
- Each session is also stored at `moderation/sessions/<endpointId>` as `{"endpointId", "subject", "expiresAt"}`, plus `chain` when decisions aren't local (see above). A node that receives a push from an endpoint it holds no session for reads this record (5 s timeout) before refusing. So a session opened on one instance holds for a push that reaches another, during an instance replacement or after a restart (#32). A record that has expired, names another endpoint, can't be read, or can't be fetched in time counts as no session. At most 16 lookups run at once; a push that finds them all busy is refused. An endpoint whose lookup found no live session is refused for 10 s without another lookup. So a peer without a session can't make the node send S3 a request per push.
- If the node can't store a session, `POST /publish/sessions` still succeeds. The session then holds only on the instance that opened it, and the node logs `Publish session not stored`.
- Session records are overwritten per endpoint and never deleted. An S3 lifecycle rule on `moderation/sessions/` keeps the prefix small: expire objects after 1 day. On a versioned bucket, every overwrite also keeps the old version, so expire noncurrent versions after 1 day as well.

### 2. Publish the catalog

Use `PUT /v2/catalogs/<sub>` ([creator-catalogs.md](creator-catalogs.md)). It requires the entitlement, an unsuspended subject, and content that is not blocked.

### When a membership lapses

When the membership lapses, the entitlement disappears from new tokens (authnz-rs#91). New sessions and tag writes are then refused. Published content stays up until a moderator blocks it.

### Creator app impact

The Creator app must open a session before each push. Until it does, pushes to a gated node are refused. Set `required = false` only on development nodes.

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
| `PUT /moderation/blocks/{hash}` `{"reason","reportId"?}` | Takedown: iroh pushes of the hash are refused, and so are iroh get and get-many requests for it (a get-many that names it among other hashes is refused whole). Observe requests are always refused. It is left out of `/catalog/{group}` listings, no tag may point at it, and a tag already pointing at it returns 404. |
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

- **Deleting stored bytes.** A block stops distribution, but it does not remove the blob or its outboard from S3.
- **Resolving a report's `contentId` to hashes.** That waits for the frozen catalog schema, so a takedown names payload hashes.
- **Consuming arkavo-rs's NATS `moderation.actions.*` events.** That NATS is not reachable from EC2. arkavo-rs or a moderator calls this API.

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

The node's IAM role needs `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on `<prefix>moderation/*`, which includes `moderation/audit/`.
