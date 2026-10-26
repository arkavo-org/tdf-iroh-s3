# Moderation through the platform's decision service

**Status:** proposal, 2026-10-22. Node side (4a, 4d) implemented on `feat/pdp-publish-decisions`; rollout (4c) and the clean-up (4e) wait on steps 0–3.
**Scope:** tdf-iroh-s3, with the changes it needs in arkavo-rs (`arks`, the AuthZEN facade and moderation intake), arkavo-org/opentdf-platform (the fork serving platform.arkavo.net) and authnz-rs.
**Read at:** tdf-iroh-s3 `1d27393`, arkavo-rs `origin/main` `7bdd073`, opentdf-platform `main` `e562aca`.

## Problem

The node decides moderation questions alone, from its own data:

- **May this subject publish?** The node checks `arkavo_entitlements` in the CWT itself (`tags_api::authorize_publisher`), then checks its own suspension records.
- **Is this subject suspended, and is this hash blocked?** These are records under `moderation/` in S3, written through the node's operator API. That API answers 503, because no operator client exists (open follow-up since 2026-10-18).

The moderation decision itself is made somewhere else. arkavo-rs takes reports, holds the moderator queue and records `actioned` with `takedown` / `suspend` (arkavo-rs#77/#78). authnz-rs holds the publishing suspension and withholds the entitlement at the next mint. So today a suspension has two authorities, the IdP and the node, and the moderator has to carry out each action by hand (arkavo-rs `docs/moderation.md`).

The direction: the node asks the decision service at platform.arkavo.net (the arks AuthZEN facade in front of the OpenTDF platform) instead of deciding for itself. The node already calls it for catalog listings (`src/authz.rs`, `AuthZenClient`).

## What the decision service can and can't decide

These facts, found in the code, shape the design.

1. **The platform's policy is a startup snapshot.** Production runs `services.authorization.policy_file` (filestore: read-only, loaded at startup, no Postgres). A takedown that changes every few minutes can't live in policy without a reload per takedown.
2. **The PDP decides on attribute FQNs, not on resource identity.** The facade turns every resource except `tool` and `mcp_server` into the `attribute_value_fqns` the PEP supplies (`translate.rs map_resource`). The PDP only knows a hash is taken down if the node tells it, which defeats the point.
3. **Dynamic state reaches the PDP through the entity resolver.** The composite ERS (opentdf-platform#55) grants from sources and withholds through constraints. `constraints.agent_status` already calls authnz-rs live (`GET /agents/{did}/status`, cached for at most 5 s) and withholds every grant from an agent that isn't eligible. A suspended publisher fits this mechanism exactly.
4. **The publish entitlement doesn't reach the PDP today. There are three separate blocks:**
   - arks's `pe_claims` forwards only the Patreon `campaign` / `campaign-tier` values of `arkavo_entitlements`. Its test asserts that `…/arkavo-creator/value/publish` is dropped.
   - In the prod config, the `identity-core` source (which owns `…/arkavo-creator`) is `pep_assertable: false`, so it ignores a PEP's claims chain. Its actions default to `read`.
   - `…/arkavo-creator` is not defined in `policy.patreon.yaml`, and the live `GET https://platform.arkavo.net/attributes` doesn't list it.
5. **The protocol is the Arkavo AuthZEN CWT profile** (arkavo-org/specifications `authzen-cwt/draft-arkavo-authzen-cwt-00.md`), not OIDC.
   - **The PEP verifies.** The node union-verifies the person's CWT (`Authorization: Bearer`) and each device's DeviceCheck CWT (repeated `X-Entity-Token`, `aud` `arkavo:devicecheck`, each bound to the person through `subject_id_bind`). It sends the facade one SARC: the person as `subject`, the devices as `context.devices`, and the node's region as `context.environment`.
   - **The facade builds the chain.** It turns that SARC into the entity chain: person, then each device, then environment.
   - **Raw CWTs never reach the platform.** The profile forbids `entityIdentifier.token` for Arkavo CWTs.
   - **No audience change is needed.** A passkey CWT's `aud` `arkavo` is already a valid person audience under the profile (§"PEP verification algorithm", step 9). `OIDC_PLATFORM_AUDIENCE` belongs to OIDC access tokens.
   - **Gap: devices have no effect on decisions yet.** Device NPEs travel as `CATEGORY_ENVIRONMENT`, and the platform skips those (`skipEnvironmentEntities=true`). The profile names this as future work (§"Semantic gaps" 3), and so does the composite design's §6.
6. **The push path carries no token.** An iroh push names only an endpoint ID. The publish session is the only link between a push and a person.
7. **Block checks sit on the iroh hot path.** `Moderation::is_blocked` is synchronous and runs for every get, get-many and push. It must answer without a network call and keep working during a PDP outage.

## Design

Moderation splits into two layers, and the decision service fits only the first.

### Layer 1: subject decisions go to the PDP

**"May this subject publish now?"** becomes one AuthZEN evaluation, sent from the node through the existing `AuthZenClient` per the CWT profile. Creator sends its passkey CWT and its DeviceCheck CWTs (`X-Entity-Token`). The node verifies them and sends the full chain:

```json
{
  "subject": { "type": "identity", "id": "<sub>", "properties": { "iss": "…", "arkavo_entitlements": ["…/arkavo-creator/value/publish"] } },
  "action": { "name": "publish" },
  "context": {
    "devices": [{ "sub": "<uuid>", "iss": "https://identity.arkavo.net", "aud": "arkavo:devicecheck", "kid": "<cnf.kid>" }],
    "environment": { "region": "us-east-1" }
  },
  "evaluations": [{ "resource": { "type": "publisher", "id": "<sub>",
    "properties": { "attribute_value_fqns": ["https://patreon.arkavo.com/attr/arkavo-creator/value/publish"] } } }]
}
```

- **Action:** `publish` (owner, 2026-10-25, on opentdf-platform#59; arks's facade passes it through lowercased). A `read` request is denied. #59 first proposed `read`, the fork's convention for direct entitlements (`policy.arkavo.yaml`).
- **Where the node asks:**
  - `POST /publish/sessions`;
  - `PUT /tags/catalog/*`;
  - `PUT /catalogs/*`;
  - `PUT /v2/catalogs/*`.
- **What stays local:** authentication (CWT signature, issuer, `aud`, person not `client:*`). Authorization (the entitlement plus the suspension) comes from the PDP.
- **Suspension (decided: the platform is the authority and reads from itself):** a moderator's `suspend` is recorded on the platform (platform.arkavo.net: arks's moderation store, next to the OpenTDF platform). A new `constraints.publishing_status` in the composite ERS reads it there, over loopback, with no call to identity.
  - It runs only when a subject's grants include a value of `…/arkavo-creator`, so catalog viewers never pay for it.
  - It withholds `…/arkavo-creator` grants from a suspended account. If the status can't be read, it withholds them too (fail closed).
  - A suspension takes effect within seconds on every route, not at the next mint (up to 1 h).
  - The IdP also withholds the publish entitlement from the suspended account's tokens (decision 5): arks's `suspend` calls identity's `PUT /admin/users/:id/publishing-suspension` as well.
- **What the PDP adds:** in claims mode, the publish grant still rests on the entitlement that the node verified and asserted. What the PDP adds is the live suspension check, the agent gate, and one place for the policy. That is what the new fail-closed dependency buys.
- **The chain counts:** devices have to affect the decision, not only travel with it. The platform has to stop skipping device NPEs, or tell them apart from the environment (the profile's named future). Composite constraints such as device-class caps and the agent gate then apply to a device that comes with a person. In OpenTDF every SUBJECT entity must be entitled, and a device never holds the publish entitlement. So non-person entities have to narrow the person's grants as constraints, not count as co-subjects. **Decided: devices narrow a grant according to policy.** The policy says which device attestation or class a grant requires, or which grants a device class is capped to. The ERS config doesn't hard-code it. Bug: opentdf-platform#60.
- **Pushes:** the session record (`moderation/sessions/<endpoint>`) also stores the PEP-verified SARC the decision used: the person's `sub`, `iss` and publish entitlement, the device objects, and no bearer token. `authorize_push` asks the PDP again with those claims, cached per subject for 30 s. A suspension therefore stops pushes within about 30 s, as the node's refresh does today, without waiting for the session's 900 s TTL. A record written before this change has no stored claims, so a push that finds one is refused like a missing session. At most a session's 900 s are lost, once, at rollout.
- **Failure mode: fail closed (decided).** If the PDP can't be reached, session open and catalog writes answer 503, and pushes are refused with a permission error. Falling back to the local check would quietly restore today's behaviour and hide an outage. This is a change: today publishing never depends on platform.arkavo.net. The catalog listing already does.

### Layer 2: content blocks stay on the node, written by arks

The moderator's decision (`actioned` with `takedown`) is made in arkavo-rs. Enforcement stays where the checks run:

- **On the node:** blocks stay in `moderation/blocks/<hash>`, read into memory and refreshed every 30 s. They are answered synchronously and survive a PDP outage. They are no longer written by hand. arks writes them as the moderation client through `PUT /moderation/blocks/{hash}`, which is arkavo-rs#93, decided 2026-10-18.
- **At the KAS:** arks refuses rewraps of a taken-down TDF before forwarding them (arkavo-rs#93 step 1). One takedown set in arkavo-rs, enforced at both places.
- **Suspended creators' catalogs (decided: blocked).** A suspension blocks the creator's catalog and every one of their catalog documents, always, not only when a moderator asks. The node gets a subject-scoped catalog block (route `/moderation/blocks/catalogs/{subject}`, stored at `moderation/catalog-blocks/<subject>`, a sibling of `blocks/` because records are listed recursively), written by arks when it records the suspension and lifted with it. The node already knows each catalog document's owner (the `hideCatalog` path), so one record covers past documents too, and the PDP stops new ones. Effects:
  - `GET /tags/catalog/<sub>` and `GET /v2/catalogs/<sub>` answer 404;
  - `GET /catalog-documents/<hash>` and iroh fetches of the creator's catalog documents are refused.

  The creator's recordings stay up unless a moderator takes them down. The node keeps no suspension records: the platform holds that state.

**Rejected: per-hash PDP decisions on fetch.** Each fetch would need either a facade evaluator for a new `content` resource type, or the deny-only restrictor seam (opentdf-platform#42/#43, open since 2026-09-20) with a takedown source. Either one puts a network call, its 10 s timeout and the PDP's availability on every iroh get. A cache would make that tolerable, but then it is the same pull-a-list model as above, with more moving parts. It is worth revisiting only if #43 lands for other reasons.

### What changes on the node

| Today | After |
|---|---|
| Entitlement checked locally in `authorize_publisher` | PDP evaluation of the person + device + environment chain (fail closed) |
| Device tokens ignored on publish routes | `X-Entity-Token` DeviceCheck CWTs verified and sent as `context.devices` |
| Suspension records refuse sessions, pushes and tag writes; `hideCatalog` optional | The PDP refuses through `publishing_status`. The node keeps no suspension records |
| — | Subject-scoped catalog blocks, written by arks: a suspended creator's catalog and catalog documents are blocked |
| Push gate: live session plus local suspension | Live session plus a PDP decision on the session's stored claims (30 s cache) |
| Blocks: hand-written S3 objects, operator API 503 | Same store, written by arks's moderation client |
| `[catalog.authz]` used only by the catalog | Also used for publish decisions (same endpoint, credential and client) |

New config: `[publishing] decisions = "local" | "shadow" | "pdp"`.

- `shadow` decides both ways, enforces the local answer and logs every disagreement.
- The default stays `local` until the platform side is live.
- `shadow` or `pdp` with no `[catalog.authz] endpoint` is a startup error. Otherwise `DenyAll` would refuse all publishing without a word.

## Plan

**Ordering:** steps 0–3 block the rollout (4c) and the clean-up (4e); 4a and 4d don't need them. Within the platform work, 2a has to come before 2b.

**0. Pre-checks (read-only; they block everything else)**

- Is the composite ERS (opentdf-platform#55, merged 2026-10-18) deployed at platform.arkavo.net, or is prod still on `patreon` mode? The committed prod config is marked "draft" with `claims_chain_peps: []`. If it isn't live, the composite cutover (its spec §8) comes first.
- The node's client ID as the platform sees it on a catalog AuthZEN decision. It belongs in `claims_chain_peps`, and the catalog cutover needs it too.

**1. authnz-rs**

- authnz-rs#103: register arks's moderation client (for its node calls). Done: `arkavo-moderation` (client credentials, `sub` `client:arkavo-moderation`, role `service-account`). The platform needs no identity access for suspensions.

**2. opentdf-platform (fork)**

- **2a. Constraint:** `constraints.publishing_status`, scoped to subjects holding an `…/arkavo-creator` grant. It reads suspension state from the platform itself (arks's moderation store over loopback), with the same allowed-only 5 s cache as `agent_status`. Tests:
  - a suspended account loses `arkavo-creator` and keeps everything else;
  - unreadable status withholds only that grant;
  - a subject without the grant makes no lookup.
- **2b. Config:**
  - define `https://patreon.arkavo.com/attr/arkavo-creator` (`anyOf`, value `publish`) in `policy.patreon.yaml`;
  - on `identity-core`, set `pep_assertable: true`;
  - add the node's client ID to `claims_chain_peps`.
- **2c. Chain semantics (#59, bug #60):** device NPEs affect decisions. Stop skipping them, or distinguish devices from environment. A device narrows the person's grants as the **policy** declares (required attestation or class per grant, caps per class).

**3. arkavo-rs**

- **3a. Facade:** `pe_claims` also forwards `…/arkavo-creator/value/publish`, under the same sanitiser and cap. The platform's capability check stays the binding guard.
- **3b. Moderation (arkavo-rs#93):**
  - on `suspend`, record the suspension in the platform's store (which the constraint reads), and `PUT` the node's catalog block for the subject; on lift, remove both;
  - on `takedown`, resolve `contentId` → payload hash through the creator catalog, `PUT` the node block, and deny rewraps;
  - retry until each call succeeds, and record each outcome on the report.

**3c. Creator (arkavo-org/Creator)**

- Send DeviceCheck CWTs as repeated `X-Entity-Token` on `POST /publish/sessions` and the catalog writes. Today neither Creator nor ArkavoKit sends one. Confirm App Attest / DeviceCheck support on Creator's platforms (macOS and iOS), and what a Mac without it presents.

**4. tdf-iroh-s3**

- **4a. Publish decisions:** a `PublishDecider` over `DecisionProvider`, with the `decisions` flag and `shadow` logging. The publish routes accept repeated `X-Entity-Token` DeviceCheck CWTs, union-verify them per the profile and send `context.devices` and `context.environment`. Store the verified SARC (no tokens) in session records, and re-decide at push.
- **4b. Operator client:** put `arkavo-moderation` in `[publishing] operator_client_ids` (host config and launch template). Its secret stays in arks's secret store.
- **4c. Rollout:** deploy with `local`. Switch to `shadow` only once opentdf-platform#59 is merged and identity-core has `pep_assertable: true`: until then the platform can't grant the publish attribute, and every member's publish would log a disagreement (local permits, platform denies). Switch to `pdp` after a set number of agreeing permits from real members (`Publish decision shadow: agrees` with `pdp=Permit`), plus the suspended test account denied both ways (which needs 2a live; `shadow` asks for a suspended subject and logs the answer before the local suspension refuses it), with no disagreement. Count agreeing permits, not agreements: at most 2 Patreon accounts and no App Store account hold the entitlement, so most decisions are deny/deny and agree without proving anything. Count decisions, not days: publishes are rare.
- **Devices** aren't required in the chain, so 4a works without them. Device tokens come in this order: authnz 0.23.1 deployed (live since 2026-10-25; before it no real device could get a DeviceCheck token from `/device-check/assert`), Creator#96 sends them, a real assertion fixture is captured, authnz#114 adds the app and environment claims, then platform#60's device rule uses them. Key rotation needs nothing here: `verify_device` looks keys up by `kid` and refreshes on a miss.
- **4d. Catalog blocks:** add subject-scoped catalog blocks (`PUT/DELETE /moderation/blocks/catalogs/{subject}`), reusing the owner tracking of today's `hideCatalog`.
- **4e. Clean up (after the switch to `pdp`, with 2a live):** until then the local suspension check stays in every mode, since removing it under `local` or `shadow` would leave suspensions enforced nowhere. Then remove suspension records, the `/moderation/suspensions` routes, `hideCatalog` (catalog blocks replace it) and the startup suspension count from the node, and update `docs/publishing-and-moderation.md` and `CLAUDE.md`.

## Decisions (owner, 2026-10-22)

1. **Publishing fails closed** while the decision service is down.
2. **A suspended creator's catalog and catalog documents are blocked.**
3. **The platform determines suspension status and reads it from itself**, with no identity call.
4. **Devices narrow a grant based on policy.**
5. **A suspension also removes the publish entitlement from tokens** (2026-10-25). arks's `suspend` writes its own store, identity's `publishing-suspension` and the node's catalog block. The node keeps its local suspension records until the platform's check is live in `pdp`.
