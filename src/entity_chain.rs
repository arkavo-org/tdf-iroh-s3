//! The entity chain a decision is asked about (draft-arkavo-authzen-cwt-00):
//! the verified person, each attested device, then the environment this node
//! observes. Shared by `GET /v2/catalogs/{sub}` and the publishing
//! decision.
//!
//! - Person: claims from a CWT this node verified.
//! - Devices: zero or more repeated `X-Entity-Token: <DeviceCheck CWT>`
//!   headers (`get_all`, not comma-separated). Each must verify with
//!   `aud=arkavo:devicecheck` and bind to the person via `subject_id_bind`
//!   (a single leading `arkavo:` is stripped; `apple:`/`client:` are not).
//! - Environment: the configured region, appended by this node, never
//!   client-supplied.
//!
//! The chain is capped at `1 + D + E ≤ 8`.

use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;
use tracing::warn;

use crate::auth::{CwtVerifier, DEVICECHECK_AUD, VerifiedClaims, subject_id_bind};
use crate::authz::{ChainEntity, EntityKind};

/// 1 person + D devices + E environment (E is 0 or 1).
pub const MAX_CHAIN_ENTITIES: usize = 8;

/// The `X-Entity-Token` values, in header order.
pub fn entity_tokens(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all("x-entity-token")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect()
}

/// Refuse a chain longer than [`MAX_CHAIN_ENTITIES`] before anything is
/// verified.
pub fn check_length(devices: usize, environment: bool) -> Result<(), (StatusCode, &'static str)> {
    if 1 + devices + usize::from(environment) > MAX_CHAIN_ENTITIES {
        return Err((StatusCode::BAD_REQUEST, "too many entities"));
    }
    Ok(())
}

/// The person entity, from claims this node extracted from the *verified*
/// CWT. `arkavo_entitlements` is forwarded as it is, when there are any: the
/// platform derives the subject's entitlements from it (opentdf-platform#69,
/// tdf-iroh-s3#51). The whole `arkavo_patreon` claim is forwarded too, for
/// the transition (the AuthZEN client allowlists its fields), `iss` so the
/// platform can pin the issuer, and `patreon_user_id` / `email` as the ERS's
/// lookup keys. `token` is kept
/// only for the OpenTDF client's token mode; it is never stored.
pub fn subject_entity(pe: &VerifiedClaims, token: Option<&str>) -> ChainEntity {
    let mut claims = serde_json::Map::new();
    claims.insert("sub".into(), pe.sub.clone().into());
    claims.insert("iss".into(), pe.iss.clone().into());
    if let Some(uid) = &pe.patreon_user_id {
        claims.insert("patreon_user_id".into(), uid.clone().into());
    }
    if let Some(email) = &pe.email {
        claims.insert("email".into(), email.clone().into());
    }
    if let Some(v) = pe.email_verified {
        claims.insert("email_verified".into(), v.into());
    }
    if let Some(idp) = &pe.idp {
        claims.insert("idp".into(), idp.clone().into());
    }
    if let Some(id) = &pe.arkavo_account_id {
        claims.insert("arkavo_account_id".into(), id.clone().into());
    }
    if let Some(roles) = &pe.arkavo_roles {
        claims.insert("arkavo_roles".into(), roles.clone().into());
    }
    if !pe.arkavo_entitlements.is_empty() {
        claims.insert(
            "arkavo_entitlements".into(),
            pe.arkavo_entitlements.clone().into(),
        );
    }
    if let Some(id) = &pe.client_id {
        claims.insert("client_id".into(), id.clone().into());
    }
    if let Some(patreon) = &pe.arkavo_patreon {
        claims.insert("arkavo_patreon".into(), patreon.clone());
    }
    ChainEntity {
        kind: EntityKind::Subject,
        token: token.map(str::to_string),
        claims: Value::Object(claims),
    }
}

/// Verify each DeviceCheck CWT and bind it to the person `pe_sub`. Any token
/// that fails is a 401: a presented-but-invalid credential is an error, not
/// a shorter chain.
pub async fn verified_devices(
    verifier: &CwtVerifier,
    tokens: &[&str],
    pe_sub: &str,
    now: i64,
) -> Result<Vec<ChainEntity>, (StatusCode, &'static str)> {
    let mut devices = Vec::with_capacity(tokens.len());
    for token in tokens {
        let claims = verifier.verify_device(token, now).await.map_err(|e| {
            warn!(error = %e, "NPE token verification failed");
            (StatusCode::UNAUTHORIZED, "invalid entity token")
        })?;
        if subject_id_bind(&claims.sub) != subject_id_bind(pe_sub) {
            warn!("Entity chain subject mismatch");
            return Err((
                StatusCode::UNAUTHORIZED,
                "entity token subject does not match bearer subject",
            ));
        }
        // verify_device guarantees the DeviceCheck audience is present; the
        // PDP's device schema takes exactly that string, whatever else `aud`
        // listed.
        let Some(kid) = claims.kid.as_deref().filter(|k| !k.is_empty()) else {
            return Err((StatusCode::UNAUTHORIZED, "invalid entity token"));
        };
        devices.push(ChainEntity {
            kind: EntityKind::Device,
            // Sent on to the PDP, which refuses surrounding whitespace.
            token: Some(token.trim().to_string()),
            claims: serde_json::json!({
                "sub": claims.sub,
                "iss": claims.iss,
                "aud": DEVICECHECK_AUD,
                "kid": kid,
            }),
        });
    }
    Ok(devices)
}

/// The chain for a person this node verified from `pe_token`: the person,
/// each `X-Entity-Token` device bound to them, then the environment, if
/// this node asserts one. A chain over [`MAX_CHAIN_ENTITIES`] is 400; a
/// device that fails is 401 ([`verified_devices`]).
pub async fn person_chain(
    verifier: &CwtVerifier,
    pe: &VerifiedClaims,
    pe_token: &str,
    headers: &HeaderMap,
    environment: Option<&Value>,
    now: i64,
) -> Result<Vec<ChainEntity>, (StatusCode, &'static str)> {
    let npe_tokens = entity_tokens(headers);
    check_length(npe_tokens.len(), environment.is_some())?;
    let mut chain = vec![subject_entity(pe, Some(pe_token))];
    chain.extend(verified_devices(verifier, &npe_tokens, &pe.sub, now).await?);
    if let Some(env) = environment {
        chain.push(environment_entity(env));
    }
    Ok(chain)
}

/// The environment entity: asserted by this node, never client-supplied.
pub fn environment_entity(environment: &Value) -> ChainEntity {
    ChainEntity {
        kind: EntityKind::Environment,
        token: None,
        claims: environment.clone(),
    }
}
