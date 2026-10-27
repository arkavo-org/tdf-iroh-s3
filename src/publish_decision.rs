//! Whether a subject may publish, asked of the platform's decision service
//! (tdf-iroh-s3#35, `docs/superpowers/specs/2026-10-22-moderation-decisions-design.md`).
//!
//! The node still authenticates the publisher (CWT signature, issuer, `aud`,
//! a person rather than a service client). What it asks the PDP is one
//! AuthZEN evaluation: action `publish` on a `publisher` resource carrying the
//! publish entitlement's attribute value, for the whole entity chain (the
//! person, each attested device, the environment). The platform withholds
//! that grant from a suspended account, and devices narrow it as its policy
//! says. It is asked when a publish session opens, not again for each push:
//! the session's Permit holds until it expires (tdf-iroh-s3#44).
//!
//! `[publishing] decisions` picks who decides:
//! - `local`: this node, from the CWT's `arkavo_entitlements` (as before);
//! - `shadow`: both; the local answer is enforced and every disagreement is
//!   logged, so the switch to `pdp` can be judged on real publishes;
//! - `pdp`: the platform. A decision that can't be made refuses (fails
//!   closed).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::authz::{
    ChainEntity, DecisionRequest, EntityKind, ResourceType, SharedDecisionProvider,
};
pub use crate::config::PublishDecisions;

/// The PDP's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Permit,
    Deny,
    /// No decision: the PDP failed, timed out or isn't configured.
    Unavailable,
}

/// A chain entity as a publish session stores it: the claims the decision
/// was asked with, never a token. A session holds a chain only when the
/// decision service permitted it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredEntity {
    pub kind: EntityKind,
    pub claims: Value,
}

/// The chain without its tokens, to store with a publish session.
pub fn strip_tokens(chain: &[ChainEntity]) -> Vec<StoredEntity> {
    chain
        .iter()
        .map(|e| StoredEntity {
            kind: e.kind,
            claims: e.claims.clone(),
        })
        .collect()
}

pub struct PublishDecider {
    mode: PublishDecisions,
    provider: Option<SharedDecisionProvider>,
    /// The attribute value FQN the `publisher` resource carries.
    entitlement: String,
    /// The environment entity this node appends (its region).
    environment: Option<Value>,
}

impl Default for PublishDecider {
    /// Local decisions only.
    fn default() -> Self {
        Self {
            mode: PublishDecisions::Local,
            provider: None,
            entitlement: crate::moderation::DEFAULT_PUBLISH_ENTITLEMENT.to_string(),
            environment: None,
        }
    }
}

impl PublishDecider {
    /// `provider` is required unless `mode` is `local`: without it every
    /// decision would be `Unavailable`, refusing all publishing in `pdp`.
    pub fn new(
        mode: PublishDecisions,
        provider: Option<SharedDecisionProvider>,
        entitlement: String,
        environment: Option<Value>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            mode == PublishDecisions::Local || provider.is_some(),
            "[publishing] decisions = {mode:?} needs [catalog.authz] endpoint"
        );
        Ok(Self {
            mode,
            provider,
            entitlement,
            environment,
        })
    }

    pub fn mode(&self) -> PublishDecisions {
        self.mode
    }

    /// Whether the PDP is asked at all.
    pub fn asks(&self) -> bool {
        self.mode != PublishDecisions::Local
    }

    /// The environment entity to append to a chain, if this node has one.
    pub fn environment(&self) -> Option<&Value> {
        self.environment.as_ref()
    }

    /// Ask the PDP whether `chain` may publish.
    pub async fn ask(&self, chain: &[ChainEntity]) -> Verdict {
        let Some(provider) = &self.provider else {
            return Verdict::Unavailable;
        };
        let Some(sub) = chain
            .iter()
            .find(|e| e.is_subject())
            .and_then(|e| e.claims.get("sub"))
            .and_then(Value::as_str)
        else {
            return Verdict::Unavailable;
        };
        let req = DecisionRequest {
            chain: chain.to_vec(),
            action: "publish".into(),
            resource_type: ResourceType::Publisher,
            resources: vec![(sub.to_string(), vec![self.entitlement.clone()])],
        };
        match provider.decide_dyn(req).await {
            Ok(d) if d.get(sub).copied().unwrap_or(false) => Verdict::Permit,
            Ok(_) => Verdict::Deny,
            Err(e) => {
                warn!(%sub, error = %e, "Publish decision failed");
                Verdict::Unavailable
            }
        }
    }
}

/// Log a shadow decision that disagrees with the enforced local one.
pub fn log_shadow(on: &'static str, sub: &str, local_permits: bool, pdp: Verdict) {
    let agrees = matches!(
        (local_permits, pdp),
        (true, Verdict::Permit) | (false, Verdict::Deny)
    );
    if agrees {
        info!(on, %sub, ?pdp, "Publish decision shadow: agrees");
    } else {
        warn!(on, %sub, local_permits, ?pdp, "Publish decision shadow: disagrees");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{DecisionProvider, Decisions};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct Stub {
        permit: bool,
        fail: bool,
        calls: AtomicUsize,
        seen: Mutex<Option<DecisionRequest>>,
    }

    impl DecisionProvider for Stub {
        async fn decide(&self, req: DecisionRequest) -> anyhow::Result<Decisions> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.seen.lock().unwrap() = Some(req.clone());
            anyhow::ensure!(!self.fail, "pdp down");
            Ok(req
                .resources
                .iter()
                .map(|(id, _)| (id.clone(), self.permit))
                .collect())
        }
    }

    fn stub(permit: bool, fail: bool) -> Arc<Stub> {
        Arc::new(Stub {
            permit,
            fail,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(None),
        })
    }

    fn decider(s: &Arc<Stub>) -> PublishDecider {
        PublishDecider::new(
            PublishDecisions::Pdp,
            Some(Arc::clone(s) as SharedDecisionProvider),
            "https://p.example/attr/arkavo-creator/value/publish".into(),
            None,
        )
        .unwrap()
    }

    fn chain() -> Vec<ChainEntity> {
        vec![
            ChainEntity {
                kind: EntityKind::Subject,
                token: None,
                claims: serde_json::json!({ "sub": "arkavo:u1", "iss": "https://id.test" }),
            },
            ChainEntity {
                kind: EntityKind::Device,
                token: None,
                claims: serde_json::json!({ "sub": "u1", "aud": "arkavo:devicecheck", "kid": "k" }),
            },
        ]
    }

    #[test]
    fn pdp_mode_without_a_provider_is_a_startup_error() {
        for mode in [PublishDecisions::Shadow, PublishDecisions::Pdp] {
            assert!(PublishDecider::new(mode, None, "x".into(), None).is_err());
        }
        assert!(PublishDecider::new(PublishDecisions::Local, None, "x".into(), None).is_ok());
    }

    #[tokio::test]
    async fn asks_for_the_publisher_resource_with_the_whole_chain() {
        let s = stub(true, false);
        assert_eq!(decider(&s).ask(&chain()).await, Verdict::Permit);
        let req = s.seen.lock().unwrap().clone().unwrap();
        assert_eq!(req.resource_type, ResourceType::Publisher);
        assert_eq!(req.action, "publish");
        assert_eq!(
            req.resources,
            vec![(
                "arkavo:u1".to_string(),
                vec!["https://p.example/attr/arkavo-creator/value/publish".to_string()]
            )]
        );
        assert_eq!(req.chain.len(), 2);
        assert_eq!(req.chain[1].kind, EntityKind::Device);
    }

    #[tokio::test]
    async fn deny_and_failure_are_told_apart() {
        assert_eq!(
            decider(&stub(false, false)).ask(&chain()).await,
            Verdict::Deny
        );
        assert_eq!(
            decider(&stub(true, true)).ask(&chain()).await,
            Verdict::Unavailable
        );
    }

    #[test]
    fn stored_chains_keep_kinds_and_drop_tokens() {
        let mut c = chain();
        c[0].token = Some("secret-cwt".into());
        c[1].token = Some("device-cwt".into());
        let stored = strip_tokens(&c);
        let json = serde_json::to_string(&stored).unwrap();
        assert!(!json.contains("secret-cwt") && !json.contains("device-cwt"));
        let back: Vec<StoredEntity> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[1].kind, EntityKind::Device);
    }
}
