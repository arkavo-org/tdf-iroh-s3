//! Entitlement decisions for the catalog, delegated to the OpenTDF
//! authorization service (authorization.v2) — this node never evaluates
//! policy locally, so there is exactly one PDP (the platform).
//!
//! Requests are made over ConnectRPC's JSON mapping (a plain HTTP POST of
//! the proto-JSON request — no codegen needed). The entity input is the
//! full chain, PE → NPE → NPE:
//!
//! - PE: the consumer's CWT, passed as a token for the platform's ERS to
//!   resolve (`CreateEntityChainsFromTokens` → Patreon ERS).
//! - NPE: attested app/device CWTs presented by the client
//!   (`X-Entity-Token`), category ENVIRONMENT.
//! - NPE: the environment this node observes (e.g. its region), asserted
//!   server-side — never client-supplied.
//!
//! Unconfigured ⇒ `DenyAll`: the catalog still lists, nothing is entitled.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::warn;

/// One entity in the chain, ordered PE first.
#[derive(Debug, Clone)]
pub struct ChainEntity {
    /// True for the person entity; false for NPEs (category ENVIRONMENT).
    pub is_subject: bool,
    /// Bearer token (base64url CWT) for token-backed entities.
    pub token: Option<String>,
    /// Claims for entities this node asserts directly (observed
    /// environment); ignored when `token` is set.
    pub claims: Value,
}

#[derive(Debug, Clone)]
pub struct DecisionRequest {
    pub chain: Vec<ChainEntity>,
    pub action: String,
    /// (resource id, attribute-value FQNs) per catalog item.
    pub resources: Vec<(String, Vec<String>)>,
}

/// Per-resource verdicts keyed by resource id. Missing id ⇒ treat as deny.
pub type Decisions = HashMap<String, bool>;

pub trait DecisionProvider: Send + Sync + 'static {
    fn decide(&self, req: DecisionRequest) -> impl Future<Output = Result<Decisions>> + Send;
}

/// Fail-closed provider used when no authorization endpoint is configured.
pub struct DenyAll;

impl DecisionProvider for DenyAll {
    async fn decide(&self, req: DecisionRequest) -> Result<Decisions> {
        Ok(req
            .resources
            .into_iter()
            .map(|(id, _)| (id, false))
            .collect())
    }
}

/// ConnectRPC-JSON client for authorization.v2.
pub struct ConnectAuthzClient {
    endpoint: String,
    bearer_token: Option<String>,
    /// Send multi-entity chains as `entityIdentifier.entityChain`.
    /// EXPERIMENTAL: an explicit entityChain tells the PDP the entities are
    /// already resolved — the ERS does not unpack tokens buried in claims —
    /// so this shape must be contract-verified against the platform before
    /// production use. When false (default), the PE token is always sent as
    /// `entityIdentifier.token` (the path the ERS resolves) and NPE/
    /// environment context is logged but not forwarded.
    entity_chain_mode: bool,
    http: reqwest::Client,
}

impl ConnectAuthzClient {
    pub fn new(endpoint: String, bearer_token: Option<String>, entity_chain_mode: bool) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bearer_token,
            entity_chain_mode,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    /// Build the proto-JSON GetDecisionMultiResource request.
    fn build_request(&self, req: &DecisionRequest) -> Result<Value> {
        let pe = req
            .chain
            .iter()
            .find(|e| e.is_subject)
            .context("decision request has no subject entity")?;
        let pe_token = pe.token.as_ref().context("subject entity has no token")?;

        let entity_identifier = if self.entity_chain_mode && req.chain.len() > 1 {
            let entities: Vec<Value> = req
                .chain
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    let category = if e.is_subject {
                        "CATEGORY_SUBJECT"
                    } else {
                        "CATEGORY_ENVIRONMENT"
                    };
                    let mut claims = e.claims.clone();
                    if let Some(token) = &e.token {
                        claims = json!({ "token": token });
                    }
                    json!({
                        "ephemeralId": format!("e{i}"),
                        "category": category,
                        "claims": {
                            "@type": "type.googleapis.com/google.protobuf.Struct",
                            "value": claims,
                        },
                    })
                })
                .collect();
            json!({ "entityChain": { "ephemeralId": "chain", "entities": entities } })
        } else {
            // The contract-verified path: a token identifier triggers the
            // platform ERS (CreateEntityChainsFromTokens) to resolve the
            // subject's claims. NPE/environment entities are validated at
            // the edge but not yet forwarded — see entity_chain_mode.
            if req.chain.len() > 1 {
                warn!(
                    dropped = req.chain.len() - 1,
                    "NPE/environment entities verified but not forwarded (entity_chain_mode off)"
                );
            }
            json!({ "token": { "ephemeralId": "pe", "jwt": pe_token } })
        };

        Ok(json!({
            "entityIdentifier": entity_identifier,
            "action": { "name": req.action },
            "resources": req.resources.iter().map(|(id, fqns)| json!({
                "ephemeralId": id,
                "attributeValues": { "fqns": fqns },
            })).collect::<Vec<_>>(),
        }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultiResourceResponse {
    #[serde(default)]
    resource_decisions: Vec<ResourceDecision>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceDecision {
    #[serde(default)]
    ephemeral_resource_id: String,
    #[serde(default)]
    decision: String,
}

impl DecisionProvider for ConnectAuthzClient {
    async fn decide(&self, req: DecisionRequest) -> Result<Decisions> {
        let url = format!(
            "{}/authorization.v2.AuthorizationService/GetDecisionMultiResource",
            self.endpoint
        );
        let body = self.build_request(&req)?;

        let mut http_req = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body);
        if let Some(token) = &self.bearer_token {
            http_req = http_req.bearer_auth(token);
        }

        let resp = http_req
            .send()
            .await
            .with_context(|| format!("authorization POST {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            warn!(%status, "authorization service rejected decision request");
            anyhow::bail!("authorization service returned {status}: {text}");
        }
        let parsed: MultiResourceResponse = resp
            .json()
            .await
            .context("authorization response JSON parse")?;

        Ok(parsed
            .resource_decisions
            .into_iter()
            .map(|d| (d.ephemeral_resource_id, d.decision == "DECISION_PERMIT"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(token: &str) -> ChainEntity {
        ChainEntity {
            is_subject: true,
            token: Some(token.to_string()),
            claims: Value::Null,
        }
    }

    #[tokio::test]
    async fn deny_all_denies_everything() {
        let req = DecisionRequest {
            chain: vec![],
            action: "read".into(),
            resources: vec![("r1".into(), vec![])],
        };
        let d = DenyAll.decide(req).await.unwrap();
        assert_eq!(d.get("r1"), Some(&false));
    }

    fn client(entity_chain_mode: bool) -> ConnectAuthzClient {
        ConnectAuthzClient::new("https://platform.test".into(), None, entity_chain_mode)
    }

    #[test]
    fn single_pe_token_uses_token_identifier() {
        let req = DecisionRequest {
            chain: vec![pe("tok-abc")],
            action: "read".into(),
            resources: vec![(
                "hash1".into(),
                vec!["https://p.example/attr/tier/value/gold".into()],
            )],
        };
        let body = client(false).build_request(&req).unwrap();
        assert_eq!(body["entityIdentifier"]["token"]["jwt"], "tok-abc");
        assert_eq!(body["action"]["name"], "read");
        assert_eq!(body["resources"][0]["ephemeralId"], "hash1");
        assert_eq!(
            body["resources"][0]["attributeValues"]["fqns"][0],
            "https://p.example/attr/tier/value/gold"
        );
    }

    #[test]
    fn chain_mode_off_forwards_only_the_pe_token() {
        // The safe default: NPE/environment context must never push the
        // request into the unverified entityChain shape, which the ERS
        // would treat as already-resolved (deny-everything footgun).
        let req = DecisionRequest {
            chain: vec![
                pe("pe-tok"),
                ChainEntity {
                    is_subject: false,
                    token: None,
                    claims: json!({ "region": "us-east-1" }),
                },
            ],
            action: "read".into(),
            resources: vec![("r".into(), vec![])],
        };
        let body = client(false).build_request(&req).unwrap();
        assert_eq!(body["entityIdentifier"]["token"]["jwt"], "pe-tok");
        assert!(body["entityIdentifier"]["entityChain"].is_null());
    }

    #[test]
    fn request_without_subject_is_an_error() {
        let req = DecisionRequest {
            chain: vec![ChainEntity {
                is_subject: false,
                token: None,
                claims: json!({}),
            }],
            action: "read".into(),
            resources: vec![],
        };
        assert!(client(false).build_request(&req).is_err());
    }

    #[test]
    fn chain_with_npes_uses_entity_chain() {
        let req = DecisionRequest {
            chain: vec![
                pe("pe-tok"),
                ChainEntity {
                    is_subject: false,
                    token: Some("npe-tok".into()),
                    claims: Value::Null,
                },
                ChainEntity {
                    is_subject: false,
                    token: None,
                    claims: json!({ "region": "us-east-1" }),
                },
            ],
            action: "read".into(),
            resources: vec![("r".into(), vec![])],
        };
        let body = client(true).build_request(&req).unwrap();
        let entities = body["entityIdentifier"]["entityChain"]["entities"]
            .as_array()
            .unwrap();
        assert_eq!(entities.len(), 3);
        assert_eq!(entities[0]["category"], "CATEGORY_SUBJECT");
        assert_eq!(entities[1]["category"], "CATEGORY_ENVIRONMENT");
        assert_eq!(entities[2]["claims"]["value"]["region"], "us-east-1");
    }
}
