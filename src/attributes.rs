//! Attribute definitions, OpenTDF-shaped, served on public endpoints.
//!
//! Attributes are NOT hardcoded: they live in a declarative JSON artifact
//! (see `attributes/patreon.arkavo.com.json`) loaded once at startup — the
//! "static final" attribute set. The HTTP listener serves it so attribute
//! FQNs resolve via standard URL + JSON conventions when the namespace
//! host points at this node:
//!
//! - `GET /attributes`                 → the whole definition set
//! - `GET /attr/{name}`                → one attribute definition
//! - `GET /attr/{name}/value/{value}`  → one attribute value
//!
//! An FQN like `https://patreon.arkavo.com/attr/tier/value/gold` is then a
//! real dereferenceable URL: scheme + namespace host + the exact path this
//! router serves. Rule names follow the OpenTDF policy enum
//! (`ATTRIBUTE_RULE_TYPE_ENUM_{ALL_OF,ANY_OF,HIERARCHY}`).

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The full definition set: one namespace and its attributes. This is the
/// authoritative artifact served verbatim on `/attributes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSet {
    pub namespace: Namespace,
    pub attributes: Vec<AttributeDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub name: String,
    #[serde(default)]
    pub fqn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDefinition {
    pub name: String,
    /// OpenTDF rule enum name: ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF | _ANY_OF | _HIERARCHY.
    pub rule: String,
    #[serde(default)]
    pub fqn: String,
    pub values: Vec<AttributeValueDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeValueDef {
    pub value: String,
    #[serde(default)]
    pub fqn: String,
}

const VALID_RULES: &[&str] = &[
    "ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF",
    "ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF",
    "ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY",
];

impl AttributeSet {
    /// Load and validate the definitions artifact. FQNs are derived from
    /// namespace + name when absent, and must match when present — the file
    /// is the single source of truth, so internal inconsistency is fatal.
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read attributes file {path}"))?;
        let mut set: AttributeSet =
            serde_json::from_str(&raw).context("Failed to parse attributes JSON")?;
        set.normalize_and_validate()?;
        Ok(set)
    }

    fn normalize_and_validate(&mut self) -> Result<()> {
        if self.namespace.name.is_empty() {
            bail!("namespace.name is required");
        }
        let ns_fqn = format!("https://{}", self.namespace.name);
        if self.namespace.fqn.is_empty() {
            self.namespace.fqn = ns_fqn.clone();
        } else if self.namespace.fqn != ns_fqn {
            bail!(
                "namespace fqn {} does not match name-derived {}",
                self.namespace.fqn,
                ns_fqn
            );
        }

        for attr in &mut self.attributes {
            if !VALID_RULES.contains(&attr.rule.as_str()) {
                bail!(
                    "attribute {} has unknown rule {:?} (expected one of {:?})",
                    attr.name,
                    attr.rule,
                    VALID_RULES
                );
            }
            let attr_fqn = format!("{ns_fqn}/attr/{}", attr.name);
            if attr.fqn.is_empty() {
                attr.fqn = attr_fqn.clone();
            } else if attr.fqn != attr_fqn {
                bail!(
                    "attribute {} fqn {} does not match derived {}",
                    attr.name,
                    attr.fqn,
                    attr_fqn
                );
            }
            for v in &mut attr.values {
                let value_fqn = format!("{attr_fqn}/value/{}", v.value);
                if v.fqn.is_empty() {
                    v.fqn = value_fqn;
                } else if v.fqn != value_fqn {
                    bail!(
                        "value {} fqn {} does not match derived {}",
                        v.value,
                        v.fqn,
                        value_fqn
                    );
                }
            }
        }
        Ok(())
    }

    pub fn attribute(&self, name: &str) -> Option<&AttributeDefinition> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Look up an attribute definition by its FQN
    /// (`https://<namespace>/attr/<name>`).
    pub fn attribute_by_fqn(&self, fqn: &str) -> Option<&AttributeDefinition> {
        self.attributes.iter().find(|a| a.fqn == fqn)
    }
}

/// Fetch the attribute definitions from the platform's public attributes
/// endpoint (the single source of truth — the same snapshot the PDP
/// evaluates) and return every attribute FQN. Used at startup to validate
/// the configured grouping attribute when the node is NOT serving
/// definitions itself.
pub async fn fetch_attribute_fqns(url: &str) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Listing {
        #[serde(default)]
        attributes: Vec<RemoteAttribute>,
    }
    #[derive(serde::Deserialize)]
    struct RemoteAttribute {
        #[serde(default)]
        fqn: String,
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("reqwest client")?;
    let resp = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("attributes endpoint returned {}", resp.status());
    }
    let listing: Listing = resp.json().await.context("attributes JSON parse")?;
    let fqns: Vec<String> = listing
        .attributes
        .into_iter()
        .map(|a| a.fqn)
        .filter(|f| !f.is_empty())
        .collect();
    if fqns.is_empty() {
        anyhow::bail!("attributes endpoint returned no definitions with FQNs");
    }
    Ok(fqns)
}

/// Routes serving the definition set. Mounted on the same listener as the
/// tag/catalog API; point the namespace host (e.g. patreon.arkavo.com) at
/// this node (or proxy these paths) and every FQN dereferences.
pub fn router(set: Arc<AttributeSet>) -> Router {
    Router::new()
        .route("/attributes", get(get_all))
        .route("/attr/{name}", get(get_attr))
        .route("/attr/{name}/value/{value}", get(get_value))
        .with_state(set)
}

/// Definitions are a static artifact — cache aggressively.
const CACHE_CONTROL: &str = "public, max-age=3600";

async fn get_all(State(set): State<Arc<AttributeSet>>) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, CACHE_CONTROL)],
        Json(set.as_ref().clone()),
    )
}

async fn get_attr(
    State(set): State<Arc<AttributeSet>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let attr = set.attribute(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(([(header::CACHE_CONTROL, CACHE_CONTROL)], Json(attr.clone())))
}

async fn get_value(
    State(set): State<Arc<AttributeSet>>,
    Path((name, value)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let attr = set.attribute(&name).ok_or(StatusCode::NOT_FOUND)?;
    let v = attr
        .values
        .iter()
        .find(|v| v.value == value)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(([(header::CACHE_CONTROL, CACHE_CONTROL)], Json(v.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn example_set() -> AttributeSet {
        AttributeSet::load("attributes/patreon.arkavo.com.json").expect("example artifact loads")
    }

    #[test]
    fn example_artifact_loads_and_fqns_resolve() {
        let set = example_set();
        assert_eq!(set.namespace.fqn, "https://patreon.arkavo.com");
        let tier = set.attribute("tier").expect("tier attribute");
        assert_eq!(tier.rule, "ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY");
        assert_eq!(tier.fqn, "https://patreon.arkavo.com/attr/tier");
        assert!(
            tier.values
                .iter()
                .any(|v| v.fqn == "https://patreon.arkavo.com/attr/tier/value/free")
        );
        assert!(
            set.attribute_by_fqn("https://patreon.arkavo.com/attr/campaign")
                .is_some()
        );
    }

    #[test]
    fn derives_missing_fqns_and_rejects_mismatches() {
        let mut set: AttributeSet = serde_json::from_str(
            r#"{"namespace":{"name":"x.example"},
                "attributes":[{"name":"a","rule":"ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF",
                               "values":[{"value":"v1"}]}]}"#,
        )
        .unwrap();
        set.normalize_and_validate().unwrap();
        assert_eq!(set.attributes[0].fqn, "https://x.example/attr/a");
        assert_eq!(
            set.attributes[0].values[0].fqn,
            "https://x.example/attr/a/value/v1"
        );

        let mut bad: AttributeSet = serde_json::from_str(
            r#"{"namespace":{"name":"x.example"},
                "attributes":[{"name":"a","rule":"ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF",
                               "fqn":"https://wrong.example/attr/a","values":[]}]}"#,
        )
        .unwrap();
        assert!(bad.normalize_and_validate().is_err());
    }

    #[test]
    fn rejects_unknown_rule() {
        let mut bad: AttributeSet = serde_json::from_str(
            r#"{"namespace":{"name":"x.example"},
                "attributes":[{"name":"a","rule":"hierarchy","values":[]}]}"#,
        )
        .unwrap();
        assert!(bad.normalize_and_validate().is_err());
    }

    #[tokio::test]
    async fn fetches_fqns_from_platform_listing() {
        // Stub serving the platform's proto-JSON shape (no namespace
        // wrapper; extra fields the node must tolerate).
        use axum::routing::get;
        let app = Router::new().route(
            "/attributes",
            get(|| async {
                axum::Json(serde_json::json!({
                    "attributes": [
                        {"id": "x1", "name": "tier",
                         "rule": "ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY",
                         "fqn": "https://patreon.arkavo.com/attr/tier",
                         "values": [{"value": "free", "fqn": "https://patreon.arkavo.com/attr/tier/value/free"}]},
                        {"name": "campaign",
                         "fqn": "https://patreon.arkavo.com/attr/campaign"}
                    ]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let fqns = fetch_attribute_fqns(&format!("http://{addr}/attributes"))
            .await
            .unwrap();
        assert!(fqns.contains(&"https://patreon.arkavo.com/attr/campaign".to_string()));
        assert_eq!(fqns.len(), 2);

        // Empty listing is a startup error, not a silent pass.
        let app = Router::new().route(
            "/attributes",
            get(|| async { axum::Json(serde_json::json!({"attributes": []})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        assert!(
            fetch_attribute_fqns(&format!("http://{addr}/attributes"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fqn_paths_dereference() {
        let router = router(Arc::new(example_set()));

        // The path component of an attribute-value FQN resolves to its JSON.
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/attr/tier/value/supporter")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: AttributeValueDef = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v.fqn,
            "https://patreon.arkavo.com/attr/tier/value/supporter"
        );

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/attr/tier")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/attr/nope")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
