//! `GET /node`: the node's iroh identity, for publishers.
//!
//! Creator reads the endpoint to push to from here
//! (`docs/creator-catalogs.md`). The iOS viewer does not: it dials only the
//! endpoint ID and addresses compiled into its release configuration, so a
//! different answer here never redirects it.

use axum::routing::get;
use axum::{Json, Router};
use iroh::Endpoint;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    /// The iroh endpoint ID, 64 lowercase hex characters.
    pub endpoint_id: String,
    /// The endpoint's home relay, or `null` before it has one.
    pub relay_url: Option<String>,
    /// `[iroh] public_addresses`, as `ip:port`.
    pub direct_addresses: Vec<String>,
    /// `[validation] max_blob_bytes`: the largest archive ingest accepts, so a
    /// publisher can refuse a larger one before uploading it.
    pub max_blob_bytes: u64,
}

/// Produces the current [`NodeInfo`] for each request.
pub type NodeInfoSource = Arc<dyn Fn() -> NodeInfo + Send + Sync>;

/// Read the running endpoint on every request (its home relay can change);
/// the direct addresses are the configured public ones, because a node
/// behind NAT or an EC2 elastic IP cannot see its own public address.
pub fn live(
    endpoint: Endpoint,
    public_addresses: &[SocketAddr],
    max_blob_bytes: u64,
) -> NodeInfoSource {
    let direct_addresses: Vec<String> = public_addresses.iter().map(|a| a.to_string()).collect();
    Arc::new(move || {
        let addr = endpoint.addr();
        NodeInfo {
            endpoint_id: addr.id.to_string(),
            relay_url: addr.relay_urls().next().map(|u| u.to_string()),
            direct_addresses: direct_addresses.clone(),
            max_blob_bytes,
        }
    })
}

pub fn router(source: NodeInfoSource) -> Router {
    Router::new().route("/node", get(move || async move { Json(source()) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn get_node(info: NodeInfo) -> (StatusCode, serde_json::Value) {
        let app = router(Arc::new(move || info.clone()));
        let res = app
            .oneshot(Request::get("/node").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn reports_identity_relay_and_addresses() {
        let (status, body) = get_node(NodeInfo {
            endpoint_id: "ab".repeat(32),
            relay_url: Some("https://relay.example./".into()),
            direct_addresses: vec!["3.91.18.97:11204".into()],
            max_blob_bytes: 2_147_483_648,
        })
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!({
                "endpointId": "ab".repeat(32),
                "relayUrl": "https://relay.example./",
                "directAddresses": ["3.91.18.97:11204"],
                "maxBlobBytes": 2_147_483_648u64,
            })
        );
    }

    #[tokio::test]
    async fn no_relay_and_no_addresses() {
        let (_, body) = get_node(NodeInfo {
            endpoint_id: "ab".repeat(32),
            relay_url: None,
            direct_addresses: vec![],
            max_blob_bytes: 4_294_967_296,
        })
        .await;
        assert_eq!(body["relayUrl"], serde_json::Value::Null);
        assert_eq!(body["directAddresses"], serde_json::json!([]));
    }
}
