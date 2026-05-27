//! End-to-end test of the tdf/catalog/1 ALPN handler. Drives one
//! subscriber over an in-memory bidi pipe. Validates that only
//! entitled entries reach the reader and that lifecycle frames
//! (CaughtUp) arrive in the right order.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tdf_iroh_s3::auth::Verifier;
use tdf_iroh_s3::auth::test_signer::{TestClaims, TestSigner};
use tdf_iroh_s3::catalog::store::EventStore;
use tdf_iroh_s3::catalog::types::NewContentEvent;
use tdf_iroh_s3::pdp::cache::AccessPdpCache;
use tdf_iroh_s3::protocol::catalog_read::{
    CatalogReadDeps, CatalogStreamMsg, CatalogSubscribe, SubscriptionLimits, handle, write_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const ISSUER: &str = "https://issuer.test";
const NODE_ID: &str = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
const FQN_A: &str = "https://example/attr/dept/value/eng";
const FQN_B: &str = "https://example/attr/dept/value/legal";

async fn pdp_with_dept_attribute() -> Arc<AccessPdpCache> {
    // Serve a JSON attribute-definitions document so AccessPdp::new() builds
    // a non-empty PDP that recognizes the dept attribute and its values.
    let body = serde_json::json!([
        {
            "fqn": "https://example/attr/dept",
            "rule": "AnyOf",
            "values": [
                {"fqn": "https://example/attr/dept/value/eng",   "value": "eng"},
                {"fqn": "https://example/attr/dept/value/legal", "value": "legal"}
            ]
        }
    ])
    .to_string()
    .into_bytes();

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    let body_bytes = body.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            c.fetch_add(1, Ordering::SeqCst);
            let body = body_bytes.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(h.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });

    AccessPdpCache::spawn(
        format!("http://{addr}"),
        Duration::from_secs(3600),
        reqwest::Client::new(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn subscriber_receives_only_granted_entries() {
    let signer = TestSigner::new(ISSUER);
    let v = Arc::new(Verifier::new(
        signer.cose_key_cache(),
        ISSUER.to_string(),
        60,
    ));
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(EventStore::open(&dir.path().join("e.redb")).await.unwrap());
    let pdp = pdp_with_dept_attribute().await;

    // Two events: one tagged eng (subject is granted) and one tagged legal
    // (denied). After append, seq is 1 and 2 respectively.
    store
        .append(NewContentEvent {
            content_id: "x1".into(),
            manifest_ref: "m1".into(),
            attribute_value_fqns: vec![FQN_A.into()],
            ingested_at: "t".into(),
        })
        .await
        .unwrap();
    store
        .append(NewContentEvent {
            content_id: "x2".into(),
            manifest_ref: "m2".into(),
            attribute_value_fqns: vec![FQN_B.into()],
            ingested_at: "t".into(),
        })
        .await
        .unwrap();

    // Subject 'alice' has read entitlement to FQN_A only.
    let mut claims = TestClaims::defaults("alice", FQN_A);
    claims.cnf_iroh_node_id = Some(NODE_ID.into());
    let cwt = signer.mint(claims);

    let deps = CatalogReadDeps {
        verifier: v,
        store: Arc::clone(&store),
        pdp,
        limits: SubscriptionLimits::new(4, 256),
        cancel: CancellationToken::new(),
    };

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_side);
    let (server_read, server_write) = tokio::io::split(server_side);

    let server =
        tokio::spawn(
            async move { handle(server_read, server_write, NODE_ID.into(), deps).await },
        );

    let req = CatalogSubscribe {
        cwt: serde_bytes::ByteBuf::from(cwt),
        after_seq: None,
    };
    write_frame(&mut client_write, &req).await.unwrap();

    // Read frames until CaughtUp.
    let mut entries = Vec::new();
    let mut got_caught_up = false;
    for _ in 0..20 {
        let len = match tokio::time::timeout(
            Duration::from_secs(2),
            client_read.read_u32(),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read len: {e}"),
            Err(_) => panic!("timed out waiting for frame"),
        };
        let mut buf = vec![0u8; len as usize];
        client_read.read_exact(&mut buf).await.unwrap();
        let msg: CatalogStreamMsg = ciborium::de::from_reader(buf.as_slice()).unwrap();
        match msg {
            CatalogStreamMsg::Entry(e) => entries.push(e),
            CatalogStreamMsg::CaughtUp { seq } => {
                assert_eq!(seq, 2, "snapshot tail should be 2 after two appends");
                got_caught_up = true;
                break;
            }
            other => panic!("unexpected backfill frame: {other:?}"),
        }
    }
    assert!(
        got_caught_up,
        "must receive CaughtUp within bounded frame count"
    );
    assert_eq!(entries.len(), 1, "only the eng-tagged entry should pass");
    assert_eq!(entries[0].content_id, "x1");
    assert_eq!(entries[0].seq, 1);

    // Close stream -> server handler exits via broadcast Closed or read error.
    drop(client_write);
    let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
}
