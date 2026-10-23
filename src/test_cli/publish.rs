//! Publishing against a node's HTTP API, the way Creator does
//! (`docs/creator-catalogs.md`): open a publish session for the pushing
//! endpoint, push over iroh, confirm ingest, publish a catalog.

use anyhow::{Context, Result, bail};
use iroh::{EndpointAddr, SecretKey};
use reqwest::StatusCode;
use std::path::Path;
use std::time::{Duration, Instant};

use super::iroh_client::IrohTestClient;
use crate::moderation::{now_secs, session_message};

/// Read a bearer token from a file, ignoring surrounding whitespace.
pub fn read_token(path: &Path) -> Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read token file {}", path.display()))?;
    let token = token.trim().to_string();
    anyhow::ensure!(!token.is_empty(), "{} is empty", path.display());
    Ok(token)
}

fn url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")
}

/// What `POST /publish/sessions` answered.
#[derive(Debug)]
pub enum SessionOutcome {
    /// 201: the body (`endpointId`, `subject`, `expiresAt`).
    Opened(serde_json::Value),
    /// 404: the node is ungated (`[publishing] required = false`); pushes
    /// need no session.
    Ungated,
}

/// Open a publish session for `secret_key`'s endpoint. The request is signed
/// with that key over exactly the bytes the node verifies
/// ([`session_message`]), binding the bearer token and the current time.
pub async fn open_session(
    base_url: &str,
    token: &str,
    secret_key: &SecretKey,
) -> Result<SessionOutcome> {
    let endpoint = secret_key.public();
    let timestamp = now_secs();
    let signature = secret_key.sign(&session_message(&endpoint, token, timestamp));
    let res = http()?
        .post(url(base_url, "/publish/sessions"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "endpointId": endpoint.to_string(),
            "timestamp": timestamp,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .context("POST /publish/sessions failed")?;
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    match status {
        StatusCode::CREATED => Ok(SessionOutcome::Opened(
            serde_json::from_str(&body).context("Unreadable session response")?,
        )),
        StatusCode::NOT_FOUND => Ok(SessionOutcome::Ungated),
        _ => bail!("POST /publish/sessions answered {status}: {body}"),
    }
}

/// Poll `GET /blobs/<hash>` until the node reports the blob ingested with
/// `expected_size` bytes, or `timeout` passes.
pub async fn wait_for_ingest(
    base_url: &str,
    hash_hex: &str,
    expected_size: u64,
    timeout: Duration,
) -> Result<()> {
    let client = http()?;
    let deadline = Instant::now() + timeout;
    loop {
        let res = client
            .get(url(base_url, &format!("/blobs/{hash_hex}")))
            .send()
            .await
            .context("GET /blobs failed")?;
        match res.status() {
            StatusCode::OK => {
                let body: serde_json::Value = res.json().await.context("Unreadable /blobs")?;
                let size = body["size"].as_u64().unwrap_or_default();
                anyhow::ensure!(
                    size == expected_size,
                    "node reports {size} bytes for {hash_hex}, pushed {expected_size}"
                );
                return Ok(());
            }
            StatusCode::NOT_FOUND if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            StatusCode::NOT_FOUND => {
                bail!("{hash_hex} not ingested after {timeout:?}: the node refused it")
            }
            status => bail!(
                "GET /blobs/{hash_hex} answered {status}: {}",
                res.text().await.unwrap_or_default()
            ),
        }
    }
}

/// The whole publishing flow for one file: open a session (unless the node
/// is ungated), push the file from the same endpoint, and wait for ingest.
pub async fn publish_file(
    addr: EndpointAddr,
    base_url: &str,
    token: &str,
    file_path: &Path,
    secret_key: SecretKey,
    timeout: Duration,
) -> Result<String> {
    let data = std::fs::read(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
    let hash = blake3::hash(&data).to_hex().to_string();
    println!("File: {} ({} bytes)", file_path.display(), data.len());
    println!("BLAKE3 hash: {hash}");

    match open_session(base_url, token, &secret_key).await? {
        SessionOutcome::Opened(body) => println!("Publish session: {body}"),
        SessionOutcome::Ungated => println!("Node is ungated; pushing without a session"),
    }

    let client = IrohTestClient::with_secret_key(Some(secret_key))
        .await
        .context("Failed to create Iroh client")?;
    println!(
        "Pushing from endpoint {} to {}...",
        client.endpoint_id(),
        addr.id
    );
    let pushed = client.push_to_node(addr, &data).await;
    client.shutdown().await?;
    let pushed = pushed.context("Push failed")?;
    anyhow::ensure!(pushed.to_hex().as_str() == hash, "pushed hash differs");

    println!("Waiting for ingest...");
    wait_for_ingest(base_url, &hash, data.len() as u64, timeout).await?;
    println!("Ingested: {hash} ({} bytes)", data.len());
    Ok(hash)
}

/// `PUT /catalogs/{sub}` with a catalog document's exact bytes.
pub async fn put_catalog(
    base_url: &str,
    token: &str,
    sub: &str,
    catalog_path: &Path,
) -> Result<serde_json::Value> {
    let body = std::fs::read(catalog_path)
        .with_context(|| format!("Failed to read {}", catalog_path.display()))?;
    let res = http()?
        .put(url(base_url, &format!("/catalogs/{sub}")))
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .context("PUT /catalogs failed")?;
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if status != StatusCode::OK {
        bail!("PUT /catalogs/{sub} answered {status}: {text}");
    }
    serde_json::from_str(&text).context("Unreadable catalog response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CwtVerifier;
    use crate::auth::test_support::{keypair, mint_with_aud};
    use crate::moderation::{
        DEFAULT_PUBLISH_ENTITLEMENT, Moderation, ModerationApi, PublishGate, PublishPolicy,
        PushRefusal, test_support::MemModeration,
    };
    use ciborium::value::Value;
    use std::sync::Arc;

    /// The CLI's signed request opens a session the node accepts, for the
    /// endpoint whose key signed it.
    #[tokio::test]
    async fn open_session_signs_what_the_node_verifies() {
        let (sk, vk) = keypair();
        let gate = Arc::new(PublishGate::new(Arc::new(Moderation::default())));
        let api = Arc::new(ModerationApi {
            store: Arc::new(MemModeration::default()),
            verifier: Arc::new(CwtVerifier::with_static_keys(vec![(b"kid-1".to_vec(), vk)])),
            gate: Arc::clone(&gate),
            policy: Arc::new(PublishPolicy {
                entitlement: Some(DEFAULT_PUBLISH_ENTITLEMENT.into()),
                audience: Some("arkavo".into()),
                session_ttl: Duration::from_secs(60),
                operator_client_ids: Default::default(),
                decider: Default::default(),
            }),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, crate::moderation::router(api)).into_future());

        let token = mint_with_aud(
            &sk,
            b"kid-1",
            "https://identity.test",
            "creator-1",
            "arkavo",
            now_secs(),
            now_secs() + 600,
            &[(
                "arkavo_entitlements",
                Value::Array(vec![Value::Text(DEFAULT_PUBLISH_ENTITLEMENT.into())]),
            )],
        );
        let key = SecretKey::from_bytes(&[7; 32]);
        match open_session(&base, &token, &key).await.unwrap() {
            SessionOutcome::Opened(body) => {
                assert_eq!(body["endpointId"], key.public().to_string());
                assert_eq!(body["subject"], "creator-1");
            }
            other => panic!("{other:?}"),
        }
        gate.connected(1, Some(key.public()));
        assert!(gate.authorize_push(1, &"a".repeat(64)).await.is_ok());
        gate.connected(2, Some(SecretKey::from_bytes(&[8; 32]).public()));
        assert_eq!(
            gate.authorize_push(2, &"a".repeat(64)).await,
            Err(PushRefusal::NoSession)
        );

        // A rejected token surfaces the node's answer.
        let err = open_session(&base, "garbage", &key).await.unwrap_err();
        assert!(err.to_string().contains("401"), "{err}");
    }

    #[tokio::test]
    async fn an_ungated_node_answers_404() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, axum::Router::new()).into_future());
        let key = SecretKey::from_bytes(&[9; 32]);
        assert!(matches!(
            open_session(&base, "token", &key).await.unwrap(),
            SessionOutcome::Ungated
        ));
    }

    #[test]
    fn secret_key_files_round_trip() {
        use crate::test_cli::iroh_client::load_or_create_secret_key;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint.key");
        let first = load_or_create_secret_key(&path).unwrap();
        let again = load_or_create_secret_key(&path).unwrap();
        assert_eq!(first.public(), again.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(&path, "not hex").unwrap();
        assert!(load_or_create_secret_key(&path).is_err());
    }
}
