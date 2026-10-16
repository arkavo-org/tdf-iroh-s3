use std::path::Path;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use tdf_iroh_s3::config::TlsConfig;
use tdf_iroh_s3::tls::serve_https;

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Write via rename so the server never sees a half-written file.
fn write_atomic(path: &Path, contents: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).unwrap();
    std::fs::rename(tmp, path).unwrap();
}

fn self_signed() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}

fn write_self_signed(dir: &Path) -> String {
    let (cert, key) = self_signed();
    write_atomic(&dir.join("privkey.pem"), &key);
    write_atomic(&dir.join("fullchain.pem"), &cert);
    cert
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn get_healthz(port: u16, trusted_pem: &str) -> reqwest::Result<String> {
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(trusted_pem.as_bytes()).unwrap())
        .tls_built_in_root_certs(false)
        .resolve("localhost", ([127, 0, 0, 1], port).into())
        .build()
        .unwrap();
    client
        .get(format!("https://localhost:{port}/healthz"))
        .send()
        .await?
        .text()
        .await
}

async fn wait_for<F, Fut>(mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..100 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn https_serves_and_reloads_renewed_cert() {
    install_provider();
    let dir = tempfile::tempdir().unwrap();
    let first = write_self_signed(dir.path());
    let port = free_port();
    let cfg = TlsConfig {
        bind_port: port,
        cert_path: dir.path().join("fullchain.pem"),
        key_path: dir.path().join("privkey.pem"),
        acm_certificate_arn: String::new(),
        reload_check_secs: 1,
    };
    let router = Router::new().route("/healthz", get(|| async { "ok" }));
    tokio::spawn(async move { serve_https(&cfg, router).await });

    assert!(
        wait_for(|| async { get_healthz(port, &first).await.is_ok_and(|b| b == "ok") }).await,
        "HTTPS never answered with the first certificate"
    );

    // A renewal rewrites both files; mtime resolution can be coarse.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = write_self_signed(dir.path());
    assert!(
        wait_for(|| async { get_healthz(port, &second).await.is_ok() }).await,
        "renewed certificate was never picked up"
    );
    assert!(get_healthz(port, &first).await.is_err());
}

#[tokio::test]
async fn https_waits_for_missing_cert() {
    install_provider();
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = TlsConfig {
        bind_port: port,
        cert_path: dir.path().join("fullchain.pem"),
        key_path: dir.path().join("privkey.pem"),
        acm_certificate_arn: String::new(),
        reload_check_secs: 1,
    };
    let router = Router::new().route("/healthz", get(|| async { "ok" }));
    let server = tokio::spawn(async move { serve_https(&cfg, router).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.is_finished(),
        "missing cert must not end the server"
    );

    let pem = write_self_signed(dir.path());
    let ok = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if get_healthz(port, &pem).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(ok.is_ok(), "HTTPS never came up once the cert appeared");
}

#[tokio::test]
async fn https_retries_a_mismatched_pair() {
    install_provider();
    let dir = tempfile::tempdir().unwrap();
    // Key from one cert, chain from another: what an interrupted sync leaves.
    let (_, stray_key) = self_signed();
    let (cert, _) = self_signed();
    write_atomic(&dir.path().join("privkey.pem"), &stray_key);
    write_atomic(&dir.path().join("fullchain.pem"), &cert);

    let port = free_port();
    let cfg = TlsConfig {
        bind_port: port,
        cert_path: dir.path().join("fullchain.pem"),
        key_path: dir.path().join("privkey.pem"),
        acm_certificate_arn: String::new(),
        reload_check_secs: 1,
    };
    let router = Router::new().route("/healthz", get(|| async { "ok" }));
    let server = tokio::spawn(async move { serve_https(&cfg, router).await });

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.is_finished(),
        "an unloadable pair must not end the server"
    );

    let pem = write_self_signed(dir.path());
    let ok = tokio::time::timeout(Duration::from_secs(20), async {
        while get_healthz(port, &pem).await.is_err() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    assert!(ok.is_ok(), "HTTPS never came up once the pair was repaired");
}
