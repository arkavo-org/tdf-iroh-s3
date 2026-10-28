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

fn client(port: u16, trusted_pem: &str) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(trusted_pem.as_bytes()).unwrap())
        .tls_built_in_root_certs(false)
        .resolve("localhost", ([127, 0, 0, 1], port).into())
}

async fn get_healthz(port: u16, trusted_pem: &str) -> reqwest::Result<String> {
    get_healthz_with(client(port, trusted_pem), port).await
}

async fn get_healthz_with(client: reqwest::ClientBuilder, port: u16) -> reqwest::Result<String> {
    client
        .build()
        .unwrap()
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
async fn https_offers_only_tls13() {
    install_provider();
    let dir = tempfile::tempdir().unwrap();
    let pem = write_self_signed(dir.path());
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

    let tls13 = || client(port, &pem).min_tls_version(reqwest::tls::Version::TLS_1_3);
    assert!(
        wait_for(|| async {
            get_healthz_with(tls13(), port)
                .await
                .is_ok_and(|b| b == "ok")
        })
        .await,
        "HTTPS never answered a TLS 1.3 client"
    );
    let tls12 = client(port, &pem).max_tls_version(reqwest::tls::Version::TLS_1_2);
    assert!(
        get_healthz_with(tls12, port).await.is_err(),
        "a TLS 1.2 client must be refused"
    );
}

/// An HTTP/2 request carries a bearer token far past hyper's default 16 KiB
/// header list: a patron's CWT with many Patreon memberships, plus device
/// tokens. Headers past `MAX_HEADER_LIST_BYTES` are still refused.
#[tokio::test]
async fn https_takes_large_headers_over_h2() {
    use tdf_iroh_s3::tls::MAX_HEADER_LIST_BYTES;

    install_provider();
    let dir = tempfile::tempdir().unwrap();
    let pem = write_self_signed(dir.path());
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
        wait_for(|| async { get_healthz(port, &pem).await.is_ok() }).await,
        "HTTPS never answered"
    );

    let h2 = client(port, &pem).http2_prior_knowledge().build().unwrap();
    let send = |bearer_bytes: usize| {
        h2.get(format!("https://localhost:{port}/healthz"))
            .header(
                "authorization",
                format!("Bearer {}", "a".repeat(bearer_bytes)),
            )
            .header("x-entity-token", "b".repeat(2048))
            .send()
    };
    let r = send(48 * 1024).await.expect("a 48 KiB bearer is accepted");
    assert_eq!(r.version(), reqwest::Version::HTTP_2);
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let over = send(MAX_HEADER_LIST_BYTES as usize).await;
    assert!(
        over.is_err() || !over.unwrap().status().is_success(),
        "headers over the limit must be refused"
    );
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
