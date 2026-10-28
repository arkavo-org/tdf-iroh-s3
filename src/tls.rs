//! HTTPS for the HTTP API. The node terminates TLS itself with rustls, from a
//! PEM cert chain and key on disk. Nothing in here talks to ACM: on EC2 the
//! `tdf-iroh-s3-cert-sync` job exports the certificate into those files, and
//! this module reloads them when either one changes, so a renewal never needs
//! a restart. Only TLS 1.3 is offered; a TLS 1.2 client gets a
//! protocol-version alert.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn};

use crate::config::TlsConfig;

/// The largest header list an HTTP/2 client may send, in bytes (hyper's
/// default is 16 KiB). An Arkavo CWT names every active Patreon membership
/// with its campaign and tiers, and travels with DeviceCheck CWTs, so a
/// heavy patron's headers outgrow 16 KiB. HTTP/1.1 already allows hyper's
/// ~400 KiB read buffer.
pub const MAX_HEADER_LIST_BYTES: u32 = 64 * 1024;

/// How often a missing or unloadable cert/key pair is retried at startup.
const LOAD_RETRY: Duration = Duration::from_secs(10);

/// Serve `router` over HTTPS on `cfg.bind_port` until the server fails.
///
/// A cert/key pair that is missing or does not load yet (first boot before
/// cert-sync has run, or a pair caught mid-write) is retried rather than
/// treated as fatal, so the iroh node keeps running meanwhile. Only a failure
/// of the listener itself is returned.
pub async fn serve_https(cfg: &TlsConfig, router: Router) -> anyhow::Result<()> {
    let (config, loaded) = load_when_ready(&cfg.cert_path, &cfg.key_path).await;

    tokio::spawn(reload_on_change(
        config.clone(),
        cfg.cert_path.clone(),
        cfg.key_path.clone(),
        Duration::from_secs(cfg.reload_check_secs.max(1)),
        loaded,
    ));

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.bind_port));
    info!("HTTPS API listening on port {}", cfg.bind_port);
    let mut server = axum_server::bind_rustls(addr, config);
    server
        .http_builder()
        .http2()
        .max_header_list_size(MAX_HEADER_LIST_BYTES);
    server
        .serve(router.into_make_service())
        .await
        .with_context(|| format!("HTTPS listener on port {}", cfg.bind_port))
}

type Mtimes = (Option<SystemTime>, Option<SystemTime>);

/// Load the pair, returning it with the mtimes read *before* the load, so a
/// rewrite that lands after it still differs from the reload baseline.
async fn load_when_ready(cert_path: &Path, key_path: &Path) -> (RustlsConfig, Mtimes) {
    let mut last_err = String::new();
    loop {
        let before = mtimes(cert_path, key_path);
        let res = if cert_path.exists() && key_path.exists() {
            load_pair(cert_path, key_path).await
        } else {
            Err("cert or key file missing".to_string())
        };
        match res {
            Ok(config) => return (RustlsConfig::from_config(config), before),
            Err(e) => {
                if e != last_err {
                    warn!(
                        "HTTPS waiting for a loadable cert {} / key {}: {e}",
                        cert_path.display(),
                        key_path.display()
                    );
                    last_err = e;
                }
            }
        }
        tokio::time::sleep(LOAD_RETRY).await;
    }
}

/// Poll both files' mtimes and reload the pair when either changes. A pair
/// that fails to load (say, caught halfway through a write) keeps the
/// previous certificate in service and is retried on the next tick.
async fn reload_on_change(
    config: RustlsConfig,
    cert_path: PathBuf,
    key_path: PathBuf,
    every: Duration,
    mut loaded: Mtimes,
) {
    loop {
        tokio::time::sleep(every).await;
        let now = mtimes(&cert_path, &key_path);
        if now == loaded {
            continue;
        }
        // Same idea as at startup: record `now` before reading, so a write
        // racing this reload is caught on the next tick.
        match load_pair(&cert_path, &key_path).await {
            Ok(new) => {
                config.reload_from_config(new);
                info!("TLS certificate reloaded from {}", cert_path.display());
                loaded = now;
            }
            Err(e) => warn!("TLS certificate reload failed, keeping the old one: {e}"),
        }
    }
}

/// Read the pair and build the listener's config from it.
async fn load_pair(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>, String> {
    let cert = read_file(cert_path).await?;
    let key = read_file(key_path).await?;
    server_config(&cert, &key).map(Arc::new)
}

async fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    tokio::fs::read(path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The listener's rustls config: TLS 1.3 only, with the provider named
/// explicitly rather than taken from the process default, and ALPN for h2
/// and HTTP/1.1 (what axum-server's own PEM loader sets).
fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, String> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    if certs.is_empty() {
        return Err("certificate chain: no certificates".to_string());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("private key: {e}"))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn mtimes(cert: &Path, key: &Path) -> Mtimes {
    let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (m(cert), m(key))
}
