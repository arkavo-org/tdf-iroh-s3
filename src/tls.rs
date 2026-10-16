//! HTTPS for the HTTP API. The node terminates TLS itself with rustls, from a
//! PEM cert chain and key on disk. Nothing in here talks to ACM: on EC2 the
//! `tdf-iroh-s3-cert-sync` job exports the certificate into those files, and
//! this module reloads them when either one changes, so a renewal never needs
//! a restart.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{info, warn};

use crate::config::TlsConfig;

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
    axum_server::bind_rustls(addr, config)
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
            RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .map_err(|e| e.to_string())
        } else {
            Err("cert or key file missing".to_string())
        };
        match res {
            Ok(config) => return (config, before),
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
        match config.reload_from_pem_file(&cert_path, &key_path).await {
            Ok(()) => {
                info!("TLS certificate reloaded from {}", cert_path.display());
                loaded = now;
            }
            Err(e) => warn!("TLS certificate reload failed, keeping the old one: {e}"),
        }
    }
}

fn mtimes(cert: &Path, key: &Path) -> Mtimes {
    let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (m(cert), m(key))
}
