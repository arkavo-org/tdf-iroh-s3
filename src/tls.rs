//! HTTPS for the HTTP API. The node terminates TLS itself with rustls, from a
//! PEM cert chain and key on disk. Nothing in here talks to ACM: on EC2 the
//! `tdf-iroh-s3-cert-sync` job exports the certificate into those files, and
//! this module reloads them when either one changes, so a renewal never needs
//! a restart.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{info, warn};

use crate::config::TlsConfig;

/// Serve `router` over HTTPS on `cfg.bind_port` until the server fails.
///
/// A cert or key that is not there yet (first boot, before cert-sync has run)
/// is waited for rather than treated as fatal, so the iroh node keeps running.
pub async fn serve_https(cfg: &TlsConfig, router: Router) -> anyhow::Result<()> {
    // reqwest pulls in ring and axum-server pulls in aws-lc-rs; with both
    // compiled in, rustls needs the process default chosen explicitly.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut warned = false;
    while !(cfg.cert_path.exists() && cfg.key_path.exists()) {
        if !warned {
            warn!(
                "HTTPS waiting for {} and {}",
                cfg.cert_path.display(),
                cfg.key_path.display()
            );
            warned = true;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    let config = RustlsConfig::from_pem_file(&cfg.cert_path, &cfg.key_path)
        .await
        .with_context(|| {
            format!(
                "loading TLS cert {} / key {}",
                cfg.cert_path.display(),
                cfg.key_path.display()
            )
        })?;

    tokio::spawn(reload_on_change(
        config.clone(),
        cfg.cert_path.clone(),
        cfg.key_path.clone(),
        Duration::from_secs(cfg.reload_check_secs.max(1)),
    ));

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.bind_port));
    info!("HTTPS API listening on port {}", cfg.bind_port);
    axum_server::bind_rustls(addr, config)
        .serve(router.into_make_service())
        .await
        .with_context(|| format!("HTTPS listener on port {}", cfg.bind_port))
}

/// Poll both files' mtimes and reload the pair when either changes. A pair
/// that fails to load (say, caught halfway through a write) keeps the
/// previous certificate in service and is retried on the next tick.
async fn reload_on_change(
    config: RustlsConfig,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    every: Duration,
) {
    let mut loaded = mtimes(&cert_path, &key_path);
    loop {
        tokio::time::sleep(every).await;
        let now = mtimes(&cert_path, &key_path);
        if now == loaded {
            continue;
        }
        match config.reload_from_pem_file(&cert_path, &key_path).await {
            Ok(()) => {
                info!("TLS certificate reloaded from {}", cert_path.display());
                loaded = now;
            }
            Err(e) => warn!("TLS certificate reload failed, keeping the old one: {e}"),
        }
    }
}

fn mtimes(cert: &Path, key: &Path) -> (Option<SystemTime>, Option<SystemTime>) {
    let m = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (m(cert), m(key))
}
