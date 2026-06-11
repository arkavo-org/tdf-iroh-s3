use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use std::sync::Arc;

use tdf_iroh_s3::auth::CwtVerifier;
use tdf_iroh_s3::config::Config;
use tdf_iroh_s3::node::TdfIrohNode;
use tdf_iroh_s3::tags_api::{self, ApiState};

#[derive(Parser)]
#[command(
    name = "tdf-iroh-s3",
    about = "TDF-validated Iroh peer with S3 blob storage"
)]
struct Cli {
    #[arg(short, long, default_value = "/etc/tdf-iroh-s3/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_file(&cli.config)?;
    info!("Config loaded from {:?}", cli.config);
    info!("S3: {}:{}", config.s3.bucket, config.s3.region);
    info!(
        "Required attributes: {:?}",
        config.validation.required_attributes
    );
    info!("Assertion check: {}", config.validation.assertion.enabled);

    let node = TdfIrohNode::spawn(config).await?;
    let addr = node.addr();
    info!("Node running at {}", addr.id);

    // HTTP tag API (catalog discovery): GET resolution is public; PUT is
    // CWT-authenticated against the configured IdP key set.
    if node.config.http.enabled {
        let http_cfg = &node.config.http;
        anyhow::ensure!(
            !http_cfg.cose_keys_url.is_empty(),
            "[http] enabled requires cose_keys_url (e.g. https://identity.arkavo.net/.well-known/cose-keys)"
        );
        let expected_iss = if http_cfg.expected_issuer.is_empty() {
            tracing::warn!(
                "[http] expected_issuer unset — any token signed by the key set is accepted"
            );
            None
        } else {
            Some(http_cfg.expected_issuer.clone())
        };
        let state = Arc::new(ApiState {
            store: Arc::clone(&node.s3_client),
            verifier: CwtVerifier::new(http_cfg.cose_keys_url.clone(), expected_iss),
            tag_prefix: http_cfg.tag_prefix.clone(),
        });
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", http_cfg.bind_port)).await?;
        info!(
            "HTTP tag API listening on port {} (tag prefix {:?})",
            http_cfg.bind_port, http_cfg.tag_prefix
        );
        let router = tags_api::router(state);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("HTTP tag API exited: {e}");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    node.shutdown().await?;
    info!("Done.");

    Ok(())
}
