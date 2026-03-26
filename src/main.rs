use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use tdf_iroh_s3::config::Config;
use tdf_iroh_s3::node::TdfIrohNode;

#[derive(Parser)]
#[command(name = "tdf-iroh-s3", about = "TDF-validated Iroh peer with S3 blob storage")]
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
    info!("Required attributes: {:?}", config.validation.required_attributes);
    info!("Assertion check: {}", config.validation.assertion.enabled);

    let node = TdfIrohNode::spawn(config).await?;
    let addr = node.addr();
    info!("Node running at {}", addr.id);

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    node.shutdown().await?;
    info!("Done.");

    Ok(())
}
