use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tdf-iroh-s3-test", about = "Test CLI for tdf-iroh-s3 nodes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a TDF file locally
    CreateTdf {
        #[arg(short, long)]
        attribute: String,

        #[arg(short, long, default_value = "test payload")]
        data: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    /// Create a TDF and push it to a remote node
    Push {
        /// Remote node Endpoint ID
        #[arg(short, long)]
        node: String,

        /// Attribute FQN to include in the TDF policy
        #[arg(short, long)]
        attribute: String,

        /// Payload data (string)
        #[arg(short, long, default_value = "test payload")]
        data: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateTdf {
            attribute,
            data,
            output,
        } => {
            tdf_iroh_s3::test_cli::create_tdf::create_tdf_file(
                &attribute,
                data.as_bytes(),
                &output,
            )?;
        }
        Commands::Push {
            node,
            attribute,
            data,
        } => {
            let node_id = tdf_iroh_s3::test_cli::iroh_client::parse_endpoint_id(&node)?;
            tdf_iroh_s3::test_cli::push::push_tdf(node_id, &attribute, data.as_bytes()).await?;
        }
    }

    Ok(())
}
