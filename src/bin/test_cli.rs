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

    /// Push raw bytes (no TDF wrapping) to a remote node
    PushRaw {
        /// Remote node Endpoint ID
        #[arg(short, long)]
        node: String,

        /// Direct address (ip:port) of the remote node
        #[arg(long)]
        addr: Option<String>,

        /// File containing raw bytes to push
        #[arg(short, long)]
        data: PathBuf,
    },

    /// Create a TDF and push it to a remote node
    Push {
        /// Remote node Endpoint ID
        #[arg(short, long)]
        node: String,

        /// Direct address (ip:port) of the remote node
        #[arg(long)]
        addr: Option<String>,

        /// Attribute FQN to include in the TDF policy
        #[arg(short, long)]
        attribute: String,

        /// Payload data (string)
        #[arg(short, long, default_value = "test payload")]
        data: String,
    },

    /// Fetch a blob from a remote node by BLAKE3 hash
    Fetch {
        /// Remote node Endpoint ID
        #[arg(short, long)]
        node: String,

        /// Direct address (ip:port) of the remote node
        #[arg(long)]
        addr: Option<String>,

        /// BLAKE3 hash (hex) of the blob to fetch
        #[arg(long)]
        hash: String,

        /// Optional output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn parse_addr(node: &str, addr: &Option<String>) -> Result<iroh::EndpointAddr> {
    let node_id = tdf_iroh_s3::test_cli::iroh_client::parse_endpoint_id(node)?;
    let socket_addr = addr
        .as_deref()
        .map(|a| a.parse::<std::net::SocketAddr>())
        .transpose()?;
    Ok(tdf_iroh_s3::test_cli::iroh_client::build_endpoint_addr(
        node_id,
        socket_addr,
    ))
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
        Commands::PushRaw { node, addr, data } => {
            let endpoint_addr = parse_addr(&node, &addr)?;
            tdf_iroh_s3::test_cli::push_raw::push_raw_file(endpoint_addr.id, &data).await?;
        }
        Commands::Push {
            node,
            addr,
            attribute,
            data,
        } => {
            let endpoint_addr = parse_addr(&node, &addr)?;
            tdf_iroh_s3::test_cli::push::push_tdf(endpoint_addr, &attribute, data.as_bytes())
                .await?;
        }
        Commands::Fetch {
            node,
            addr,
            hash,
            output,
        } => {
            let endpoint_addr = parse_addr(&node, &addr)?;
            tdf_iroh_s3::test_cli::fetch::fetch_blob(endpoint_addr, &hash, output.as_deref())
                .await?;
        }
    }

    Ok(())
}
