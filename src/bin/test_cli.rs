use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tdf_iroh_s3::test_cli::iroh_client::load_or_create_secret_key;
use tdf_iroh_s3::test_cli::publish;

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

    /// Push a file's bytes as they are (an existing TDF, or junk) to a remote node
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

        /// Endpoint key (hex) to push from, created if missing. Use the file
        /// given to publish-session so a gated node accepts the push.
        #[arg(long)]
        secret_key_file: Option<PathBuf>,
    },

    /// Open a publish session for this CLI's endpoint (POST /publish/sessions)
    PublishSession {
        /// Base URL of the node's HTTP API, e.g. http://127.0.0.1:8090
        #[arg(long)]
        url: String,

        /// File holding the publisher's Arkavo CWT
        #[arg(long)]
        token_file: PathBuf,

        /// Endpoint key (hex) the session names, created if missing. Pass
        /// the same file to push-raw.
        #[arg(long)]
        secret_key_file: PathBuf,
    },

    /// Open a session, push a file from the same endpoint, and wait until
    /// GET /blobs confirms ingest (Creator's publishing flow)
    Publish {
        /// Remote node Endpoint ID (see GET /node)
        #[arg(short, long)]
        node: String,

        /// Direct address (ip:port) of the remote node
        #[arg(long)]
        addr: Option<String>,

        /// Base URL of the node's HTTP API, e.g. http://127.0.0.1:8090
        #[arg(long)]
        url: String,

        /// File holding the publisher's Arkavo CWT
        #[arg(long)]
        token_file: PathBuf,

        /// File to push (a TDF archive)
        #[arg(short, long)]
        data: PathBuf,

        /// Endpoint key (hex) to push from; a fresh key when omitted
        #[arg(long)]
        secret_key_file: Option<PathBuf>,

        /// Seconds to wait for GET /blobs to confirm ingest
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },

    /// Publish a catalog document (PUT /catalogs/{sub})
    PutCatalog {
        /// Base URL of the node's HTTP API, e.g. http://127.0.0.1:8090
        #[arg(long)]
        url: String,

        /// File holding the publisher's Arkavo CWT
        #[arg(long)]
        token_file: PathBuf,

        /// The token's subject, exactly as minted
        #[arg(long)]
        sub: String,

        /// The arkavo.creator-catalog/1 JSON document, sent byte for byte
        #[arg(long)]
        catalog: PathBuf,
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
        Commands::PushRaw {
            node,
            addr,
            data,
            secret_key_file,
        } => {
            let endpoint_addr = parse_addr(&node, &addr)?;
            let secret_key = secret_key_file
                .as_deref()
                .map(load_or_create_secret_key)
                .transpose()?;
            tdf_iroh_s3::test_cli::push_raw::push_raw_file(endpoint_addr, &data, secret_key)
                .await?;
        }
        Commands::PublishSession {
            url,
            token_file,
            secret_key_file,
        } => {
            let token = publish::read_token(&token_file)?;
            let key = load_or_create_secret_key(&secret_key_file)?;
            println!("Endpoint: {}", key.public());
            match publish::open_session(&url, &token, &key).await? {
                publish::SessionOutcome::Opened(body) => println!("Session opened: {body}"),
                publish::SessionOutcome::Ungated => {
                    println!("404: the node is ungated; push without a session")
                }
            }
        }
        Commands::Publish {
            node,
            addr,
            url,
            token_file,
            data,
            secret_key_file,
            timeout_secs,
        } => {
            let endpoint_addr = parse_addr(&node, &addr)?;
            let token = publish::read_token(&token_file)?;
            let key = match secret_key_file {
                Some(path) => load_or_create_secret_key(&path)?,
                None => iroh::SecretKey::generate(),
            };
            publish::publish_file(
                endpoint_addr,
                &url,
                &token,
                &data,
                key,
                std::time::Duration::from_secs(timeout_secs),
            )
            .await?;
        }
        Commands::PutCatalog {
            url,
            token_file,
            sub,
            catalog,
        } => {
            let token = publish::read_token(&token_file)?;
            let body = publish::put_catalog(&url, &token, &sub, &catalog).await?;
            println!("{body}");
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
