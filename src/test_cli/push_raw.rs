use anyhow::{Context, Result};
use iroh::{EndpointAddr, SecretKey};
use std::path::Path;

use super::iroh_client::IrohTestClient;

/// Push a file's bytes as they are (no TDF wrapping) to a remote node: an
/// existing TDF archive, or junk to check that the node refuses it.
/// `secret_key` fixes the pushing endpoint, as a publish session requires.
pub async fn push_raw_file(
    addr: EndpointAddr,
    file_path: &Path,
    secret_key: Option<SecretKey>,
) -> Result<()> {
    let data = std::fs::read(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

    let hash = blake3::hash(&data);
    println!("Raw data ({} bytes)", data.len());
    println!("BLAKE3 hash: {}", hash.to_hex());

    let client = IrohTestClient::with_secret_key(secret_key)
        .await
        .context("Failed to create Iroh client")?;
    println!("Client endpoint: {}", client.endpoint_id());

    println!("Connecting to node {}...", addr.id);
    match client.push_to_node(addr, &data).await {
        Ok(h) => println!("Pushed blob: {}", h.to_hex()),
        Err(e) => println!("Push rejected: {}", e),
    }

    client.shutdown().await?;
    Ok(())
}
