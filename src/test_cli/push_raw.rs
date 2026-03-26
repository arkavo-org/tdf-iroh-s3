use anyhow::{Context, Result};
use iroh::EndpointId;
use std::path::Path;

use super::iroh_client::IrohTestClient;

/// Push raw bytes (not wrapped in TDF) to a remote node.
/// Used to test that the node rejects non-TDF data.
pub async fn push_raw_file(node_id: EndpointId, file_path: &Path) -> Result<()> {
    let data = std::fs::read(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

    let hash = blake3::hash(&data);
    println!("Raw data ({} bytes)", data.len());
    println!("BLAKE3 hash: {}", hash.to_hex());

    let client = IrohTestClient::new()
        .await
        .context("Failed to create Iroh client")?;

    println!("Connecting to node {}...", node_id);
    match client.push_to_node(node_id, &data).await {
        Ok(h) => println!("Pushed blob: {}", h.to_hex()),
        Err(e) => println!("Push rejected: {}", e),
    }

    client.shutdown().await?;
    Ok(())
}
