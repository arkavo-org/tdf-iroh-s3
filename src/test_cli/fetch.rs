use anyhow::{Context, Result};
use iroh::EndpointAddr;
use iroh_blobs::Hash;
use std::path::Path;
use std::str::FromStr;

use super::iroh_client::IrohTestClient;

/// Fetch a blob from a remote node by its BLAKE3 hash.
pub async fn fetch_blob(
    addr: EndpointAddr,
    hash_hex: &str,
    output_path: Option<&Path>,
) -> Result<()> {
    let hash = Hash::from_str(hash_hex).context("Invalid BLAKE3 hash hex string")?;

    let client = IrohTestClient::new()
        .await
        .context("Failed to create Iroh client")?;

    println!("Connecting to node {}...", addr.id);
    println!("Fetching blob {}...", hash_hex);

    let data = client
        .fetch_from_node(addr, hash)
        .await
        .context("Failed to fetch blob")?;

    println!("Fetched {} bytes", data.len());

    // Verify hash
    let computed_hash = blake3::hash(&data);
    if computed_hash.as_bytes() != hash.as_bytes() {
        anyhow::bail!(
            "Hash mismatch! Expected {} but got {}",
            hash_hex,
            computed_hash.to_hex()
        );
    }
    println!("Hash verified: {}", hash_hex);

    if let Some(path) = output_path {
        std::fs::write(path, &data)
            .with_context(|| format!("Failed to write to {}", path.display()))?;
        println!("Written to {}", path.display());
    }

    client.shutdown().await?;
    Ok(())
}
