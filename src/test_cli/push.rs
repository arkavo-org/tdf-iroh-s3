use anyhow::{Context, Result};
use iroh::EndpointId;

use super::create_tdf::create_tdf_bytes;
use super::iroh_client::IrohTestClient;

/// Create a TDF with the given attribute and push it to a remote node.
pub async fn push_tdf(
    node_id: EndpointId,
    attribute_fqn: &str,
    data: &[u8],
) -> Result<()> {
    let tdf_bytes = create_tdf_bytes(attribute_fqn, data)
        .context("Failed to create TDF")?;

    let tdf_hash = blake3::hash(&tdf_bytes);
    println!("Created TDF ({} bytes)", tdf_bytes.len());
    println!("BLAKE3 hash: {}", tdf_hash.to_hex());

    let client = IrohTestClient::new()
        .await
        .context("Failed to create Iroh client")?;

    println!("Connecting to node {}...", node_id);
    let hash = client
        .push_to_node(node_id, &tdf_bytes)
        .await
        .context("Failed to push TDF to node")?;

    println!("Pushed blob: {}", hash.to_hex());
    client.shutdown().await?;

    Ok(())
}
