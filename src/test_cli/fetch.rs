use anyhow::{Context, Result, bail};
use iroh::EndpointAddr;
use iroh_blobs::Hash;
use std::ops::Range;
use std::path::Path;
use std::str::FromStr;

use super::iroh_client::IrohTestClient;
use super::tdf_stream::TdfRemoteArchive;

/// Parse a `<start>..<end>` byte range (half-open, e.g. `0..65536`).
pub fn parse_byte_range(spec: &str) -> Result<Range<u64>> {
    let Some((start, end)) = spec.split_once("..") else {
        bail!("invalid byte range {spec:?}: expected START..END (e.g. 0..65536)");
    };
    let start: u64 = start
        .parse()
        .with_context(|| format!("invalid range start {start:?}"))?;
    let end: u64 = end
        .parse()
        .with_context(|| format!("invalid range end {end:?}"))?;
    if end <= start {
        bail!("invalid byte range {start}..{end}: end must be greater than start");
    }
    Ok(start..end)
}

/// What to fetch from a remote TDF blob.
pub enum FetchMode {
    /// Download the whole blob and verify its BLAKE3 hash.
    Whole,
    /// Fetch only a single verified byte range `[start, end)`.
    ByteRange(Range<u64>),
    /// Fetch only the ZIP Central Directory and print all archive members.
    ListMembers,
    /// Fetch only one ZIP member (e.g. `manifest.json`, `video-segment0.m4s`).
    Member(String),
    /// Fetch only one encrypted OpenTDF payload segment (0-indexed).
    PayloadSegment(usize),
}

/// Fetch a whole blob from a remote node by its BLAKE3 hash.
pub async fn fetch_blob(
    addr: EndpointAddr,
    hash_hex: &str,
    output_path: Option<&Path>,
) -> Result<()> {
    fetch_with_mode(addr, hash_hex, FetchMode::Whole, output_path).await
}

/// Fetch a blob, a byte range, a single ZIP member, or an OpenTDF payload
/// segment from a remote node by BLAKE3 hash.
pub async fn fetch_with_mode(
    addr: EndpointAddr,
    hash_hex: &str,
    mode: FetchMode,
    output_path: Option<&Path>,
) -> Result<()> {
    let hash = Hash::from_str(hash_hex).context("Invalid BLAKE3 hash hex string")?;

    let client = IrohTestClient::new()
        .await
        .context("Failed to create Iroh client")?;

    println!("Connecting to node {}...", addr.id);

    let data = match mode {
        FetchMode::Whole => {
            println!("Fetching blob {}...", hash_hex);
            let data = client
                .fetch_from_node(addr, hash)
                .await
                .context("Failed to fetch blob")?;
            println!("Fetched {} bytes", data.len());
            let computed_hash = blake3::hash(&data);
            if computed_hash.as_bytes() != hash.as_bytes() {
                bail!(
                    "Hash mismatch! Expected {} but got {}",
                    hash_hex,
                    computed_hash.to_hex()
                );
            }
            println!("Hash verified: {}", hash_hex);
            Some(data.to_vec())
        }
        FetchMode::ByteRange(range) => {
            println!(
                "Fetching verified byte range {}..{} of {}...",
                range.start, range.end, hash_hex
            );
            let conn = client.connect(addr).await?;
            let data = client.get_byte_range_on(&conn, hash, range.clone()).await?;
            println!("Fetched and BAO-verified {} bytes", data.len());
            Some(data)
        }
        FetchMode::ListMembers => {
            let conn = client.connect(addr).await?;
            let archive = TdfRemoteArchive::open(&client, conn, hash, None).await?;
            println!(
                "TDF {} ({} bytes, {} members):",
                hash_hex,
                archive.size(),
                archive.members().len()
            );
            for m in archive.members() {
                let method = match m.compression_method {
                    0 => "stored",
                    8 => "deflate",
                    other => {
                        println!(
                            "  {}  offset={} compressed={} uncompressed={} method={other}",
                            m.name, m.header_offset, m.compressed_size, m.uncompressed_size
                        );
                        continue;
                    }
                };
                println!(
                    "  {}  offset={} compressed={} uncompressed={} method={method}",
                    m.name, m.header_offset, m.compressed_size, m.uncompressed_size
                );
            }
            None
        }
        FetchMode::Member(name) => {
            println!("Streaming TDF member {:?} from {}...", name, hash_hex);
            let conn = client.connect(addr).await?;
            let archive = TdfRemoteArchive::open(&client, conn, hash, None).await?;
            let data = archive.fetch_member(&name).await?;
            println!(
                "Fetched and verified member {:?} ({} bytes of {} byte archive)",
                name,
                data.len(),
                archive.size()
            );
            Some(data)
        }
        FetchMode::PayloadSegment(index) => {
            println!(
                "Streaming OpenTDF payload segment {} from {}...",
                index, hash_hex
            );
            let conn = client.connect(addr).await?;
            let mut archive = TdfRemoteArchive::open(&client, conn, hash, None).await?;
            let data = archive.fetch_payload_segment(index).await?;
            println!(
                "Fetched and verified payload segment {} ({} bytes of {} byte archive)",
                index,
                data.len(),
                archive.size()
            );
            Some(data)
        }
    };

    if let (Some(path), Some(bytes)) = (output_path, data) {
        std::fs::write(path, &bytes)
            .with_context(|| format!("Failed to write to {}", path.display()))?;
        println!("Written to {}", path.display());
    }

    client.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_range_valid_and_invalid() {
        assert_eq!(parse_byte_range("0..65536").unwrap(), 0..65536);
        assert_eq!(parse_byte_range("1024..2048").unwrap(), 1024..2048);
        assert!(parse_byte_range("1024..1024").is_err());
        assert!(parse_byte_range("2048..1024").is_err());
        assert!(parse_byte_range("1024").is_err());
        assert!(parse_byte_range("a..b").is_err());
    }
}
