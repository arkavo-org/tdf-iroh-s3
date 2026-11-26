//! On-demand streaming of individual ZIP members and OpenTDF payload segments
//! from a remote TDF blob over a single Iroh QUIC connection.
//!
//! A TDF is a ZIP archive served over `iroh-blobs` with BAO verified streaming.
//! Rather than downloading the entire archive, [`TdfRemoteArchive`] fetches
//! only the ZIP Central Directory at the end of the blob, then fetches
//! individual members (such as HLS playlists and fMP4 `.m4s` segments) or
//! individual encrypted OpenTDF segments inside a `Stored` payload member via
//! ranged `GetRequest`s, verifying every 16 KiB chunk group against the blob's
//! BLAKE3 root hash.

use std::io::{Cursor, Read};
use std::ops::Range;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::Connection;
use iroh_blobs::Hash;
use opentdf::TdfManifest;
use zip::ZipArchive;

use crate::test_cli::iroh_client::IrohTestClient;

/// Initial tail window fetched from the end of a TDF to locate the ZIP End of
/// Central Directory (and, for small/medium archives, the Central Directory
/// itself in the same round trip).
const TAIL_FETCH_BYTES: u64 = 64 * 1024;

/// Slack read past the fixed 30-byte ZIP local file header so the variable
/// filename and extra fields are almost always covered in the same single
/// range fetch as the member's payload.
const LOCAL_HEADER_SLACK: u64 = 4096;

/// ZIP compression method for uncompressed (random-access) members.
pub const ZIP_METHOD_STORED: u16 = 0;

/// Metadata for one member listed in a TDF's ZIP Central Directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipMemberInfo {
    pub name: String,
    /// Byte offset of the member's local file header within the TDF blob.
    pub header_offset: u64,
    /// Compressed byte length stored in the archive.
    pub compressed_size: u64,
    /// Uncompressed byte length of the member.
    pub uncompressed_size: u64,
    /// ZIP compression method (`0` = Stored, `8` = Deflate).
    pub compression_method: u16,
    /// Raw Central Directory File Header bytes for this entry, used to
    /// reassemble a standalone single-entry ZIP view when decoding/verifying
    /// the member with the `zip` crate.
    raw_cd_entry: Vec<u8>,
}

/// Byte location of the ZIP Central Directory within an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CentralDirectorySpan {
    offset: u64,
    size: u64,
}

/// A remote TDF opened for on-demand member and segment streaming over one
/// reusable Iroh QUIC connection.
pub struct TdfRemoteArchive<'a> {
    client: &'a IrohTestClient,
    conn: Connection,
    hash: Hash,
    size: u64,
    members: Vec<ZipMemberInfo>,
    /// Cached manifest once fetched (used by [`Self::fetch_payload_segment`]).
    manifest: Option<TdfManifest>,
}

impl<'a> TdfRemoteArchive<'a> {
    /// Open a remote TDF by fetching only its size and ZIP Central Directory.
    /// When `known_size` is `Some`, skips the initial size probe.
    pub async fn open(
        client: &'a IrohTestClient,
        conn: Connection,
        hash: Hash,
        known_size: Option<u64>,
    ) -> Result<Self> {
        let size = match known_size {
            Some(size) => size,
            None => client.probe_size_on(&conn, hash).await?,
        };
        if size < 22 {
            bail!("blob of {size} bytes is too small to be a ZIP/TDF archive");
        }

        let tail_start = size.saturating_sub(TAIL_FETCH_BYTES);
        let tail = client
            .get_byte_range_on(&conn, hash, tail_start..size)
            .await
            .context("Failed to fetch ZIP tail")?;

        let cd_span = match locate_central_directory(&tail, tail_start, size)? {
            CdLookup::Found(span) => span,
            CdLookup::NeedZip64Eocd { eocd64_offset } => {
                let eocd64_end = eocd64_offset.saturating_add(56).min(size);
                let eocd64 = client
                    .get_byte_range_on(&conn, hash, eocd64_offset..eocd64_end)
                    .await
                    .context("Failed to fetch ZIP64 EOCD record")?;
                parse_zip64_eocd(&eocd64)?
            }
        };

        let cd_end = cd_span
            .offset
            .checked_add(cd_span.size)
            .filter(|&end| end <= size)
            .ok_or_else(|| anyhow!("ZIP Central Directory range exceeds archive size"))?;

        let cd_bytes = if cd_span.offset >= tail_start && cd_end <= size {
            let rel_start = (cd_span.offset - tail_start) as usize;
            let rel_end = (cd_end - tail_start) as usize;
            tail[rel_start..rel_end].to_vec()
        } else {
            client
                .get_byte_range_on(&conn, hash, cd_span.offset..cd_end)
                .await
                .context("Failed to fetch ZIP Central Directory")?
        };

        let members = parse_central_directory(&cd_bytes)?;

        Ok(Self {
            client,
            conn,
            hash,
            size,
            members,
            manifest: None,
        })
    }

    /// Total size of the TDF archive in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// All members listed in the TDF's ZIP Central Directory.
    pub fn members(&self) -> &[ZipMemberInfo] {
        &self.members
    }

    /// Look up one member by exact archive path.
    pub fn member(&self, name: &str) -> Option<&ZipMemberInfo> {
        self.members.iter().find(|m| m.name == name)
    }

    /// Fetch and return the uncompressed bytes of a single ZIP member (for
    /// example `manifest.json`, `master.m3u8`, or `video-segment0.m4s`),
    /// verifying both its BAO hash proof and its ZIP CRC32.
    pub async fn fetch_member(&self, name: &str) -> Result<Vec<u8>> {
        let info = self
            .member(name)
            .with_context(|| format!("member {name:?} not found in TDF archive"))?
            .clone();

        // Fetch the local file header plus the compressed payload in one range
        // request (extending only if the local extra field exceeds our slack).
        let header_guess = 30u64
            .saturating_add(info.name.len() as u64)
            .saturating_add(LOCAL_HEADER_SLACK);
        let initial_end = info
            .header_offset
            .saturating_add(header_guess)
            .saturating_add(info.compressed_size)
            .min(self.size);

        let mut member_bytes = self
            .client
            .get_byte_range_on(&self.conn, self.hash, info.header_offset..initial_end)
            .await
            .with_context(|| format!("Failed to fetch member {name:?}"))?;

        let data_offset = parse_local_header_data_offset(&member_bytes, info.header_offset)?;
        let data_end = data_offset
            .checked_add(info.compressed_size)
            .filter(|&end| end <= self.size)
            .ok_or_else(|| anyhow!("member {name:?} extends past archive end"))?;

        if data_end > initial_end {
            let rest = self
                .client
                .get_byte_range_on(&self.conn, self.hash, initial_end..data_end)
                .await
                .with_context(|| format!("Failed to fetch remaining bytes of member {name:?}"))?;
            member_bytes.extend_from_slice(&rest);
        }

        let entry_len = usize::try_from(data_end - info.header_offset)
            .context("ZIP member larger than addressable memory")?;
        decode_single_member(&info, &member_bytes[..entry_len])
    }

    /// Fetch and parse the TDF manifest (`manifest.json` or legacy
    /// `0.manifest.json`), caching it for subsequent calls.
    pub async fn fetch_manifest(&mut self) -> Result<&TdfManifest> {
        if self.manifest.is_none() {
            let name = ["manifest.json", "0.manifest.json"]
                .into_iter()
                .find(|n| self.member(n).is_some())
                .ok_or_else(|| anyhow!("TDF archive has no manifest.json or 0.manifest.json"))?;
            let bytes = self.fetch_member(name).await?;
            let json = std::str::from_utf8(&bytes).context("TDF manifest is not UTF-8")?;
            let parsed =
                TdfManifest::from_json(json).context("Failed to parse TDF manifest JSON")?;
            self.manifest = Some(parsed);
        }
        Ok(self.manifest.as_ref().expect("populated above"))
    }

    /// Fetch one encrypted OpenTDF payload segment (0-indexed into
    /// `encryptionInformation.integrityInformation.segments`) directly from
    /// the TDF's payload member without downloading the rest of the payload.
    ///
    /// Requires the payload member to be ZIP-stored (`compression_method == 0`,
    /// no deflate) so segment offsets map directly to archive byte ranges.
    pub async fn fetch_payload_segment(&mut self, segment_index: usize) -> Result<Vec<u8>> {
        let (payload_name, seg_offset, seg_len) = {
            let manifest = self.fetch_manifest().await?;
            let payload_name = if manifest.payload.url.is_empty() {
                "0.payload".to_string()
            } else {
                manifest.payload.url.clone()
            };
            let integrity = &manifest.encryption_information.integrity_information;
            if segment_index >= integrity.segments.len() {
                bail!(
                    "segment index {segment_index} out of range (manifest lists {} segments)",
                    integrity.segments.len()
                );
            }
            let mut offset = 0u64;
            for seg in &integrity.segments[..segment_index] {
                let sz = seg
                    .encrypted_segment_size
                    .unwrap_or(integrity.encrypted_segment_size_default);
                offset = offset
                    .checked_add(sz)
                    .ok_or_else(|| anyhow!("segment offset overflow"))?;
            }
            let seg = &integrity.segments[segment_index];
            let seg_len = seg
                .encrypted_segment_size
                .unwrap_or(integrity.encrypted_segment_size_default);
            (payload_name, offset, seg_len)
        };

        let info = self
            .member(&payload_name)
            .with_context(|| format!("payload member {payload_name:?} not found in TDF"))?
            .clone();
        if info.compression_method != ZIP_METHOD_STORED {
            bail!(
                "payload member {payload_name:?} uses ZIP compression method {} (must be Stored / 0 for segment streaming)",
                info.compression_method
            );
        }

        // Read the 30-byte local file header to find the exact start of payload data.
        let header_end = info.header_offset.saturating_add(30).min(self.size);
        let local_header = self
            .client
            .get_byte_range_on(&self.conn, self.hash, info.header_offset..header_end)
            .await
            .context("Failed to fetch payload local file header")?;
        let data_offset = parse_local_header_data_offset(&local_header, info.header_offset)?;

        let byte_range = (data_offset + seg_offset)..(data_offset + seg_offset + seg_len);
        if byte_range.end > data_offset + info.compressed_size || byte_range.end > self.size {
            bail!(
                "segment {segment_index} ({byte_range:?}) exceeds payload member bounds ({}..{})",
                data_offset,
                data_offset + info.compressed_size
            );
        }

        self.client
            .get_byte_range_on(&self.conn, self.hash, byte_range)
            .await
            .with_context(|| format!("Failed to fetch OpenTDF payload segment {segment_index}"))
    }
}

/// Decode and CRC-verify a single member from its `[local_header || payload]`
/// bytes by wrapping them with its Central Directory entry (rebased to offset
/// 0) and a synthetic End of Central Directory, then reading through `zip`.
fn decode_single_member(info: &ZipMemberInfo, local_and_payload: &[u8]) -> Result<Vec<u8>> {
    let cd_offset = u32::try_from(local_and_payload.len())
        .context("single ZIP member exceeds 4 GiB standalone view")?;
    let mut cd_entry = info.raw_cd_entry.clone();
    rebase_cd_entry_to_zero(&mut cd_entry)?;
    let cd_size = u32::try_from(cd_entry.len()).context("Central Directory entry too large")?;

    let mut mini_zip = Vec::with_capacity(local_and_payload.len() + cd_entry.len() + 22);
    mini_zip.extend_from_slice(local_and_payload);
    mini_zip.extend_from_slice(&cd_entry);
    // End of Central Directory (22 bytes, 1 entry).
    mini_zip.extend_from_slice(b"PK\x05\x06");
    mini_zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
    mini_zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    mini_zip.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    mini_zip.extend_from_slice(&1u16.to_le_bytes()); // total entries
    mini_zip.extend_from_slice(&cd_size.to_le_bytes());
    mini_zip.extend_from_slice(&cd_offset.to_le_bytes());
    mini_zip.extend_from_slice(&0u16.to_le_bytes()); // comment length

    let mut archive = ZipArchive::new(Cursor::new(mini_zip))
        .context("Failed to open standalone ZIP view for member extraction")?;
    let mut entry = archive
        .by_index(0)
        .with_context(|| format!("Failed to read member {:?}", info.name))?;
    let mut out = Vec::with_capacity(info.uncompressed_size as usize);
    entry
        .read_to_end(&mut out)
        .with_context(|| format!("Failed to decode/verify member {:?}", info.name))?;
    Ok(out)
}

/// Patch a raw Central Directory File Header so its local header offset is `0`
/// (including inside a ZIP64 extended information extra field if present).
fn rebase_cd_entry_to_zero(cd_entry: &mut [u8]) -> Result<()> {
    const CD_FIXED_LEN: usize = 46;
    if cd_entry.len() < CD_FIXED_LEN {
        bail!("Central Directory entry shorter than {CD_FIXED_LEN} bytes");
    }
    let uncompressed_32 = u32::from_le_bytes(cd_entry[24..28].try_into().expect("4 bytes"));
    let compressed_32 = u32::from_le_bytes(cd_entry[20..24].try_into().expect("4 bytes"));
    let offset_32 = u32::from_le_bytes(cd_entry[42..46].try_into().expect("4 bytes"));

    if offset_32 != u32::MAX {
        cd_entry[42..46].copy_from_slice(&0u32.to_le_bytes());
        return Ok(());
    }

    // Offset was stored in the ZIP64 extra field (header ID 0x0001): zero it there.
    let name_len = u16::from_le_bytes([cd_entry[28], cd_entry[29]]) as usize;
    let extra_len = u16::from_le_bytes([cd_entry[30], cd_entry[31]]) as usize;
    let extra_start = CD_FIXED_LEN + name_len;
    let extra_end = extra_start + extra_len;
    if extra_end > cd_entry.len() {
        bail!("truncated ZIP64 extra field in Central Directory entry");
    }
    let extra = &mut cd_entry[extra_start..extra_end];
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let len = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        pos += 4;
        if pos + len > extra.len() {
            bail!("truncated extra field in Central Directory entry");
        }
        if id == 0x0001 {
            let mut field_off = 0usize;
            if uncompressed_32 == u32::MAX {
                field_off += 8;
            }
            if compressed_32 == u32::MAX {
                field_off += 8;
            }
            if field_off + 8 > len {
                bail!("ZIP64 extra field missing 64-bit local header offset");
            }
            extra[pos + field_off..pos + field_off + 8].copy_from_slice(&0u64.to_le_bytes());
            return Ok(());
        }
        pos += len;
    }
    bail!("ZIP64 local header offset sentinel without 0x0001 extra field");
}

enum CdLookup {
    Found(CentralDirectorySpan),
    NeedZip64Eocd { eocd64_offset: u64 },
}

fn locate_central_directory(tail: &[u8], tail_offset: u64, total_size: u64) -> Result<CdLookup> {
    const EOCD_SIG: [u8; 4] = *b"PK\x05\x06";
    const ZIP64_LOCATOR_SIG: [u8; 4] = *b"PK\x06\x07";
    const EOCD_MIN_LEN: usize = 22;

    if tail.len() < EOCD_MIN_LEN {
        bail!("ZIP tail too short ({} bytes)", tail.len());
    }
    let max_start = tail.len() - EOCD_MIN_LEN;
    let eocd_rel = (0..=max_start)
        .rev()
        .find(|&i| {
            tail[i..i + 4] == EOCD_SIG && {
                let comment_len = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
                i + EOCD_MIN_LEN + comment_len == tail.len()
            }
        })
        .ok_or_else(|| anyhow!("ZIP End of Central Directory not found"))?;

    let eocd = &tail[eocd_rel..eocd_rel + EOCD_MIN_LEN];
    let entries = u16::from_le_bytes([eocd[10], eocd[11]]);
    let cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]);
    let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]);

    if entries == u16::MAX || cd_size == u32::MAX || cd_offset == u32::MAX {
        if eocd_rel < 20 {
            bail!("ZIP64 EOCD locator precedes fetched tail");
        }
        let loc = &tail[eocd_rel - 20..eocd_rel];
        if loc[0..4] != ZIP64_LOCATOR_SIG {
            bail!("ZIP64 EOCD locator signature missing");
        }
        let eocd64_offset = u64::from_le_bytes(loc[8..16].try_into().expect("8 bytes"));
        if eocd64_offset >= total_size {
            bail!("ZIP64 EOCD offset {eocd64_offset} exceeds archive size {total_size}");
        }
        if eocd64_offset >= tail_offset {
            let rel = (eocd64_offset - tail_offset) as usize;
            return Ok(CdLookup::Found(parse_zip64_eocd(&tail[rel..])?));
        }
        return Ok(CdLookup::NeedZip64Eocd { eocd64_offset });
    }

    Ok(CdLookup::Found(CentralDirectorySpan {
        offset: cd_offset as u64,
        size: cd_size as u64,
    }))
}

fn parse_zip64_eocd(slice: &[u8]) -> Result<CentralDirectorySpan> {
    const EOCD64_SIG: [u8; 4] = *b"PK\x06\x06";
    if slice.len() < 56 || slice[0..4] != EOCD64_SIG {
        bail!("invalid ZIP64 End of Central Directory record");
    }
    let cd_size = u64::from_le_bytes(slice[40..48].try_into().expect("8 bytes"));
    let cd_offset = u64::from_le_bytes(slice[48..56].try_into().expect("8 bytes"));
    Ok(CentralDirectorySpan {
        offset: cd_offset,
        size: cd_size,
    })
}

/// Parse all Central Directory File Headers (`PK\x01\x02`) from `cd_bytes`.
fn parse_central_directory(cd_bytes: &[u8]) -> Result<Vec<ZipMemberInfo>> {
    const CD_HEADER_SIG: [u8; 4] = *b"PK\x01\x02";
    const CD_FIXED_LEN: usize = 46;

    let mut members = Vec::new();
    let mut pos = 0usize;
    while pos < cd_bytes.len() {
        if pos + CD_FIXED_LEN > cd_bytes.len() || cd_bytes[pos..pos + 4] != CD_HEADER_SIG {
            bail!("corrupt ZIP Central Directory header at offset {pos}");
        }
        let h = &cd_bytes[pos..pos + CD_FIXED_LEN];
        let compression_method = u16::from_le_bytes([h[10], h[11]]);
        let mut compressed_size = u32::from_le_bytes([h[20], h[21], h[22], h[23]]) as u64;
        let mut uncompressed_size = u32::from_le_bytes([h[24], h[25], h[26], h[27]]) as u64;
        let name_len = u16::from_le_bytes([h[28], h[29]]) as usize;
        let extra_len = u16::from_le_bytes([h[30], h[31]]) as usize;
        let comment_len = u16::from_le_bytes([h[32], h[33]]) as usize;
        let mut header_offset = u32::from_le_bytes([h[42], h[43], h[44], h[45]]) as u64;

        let name_start = pos + CD_FIXED_LEN;
        let extra_start = name_start + name_len;
        let next_pos = extra_start + extra_len + comment_len;
        if next_pos > cd_bytes.len() {
            bail!("truncated ZIP Central Directory entry at offset {pos}");
        }
        let name = String::from_utf8_lossy(&cd_bytes[name_start..extra_start]).into_owned();
        let extra = &cd_bytes[extra_start..extra_start + extra_len];

        if uncompressed_size == u32::MAX as u64
            || compressed_size == u32::MAX as u64
            || header_offset == u32::MAX as u64
        {
            apply_zip64_extra(
                extra,
                &mut uncompressed_size,
                &mut compressed_size,
                &mut header_offset,
            )?;
        }

        members.push(ZipMemberInfo {
            name,
            header_offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            raw_cd_entry: cd_bytes[pos..next_pos].to_vec(),
        });
        pos = next_pos;
    }
    Ok(members)
}

fn apply_zip64_extra(
    extra: &[u8],
    uncompressed_size: &mut u64,
    compressed_size: &mut u64,
    header_offset: &mut u64,
) -> Result<()> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let len = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        pos += 4;
        if pos + len > extra.len() {
            bail!("truncated ZIP64 extra field");
        }
        if id == 0x0001 {
            let mut field = &extra[pos..pos + len];
            let mut take_u64 = || -> Result<u64> {
                if field.len() < 8 {
                    bail!("ZIP64 extra field missing expected 64-bit value");
                }
                let val = u64::from_le_bytes(field[..8].try_into().expect("8 bytes"));
                field = &field[8..];
                Ok(val)
            };
            if *uncompressed_size == u32::MAX as u64 {
                *uncompressed_size = take_u64()?;
            }
            if *compressed_size == u32::MAX as u64 {
                *compressed_size = take_u64()?;
            }
            if *header_offset == u32::MAX as u64 {
                *header_offset = take_u64()?;
            }
            return Ok(());
        }
        pos += len;
    }
    bail!("ZIP64 sentinel set without 0x0001 extra field");
}

fn parse_local_header_data_offset(local_header: &[u8], header_offset: u64) -> Result<u64> {
    const LOCAL_HEADER_SIG: [u8; 4] = *b"PK\x03\x04";
    if local_header.len() < 30 || local_header[0..4] != LOCAL_HEADER_SIG {
        bail!("invalid ZIP local file header at offset {header_offset}");
    }
    let name_len = u16::from_le_bytes([local_header[26], local_header[27]]) as u64;
    let extra_len = u16::from_le_bytes([local_header[28], local_header[29]]) as u64;
    header_offset
        .checked_add(30)
        .and_then(|o| o.checked_add(name_len))
        .and_then(|o| o.checked_add(extra_len))
        .ok_or_else(|| anyhow!("ZIP local file header offset overflow"))
}

/// Convert a byte range `[start, end)` into the minimal 1 KiB `ChunkRanges`
/// covering those bytes.
pub fn byte_range_to_chunk_ranges(bytes: &Range<u64>) -> iroh_blobs::protocol::ChunkRanges {
    use bao_tree::{ChunkNum, ChunkRanges};
    if bytes.is_empty() {
        return ChunkRanges::empty();
    }
    let first = ChunkNum(bytes.start / 1024);
    let last = ChunkNum(bytes.end.div_ceil(1024));
    ChunkRanges::from(first..last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    fn build_zip(members: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, data, method) in members {
                let opts = SimpleFileOptions::default().compression_method(*method);
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn locates_and_parses_central_directory_and_local_offsets() {
        let zip_bytes = build_zip(&[
            (
                "manifest.json",
                b"{\"hello\":\"world\"}",
                CompressionMethod::Stored,
            ),
            (
                "video-segment0.m4s",
                &[0xAB; 5000],
                CompressionMethod::Stored,
            ),
            (
                "master.m3u8",
                b"#EXTM3U\n#EXT-X-VERSION:7\n",
                CompressionMethod::Deflated,
            ),
        ]);
        let size = zip_bytes.len() as u64;
        let CdLookup::Found(span) = locate_central_directory(&zip_bytes, 0, size).unwrap() else {
            panic!("expected direct EOCD");
        };
        let cd = &zip_bytes[span.offset as usize..(span.offset + span.size) as usize];
        let members = parse_central_directory(cd).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].name, "manifest.json");
        assert_eq!(members[0].compression_method, ZIP_METHOD_STORED);
        assert_eq!(members[1].name, "video-segment0.m4s");
        assert_eq!(members[1].compressed_size, 5000);
        assert_eq!(members[2].name, "master.m3u8");
        assert_eq!(members[2].compression_method, 8);

        let seg_off = parse_local_header_data_offset(
            &zip_bytes[members[1].header_offset as usize..],
            members[1].header_offset,
        )
        .unwrap();
        assert_eq!(
            &zip_bytes[seg_off as usize..seg_off as usize + 5000],
            &[0xAB; 5000]
        );
    }

    #[test]
    fn decodes_stored_and_deflated_single_members_independently() {
        let seg0 = vec![0x11u8; 40_000];
        let seg1 = vec![0x22u8; 40_000];
        let seg2 = vec![0x33u8; 40_000];
        let zip_bytes = build_zip(&[
            ("video-segment0.m4s", &seg0, CompressionMethod::Stored),
            ("video-segment1.m4s", &seg1, CompressionMethod::Stored),
            ("video-segment2.m4s", &seg2, CompressionMethod::Deflated),
        ]);
        let size = zip_bytes.len() as u64;
        let tail_start = size.saturating_sub(4096);
        let tail = zip_bytes[tail_start as usize..].to_vec();
        let CdLookup::Found(span) = locate_central_directory(&tail, tail_start, size).unwrap()
        else {
            panic!("expected direct EOCD");
        };
        let cd = &zip_bytes[span.offset as usize..(span.offset + span.size) as usize];
        let members = parse_central_directory(cd).unwrap();

        for (member, expected) in [(&members[1], &seg1), (&members[2], &seg2)] {
            let data_off = parse_local_header_data_offset(
                &zip_bytes[member.header_offset as usize..],
                member.header_offset,
            )
            .unwrap();
            let end = (data_off + member.compressed_size) as usize;
            let slice = &zip_bytes[member.header_offset as usize..end];
            let decoded = decode_single_member(member, slice).unwrap();
            assert_eq!(&decoded, expected);
        }
    }
}
