use anyhow::{Context, Result, bail};
use opentdf::TdfManifest;
use std::io::{Cursor, Read, Seek};
use zip::ZipArchive;

/// The spec's manifest member.
const MANIFEST: &str = "manifest.json";
/// The manifest member every SDK wrote before the spec named one.
const LEGACY_MANIFEST: &str = "0.manifest.json";
/// The payload member when `payload.url` is empty.
const DEFAULT_PAYLOAD: &str = "0.payload";
/// Largest manifest read. Manifests are a few KiB; the bound keeps a
/// crafted archive from inflating one into memory.
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Validates that the given bytes are a valid TDF archive with a manifest
/// and payload. Returns the parsed TdfManifest on success.
pub fn validate_tdf_structure(data: &[u8]) -> Result<TdfManifest> {
    validate_tdf_structure_from(Cursor::new(data))
}

/// Validates a TDF archive read from `reader` (a file at ingest), reading
/// only the ZIP central directory and the manifest. The payload member must
/// exist; its bytes are not read, so their CRC is not checked.
///
/// Two layouts are accepted, as opentdf's `TdfArchive` resolves them:
/// - the spec layout: `manifest.json`, with the payload in the member that
///   `payload.url` names (`0.payload` in Arkavo's FairPlay key-envelope
///   archives). Other members, such as HLS playlists and fMP4 segments, are
///   allowed alongside it;
/// - the legacy layout: `0.manifest.json` with `0.payload`.
///
/// The manifest must parse as an OpenTDF manifest with every required field.
pub fn validate_tdf_structure_from<R: Read + Seek>(reader: R) -> Result<TdfManifest> {
    let mut archive = ZipArchive::new(reader)
        .context("Failed to open as TDF archive (not a valid ZIP or TDF)")?;

    let Some(manifest_name) = [MANIFEST, LEGACY_MANIFEST]
        .into_iter()
        .find(|name| archive.index_for_name(name).is_some())
    else {
        bail!(
            "TDF archive contains no entries: missing manifest file {MANIFEST} (or legacy {LEGACY_MANIFEST})"
        );
    };

    let manifest = {
        let member = archive
            .by_name(manifest_name)
            .context("Failed to read TDF entry")?;
        if member.size() > MAX_MANIFEST_BYTES {
            bail!(
                "manifest of {} bytes exceeds {MAX_MANIFEST_BYTES} bytes",
                member.size()
            );
        }
        let mut json = String::new();
        member
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_string(&mut json)
            .context("Failed to read TDF entry")?;
        if json.len() as u64 > MAX_MANIFEST_BYTES {
            bail!("manifest exceeds {MAX_MANIFEST_BYTES} bytes");
        }
        TdfManifest::from_json(&json).context("Failed to deserialize manifest")?
    };

    let payload_name = payload_member(&manifest)?;
    if archive.index_for_name(&payload_name).is_none() {
        bail!("Missing payload file: {payload_name:?} (the member named by manifest.payload.url)");
    }
    Ok(manifest)
}

/// The member holding the payload: `payload.url`, or `0.payload` when it is
/// empty. Refuses a name that escapes the archive or is shaped like a
/// manifest member, as opentdf's reader does.
fn payload_member(manifest: &TdfManifest) -> Result<String> {
    let url = manifest.payload.url.as_str();
    if url.is_empty() {
        return Ok(DEFAULT_PAYLOAD.to_string());
    }
    let safe = !url.starts_with('/')
        && !url.contains('\\')
        && !url.split('/').any(|segment| segment == "..");
    if !safe {
        bail!("unsafe payload url in manifest: {url:?}");
    }
    let manifest_shaped = url == MANIFEST
        || url
            .strip_suffix(".manifest.json")
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if manifest_shaped {
        bail!("payload url collides with the manifest entry name: {url:?}");
    }
    Ok(url.to_string())
}
