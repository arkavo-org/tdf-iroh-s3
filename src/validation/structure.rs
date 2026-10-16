use anyhow::{Context, Result, bail};
use opentdf::TdfArchive;
use opentdf::TdfManifest;
use std::io::Cursor;

/// Validates that the given bytes are a valid TDF archive with a manifest and payload.
/// Returns the parsed TdfManifest on success.
///
/// Two layouts are accepted (opentdf's `TdfArchive` resolves both):
/// - the spec layout: `manifest.json`, with the payload in the member that
///   `payload.url` names (`0.payload` in Arkavo's FairPlay key-envelope
///   archives). Other members, such as HLS playlists and fMP4 segments, are
///   allowed alongside it;
/// - the legacy layout: `0.manifest.json` with `0.payload`.
///
/// The manifest must parse as an OpenTDF manifest with every required field.
pub fn validate_tdf_structure(data: &[u8]) -> Result<TdfManifest> {
    let cursor = Cursor::new(data);
    let mut archive = TdfArchive::new(cursor)
        .context("Failed to open as TDF archive (not a valid ZIP or TDF)")?;

    if archive.is_empty() {
        bail!("TDF archive contains no entries");
    }

    let entry = archive.by_index().context("Failed to read TDF entry")?;

    // TdfManifest does not implement Clone, so round-trip through JSON
    let json = entry
        .manifest
        .to_json()
        .context("Failed to serialize manifest")?;
    let manifest = TdfManifest::from_json(&json).context("Failed to deserialize manifest")?;

    Ok(manifest)
}
