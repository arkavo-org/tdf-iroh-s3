use anyhow::{Context, Result, bail};
use opentdf::TdfManifest;
use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::rc::Rc;
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
/// Most members an archive may list. Opening an archive costs memory per
/// member: a Creator HLS archive lists two segments per 8 seconds, about
/// 900 members an hour, so this allows days of recording.
pub const MAX_ARCHIVE_ENTRIES: u64 = 65_535;
/// Most bytes read while opening an archive: the end-of-central-directory
/// search and the central directory itself. It bounds the memory the
/// member list takes; 65,535 members with short names need under 5 MiB.
pub const MAX_CENTRAL_DIRECTORY_READ: u64 = 16 * 1024 * 1024;
/// A crafted archive could offer many ZIP64 end records for the opener to
/// try; real archives have one.
const MAX_ZIP64_CANDIDATES: usize = 4;

/// Validates that the given bytes are a valid TDF archive with a manifest
/// and payload. Returns the parsed TdfManifest on success.
pub fn validate_tdf_structure(data: &[u8]) -> Result<TdfManifest> {
    validate_tdf_structure_from(Cursor::new(data))
}

/// Validates a TDF archive read from `reader` (a file at ingest), reading
/// the ZIP central directory, the manifest and the payload member. Memory
/// does not grow with the archive: the central directory is bounded
/// ([`MAX_ARCHIVE_ENTRIES`], [`MAX_CENTRAL_DIRECTORY_READ`]), and the
/// payload is streamed to check its CRC and size.
///
/// Two layouts are accepted, as opentdf's `TdfArchive` resolves them:
/// - the spec layout: `manifest.json`, with the payload in the member that
///   `payload.url` names (`0.payload` in Arkavo's FairPlay key-envelope
///   archives). Other members, such as HLS playlists and fMP4 segments, are
///   allowed alongside it;
/// - the legacy layout: `0.manifest.json` with `0.payload`.
///
/// The manifest must parse as an OpenTDF manifest with every required field.
pub fn validate_tdf_structure_from<R: Read + Seek>(mut reader: R) -> Result<TdfManifest> {
    let archive_len = reader
        .seek(SeekFrom::End(0))
        .context("Failed to read TDF archive")?;
    check_zip64_entry_counts(&mut reader, archive_len)?;

    // The opener may try several end records, reading backwards through the
    // file; the budget caps what it reads, and with it the members it lists.
    let budget = Rc::new(Cell::new(Some(MAX_CENTRAL_DIRECTORY_READ)));
    let mut archive = ZipArchive::new(BudgetReader {
        inner: reader,
        budget: Rc::clone(&budget),
    })
    .context("Failed to open as TDF archive (not a valid ZIP or TDF)")?;
    budget.set(None);
    if archive.len() as u64 > MAX_ARCHIVE_ENTRIES {
        bail!(
            "TDF archive lists {} members, more than {MAX_ARCHIVE_ENTRIES}",
            archive.len()
        );
    }

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
    check_payload(&mut archive, &payload_name, archive_len)?;
    Ok(manifest)
}

/// Read the payload member to its end, so a truncated or corrupt payload
/// is refused: the ZIP reader checks the CRC at the end. A TDF payload is
/// ciphertext, which does not compress, so a member that would inflate
/// past the archive's own size is refused before reading (a compression
/// bomb).
fn check_payload<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    archive_len: u64,
) -> Result<()> {
    let member = archive
        .by_name(name)
        .with_context(|| format!("Failed to read payload member {name:?}"))?;
    let declared = member.size();
    if declared > archive_len {
        bail!("payload member {name:?} declares {declared} bytes, more than the archive holds");
    }
    let read = io::copy(&mut member.take(declared + 1), &mut io::sink())
        .with_context(|| format!("payload member {name:?} is corrupt"))?;
    if read != declared {
        bail!("payload member {name:?} holds {read} bytes, not the {declared} it declares");
    }
    Ok(())
}

/// Refuse an archive whose ZIP64 end record lists more than
/// [`MAX_ARCHIVE_ENTRIES`] members. The ZIP reader reserves memory for every
/// member an end record lists before reading one, so the count is checked
/// first, for every end record the reader could use: each end-of-central-
/// directory signature within the last [`MAX_CENTRAL_DIRECTORY_READ`]
/// bytes (the reader cannot search further back), and each ZIP64 end record
/// its locator could lead the reader to. A ZIP32 end record lists at most
/// 65,535 members.
fn check_zip64_entry_counts<R: Read + Seek>(reader: &mut R, len: u64) -> Result<()> {
    const EOCD: [u8; 4] = *b"PK\x05\x06";
    const LOCATOR: [u8; 4] = *b"PK\x06\x07";
    const EOCD64: [u8; 4] = *b"PK\x06\x06";
    const EOCD_LEN: usize = 22;
    const LOCATOR_LEN: u64 = 20;
    const EOCD64_LEN: usize = 56;

    let window = len.min(MAX_CENTRAL_DIRECTORY_READ);
    let tail_start = len - window;
    let tail = read_at(reader, tail_start, window)?;
    let mut candidates = 0;
    for p in positions(&tail, &EOCD) {
        let Some(eocd) = tail.get(p..p + EOCD_LEN) else {
            continue;
        };
        let files = u16::from_le_bytes([eocd[10], eocd[11]]);
        let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]);
        if files != u16::MAX && cd_offset != u32::MAX {
            continue; // not ZIP64
        }
        let eocd_at = tail_start + p as u64;
        let Some(locator_at) = eocd_at.checked_sub(LOCATOR_LEN) else {
            continue;
        };
        let locator = read_at(reader, locator_at, LOCATOR_LEN)?;
        if locator[..4] != LOCATOR {
            continue;
        }
        candidates += 1;
        if candidates > MAX_ZIP64_CANDIDATES {
            bail!("TDF archive has more than {MAX_ZIP64_CANDIDATES} ZIP64 end records");
        }
        // The reader looks for the ZIP64 end record forward from where the
        // locator says it is, up to the locator.
        let start = u64::from_le_bytes(locator[8..16].try_into().expect("8 bytes"));
        if start >= locator_at {
            continue;
        }
        let end = locator_at.min(
            start
                .saturating_add(window)
                .saturating_add(EOCD64_LEN as u64),
        );
        let region = read_at(reader, start, end - start)?;
        for q in positions(&region, &EOCD64) {
            let Some(record) = region.get(q..q + EOCD64_LEN) else {
                continue;
            };
            let on_disk = u64::from_le_bytes(record[24..32].try_into().expect("8 bytes"));
            let files = u64::from_le_bytes(record[32..40].try_into().expect("8 bytes"));
            if files.max(on_disk) > MAX_ARCHIVE_ENTRIES {
                bail!(
                    "TDF archive lists {} members, more than {MAX_ARCHIVE_ENTRIES}",
                    files.max(on_disk)
                );
            }
        }
    }
    reader
        .seek(SeekFrom::Start(0))
        .context("Failed to read TDF archive")?;
    Ok(())
}

fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, len: u64) -> Result<Vec<u8>> {
    reader
        .seek(SeekFrom::Start(offset))
        .context("Failed to read TDF archive")?;
    let mut buf = Vec::with_capacity(len as usize);
    reader
        .take(len)
        .read_to_end(&mut buf)
        .context("Failed to read TDF archive")?;
    Ok(buf)
}

/// Every offset in `haystack` where `needle` starts.
fn positions<'a>(haystack: &'a [u8], needle: &'a [u8; 4]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(move |(_, w)| *w == needle)
        .map(|(i, _)| i)
}

/// A reader that fails once it has read its budget; `None` is unlimited.
/// Seeks are free.
struct BudgetReader<R> {
    inner: R,
    budget: Rc<Cell<Option<u64>>>,
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(left) = self.budget.get() else {
            return self.inner.read(buf);
        };
        if left == 0 && !buf.is_empty() {
            return Err(io::Error::other(format!(
                "TDF archive central directory exceeds {MAX_CENTRAL_DIRECTORY_READ} bytes"
            )));
        }
        let max = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        self.budget.set(Some(left - n as u64));
        Ok(n)
    }
}

impl<R: Seek> Seek for BudgetReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
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
