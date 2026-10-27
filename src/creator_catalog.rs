//! A creator catalog's clear entry list, the `index` of `PUT
//! /v2/catalogs/{sub}` (tdf-iroh-s3#39).
//!
//! The catalog document itself, `arkavo.creator-catalog/2`, is the payload
//! of a ZTDF envelope (`catalog_metadata::check_envelope`) the node never
//! decrypts, so the node checks the recordings it lists through the index
//! the publisher sends with it (`docs/creator-catalogs.md`). Each document
//! entry names a recording by hash and size and carries its metadata TDF
//! (title, publish time, attributes) inline; an index entry is the same
//! entry without the metadata, which only Creator and the viewer read.
//! Strict: unknown and duplicate keys are refused.
//!
//! Pure: no I/O, so every rule is a plain unit test.

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Largest catalog document (the envelope ZTDF), in bytes: 4 MiB, room for
/// 1000 entries with their metadata TDFs inline.
pub const MAX_CATALOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1000;
pub const MAX_OWNER_BYTES: usize = 248;
pub const MAX_CONTENT_ID_BYTES: usize = 256;
/// 2^53 - 1, the largest integer every JSON reader represents exactly.
pub const MAX_VERSION: u64 = 9_007_199_254_740_991;
/// 4 GiB − 1 (`u32::MAX`): the largest TDF a catalog may name, and the
/// default `[validation] max_blob_bytes` (`config::DEFAULT_MAX_BLOB_BYTES`).
pub const MAX_PAYLOAD_SIZE: u64 = 4_294_967_295;
/// One published recording: what the node checks at publish.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreatorCatalogEntry {
    #[serde(rename = "contentID")]
    pub content_id: String,
    pub version: u64,
    /// BLAKE3 hash of the TDF bytes, 64 lowercase hex characters.
    pub payload_hash: String,
    pub payload_size: u64,
}

/// Parse and validate an index: an array of at most [`MAX_ENTRIES`] entries
/// with unique `contentID`s. The caller has already refused duplicate keys
/// ([`NoDuplicateKeys`]) in the bytes it came from. The error is the reason
/// the HTTP layer reports as `invalid index: <reason>`.
pub fn parse_index(index: serde_json::Value) -> Result<Vec<CreatorCatalogEntry>, String> {
    let serde_json::Value::Array(raw) = index else {
        return Err(format!("must be an array of at most {MAX_ENTRIES} entries"));
    };
    if raw.len() > MAX_ENTRIES {
        return Err(format!("must be an array of at most {MAX_ENTRIES} entries"));
    }
    let mut entries = Vec::with_capacity(raw.len());
    let mut content_ids: HashMap<String, usize> = HashMap::with_capacity(raw.len());
    for (i, raw) in raw.into_iter().enumerate() {
        let e = entry(raw).map_err(|reason| format!("entries[{i}].{reason}"))?;
        if let Some(first) = content_ids.insert(e.content_id.clone(), i) {
            return Err(format!(
                "entries[{i}].contentID duplicates entries[{first}].contentID"
            ));
        }
        entries.push(e);
    }
    Ok(entries)
}

fn entry(raw: serde_json::Value) -> Result<CreatorCatalogEntry, String> {
    let e: CreatorCatalogEntry = serde_json::from_value(raw).map_err(|e| e.to_string())?;
    if !valid_identifier(&e.content_id, MAX_CONTENT_ID_BYTES) {
        return Err(format!(
            "contentID must be 1-{MAX_CONTENT_ID_BYTES} bytes of [A-Za-z0-9:._@-] without \"..\""
        ));
    }
    if !(1..=MAX_VERSION).contains(&e.version) {
        return Err(format!(
            "version must be an integer from 1 to {MAX_VERSION}"
        ));
    }
    if !is_lower_hex_hash(&e.payload_hash) {
        return Err("payloadHash must be 64 lowercase hex characters".to_string());
    }
    if !(1..=MAX_PAYLOAD_SIZE).contains(&e.payload_size) {
        return Err(format!(
            "payloadSize must be an integer from 1 to {MAX_PAYLOAD_SIZE}"
        ));
    }
    Ok(e)
}

/// `owner` and `contentID`: `[A-Za-z0-9:._@-]{1,max}`, never `.` and never
/// containing `..`.
pub fn valid_identifier(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
        && s != "."
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'@' | b'-'))
}

/// A BLAKE3 hash as the catalog routes take it: 64 lowercase hex characters.
pub fn is_lower_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `YYYY-MM-DDTHH:MM:SSZ`: RFC 3339 in UTC, to the second, with a real
/// calendar date. A leap second (`:60`) is refused: readers that parse with
/// a strict calendar would reject it.
pub fn is_utc_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    let shape = b.iter().enumerate().all(|(i, &c)| match i {
        4 | 7 => c == b'-',
        10 => c == b'T',
        13 | 16 => c == b':',
        19 => c == b'Z',
        _ => c.is_ascii_digit(),
    });
    if !shape {
        return false;
    }
    let num = |range: std::ops::Range<usize>| {
        b[range]
            .iter()
            .fold(0u32, |n, &c| n * 10 + u32::from(c - b'0'))
    };
    let (year, month, day) = (num(0..4), num(5..7), num(8..10));
    let (hour, minute, second) = (num(11..13), num(14..16), num(17..19));
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

/// Deserializes any JSON value, failing on an object that repeats a key.
pub(crate) struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate key `{key}`")));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    /// ArkavoKit's shared catalog vectors of `kind`
    /// (`Tests/ArkavoCatalogTests/Vectors/catalog-vectors.json`), so the node
    /// and the Swift readers agree: (name, valid, bytes).
    pub fn vectors(kind: &str) -> Vec<(String, bool, Vec<u8>)> {
        use base64::Engine as _;
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/arkavo-catalog-vectors.json"
        ))
        .unwrap();
        let vectors: Vec<_> = file["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == kind)
            .map(|v| {
                let bytes = match (v["text"].as_str(), v["base64"].as_str()) {
                    (Some(text), _) => text.as_bytes().to_vec(),
                    (None, Some(b64)) => base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .unwrap(),
                    _ => panic!("vector without bytes: {v}"),
                };
                (
                    v["name"].as_str().unwrap().to_string(),
                    v["valid"].as_bool().unwrap(),
                    bytes,
                )
            })
            .collect();
        assert!(!vectors.is_empty(), "no {kind} vectors");
        vectors
    }

    /// The `payloadSize` of [`entry`].
    pub const PAYLOAD_SIZE: u64 = 7_342_067;

    /// A valid index entry for `payload`, as a JSON value.
    pub fn entry(content_id: &str, payload: &str) -> serde_json::Value {
        serde_json::json!({
            "contentID": content_id,
            "version": 1,
            "payloadHash": payload,
            "payloadSize": PAYLOAD_SIZE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::entry;
    use super::*;
    use serde_json::{Value, json};

    fn hash() -> String {
        "4f".repeat(32)
    }

    /// As the route parses it: duplicate keys refused in the bytes, then
    /// the value.
    fn parse(bytes: &[u8]) -> Result<Vec<CreatorCatalogEntry>, String> {
        serde_json::from_slice::<NoDuplicateKeys>(bytes).map_err(|e| e.to_string())?;
        parse_index(serde_json::from_slice(bytes).map_err(|e| e.to_string())?)
    }

    fn index(entries: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&entries).unwrap()
    }

    fn entry_with(f: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut e = entry("rec-1", &hash());
        f(&mut e);
        index(vec![e])
    }

    fn reason(bytes: &[u8]) -> String {
        parse(bytes).expect_err("index should be refused")
    }

    #[test]
    fn the_contract_example_is_valid() {
        let entries = parse(
            br#"[ { "contentID": "rec-2b9c4f1e0d8a4c7f", "version": 2,
                 "payloadHash": "4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a", "payloadSize": 7342067 } ]"#,
        )
        .unwrap();
        assert_eq!(
            entries,
            vec![CreatorCatalogEntry {
                content_id: "rec-2b9c4f1e0d8a4c7f".into(),
                version: 2,
                payload_hash: "4f8a".repeat(16),
                payload_size: 7_342_067,
            }]
        );
    }

    #[test]
    fn an_empty_index_is_valid() {
        assert!(parse(b"[]").unwrap().is_empty());
    }

    #[test]
    fn an_index_is_an_array() {
        for bad in [&b"{}"[..], b"null", b"\"x\"", br#"{"entries":[]}"#] {
            assert_eq!(
                reason(bad),
                "must be an array of at most 1000 entries",
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn an_entry_has_exactly_its_own_keys() {
        // The metadata stays in the envelope; neither its TDF nor a hash of
        // it, nor `/1`'s display fields, belongs in the index.
        for (key, value) in [
            ("metadata", json!("AAAA")),
            ("metadataHash", json!("6d".repeat(32))),
            ("metadataSize", json!(2148)),
            ("metadataManifest", json!("e30")),
            ("title", json!("Studio session")),
            ("publishedAt", json!("2026-10-16T14:30:00Z")),
            ("attributeFQNs", json!([])),
            ("extra", json!(1)),
        ] {
            let r = reason(&entry_with(|e| e[key] = value.clone()));
            assert!(r.contains("unknown field"), "{key}: {r}");
        }
        for key in ["contentID", "version", "payloadHash", "payloadSize"] {
            let r = reason(&entry_with(|e| {
                e.as_object_mut().unwrap().remove(key);
            }));
            assert!(r.contains("missing field"), "{key}: {r}");
        }
        // Case matters: contentId is not contentID.
        let r = reason(&entry_with(|e| {
            let id = e.as_object_mut().unwrap().remove("contentID").unwrap();
            e["contentId"] = id;
        }));
        assert!(r.contains("unknown field"), "{r}");
    }

    #[test]
    fn duplicate_keys_are_refused() {
        let h = hash();
        let repeated = format!(
            r#"[{{"contentID":"x","version":1,"version":2,"payloadHash":"{h}","payloadSize":1}}]"#
        );
        assert!(reason(repeated.as_bytes()).contains("duplicate key `version`"));
        // An escaped spelling of the same key is the same key.
        let escaped = format!(
            r#"[{{"contentID":"x","contentID":"y","version":1,"payloadHash":"{h}","payloadSize":1}}]"#
        );
        assert!(reason(escaped.as_bytes()).contains("duplicate key `contentID`"));
    }

    #[test]
    fn content_ids_are_unique_and_well_formed() {
        let bytes = index(vec![
            entry("rec-1", &hash()),
            entry("rec-1", &"5a".repeat(32)),
        ]);
        assert!(reason(&bytes).contains("entries[1].contentID duplicates entries[0]"));
        for id in ["", ".", "a..b", "a/b", &"c".repeat(257)] {
            assert!(
                reason(&entry_with(|e| e["contentID"] = json!(id)))
                    .starts_with("entries[0].contentID"),
                "{id}"
            );
        }
        assert!(parse(&entry_with(|e| e["contentID"] = json!("c".repeat(256)))).is_ok());
        // Two entries may name one recording.
        let bytes = index(vec![entry("rec-1", &hash()), entry("rec-2", &hash())]);
        assert!(parse(&bytes).is_ok());
    }

    #[test]
    fn version_is_an_integer_in_range() {
        for ok in [json!(1), json!(MAX_VERSION)] {
            assert!(
                parse(&entry_with(|e| e["version"] = ok.clone())).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            json!(0),
            json!(MAX_VERSION + 1),
            json!(-1),
            json!(1.0),
            json!("1"),
            Value::Null,
        ] {
            assert!(
                reason(&entry_with(|e| e["version"] = bad.clone())).starts_with("entries[0]."),
                "{bad}"
            );
        }
    }

    #[test]
    fn payload_hash_and_size_are_checked() {
        for h in ["4F".repeat(32), "4f".repeat(31), String::new()] {
            assert!(
                reason(&entry_with(|e| e["payloadHash"] = json!(h))).contains("payloadHash"),
                "{h}"
            );
        }
        assert!(parse(&entry_with(|e| e["payloadSize"] = json!(MAX_PAYLOAD_SIZE))).is_ok());
        for bad in [json!(0), json!(MAX_PAYLOAD_SIZE + 1), json!(1.5)] {
            assert!(
                reason(&entry_with(|e| e["payloadSize"] = bad.clone())).starts_with("entries[0]."),
                "{bad}"
            );
        }
    }

    #[test]
    fn at_most_a_thousand_entries() {
        let entries = |n: usize| -> Vec<Value> {
            (0..n)
                .map(|i| entry(&format!("rec-{i:032x}"), &format!("{i:064x}")))
                .collect()
        };
        assert_eq!(parse(&index(entries(1000))).unwrap().len(), 1000);
        assert_eq!(
            reason(&index(entries(1001))),
            "must be an array of at most 1000 entries"
        );
    }

    #[test]
    fn arkavo_kit_index_vectors_agree() {
        for (name, valid, bytes) in test_support::vectors("index") {
            assert_eq!(parse(&bytes).is_ok(), valid, "{name}: {:?}", parse(&bytes));
        }
    }

    #[test]
    fn utc_timestamps_have_the_exact_form() {
        for ok in ["2026-10-16T14:30:00Z", "2024-02-29T23:59:59Z"] {
            assert!(is_utc_timestamp(ok), "{ok}");
        }
        for bad in [
            "2026-10-16T14:30:00",
            "2026-10-16T14:30:00.000Z",
            "2026-10-16T14:30:00+00:00",
            "2026-10-16 14:30:00Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-16T24:00:00Z",
            "2026-10-16T23:59:60Z",
        ] {
            assert!(!is_utc_timestamp(bad), "{bad}");
        }
    }
}
