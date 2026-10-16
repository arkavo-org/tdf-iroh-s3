//! Creator catalog documents, `arkavo.creator-catalog/1`.
//!
//! A creator's catalog is one JSON document listing their published
//! recordings (see `docs/creator-catalogs.md`). The node stores each version
//! verbatim under the BLAKE3 hash of its bytes and points the tag
//! `catalog/<sub>` at the current one, so the bytes a reader fetches are
//! exactly the bytes the creator uploaded. Validation here is strict because
//! readers apply the same rules: a document this node accepts must never be
//! one a viewer rejects.
//!
//! Pure: no I/O, so every rule is a plain unit test.

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// The only schema this node accepts.
pub const SCHEMA: &str = "arkavo.creator-catalog/1";
/// Largest document, in bytes.
pub const MAX_CATALOG_BYTES: usize = 262_144;
pub const MAX_ENTRIES: usize = 1000;
pub const MAX_OWNER_BYTES: usize = 248;
pub const MAX_CONTENT_ID_BYTES: usize = 256;
/// 2^53 - 1, the largest integer every JSON reader represents exactly.
pub const MAX_VERSION: u64 = 9_007_199_254_740_991;
/// 4 GiB − 1 (`u32::MAX`): the largest TDF a catalog may name, and the
/// default `[validation] max_blob_bytes` (`config::DEFAULT_MAX_BLOB_BYTES`).
pub const MAX_PAYLOAD_SIZE: u64 = 4_294_967_295;
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_ATTRIBUTE_FQNS: usize = 32;
pub const MAX_ATTRIBUTE_FQN_BYTES: usize = 512;

/// A parsed, validated catalog document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatorCatalog {
    pub schema: String,
    pub owner: String,
    pub entries: Vec<CreatorCatalogEntry>,
}

/// One published recording.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreatorCatalogEntry {
    #[serde(rename = "contentID")]
    pub content_id: String,
    pub version: u64,
    /// BLAKE3 hash of the TDF bytes, 64 lowercase hex characters.
    pub payload_hash: String,
    pub payload_size: u64,
    /// Optional, but never `null`: when present it is a string.
    #[serde(default, deserialize_with = "present_string")]
    pub title: Option<String>,
    pub published_at: String,
    #[serde(rename = "attributeFQNs")]
    pub attribute_fqns: Vec<String>,
}

/// `title` is optional, so an absent key is `None`; a present key must be a
/// string (`null` is rejected, not read as absent).
fn present_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

/// Parse and validate a catalog document. The error is the reason the
/// HTTP layer reports as `invalid catalog: <reason>`. The caller compares
/// `owner` with the subject it expects.
pub fn parse(bytes: &[u8]) -> Result<CreatorCatalog, String> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(format!("larger than {MAX_CATALOG_BYTES} bytes"));
    }
    std::str::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())?;
    // serde_json keeps the last of two equal keys without complaint, so a
    // separate pass rejects them before the typed parse.
    serde_json::from_slice::<NoDuplicateKeys>(bytes).map_err(|e| e.to_string())?;
    let doc: CreatorCatalog = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    validate(&doc)?;
    Ok(doc)
}

fn validate(doc: &CreatorCatalog) -> Result<(), String> {
    if doc.schema != SCHEMA {
        return Err(format!("schema must be \"{SCHEMA}\""));
    }
    if !valid_identifier(&doc.owner, MAX_OWNER_BYTES) {
        return Err(format!(
            "owner must be 1-{MAX_OWNER_BYTES} bytes of [A-Za-z0-9:._@-] without \"..\""
        ));
    }
    if doc.entries.len() > MAX_ENTRIES {
        return Err(format!("entries must hold at most {MAX_ENTRIES} entries"));
    }
    let mut content_ids: HashMap<&str, usize> = HashMap::with_capacity(doc.entries.len());
    for (i, entry) in doc.entries.iter().enumerate() {
        validate_entry(entry).map_err(|reason| format!("entries[{i}].{reason}"))?;
        if let Some(first) = content_ids.insert(entry.content_id.as_str(), i) {
            return Err(format!(
                "entries[{i}].contentID duplicates entries[{first}].contentID"
            ));
        }
    }
    Ok(())
}

fn validate_entry(e: &CreatorCatalogEntry) -> Result<(), String> {
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
    if let Some(title) = &e.title
        && !(1..=MAX_TITLE_BYTES).contains(&title.len())
    {
        return Err(format!("title must be 1-{MAX_TITLE_BYTES} bytes"));
    }
    if !is_utc_timestamp(&e.published_at) {
        return Err(
            "publishedAt must be RFC 3339 UTC in the form YYYY-MM-DDTHH:MM:SSZ".to_string(),
        );
    }
    if e.attribute_fqns.len() > MAX_ATTRIBUTE_FQNS {
        return Err(format!(
            "attributeFQNs must hold at most {MAX_ATTRIBUTE_FQNS} URLs"
        ));
    }
    for (j, fqn) in e.attribute_fqns.iter().enumerate() {
        if !is_https_url(fqn) {
            return Err(format!(
                "attributeFQNs[{j}] must be an https:// URL of at most {MAX_ATTRIBUTE_FQN_BYTES} bytes"
            ));
        }
    }
    Ok(())
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

/// An `https://` URL of at most 512 bytes with a host, in visible ASCII.
///
/// The URL must parse (WHATWG rules, as browsers and Foundation read it)
/// with scheme `https` and a non-empty host. The literal `https://`
/// followed by something other than `/` is required as well, because the
/// parser repairs `https:///a` into host `a`, which a strict reader refuses.
fn is_https_url(s: &str) -> bool {
    s.len() <= MAX_ATTRIBUTE_FQN_BYTES
        && s.bytes().all(|b| b.is_ascii_graphic())
        && s.strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && url::Url::parse(s)
            .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()))
}

/// Deserializes any JSON value, failing on an object that repeats a key.
struct NoDuplicateKeys;

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
    /// A valid entry for `hash`, as a JSON value.
    pub fn entry(content_id: &str, hash: &str) -> serde_json::Value {
        serde_json::json!({
            "contentID": content_id,
            "version": 1,
            "payloadHash": hash,
            "payloadSize": 7342067,
            "title": "Studio session",
            "publishedAt": "2026-10-16T14:30:00Z",
            "attributeFQNs": ["https://patreon.arkavo.com/attr/campaign/value/12345678"],
        })
    }

    /// A valid catalog for `owner` listing `entries`, serialized.
    pub fn catalog(owner: &str, entries: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": super::SCHEMA,
            "owner": owner,
            "entries": entries,
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{catalog, entry};
    use super::*;
    use serde_json::{Value, json};

    const OWNER: &str = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";

    fn hash() -> String {
        "4f".repeat(32)
    }

    fn doc_with(f: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut doc: Value =
            serde_json::from_slice(&catalog(OWNER, vec![entry("rec-1", &hash())])).unwrap();
        f(&mut doc);
        serde_json::to_vec(&doc).unwrap()
    }

    fn entry_with(f: impl FnOnce(&mut Value)) -> Vec<u8> {
        doc_with(|d| f(&mut d["entries"][0]))
    }

    fn reason(bytes: &[u8]) -> String {
        parse(bytes).expect_err("document should be refused")
    }

    #[test]
    fn the_contract_example_is_valid() {
        let doc = parse(
            br#"{
  "schema": "arkavo.creator-catalog/1",
  "owner": "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10",
  "entries": [
    {
      "contentID": "rec-2b9c4f1e0d8a4c7f",
      "version": 2,
      "payloadHash": "4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a4f8a",
      "payloadSize": 7342067,
      "title": "Studio session",
      "publishedAt": "2026-10-16T14:30:00Z",
      "attributeFQNs": ["https://patreon.arkavo.com/attr/campaign/value/12345678"]
    }
  ]
}"#,
        )
        .unwrap();
        assert_eq!(doc.owner, OWNER);
        assert_eq!(doc.entries[0].content_id, "rec-2b9c4f1e0d8a4c7f");
        assert_eq!(doc.entries[0].version, 2);
        assert_eq!(doc.entries[0].payload_size, 7_342_067);
        assert_eq!(doc.entries[0].title.as_deref(), Some("Studio session"));
    }

    #[test]
    fn an_empty_catalog_is_valid() {
        assert!(parse(&catalog(OWNER, vec![])).unwrap().entries.is_empty());
    }

    #[test]
    fn title_is_optional_but_never_null() {
        let doc = parse(&entry_with(|e| {
            e.as_object_mut().unwrap().remove("title");
        }))
        .unwrap();
        assert!(doc.entries[0].title.is_none());
        assert!(reason(&entry_with(|e| e["title"] = Value::Null)).contains("null"));
        assert!(reason(&entry_with(|e| e["title"] = json!(""))).contains("title"));
        assert!(parse(&entry_with(|e| e["title"] = json!("é".repeat(256)))).is_ok());
        assert!(reason(&entry_with(|e| e["title"] = json!("x".repeat(513)))).contains("title"));
    }

    #[test]
    fn schema_must_match_exactly() {
        for schema in [
            json!("arkavo.creator-catalog/2"),
            json!("Arkavo.creator-catalog/1"),
            json!(1),
        ] {
            assert!(parse(&doc_with(|d| d["schema"] = schema.clone())).is_err());
        }
    }

    #[test]
    fn owner_rules() {
        for owner in [
            "arkavo:abc",
            "user@example.com",
            "a.b_c-d",
            &"o".repeat(248),
        ] {
            assert!(
                parse(&doc_with(|d| d["owner"] = json!(owner))).is_ok(),
                "{owner}"
            );
        }
        for owner in ["", "a..b", "a/b", "a b", "ü", &"o".repeat(249)] {
            assert!(
                reason(&doc_with(|d| d["owner"] = json!(owner))).starts_with("owner"),
                "{owner}"
            );
        }
    }

    #[test]
    fn unknown_keys_are_refused_everywhere() {
        assert!(reason(&doc_with(|d| d["extra"] = json!(1))).contains("unknown field"));
        assert!(reason(&entry_with(|e| e["extra"] = json!(1))).contains("unknown field"));
        // Case matters: contentId is not contentID.
        let r = reason(&entry_with(|e| {
            let id = e.as_object_mut().unwrap().remove("contentID").unwrap();
            e["contentId"] = id;
        }));
        assert!(r.contains("unknown field"), "{r}");
    }

    #[test]
    fn missing_required_keys_are_refused() {
        for key in [
            "contentID",
            "version",
            "payloadHash",
            "payloadSize",
            "publishedAt",
            "attributeFQNs",
        ] {
            let r = reason(&entry_with(|e| {
                e.as_object_mut().unwrap().remove(key);
            }));
            assert!(r.contains("missing field"), "{key}: {r}");
        }
        for key in ["schema", "owner", "entries"] {
            let r = reason(&doc_with(|d| {
                d.as_object_mut().unwrap().remove(key);
            }));
            assert!(r.contains("missing field"), "{key}: {r}");
        }
    }

    #[test]
    fn duplicate_keys_are_refused_at_every_level() {
        let top = br#"{"schema":"arkavo.creator-catalog/1","owner":"a","owner":"a","entries":[]}"#;
        assert!(reason(top).contains("duplicate key `owner`"));

        let h = hash();
        let nested = format!(
            r#"{{"schema":"arkavo.creator-catalog/1","owner":"a","entries":[{{"contentID":"x","version":1,"version":2,"payloadHash":"{h}","payloadSize":1,"publishedAt":"2026-10-16T14:30:00Z","attributeFQNs":[]}}]}}"#
        );
        assert!(reason(nested.as_bytes()).contains("duplicate key `version`"));

        // An escaped spelling of the same key is the same key: `\u006fwner`
        // is `owner`, at the top level and in an entry.
        let escaped =
            br#"{"schema":"arkavo.creator-catalog/1","owner":"a","\u006fwner":"b","entries":[]}"#;
        assert!(reason(escaped).contains("duplicate key `owner`"));
        let escaped_nested = format!(
            r#"{{"schema":"arkavo.creator-catalog/1","owner":"a","entries":[{{"contentID":"x","\u0063ontentID":"y","version":1,"payloadHash":"{h}","payloadSize":1,"publishedAt":"2026-10-16T14:30:00Z","attributeFQNs":[]}}]}}"#
        );
        assert!(reason(escaped_nested.as_bytes()).contains("duplicate key `contentID`"));
    }

    #[test]
    fn content_ids_are_unique_and_well_formed() {
        let bytes = catalog(
            OWNER,
            vec![entry("rec-1", &hash()), entry("rec-1", &hash())],
        );
        assert!(reason(&bytes).contains("entries[1].contentID duplicates entries[0]"));
        for id in ["", "a..b", "a/b", &"c".repeat(257)] {
            assert!(
                reason(&entry_with(|e| e["contentID"] = json!(id))).contains("contentID"),
                "{id}"
            );
        }
        assert!(parse(&entry_with(|e| e["contentID"] = json!("c".repeat(256)))).is_ok());
    }

    #[test]
    fn version_is_an_integer_in_range() {
        for v in [json!(1), json!(9_007_199_254_740_991u64)] {
            assert!(
                parse(&entry_with(|e| e["version"] = v.clone())).is_ok(),
                "{v}"
            );
        }
        for v in [
            json!(0),
            json!(-1),
            json!(9_007_199_254_740_992u64),
            json!(1.0),
            json!(1.5),
            json!("1"),
            Value::Null,
        ] {
            assert!(
                parse(&entry_with(|e| e["version"] = v.clone())).is_err(),
                "{v}"
            );
        }
        // An exponent is a float to JSON readers: refused.
        let h = hash();
        let exp = format!(
            r#"{{"schema":"arkavo.creator-catalog/1","owner":"a","entries":[{{"contentID":"x","version":1e0,"payloadHash":"{h}","payloadSize":1,"publishedAt":"2026-10-16T14:30:00Z","attributeFQNs":[]}}]}}"#
        );
        assert!(parse(exp.as_bytes()).is_err());
    }

    #[test]
    fn payload_hash_is_lowercase_hex() {
        for h in [
            "4F".repeat(32),
            "4f".repeat(31),
            "zz".repeat(32),
            String::new(),
        ] {
            assert!(
                reason(&entry_with(|e| e["payloadHash"] = json!(h))).contains("payloadHash"),
                "{h}"
            );
        }
    }

    #[test]
    fn payload_size_is_in_range() {
        assert!(parse(&entry_with(|e| e["payloadSize"] = json!(4_294_967_295u64))).is_ok());
        assert!(
            reason(&entry_with(|e| e["payloadSize"] = json!(4_294_967_296u64)))
                .contains("payloadSize")
        );
        assert!(reason(&entry_with(|e| e["contentID"] = json!("."))).contains("contentID"));
        assert!(parse(&entry_with(|e| e["payloadSize"] = json!(1))).is_ok());
        for v in [json!(0), json!(4_294_967_297u64), json!(-5), json!(2.5)] {
            assert!(
                parse(&entry_with(|e| e["payloadSize"] = v.clone())).is_err(),
                "{v}"
            );
        }
    }

    #[test]
    fn published_at_has_the_exact_form() {
        for ok in [
            "2026-10-16T14:30:00Z",
            "2024-02-29T23:59:59Z",
            "2000-02-29T00:00:00Z",
            "1999-12-31T00:00:00Z",
        ] {
            assert!(is_utc_timestamp(ok), "{ok}");
        }
        for bad in [
            "2026-10-16T14:30:00",
            "2026-10-16T14:30:00z",
            "2026-10-16t14:30:00Z",
            "2026-10-16 14:30:00Z",
            "2026-10-16T14:30:00.000Z",
            "2026-10-16T14:30:00+00:00",
            "2026-10-16T14:30Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-10-00T00:00:00Z",
            "2026-10-16T24:00:00Z",
            "2026-10-16T23:60:00Z",
            "2026-12-31T23:59:60Z",
            "+026-10-16T14:30:00Z",
            "２026-10-16T14:30:00Z",
        ] {
            assert!(!is_utc_timestamp(bad), "{bad}");
        }
        assert!(
            reason(&entry_with(
                |e| e["publishedAt"] = json!("2026-10-16T14:30:00+00:00")
            ))
            .contains("publishedAt")
        );
    }

    #[test]
    fn attribute_fqns_are_https_urls() {
        assert!(parse(&entry_with(|e| e["attributeFQNs"] = json!([]))).is_ok());
        let max = format!("https://a.example/{}", "v".repeat(512 - 18));
        assert_eq!(max.len(), 512);
        assert!(parse(&entry_with(|e| e["attributeFQNs"] = json!([max]))).is_ok());
        let fqns: Vec<String> = (0..32).map(|i| format!("https://a.example/{i}")).collect();
        assert!(parse(&entry_with(|e| e["attributeFQNs"] = json!(fqns))).is_ok());
        for good in [
            "https://a.example:8443/attr/x/value/y",
            "https://[2001:db8::1]/attr/x",
            "https://192.0.2.7/attr/x",
            "https://user@a.example/attr/x",
        ] {
            assert!(
                parse(&entry_with(|e| e["attributeFQNs"] = json!([good]))).is_ok(),
                "{good}"
            );
        }

        let fqns: Vec<String> = (0..33).map(|i| format!("https://a.example/{i}")).collect();
        assert!(reason(&entry_with(|e| e["attributeFQNs"] = json!(fqns))).contains("at most 32"));
        for bad in [
            "http://a.example/attr/x".to_string(),
            "HTTPS://a.example/attr/x".to_string(),
            "https://".to_string(),
            "https:///path".to_string(),
            // No host: the parser refuses these, a prefix check alone did not.
            "https://?x".to_string(),
            "https://#fragment".to_string(),
            "https://:443/attr".to_string(),
            "https://user@/attr".to_string(),
            "https://a.example:99999/attr".to_string(),
            "https://exa%00mple/attr".to_string(),
            "https://a.example/with space".to_string(),
            format!("https://a.example/{}", "v".repeat(512 - 17)),
            "ftp://a.example".to_string(),
        ] {
            assert!(
                reason(&entry_with(|e| e["attributeFQNs"] = json!([bad.clone()])))
                    .contains("attributeFQNs[0]"),
                "{bad}"
            );
        }
        assert!(
            parse(&entry_with(
                |e| e["attributeFQNs"] = json!("https://a.example")
            ))
            .is_err()
        );
    }

    #[test]
    fn entry_count_is_bounded() {
        let entries = |n: usize| -> Vec<Value> {
            (0..n)
                .map(|i| {
                    json!({
                        "contentID": format!("r{i}"),
                        "version": 1,
                        "payloadHash": "4f".repeat(32),
                        "payloadSize": 1,
                        "publishedAt": "2026-10-16T14:30:00Z",
                        "attributeFQNs": [],
                    })
                })
                .collect()
        };
        let bytes = catalog("a", entries(1000));
        assert!(bytes.len() <= MAX_CATALOG_BYTES, "{}", bytes.len());
        assert_eq!(parse(&bytes).unwrap().entries.len(), 1000);
        let bytes = catalog("a", entries(1001));
        assert!(bytes.len() <= MAX_CATALOG_BYTES, "{}", bytes.len());
        assert!(reason(&bytes).contains("at most 1000"));
    }

    #[test]
    fn non_documents_are_refused() {
        for bad in [
            &b""[..],
            b"null",
            b"[]",
            b"\"catalog\"",
            b"{",
            b"\xEF\xBB\xBF{}",
            b"{\"schema\":\"\xff\"}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(reason(b"{\"a\":\"\xff\"}"), "not UTF-8");
        // Trailing content after the document.
        let mut bytes = catalog(OWNER, vec![]);
        bytes.extend_from_slice(b" {}");
        assert!(parse(&bytes).is_err());
        // Trailing whitespace is still JSON.
        let mut bytes = catalog(OWNER, vec![]);
        bytes.extend_from_slice(b" \n");
        assert!(parse(&bytes).is_ok());
    }

    #[test]
    fn size_limit_is_enforced() {
        let mut bytes = catalog(OWNER, vec![]);
        bytes.resize(MAX_CATALOG_BYTES, b' ');
        assert!(parse(&bytes).is_ok());
        bytes.push(b' ');
        assert!(reason(&bytes).contains("larger than"));
    }
}
