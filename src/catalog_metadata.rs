//! A catalog `/2`'s TDFs, checked on their clear manifests
//! (tdf-iroh-s3#39): the envelope that holds the catalog document, and the
//! recordings it lists.
//!
//! The node never decrypts. The envelope is the ZTDF whose payload is the
//! catalog document. Its `payload.mimeType` is [`CATALOG_MIME_TYPE`] and its
//! policy names exactly one attribute: the creator's Patreon campaign, or for
//! a creator without one their own creator attribute. Every entry's
//! recording carries that attribute (read from the manifest ingest stored
//! under `manifests/<hash>`), so a viewer who can open an entry can open the
//! catalog.
//!
//! Each entry's metadata TDF travels inside the envelope, so the node never
//! sees it: Creator checks it against its recording before publishing.
//!
//! Pure: no I/O.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use opentdf::{AttributePolicy, AttributeValue, LogicalOperator};
use serde_json::{Map, Value};

/// A metadata TDF's `payload.mimeType`, which Creator checks; the node only
/// refuses it as an envelope's.
pub const CATALOG_ENTRY_MIME_TYPE: &str = "application/vnd.arkavo.catalog-entry+json";

/// The envelope's `payload.mimeType`.
pub const CATALOG_MIME_TYPE: &str = "application/vnd.arkavo.creator-catalog+json";

/// A campaign attribute value: this prefix, then the campaign id, one or
/// more digits: the platform's Patreon entity resolution grants no other.
pub const CAMPAIGN_FQN_PREFIX: &str = "https://patreon.arkavo.com/attr/campaign/value/";

/// A creator attribute value: this prefix, then the creator's `sub`, a bare
/// lowercase account UUID: identity grants `creator/value/<account id>`,
/// never an `arkavo:`-prefixed one.
pub const CREATOR_FQN_PREFIX: &str = "https://arkavo.net/attr/creator/value/";

/// The parts of a manifest the checks read.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestPolicy {
    /// `payload.mimeType`.
    mime_type: Option<String>,
    /// The decoded policy object.
    policy: Map<String, Value>,
}

/// Why an envelope is not a catalog of its subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeRefusal {
    /// `payload.mimeType` isn't [`CATALOG_MIME_TYPE`].
    NotCatalog,
    /// The policy's `uuid` isn't a non-empty string.
    NoPolicyId,
    /// Any other key than `uuid` and `body`, a `dissem` list, or anything
    /// but exactly one campaign or the subject's creator attribute.
    Policy,
}

/// Read a manifest (`manifests/<hash>`, or an envelope's). `None` when it is
/// not a manifest with a base64 JSON-object policy and a `keyAccess` array
/// whose objects each name a KAS `url`.
pub fn read_manifest(bytes: &[u8]) -> Option<ManifestPolicy> {
    let manifest: Value = serde_json::from_slice(bytes).ok()?;
    let mime_type = manifest
        .get("payload")
        .and_then(|p| p.get("mimeType"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let info = manifest.get("encryptionInformation")?;
    let policy = STANDARD.decode(info.get("policy")?.as_str()?).ok()?;
    let Value::Object(policy) = serde_json::from_slice(&policy).ok()? else {
        return None;
    };
    let key_access = info.get("keyAccess")?.as_array()?;
    if !key_access
        .iter()
        .all(|k| k.get("url").and_then(Value::as_str).is_some())
    {
        return None;
    }
    Some(ManifestPolicy { mime_type, policy })
}

impl ManifestPolicy {
    /// The policy's `uuid`, when it is a non-empty string.
    pub fn policy_id(&self) -> Option<&str> {
        self.policy
            .get("uuid")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
    }

    /// Whether the policy names `fqn`, in the spec form or opentdf-rs's
    /// structured form ([`extract_attribute_fqns`]).
    pub fn has_attribute(&self, fqn: &str) -> bool {
        serde_json::to_string(&self.policy)
            .ok()
            .and_then(|json| extract_attribute_fqns(&json).ok())
            .is_some_and(|fqns| fqns.iter().any(|f| f == fqn))
    }
}

/// Extract every attribute-value FQN referenced by a TDF policy
/// (`https://<namespace>/attr/<name>/value/<value>`; value-less conditions
/// such as `Present` yield `https://<namespace>/attr/<name>`). The result
/// is deduplicated and sorted for deterministic index entries.
///
/// `body.dataAttributes` entries come in two shapes, and a policy may mix
/// them:
/// - the OpenTDF spec form, `{"attribute": "<FQN>"}`, which the Creator app
///   and the other SDKs write;
/// - the structured condition form opentdf-rs writes
///   (`{"attribute": {"namespace", "name"}, "operator", "value"}`, or a
///   logical operator over such conditions).
///
/// Keys outside `body` (for example Arkavo's `arkavo:*` extensions) are
/// ignored.
pub fn extract_attribute_fqns(policy_json: &str) -> Result<Vec<String>> {
    let policy: serde_json::Value =
        serde_json::from_str(policy_json).context("Failed to parse TDF policy JSON")?;
    let body = policy.get("body").context("TDF policy has no body")?;
    let attributes = match body.get("dataAttributes") {
        None | Some(serde_json::Value::Null) => &[][..],
        Some(serde_json::Value::Array(a)) => a.as_slice(),
        Some(_) => anyhow::bail!("TDF policy dataAttributes is not an array"),
    };

    let mut fqns = Vec::new();
    for attribute in attributes {
        if let Some(fqn) = attribute.get("attribute").and_then(|a| a.as_str()) {
            fqns.push(fqn.to_string());
            continue;
        }
        let attr_policy: AttributePolicy = serde_json::from_value(attribute.clone())
            .context("Failed to parse TDF policy data attribute")?;
        collect_fqns(&attr_policy, &mut fqns);
    }
    fqns.sort();
    fqns.dedup();
    Ok(fqns)
}

fn collect_fqns(policy: &AttributePolicy, out: &mut Vec<String>) {
    match policy {
        AttributePolicy::Condition(cond) => {
            let base = format!(
                "https://{}/attr/{}",
                cond.attribute.namespace, cond.attribute.name
            );
            match &cond.value {
                Some(AttributeValue::String(s)) => out.push(format!("{base}/value/{s}")),
                Some(AttributeValue::StringArray(values)) => {
                    for s in values {
                        out.push(format!("{base}/value/{s}"));
                    }
                }
                Some(AttributeValue::Number(n)) => out.push(format!("{base}/value/{n}")),
                Some(AttributeValue::Boolean(b)) => out.push(format!("{base}/value/{b}")),
                Some(AttributeValue::DateTime(dt)) => {
                    out.push(format!("{base}/value/{}", dt.to_rfc3339()));
                }
                Some(AttributeValue::NumberArray(values)) => {
                    for n in values {
                        out.push(format!("{base}/value/{n}"));
                    }
                }
                None => out.push(base),
            }
        }
        AttributePolicy::Logical(op) => match op {
            LogicalOperator::AND { conditions } | LogicalOperator::OR { conditions } => {
                for c in conditions {
                    collect_fqns(c, out);
                }
            }
            LogicalOperator::NOT { condition } => collect_fqns(condition, out),
        },
    }
}

/// The envelope's one attribute, when `envelope` (its manifest) is a catalog
/// of `sub`: type [`CATALOG_MIME_TYPE`], a policy of only `uuid` (non-empty)
/// and `body`, no `dissem`, and `body.dataAttributes` exactly one element
/// whose `attribute` is a campaign value or `sub`'s creator value, byte for
/// byte. Either way an attribute the platform grants someone: a value it
/// never grants would make a catalog nobody can open.
pub fn check_envelope(envelope: &ManifestPolicy, sub: &str) -> Result<String, EnvelopeRefusal> {
    if envelope.mime_type.as_deref() != Some(CATALOG_MIME_TYPE) {
        return Err(EnvelopeRefusal::NotCatalog);
    }
    let mut keys: Vec<&str> = envelope.policy.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["body", "uuid"] {
        return Err(EnvelopeRefusal::Policy);
    }
    if envelope.policy_id().is_none() {
        return Err(EnvelopeRefusal::NoPolicyId);
    }
    if !list(&envelope.policy, "dissem").is_some_and(<[Value]>::is_empty) {
        return Err(EnvelopeRefusal::Policy);
    }
    let fqn = match list(&envelope.policy, "dataAttributes") {
        Some([one]) => one.get("attribute").and_then(Value::as_str),
        _ => None,
    };
    let campaign = |f: &str| {
        f.strip_prefix(CAMPAIGN_FQN_PREFIX)
            .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
    };
    let creator = |f: &str| f.strip_prefix(CREATOR_FQN_PREFIX) == Some(sub) && is_lower_uuid(sub);
    match fqn {
        Some(f) if campaign(f) || creator(f) => Ok(f.to_string()),
        _ => Err(EnvelopeRefusal::Policy),
    }
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` in lowercase hex.
fn is_lower_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// `body.<key>` as a list: absent and `null` are empty; anything else that
/// is not an array is `None`, which matches nothing.
fn list<'a>(policy: &'a Map<String, Value>, key: &str) -> Option<&'a [Value]> {
    match policy.get("body").and_then(|b| b.get(key)) {
        None | Some(Value::Null) => Some(&[]),
        Some(Value::Array(a)) => Some(a),
        Some(_) => None,
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use serde_json::json;

    /// A recording's stored manifest with `policy` and one key access object
    /// per KAS.
    pub fn manifest(policy: Value, kas: &[&str]) -> Vec<u8> {
        manifest_of_type(policy, kas, "application/octet-stream")
    }

    /// A catalog envelope's manifest.
    pub fn envelope_manifest(policy: Value, kas: &[&str]) -> Vec<u8> {
        manifest_of_type(policy, kas, CATALOG_MIME_TYPE)
    }

    /// A catalog envelope ZTDF: `manifest.json` with `policy`, type
    /// `mime_type` and one key access object at [`KAS`], and a stored
    /// `0.payload` of `payload` (standing in for the encrypted document).
    pub fn envelope_tdf(policy: Value, mime_type: &str, payload: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut m = opentdf::TdfManifest::new("0.payload".into(), KAS.into());
        m.payload.mime_type = Some(mime_type.into());
        m.encryption_information.policy = STANDARD.encode(serde_json::to_vec(&policy).unwrap());
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let stored = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            w.start_file("manifest.json", stored).unwrap();
            w.write_all(m.to_json().unwrap().as_bytes()).unwrap();
            w.start_file("0.payload", stored).unwrap();
            w.write_all(payload).unwrap();
            w.finish().unwrap();
        }
        buf
    }

    /// An envelope policy naming only `fqn`.
    pub fn envelope_policy(fqn: &str) -> Value {
        json!({
            "uuid": "0b0e6f7c-0000-4000-8000-0000000000e0",
            "body": { "dataAttributes": [{ "attribute": fqn }], "dissem": [] },
        })
    }

    pub fn manifest_of_type(policy: Value, kas: &[&str], mime_type: &str) -> Vec<u8> {
        let key_access: Vec<Value> = kas
            .iter()
            .map(|url| {
                json!({
                    "type": "wrapped", "url": url, "protocol": "kas",
                    "wrappedKey": "AAAA", "policyBinding": { "alg": "HS256", "hash": "AAAA" },
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "payload": { "type": "reference", "url": "0.payload", "protocol": "zip",
                         "isEncrypted": true, "mimeType": mime_type },
            "encryptionInformation": {
                "type": "split",
                "policy": STANDARD.encode(serde_json::to_vec(&policy).unwrap()),
                "keyAccess": key_access,
                "method": { "algorithm": "AES-256-GCM", "isStreamable": true, "iv": "" },
                "integrityInformation": {},
            },
        }))
        .unwrap()
    }

    pub const KAS: &str = "https://platform.arkavo.net/kas";
    pub const CAMPAIGN: &str = "https://patreon.arkavo.com/attr/campaign/value/12345678";

    /// A recording's policy, with its clear `arkavo:` extensions.
    pub fn recording_policy() -> Value {
        json!({
            "uuid": "0b0e6f7c-0000-4000-8000-000000000001",
            "body": { "dataAttributes": [{ "attribute": CAMPAIGN }], "dissem": [] },
            "arkavo:classification": "general",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use serde_json::json;

    fn policy_json(fqns: &[&str]) -> String {
        use opentdf::prelude::*;
        let mut builder = PolicyBuilder::new().id_auto().dissemination(["t@test"]);
        for fqn in fqns {
            builder = builder.attribute_fqn(fqn).unwrap();
        }
        serde_json::to_string(&builder.build().unwrap()).unwrap()
    }

    #[test]
    fn extracts_fqns_from_policy() {
        let json = policy_json(&[
            "https://patreon.arkavo.com/attr/campaign/value/12345678",
            "https://patreon.arkavo.com/attr/tier/value/gold",
        ]);
        let fqns = extract_attribute_fqns(&json).unwrap();
        assert!(
            fqns.contains(&"https://patreon.arkavo.com/attr/campaign/value/12345678".to_string()),
            "campaign FQN missing: {fqns:?}"
        );
        assert!(
            fqns.contains(&"https://patreon.arkavo.com/attr/tier/value/gold".to_string()),
            "tier FQN missing: {fqns:?}"
        );
    }

    #[test]
    fn fqns_are_deduped_and_sorted() {
        let json = policy_json(&[
            "https://b.example/attr/x/value/1",
            "https://a.example/attr/x/value/1",
            "https://a.example/attr/x/value/1",
        ]);
        let fqns = extract_attribute_fqns(&json).unwrap();
        let mut sorted = fqns.clone();
        sorted.sort();
        assert_eq!(fqns, sorted);
        assert_eq!(
            fqns.iter()
                .filter(|f| f.as_str() == "https://a.example/attr/x/value/1")
                .count(),
            1
        );
    }

    #[test]
    fn extracts_fqns_from_spec_form_policy() {
        // The shape Creator writes: `{"attribute": "<FQN>"}` entries, plus
        // `arkavo:*` keys outside `body`.
        let json = r#"{
            "arkavo:fpsProfile": "urn:arkavo:fairplay:key-envelope:1",
            "body": {
                "dataAttributes": [
                    {"attribute": "https://patreon.arkavo.com/attr/campaign/value/12345678"},
                    {"attribute": "https://patreon.arkavo.com/attr/campaign-tier/value/12345678_free"}
                ],
                "dissem": []
            },
            "uuid": "00000000-0000-4000-8000-000000000001"
        }"#;
        assert_eq!(
            extract_attribute_fqns(json).unwrap(),
            vec![
                "https://patreon.arkavo.com/attr/campaign-tier/value/12345678_free".to_string(),
                "https://patreon.arkavo.com/attr/campaign/value/12345678".to_string(),
            ]
        );
    }

    #[test]
    fn empty_or_null_data_attributes_yield_nothing() {
        for json in [
            r#"{"body":{"dataAttributes":null,"dissem":null},"uuid":"u"}"#,
            r#"{"body":{"dissem":[]},"uuid":"u"}"#,
        ] {
            assert!(extract_attribute_fqns(json).unwrap().is_empty(), "{json}");
        }
        assert!(extract_attribute_fqns(r#"{"uuid":"u"}"#).is_err());
        assert!(extract_attribute_fqns(r#"{"body":{"dataAttributes":{}}}"#).is_err());
    }

    fn read(policy: Value, kas: &[&str]) -> ManifestPolicy {
        read_manifest(&manifest(policy, kas)).expect("readable manifest")
    }

    #[test]
    fn unreadable_manifests_are_none() {
        assert!(read_manifest(b"not json").is_none());
        assert!(read_manifest(b"{}").is_none());
        let not_base64 = json!({ "encryptionInformation": { "policy": "%%", "keyAccess": [] } });
        assert!(read_manifest(&serde_json::to_vec(&not_base64).unwrap()).is_none());
        let not_object = json!({ "encryptionInformation": {
            "policy": STANDARD.encode("[1]"), "keyAccess": [] } });
        assert!(read_manifest(&serde_json::to_vec(&not_object).unwrap()).is_none());
        let no_url = json!({ "encryptionInformation": {
            "policy": STANDARD.encode("{}"), "keyAccess": [{ "type": "wrapped" }] } });
        assert!(read_manifest(&serde_json::to_vec(&no_url).unwrap()).is_none());
    }

    fn envelope(policy: Value) -> Result<String, EnvelopeRefusal> {
        check_envelope(
            &read_manifest(&envelope_manifest(policy, &[KAS])).unwrap(),
            SUB,
        )
    }

    const SUB: &str = "5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10";

    #[test]
    fn an_envelope_names_one_campaign_or_its_creator() {
        let creator = format!("{CREATOR_FQN_PREFIX}{SUB}");
        for fqn in [
            CAMPAIGN,
            "https://patreon.arkavo.com/attr/campaign/value/7",
            creator.as_str(),
        ] {
            assert_eq!(envelope(envelope_policy(fqn)), Ok(fqn.to_string()), "{fqn}");
        }
        let other_creator = format!("{CREATOR_FQN_PREFIX}someone-else");
        let prefixed_creator = format!("{creator}x");
        for fqn in [
            "https://patreon.arkavo.com/attr/campaign/value/",
            "https://patreon.arkavo.com/attr/campaign/value/12/34",
            "https://patreon.arkavo.com/attr/campaign/value/12.34",
            "https://patreon.arkavo.com/attr/campaign/value/a_B-9",
            "https://patreon.arkavo.com/attr/campaign/value/12a",
            "https://patreon.arkavo.com/attr/campaign/value/-12",
            "https://patreon.arkavo.com/attr/tier/value/12345678",
            "https://PATREON.arkavo.com/attr/campaign/value/12345678",
            other_creator.as_str(),
            prefixed_creator.as_str(),
            CREATOR_FQN_PREFIX,
        ] {
            assert_eq!(
                envelope(envelope_policy(fqn)),
                Err(EnvelopeRefusal::Policy),
                "{fqn}"
            );
        }
        // A creator value names a bare lowercase account UUID, whatever the
        // subject's own spelling.
        for sub in [
            format!("arkavo:{SUB}"),
            SUB.to_uppercase(),
            "creator-1".to_string(),
        ] {
            let m = read_manifest(&envelope_manifest(
                envelope_policy(&format!("{CREATOR_FQN_PREFIX}{sub}")),
                &[KAS],
            ))
            .unwrap();
            assert_eq!(
                check_envelope(&m, &sub),
                Err(EnvelopeRefusal::Policy),
                "{sub}"
            );
        }
    }

    #[test]
    fn an_envelope_policy_is_exactly_one_attribute() {
        let two = json!({ "uuid": "u", "body": { "dataAttributes": [
            { "attribute": CAMPAIGN },
            { "attribute": format!("{CREATOR_FQN_PREFIX}{SUB}") } ] } });
        let none = json!({ "uuid": "u", "body": { "dataAttributes": [] } });
        let absent = json!({ "uuid": "u", "body": {} });
        // opentdf-rs's structured form names the attribute by namespace and
        // name: an envelope's element must be the spec form.
        let structured = json!({ "uuid": "u", "body": { "dataAttributes": [
            { "attribute": { "namespace": "patreon.arkavo.com", "name": "campaign" },
              "operator": "equals", "value": "12345678" } ] } });
        let dissem = json!({ "uuid": "u", "body": {
            "dataAttributes": [{ "attribute": CAMPAIGN }], "dissem": ["a@example.com"] } });
        let mut classified = envelope_policy(CAMPAIGN);
        classified["arkavo:classification"] = json!("general");
        for policy in [two, none, absent, structured, dissem, classified] {
            assert_eq!(
                envelope(policy.clone()),
                Err(EnvelopeRefusal::Policy),
                "{policy}"
            );
        }
        // `dissem` may be absent.
        let no_dissem =
            json!({ "uuid": "u", "body": { "dataAttributes": [{ "attribute": CAMPAIGN }] } });
        assert!(envelope(no_dissem).is_ok());
        for id in [json!(""), json!(1), Value::Null] {
            let mut p = envelope_policy(CAMPAIGN);
            p["uuid"] = id.clone();
            assert_eq!(envelope(p), Err(EnvelopeRefusal::NoPolicyId), "{id}");
        }
    }

    #[test]
    fn an_envelope_has_the_catalog_type() {
        for mime in [CATALOG_ENTRY_MIME_TYPE, "application/json", ""] {
            let m =
                read_manifest(&manifest_of_type(envelope_policy(CAMPAIGN), &[KAS], mime)).unwrap();
            assert_eq!(
                check_envelope(&m, SUB),
                Err(EnvelopeRefusal::NotCatalog),
                "{mime}"
            );
        }
    }

    #[test]
    fn a_recording_names_an_attribute_in_either_form() {
        let spec = read(recording_policy(), &[KAS]);
        assert!(spec.has_attribute(CAMPAIGN));
        assert!(!spec.has_attribute("https://patreon.arkavo.com/attr/campaign/value/1"));
        let structured = read(
            json!({ "uuid": "u", "body": { "dataAttributes": [
                { "attribute": { "namespace": "patreon.arkavo.com", "name": "campaign" },
                  "operator": "equals", "value": "12345678" } ] } }),
            &[KAS],
        );
        assert!(structured.has_attribute(CAMPAIGN));
        assert!(!read(json!({ "uuid": "u", "body": {} }), &[KAS]).has_attribute(CAMPAIGN));
    }

    #[test]
    fn a_manifest_as_ingest_stores_it_is_read() {
        // `catalog::derive_artifacts` stores `TdfManifest::to_json`.
        let mut m = opentdf::TdfManifest::new("0.payload".into(), KAS.into());
        m.payload.mime_type = Some(CATALOG_MIME_TYPE.into());
        m.encryption_information.policy =
            STANDARD.encode(serde_json::to_vec(&envelope_policy(CAMPAIGN)).unwrap());
        let read = read_manifest(m.to_json().unwrap().as_bytes()).expect("readable");
        assert_eq!(check_envelope(&read, "u"), Ok(CAMPAIGN.to_string()));
        assert!(read.has_attribute(CAMPAIGN));
    }
}
