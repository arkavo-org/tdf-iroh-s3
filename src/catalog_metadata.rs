//! A catalog `/2`'s TDFs, checked on their clear manifests
//! (tdf-iroh-s3#39): each entry's metadata TDF against its recording, and
//! the envelope that holds the catalog document.
//!
//! The node never decrypts. It compares the two clear manifests, as stored
//! at ingest under `manifests/<hash>`: the metadata TDF must carry the
//! recording's policy (`body.dataAttributes` and `body.dissem`, each as a
//! set) and the same KAS, so it opens for exactly the viewers who can play
//! the recording. Anyone holding a hash can read its manifest, so the
//! metadata policy holds only `uuid` and `body`: a top-level key such as
//! `arkavo:classification` would repeat the recording's labels in the clear.
//! Its `payload.mimeType` is [`CATALOG_ENTRY_MIME_TYPE`], which keeps it out
//! of the group index (`catalog::derive_artifacts`) though it carries the
//! recording's attributes. Its policy `uuid` is a non-empty string: a viewer
//! unwraps a catalog's metadata in one bulk rewrap, and the platform's KAS
//! drops an entry without a policy id and refuses duplicate ids.
//!
//! The envelope is the ZTDF whose payload is the catalog document. Its
//! `payload.mimeType` is [`CATALOG_MIME_TYPE`] and its policy names exactly
//! one attribute: the creator's Patreon campaign, or for a creator without
//! one their own creator attribute. Every entry's recording carries that
//! attribute, so a viewer who can open an entry can open the catalog.
//!
//! Pure: no I/O.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// A metadata TDF's `payload.mimeType`. Ingest doesn't index a blob of this
/// type under `catalog-index/`, and a `/2` entry's metadata must have it.
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

/// The parts of a stored manifest the comparison reads.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestPolicy {
    /// `payload.mimeType`.
    mime_type: Option<String>,
    /// The decoded policy object.
    policy: Map<String, Value>,
    /// `encryptionInformation.keyAccess[].url`.
    kas: BTreeSet<String>,
}

/// Why a metadata TDF does not fit its entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataRefusal {
    /// The metadata policy has a top-level key besides `uuid` and `body`.
    ExtraPolicyKeys,
    /// The metadata policy's `uuid` isn't a non-empty string.
    NoPolicyId,
    /// The metadata TDF's `payload.mimeType` isn't [`CATALOG_ENTRY_MIME_TYPE`].
    NotCatalogMetadata,
    /// The attributes, dissemination list or KAS differ from the recording's.
    PolicyMismatch,
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

/// Read a stored manifest (`manifests/<hash>`). `None` when it is not a
/// manifest with a base64 JSON-object policy and a `keyAccess` array.
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
    let kas = info
        .get("keyAccess")?
        .as_array()?
        .iter()
        .map(|k| k.get("url").and_then(Value::as_str).map(str::to_string))
        .collect::<Option<BTreeSet<_>>>()?;
    Some(ManifestPolicy {
        mime_type,
        policy,
        kas,
    })
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
    /// structured form (`catalog::extract_attribute_fqns`).
    pub fn has_attribute(&self, fqn: &str) -> bool {
        serde_json::to_string(&self.policy)
            .ok()
            .and_then(|json| crate::catalog::extract_attribute_fqns(&json).ok())
            .is_some_and(|fqns| fqns.iter().any(|f| f == fqn))
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

/// Whether `metadata` may stand for the recording `payload` in a catalog.
pub fn check(payload: &ManifestPolicy, metadata: &ManifestPolicy) -> Result<(), MetadataRefusal> {
    let mut keys: Vec<&str> = metadata.policy.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["body", "uuid"] {
        return Err(MetadataRefusal::ExtraPolicyKeys);
    }
    if metadata.policy_id().is_none() {
        return Err(MetadataRefusal::NoPolicyId);
    }
    if metadata.mime_type.as_deref() != Some(CATALOG_ENTRY_MIME_TYPE) {
        return Err(MetadataRefusal::NotCatalogMetadata);
    }
    let same = payload.kas == metadata.kas
        && same_set(
            list(&payload.policy, "dataAttributes"),
            list(&metadata.policy, "dataAttributes"),
        )
        && same_set(
            list(&payload.policy, "dissem"),
            list(&metadata.policy, "dissem"),
        );
    if same {
        Ok(())
    } else {
        Err(MetadataRefusal::PolicyMismatch)
    }
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

/// Equal as sets of whole JSON values (order and repeats ignored).
fn same_set(a: Option<&[Value]>, b: Option<&[Value]>) -> bool {
    let (Some(a), Some(b)) = (a, b) else {
        return false;
    };
    a.iter().all(|x| b.contains(x)) && b.iter().all(|x| a.contains(x))
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

    /// A metadata TDF's stored manifest.
    pub fn metadata_manifest(policy: Value, kas: &[&str]) -> Vec<u8> {
        manifest_of_type(policy, kas, CATALOG_ENTRY_MIME_TYPE)
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

    /// The matching metadata policy: its own uuid, the same body.
    pub fn metadata_policy() -> Value {
        json!({
            "uuid": "0b0e6f7c-0000-4000-8000-000000000002",
            "body": { "dataAttributes": [{ "attribute": CAMPAIGN }], "dissem": [] },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use serde_json::json;

    /// Read as a metadata manifest; a recording's type is never checked.
    fn read(policy: Value, kas: &[&str]) -> ManifestPolicy {
        read_manifest(&metadata_manifest(policy, kas)).expect("readable manifest")
    }

    fn checked(meta: Value) -> Result<(), MetadataRefusal> {
        check(&read(recording_policy(), &[KAS]), &read(meta, &[KAS]))
    }

    #[test]
    fn the_same_policy_and_kas_fit() {
        assert_eq!(checked(metadata_policy()), Ok(()));
    }

    #[test]
    fn only_uuid_and_body_are_allowed() {
        for key in ["arkavo:classification", "arkavo:components", "extra"] {
            let mut p = metadata_policy();
            p[key] = json!("x");
            assert_eq!(checked(p), Err(MetadataRefusal::ExtraPolicyKeys), "{key}");
        }
        for key in ["uuid", "body"] {
            let mut p = metadata_policy();
            p.as_object_mut().unwrap().remove(key);
            assert_eq!(checked(p), Err(MetadataRefusal::ExtraPolicyKeys), "{key}");
        }
    }

    #[test]
    fn the_policy_id_is_a_non_empty_string() {
        for id in [json!(""), json!(7), Value::Null] {
            let mut p = metadata_policy();
            p["uuid"] = id.clone();
            assert_eq!(checked(p), Err(MetadataRefusal::NoPolicyId), "{id}");
        }
    }

    #[test]
    fn metadata_must_have_the_catalog_entry_type() {
        let payload = read(recording_policy(), &[KAS]);
        for mime in ["application/octet-stream", "application/json", ""] {
            let meta = read_manifest(&manifest_of_type(metadata_policy(), &[KAS], mime)).unwrap();
            assert_eq!(
                check(&payload, &meta),
                Err(MetadataRefusal::NotCatalogMetadata),
                "{mime}"
            );
        }
        let mut untyped: Value =
            serde_json::from_slice(&metadata_manifest(metadata_policy(), &[KAS])).unwrap();
        untyped["payload"]
            .as_object_mut()
            .unwrap()
            .remove("mimeType");
        let meta = read_manifest(&serde_json::to_vec(&untyped).unwrap()).unwrap();
        assert_eq!(
            check(&payload, &meta),
            Err(MetadataRefusal::NotCatalogMetadata)
        );
        // The minimal-policy check comes first.
        let mut classified = metadata_policy();
        classified["arkavo:classification"] = json!("x");
        let meta = read_manifest(&manifest(classified, &[KAS])).unwrap();
        assert_eq!(
            check(&payload, &meta),
            Err(MetadataRefusal::ExtraPolicyKeys)
        );
    }

    #[test]
    fn attributes_compare_as_sets_of_whole_values() {
        let two = |a: &str, b: &str| json!({ "uuid": "u", "body": { "dataAttributes": [{ "attribute": a }, { "attribute": b }], "dissem": [] } });
        let other = "https://patreon.arkavo.com/attr/campaign/value/99";
        let payload = read(two(CAMPAIGN, other), &[KAS]);
        // Order and repeats don't matter.
        assert_eq!(check(&payload, &read(two(other, CAMPAIGN), &[KAS])), Ok(()));
        let repeated = json!({ "uuid": "u", "body": { "dataAttributes": [
            { "attribute": other }, { "attribute": CAMPAIGN }, { "attribute": other }] } });
        assert_eq!(check(&payload, &read(repeated, &[KAS])), Ok(()));
        // A missing, extra or different attribute does.
        for meta in [
            json!({ "uuid": "u", "body": { "dataAttributes": [{ "attribute": CAMPAIGN }] } }),
            json!({ "uuid": "u", "body": { "dataAttributes": [] } }),
            json!({ "uuid": "u", "body": {} }),
            two(CAMPAIGN, "https://patreon.arkavo.com/attr/campaign/value/7"),
            // The same FQN with another field is another value.
            json!({ "uuid": "u", "body": { "dataAttributes": [
                { "attribute": CAMPAIGN, "isDefault": true }, { "attribute": other }] } }),
            json!({ "uuid": "u", "body": { "dataAttributes": "x" } }),
        ] {
            assert_eq!(
                check(&payload, &read(meta.clone(), &[KAS])),
                Err(MetadataRefusal::PolicyMismatch),
                "{meta}"
            );
        }
    }

    #[test]
    fn an_empty_policy_matches_only_an_empty_policy() {
        let empty = json!({ "uuid": "u", "body": { "dataAttributes": [], "dissem": [] } });
        let payload = read(empty.clone(), &[KAS]);
        assert_eq!(check(&payload, &read(empty, &[KAS])), Ok(()));
        let null = json!({ "uuid": "u", "body": { "dataAttributes": null } });
        assert_eq!(check(&payload, &read(null, &[KAS])), Ok(()));
        assert_eq!(
            check(&payload, &read(metadata_policy(), &[KAS])),
            Err(MetadataRefusal::PolicyMismatch)
        );
    }

    #[test]
    fn dissem_compares_as_a_set() {
        let with = |d: Value| json!({ "uuid": "u", "body": { "dataAttributes": [], "dissem": d } });
        let payload = read(with(json!(["a@x", "b@x"])), &[KAS]);
        assert_eq!(
            check(&payload, &read(with(json!(["b@x", "a@x"])), &[KAS])),
            Ok(())
        );
        for d in [json!(["a@x"]), json!([]), json!(["a@x", "b@x", "c@x"])] {
            assert_eq!(
                check(&payload, &read(with(d.clone()), &[KAS])),
                Err(MetadataRefusal::PolicyMismatch),
                "{d}"
            );
        }
    }

    #[test]
    fn the_kas_must_be_the_same() {
        let payload = read(recording_policy(), &[KAS]);
        for kas in [
            &["https://other.example/kas"][..],
            &[KAS, "https://other.example/kas"],
            &[],
        ] {
            assert_eq!(
                check(&payload, &read(metadata_policy(), kas)),
                Err(MetadataRefusal::PolicyMismatch),
                "{kas:?}"
            );
        }
        // Two key access objects for one KAS (a split) name one KAS.
        assert_eq!(
            check(&payload, &read(metadata_policy(), &[KAS, KAS])),
            Ok(())
        );
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
        m.payload.mime_type = Some(CATALOG_ENTRY_MIME_TYPE.into());
        m.encryption_information.policy =
            STANDARD.encode(serde_json::to_vec(&metadata_policy()).unwrap());
        let read = read_manifest(m.to_json().unwrap().as_bytes()).expect("readable");
        assert_eq!(read.kas, BTreeSet::from([KAS.to_string()]));
        assert_eq!(read.mime_type.as_deref(), Some(CATALOG_ENTRY_MIME_TYPE));
        assert_eq!(check(&read, &read.clone()), Ok(()));
    }
}
