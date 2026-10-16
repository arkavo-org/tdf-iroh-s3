use tdf_iroh_s3::validation::structure::validate_tdf_structure;

#[test]
fn test_valid_tdf_accepted() {
    let tdf_bytes = create_test_tdf();
    let result = validate_tdf_structure(&tdf_bytes);
    assert!(
        result.is_ok(),
        "Valid TDF should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn test_random_bytes_rejected() {
    let garbage = vec![0u8; 256];
    let result = validate_tdf_structure(&garbage);
    assert!(result.is_err(), "Random bytes should be rejected");
}

#[test]
fn test_empty_zip_rejected() {
    let mut buf = Vec::new();
    {
        let writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        writer.finish().unwrap();
    }
    let result = validate_tdf_structure(&buf);
    assert!(result.is_err(), "ZIP without manifest should be rejected");
}

fn create_test_tdf() -> Vec<u8> {
    use opentdf::prelude::*;

    let policy = PolicyBuilder::new()
        .id_auto()
        .dissemination(["test@example.com"])
        .build()
        .unwrap();

    Tdf::encrypt(b"test payload data")
        .kas_url("https://kas.example.com")
        .policy(policy)
        .to_bytes()
        .unwrap()
}

/// The manifest of an Arkavo FairPlay key-envelope archive (the field shape
/// Creator writes; every key and binding value is a dummy).
const FAIRPLAY_MANIFEST: &str = include_str!("fixtures/fairplay-key-envelope-manifest.json");

/// A Stored zip of `(name, bytes)` members, in order.
fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in members {
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    buf
}

/// The member layout of a Creator FairPlay archive: `manifest.json` first,
/// the HLS playlists and fMP4 media, and the key envelope in `0.payload`.
fn fairplay_layout(manifest: &str, payload_member: &str) -> Vec<u8> {
    zip_of(&[
        ("manifest.json", manifest.as_bytes()),
        ("master.m3u8", b"#EXTM3U\n"),
        ("video.m3u8", b"#EXTM3U\n"),
        ("video-init.mp4", &[0u8; 64]),
        ("video-segment0.m4s", &[1u8; 256]),
        ("audio.m3u8", b"#EXTM3U\n"),
        ("audio-init.mp4", &[2u8; 64]),
        ("audio-segment0.m4s", &[3u8; 128]),
        (payload_member, &[4u8; 44]),
    ])
}

#[test]
fn spec_layout_with_extra_members_is_accepted() {
    let manifest = validate_tdf_structure(&fairplay_layout(FAIRPLAY_MANIFEST, "0.payload"))
        .expect("spec layout archive is a TDF");
    assert_eq!(manifest.payload.url, "0.payload");
    assert_eq!(
        manifest.encryption_information.method.algorithm,
        "AES-256-GCM"
    );
}

#[test]
fn spec_layout_reads_the_payload_member_payload_url_names() {
    let manifest = FAIRPLAY_MANIFEST.replace("\"url\": \"0.payload\"", "\"url\": \"envelope.bin\"");
    assert_ne!(manifest, FAIRPLAY_MANIFEST, "fixture names 0.payload");
    let parsed = validate_tdf_structure(&fairplay_layout(&manifest, "envelope.bin"))
        .expect("payload member named by payload.url");
    assert_eq!(parsed.payload.url, "envelope.bin");

    // The named member is missing: refused, even though 0.payload exists.
    assert!(validate_tdf_structure(&fairplay_layout(&manifest, "0.payload")).is_err());
}

#[test]
fn spec_layout_without_its_payload_member_is_rejected() {
    let bytes = zip_of(&[
        ("manifest.json", FAIRPLAY_MANIFEST.as_bytes()),
        ("video-segment0.m4s", &[1u8; 16]),
    ]);
    assert!(validate_tdf_structure(&bytes).is_err());
}

#[test]
fn legacy_layout_is_still_accepted() {
    let bytes = zip_of(&[
        ("0.manifest.json", FAIRPLAY_MANIFEST.as_bytes()),
        ("0.payload", &[4u8; 44]),
    ]);
    let manifest = validate_tdf_structure(&bytes).expect("legacy layout is a TDF");
    assert_eq!(manifest.payload.url, "0.payload");
}

#[test]
fn manifest_missing_a_required_field_is_rejected() {
    let mut manifest: serde_json::Value = serde_json::from_str(FAIRPLAY_MANIFEST).unwrap();
    manifest["encryptionInformation"]
        .as_object_mut()
        .unwrap()
        .remove("keyAccess");
    let bytes = fairplay_layout(&manifest.to_string(), "0.payload");
    assert!(validate_tdf_structure(&bytes).is_err());

    let bytes = zip_of(&[("manifest.json", b"{}"), ("0.payload", b"x")]);
    assert!(validate_tdf_structure(&bytes).is_err());
}

#[test]
fn fairplay_policy_groups_by_campaign() {
    use tdf_iroh_s3::catalog::derive_artifacts;
    use tdf_iroh_s3::config::CatalogConfig;

    let bytes = fairplay_layout(FAIRPLAY_MANIFEST, "0.payload");
    let manifest = validate_tdf_structure(&bytes).unwrap();
    let config = CatalogConfig {
        enabled: true,
        ..CatalogConfig::default()
    };
    let derived = derive_artifacts(&manifest, &"ab".repeat(32), bytes.len() as u64, 0, &config)
        .expect("spec-form policy derives");
    let groups: Vec<&str> = derived.entries.iter().map(|(g, _)| g.as_str()).collect();
    assert_eq!(groups, ["12345678"]);
}
