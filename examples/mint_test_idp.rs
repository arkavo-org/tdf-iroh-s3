//! Emit test-IdP artifacts for local platform contract testing:
//! a COSE key set (CBOR) and a signed Arkavo-style CWT.
//!
//!   cargo run --example mint_test_idp -- /tmp/idp http://127.0.0.1:9999 http://localhost:8080
//!
//! Writes <dir>/cose-keys.bin and <dir>/token.txt. Deterministic key — test
//! use only.
//!
//! Optional fourth and fifth arguments set the subject (default
//! `catalog-node`) and a comma-separated `arkavo_entitlements` list, which
//! mints a creator token a local node accepts for publishing:
//!
//!   cargo run --example mint_test_idp -- /tmp/idp http://127.0.0.1:9999 arkavo \
//!       5c1f0e7a-2b8d-4c0f-9a51-3f2b6d8e4a10 \
//!       https://patreon.arkavo.com/attr/arkavo-creator/value/publish
//!
//! Serve <dir> over HTTP and point the node's `[http] cose_keys_url` at
//! `<iss>/cose-keys.bin`, with `expected_issuer = <iss>`.

use base64::Engine;
use ciborium::value::Value;
use coset::iana;
use coset::{AsCborValue, CborSerializable, CoseSign1Builder, HeaderBuilder};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).map(String::as_str).unwrap_or("/tmp/idp");
    let iss = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("http://127.0.0.1:9999");
    let aud = args
        .get(3)
        .map(String::as_str)
        .unwrap_or("http://localhost:8080");
    let sub = args.get(4).map(String::as_str).unwrap_or("catalog-node");
    let entitlements: Vec<Value> = args
        .get(5)
        .map(|list| {
            list.split(',')
                .filter(|e| !e.is_empty())
                .map(|e| Value::Text(e.into()))
                .collect()
        })
        .unwrap_or_default();

    std::fs::create_dir_all(dir).expect("create output dir");

    let sk = SigningKey::from_slice(&[0x42; 32]).expect("valid scalar");
    let vk = sk.verifying_key();

    // COSE key set: CBOR array of one EC2/P-256 key, mirroring authnz-rs's
    // /.well-known/cose-keys.
    let point = vk.to_encoded_point(false);
    let cose_key = coset::CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        point.x().unwrap().to_vec(),
        point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .key_id(b"test-kid-1".to_vec())
    .build();
    let set = Value::Array(vec![cose_key.to_cbor_value().unwrap()]);
    let mut key_set_bytes = Vec::new();
    ciborium::ser::into_writer(&set, &mut key_set_bytes).unwrap();
    std::fs::write(format!("{dir}/cose-keys.bin"), &key_set_bytes).unwrap();

    // CWT: tag 6.61 + COSE_Sign1 (untagged inner, like authnz-rs `mint`).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // cti: unique per mint, as authnz-rs issues it (the node requires one).
    let cti = blake3::hash(format!("{sub}{now}").as_bytes()).as_bytes()[..16].to_vec();
    let mut claims: Vec<(Value, Value)> = vec![
        (Value::Integer(1.into()), Value::Text(iss.into())),
        (Value::Integer(2.into()), Value::Text(sub.into())),
        (Value::Integer(3.into()), Value::Text(aud.into())),
        (
            Value::Integer(4.into()),
            Value::Integer((now + 86_400).into()),
        ),
        (Value::Integer(6.into()), Value::Integer(now.into())),
        (Value::Integer(7.into()), Value::Bytes(cti)),
        (
            Value::Text("azp".into()),
            Value::Text("catalog-node".into()),
        ),
        (
            Value::Text("roles".into()),
            Value::Array(vec![Value::Text("opentdf-admin".into())]),
        ),
    ];
    if !entitlements.is_empty() {
        claims.push((
            Value::Text("arkavo_entitlements".into()),
            Value::Array(entitlements),
        ));
    }
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&Value::Map(claims), &mut payload).unwrap();

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"test-kid-1".to_vec())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |to_sign| {
            let sig: Signature = sk.sign(to_sign);
            sig.to_bytes().to_vec()
        })
        .build();
    let inner = sign1.to_vec().unwrap();
    let mut tagged = vec![0xD8, 0x3D];
    tagged.extend_from_slice(&inner);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tagged);
    std::fs::write(format!("{dir}/token.txt"), &token).unwrap();

    println!("wrote {dir}/cose-keys.bin ({} bytes)", key_set_bytes.len());
    println!("wrote {dir}/token.txt (iss={iss}, aud={aud}, sub={sub}, azp=catalog-node)");
}
