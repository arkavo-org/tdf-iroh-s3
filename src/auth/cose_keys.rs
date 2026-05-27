//! COSE_Key set fetch, parse, and in-memory cache.
//!
//! The upstream endpoint serves `application/cose-key-set+cbor` — a CBOR
//! array of [`coset::CoseKey`] entries. We parse the set and store
//! `kid -> VerifyingKey` for the only supported shape (kty = EC2, crv =
//! P-256, alg = ES256).
//!
//! A background tokio task refreshes on the configured interval; the
//! verifier may additionally request a `force_refresh` on a `kid` miss,
//! rate-limited to once per second so a flood of bogus tokens cannot
//! stampede the upstream endpoint.

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use coset::iana::EnumI64;
use coset::{CborSerializable, CoseKey, CoseKeySet, iana};
use p256::ecdsa::VerifyingKey;
use p256::elliptic_curve::sec1::EncodedPoint;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Minimum gap between two force-refresh attempts. Bounds the worst-case
/// stampede when an attacker spams unknown `kid`s.
const FORCE_REFRESH_MIN_GAP: Duration = Duration::from_secs(1);

/// COSE keys are addressed by an opaque byte string (`kid`).
pub type Kid = Vec<u8>;

pub struct CoseKeyCache {
    url: Option<String>,
    http: reqwest::Client,
    keys: ArcSwap<HashMap<Kid, VerifyingKey>>,
    /// Raw CBOR of the most recently fetched COSE_KeySet — empty `Bytes`
    /// means "no fetch has succeeded yet". Stored alongside the parsed map
    /// so the CWT verifier can hand the original bytes to `pep_check`,
    /// which iterates the array itself rather than relying on our parser.
    raw_bytes: ArcSwap<Bytes>,
    last_force_refresh: Mutex<Option<Instant>>,
}

impl CoseKeyCache {
    /// Construct a cache backed by an HTTP COSE_KeySet endpoint and spawn a
    /// background refresh task. An initial fetch is attempted
    /// synchronously; if it fails, the cache stays empty (verify calls
    /// will trigger a force_refresh on first miss) and a warning is
    /// logged. We deliberately do not fail node boot on initial fetch
    /// errors so a brief upstream outage cannot bring the node down.
    pub async fn spawn(
        url: String,
        refresh_interval: Duration,
        http: reqwest::Client,
    ) -> Result<Arc<Self>> {
        let cache = Arc::new(Self {
            url: Some(url.clone()),
            http: http.clone(),
            keys: ArcSwap::from_pointee(HashMap::new()),
            raw_bytes: ArcSwap::from_pointee(Bytes::new()),
            last_force_refresh: Mutex::new(None),
        });

        match fetch_and_parse(&http, &url).await {
            Ok((initial_map, raw)) => {
                cache.keys.store(Arc::new(initial_map));
                cache.raw_bytes.store(Arc::new(raw));
            }
            Err(e) => warn!(
                url = %url,
                error = %e,
                "initial COSE_KeySet fetch failed; cache will populate on first verify miss"
            ),
        }

        let weak = Arc::downgrade(&cache);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // skip immediate tick — initial fetch already ran
            loop {
                ticker.tick().await;
                let Some(cache) = weak.upgrade() else {
                    debug!("CoseKeyCache dropped, exiting refresh task");
                    return;
                };
                if let Err(e) = cache.refresh().await {
                    warn!(error = %e, "scheduled COSE_KeySet refresh failed");
                }
            }
        });

        Ok(cache)
    }

    /// Construct a cache prepopulated with a fixed set of keys and the raw
    /// CBOR `COSE_KeySet` bytes that produced them. No HTTP. Used by tests
    /// and the dev test-signer; `force_refresh` is a no-op.
    ///
    /// The raw bytes are what `Verifier::verify` hands to
    /// `pep_check::verify_cose_sign1`, so they must round-trip to the same
    /// keys in the parsed map.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn new_static(keys: HashMap<Kid, VerifyingKey>, raw_keyset: Bytes) -> Arc<Self> {
        Arc::new(Self {
            url: None,
            http: reqwest::Client::new(),
            keys: ArcSwap::from_pointee(keys),
            raw_bytes: ArcSwap::from_pointee(raw_keyset),
            last_force_refresh: Mutex::new(None),
        })
    }

    pub fn get(&self, kid: &[u8]) -> Option<VerifyingKey> {
        self.keys.load().get(kid).copied()
    }

    /// Raw CBOR of the most recently fetched (or seeded) COSE_KeySet.
    /// Returns `None` until a fetch has succeeded — verifiers should
    /// surface this as "key set unavailable" rather than guess.
    pub fn raw_bytes(&self) -> Option<Bytes> {
        let guard = self.raw_bytes.load_full();
        if guard.is_empty() {
            None
        } else {
            Some((*guard).clone())
        }
    }

    /// Trigger an out-of-band refresh, rate-limited to one per
    /// [`FORCE_REFRESH_MIN_GAP`]. Returns whether a fetch was attempted.
    pub async fn force_refresh(&self) -> bool {
        let Some(url) = self.url.as_deref() else {
            return false;
        };
        let mut guard = self.last_force_refresh.lock().await;
        let now = Instant::now();
        if let Some(prev) = *guard
            && now.duration_since(prev) < FORCE_REFRESH_MIN_GAP
        {
            return false;
        }
        *guard = Some(now);
        drop(guard);

        match fetch_and_parse(&self.http, url).await {
            Ok((map, raw)) => {
                self.keys.store(Arc::new(map));
                self.raw_bytes.store(Arc::new(raw));
                true
            }
            Err(e) => {
                warn!(error = %e, "force COSE_KeySet refresh failed");
                false
            }
        }
    }

    async fn refresh(&self) -> Result<()> {
        let Some(url) = self.url.as_deref() else {
            return Ok(());
        };
        let (map, raw) = fetch_and_parse(&self.http, url).await?;
        self.keys.store(Arc::new(map));
        self.raw_bytes.store(Arc::new(raw));
        Ok(())
    }
}

async fn fetch_and_parse(
    http: &reqwest::Client,
    url: &str,
) -> Result<(HashMap<Kid, VerifyingKey>, Bytes)> {
    let bytes = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("COSE_KeySet GET {url}"))?
        .bytes()
        .await
        .with_context(|| format!("COSE_KeySet body read from {url}"))?;

    let map = parse_cose_key_set(&bytes)?;
    Ok((map, bytes))
}

pub(crate) fn parse_cose_key_set(bytes: &[u8]) -> Result<HashMap<Kid, VerifyingKey>> {
    let set = CoseKeySet::from_slice(bytes)
        .map_err(|e| anyhow!("CoseKeySet CBOR parse: {e}"))?;
    let mut out = HashMap::with_capacity(set.0.len());
    for key in set.0 {
        match parse_one(&key) {
            Ok((kid, vk)) => {
                out.insert(kid, vk);
            }
            Err(e) => {
                warn!(kid = %hex::encode(&key.key_id), error = %e, "skipping unsupported COSE_Key");
            }
        }
    }
    Ok(out)
}

fn parse_one(key: &CoseKey) -> Result<(Kid, VerifyingKey)> {
    if key.kty != coset::KeyType::Assigned(iana::KeyType::EC2) {
        return Err(anyhow!("unsupported kty {:?}", key.kty));
    }
    match &key.alg {
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) | None => {}
        Some(other) => return Err(anyhow!("unsupported alg {other:?}")),
    }
    if key.key_id.is_empty() {
        return Err(anyhow!("COSE_Key missing kid"));
    }

    let mut crv: Option<i64> = None;
    let mut x: Option<&Vec<u8>> = None;
    let mut y: Option<&Vec<u8>> = None;
    for (label, value) in &key.params {
        let coset::Label::Int(i) = label else { continue };
        match (*i, value) {
            (-1, ciborium::Value::Integer(n)) => {
                crv = Some((*n).try_into().map_err(|e| anyhow!("crv int: {e}"))?);
            }
            (-2, ciborium::Value::Bytes(b)) => x = Some(b),
            (-3, ciborium::Value::Bytes(b)) => y = Some(b),
            _ => {}
        }
    }

    if crv != Some(iana::EllipticCurve::P_256.to_i64()) {
        return Err(anyhow!("unsupported crv {crv:?} (only P-256)"));
    }
    let x = x.ok_or_else(|| anyhow!("COSE_Key missing -2 (x)"))?;
    let y = y.ok_or_else(|| anyhow!("COSE_Key missing -3 (y)"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(anyhow!("P-256 coordinates must be 32 bytes"));
    }
    let point: EncodedPoint<p256::NistP256> =
        EncodedPoint::<p256::NistP256>::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
    let vk = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| anyhow!("invalid P-256 point: {e}"))?;
    Ok((key.key_id.clone(), vk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_bytes(body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter_clone.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/cose-key-set+cbor\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                });
            }
        });
        (format!("http://{addr}"), counter)
    }

    fn empty_set() -> Vec<u8> {
        CoseKeySet(Vec::new()).to_vec().expect("serialize empty set")
    }

    #[tokio::test]
    async fn force_refresh_is_rate_limited() {
        let (url, counter) = serve_bytes(empty_set()).await;
        let http = reqwest::Client::new();
        let cache = CoseKeyCache::spawn(url.clone(), Duration::from_secs(3600), http)
            .await
            .expect("initial fetch");

        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let mut joins = Vec::new();
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            joins.push(tokio::spawn(async move { cache.force_refresh().await }));
        }
        for j in joins {
            let _ = j.await;
        }

        let total = counter.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&total),
            "expected 1 or 2 fetches, got {total}"
        );
    }

    #[test]
    fn parses_the_real_arkavo_cose_key_set() {
        // Captured from https://identity.arkavo.net/.well-known/cose-keys
        let bytes: [u8; 113] = [
            0x81, 0xa6, 0x01, 0x02, 0x02, 0x58, 0x20, 0xd8, 0x31, 0x3e, 0xe9, 0xb4, 0xc0, 0x4c,
            0x46, 0x1a, 0x0e, 0xb0, 0x0c, 0x5f, 0x26, 0xce, 0x08, 0xf7, 0xab, 0xd6, 0x70, 0x15,
            0x7c, 0x48, 0xd6, 0xb5, 0x82, 0x4e, 0xcf, 0x7a, 0x1b, 0xa1, 0xb9, 0x03, 0x26, 0x20,
            0x01, 0x21, 0x58, 0x20, 0x9a, 0xd9, 0xd1, 0xe0, 0x32, 0x0d, 0x8f, 0xa5, 0x52, 0x10,
            0xfc, 0x4a, 0xb4, 0x4f, 0xa7, 0x62, 0x33, 0xef, 0x36, 0xab, 0xa2, 0x47, 0x4c, 0x71,
            0xd1, 0x9c, 0x38, 0x6d, 0x41, 0x15, 0x94, 0x5c, 0x22, 0x58, 0x20, 0x3c, 0xb9, 0x55,
            0x0f, 0x36, 0x53, 0xdb, 0x28, 0xac, 0xf0, 0x3b, 0xa0, 0x57, 0x3c, 0x18, 0xa7, 0xa7,
            0x45, 0x99, 0xfd, 0xa2, 0x7c, 0x88, 0x28, 0x79, 0xff, 0x46, 0x02, 0x05, 0x41, 0xba,
            0x8c,
        ];
        let map = parse_cose_key_set(&bytes).expect("parses");
        assert_eq!(map.len(), 1, "expected exactly one key");
        let (kid, _vk) = map.into_iter().next().unwrap();
        assert_eq!(kid.len(), 32, "kid is the 32-byte SHA-256-style identifier");
    }
}
