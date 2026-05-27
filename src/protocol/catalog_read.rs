//! `tdf/catalog/1` ALPN — reader-side CWT-gated catalog stream.
//!
//! Wire format: length-prefixed CBOR frames over a single bidi QUIC stream.
//! Reader sends one `CatalogSubscribe`, then receives a sequence of
//! `CatalogStreamMsg` frames (Entry / CaughtUp / Heartbeat /
//! TokenExpiringSoon / Error) until close.

use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::auth::{Verifier, cwt_to_entitlements};
use crate::catalog::store::EventStore;
use crate::catalog::types::ContentEvent;
use crate::pdp::cache::AccessPdpCache;
use opentdf::pdp::Action;

pub const ALPN: &[u8] = b"tdf/catalog/1";

const MAX_REQUEST_BYTES: u32 = 64 * 1024;
const MAX_FRAME_BYTES: u32 = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct CatalogSubscribe {
    pub cwt: ByteBuf,
    pub after_seq: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CatalogStreamMsg {
    Entry(ContentEvent),
    CaughtUp { seq: u64 },
    Heartbeat,
    TokenExpiringSoon { exp: i64 },
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    PdpUnavailable,
    Internal,
    TooManySubscriptions,
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<()> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(msg, &mut buf).context("encode frame as CBOR")?;
    if buf.len() as u32 > MAX_FRAME_BYTES {
        bail!("frame too large ({} bytes)", buf.len());
    }
    w.write_u32(buf.len() as u32).await.context("write frame length")?;
    w.write_all(&buf).await.context("write frame body")?;
    w.flush().await.ok();
    Ok(())
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<CatalogSubscribe> {
    let len = r.read_u32().await.context("read request length")?;
    if len > MAX_REQUEST_BYTES {
        bail!("request too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await.context("read request body")?;
    let req: CatalogSubscribe = ciborium::de::from_reader(buf.as_slice())
        .context("decode CatalogSubscribe CBOR")?;
    Ok(req)
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const TOKEN_WARNING_LEAD: i64 = 60;

#[derive(Default)]
pub struct SubscriptionLimits {
    pub max_per_peer: u32,
    pub max_total: u32,
    per_peer: Mutex<HashMap<String, u32>>,
    total: AtomicU32,
}

impl SubscriptionLimits {
    pub fn new(max_per_peer: u32, max_total: u32) -> Arc<Self> {
        Arc::new(Self {
            max_per_peer,
            max_total,
            per_peer: Mutex::new(HashMap::new()),
            total: AtomicU32::new(0),
        })
    }

    fn try_acquire(&self, peer: &str) -> bool {
        if self.total.load(Ordering::SeqCst) >= self.max_total {
            return false;
        }
        let mut map = self.per_peer.lock();
        let count = map.entry(peer.to_string()).or_insert(0);
        if *count >= self.max_per_peer {
            return false;
        }
        *count += 1;
        self.total.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn release(&self, peer: &str) {
        let mut map = self.per_peer.lock();
        if let Some(c) = map.get_mut(peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                map.remove(peer);
            }
        }
        self.total.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct CatalogReadDeps {
    pub verifier: Arc<Verifier>,
    pub store: Arc<EventStore>,
    pub pdp: Arc<AccessPdpCache>,
    pub limits: Arc<SubscriptionLimits>,
    pub cancel: CancellationToken,
}

/// One subscriber's full lifecycle. Returns Ok(()) on graceful close;
/// returns Err only on unexpected I/O. Auth failures silently close
/// (no error frame) per contract §4.
pub async fn handle<R, W>(
    mut read: R,
    mut write: W,
    remote_node_id: String,
    deps: CatalogReadDeps,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let req = match read_request(&mut read).await {
        Ok(r) => r,
        Err(e) => {
            warn!(peer = %remote_node_id, err = %e, "catalog subscribe: bad request");
            return Ok(());
        }
    };

    let claims = match deps.verifier.verify(&req.cwt, &remote_node_id).await {
        Ok(c) => c,
        Err(e) => {
            warn!(peer = %remote_node_id, err = %e,
                  "catalog subscribe: cwt rejected; closing silently");
            return Ok(()); // contract §4: silent close, never emit a frame
        }
    };
    info!(sub = %claims.subject, peer = %remote_node_id, "catalog subscribe opened");

    let entitlements = cwt_to_entitlements(&claims);
    if entitlements.is_empty() {
        warn!(peer = %remote_node_id, "catalog subscribe: empty entitlements; closing");
        return Ok(());
    }

    if !deps.limits.try_acquire(&remote_node_id) {
        let _ = write_frame(
            &mut write,
            &CatalogStreamMsg::Error {
                code: ErrorCode::TooManySubscriptions,
                message: "subscription cap reached".into(),
            },
        )
        .await;
        return Ok(());
    }
    let _guard = ReleaseOnDrop::new(&deps.limits, remote_node_id.clone());

    let pdp = deps.pdp.load();
    let action = Action::new("read");

    // Backfill
    let after = req.after_seq.unwrap_or(0);
    let mut bf = deps.store.list_from(after).await.context("list_from")?;
    while let Some(ev) = futures_lite::StreamExt::next(&mut bf).await {
        let ev = ev?;
        let allow = pdp
            .check(&entitlements, &action, &ev.attribute_value_fqns)
            .map(|d| d.is_allow())
            .unwrap_or(false);
        if allow {
            write_frame(&mut write, &CatalogStreamMsg::Entry(ev)).await?;
        }
    }
    let tail = deps.store.current_tail();
    write_frame(&mut write, &CatalogStreamMsg::CaughtUp { seq: tail }).await?;

    // Live
    let mut live = deps.store.subscribe();
    let mut hb = tokio::time::interval(HEARTBEAT_INTERVAL);
    hb.tick().await;
    let mut warned = false;
    loop {
        tokio::select! {
            biased;
            _ = deps.cancel.cancelled() => {
                debug!(peer = %remote_node_id, "catalog subscribe: server cancelled");
                return Ok(());
            }
            ev = live.recv() => match ev {
                Ok(ev) => {
                    let allow = pdp
                        .check(&entitlements, &action, &ev.attribute_value_fqns)
                        .map(|d| d.is_allow())
                        .unwrap_or(false);
                    if allow {
                        write_frame(&mut write, &CatalogStreamMsg::Entry(ev)).await?;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    warn!(peer = %remote_node_id, dropped = n, "subscriber lagged; closing");
                    let _ = write_frame(&mut write, &CatalogStreamMsg::Error {
                        code: ErrorCode::Internal,
                        message: format!("lagged, {n} events dropped"),
                    }).await;
                    return Ok(());
                }
                Err(RecvError::Closed) => return Ok(()),
            },
            _ = hb.tick() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
                if now >= claims.exp {
                    let _ = write_frame(&mut write, &CatalogStreamMsg::Error {
                        code: ErrorCode::BadRequest,
                        message: "cwt expired".into(),
                    }).await;
                    return Ok(());
                }
                if !warned && now >= claims.exp - TOKEN_WARNING_LEAD {
                    write_frame(&mut write, &CatalogStreamMsg::TokenExpiringSoon { exp: claims.exp }).await?;
                    warned = true;
                }
                write_frame(&mut write, &CatalogStreamMsg::Heartbeat).await?;
            }
        }
    }
}

struct ReleaseOnDrop<'a> {
    limits: &'a SubscriptionLimits,
    peer: String,
}
impl<'a> ReleaseOnDrop<'a> {
    fn new(limits: &'a SubscriptionLimits, peer: String) -> Self {
        Self { limits, peer }
    }
}
impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        self.limits.release(&self.peer);
    }
}
