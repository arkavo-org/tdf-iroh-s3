//! AccessPdp cache with stale-while-revalidate background refresh.

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use opentdf::pdp::{AccessPdp, Attribute, PdpOptions};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

const FORCE_REFRESH_MIN_GAP: Duration = Duration::from_secs(1);

pub struct AccessPdpCache {
    url: String,
    http: reqwest::Client,
    pdp: ArcSwap<AccessPdp>,
    last_force_refresh: Mutex<Option<Instant>>,
}

impl AccessPdpCache {
    /// Build the cache. On initial fetch failure, returns Err — callers MUST
    /// fail-closed (panic-loop, exit, etc.). Without attribute definitions
    /// the PDP would deny every check silently.
    pub async fn spawn(
        url: String,
        refresh_interval: Duration,
        http: reqwest::Client,
    ) -> Result<Arc<Self>> {
        let initial = fetch_and_build(&http, &url)
            .await
            .with_context(|| format!("initial PDP fetch from {url}"))?;
        let cache = Arc::new(Self {
            url: url.clone(),
            http: http.clone(),
            pdp: ArcSwap::from_pointee(initial),
            last_force_refresh: Mutex::new(None),
        });
        let weak = Arc::downgrade(&cache);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // initial tick already covered by boot fetch
            loop {
                ticker.tick().await;
                let Some(cache) = weak.upgrade() else {
                    debug!("AccessPdpCache dropped, exiting refresh task");
                    return;
                };
                if let Err(e) = cache.refresh().await {
                    warn!(error = %e, url = %cache.url, "scheduled PDP refresh failed; keeping stale");
                }
            }
        });
        Ok(cache)
    }

    pub fn load(&self) -> Arc<AccessPdp> {
        self.pdp.load_full()
    }

    /// Out-of-band refresh, rate-limited to one per [`FORCE_REFRESH_MIN_GAP`].
    /// Records the timestamp ONLY on successful fetch so a transient
    /// upstream error does not consume the budget. Single-flight via the mutex.
    pub async fn force_refresh(&self) -> bool {
        let mut guard = self.last_force_refresh.lock().await;
        let now = Instant::now();
        if let Some(prev) = *guard
            && now.duration_since(prev) < FORCE_REFRESH_MIN_GAP
        {
            return false;
        }
        // Hold the guard across the fetch: serializes concurrent callers
        // (true single-flight) and prevents duplicate in-flight requests.
        match fetch_and_build(&self.http, &self.url).await {
            Ok(new_pdp) => {
                self.pdp.store(Arc::new(new_pdp));
                *guard = Some(now);
                true
            }
            Err(e) => {
                // On failure we deliberately do NOT stamp the timestamp,
                // so the next caller can retry immediately rather than
                // burning the 1s budget on a transient error.
                warn!(error = %e, "force PDP refresh failed");
                false
            }
        }
    }

    async fn refresh(&self) -> Result<()> {
        let new_pdp = fetch_and_build(&self.http, &self.url).await?;
        self.pdp.store(Arc::new(new_pdp));
        Ok(())
    }
}

async fn fetch_and_build(http: &reqwest::Client, url: &str) -> Result<AccessPdp> {
    let bytes = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("status from {url}"))?
        .bytes()
        .await
        .with_context(|| format!("body from {url}"))?;
    let attrs: Vec<Attribute> = serde_json::from_slice(&bytes)
        .context("decode attribute definitions JSON")?;
    AccessPdp::new(attrs, PdpOptions::default())
        .map_err(|e| anyhow!("build AccessPdp: {e}"))
}
