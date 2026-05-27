use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tdf_iroh_s3::pdp::cache::AccessPdpCache;

async fn serve_attribute_defs(body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(h.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    (format!("http://{addr}"), counter)
}

#[tokio::test]
async fn loads_attribute_definitions_at_boot() {
    let (url, counter) = serve_attribute_defs(b"[]".to_vec()).await;
    let cache = AccessPdpCache::spawn(url, Duration::from_secs(3600), reqwest::Client::new())
        .await
        .expect("initial fetch");
    let _pdp = cache.load(); // Arc<AccessPdp>
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn boot_fails_when_initial_fetch_errors() {
    let res = AccessPdpCache::spawn(
        "http://127.0.0.1:1".to_string(),
        Duration::from_secs(3600),
        reqwest::Client::builder().timeout(Duration::from_millis(500)).build().unwrap(),
    ).await;
    assert!(res.is_err(), "boot must fail-closed on initial fetch error");
}

#[tokio::test]
async fn force_refresh_is_single_flight() {
    // Server delays responses long enough that 10 concurrent force_refresh
    // calls all overlap. Without single-flight they'd all fetch; with
    // single-flight only one wins, the others observe the fresh timestamp
    // and return false.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // Read request
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                // Delay long enough that all 10 concurrent force_refresh
                // calls overlap before any of them gets a response.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let body = b"[]";
                let h = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(h.as_bytes()).await;
                let _ = s.write_all(body).await;
            });
        }
    });
    let url = format!("http://{addr}");
    let cache = AccessPdpCache::spawn(url, Duration::from_secs(3600), reqwest::Client::new())
        .await
        .expect("initial fetch");
    let initial = counter.load(Ordering::SeqCst);
    assert_eq!(initial, 1);

    // Fire 10 concurrent force_refresh calls
    let mut joins = Vec::new();
    for _ in 0..10 {
        let cache = Arc::clone(&cache);
        joins.push(tokio::spawn(async move { cache.force_refresh().await }));
    }
    let mut wins = 0;
    for j in joins {
        if j.await.unwrap() { wins += 1; }
    }
    let total = counter.load(Ordering::SeqCst) - initial;
    assert_eq!(total, 1, "exactly one fetch should have happened (got {total}); single-flight broken");
    assert_eq!(wins, 1, "exactly one caller should have returned true (got {wins})");
}
