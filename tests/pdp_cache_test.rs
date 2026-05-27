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
