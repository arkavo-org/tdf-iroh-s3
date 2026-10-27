use tdf_iroh_s3::store::s3::S3Client;

#[tokio::test]
async fn test_s3_key_generation() {
    let client = S3Client::new_mock("test-bucket", "us-east-1", "");
    let hash_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    assert_eq!(client.blob_key(hash_hex), format!("blobs/{}", hash_hex));
    assert_eq!(
        client.outboard_key(hash_hex),
        format!("outboards/{}", hash_hex)
    );
    assert_eq!(
        client.catalog_index_key(hash_hex),
        format!("catalog-indexes/{}", hash_hex)
    );
    assert_eq!(
        client.campaign_creator_key("13167240"),
        "campaign-creators/13167240"
    );
    assert_eq!(
        client.catalog_document_key(hash_hex),
        format!("catalog-documents/{}", hash_hex)
    );
}

#[tokio::test]
async fn test_s3_key_with_prefix() {
    let client = S3Client::new_mock("test-bucket", "us-east-1", "myprefix/");
    let hash_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    assert_eq!(
        client.blob_key(hash_hex),
        format!("myprefix/blobs/{}", hash_hex)
    );
    assert_eq!(
        client.catalog_document_key(hash_hex),
        format!("myprefix/catalog-documents/{}", hash_hex)
    );
}

/// A loopback S3 that keeps each object's body and `x-amz-meta-owner`.
async fn metadata_s3() -> String {
    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::IntoResponse;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type Objects = Arc<Mutex<HashMap<String, (Bytes, Option<String>)>>>;
    let objects: Objects = Arc::default();
    let app = axum::Router::new().fallback(
        move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
            let objects = Arc::clone(&objects);
            async move {
                let key = uri.path().to_string();
                let mut objects = objects.lock().unwrap();
                match method {
                    Method::PUT => {
                        let owner = headers
                            .get("x-amz-meta-owner")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        objects.insert(key, (body, owner));
                        (StatusCode::OK, [("etag", "\"fake\"")]).into_response()
                    }
                    Method::GET | Method::HEAD => match objects.get(&key) {
                        Some((body, owner)) => {
                            let mut res = if method == Method::GET {
                                body.clone().into_response()
                            } else {
                                (StatusCode::OK, [("content-length", body.len().to_string())])
                                    .into_response()
                            };
                            if let Some(owner) = owner {
                                res.headers_mut()
                                    .insert("x-amz-meta-owner", owner.parse().unwrap());
                            }
                            res
                        }
                        None if method == Method::GET => (
                            StatusCode::NOT_FOUND,
                            "<Error><Code>NoSuchKey</Code><Message>none</Message></Error>",
                        )
                            .into_response(),
                        None => StatusCode::NOT_FOUND.into_response(),
                    },
                    _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
                }
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    url
}

/// A catalog document's owner travels as `x-amz-meta-owner`: written with
/// the document, read back by GET and HEAD.
#[tokio::test(flavor = "current_thread")]
async fn test_catalog_document_owner_metadata_round_trips() {
    // SAFETY: current_thread runtime ensures no other threads read env vars concurrently.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
    let endpoint_url = metadata_s3().await;
    let client = S3Client::from_config(&tdf_iroh_s3::config::S3Config {
        bucket: "test-bucket".into(),
        region: "us-east-1".into(),
        prefix: String::new(),
        endpoint_url,
        force_path_style: true,
    })
    .await
    .unwrap();

    let hash = "ab".repeat(32);
    assert!(client.head_catalog_document(&hash).await.unwrap().is_none());
    assert!(client.get_catalog_document(&hash).await.unwrap().is_none());

    let body = axum::body::Bytes::from_static(b"{\"schema\":\"x\"}");
    client
        .put_catalog_document(&hash, body.clone(), "arkavo:creator-1")
        .await
        .unwrap();
    let (got, owner) = client.get_catalog_document(&hash).await.unwrap().unwrap();
    assert_eq!(got, body);
    assert_eq!(owner.as_deref(), Some("arkavo:creator-1"));
    let head = client.head_catalog_document(&hash).await.unwrap();
    assert_eq!(head, Some(Some("arkavo:creator-1".to_string())));
}

/// An outboard is stored and sized by HEAD; a blob of 16 KiB or less has an
/// empty one, which is a zero-length object, not a missing one.
#[tokio::test(flavor = "current_thread")]
async fn test_outboard_put_and_size_including_empty() {
    use bytes::Bytes;
    use tdf_iroh_s3::config::S3Config;
    use tdf_iroh_s3::store::s3::S3Client;

    // SAFETY: current_thread runtime ensures no other threads read env vars concurrently.
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
    }
    let s3 = S3Client::from_config(&S3Config {
        bucket: "test-bucket".into(),
        region: "us-east-1".into(),
        prefix: String::new(),
        endpoint_url: metadata_s3().await,
        force_path_style: true,
    })
    .await
    .unwrap();

    assert_eq!(s3.outboard_size("aa").await.unwrap(), None);
    s3.put_outboard("aa", Bytes::new()).await.unwrap();
    assert_eq!(s3.outboard_size("aa").await.unwrap(), Some(0));
    assert!(s3.get_outboard("aa").await.unwrap().is_empty());
    s3.put_outboard("bb", Bytes::from(vec![1u8; 128]))
        .await
        .unwrap();
    assert_eq!(s3.outboard_size("bb").await.unwrap(), Some(128));
}
