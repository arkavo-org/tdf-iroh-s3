use tdf_iroh_s3::store::s3::S3Client;

#[tokio::test]
async fn test_s3_key_generation() {
    let client = S3Client::new_mock("test-bucket", "us-east-1", "");
    let hash_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    assert_eq!(client.blob_key(hash_hex), format!("blobs/{}", hash_hex));
    assert_eq!(client.outboard_key(hash_hex), format!("outboards/{}", hash_hex));
    assert_eq!(client.tag_key("my-tag"), "tags/my-tag".to_string());
}

#[tokio::test]
async fn test_s3_key_with_prefix() {
    let client = S3Client::new_mock("test-bucket", "us-east-1", "myprefix/");
    let hash_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    assert_eq!(
        client.blob_key(hash_hex),
        format!("myprefix/blobs/{}", hash_hex)
    );
}
