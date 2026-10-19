use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use aws_sdk_s3::config::RequestChecksumCalculation;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::path::Path;

use crate::config::S3Config;

/// User metadata key holding a catalog document's owner
/// (`x-amz-meta-owner`).
pub const CATALOG_OWNER_METADATA: &str = "owner";

pub struct S3Client {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Client {
    /// Create a new S3 client using the default AWS credential chain (IAM role on EC2).
    pub async fn new(bucket: &str, region: &str, prefix: &str) -> Result<Self> {
        Self::from_config(&S3Config {
            bucket: bucket.to_string(),
            region: region.to_string(),
            prefix: prefix.to_string(),
            endpoint_url: String::new(),
            force_path_style: false,
        })
        .await
    }

    /// Create a client from the `[s3]` section: the default AWS credential
    /// chain, plus the endpoint and addressing overrides an S3-compatible
    /// store (LocalStack, MinIO) needs.
    pub async fn from_config(config: &S3Config) -> Result<Self> {
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(config.force_path_style);
        if !config.endpoint_url.is_empty() {
            builder = builder.endpoint_url(&config.endpoint_url);
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket.clone(),
            prefix: config.prefix.clone(),
        })
    }

    /// Create a mock S3 client for testing (no real AWS calls).
    pub fn new_mock(bucket: &str, region: &str, prefix: &str) -> Self {
        let config = aws_sdk_s3::config::Builder::new()
            .region(aws_sdk_s3::config::Region::new(region.to_string()))
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .build();
        let client = Client::from_conf(config);
        Self {
            client,
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
        }
    }

    /// A client for a loopback S3 stand-in at `endpoint_url`, with static
    /// credentials, for tests.
    #[cfg(test)]
    pub fn for_endpoint(bucket: &str, endpoint_url: &str) -> Self {
        let config = aws_sdk_s3::config::Builder::new()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(endpoint_url)
            .force_path_style(true)
            .build();
        Self {
            client: Client::from_conf(config),
            bucket: bucket.to_string(),
            prefix: String::new(),
        }
    }

    pub fn blob_key(&self, hash_hex: &str) -> String {
        format!("{}blobs/{}", self.prefix, hash_hex)
    }

    pub fn outboard_key(&self, hash_hex: &str) -> String {
        format!("{}outboards/{}", self.prefix, hash_hex)
    }

    pub fn tag_key(&self, tag_name: &str) -> String {
        format!("{}tags/{}", self.prefix, tag_name)
    }

    pub fn manifest_key(&self, hash_hex: &str) -> String {
        format!("{}manifests/{}", self.prefix, hash_hex)
    }

    pub fn catalog_entry_key(&self, group: &str, hash_hex: &str) -> String {
        format!("{}catalog-index/{}/{}", self.prefix, group, hash_hex)
    }

    pub fn catalog_document_key(&self, hash_hex: &str) -> String {
        format!("{}catalog-documents/{}", self.prefix, hash_hex)
    }

    /// The BAO outboard of a catalog document (catalog v2), kept apart from
    /// `outboards/` as the document is kept apart from `blobs/`.
    pub fn catalog_outboard_key(&self, hash_hex: &str) -> String {
        format!("{}catalog-outboards/{}", self.prefix, hash_hex)
    }

    /// A creator's signed catalog pointer bundle (catalog v2).
    pub fn catalog_pointer_key(&self, sub: &str) -> String {
        format!("{}catalog-pointers/{}", self.prefix, sub)
    }

    pub async fn put_blob(&self, hash_hex: &str, data: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.blob_key(hash_hex))
            .body(data.into())
            .send()
            .await
            .context("Failed to PUT blob to S3")?;
        Ok(())
    }

    /// Upload a blob from a file of `size` bytes, streaming it: the body is
    /// read from disk as it is sent, never held in memory.
    ///
    /// The SDK's default CRC32 checksum is off for this request. With it, a
    /// streamed body is sent `aws-chunked`, and aws-runtime 1.7.1 (the
    /// newest that builds on this crate's Rust 1.91) sends the body as one
    /// chunk while declaring a Content-Length for 64 KiB chunks, so the
    /// request never completes. Without it the body is sent as is, with its
    /// exact length; TLS protects it in transit.
    pub async fn put_blob_file(&self, hash_hex: &str, path: &Path, size: u64) -> Result<()> {
        let body = ByteStream::read_from()
            .path(path)
            .length(aws_sdk_s3::primitives::Length::Exact(size))
            .build()
            .await
            .with_context(|| format!("Failed to open {} for upload", path.display()))?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.blob_key(hash_hex))
            .content_length(i64::try_from(size).context("blob too large for S3")?)
            .body(body)
            .customize()
            .config_override(
                aws_sdk_s3::config::Builder::default()
                    .request_checksum_calculation(RequestChecksumCalculation::WhenRequired),
            )
            .send()
            .await
            .context("Failed to PUT blob to S3")?;
        Ok(())
    }

    pub async fn put_outboard(&self, hash_hex: &str, data: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.outboard_key(hash_hex))
            .body(data.into())
            .send()
            .await
            .context("Failed to PUT outboard to S3")?;
        Ok(())
    }

    /// Store the extracted manifest.json alongside the blob. Readers of
    /// policy/metadata (catalog indexing, UIs, repair) hit this small object
    /// instead of downloading and unzipping the full TDF.
    pub async fn put_manifest(&self, hash_hex: &str, manifest_json: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.manifest_key(hash_hex))
            .content_type("application/json")
            .body(manifest_json.into())
            .send()
            .await
            .context("Failed to PUT manifest to S3")?;
        Ok(())
    }

    /// Store a catalog index entry under `catalog-index/<group>/<hash>`.
    pub async fn put_catalog_entry(
        &self,
        group: &str,
        hash_hex: &str,
        entry_json: Bytes,
    ) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.catalog_entry_key(group, hash_hex))
            .content_type("application/json")
            .body(entry_json.into())
            .send()
            .await
            .context("Failed to PUT catalog entry to S3")?;
        Ok(())
    }

    /// List the blob hashes indexed under one catalog group (keys below
    /// `catalog-index/<group>/`), paginating as needed.
    pub async fn list_catalog_hashes(&self, group: &str) -> Result<Vec<String>> {
        let prefix = format!("{}catalog-index/{}/", self.prefix, group);
        let mut hashes = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(token) = &continuation {
                req = req.continuation_token(token);
            }
            let resp = req
                .send()
                .await
                .context("Failed to LIST catalog entries in S3")?;
            for obj in resp.contents() {
                if let Some(key) = obj.key()
                    && let Some(hash) = key.strip_prefix(&prefix)
                {
                    hashes.push(hash.to_string());
                }
            }
            match resp.next_continuation_token() {
                Some(token) => continuation = Some(token.to_string()),
                None => break,
            }
        }
        Ok(hashes)
    }

    pub async fn get_catalog_entry(&self, group: &str, hash_hex: &str) -> Result<Option<Bytes>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.catalog_entry_key(group, hash_hex))
            .send()
            .await
        {
            Ok(resp) => {
                let data = resp.body.collect().await?;
                Ok(Some(data.into_bytes()))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to GET catalog entry from S3: {}",
                        e
                    ))
                }
            }
        }
    }

    pub async fn get_blob(&self, hash_hex: &str) -> Result<Bytes> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.blob_key(hash_hex))
            .send()
            .await
            .context("Failed to GET blob from S3")?;
        let data = resp
            .body
            .collect()
            .await
            .context("Failed to read blob body from S3")?;
        Ok(data.into_bytes())
    }

    /// Open a GET of the object at `key` from byte `start` to its end,
    /// streamed. `None` when there is no such object. The body is read as
    /// it arrives; the caller bounds how long it waits.
    pub async fn get_object_from(
        &self,
        key: &str,
        start: u64,
    ) -> Result<Option<std::pin::Pin<Box<dyn tokio::io::AsyncBufRead + Send>>>> {
        let mut request = self.client.get_object().bucket(&self.bucket).key(key);
        // A range on a zero-length object is invalid in S3; from 0, ask for
        // all of it.
        if start > 0 {
            request = request.range(format!("bytes={start}-"));
        }
        match request.send().await {
            Ok(resp) => Ok(Some(Box::pin(resp.body.into_async_read()))),
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to GET {key} from S3: {e}"))
                }
            }
        }
    }

    pub async fn get_outboard(&self, hash_hex: &str) -> Result<Bytes> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.outboard_key(hash_hex))
            .send()
            .await
            .context("Failed to GET outboard from S3")?;
        let data = resp
            .body
            .collect()
            .await
            .context("Failed to read outboard body from S3")?;
        Ok(data.into_bytes())
    }

    /// The stored size of an ingested blob, or `None` when there is no
    /// such blob.
    pub async fn blob_size(&self, hash_hex: &str) -> Result<Option<u64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.blob_key(hash_hex))
            .send()
            .await
        {
            Ok(head) => {
                let size = head
                    .content_length()
                    .and_then(|n| u64::try_from(n).ok())
                    .context("S3 HEAD of a blob returned no content length")?;
                Ok(Some(size))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to HEAD blob in S3: {}", e))
                }
            }
        }
    }

    /// The stored size of a blob's outboard, or `None` when there is no
    /// such outboard. An empty outboard (a blob of 16 KiB or less) is
    /// `Some(0)`.
    pub async fn outboard_size(&self, hash_hex: &str) -> Result<Option<u64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.outboard_key(hash_hex))
            .send()
            .await
        {
            Ok(head) => {
                let size = head
                    .content_length()
                    .and_then(|n| u64::try_from(n).ok())
                    .context("S3 HEAD of an outboard returned no content length")?;
                Ok(Some(size))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to HEAD outboard in S3: {}", e))
                }
            }
        }
    }

    /// Store a creator catalog document under `catalog-documents/<hash>`,
    /// byte for byte, with its owner as object metadata (`x-amz-meta-owner`)
    /// so a read can apply the owner's suspension without parsing it.
    pub async fn put_catalog_document(
        &self,
        hash_hex: &str,
        body: Bytes,
        owner: &str,
    ) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.catalog_document_key(hash_hex))
            .content_type("application/json")
            .metadata(CATALOG_OWNER_METADATA, owner)
            .body(body.into())
            .send()
            .await
            .context("Failed to PUT catalog document to S3")?;
        Ok(())
    }

    /// A stored catalog document and its `owner` metadata (`None` for a
    /// document stored without it).
    pub async fn get_catalog_document(
        &self,
        hash_hex: &str,
    ) -> Result<Option<(Bytes, Option<String>)>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.catalog_document_key(hash_hex))
            .send()
            .await
        {
            Ok(resp) => {
                let owner = resp
                    .metadata()
                    .and_then(|m| m.get(CATALOG_OWNER_METADATA))
                    .cloned();
                let data = resp.body.collect().await?;
                Ok(Some((data.into_bytes(), owner)))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to GET catalog document from S3: {}",
                        e
                    ))
                }
            }
        }
    }

    /// Whether a catalog document is stored, and its `owner` metadata, from
    /// a HEAD (no body).
    pub async fn head_catalog_document(&self, hash_hex: &str) -> Result<Option<Option<String>>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.catalog_document_key(hash_hex))
            .send()
            .await
        {
            Ok(head) => Ok(Some(
                head.metadata()
                    .and_then(|m| m.get(CATALOG_OWNER_METADATA))
                    .cloned(),
            )),
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to HEAD catalog document in S3: {}",
                        e
                    ))
                }
            }
        }
    }

    /// A stored catalog document's size and `owner` metadata, from a HEAD.
    pub async fn catalog_document_size(
        &self,
        hash_hex: &str,
    ) -> Result<Option<(u64, Option<String>)>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.catalog_document_key(hash_hex))
            .send()
            .await
        {
            Ok(head) => {
                let size = head
                    .content_length()
                    .and_then(|n| u64::try_from(n).ok())
                    .context("S3 HEAD of a catalog document returned no content length")?;
                let owner = head
                    .metadata()
                    .and_then(|m| m.get(CATALOG_OWNER_METADATA))
                    .cloned();
                Ok(Some((size, owner)))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to HEAD catalog document in S3: {}",
                        e
                    ))
                }
            }
        }
    }

    pub async fn put_catalog_outboard(&self, hash_hex: &str, data: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.catalog_outboard_key(hash_hex))
            .body(data.into())
            .send()
            .await
            .context("Failed to PUT catalog outboard to S3")?;
        Ok(())
    }

    /// The stored size of a catalog document's outboard, or `None`.
    pub async fn catalog_outboard_size(&self, hash_hex: &str) -> Result<Option<u64>> {
        self.object_size(&self.catalog_outboard_key(hash_hex), "catalog outboard")
            .await
    }

    async fn object_size(&self, key: &str, what: &str) -> Result<Option<u64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(head) => Ok(Some(
                head.content_length()
                    .and_then(|n| u64::try_from(n).ok())
                    .with_context(|| format!("S3 HEAD of a {what} returned no content length"))?,
            )),
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_not_found()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to HEAD {what} in S3: {}", e))
                }
            }
        }
    }

    /// A creator's stored pointer bundle and its ETag.
    pub async fn get_catalog_pointer(&self, sub: &str) -> Result<Option<(Bytes, String)>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.catalog_pointer_key(sub))
            .send()
            .await
        {
            Ok(resp) => {
                let etag = resp
                    .e_tag()
                    .context("S3 GET of a catalog pointer returned no ETag")?
                    .to_string();
                let data = resp.body.collect().await?;
                Ok(Some((data.into_bytes(), etag)))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to GET catalog pointer from S3: {}", e))
                }
            }
        }
    }

    /// Store a creator's pointer bundle only if the stored one is still
    /// `expected` (its ETag), or, with `None`, only if there is none.
    /// `false` when another write got there first.
    pub async fn put_catalog_pointer(
        &self,
        sub: &str,
        body: Bytes,
        expected: Option<&str>,
    ) -> Result<bool> {
        let put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.catalog_pointer_key(sub))
            .content_type("application/json")
            .body(body.into());
        let put = match expected {
            Some(etag) => put.if_match(etag),
            None => put.if_none_match("*"),
        };
        match put.send().await {
            Ok(_) => Ok(true),
            // 412: the condition failed; 409: a concurrent conditional
            // write to the same key is in progress.
            Err(e) if e.raw_response().is_some_and(|r| matches!(r.status().as_u16(), 409 | 412)) => {
                Ok(false)
            }
            Err(e) => Err(anyhow::anyhow!("Failed to PUT catalog pointer to S3: {}", e)),
        }
    }

    pub async fn delete_blob(&self, hash_hex: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.blob_key(hash_hex))
            .send()
            .await
            .context("Failed to DELETE blob from S3")?;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.outboard_key(hash_hex))
            .send()
            .await
            .context("Failed to DELETE outboard from S3")?;
        Ok(())
    }

    pub async fn put_tag(&self, tag_name: &str, hash_hex: &str) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.tag_key(tag_name))
            .body(Bytes::from(hash_hex.to_string()).into())
            .send()
            .await
            .context("Failed to PUT tag to S3")?;
        Ok(())
    }

    pub async fn get_tag(&self, tag_name: &str) -> Result<Option<String>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.tag_key(tag_name))
            .send()
            .await
        {
            Ok(resp) => {
                let data = resp.body.collect().await?;
                let hash_hex = String::from_utf8(data.into_bytes().to_vec())?;
                Ok(Some(hash_hex))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(anyhow::anyhow!("Failed to GET tag from S3: {}", e))
                }
            }
        }
    }

    pub async fn delete_tag(&self, tag_name: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.tag_key(tag_name))
            .send()
            .await
            .context("Failed to DELETE tag from S3")?;
        Ok(())
    }

    fn moderation_prefix(&self, kind: &str) -> String {
        format!("{}moderation/{}/", self.prefix, kind)
    }

    /// Write one moderation record (`moderation/<kind>/<key>`).
    pub async fn put_moderation_record(&self, kind: &str, key: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(format!("{}{}", self.moderation_prefix(kind), key))
            .content_type("application/json")
            .body(body.into())
            .send()
            .await
            .context("Failed to PUT moderation record to S3")?;
        Ok(())
    }

    /// Every record under `moderation/<kind>/`, paginating as needed.
    pub async fn list_moderation_records(&self, kind: &str) -> Result<Vec<Bytes>> {
        let prefix = self.moderation_prefix(kind);
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&prefix);
            if let Some(token) = &continuation {
                req = req.continuation_token(token);
            }
            let resp = req
                .send()
                .await
                .context("Failed to LIST moderation records in S3")?;
            for obj in resp.contents() {
                let Some(key) = obj.key() else { continue };
                let got = self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send()
                    .await
                    .context("Failed to GET moderation record from S3")?;
                out.push(got.body.collect().await?.into_bytes());
            }
            match resp.next_continuation_token() {
                Some(token) => continuation = Some(token.to_string()),
                None => break,
            }
        }
        Ok(out)
    }
}
