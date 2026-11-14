use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use aws_sdk_s3::config::RequestChecksumCalculation;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::{ByteStream, DateTime};
use bytes::Bytes;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use crate::config::S3Config;
use crate::object_store::{ObjectInfo, ObjectStore, VersionInfo};

/// User metadata key holding a catalog document's owner
/// (`x-amz-meta-owner`).
pub const CATALOG_OWNER_METADATA: &str = "owner";

/// Keys per page of an `ObjectStore` listing: S3's maximum.
const DEFAULT_LIST_PAGE_SIZE: i32 = 1000;

pub struct S3Client {
    client: Client,
    bucket: String,
    prefix: String,
    list_page_size: i32,
}

/// The pauses before sending a conditional write again after S3's 409:
/// at most three attempts in all.
const CONFLICT_BACKOFF: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(500)];

/// The HTTP status S3 answered with, if it answered.
fn status<E>(e: &SdkError<E>) -> Option<u16> {
    e.raw_response().map(|r| r.status().as_u16())
}

/// Whether a conditional write lost: 412, its condition failed. Not 409
/// (see [`in_conflict`]).
fn lost_condition<E>(e: &SdkError<E>) -> bool {
    status(e) == Some(412)
}

/// Whether S3 answered a conditional write 409 (`ConditionalRequestConflict`):
/// a conflicting conditional write to the same key is still in progress,
/// so whether this one loses is unknown. S3 says to retry.
fn in_conflict<E>(e: &SdkError<E>) -> bool {
    status(e) == Some(409)
}

/// Send a conditional write, `send` building it afresh for each attempt.
/// `Ok(true)` when written, `Ok(false)` when it lost (412). A 409 is sent
/// again after each of [`CONFLICT_BACKOFF`]'s pauses; a 409 on the last
/// attempt is `Err` (the outcome is unknown), never `Ok(false)`. Any other
/// error is `Err` at once. `what` is the error's context.
async fn send_conditional<T, E, F, Fut>(what: &str, mut send: F) -> Result<bool>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SdkError<E>>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut pauses = CONFLICT_BACKOFF.iter();
    loop {
        match send().await {
            Ok(_) => return Ok(true),
            Err(e) if lost_condition(&e) => return Ok(false),
            Err(e) if in_conflict(&e) => match pauses.next() {
                Some(pause) => tokio::time::sleep(*pause).await,
                None => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "{what}: S3 answered 409 {} times, a conflicting conditional write \
                         to the key still in progress",
                        CONFLICT_BACKOFF.len() + 1
                    )));
                }
            },
            Err(e) => return Err(anyhow::Error::new(e).context(what.to_string())),
        }
    }
}

/// The versions of exactly `key` in a listing of `key` as a prefix (which
/// also returns `key…`), each paired with whether it is the current one.
/// The current one goes last, so a delete that stops part-way leaves what
/// readers see as it was: an older version never comes back.
fn versions_of(key: &str, listed: Vec<(VersionInfo, bool)>) -> Vec<VersionInfo> {
    let mut versions: Vec<(VersionInfo, bool)> =
        listed.into_iter().filter(|(v, _)| v.key == key).collect();
    versions.sort_by_key(|&(_, current)| current);
    versions.into_iter().map(|(v, _)| v).collect()
}

/// A listed entry's write time in Unix seconds. Missing is an error: a
/// made-up time could make a fresh write look old.
fn unix_secs(modified: Option<&DateTime>, listed: &str) -> Result<i64> {
    modified
        .map(DateTime::secs)
        .with_context(|| format!("S3 listed {listed} with no last-modified time"))
}

/// Whether a listing page of `prefix` says more pages follow. Missing
/// `IsTruncated` is an error: read as the end of the listing, it could
/// leave keys unlisted.
fn more_pages(is_truncated: Option<bool>, prefix: &str) -> Result<bool> {
    is_truncated.with_context(|| format!("S3 listed {prefix} with no IsTruncated"))
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
            list_page_size: DEFAULT_LIST_PAGE_SIZE,
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
            list_page_size: DEFAULT_LIST_PAGE_SIZE,
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
            list_page_size: DEFAULT_LIST_PAGE_SIZE,
        }
    }

    /// Page `ObjectStore` listings by `n` keys instead of 1000, so tests
    /// can make a listing span pages.
    pub fn with_list_page_size(mut self, n: i32) -> Self {
        self.list_page_size = n;
        self
    }

    /// An `ObjectStore` key (relative to the `[s3] prefix`) as stored.
    fn object_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }

    /// A key S3 listed for `prefix`, relative to the `[s3] prefix`. A key
    /// outside the listing's prefix is an error.
    fn relative_key(&self, listed: &str, prefix: &str) -> Result<String> {
        listed
            .strip_prefix(self.prefix.as_str())
            .filter(|key| key.starts_with(prefix))
            .map(str::to_string)
            .with_context(|| {
                format!(
                    "S3 listed {listed}, outside the prefix {}{prefix}",
                    self.prefix
                )
            })
    }

    /// Every version and delete marker under `prefix`, each with whether it
    /// is the current one, across every page.
    async fn list_versions_marked(&self, prefix: &str) -> Result<Vec<(VersionInfo, bool)>> {
        let full = self.object_key(prefix);
        let mut out = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut version_id_marker: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_object_versions()
                .bucket(&self.bucket)
                .prefix(&full)
                .max_keys(self.list_page_size);
            if let Some(marker) = &key_marker {
                req = req.key_marker(marker);
            }
            if let Some(marker) = &version_id_marker {
                req = req.version_id_marker(marker);
            }
            let resp = req
                .send()
                .await
                .with_context(|| format!("Failed to LIST versions under {full} in S3"))?;
            let versions = resp.versions().iter().map(|v| {
                (
                    v.key(),
                    v.version_id(),
                    v.last_modified(),
                    v.is_latest(),
                    false,
                )
            });
            let markers = resp.delete_markers().iter().map(|m| {
                (
                    m.key(),
                    m.version_id(),
                    m.last_modified(),
                    m.is_latest(),
                    true,
                )
            });
            for (key, version_id, modified, latest, delete_marker) in versions.chain(markers) {
                let listed = key.context("S3 listed a version with no key")?;
                let version_id = version_id
                    .with_context(|| format!("S3 listed a version of {listed} with no ID"))?;
                out.push((
                    VersionInfo {
                        key: self.relative_key(listed, prefix)?,
                        version_id: version_id.to_string(),
                        delete_marker,
                        modified: unix_secs(modified, listed)?,
                    },
                    latest.unwrap_or(false),
                ));
            }
            if !more_pages(resp.is_truncated(), &full)? {
                break;
            }
            // Without both markers the next page could skip versions.
            key_marker = Some(
                resp.next_key_marker()
                    .context("S3 cut a version listing short with no next key marker")?
                    .to_string(),
            );
            version_id_marker = Some(
                resp.next_version_id_marker()
                    .context("S3 cut a version listing short with no next version ID marker")?
                    .to_string(),
            );
        }
        // S3 lists in key order, but the SDK splits each page into versions
        // and delete markers. A stable sort restores key order.
        out.sort_by(|(a, _), (b, _)| a.key.cmp(&b.key));
        Ok(out)
    }

    pub fn blob_key(&self, hash_hex: &str) -> String {
        format!("{}blobs/{}", self.prefix, hash_hex)
    }

    pub fn outboard_key(&self, hash_hex: &str) -> String {
        format!("{}outboards/{}", self.prefix, hash_hex)
    }

    pub fn manifest_key(&self, hash_hex: &str) -> String {
        format!("{}manifests/{}", self.prefix, hash_hex)
    }

    pub fn catalog_document_key(&self, hash_hex: &str) -> String {
        format!("{}catalog-documents/{}", self.prefix, hash_hex)
    }

    /// The BAO outboard of a catalog document (catalog v2), kept apart from
    /// `outboards/` as the document is kept apart from `blobs/`.
    pub fn catalog_outboard_key(&self, hash_hex: &str) -> String {
        format!("{}catalog-outboards/{}", self.prefix, hash_hex)
    }

    /// A catalog's clear entry list and envelope attribute, as checked at
    /// publish. Never served: moderation reads it.
    pub fn catalog_index_key(&self, hash_hex: &str) -> String {
        format!("{}catalog-indexes/{}", self.prefix, hash_hex)
    }

    /// A creator's signed catalog pointer bundle (catalog v2).
    pub fn catalog_pointer_key(&self, sub: &str) -> String {
        format!("{}catalog-pointers/{}", self.prefix, sub)
    }

    /// One publish's transition record (`deletion::Transition`), named by
    /// `deletion::transition_name`; `sub` as in the pointer key. Never
    /// served: the deletion sweep reads it.
    pub fn catalog_transition_key(&self, sub: &str, name: &str) -> String {
        format!("{}catalog-transitions/{}/{}", self.prefix, sub, name)
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

    /// The extracted manifest.json of an ingested blob; `None` when none is
    /// stored.
    pub async fn get_manifest(&self, hash_hex: &str) -> Result<Option<Bytes>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.manifest_key(hash_hex))
            .send()
            .await
        {
            Ok(resp) => Ok(Some(resp.body.collect().await?.into_bytes())),
            Err(e) if e.as_service_error().is_some_and(|se| se.is_no_such_key()) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to GET manifest from S3: {}", e)),
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
            .content_type("application/zip")
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
                    Err(anyhow::anyhow!(
                        "Failed to GET catalog pointer from S3: {}",
                        e
                    ))
                }
            }
        }
    }

    /// Create a catalog's index record under `catalog-indexes/<hash>` only
    /// if none exists (`If-None-Match: *`): one envelope has one index.
    /// `false` when one already does; `Err` when a concurrent conditional
    /// write to it is still in progress after the retries
    /// (`send_conditional`).
    pub async fn create_catalog_index(&self, hash_hex: &str, body: Bytes) -> Result<bool> {
        let key = self.catalog_index_key(hash_hex);
        send_conditional("Failed to create catalog index in S3", || {
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .content_type("application/json")
                .if_none_match("*")
                .body(body.clone().into())
                .send()
        })
        .await
    }

    /// A catalog's index record, or `None` (a catalog published before
    /// envelopes has none).
    pub async fn get_catalog_index(&self, hash_hex: &str) -> Result<Option<Bytes>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.catalog_index_key(hash_hex))
            .send()
            .await
        {
            Ok(resp) => Ok(Some(resp.body.collect().await?.into_bytes())),
            Err(e) if e.as_service_error().is_some_and(|se| se.is_no_such_key()) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(
                "Failed to GET catalog index from S3: {}",
                e
            )),
        }
    }

    /// Write a publish's transition record, after its index record and
    /// before its document, outboard and pointer.
    pub async fn put_catalog_transition(&self, sub: &str, name: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.catalog_transition_key(sub, name))
            .content_type("application/json")
            .body(body.into())
            .send()
            .await
            .context("Failed to PUT catalog transition to S3")?;
        Ok(())
    }

    /// Store a creator's pointer bundle only if the stored one is still
    /// `expected` (its ETag), or, with `None`, only if there is none.
    /// `false` when another write got there first; `Err` when a conflicting
    /// write is still in progress after the retries (`send_conditional`).
    pub async fn put_catalog_pointer(
        &self,
        sub: &str,
        body: Bytes,
        expected: Option<&str>,
    ) -> Result<bool> {
        let key = self.catalog_pointer_key(sub);
        send_conditional("Failed to PUT catalog pointer to S3", || {
            let put = self
                .client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .content_type("application/json")
                .body(body.clone().into());
            match expected {
                Some(etag) => put.if_match(etag),
                None => put.if_none_match("*"),
            }
            .send()
        })
        .await
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

    /// Create one moderation record (`moderation/<kind>/<key>`) only if
    /// none exists (`If-None-Match: *`). `false` when one already does;
    /// `Err` when a concurrent conditional write to it is still in progress
    /// after the retries (`send_conditional`).
    pub async fn create_moderation_record(
        &self,
        kind: &str,
        key: &str,
        body: Bytes,
    ) -> Result<bool> {
        let key = format!("{}{}", self.moderation_prefix(kind), key);
        send_conditional("Failed to create moderation record in S3", || {
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .content_type("application/json")
                .if_none_match("*")
                .body(body.clone().into())
                .send()
        })
        .await
    }

    /// One moderation record (`moderation/<kind>/<key>`), or `None`.
    pub async fn get_moderation_record(&self, kind: &str, key: &str) -> Result<Option<Bytes>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(format!("{}{}", self.moderation_prefix(kind), key))
            .send()
            .await
        {
            Ok(resp) => Ok(Some(resp.body.collect().await?.into_bytes())),
            Err(e) if e.as_service_error().is_some_and(|se| se.is_no_such_key()) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(
                "Failed to GET moderation record from S3: {}",
                e
            )),
        }
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

/// The bucket for the offline commands. Keys are relative to the `[s3]
/// prefix`.
impl ObjectStore for S3Client {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>> {
        let full = self.object_key(prefix);
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full)
                .max_keys(self.list_page_size);
            if let Some(token) = &continuation {
                req = req.continuation_token(token);
            }
            let resp = req
                .send()
                .await
                .with_context(|| format!("Failed to LIST {full} in S3"))?;
            for obj in resp.contents() {
                let listed = obj.key().context("S3 listed an object with no key")?;
                out.push(ObjectInfo {
                    key: self.relative_key(listed, prefix)?,
                    modified: unix_secs(obj.last_modified(), listed)?,
                });
            }
            if !more_pages(resp.is_truncated(), &full)? {
                break;
            }
            continuation = Some(
                resp.next_continuation_token()
                    .context("S3 cut a listing short with no continuation token")?
                    .to_string(),
            );
        }
        Ok(out)
    }

    async fn list_versions(&self, prefix: &str) -> Result<Vec<VersionInfo>> {
        Ok(self
            .list_versions_marked(prefix)
            .await?
            .into_iter()
            .map(|(v, _)| v)
            .collect())
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
        {
            Ok(resp) => Ok(Some(
                resp.body
                    .collect()
                    .await
                    .with_context(|| format!("Failed to read {key} from S3"))?
                    .into_bytes(),
            )),
            Err(e) if e.as_service_error().is_some_and(|se| se.is_no_such_key()) => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context(format!("Failed to GET {key} from S3"))),
        }
    }

    async fn head_owner(&self, key: &str) -> Result<Option<Option<String>>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .send()
            .await
        {
            Ok(head) => Ok(Some(
                head.metadata()
                    .and_then(|m| m.get(CATALOG_OWNER_METADATA))
                    .cloned(),
            )),
            Err(e) if e.as_service_error().is_some_and(|se| se.is_not_found()) => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context(format!("Failed to HEAD {key} in S3"))),
        }
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.object_key(key))
            .body(body.into())
            .send()
            .await
            .with_context(|| format!("Failed to PUT {key} to S3"))?;
        Ok(())
    }

    async fn create(&self, key: &str, body: Bytes) -> Result<bool> {
        let object_key = self.object_key(key);
        send_conditional(&format!("Failed to create {key} in S3"), || {
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&object_key)
                .if_none_match("*")
                .body(body.clone().into())
                .send()
        })
        .await
    }

    /// Call 12: list `key`'s versions with `key` as the prefix, keep exact
    /// matches, then one `DeleteObject` with `VersionId` per version and
    /// delete marker, the current one last. A failure part-way leaves the
    /// rest for the next run.
    async fn delete_all_versions(&self, key: &str) -> Result<usize> {
        let versions = versions_of(key, self.list_versions_marked(key).await?);
        for v in &versions {
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(self.object_key(key))
                .version_id(&v.version_id)
                .send()
                .await
                .with_context(|| {
                    format!("Failed to DELETE version {} of {key} from S3", v.version_id)
                })?;
        }
        Ok(versions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(key: &str, id: &str, delete_marker: bool) -> VersionInfo {
        VersionInfo {
            key: key.to_string(),
            version_id: id.to_string(),
            delete_marker,
            modified: 0,
        }
    }

    #[test]
    fn the_list_page_size_defaults_to_1000() {
        let s3 = S3Client::new_mock("bucket", "us-east-1", "");
        assert_eq!(s3.list_page_size, 1000);
        assert_eq!(s3.with_list_page_size(2).list_page_size, 2);
    }

    #[test]
    fn transitions_are_keyed_by_subject_and_name() {
        let s3 = S3Client::new_mock("bucket", "us-east-1", "run-1/");
        assert_eq!(
            s3.catalog_transition_key("arkavo:u1", "00000000000000000007-ab"),
            "run-1/catalog-transitions/arkavo:u1/00000000000000000007-ab"
        );
    }

    #[test]
    fn listed_keys_lose_the_s3_prefix() {
        let s3 = S3Client::new_mock("bucket", "us-east-1", "run-1/");
        assert_eq!(
            s3.relative_key("run-1/blobs/aa", "blobs/").unwrap(),
            "blobs/aa"
        );
        assert_eq!(s3.relative_key("run-1/blobs/aa", "").unwrap(), "blobs/aa");
        assert!(s3.relative_key("run-2/blobs/aa", "blobs/").is_err());
        assert!(s3.relative_key("blobs/aa", "blobs/").is_err());
        assert!(s3.relative_key("run-1/manifests/aa", "blobs/").is_err());

        let bare = S3Client::new_mock("bucket", "us-east-1", "");
        assert_eq!(bare.relative_key("blobs/aa", "blobs/").unwrap(), "blobs/aa");
    }

    /// Call 12: a listing of `blobs/aa` as a prefix also returns
    /// `blobs/aab`, which must survive. The current version goes last, so a
    /// delete that stops part-way never brings back an older version.
    #[test]
    fn only_the_exact_key_is_deleted_its_current_version_last() {
        let listed = vec![
            (version("blobs/aa", "v3", false), true),
            (version("blobs/aa", "v2", false), false),
            (version("blobs/aab", "v9", false), true),
            (version("blobs/aa", "v1", false), false),
            (version("blobs/aa", "m1", true), false),
        ];
        let ids: Vec<String> = versions_of("blobs/aa", listed)
            .into_iter()
            .map(|v| v.version_id)
            .collect();
        assert_eq!(ids, ["v2", "v1", "m1", "v3"]);
    }

    /// A key whose current version is a delete marker: the marker goes last.
    #[test]
    fn a_current_delete_marker_is_deleted_last() {
        let listed = vec![
            (version("k", "v1", false), false),
            (version("k", "m2", true), true),
        ];
        let ids: Vec<String> = versions_of("k", listed)
            .into_iter()
            .map(|v| v.version_id)
            .collect();
        assert_eq!(ids, ["v1", "m2"]);
    }

    /// A page without `IsTruncated` is an error: read as the end of the
    /// listing, it would leave keys unlisted, and the sweep would decide
    /// on part of the bucket.
    #[test]
    fn a_listing_without_is_truncated_is_an_error() {
        assert!(more_pages(Some(true), "blobs/").unwrap());
        assert!(!more_pages(Some(false), "blobs/").unwrap());
        let err = more_pages(None, "run-1/blobs/").unwrap_err();
        let err = format!("{err:#}");
        assert!(
            err.contains("IsTruncated") && err.contains("run-1/blobs/"),
            "{err}"
        );
    }

    /// A PutObject that S3 answered with `status`.
    fn failed(status: u16) -> SdkError<aws_sdk_s3::operation::put_object::PutObjectError> {
        use aws_sdk_s3::config::http::HttpResponse;
        use aws_sdk_s3::operation::put_object::PutObjectError;
        use aws_sdk_s3::primitives::SdkBody;

        let raw = HttpResponse::new(status.try_into().unwrap(), SdkBody::empty());
        SdkError::service_error(PutObjectError::unhandled("x"), raw)
    }

    /// `send_conditional` against S3 answering `statuses` in turn (200 is a
    /// write): its result, how many attempts it made and how long it took.
    async fn conditional(statuses: &[u16]) -> (Result<bool>, usize, std::time::Duration) {
        let mut answers = statuses.iter().copied();
        let mut attempts = 0;
        let started = tokio::time::Instant::now();
        let result = send_conditional("Failed to PUT k", || {
            attempts += 1;
            let status = answers.next().expect("no attempt left");
            std::future::ready(match status {
                200 => Ok(()),
                _ => Err(failed(status)),
            })
        })
        .await;
        (result, attempts, started.elapsed())
    }

    /// 409 is not "lost": a conflicting conditional write is still in
    /// progress, and S3 says to retry.
    #[test]
    fn a_lost_condition_is_412_only() {
        assert!(lost_condition(&failed(412)));
        assert!(!lost_condition(&failed(409)));
        assert!(!lost_condition(&failed(403)));
        assert!(!lost_condition(&failed(500)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_conditional_write_is_sent_again_after_a_409() {
        let (result, attempts, took) = conditional(&[409, 200]).await;
        assert!(result.unwrap());
        assert_eq!(attempts, 2);
        assert_eq!(took, std::time::Duration::from_millis(100));

        // The conflicting write won meanwhile: lost.
        let (result, attempts, _) = conditional(&[409, 409, 412]).await;
        assert!(!result.unwrap());
        assert_eq!(attempts, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_409_on_every_attempt_is_an_error_not_lost() {
        let (result, attempts, took) = conditional(&[409, 409, 409]).await;
        let e = result.unwrap_err();
        assert_eq!(attempts, 3);
        assert_eq!(took, std::time::Duration::from_millis(600));
        let shown = e.to_string();
        assert!(shown.starts_with("Failed to PUT k: "), "{shown}");
        assert!(shown.contains("409"), "{shown}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_412_is_lost_without_a_retry() {
        let (result, attempts, took) = conditional(&[412]).await;
        assert!(!result.unwrap());
        assert_eq!(attempts, 1);
        assert_eq!(took, std::time::Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn other_errors_fail_without_a_retry() {
        for status in [403, 500, 503] {
            let (result, attempts, took) = conditional(&[status]).await;
            assert_eq!(
                result.unwrap_err().to_string(),
                "Failed to PUT k",
                "{status}"
            );
            assert_eq!(attempts, 1, "{status}");
            assert_eq!(took, std::time::Duration::ZERO, "{status}");
        }
    }
}
