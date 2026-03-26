use anyhow::{Context, Result};
use aws_sdk_s3::Client;
use bytes::Bytes;

pub struct S3Client {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Client {
    /// Create a new S3 client using the default AWS credential chain (IAM role on EC2).
    pub async fn new(bucket: &str, region: &str, prefix: &str) -> Result<Self> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region.to_string()))
            .load()
            .await;
        let client = Client::new(&config);
        Ok(Self {
            client,
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
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

    pub fn blob_key(&self, hash_hex: &str) -> String {
        format!("{}blobs/{}", self.prefix, hash_hex)
    }

    pub fn outboard_key(&self, hash_hex: &str) -> String {
        format!("{}outboards/{}", self.prefix, hash_hex)
    }

    pub fn tag_key(&self, tag_name: &str) -> String {
        format!("{}tags/{}", self.prefix, tag_name)
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

    pub async fn has_blob(&self, hash_hex: &str) -> Result<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.blob_key(hash_hex))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.as_service_error()
                    .map_or(false, |se| se.is_not_found())
                {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!("Failed to HEAD blob in S3: {}", e))
                }
            }
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
                if e.as_service_error()
                    .map_or(false, |se| se.is_no_such_key())
                {
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
}
