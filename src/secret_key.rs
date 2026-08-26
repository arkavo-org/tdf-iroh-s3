use anyhow::{Context, Result};
use aws_sdk_ssm::types::ParameterType;
use iroh_base::SecretKey;
use tracing::info;

/// Load the node's secret key from SSM Parameter Store, or generate a new one
/// and store it if the parameter doesn't exist yet.
pub async fn load_or_create(param_name: &str, region: &str) -> Result<SecretKey> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;
    let ssm = aws_sdk_ssm::Client::new(&config);

    // Try to load existing key
    match ssm
        .get_parameter()
        .name(param_name)
        .with_decryption(true)
        .send()
        .await
    {
        Ok(output) => {
            let value = output
                .parameter()
                .and_then(|p| p.value())
                .context("SSM parameter has no value")?;
            let bytes = hex::decode(value).context("SSM parameter is not valid hex")?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|v: Vec<u8>| anyhow::anyhow!("Expected 32 bytes, got {}", v.len()))?;
            info!("Loaded node secret key from SSM: {param_name}");
            Ok(SecretKey::from_bytes(&key_bytes))
        }
        Err(e) => {
            // Check if it's a parameter-not-found error
            if is_parameter_not_found(&e) {
                info!("No secret key found in SSM, generating new one");
                let key = SecretKey::generate();
                let key_hex = hex::encode(key.to_bytes());

                ssm.put_parameter()
                    .name(param_name)
                    .value(&key_hex)
                    .r#type(ParameterType::SecureString)
                    .description("TDF Iroh S3 node secret key")
                    .send()
                    .await
                    .context("Failed to store secret key in SSM")?;

                info!("Stored new secret key in SSM: {param_name}");
                Ok(key)
            } else {
                Err(e).context("Failed to get secret key from SSM")
            }
        }
    }
}

fn is_parameter_not_found(
    e: &aws_sdk_ssm::error::SdkError<aws_sdk_ssm::operation::get_parameter::GetParameterError>,
) -> bool {
    matches!(
        e,
        aws_sdk_ssm::error::SdkError::ServiceError(se)
            if se.err().is_parameter_not_found()
    )
}
