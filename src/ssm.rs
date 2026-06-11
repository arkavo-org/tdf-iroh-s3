use anyhow::{Context, Result};

/// Load a parameter from SSM Parameter Store, decrypted.
///
/// Load-only counterpart to [`crate::secret_key::load_or_create`]: it never
/// creates the parameter. The node's iroh secret key can be minted on first
/// boot, but a client-credentials secret must *match* the credential the IdP
/// issued — generating a fresh one would silently fail-close the catalog — so
/// a missing parameter is a hard error rather than a trigger to create one.
///
/// The value lives in SSM as a `SecureString`, fetched at startup via the
/// instance role, so the long-lived credential never sits in the config file
/// or in IMDS-readable user-data.
pub async fn load_secret(param_name: &str, region: &str) -> Result<String> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;
    let ssm = aws_sdk_ssm::Client::new(&config);

    let output = ssm
        .get_parameter()
        .name(param_name)
        .with_decryption(true)
        .send()
        .await
        .with_context(|| format!("failed to get SSM parameter {param_name}"))?;

    let value = output
        .parameter()
        .and_then(|p| p.value())
        .with_context(|| format!("SSM parameter {param_name} has no value"))?;

    Ok(value.to_string())
}
