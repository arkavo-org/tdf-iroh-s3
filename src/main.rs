use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use std::sync::Arc;

use tdf_iroh_s3::attributes::{self, AttributeSet};
use tdf_iroh_s3::auth::CwtVerifier;
use tdf_iroh_s3::authz::{ConnectAuthzClient, DecisionProvider, DenyAll};
use tdf_iroh_s3::catalog_api::{self, CatalogApiState, CatalogCache};
use tdf_iroh_s3::config::Config;
use tdf_iroh_s3::node::TdfIrohNode;
use tdf_iroh_s3::tags_api::{self, ApiState};

#[derive(Parser)]
#[command(
    name = "tdf-iroh-s3",
    about = "TDF-validated Iroh peer with S3 blob storage"
)]
struct Cli {
    #[arg(short, long, default_value = "/etc/tdf-iroh-s3/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::from_file(&cli.config)?;
    info!("Config loaded from {:?}", cli.config);
    info!("S3: {}:{}", config.s3.bucket, config.s3.region);
    info!(
        "Required attributes: {:?}",
        config.validation.required_attributes
    );
    info!("Assertion check: {}", config.validation.assertion.enabled);

    let node = TdfIrohNode::spawn(config).await?;
    let addr = node.addr();
    info!("Node running at {}", addr.id);

    // HTTP tag API (catalog discovery): GET resolution is public; PUT is
    // CWT-authenticated against the configured IdP key set.
    if node.config.http.enabled {
        let http_cfg = &node.config.http;
        anyhow::ensure!(
            !http_cfg.cose_keys_url.is_empty(),
            "[http] enabled requires cose_keys_url (e.g. https://identity.arkavo.net/.well-known/cose-keys)"
        );
        let expected_iss = if http_cfg.expected_issuer.is_empty() {
            tracing::warn!(
                "[http] expected_issuer unset — any token signed by the key set is accepted"
            );
            None
        } else {
            Some(http_cfg.expected_issuer.clone())
        };
        let verifier = Arc::new(CwtVerifier::new(
            http_cfg.cose_keys_url.clone(),
            expected_iss,
        ));
        let state = Arc::new(ApiState {
            store: Arc::clone(&node.s3_client),
            verifier: Arc::clone(&verifier),
            tag_prefix: http_cfg.tag_prefix.clone(),
        });
        let mut router = tags_api::router(state);

        // Catalog: public attribute definitions + the entitled-catalog
        // endpoint. Attributes are never hardcoded — the definitions
        // artifact is the source of truth, and the grouping attribute must
        // be defined in it.
        let cat = &node.config.catalog;
        if cat.enabled {
            anyhow::ensure!(
                !cat.attributes_file.is_empty(),
                "[catalog] enabled requires attributes_file (OpenTDF-shaped definitions JSON)"
            );
            let set = AttributeSet::load(&cat.attributes_file)?;
            anyhow::ensure!(
                set.attribute_by_fqn(&cat.group_attribute_fqn).is_some(),
                "[catalog] group_attribute_fqn {} is not defined in {}",
                cat.group_attribute_fqn,
                cat.attributes_file
            );
            info!(
                "Attribute definitions loaded: namespace {} ({} attributes)",
                set.namespace.fqn,
                set.attributes.len()
            );
            router = router.merge(attributes::router(Arc::new(set)));

            let environment = if cat.authz.environment_region.is_empty() {
                None
            } else {
                Some(serde_json::json!({
                    "kind": "environment",
                    "region": cat.authz.environment_region,
                }))
            };
            let cache = CatalogCache::new(
                Arc::clone(&node.s3_client),
                std::time::Duration::from_secs(cat.cache_ttl_secs),
            );
            if cat.authz.endpoint.is_empty() {
                tracing::warn!(
                    "[catalog.authz] endpoint unset — catalog decisions fail closed (nothing entitled)"
                );
                router = router.merge(catalog_router(
                    cache,
                    DenyAll,
                    Arc::clone(&verifier),
                    cat.authz.action.clone(),
                    environment,
                ));
            } else {
                let bearer =
                    (!cat.authz.bearer_token.is_empty()).then(|| cat.authz.bearer_token.clone());
                let provider = ConnectAuthzClient::new(cat.authz.endpoint.clone(), bearer);
                router = router.merge(catalog_router(
                    cache,
                    provider,
                    Arc::clone(&verifier),
                    cat.authz.action.clone(),
                    environment,
                ));
            }
            info!(
                "Catalog endpoint enabled (group attribute {})",
                cat.group_attribute_fqn
            );
        }

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", http_cfg.bind_port)).await?;
        info!(
            "HTTP tag API listening on port {} (tag prefix {:?})",
            http_cfg.bind_port, http_cfg.tag_prefix
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("HTTP tag API exited: {e}");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    node.shutdown().await?;
    info!("Done.");

    Ok(())
}

fn catalog_router<D: DecisionProvider>(
    cache: CatalogCache<tdf_iroh_s3::store::s3::S3Client>,
    provider: D,
    verifier: Arc<CwtVerifier>,
    action: String,
    environment: Option<serde_json::Value>,
) -> axum::Router {
    catalog_api::router(Arc::new(CatalogApiState {
        cache,
        provider,
        verifier,
        action,
        environment,
    }))
}
