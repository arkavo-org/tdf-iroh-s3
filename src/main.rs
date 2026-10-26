use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use std::sync::Arc;

use tdf_iroh_s3::attributes::{self, AttributeSet};
use tdf_iroh_s3::auth::CwtVerifier;
use tdf_iroh_s3::authz::{
    AuthZenClient, AuthzProtocol, ConnectAuthzClient, DecisionProvider, DenyAll,
    SharedDecisionProvider,
};
use tdf_iroh_s3::catalog_api::{self, CatalogApiState, CatalogCache};
use tdf_iroh_s3::catalogs_api;
use tdf_iroh_s3::catalogs_v2_api;
use tdf_iroh_s3::config::{AuthzConfig, Config, PublishDecisions};
use tdf_iroh_s3::moderation::{self, Moderation, ModerationApi, PublishGate, PublishPolicy};
use tdf_iroh_s3::node::TdfIrohNode;
use tdf_iroh_s3::node_api;
use tdf_iroh_s3::publish_decision::PublishDecider;
use tdf_iroh_s3::ssm;
use tdf_iroh_s3::store::s3::S3Client;
use tdf_iroh_s3::tags_api::{self, ApiState, TagPublishing};
use tdf_iroh_s3::tls;

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
            // The store's garbage collector logs at info each time it skips
            // a run, which it does every interval while no refused blob is
            // waiting for deletion.
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,iroh_blobs::store::gc=warn")),
        )
        .init();

    // reqwest pulls in ring and axum-server pulls in aws-lc-rs; with both
    // compiled in, rustls needs the process default chosen explicitly.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    let config = Config::from_file(&cli.config)?;
    info!("Config loaded from {:?}", cli.config);
    info!("S3: {}:{}", config.s3.bucket, config.s3.region);
    info!(
        "Required attributes: {:?}",
        config.validation.required_attributes
    );
    info!("Assertion check: {}", config.validation.assertion.enabled);

    // One decision service client, shared by the entitled catalog and the
    // publishing decisions (tdf-iroh-s3#35). Built only when one of them
    // uses it, since building it may read a secret from SSM.
    let provider =
        if config.catalog.enabled || config.publishing.decisions != PublishDecisions::Local {
            decision_provider(&config).await?
        } else {
            None
        };
    // A chain read back from a publish session carries no token, so the
    // OpenTDF client's token mode could never decide a push: every push
    // would be refused.
    if config.publishing.decisions != PublishDecisions::Local
        && config
            .catalog
            .authz
            .protocol
            .eq_ignore_ascii_case("opentdf-v2")
    {
        let entity_mode: tdf_iroh_s3::authz::EntityMode = config
            .catalog
            .authz
            .entity_mode
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        anyhow::ensure!(
            entity_mode == tdf_iroh_s3::authz::EntityMode::Claims,
            "[publishing] decisions = {:?} needs [catalog.authz] protocol authzen or entity_mode claims",
            config.publishing.decisions
        );
    }
    let environment = environment_entity(&config.catalog.authz);
    let decider = Arc::new(PublishDecider::new(
        config.publishing.decisions,
        provider.clone(),
        config.publishing.entitlement.clone(),
        environment.clone(),
    )?);
    info!("Publish decisions: {:?}", config.publishing.decisions);
    if decider.asks() && !config.publishing.required {
        tracing::warn!(
            "[publishing] decisions = {:?} has no effect while required = false",
            config.publishing.decisions
        );
    }

    // Creator publishing gate (tdf-iroh-s3#17). Moderation records are read
    // before the node accepts anything, and startup fails if they cannot be:
    // a node that forgot its suspensions must not come up.
    let gate = if config.publishing.required {
        let store = Arc::new(S3Client::from_config(&config.s3).await?);
        let view = Arc::new(Moderation::default());
        view.reload(store.as_ref())
            .await
            .context("Failed to load moderation records")?;
        view.spawn_refresh(
            Arc::clone(&store),
            std::time::Duration::from_secs(config.publishing.moderation_refresh_secs.max(5)),
        );
        info!(
            "Publishing gate on: entitlement {}, {} suspension(s), {} block(s)",
            config.publishing.entitlement,
            view.active_suspensions().len(),
            view.active_blocks().len()
        );
        if !config.http.enabled {
            tracing::warn!(
                "[publishing] required but [http] disabled: no publish session can be opened, so every push is refused"
            );
        }
        Some(Arc::new(
            PublishGate::new(view)
                .with_session_store(store)
                .with_decider(Arc::clone(&decider))
                .with_session_ttl(std::time::Duration::from_secs(
                    config.publishing.session_ttl_secs,
                )),
        ))
    } else {
        tracing::warn!("[publishing] required = false: pushes and tag writes are open");
        None
    };
    let moderation = gate.as_ref().map(|g| Arc::clone(&g.moderation));

    let node = TdfIrohNode::spawn_with_gate(config, gate.clone()).await?;
    let addr = node.addr();
    info!("Node running at {}", addr.id);
    info!(
        "Public addresses for GET /node: {:?}",
        node.config.iroh.public_addresses
    );

    // HTTP tag API (catalog discovery): GET resolution is public; PUT is
    // CWT-authenticated against the configured IdP key set.
    let mut https = None;
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
        let pub_cfg = &node.config.publishing;
        let policy = Arc::new(PublishPolicy {
            entitlement: Some(pub_cfg.entitlement.clone()).filter(|e| !e.is_empty()),
            audience: Some(pub_cfg.audience.clone()).filter(|a| !a.is_empty()),
            session_ttl: std::time::Duration::from_secs(pub_cfg.session_ttl_secs),
            operator_client_ids: pub_cfg.operator_client_ids.iter().cloned().collect(),
            decider: Arc::clone(&decider),
        });
        let state = Arc::new(ApiState {
            store: Arc::clone(&node.s3_client),
            verifier: Arc::clone(&verifier),
            tag_prefix: http_cfg.tag_prefix.clone(),
            catalog_documents: Default::default(),
            catalog: tdf_iroh_s3::tags_api::CatalogRules {
                token: http_cfg.catalog_token,
                accept_schema_1: http_cfg.accept_catalog_schema_1,
            },
            publishing: gate.as_ref().map(|g| TagPublishing {
                policy: Arc::clone(&policy),
                moderation: Arc::clone(&g.moderation),
            }),
        });
        // Tags and the creator catalog routes exist whenever HTTP does; on
        // an ungated node they still verify tokens but skip the publishing
        // checks.
        let v2 = catalogs_v2_api::state(
            Arc::clone(&state),
            &http_cfg.passkey_rp_id,
            &http_cfg.passkey_status_url,
        );
        let mut router = tags_api::router(Arc::clone(&state))
            .merge(catalogs_api::router(state))
            .merge(catalogs_v2_api::router(v2))
            .merge(node_api::router(node_api::live(
                node.endpoint().clone(),
                &node.config.iroh.public_addresses,
                node.config.validation.max_blob_bytes,
            )));
        if let Some(g) = &gate {
            if policy.operator_client_ids.is_empty() {
                tracing::warn!(
                    "[publishing] operator_client_ids empty: the moderation API answers 503"
                );
            }
            router = router.merge(moderation::router(Arc::new(ModerationApi {
                store: Arc::clone(&node.s3_client),
                verifier: Arc::clone(&verifier),
                gate: Arc::clone(g),
                policy: Arc::clone(&policy),
            })));
        }

        // Catalog: public attribute definitions + the entitled-catalog
        // endpoint. Attributes are never hardcoded — the definitions
        // artifact is the source of truth, and the grouping attribute must
        // be defined in it.
        let cat = &node.config.catalog;
        if cat.enabled {
            anyhow::ensure!(
                cat.attributes_url.is_empty() != cat.attributes_file.is_empty(),
                "[catalog] enabled requires exactly one of attributes_url (platform single source) or attributes_file (local artifact, node serves it)"
            );
            if !cat.attributes_url.is_empty() {
                // Single source of truth: the platform serves definitions
                // from the snapshot the PDP evaluates; this node only
                // validates its grouping attribute against it at startup.
                let fqns = attributes::fetch_attribute_fqns(&cat.attributes_url).await?;
                anyhow::ensure!(
                    fqns.iter().any(|f| f == &cat.group_attribute_fqn),
                    "[catalog] group_attribute_fqn {} is not defined at {}",
                    cat.group_attribute_fqn,
                    cat.attributes_url
                );
                info!(
                    "Attribute definitions validated against {} ({} attributes); definitions are served by the platform, not this node",
                    cat.attributes_url,
                    fqns.len()
                );
            } else {
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
            }

            let cache = CatalogCache::new(
                Arc::clone(&node.s3_client),
                std::time::Duration::from_secs(cat.cache_ttl_secs),
            );
            router = match &provider {
                Some(provider) => router.merge(catalog_router(
                    cache,
                    Arc::clone(provider),
                    Arc::clone(&verifier),
                    cat.authz.action.clone(),
                    environment.clone(),
                    moderation.clone(),
                    http_cfg.catalog_token,
                )),
                None => {
                    tracing::warn!(
                        "[catalog.authz] endpoint unset — catalog decisions fail closed (nothing entitled)"
                    );
                    router.merge(catalog_router(
                        cache,
                        DenyAll,
                        Arc::clone(&verifier),
                        cat.authz.action.clone(),
                        environment.clone(),
                        moderation.clone(),
                        http_cfg.catalog_token,
                    ))
                }
            };
            info!(
                "Catalog endpoint enabled (group attribute {})",
                cat.group_attribute_fqn
            );
        }

        if let Some(tls_cfg) = &http_cfg.tls {
            anyhow::ensure!(
                tls_cfg.bind_port != http_cfg.bind_port,
                "[http.tls] bind_port {} must differ from [http] bind_port",
                tls_cfg.bind_port
            );
        }
        // With TLS on, the plain listener stays for on-host checks only.
        let plain_host = if http_cfg.tls.is_some() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            http_cfg.bind_address
        };
        let listener = tokio::net::TcpListener::bind((plain_host, http_cfg.bind_port)).await?;
        info!(
            "HTTP API listening on {} (tag prefix {:?})",
            listener.local_addr()?,
            http_cfg.tag_prefix
        );
        if let Some(tls_cfg) = &http_cfg.tls {
            let tls_router = router.clone();
            let tls_cfg = tls_cfg.clone();
            https = Some(tokio::spawn(async move {
                tls::serve_https(&tls_cfg, tls_router).await
            }));
        }
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("HTTP tag API exited: {e}");
            }
        });
    }

    // With TLS on, HTTPS is the only externally reachable API: if it ends,
    // exit non-zero so systemd restarts the node instead of leaving it dark.
    // The same goes for the store's garbage collector, the only cleanup of
    // staged pushes: a restart starts a fresh one.
    let https = async {
        match https {
            Some(https) => match https.await {
                Ok(Ok(())) => anyhow::anyhow!("HTTPS listener stopped"),
                Ok(Err(e)) => e,
                Err(e) => anyhow::Error::from(e).context("HTTPS task"),
            },
            None => std::future::pending().await,
        }
    };
    let signal = tokio::select! {
        signal = shutdown_signal() => signal?,
        err = https => {
            node.shutdown().await?;
            return Err(err);
        }
        () = node.collector_stopped() => {
            node.shutdown().await?;
            anyhow::bail!("The store's garbage collector stopped; restarting for a fresh one");
        }
    };
    info!("{signal} received, shutting down...");
    node.shutdown().await?;
    info!("Done.");

    Ok(())
}

/// Wait for Ctrl-C (SIGINT) or, on Unix, SIGTERM, which is what systemd
/// sends on `systemctl stop`. Returns the signal's name.
async fn shutdown_signal() -> Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).context("Installing SIGTERM handler")?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                r.context("Waiting for Ctrl-C")?;
                Ok("SIGINT")
            }
            _ = term.recv() => Ok("SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("Waiting for Ctrl-C")?;
        Ok("Ctrl-C")
    }
}

/// The environment entity this node asserts (its region), if configured.
fn environment_entity(authz: &AuthzConfig) -> Option<serde_json::Value> {
    if authz.environment_region.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "kind": "environment",
        "region": authz.environment_region,
    }))
}

/// The decision service client from `[catalog.authz]`, or `None` when no
/// endpoint is configured.
async fn decision_provider(config: &Config) -> Result<Option<SharedDecisionProvider>> {
    let authz = &config.catalog.authz;
    if authz.endpoint.is_empty() {
        return Ok(None);
    }
    let credential = if !authz.token_url.is_empty() {
        // Secret resolution, in order of precedence. A long-lived
        // credential should never sit in the TOML, so config is the
        // least-preferred source (tests / local override):
        //   1. config client_secret
        //   2. CATALOG_AUTHZ_CLIENT_SECRET env var
        //   3. client_secret_param in SSM (the production path —
        //      mirrors the node-secret-key load in secret_key.rs;
        //      fetched decrypted via the instance role)
        let client_secret = if !authz.client_secret.is_empty() {
            authz.client_secret.clone()
        } else {
            let from_env = std::env::var("CATALOG_AUTHZ_CLIENT_SECRET").unwrap_or_default();
            if !from_env.is_empty() {
                from_env
            } else if !authz.client_secret_param.is_empty() {
                ssm::load_secret(&authz.client_secret_param, &config.s3.region)
                    .await
                    .with_context(|| {
                        format!(
                            "[catalog.authz] loading client secret from SSM parameter {}",
                            authz.client_secret_param
                        )
                    })?
            } else {
                String::new()
            }
        };
        anyhow::ensure!(
            !authz.client_id.is_empty() && !client_secret.is_empty(),
            "[catalog.authz] token_url requires client_id and a client secret \
             (config client_secret, CATALOG_AUTHZ_CLIENT_SECRET env, or client_secret_param in SSM)"
        );
        tdf_iroh_s3::authz::ServiceCredential::ClientCredentials {
            token_url: authz.token_url.clone(),
            client_id: authz.client_id.clone(),
            client_secret,
        }
    } else if !authz.bearer_token.is_empty() {
        tdf_iroh_s3::authz::ServiceCredential::Static(authz.bearer_token.clone())
    } else {
        tracing::warn!(
            "[catalog.authz] no credential configured — the platform requires an authenticated caller, decisions will be rejected"
        );
        tdf_iroh_s3::authz::ServiceCredential::None
    };
    let protocol: AuthzProtocol = authz
        .protocol
        .parse()
        .map_err(|e: String| anyhow::anyhow!("[catalog.authz] {e}"))?;
    let provider: SharedDecisionProvider = match protocol {
        AuthzProtocol::Authzen => {
            info!("Decision service protocol authzen (PDP {})", authz.endpoint);
            Arc::new(AuthZenClient::new(authz.endpoint.clone(), credential))
        }
        AuthzProtocol::OpentdfV2 => {
            let entity_mode: tdf_iroh_s3::authz::EntityMode = authz
                .entity_mode
                .parse()
                .map_err(|e: String| anyhow::anyhow!(e))?;
            info!(
                "Decision service protocol opentdf-v2 (PDP {})",
                authz.endpoint
            );
            Arc::new(ConnectAuthzClient::new(
                authz.endpoint.clone(),
                credential,
                entity_mode,
            ))
        }
    };
    Ok(Some(provider))
}

fn catalog_router<D: DecisionProvider>(
    cache: CatalogCache<tdf_iroh_s3::store::s3::S3Client>,
    provider: D,
    verifier: Arc<CwtVerifier>,
    action: String,
    environment: Option<serde_json::Value>,
    moderation: Option<Arc<Moderation>>,
    token: tdf_iroh_s3::config::CatalogToken,
) -> axum::Router {
    catalog_api::router(Arc::new(CatalogApiState {
        cache,
        provider,
        verifier,
        action,
        environment,
        moderation,
        token,
    }))
}
