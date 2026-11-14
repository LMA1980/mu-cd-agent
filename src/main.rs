//! MuConDe-agent main daemon binary entry point.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use mu_cd_agent::{
    builtin_catalog, IntegrationTestSelection, MuConDeAgent, MuConDeAgentConfig,
    SystemCommandRunner, SystemHealthProber,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,mu_cd_agent=debug")),
        )
        .init();

    tracing::info!("Starting mu-cd-agent v{}", mu_cd_agent::agent_version());

    let node_id = std::env::var("MUCONDE_NODE_ID").unwrap_or_else(|_| "worker-node".into());
    let listen_addr =
        std::env::var("MUCONDE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8446".into());
    let muconde_root = std::env::var("MUCONDE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/srv/muconde"));

    let tls_ca_path = std::env::var("MUCONDE_TLS_CA_CERT").ok().map(PathBuf::from);
    let tls_cert_path = std::env::var("MUCONDE_TLS_SERVER_CERT")
        .ok()
        .map(PathBuf::from);
    let tls_key_path = std::env::var("MUCONDE_TLS_SERVER_KEY")
        .ok()
        .map(PathBuf::from);

    let manifest_dir = std::env::var("MUCONDE_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let manifest = mu_cd_agent::MuCdManifest::load_optional_from_dir(&manifest_dir)?;

    // Contract `integration_tests` selector: "all" (default) or a comma-separated list.
    let integration_tests = match std::env::var("MUCONDE_INTEGRATION_TESTS") {
        Ok(v) => {
            let trimmed = v.trim();
            if trimmed.eq_ignore_ascii_case("all") {
                IntegrationTestSelection::All
            } else {
                let names: Vec<String> = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if names.is_empty() {
                    return Err(mu_cd_agent::AgentError::Config(
                        "MUCONDE_INTEGRATION_TESTS must be 'all' or a non-empty list".into(),
                    )
                    .into());
                }
                IntegrationTestSelection::from_names(&names)
            }
        }
        Err(_) => match &manifest {
            Some(m) => m.selection()?,
            None => IntegrationTestSelection::default(),
        },
    };

    let manifest_digest = manifest.as_ref().and_then(|m| m.it_archive_digest.clone());
    let ab_rules = manifest
        .as_ref()
        .map(|m| m.ab_rules.clone())
        .unwrap_or_default();

    let config = MuConDeAgentConfig {
        node_id,
        listen_addr,
        muconde_root,
        tls_ca_path,
        tls_cert_path,
        tls_key_path,
        default_warmup_timeout_secs: 30,
        required_consecutive_successes: 3,
        collector_addr: std::env::var("MUOBSERVE_COLLECTOR_ADDR").ok(),
        integration_tests,
        gate_catalog: builtin_catalog(),
        ab_rules,
        it_archive_digest: std::env::var("MUCONDE_IT_ARCHIVE_DIGEST")
            .ok()
            .or(manifest_digest),
        it_bundle_id: std::env::var("MUCONDE_IT_BUNDLE_ID").ok(),
        registry_url: std::env::var("MUCONDE_REGISTRY_URL").ok(),
        cas_blobs_dir: std::env::var("MUCONDE_CAS_BLOBS_DIR")
            .ok()
            .map(PathBuf::from),
        ..MuConDeAgentConfig::default()
    };

    let runner = Arc::new(SystemCommandRunner::new());
    let prober = Arc::new(SystemHealthProber::new(runner.clone()));
    let agent = MuConDeAgent::new(config, runner, prober);

    agent.run().await?;

    Ok(())
}
