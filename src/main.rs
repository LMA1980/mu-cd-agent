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

    let env_lookup = |key: &str| std::env::var(key).ok();
    let registry_url = resolve_registry_url(&env_lookup);
    let registry_token = resolve_registry_token(&env_lookup);
    let cas_blobs_dir = resolve_cas_blobs_dir(&env_lookup);

    let config = MuConDeAgentConfig {
        node_id,
        listen_addr,
        muconde_root: muconde_root.clone(),
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
        registry_url,
        registry_token,
        cas_blobs_dir,
        ..MuConDeAgentConfig::default()
    };

    let runner = Arc::new(SystemCommandRunner::new());
    let prober = Arc::new(SystemHealthProber::new(runner.clone()).with_muconde_root(&muconde_root));
    let agent = MuConDeAgent::new(config, runner, prober);

    agent.run().await?;

    Ok(())
}

fn first_non_empty_var<'a>(
    lookup: &dyn Fn(&str) -> Option<String>,
    keys: &[&'a str],
) -> Option<String> {
    for key in keys {
        if let Some(val) = lookup(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn resolve_registry_url(lookup: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    first_non_empty_var(lookup, &["MUCONDE_REGISTRY_URL", "MUREGIST_URL"])
}

fn resolve_cas_blobs_dir(lookup: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    first_non_empty_var(lookup, &["MUCONDE_CAS_BLOBS_DIR", "MUREGIST_CAS_BLOBS_DIR"])
        .map(PathBuf::from)
}

fn resolve_registry_token(lookup: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(path) = first_non_empty_var(
        lookup,
        &["MUCONDE_REGISTRY_TOKEN_FILE", "MUREGIST_TOKEN_FILE"],
    ) {
        return std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }
    if let Some(raw) = first_non_empty_var(lookup, &["MUCONDE_REGISTRY_TOKEN", "MUREGIST_TOKEN"]) {
        if raw.starts_with('/') {
            return std::fs::read_to_string(&raw)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
        }
        return Some(raw);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_registry_and_cas_env_fallback_precedence() {
        let map_fallback = HashMap::from([
            ("MUREGIST_URL", "https://registry.example:8444"),
            ("MUREGIST_CAS_BLOBS_DIR", "/var/lib/muregist"),
        ]);
        let lookup_fb = |k: &str| map_fallback.get(k).map(|v| (*v).to_string());
        assert_eq!(
            resolve_registry_url(&lookup_fb).as_deref(),
            Some("https://registry.example:8444")
        );
        assert_eq!(
            resolve_cas_blobs_dir(&lookup_fb),
            Some(PathBuf::from("/var/lib/muregist"))
        );

        let map_primary = HashMap::from([
            ("MUCONDE_REGISTRY_URL", "https://primary.example:8444"),
            ("MUREGIST_URL", "https://legacy.example:8444"),
            ("MUCONDE_CAS_BLOBS_DIR", "/srv/cas"),
            ("MUREGIST_CAS_BLOBS_DIR", "/var/lib/muregist"),
        ]);
        let lookup_pri = |k: &str| map_primary.get(k).map(|v| (*v).to_string());
        assert_eq!(
            resolve_registry_url(&lookup_pri).as_deref(),
            Some("https://primary.example:8444")
        );
        assert_eq!(
            resolve_cas_blobs_dir(&lookup_pri),
            Some(PathBuf::from("/srv/cas"))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_resolve_registry_token_file_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("token");
        std::fs::write(&token_path, "secret-token-123\n").unwrap();

        let map_good = HashMap::from([(
            "MUREGIST_TOKEN_FILE",
            token_path.to_str().unwrap().to_string(),
        )]);
        assert_eq!(
            resolve_registry_token(&|k| map_good.get(k).cloned()).as_deref(),
            Some("secret-token-123")
        );

        let map_missing =
            HashMap::from([("MUCONDE_REGISTRY_TOKEN_FILE", "/nonexistent/secret/token")]);
        assert_eq!(
            resolve_registry_token(&|k| map_missing.get(k).map(|v| (*v).to_string())),
            None
        );

        let map_missing_path_literal =
            HashMap::from([("MUREGIST_TOKEN", "/nonexistent/secret/token")]);
        assert_eq!(
            resolve_registry_token(&|k| map_missing_path_literal.get(k).map(|v| (*v).to_string())),
            None
        );
    }
}
