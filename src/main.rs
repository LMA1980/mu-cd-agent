//! mu-cd-agent main daemon binary entry point.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mu_cd_agent::slot::default_cd_root_with;
use mu_cd_agent::{
    builtin_catalog, first_non_empty_var, IntegrationTestSelection, ItSandboxConfig, MuCdManifest,
    MuConDeAgent, MuConDeAgentConfig, SystemCommandRunner, SystemHealthProber,
    DEFAULT_CANARY_PROFILE_PATH, DEFAULT_HOST_CEILING_PATH,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V")
    {
        println!("mu-cd-agent {}", mu_cd_agent::agent_version());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,mu_cd_agent=debug")),
        )
        .init();

    tracing::info!("Starting mu-cd-agent v{}", mu_cd_agent::agent_version());

    let env_lookup = |key: &str| std::env::var(key).ok();
    let config = build_agent_config_with(&env_lookup, |p| p.exists())?;
    let muconde_root = config.muconde_root.clone();

    let runner = Arc::new(SystemCommandRunner::new());
    let prober = Arc::new(SystemHealthProber::new(runner.clone()).with_muconde_root(&muconde_root));
    let agent = MuConDeAgent::new(config, runner, prober);

    agent.run().await?;

    Ok(())
}

fn build_agent_config_with(
    lookup: &dyn Fn(&str) -> Option<String>,
    exists: impl Fn(&Path) -> bool,
) -> Result<MuConDeAgentConfig, Box<dyn std::error::Error>> {
    let node_id = first_non_empty_var(
        lookup,
        &["MU_CD_AGENT_NODE_ID", "MU_CD_NODE_ID", "MUCONDE_NODE_ID"],
    )
    .unwrap_or_else(|| "worker-node".into());
    let listen_addr = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_LISTEN_ADDR",
            "MU_CD_LISTEN_ADDR",
            "MUCONDE_LISTEN_ADDR",
        ],
    )
    .unwrap_or_else(|| "0.0.0.0:8446".into());
    let muconde_root =
        first_non_empty_var(lookup, &["MU_CD_AGENT_ROOT", "MU_CD_ROOT", "MUCONDE_ROOT"])
            .map(PathBuf::from)
            .unwrap_or_else(|| default_cd_root_with(&exists));

    let tls_ca_path = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_TLS_CA_CERT",
            "MU_CD_TLS_CA_CERT",
            "MUCONDE_TLS_CA_CERT",
        ],
    )
    .map(PathBuf::from);
    let tls_cert_path = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_TLS_SERVER_CERT",
            "MU_CD_TLS_SERVER_CERT",
            "MUCONDE_TLS_SERVER_CERT",
        ],
    )
    .map(PathBuf::from);
    let tls_key_path = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_TLS_SERVER_KEY",
            "MU_CD_TLS_SERVER_KEY",
            "MUCONDE_TLS_SERVER_KEY",
        ],
    )
    .map(PathBuf::from);

    let manifest_dir = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_MANIFEST_DIR",
            "MU_CD_MANIFEST_DIR",
            "MUCONDE_MANIFEST_DIR",
        ],
    )
    .map(PathBuf::from)
    .unwrap_or_else(|| PathBuf::from("."));
    let manifest = MuCdManifest::load_optional_from_dir(&manifest_dir)?;

    // Contract `integration_tests` selector: "all" (default) or a comma-separated list.
    let integration_tests = match first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_INTEGRATION_TESTS",
            "MU_CD_INTEGRATION_TESTS",
            "MUCONDE_INTEGRATION_TESTS",
        ],
    ) {
        Some(v) => {
            if v.eq_ignore_ascii_case("all") {
                IntegrationTestSelection::All
            } else {
                let names: Vec<String> = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if names.is_empty() {
                    return Err(mu_cd_agent::AgentError::Config(
                        "MU_CD_AGENT_INTEGRATION_TESTS / MU_CD_INTEGRATION_TESTS / MUCONDE_INTEGRATION_TESTS must be 'all' or a non-empty list".into(),
                    )
                    .into());
                }
                IntegrationTestSelection::from_names(&names)
            }
        }
        None => match &manifest {
            Some(m) => m.selection()?,
            None => IntegrationTestSelection::default(),
        },
    };

    let manifest_digest = manifest.as_ref().and_then(|m| m.it_archive_digest.clone());
    let ab_rules = manifest
        .as_ref()
        .map(|m| m.ab_rules.clone())
        .unwrap_or_default();

    let collector_addr = first_non_empty_var(
        lookup,
        &[
            "MU_OBSERVABLE_COLLECTOR_ADDR",
            "MU_CD_AGENT_COLLECTOR_ADDR",
            "MU_CD_COLLECTOR_ADDR",
            "MUOBSERVE_COLLECTOR_ADDR",
        ],
    );
    let it_archive_digest = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_IT_ARCHIVE_DIGEST",
            "MU_CD_IT_ARCHIVE_DIGEST",
            "MUCONDE_IT_ARCHIVE_DIGEST",
        ],
    )
    .or(manifest_digest);
    let it_bundle_id = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_IT_BUNDLE_ID",
            "MU_CD_IT_BUNDLE_ID",
            "MUCONDE_IT_BUNDLE_ID",
        ],
    );

    let registry_url = resolve_registry_url(lookup);
    let registry_token = resolve_registry_token(lookup);
    let cas_blobs_dir = resolve_cas_blobs_dir(lookup);

    let host_ceiling_path = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_CEILING_PATH",
            "MU_CD_CEILING_PATH",
            "MU_ISOLATION_CEILING_PATH",
        ],
    )
    .map(PathBuf::from)
    .unwrap_or_else(|| PathBuf::from(DEFAULT_HOST_CEILING_PATH));

    let security_file_path = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_CANARY_PROFILE_PATH",
            "MU_CD_AGENT_SECURITY_FILE",
            "MU_CD_CANARY_PROFILE_PATH",
        ],
    )
    .map(PathBuf::from)
    .or_else(|| {
        let default_profile = PathBuf::from(DEFAULT_CANARY_PROFILE_PATH);
        exists(&default_profile).then_some(default_profile)
    });

    let it_sandbox = ItSandboxConfig {
        host_ceiling_path: Some(host_ceiling_path),
        security_file_path,
        ..ItSandboxConfig::default()
    };

    Ok(MuConDeAgentConfig {
        node_id,
        listen_addr,
        muconde_root,
        tls_ca_path,
        tls_cert_path,
        tls_key_path,
        default_warmup_timeout_secs: 30,
        required_consecutive_successes: 3,
        collector_addr,
        integration_tests,
        gate_catalog: builtin_catalog(),
        ab_rules,
        it_archive_digest,
        it_bundle_id,
        registry_url,
        registry_token,
        cas_blobs_dir,
        it_sandbox,
    })
}

fn resolve_registry_url(lookup: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_REGISTRY_URL",
            "MU_CD_REGISTRY_URL",
            "MU_REGISTRY_URL",
            "MUCONDE_REGISTRY_URL",
            "MUREGIST_URL",
        ],
    )
}

fn resolve_cas_blobs_dir(lookup: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_CAS_BLOBS_DIR",
            "MU_CD_CAS_BLOBS_DIR",
            "MU_REGISTRY_CAS_BLOBS_DIR",
            "MUCONDE_CAS_BLOBS_DIR",
            "MUREGIST_CAS_BLOBS_DIR",
        ],
    )
    .map(PathBuf::from)
}

fn resolve_registry_token(lookup: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(path) = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_REGISTRY_TOKEN_FILE",
            "MU_CD_REGISTRY_TOKEN_FILE",
            "MU_REGISTRY_TOKEN_FILE",
            "MUCONDE_REGISTRY_TOKEN_FILE",
            "MUREGIST_TOKEN_FILE",
        ],
    ) {
        return std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }
    if let Some(raw) = first_non_empty_var(
        lookup,
        &[
            "MU_CD_AGENT_REGISTRY_TOKEN",
            "MU_CD_REGISTRY_TOKEN",
            "MU_REGISTRY_TOKEN",
            "MUCONDE_REGISTRY_TOKEN",
            "MUREGIST_TOKEN",
        ],
    ) {
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
            (
                "MU_CD_AGENT_REGISTRY_URL",
                "https://agent-primary.example:8444",
            ),
            ("MU_REGISTRY_URL", "https://registry-alias.example:8444"),
            (
                "MUCONDE_REGISTRY_URL",
                "https://legacy-muconde.example:8444",
            ),
            ("MUREGIST_URL", "https://legacy.example:8444"),
            ("MU_CD_CAS_BLOBS_DIR", "/var/lib/mu-registry"),
            ("MUCONDE_CAS_BLOBS_DIR", "/srv/cas"),
            ("MUREGIST_CAS_BLOBS_DIR", "/var/lib/muregist"),
        ]);
        let lookup_pri = |k: &str| map_primary.get(k).map(|v| (*v).to_string());
        assert_eq!(
            resolve_registry_url(&lookup_pri).as_deref(),
            Some("https://agent-primary.example:8444")
        );
        assert_eq!(
            resolve_cas_blobs_dir(&lookup_pri),
            Some(PathBuf::from("/var/lib/mu-registry"))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_mu_cd_agent_env_precedence_and_muconde_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let manifest_dir = temp.path().to_str().unwrap().to_string();

        // 1. Canonical MU_CD_AGENT_* / MU_CD_* / MU_OBSERVABLE_* override legacy MUCONDE_* / MUOBSERVE_*
        let canonical = HashMap::from([
            ("MU_CD_AGENT_NODE_ID", "worker-riscv64".to_string()),
            ("MU_CD_NODE_ID", "node-fallback".to_string()),
            ("MUCONDE_NODE_ID", "legacy-node".to_string()),
            ("MU_CD_AGENT_LISTEN_ADDR", "127.0.0.1:9446".to_string()),
            ("MUCONDE_LISTEN_ADDR", "0.0.0.0:8446".to_string()),
            ("MU_CD_ROOT", "/srv/mucd".to_string()),
            ("MUCONDE_ROOT", "/srv/muconde".to_string()),
            ("MU_CD_AGENT_TLS_CA_CERT", "/etc/mu-cd/ca.crt".to_string()),
            ("MUCONDE_TLS_CA_CERT", "/etc/legacy/ca.crt".to_string()),
            ("MU_CD_TLS_SERVER_CERT", "/etc/mu-cd/srv.crt".to_string()),
            ("MUCONDE_TLS_SERVER_CERT", "/etc/legacy/srv.crt".to_string()),
            ("MU_CD_TLS_SERVER_KEY", "/etc/mu-cd/srv.key".to_string()),
            ("MUCONDE_TLS_SERVER_KEY", "/etc/legacy/srv.key".to_string()),
            ("MU_CD_AGENT_MANIFEST_DIR", manifest_dir.clone()),
            ("MUCONDE_MANIFEST_DIR", "/nonexistent".to_string()),
            ("MU_CD_INTEGRATION_TESTS", "systemd_unit_active".to_string()),
            ("MUCONDE_INTEGRATION_TESTS", "all".to_string()),
            ("MU_CD_IT_ARCHIVE_DIGEST", "a".repeat(64)),
            ("MUCONDE_IT_ARCHIVE_DIGEST", "b".repeat(64)),
            ("MU_CD_AGENT_IT_BUNDLE_ID", "bundle-new".to_string()),
            ("MUCONDE_IT_BUNDLE_ID", "bundle-old".to_string()),
            ("MU_OBSERVABLE_COLLECTOR_ADDR", "127.0.0.1:4319".to_string()),
            ("MUOBSERVE_COLLECTOR_ADDR", "127.0.0.1:9999".to_string()),
        ]);
        let cfg = build_agent_config_with(&|k| canonical.get(k).cloned(), |_| false).unwrap();
        assert_eq!(cfg.node_id, "worker-riscv64");
        assert_eq!(cfg.listen_addr, "127.0.0.1:9446");
        assert_eq!(cfg.muconde_root, PathBuf::from("/srv/mucd"));
        assert_eq!(cfg.tls_ca_path, Some(PathBuf::from("/etc/mu-cd/ca.crt")));
        assert_eq!(cfg.tls_cert_path, Some(PathBuf::from("/etc/mu-cd/srv.crt")));
        assert_eq!(cfg.tls_key_path, Some(PathBuf::from("/etc/mu-cd/srv.key")));
        assert_eq!(
            cfg.integration_tests,
            IntegrationTestSelection::Selected(vec!["systemd_unit_active".to_string()])
        );
        assert_eq!(cfg.it_archive_digest, Some("a".repeat(64)));
        assert_eq!(cfg.it_bundle_id.as_deref(), Some("bundle-new"));
        assert_eq!(cfg.collector_addr.as_deref(), Some("127.0.0.1:4319"));

        // 2. Legacy MUCONDE_* / MUOBSERVE_* still accepted when MU_CD_* absent
        let legacy = HashMap::from([
            ("MUCONDE_NODE_ID", "legacy-node".to_string()),
            ("MUCONDE_LISTEN_ADDR", "127.0.0.1:7446".to_string()),
            ("MUCONDE_ROOT", "/srv/muconde".to_string()),
            ("MUCONDE_MANIFEST_DIR", manifest_dir),
            ("MUCONDE_IT_ARCHIVE_DIGEST", "b".repeat(64)),
            ("MUCONDE_IT_BUNDLE_ID", "bundle-old".to_string()),
            ("MUOBSERVE_COLLECTOR_ADDR", "127.0.0.1:9999".to_string()),
        ]);
        let cfg_legacy = build_agent_config_with(&|k| legacy.get(k).cloned(), |_| false).unwrap();
        assert_eq!(cfg_legacy.node_id, "legacy-node");
        assert_eq!(cfg_legacy.listen_addr, "127.0.0.1:7446");
        assert_eq!(cfg_legacy.muconde_root, PathBuf::from("/srv/muconde"));
        assert_eq!(cfg_legacy.it_archive_digest, Some("b".repeat(64)));
        assert_eq!(cfg_legacy.it_bundle_id.as_deref(), Some("bundle-old"));
        assert_eq!(cfg_legacy.collector_addr.as_deref(), Some("127.0.0.1:9999"));

        // 3. Unset root falls back to /srv/muconde only if only /srv/muconde exists; else /srv/mucd
        let cfg_only_legacy =
            build_agent_config_with(&|k| (k == "MU_CD_NODE_ID").then(|| "n1".to_string()), |p| {
                p == Path::new("/srv/muconde")
            })
            .unwrap();
        assert_eq!(cfg_only_legacy.node_id, "n1");
        assert_eq!(cfg_only_legacy.muconde_root, PathBuf::from("/srv/muconde"));

        let cfg_fresh = build_agent_config_with(&|_| None, |_| false).unwrap();
        assert_eq!(cfg_fresh.muconde_root, PathBuf::from("/srv/mucd"));
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

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_host_ceiling_and_canary_profile_env_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let manifest_dir = temp.path().to_str().unwrap().to_string();

        // Default ceiling path when unset; auto-detects canary profile only when present
        let base_map = HashMap::from([("MU_CD_AGENT_MANIFEST_DIR", manifest_dir.clone())]);
        let cfg_default =
            build_agent_config_with(&|k| base_map.get(k).cloned(), |_| false).unwrap();
        assert_eq!(
            cfg_default.it_sandbox.host_ceiling_path,
            Some(PathBuf::from(DEFAULT_HOST_CEILING_PATH))
        );
        assert_eq!(cfg_default.it_sandbox.security_file_path, None);

        let cfg_with_profile = build_agent_config_with(&|k| base_map.get(k).cloned(), |p| {
            p == Path::new(DEFAULT_CANARY_PROFILE_PATH)
        })
        .unwrap();
        assert_eq!(
            cfg_with_profile.it_sandbox.security_file_path,
            Some(PathBuf::from(DEFAULT_CANARY_PROFILE_PATH))
        );

        // Explicit env overrides take precedence
        let override_map = HashMap::from([
            ("MU_CD_AGENT_MANIFEST_DIR", manifest_dir),
            (
                "MU_CD_AGENT_CEILING_PATH",
                "/custom/ceiling.yml".to_string(),
            ),
            (
                "MU_ISOLATION_CEILING_PATH",
                "/fallback/ceiling.yml".to_string(),
            ),
            (
                "MU_CD_AGENT_CANARY_PROFILE_PATH",
                "/custom/canary-profile.yml".to_string(),
            ),
        ]);
        let cfg_override =
            build_agent_config_with(&|k| override_map.get(k).cloned(), |_| false).unwrap();
        assert_eq!(
            cfg_override.it_sandbox.host_ceiling_path,
            Some(PathBuf::from("/custom/ceiling.yml"))
        );
        assert_eq!(
            cfg_override.it_sandbox.security_file_path,
            Some(PathBuf::from("/custom/canary-profile.yml"))
        );
    }
}
