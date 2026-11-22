//! Declarative deployment manifest (`mu-cd.yml` / `MuConDe.yml`) and A/B rules.

#![deny(unsafe_code)]

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;
use crate::gate::IntegrationTestSelection;

/// Default number of historical read-only Btrfs snapshots retained per service.
pub const DEFAULT_KEEP_SNAPSHOTS: usize = 5;

/// Declarative A/B deployment and snapshot retention rules (`ab_rules` in `mu-cd.yml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AbRulesConfig {
    /// Take a read-only Btrfs snapshot of the active slot prior to staging candidate bytes.
    pub btrfs_snapshots: bool,
    /// Maximum number of historical read-only snapshots retained per service.
    pub keep_snapshots: usize,
    /// Trigger immediate atomic rollback and artifact taint on any critical test failure.
    pub auto_rollback_on_critical: bool,
}

impl Default for AbRulesConfig {
    fn default() -> Self {
        Self {
            btrfs_snapshots: true,
            keep_snapshots: DEFAULT_KEEP_SNAPSHOTS,
            auto_rollback_on_critical: true,
        }
    }
}

/// Deserializes either `"all"` or a list of integration test names from `mu-cd.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RawIntegrationTestsField {
    All(String),
    Selected(Vec<String>),
}

impl Default for RawIntegrationTestsField {
    fn default() -> Self {
        Self::All("all".to_string())
    }
}

impl RawIntegrationTestsField {
    /// Converts the raw YAML field into an [`IntegrationTestSelection`], failing closed on
    /// unknown scalar strings other than `"all"`.
    pub fn into_selection(&self) -> Result<IntegrationTestSelection, AgentError> {
        match self {
            Self::All(s) => {
                let trimmed = s.trim();
                if trimmed.eq_ignore_ascii_case("all") {
                    Ok(IntegrationTestSelection::All)
                } else if trimmed.is_empty() {
                    Err(AgentError::Config(
                        "integration_tests scalar must be 'all' or a non-empty list".into(),
                    ))
                } else {
                    Ok(IntegrationTestSelection::Selected(
                        vec![trimmed.to_string()],
                    ))
                }
            }
            Self::Selected(list) => {
                if list.is_empty() {
                    return Err(AgentError::Config(
                        "integration_tests list must not be empty; use 'all' or specify tests"
                            .into(),
                    ));
                }
                if list.iter().any(|name| name.trim().is_empty()) {
                    return Err(AgentError::Config(
                        "integration_tests entries must be non-empty".into(),
                    ));
                }
                Ok(IntegrationTestSelection::from_names(list))
            }
        }
    }
}

/// Declarative deployment target and binary/systemd unit overrides (`deployment` in `mu-cd.yml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DeploymentConfig {
    pub target_nodes: Vec<String>,
    pub binary: Option<String>,
    pub install_path: Option<String>,
    pub systemd_unit: Option<String>,
    pub web_root: Option<String>,
    pub artifact: Option<String>,
    #[serde(default)]
    pub self_upgrade_guard: bool,
}

impl DeploymentConfig {
    /// Returns the trimmed `binary` override when non-empty.
    pub fn normalized_binary(&self) -> Option<&str> {
        self.binary
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Returns the trimmed `install_path` override when non-empty.
    pub fn normalized_install_path(&self) -> Option<&str> {
        self.install_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// Returns the trimmed `systemd_unit` override with a `.service` suffix when no unit type suffix is present.
    pub fn normalized_systemd_unit(&self) -> Option<String> {
        let trimmed = self
            .systemd_unit
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        if trimmed.contains('.') {
            Some(trimmed.to_string())
        } else {
            Some(format!("{trimmed}.service"))
        }
    }

    /// Returns the trimmed `web_root` override when non-empty.
    pub fn normalized_web_root(&self) -> Option<&str> {
        self.web_root
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

/// Declarative per-service deployment contract parsed from `.mucd/mu-cd.yml`
/// or legacy `.muconde/MuConDe.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MuCdManifest {
    pub version: Option<String>,
    pub service: Option<String>,
    #[serde(default)]
    pub target_nodes: Vec<String>,
    #[serde(default)]
    pub integration_tests: RawIntegrationTestsField,
    #[serde(default)]
    pub it_archive_digest: Option<String>,
    #[serde(default)]
    pub ab_rules: AbRulesConfig,
    #[serde(default)]
    pub deployment: DeploymentConfig,
}

impl MuCdManifest {
    /// Parses a YAML string into a validated [`MuCdManifest`].
    pub fn from_yaml_str(yaml: &str) -> Result<Self, AgentError> {
        let parsed: Self =
            serde_yaml::from_str(yaml).map_err(|e| AgentError::Config(e.to_string()))?;
        let _ = parsed.integration_tests.into_selection()?;
        Ok(parsed)
    }

    /// Loads `.mucd/mu-cd.yml` (preferred) or `.muconde/MuConDe.yml` (legacy fallback)
    /// under `base_dir`, returning `Ok(None)` when neither file exists.
    pub fn load_optional_from_dir(base_dir: &Path) -> Result<Option<Self>, AgentError> {
        let primary = base_dir.join(".mucd").join("mu-cd.yml");
        let legacy = base_dir.join(".muconde").join("MuConDe.yml");
        let chosen = if primary.is_file() {
            primary
        } else if legacy.is_file() {
            legacy
        } else {
            return Ok(None);
        };
        let raw = fs::read_to_string(&chosen)
            .map_err(|e| AgentError::Config(format!("failed to read {}: {e}", chosen.display())))?;
        Self::from_yaml_str(&raw).map(Some)
    }

    /// Returns the validated integration test selection from this manifest.
    pub fn selection(&self) -> Result<IntegrationTestSelection, AgentError> {
        self.integration_tests.into_selection()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ab_rules_defaults() {
        let rules = AbRulesConfig::default();
        assert!(rules.btrfs_snapshots);
        assert_eq!(rules.keep_snapshots, DEFAULT_KEEP_SNAPSHOTS);
        assert!(rules.auto_rollback_on_critical);
    }

    #[test]
    fn test_parse_manifest_with_ab_rules_and_selected_tests() {
        let yaml = r#"
version: "1"
service: "mu-cd-agent"
it_archive_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
integration_tests:
  - "systemd_unit_active"
  - "it_smoke_http"
ab_rules:
  btrfs_snapshots: true
  keep_snapshots: 3
  auto_rollback_on_critical: true
"#;
        let manifest = MuCdManifest::from_yaml_str(yaml).expect("parse manifest");
        assert_eq!(manifest.service.as_deref(), Some("mu-cd-agent"));
        assert_eq!(
            manifest.ab_rules,
            AbRulesConfig {
                btrfs_snapshots: true,
                keep_snapshots: 3,
                auto_rollback_on_critical: true,
            }
        );
        assert_eq!(
            manifest.selection().unwrap(),
            IntegrationTestSelection::Selected(vec![
                "systemd_unit_active".into(),
                "it_smoke_http".into()
            ])
        );
    }

    #[test]
    fn test_parse_manifest_rejects_empty_list() {
        let yaml = r#"
version: "1"
service: "mu-cd-agent"
integration_tests: []
"#;
        let err = MuCdManifest::from_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, AgentError::Config(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_load_optional_from_dir_prefers_mucd_over_legacy() {
        let dir = tempdir().unwrap();
        let legacy_dir = dir.path().join(".muconde");
        fs::create_dir_all(&legacy_dir).unwrap();
        fs::write(
            legacy_dir.join("MuConDe.yml"),
            "version: \"1\"\nab_rules:\n  keep_snapshots: 2\n",
        )
        .unwrap();
        let loaded = MuCdManifest::load_optional_from_dir(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.ab_rules.keep_snapshots, 2);

        let primary_dir = dir.path().join(".mucd");
        fs::create_dir_all(&primary_dir).unwrap();
        fs::write(
            primary_dir.join("mu-cd.yml"),
            "version: \"1\"\nab_rules:\n  keep_snapshots: 4\n",
        )
        .unwrap();
        let loaded_primary = MuCdManifest::load_optional_from_dir(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(loaded_primary.ab_rules.keep_snapshots, 4);
    }

    #[test]
    fn test_parse_manifest_deployment_block_and_defaults() {
        let yaml_daemon = r#"
version: "1"
service: "mu-cd-agent"
target_nodes:
  - "node-a"
  - "worker-riscv64"
  - "worker-aarch64"
integration_tests: "all"
deployment:
  target_nodes:
    - "node-a"
    - "worker-riscv64"
    - "worker-aarch64"
  binary: "mu-cd-agent"
  install_path: "/usr/local/bin/mu-cd-agent"
  systemd_unit: "mu-cd-agent"
  self_upgrade_guard: true
"#;
        let daemon = MuCdManifest::from_yaml_str(yaml_daemon).expect("parse daemon manifest");
        assert!(daemon.deployment.self_upgrade_guard);
        assert_eq!(
            daemon.target_nodes,
            vec!["node-a", "worker-riscv64", "worker-aarch64"]
        );
        assert_eq!(daemon.deployment.normalized_binary(), Some("mu-cd-agent"));
        assert_eq!(
            daemon.deployment.normalized_install_path(),
            Some("/usr/local/bin/mu-cd-agent")
        );
        assert_eq!(
            daemon.deployment.normalized_systemd_unit().as_deref(),
            Some("mu-cd-agent.service")
        );

        let yaml_web = r#"
version: "1"
service: "muconsole"
integration_tests: "all"
deployment:
  web_root: "/var/www/muconsole"
  artifact: "dist"
"#;
        let web = MuCdManifest::from_yaml_str(yaml_web).expect("parse web manifest");
        assert_eq!(
            web.deployment.normalized_web_root(),
            Some("/var/www/muconsole")
        );
        assert_eq!(web.deployment.artifact.as_deref(), Some("dist"));

        let yaml_minimal = "version: \"1\"\nservice: \"mu-registry\"\n";
        let minimal = MuCdManifest::from_yaml_str(yaml_minimal).expect("parse minimal manifest");
        assert_eq!(minimal.deployment, DeploymentConfig::default());
        assert!(minimal.deployment.normalized_binary().is_none());
        assert!(minimal.deployment.normalized_systemd_unit().is_none());
    }
}
