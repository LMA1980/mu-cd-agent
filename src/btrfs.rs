//! Btrfs subvolume snapshotting and atomic candidate binary staging.

#![deny(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mu_cd_ipc::{DeploymentSlot, StageDeploymentRequest, StageDeploymentResponse};

use crate::error::AgentError;

/// Permitted platform service binaries managed by `mu-cd-agent`.
///
/// Strictly scoped to platform application binaries — never the full host OS rootfs.
/// Retains legacy pre-M8 service names alongside M8-aligned names during 3-phase transition.
pub const ALLOWED_SERVICES: &[&str] = &[
    "action-runner",
    "action-runner-controller",
    "muregist",
    "muconde-agent",
    "model-runner",
    "mu-ci-worker",
    "mu-ci-controller",
    "mu-registry",
    "mu-cd-agent",
    "mu-cd-controller",
    "mu-observable-hub",
    "mu-observable-collector",
    "mu-observable-sentinel",
    "jero-runner",
];

/// Validates a service name against path-traversal patterns and the platform allowlist.
pub fn validate_service_name(service: &str) -> Result<(), AgentError> {
    if service.is_empty() {
        return Err(AgentError::InvalidServiceName("empty service name".into()));
    }
    if service.contains("..") || service.contains('/') || service.contains('\\') {
        return Err(AgentError::PathTraversal(service.to_string()));
    }
    if !service
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AgentError::InvalidServiceName(service.to_string()));
    }
    if !ALLOWED_SERVICES.contains(&service) {
        return Err(AgentError::ServiceNotAllowed(service.to_string()));
    }
    Ok(())
}

/// Output of an executed external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Abstract runner for system operations (btrfs, install, systemctl).
pub trait CommandRunner: Send + Sync {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AgentError>;
}

/// Real system command runner that executes subprocesses on host Linux environments.
#[derive(Debug, Default)]
pub struct SystemCommandRunner;

impl SystemCommandRunner {
    pub fn new() -> Self {
        Self
    }
}

impl CommandRunner for SystemCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AgentError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(AgentError::Io)?;

        let status = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(AgentError::CommandFailed {
                command: format!("{} {}", program, args.join(" ")),
                exit_code: Some(status),
                stderr,
            });
        }

        Ok(CommandOutput {
            status,
            stdout,
            stderr,
        })
    }
}

/// Mock command runner recording invocations and optionally simulating filesystem effects.
#[derive(Debug, Default)]
pub struct MockCommandRunner {
    pub calls: Arc<Mutex<Vec<Vec<String>>>>,
    pub simulate_fs: bool,
    pub fail_command_prefix: Option<String>,
}

impl MockCommandRunner {
    pub fn new(simulate_fs: bool) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            simulate_fs,
            fail_command_prefix: None,
        }
    }

    pub fn with_failure(prefix: impl Into<String>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            simulate_fs: false,
            fail_command_prefix: Some(prefix.into()),
        }
    }

    pub fn recorded_calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for MockCommandRunner {
    fn run_command(&self, program: &str, args: &[&str]) -> Result<CommandOutput, AgentError> {
        let full_cmd: Vec<String> = std::iter::once(program.to_string())
            .chain(args.iter().map(|s| s.to_string()))
            .collect();
        let cmd_line = full_cmd.join(" ");

        self.calls.lock().unwrap().push(full_cmd.clone());

        if let Some(ref fail_prefix) = self.fail_command_prefix {
            if cmd_line.starts_with(fail_prefix) {
                return Err(AgentError::CommandFailed {
                    command: cmd_line,
                    exit_code: Some(1),
                    stderr: "Simulated command failure".into(),
                });
            }
        }

        if self.simulate_fs {
            // Emulate btrfs subvolume snapshot -r <src> <dest>
            if program == "btrfs"
                && args.len() >= 4
                && args[0] == "subvolume"
                && args[1] == "snapshot"
            {
                let dest = Path::new(args[args.len() - 1]);
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::create_dir_all(dest);
            } else if program == "btrfs"
                && args.len() >= 3
                && args[0] == "subvolume"
                && args[1] == "delete"
            {
                let target = Path::new(args[2]);
                if target.exists() {
                    let _ = fs::remove_dir_all(target);
                }
            } else if program == "btrfs"
                && args.len() >= 3
                && args[0] == "subvolume"
                && args[1] == "create"
            {
                let target = Path::new(args[2]);
                let _ = fs::create_dir_all(target);
            } else if program == "install" && args.len() >= 4 && args[0] == "-m" && args[1] == "755"
            {
                let src = Path::new(args[2]);
                let dest = Path::new(args[3]);
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if src.exists() {
                    let bytes = fs::read(src).map_err(AgentError::Io)?;
                    fs::write(dest, bytes).map_err(AgentError::Io)?;
                } else {
                    fs::write(dest, b"#!/bin/sh\necho mock\n").map_err(AgentError::Io)?;
                }
                let mut perms = fs::metadata(dest).map_err(AgentError::Io)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(dest, perms).map_err(AgentError::Io)?;
            }
        }

        Ok(CommandOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

/// Manager for per-service Btrfs subvolumes and binary staging.
pub struct BtrfsManager {
    root_dir: PathBuf,
    runner: Arc<dyn CommandRunner>,
}

impl BtrfsManager {
    pub fn new(root_dir: impl Into<PathBuf>, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            root_dir: root_dir.into(),
            runner,
        }
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn service_dir(&self, service: &str) -> PathBuf {
        self.root_dir.join(service)
    }

    pub fn snapshots_dir(&self, service: &str) -> PathBuf {
        self.service_dir(service).join("snapshots")
    }

    pub fn slot_dir(&self, service: &str, slot_name: &str) -> PathBuf {
        self.service_dir(service).join(slot_name)
    }

    /// Prepares staging slot `@b` for the given service:
    /// 1. Takes read-only Btrfs snapshot of current active slot `@a` into `snapshots/@snap-<prev_digest>`.
    /// 2. Resets writable staging subvolume `@b` (`delete` if exists, then `create`).
    /// 3. Installs candidate binary into `@b/bin/<service>` using `install -m 755` semantics.
    pub fn prepare_staging_slot(
        &self,
        service: &str,
        candidate_binary_path: &Path,
        digest: &str,
        prev_digest: &str,
    ) -> Result<PathBuf, AgentError> {
        validate_service_name(service)?;

        let srv_dir = self.service_dir(service);
        let snapshots_dir = srv_dir.join("snapshots");
        let slot_a = self.slot_dir(service, "@a");
        let slot_b = self.slot_dir(service, "@b");

        // Ensure service root and snapshots container directories exist
        fs::create_dir_all(&snapshots_dir)?;

        // 1. Create read-only snapshot of current active slot (@a) into snapshots/@snap-<prev_digest>
        let snap_tag = if prev_digest.is_empty() {
            "initial"
        } else {
            prev_digest
        };
        let snapshot_dest = snapshots_dir.join(format!("@snap-{}", snap_tag));

        // Only snapshot if slot @a exists (or mock runner simulates it)
        if slot_a.exists() || self.root_dir.is_relative() {
            let _ = self.runner.run_command(
                "btrfs",
                &[
                    "subvolume",
                    "snapshot",
                    "-r",
                    slot_a.to_str().unwrap_or("@a"),
                    snapshot_dest.to_str().unwrap_or(""),
                ],
            )?;
        }

        // 2. Recreate or reset writable staging subvolume @b
        let slot_b_str = slot_b.to_str().unwrap_or("@b");
        // Delete if present (ignore non-zero status if subvolume does not yet exist)
        let _ = self
            .runner
            .run_command("btrfs", &["subvolume", "delete", slot_b_str]);

        self.runner
            .run_command("btrfs", &["subvolume", "create", slot_b_str])?;

        let bin_dir = slot_b.join("bin");
        fs::create_dir_all(&bin_dir)?;

        // 3. Install candidate binary into @b/bin/<service> using install -m 755
        let target_binary = bin_dir.join(service);
        let cand_str = candidate_binary_path.to_str().unwrap_or("");
        let target_str = target_binary.to_str().unwrap_or("");

        self.runner
            .run_command("install", &["-m", "755", cand_str, target_str])?;

        // On POSIX systems, verify and guarantee 0755 permissions
        if target_binary.exists() {
            let mut perms = fs::metadata(&target_binary)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&target_binary, perms)?;
        }

        tracing::info!(
            service = service,
            digest = digest,
            target = %target_binary.display(),
            "Successfully staged candidate binary into slot @b"
        );

        Ok(target_binary)
    }

    /// Handles incoming `StageDeploymentRequest` from `MuConDe-controller`.
    pub fn handle_stage_deployment_request(
        &self,
        req: &StageDeploymentRequest,
        candidate_binary_path: &Path,
        prev_digest: &str,
    ) -> StageDeploymentResponse {
        let slot_str = match req.target_slot {
            DeploymentSlot::SlotA => "@a",
            DeploymentSlot::SlotB => "@b",
        };
        let btrfs_subvolume_path = self.slot_dir(&req.service_name, slot_str);

        match self.prepare_staging_slot(
            &req.service_name,
            candidate_binary_path,
            &req.artifact_sha256,
            prev_digest,
        ) {
            Ok(_) => StageDeploymentResponse {
                deployment_id: req.deployment_id.clone(),
                target_slot: req.target_slot,
                btrfs_subvolume_path: btrfs_subvolume_path.to_string_lossy().to_string(),
                staged_ok: true,
                error_message: None,
            },
            Err(e) => StageDeploymentResponse {
                deployment_id: req.deployment_id.clone(),
                target_slot: req.target_slot,
                btrfs_subvolume_path: btrfs_subvolume_path.to_string_lossy().to_string(),
                staged_ok: false,
                error_message: Some(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_service_name_validation() {
        assert!(validate_service_name("action-runner").is_ok());
        assert!(validate_service_name("action-runner-controller").is_ok());
        assert!(validate_service_name("muregist").is_ok());
        assert!(validate_service_name("muconde-agent").is_ok());
        assert!(validate_service_name("model-runner").is_ok());
        assert!(validate_service_name("mu-ci-worker").is_ok());
        assert!(validate_service_name("mu-ci-controller").is_ok());
        assert!(validate_service_name("mu-registry").is_ok());
        assert!(validate_service_name("mu-cd-agent").is_ok());
        assert!(validate_service_name("mu-cd-controller").is_ok());
        assert!(validate_service_name("mu-observable-hub").is_ok());
        assert!(validate_service_name("mu-observable-collector").is_ok());
        assert!(validate_service_name("mu-observable-sentinel").is_ok());
        assert!(validate_service_name("jero-runner").is_ok());

        // Path traversal attempts
        assert!(matches!(
            validate_service_name("../action-runner"),
            Err(AgentError::PathTraversal(_))
        ));
        assert!(matches!(
            validate_service_name("action-runner/evil"),
            Err(AgentError::PathTraversal(_))
        ));
        assert!(matches!(
            validate_service_name(r"action-runner\evil"),
            Err(AgentError::PathTraversal(_))
        ));

        // Invalid service not in allowlist
        assert!(matches!(
            validate_service_name("unauthorized-service"),
            Err(AgentError::ServiceNotAllowed(_))
        ));

        // Invalid characters
        assert!(matches!(
            validate_service_name("action_runner"),
            Err(AgentError::InvalidServiceName(_))
        ));
        assert!(matches!(
            validate_service_name(""),
            Err(AgentError::InvalidServiceName(_))
        ));
    }

    #[test]
    fn test_btrfs_command_construction_and_staging() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        fs::create_dir_all(&root).unwrap();

        // Create initial slot @a and candidate binary
        let service = "action-runner";
        let slot_a = root.join(service).join("@a");
        fs::create_dir_all(&slot_a).unwrap();

        let cand_bin = temp.path().join("candidate_binary");
        fs::write(&cand_bin, b"#!/bin/sh\necho test\n").unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let manager = BtrfsManager::new(&root, runner.clone());

        let staged_bin = manager
            .prepare_staging_slot(service, &cand_bin, "sha256-new", "sha256-old")
            .expect("prepare staging slot");

        assert_eq!(
            staged_bin,
            root.join(service).join("@b").join("bin").join(service)
        );
        assert!(staged_bin.exists());

        // Verify 0755 file permissions
        let perms = fs::metadata(&staged_bin).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);

        // Verify command sequence and arguments
        let calls = runner.recorded_calls();
        assert!(!calls.is_empty());

        // Snapshot command
        let snap_call = calls
            .iter()
            .find(|c| c.contains(&"snapshot".to_string()))
            .unwrap();
        assert_eq!(snap_call[0], "btrfs");
        assert_eq!(snap_call[1], "subvolume");
        assert_eq!(snap_call[2], "snapshot");
        assert_eq!(snap_call[3], "-r");
        assert!(snap_call[4].ends_with("@a"));
        assert!(snap_call[5].contains("@snap-sha256-old"));

        // Delete & create @b
        let create_call = calls
            .iter()
            .find(|c| c.contains(&"create".to_string()))
            .unwrap();
        assert_eq!(create_call[0], "btrfs");
        assert_eq!(create_call[1], "subvolume");
        assert_eq!(create_call[2], "create");
        assert!(create_call[3].ends_with("@b"));

        // Install command with -m 755
        let install_call = calls.iter().find(|c| c[0] == "install").unwrap();
        assert_eq!(install_call[1], "-m");
        assert_eq!(install_call[2], "755");
        assert_eq!(install_call[3], cand_bin.to_str().unwrap());
        assert_eq!(install_call[4], staged_bin.to_str().unwrap());
    }

    #[test]
    fn test_handle_stage_deployment_request() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let service = "model-runner";

        let cand_bin = temp.path().join("model-runner-bin");
        fs::write(&cand_bin, b"binary_data").unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let manager = BtrfsManager::new(root, runner);

        let req = StageDeploymentRequest {
            deployment_id: "dep-001".into(),
            lease_id: "lease-100".into(),
            service_name: service.into(),
            artifact_sha256: "deadbeef".into(),
            target_slot: DeploymentSlot::SlotB,
        };

        let resp = manager.handle_stage_deployment_request(&req, &cand_bin, "cafebabe");
        assert!(resp.staged_ok);
        assert_eq!(resp.deployment_id, "dep-001");
        assert_eq!(resp.target_slot, DeploymentSlot::SlotB);
        assert!(resp.error_message.is_none());
    }
}
