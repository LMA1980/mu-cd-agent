//! Btrfs subvolume snapshotting and atomic candidate binary staging.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use mu_cd_ipc::{DeploymentSlot, StageDeploymentRequest, StageDeploymentResponse};
use serde::{Deserialize, Serialize};

use crate::error::AgentError;
use crate::manifest::AbRulesConfig;
use crate::slot::{read_active_slot_at, Slot};

const ARTIFACT_DIGEST_MARKER: &str = ".artifact_sha256";
const RETENTION_MANIFEST_FILE: &str = ".retention.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct SnapshotManifest {
    next_seq: u64,
    entries: Vec<SnapshotRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SnapshotRecord {
    name: String,
    slot: String,
    digest: String,
    seq: u64,
}

fn validate_snapshot_tag(raw: &str) -> Result<&str, AgentError> {
    if raw.is_empty()
        || raw.starts_with('.')
        || raw.contains("..")
        || raw.contains('/')
        || raw.contains('\\')
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(AgentError::Slot(format!(
            "Invalid snapshot digest/tag '{raw}': must match ^[A-Za-z0-9][A-Za-z0-9._-]*$"
        )));
    }
    Ok(raw)
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), AgentError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from_path = entry.path();
        let to_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_contents(&from_path, &to_path)?;
        } else if file_type.is_file() {
            fs::copy(&from_path, &to_path)?;
            if let Ok(meta) = fs::metadata(&from_path) {
                let _ = fs::set_permissions(&to_path, meta.permissions());
            }
        }
    }
    Ok(())
}

/// Permitted platform service binaries managed by `mu-cd-agent`.
///
/// Strictly scoped to platform application binaries — never the full host OS rootfs.
/// Retains legacy pre-M8 service names alongside M8-aligned names during 3-phase transition.
pub const ALLOWED_SERVICES: &[&str] = &[
    "action-runner",
    "action-runner-worker",
    "action-runner-controller",
    "action-runner-web",
    "muconsole",
    "mu-console",
    "mu-ci-web",
    "muregist",
    "muconde-agent",
    "muconde-controller",
    "muobserve",
    "muobserve-collector",
    "muobserve-sentinel",
    "model-runner",
    "k3-manager",
    "jero-manager",
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

/// Returns `true` when `service` refers to a static web frontend bundle served by Nginx.
pub fn is_static_web_service(service: &str) -> bool {
    matches!(
        service,
        "muconsole" | "mu-console" | "action-runner-web" | "mu-ci-web"
    )
}

/// Maps a logical or M8-aligned service name to candidate host binary names under `/usr/local/bin`.
pub fn candidate_binary_names(service: &str) -> &'static [&'static str] {
    match service {
        "action-runner" | "action-runner-worker" | "mu-ci-worker" => {
            &["mu-ci-worker", "action-runner"]
        }
        "action-runner-controller" | "mu-ci-controller" => {
            &["action-runner-controller", "mu-ci-controller"]
        }
        "muregist" | "mu-registry" => &["muregist", "mu-registry"],
        "muconde-agent" | "mu-cd-agent" => &["mu-cd-agent", "muconde-agent"],
        "muconde-controller" | "mu-cd-controller" => &["mu-cd-controller", "muconde-controller"],
        "muobserve" | "mu-observable-hub" => &["muobservectl", "muobserve", "mu-observable-hub"],
        "muobserve-collector" | "mu-observable-collector" => {
            &["muobserve-collector", "mu-observable-collector"]
        }
        "muobserve-sentinel" | "mu-observable-sentinel" => {
            &["muobserve-sentinel", "mu-observable-sentinel"]
        }
        "model-runner" | "jero-runner" | "k3-manager" | "jero-manager" => {
            &["k3-manager", "model-runner", "jero-runner"]
        }
        _ => &[],
    }
}

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
            // Emulate btrfs subvolume snapshot [-r] <src> <dest>
            if program == "btrfs"
                && args.len() >= 4
                && args[0] == "subvolume"
                && args[1] == "snapshot"
            {
                let src = Path::new(args[args.len() - 2]);
                let dest = Path::new(args[args.len() - 1]);
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if src.is_dir() {
                    copy_dir_contents(src, dest)?;
                } else {
                    let _ = fs::create_dir_all(dest);
                }
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

fn load_snapshot_manifest(snapshots_dir: &Path) -> SnapshotManifest {
    let manifest_path = snapshots_dir.join(RETENTION_MANIFEST_FILE);
    fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save_snapshot_manifest(
    snapshots_dir: &Path,
    manifest: &SnapshotManifest,
) -> Result<(), AgentError> {
    let manifest_path = snapshots_dir.join(RETENTION_MANIFEST_FILE);
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|e| AgentError::Serialization(e.to_string()))?;
    fs::write(manifest_path, json)?;
    Ok(())
}

fn ordered_snapshot_names(snapshots_dir: &Path, manifest: &SnapshotManifest) -> Vec<String> {
    if !snapshots_dir.is_dir() {
        return Vec::new();
    }
    let seq_by_name: HashMap<&str, u64> = manifest
        .entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry.seq))
        .collect();

    let mut items: Vec<(u64, u128, String)> = Vec::new();
    if let Ok(entries) = fs::read_dir(snapshots_dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if !file_name.starts_with("@snap-") {
                continue;
            }
            let seq = seq_by_name.get(file_name.as_str()).copied().unwrap_or(0);
            let mtime_nanos = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t: SystemTime| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            items.push((seq, mtime_nanos, file_name));
        }
    }

    items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    items.into_iter().map(|(_, _, name)| name).collect()
}

fn find_latest_snapshot_for_slot(
    service_dir: &Path,
    restore_slot: Slot,
) -> Result<Option<PathBuf>, AgentError> {
    let snapshots_dir = service_dir.join("snapshots");
    if !snapshots_dir.is_dir() {
        return Ok(None);
    }
    let manifest = load_snapshot_manifest(&snapshots_dir);
    let ordered = ordered_snapshot_names(&snapshots_dir, &manifest);

    // Prefer newest snapshot recorded explicitly for `restore_slot`
    for name in ordered.iter().rev() {
        if let Some(rec) = manifest.entries.iter().find(|r| &r.name == name) {
            if rec.slot == restore_slot.as_str() {
                let candidate = snapshots_dir.join(name);
                if candidate.is_dir() {
                    return Ok(Some(candidate));
                }
            }
        }
    }

    // Fallback to newest snapshot directory overall when manifest lacks slot metadata
    Ok(ordered
        .into_iter()
        .rev()
        .map(|name| snapshots_dir.join(name))
        .find(|path| path.is_dir()))
}

pub(crate) fn restore_slot_from_latest_snapshot_if_available(
    service_dir: &Path,
    restore_slot: Slot,
    runner: &dyn CommandRunner,
) -> Result<Option<PathBuf>, AgentError> {
    let Some(snapshot_path) = find_latest_snapshot_for_slot(service_dir, restore_slot)? else {
        return Ok(None);
    };
    restore_slot_from_snapshot(service_dir, restore_slot, &snapshot_path, runner)?;
    Ok(Some(snapshot_path))
}

pub(crate) fn restore_slot_from_latest_snapshot(
    service_dir: &Path,
    restore_slot: Slot,
    runner: &dyn CommandRunner,
) -> Result<PathBuf, AgentError> {
    let snapshot_path =
        find_latest_snapshot_for_slot(service_dir, restore_slot)?.ok_or_else(|| {
            AgentError::Slot(format!(
                "No read-only Btrfs snapshot available in {} for slot {}",
                service_dir.join("snapshots").display(),
                restore_slot.as_str()
            ))
        })?;
    restore_slot_from_snapshot(service_dir, restore_slot, &snapshot_path, runner)?;
    Ok(snapshot_path)
}

fn restore_slot_from_snapshot(
    service_dir: &Path,
    restore_slot: Slot,
    snapshot_path: &Path,
    runner: &dyn CommandRunner,
) -> Result<(), AgentError> {
    let target_slot_dir = service_dir.join(restore_slot.as_str());
    let target_str = target_slot_dir.to_str().unwrap_or("");
    let _ = runner.run_command("btrfs", &["subvolume", "delete", target_str]);
    if target_slot_dir.exists() {
        let _ = fs::remove_dir_all(&target_slot_dir);
    }

    let snap_str = snapshot_path.to_str().unwrap_or("");
    runner.run_command("btrfs", &["subvolume", "snapshot", snap_str, target_str])?;
    Ok(())
}

/// Receipt detailing a completed staging preparation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedStaging {
    pub active_slot_before: Option<Slot>,
    pub staged_slot: Slot,
    pub staged_binary_path: PathBuf,
    pub snapshot_path: Option<PathBuf>,
    pub pruned_snapshots: Vec<String>,
}

/// Manager for per-service Btrfs subvolumes and binary staging.
pub struct BtrfsManager {
    root_dir: PathBuf,
    runner: Arc<dyn CommandRunner>,
    ab_rules: AbRulesConfig,
}

impl BtrfsManager {
    pub fn new(root_dir: impl Into<PathBuf>, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            root_dir: root_dir.into(),
            runner,
            ab_rules: AbRulesConfig::default(),
        }
    }

    /// Configures declarative [`AbRulesConfig`] snapshot and rollback rules.
    pub fn with_ab_rules(mut self, ab_rules: AbRulesConfig) -> Self {
        self.ab_rules = ab_rules;
        self
    }

    pub fn ab_rules(&self) -> &AbRulesConfig {
        &self.ab_rules
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

    /// Resolves the live slot (`@a` or `@b`) from `<svc>/current`.
    pub fn read_active_slot(&self, service: &str) -> Result<Option<Slot>, AgentError> {
        validate_service_name(service)?;
        read_active_slot_at(&self.service_dir(service))
    }

    /// Reads the staged/active artifact SHA-256 marker recorded inside `<svc>/<slot>/.artifact_sha256`.
    pub fn read_slot_digest(
        &self,
        service: &str,
        slot: Slot,
    ) -> Result<Option<String>, AgentError> {
        validate_service_name(service)?;
        let marker = self
            .slot_dir(service, slot.as_str())
            .join(ARTIFACT_DIGEST_MARKER);
        if !marker.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(marker)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_string()))
        }
    }

    /// Lists retained `@snap-*` snapshots for `service`, ordered oldest to newest.
    pub fn list_snapshots(&self, service: &str) -> Result<Vec<String>, AgentError> {
        validate_service_name(service)?;
        let snapshots_dir = self.snapshots_dir(service);
        let manifest = load_snapshot_manifest(&snapshots_dir);
        Ok(ordered_snapshot_names(&snapshots_dir, &manifest))
    }

    /// Prunes the oldest `@snap-*` subvolumes exceeding `keep_snapshots`.
    pub fn prune_snapshots(
        &self,
        service: &str,
        keep_snapshots: usize,
    ) -> Result<Vec<String>, AgentError> {
        validate_service_name(service)?;
        let snapshots_dir = self.snapshots_dir(service);
        if !snapshots_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut manifest = load_snapshot_manifest(&snapshots_dir);
        let ordered = ordered_snapshot_names(&snapshots_dir, &manifest);
        let excess = ordered.len().saturating_sub(keep_snapshots);
        if excess == 0 {
            return Ok(Vec::new());
        }

        let mut pruned = Vec::with_capacity(excess);
        for snap_name in ordered.into_iter().take(excess) {
            let snap_path = snapshots_dir.join(&snap_name);
            let snap_str = snap_path.to_str().unwrap_or("");
            let _ = self
                .runner
                .run_command("btrfs", &["subvolume", "delete", snap_str]);
            if snap_path.exists() {
                fs::remove_dir_all(&snap_path)?;
            }
            manifest.entries.retain(|entry| entry.name != snap_name);
            pruned.push(snap_name);
        }
        save_snapshot_manifest(&snapshots_dir, &manifest)?;
        Ok(pruned)
    }

    /// Prepares the symmetric candidate slot (`active.other()`, defaulting to `@b` on
    /// uninitialized layouts) for the given service using configured `ab_rules`.
    pub fn prepare_staging_slot(
        &self,
        service: &str,
        candidate_binary_path: &Path,
        digest: &str,
        prev_digest: &str,
    ) -> Result<PathBuf, AgentError> {
        let prepared = self.prepare_staging_slot_with_rules(
            service,
            candidate_binary_path,
            digest,
            prev_digest,
            None,
            &self.ab_rules,
        )?;
        Ok(prepared.staged_binary_path)
    }

    /// Prepares the symmetric candidate slot (`live.other()` when `<svc>/current` exists,
    /// or `requested_target.unwrap_or(Slot::B)` during bootstrap), takes a read-only
    /// Btrfs snapshot of the active slot, prunes snapshots per `rules.keep_snapshots`,
    /// and installs `candidate_binary_path` into `<candidate>/bin/<service>`.
    pub fn prepare_staging_slot_with_rules(
        &self,
        service: &str,
        candidate_binary_path: &Path,
        digest: &str,
        prev_digest: &str,
        requested_target: Option<Slot>,
        rules: &AbRulesConfig,
    ) -> Result<PreparedStaging, AgentError> {
        validate_service_name(service)?;

        let srv_dir = self.service_dir(service);
        let snapshots_dir = self.snapshots_dir(service);
        fs::create_dir_all(&snapshots_dir)?;

        let active_slot_before = read_active_slot_at(&srv_dir)?;
        let candidate_slot = match active_slot_before {
            Some(live) => {
                let symmetric = live.other();
                if let Some(req) = requested_target {
                    if req != symmetric {
                        tracing::warn!(
                            service = service,
                            live_slot = live.as_str(),
                            requested = req.as_str(),
                            using = symmetric.as_str(),
                            "Requested target_slot matches live active slot; enforcing live.other()"
                        );
                    }
                }
                symmetric
            }
            None => requested_target.unwrap_or(Slot::B),
        };
        let snapshot_source_slot = active_slot_before.unwrap_or_else(|| candidate_slot.other());
        let source_slot_dir = self.slot_dir(service, snapshot_source_slot.as_str());
        let candidate_slot_dir = self.slot_dir(service, candidate_slot.as_str());

        // Resolve prior digest from explicit argument, active slot marker, or "initial"
        let recorded_prev = self.read_slot_digest(service, snapshot_source_slot)?;
        let raw_snap_tag = if !prev_digest.is_empty() {
            prev_digest.to_string()
        } else {
            recorded_prev.unwrap_or_else(|| "initial".to_string())
        };
        let snap_tag = validate_snapshot_tag(&raw_snap_tag)?;

        // 1. Create read-only snapshot of active slot into snapshots/@snap-<prev_digest>
        let mut snapshot_path = None;
        if rules.btrfs_snapshots && (source_slot_dir.exists() || self.root_dir.is_relative()) {
            let snap_name = format!("@snap-{snap_tag}");
            let snapshot_dest = snapshots_dir.join(&snap_name);
            if snapshot_dest.exists() {
                let _ = self.runner.run_command(
                    "btrfs",
                    &["subvolume", "delete", snapshot_dest.to_str().unwrap_or("")],
                );
                if snapshot_dest.exists() {
                    let _ = fs::remove_dir_all(&snapshot_dest);
                }
            }

            let _ = self.runner.run_command(
                "btrfs",
                &[
                    "subvolume",
                    "snapshot",
                    "-r",
                    source_slot_dir
                        .to_str()
                        .unwrap_or(snapshot_source_slot.as_str()),
                    snapshot_dest.to_str().unwrap_or(""),
                ],
            )?;

            let mut manifest = load_snapshot_manifest(&snapshots_dir);
            manifest.next_seq = manifest.next_seq.saturating_add(1);
            let seq = manifest.next_seq;
            manifest.entries.retain(|entry| entry.name != snap_name);
            manifest.entries.push(SnapshotRecord {
                name: snap_name,
                slot: snapshot_source_slot.as_str().to_string(),
                digest: snap_tag.to_string(),
                seq,
            });
            save_snapshot_manifest(&snapshots_dir, &manifest)?;
            snapshot_path = Some(snapshot_dest);
        }

        // 2. Enforce retention policy on historical read-only snapshots
        let pruned_snapshots = self.prune_snapshots(service, rules.keep_snapshots)?;

        // 3. Recreate or reset writable staging subvolume (`candidate_slot`)
        let candidate_str = candidate_slot_dir
            .to_str()
            .unwrap_or(candidate_slot.as_str());
        let _ = self
            .runner
            .run_command("btrfs", &["subvolume", "delete", candidate_str]);
        if candidate_slot_dir.exists() {
            let _ = fs::remove_dir_all(&candidate_slot_dir);
        }

        self.runner
            .run_command("btrfs", &["subvolume", "create", candidate_str])?;

        let bin_dir = candidate_slot_dir.join("bin");
        fs::create_dir_all(&bin_dir)?;

        // 4. Install candidate binary into <candidate_slot>/bin/<service> using install -m 755
        let target_binary = bin_dir.join(service);
        let cand_str = candidate_binary_path.to_str().unwrap_or("");
        let target_str = target_binary.to_str().unwrap_or("");

        self.runner
            .run_command("install", &["-m", "755", cand_str, target_str])?;

        if target_binary.exists() {
            let mut perms = fs::metadata(&target_binary)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&target_binary, perms)?;
        }

        if !digest.trim().is_empty() && candidate_slot_dir.is_dir() {
            let _ = fs::write(
                candidate_slot_dir.join(ARTIFACT_DIGEST_MARKER),
                digest.trim(),
            );
        }

        if is_static_web_service(service) && self.root_dir == Path::new("/srv/muconde") {
            let _ = self.stage_static_web_bundle(service, &candidate_slot_dir);
        }

        tracing::info!(
            service = service,
            digest = digest,
            staged_slot = candidate_slot.as_str(),
            target = %target_binary.display(),
            pruned_count = pruned_snapshots.len(),
            "Successfully staged candidate binary into symmetric candidate slot"
        );

        Ok(PreparedStaging {
            active_slot_before,
            staged_slot: candidate_slot,
            staged_binary_path: target_binary,
            snapshot_path,
            pruned_snapshots,
        })
    }

    /// Synchronizes static web frontend assets (`dist/`) from the local Git checkout into `slot_dir/dist`.
    pub fn stage_static_web_bundle(
        &self,
        service: &str,
        slot_dir: &Path,
    ) -> Result<(), AgentError> {
        let repo_candidates: &[&str] = match service {
            "muconsole" | "mu-console" => &[
                "/home/lma1980/repository/MuConsole",
                "/home/lma1980/repository/mu-console",
                "/var/lib/action-runner/workspace/repos/LMA1980/mu-console",
            ],
            "action-runner-web" | "mu-ci-web" => &[
                "/home/lma1980/repository/ActionRunner-web",
                "/home/lma1980/repository/mu-ci-web",
                "/var/lib/action-runner/workspace/repos/LMA1980/mu-ci-web",
            ],
            _ => &[],
        };

        for repo in repo_candidates {
            let repo_path = Path::new(repo);
            if repo_path.join(".git").exists() {
                let _ = self
                    .runner
                    .run_command("git", &["-C", repo, "fetch", "origin", "main"]);
                let _ = self
                    .runner
                    .run_command("git", &["-C", repo, "reset", "--hard", "origin/main"]);
            }
            let dist_src = repo_path.join("dist");
            if dist_src.is_dir() {
                let dist_dest = slot_dir.join("dist");
                fs::create_dir_all(&dist_dest)?;
                let src_dot = format!("{}/.", dist_src.display());
                let _ = self
                    .runner
                    .run_command("cp", &["-a", &src_dot, dist_dest.to_str().unwrap_or("")]);
                return Ok(());
            }
        }
        Ok(())
    }

    /// Ensures that `candidate_path` (`/srv/muconde/staging/<artifact_sha256>`) exists before staging.
    ///
    /// If not already present on disk, resolves the artifact from:
    /// 1. Local `MuRegist` CAS blob store (`/var/lib/muregist/blobs/<sha256>`),
    /// 2. Shared CI release target directory (`/var/lib/action-runner/workspace/target_shared/release/<bin>`),
    /// 3. Installed host binary (`/usr/local/bin/<bin>`), or
    /// 4. Static web bundle stamp when `is_static_web_service(service)` is true.
    pub fn ensure_candidate_artifact(
        &self,
        service: &str,
        artifact_sha256: &str,
        candidate_path: &Path,
    ) -> Result<(), AgentError> {
        if candidate_path.exists() {
            return Ok(());
        }
        validate_service_name(service)?;
        if let Some(parent) = candidate_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // 1. Check MuRegist CAS blob
        let cas_blob = Path::new("/var/lib/muregist/blobs").join(artifact_sha256);
        if cas_blob.is_file() {
            fs::copy(&cas_blob, candidate_path)?;
            let mut perms = fs::metadata(candidate_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(candidate_path, perms)?;
            return Ok(());
        }

        // 2. Check static web service
        if is_static_web_service(service) {
            let stamp =
                format!("#!/bin/sh\n# static web bundle {service} {artifact_sha256}\nexit 0\n");
            fs::write(candidate_path, stamp.as_bytes())?;
            let mut perms = fs::metadata(candidate_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(candidate_path, perms)?;
            return Ok(());
        }

        // 3. Check built release binary or installed /usr/local/bin binary
        for bin in candidate_binary_names(service) {
            let candidates = [
                PathBuf::from(format!(
                    "/var/lib/action-runner/workspace/target_shared/release/{bin}"
                )),
                PathBuf::from(format!("/usr/local/bin/{bin}")),
            ];
            for src in candidates {
                if src.is_file() {
                    fs::copy(&src, candidate_path)?;
                    let mut perms = fs::metadata(candidate_path)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(candidate_path, perms)?;
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Handles incoming `StageDeploymentRequest` from `MuConDe-controller`, honoring symmetric
    /// `active.other()` staging whenever `<svc>/current` is set.
    pub fn handle_stage_deployment_request(
        &self,
        req: &StageDeploymentRequest,
        candidate_binary_path: &Path,
        prev_digest: &str,
    ) -> StageDeploymentResponse {
        self.handle_stage_deployment_request_with_rules(
            req,
            candidate_binary_path,
            prev_digest,
            &self.ab_rules,
        )
    }

    /// Handles `StageDeploymentRequest` under explicit [`AbRulesConfig`].
    pub fn handle_stage_deployment_request_with_rules(
        &self,
        req: &StageDeploymentRequest,
        candidate_binary_path: &Path,
        prev_digest: &str,
        rules: &AbRulesConfig,
    ) -> StageDeploymentResponse {
        let requested_slot = Slot::from(req.target_slot);
        match self.prepare_staging_slot_with_rules(
            &req.service_name,
            candidate_binary_path,
            &req.artifact_sha256,
            prev_digest,
            Some(requested_slot),
            rules,
        ) {
            Ok(prepared) => {
                let btrfs_subvolume_path =
                    self.slot_dir(&req.service_name, prepared.staged_slot.as_str());
                StageDeploymentResponse {
                    deployment_id: req.deployment_id.clone(),
                    target_slot: DeploymentSlot::from(prepared.staged_slot),
                    btrfs_subvolume_path: btrfs_subvolume_path.to_string_lossy().to_string(),
                    staged_ok: true,
                    error_message: None,
                }
            }
            Err(e) => {
                let fallback_slot = requested_slot.as_str();
                let btrfs_subvolume_path = self.slot_dir(&req.service_name, fallback_slot);
                StageDeploymentResponse {
                    deployment_id: req.deployment_id.clone(),
                    target_slot: req.target_slot,
                    btrfs_subvolume_path: btrfs_subvolume_path.to_string_lossy().to_string(),
                    staged_ok: false,
                    error_message: Some(e.to_string()),
                }
            }
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
        assert!(validate_service_name("muconsole").is_ok());
        assert!(validate_service_name("mu-console").is_ok());
        assert!(validate_service_name("mu-ci-web").is_ok());
        assert!(validate_service_name("action-runner-web").is_ok());
        assert!(validate_service_name("muobserve").is_ok());
        assert!(validate_service_name("muobserve-collector").is_ok());
        assert!(validate_service_name("muconde-controller").is_ok());
        assert!(validate_service_name("k3-manager").is_ok());
        assert!(is_static_web_service("muconsole"));
        assert!(is_static_web_service("mu-ci-web"));
        assert!(!is_static_web_service("mu-ci-worker"));

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

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_ping_pong_a_to_b_to_a_staging_retention_and_snapshot_rollback() {
        use crate::slot::SlotManager;
        use std::time::Instant;

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "mu-cd-agent";

        let runner = Arc::new(MockCommandRunner::new(true));
        let rules = AbRulesConfig {
            btrfs_snapshots: true,
            keep_snapshots: 2,
            auto_rollback_on_critical: true,
        };
        let btrfs = BtrfsManager::new(&root, runner.clone()).with_ab_rules(rules.clone());
        let slots = SlotManager::new(&root, runner.clone());

        // Seed initial @a production binary (v1) and point current -> @a
        let slot_a = btrfs.slot_dir(service, "@a");
        fs::create_dir_all(slot_a.join("bin")).unwrap();
        fs::write(slot_a.join("bin").join(service), b"v1-binary").unwrap();
        fs::write(slot_a.join(".artifact_sha256"), b"sha-v1").unwrap();
        slots.atomic_swap_active_slot(service, Slot::A).unwrap();
        assert_eq!(btrfs.read_active_slot(service).unwrap(), Some(Slot::A));

        // Cycle 1: Live @a -> stage v2 into @b (snapshots @a@sha-v1), promote @b
        let v2 = temp.path().join("cand-v2");
        fs::write(&v2, b"v2-binary").unwrap();
        let prep1 = btrfs
            .prepare_staging_slot_with_rules(service, &v2, "sha-v2", "", None, &rules)
            .unwrap();
        assert_eq!(prep1.active_slot_before, Some(Slot::A));
        assert_eq!(prep1.staged_slot, Slot::B);
        assert_eq!(
            fs::read(btrfs.slot_dir(service, "@b").join("bin").join(service)).unwrap(),
            b"v2-binary"
        );
        assert_eq!(
            btrfs.list_snapshots(service).unwrap(),
            vec!["@snap-sha-v1".to_string()]
        );
        slots.atomic_swap_active_slot(service, Slot::B).unwrap();
        assert_eq!(btrfs.read_active_slot(service).unwrap(), Some(Slot::B));

        // Cycle 2: Live @b -> stage v3 into @a (snapshots @b@sha-v2), promote @a
        let v3 = temp.path().join("cand-v3");
        fs::write(&v3, b"v3-binary").unwrap();
        let req_bad_slot = StageDeploymentRequest {
            deployment_id: "dep-2".into(),
            lease_id: "l-2".into(),
            service_name: service.into(),
            artifact_sha256: "sha-v3".into(),
            // Even if caller passes SlotB while @b is live, agent enforces live.other() (@a)
            target_slot: DeploymentSlot::SlotB,
        };
        let resp2 = btrfs.handle_stage_deployment_request(&req_bad_slot, &v3, "");
        assert!(resp2.staged_ok);
        assert_eq!(resp2.target_slot, DeploymentSlot::SlotA);
        assert!(resp2.btrfs_subvolume_path.ends_with("/@a"));
        assert_eq!(
            fs::read(btrfs.slot_dir(service, "@a").join("bin").join(service)).unwrap(),
            b"v3-binary"
        );
        // Live @b remains untouched until swap
        assert_eq!(
            fs::read(btrfs.slot_dir(service, "@b").join("bin").join(service)).unwrap(),
            b"v2-binary"
        );
        assert_eq!(
            btrfs.list_snapshots(service).unwrap(),
            vec!["@snap-sha-v1".to_string(), "@snap-sha-v2".to_string()]
        );
        slots.atomic_swap_active_slot(service, Slot::A).unwrap();
        assert_eq!(btrfs.read_active_slot(service).unwrap(), Some(Slot::A));

        // Cycle 3: Live @a -> stage v4 into @b; keep_snapshots=2 prunes oldest (@snap-sha-v1)
        let v4 = temp.path().join("cand-v4");
        fs::write(&v4, b"v4-binary").unwrap();
        let prep3 = btrfs
            .prepare_staging_slot_with_rules(service, &v4, "sha-v4", "", None, &rules)
            .unwrap();
        assert_eq!(prep3.staged_slot, Slot::B);
        assert_eq!(prep3.pruned_snapshots, vec!["@snap-sha-v1".to_string()]);
        assert_eq!(
            btrfs.list_snapshots(service).unwrap(),
            vec!["@snap-sha-v2".to_string(), "@snap-sha-v3".to_string()]
        );
        slots.atomic_swap_active_slot(service, Slot::B).unwrap();

        // Simulate missing @a prior slot dir and verify <1s rollback restores @snap-sha-v3 into @a
        fs::remove_dir_all(btrfs.slot_dir(service, "@a")).unwrap();
        let start = Instant::now();
        let rb_receipt = slots
            .rollback_to_prior_slot(service, Some(Slot::A))
            .expect("atomic rollback restoring read-only snapshot");
        let elapsed_ms = start.elapsed().as_millis();
        assert!(elapsed_ms < 1000, "Rollback took {}ms", elapsed_ms);
        assert_eq!(rb_receipt.active_slot, Slot::A);
        assert_eq!(btrfs.read_active_slot(service).unwrap(), Some(Slot::A));
        assert_eq!(
            fs::read(btrfs.slot_dir(service, "@a").join("bin").join(service)).unwrap(),
            b"v3-binary"
        );
    }
}
