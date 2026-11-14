//! Dual A/B deployment slot management and atomic symlink swapping.

#![deny(unsafe_code)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mu_cd_ipc::DeploymentSlot;

use crate::btrfs::{validate_service_name, CommandRunner};
use crate::error::AgentError;

/// Deployment slot identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    /// String representation matching Btrfs subvolume naming (@a / @b).
    pub fn as_str(&self) -> &'static str {
        match self {
            Slot::A => "@a",
            Slot::B => "@b",
        }
    }

    /// Returns the opposite deployment slot (`A <-> B`) for symmetric ping-pong alternation.
    pub const fn other(self) -> Self {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// Resolves `@a` or `@b` (or a path ending with `/@a` or `/@b`) into a [`Slot`].
    pub fn from_target_str(target: &str) -> Option<Self> {
        let trimmed = target.trim_end_matches('/');
        if trimmed == "@a" || trimmed.ends_with("/@a") {
            Some(Slot::A)
        } else if trimmed == "@b" || trimmed.ends_with("/@b") {
            Some(Slot::B)
        } else {
            None
        }
    }
}

/// Resolves the currently active slot from `<service_dir>/current` without validating service allowlists.
pub(crate) fn read_active_slot_at(service_dir: &Path) -> Result<Option<Slot>, AgentError> {
    let link_path = service_dir.join("current");
    if !link_path.is_symlink() && !link_path.exists() {
        return Ok(None);
    }

    let target = fs::read_link(&link_path).map_err(AgentError::Io)?;
    let target_str = target.to_string_lossy();
    Slot::from_target_str(&target_str)
        .ok_or_else(|| {
            AgentError::Slot(format!(
                "Symlink {} points to unrecognized target: {}",
                link_path.display(),
                target_str
            ))
        })
        .map(Some)
}

impl From<DeploymentSlot> for Slot {
    fn from(slot: DeploymentSlot) -> Self {
        match slot {
            DeploymentSlot::SlotA => Slot::A,
            DeploymentSlot::SlotB => Slot::B,
        }
    }
}

impl From<Slot> for DeploymentSlot {
    fn from(slot: Slot) -> Self {
        match slot {
            Slot::A => DeploymentSlot::SlotA,
            Slot::B => DeploymentSlot::SlotB,
        }
    }
}

/// Verification receipt generated upon atomic slot pointer swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapReceipt {
    pub service: String,
    pub active_slot: Slot,
    pub swapped_at_epoch_ms: u64,
}

/// Manager responsible for atomic slot pointer swapping and systemd restarts.
pub struct SlotManager {
    root_dir: PathBuf,
    runner: Arc<dyn CommandRunner>,
}

impl SlotManager {
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

    pub fn current_symlink(&self, service: &str) -> PathBuf {
        self.service_dir(service).join("current")
    }

    /// Reads the currently active slot for the service by inspecting the `current` symlink.
    pub fn read_active_slot(&self, service: &str) -> Result<Option<Slot>, AgentError> {
        validate_service_name(service)?;
        read_active_slot_at(&self.service_dir(service))
    }

    /// Resolves the candidate target slot for the next deployment: `active.other()` when
    /// `<svc>/current` is set, or [`Slot::B`] on an uninitialized bootstrap layout.
    pub fn resolve_target_slot(&self, service: &str) -> Result<Slot, AgentError> {
        Ok(self
            .read_active_slot(service)?
            .map(Slot::other)
            .unwrap_or(Slot::B))
    }

    /// Rolls back atomically to `preferred_restore` (or the opposite of `<svc>/current`),
    /// restoring the target slot from its latest read-only Btrfs snapshot if missing.
    pub fn rollback_to_prior_slot(
        &self,
        service: &str,
        preferred_restore: Option<Slot>,
    ) -> Result<SwapReceipt, AgentError> {
        validate_service_name(service)?;
        let restore_slot = match preferred_restore {
            Some(slot) => slot,
            None => self
                .read_active_slot(service)?
                .map(Slot::other)
                .unwrap_or(Slot::A),
        };

        let srv_dir = self.service_dir(service);
        let slot_dir = srv_dir.join(restore_slot.as_str());
        if !slot_dir.exists() {
            crate::btrfs::restore_slot_from_latest_snapshot_if_available(
                &srv_dir,
                restore_slot,
                self.runner.as_ref(),
            )?;
        }

        self.atomic_swap_active_slot(service, restore_slot)
    }

    /// Restores `restore_slot` from the newest read-only snapshot of that slot (or latest
    /// available snapshot) and atomically switches `<svc>/current` to `restore_slot`.
    pub fn rollback_restoring_snapshot(
        &self,
        service: &str,
        restore_slot: Slot,
    ) -> Result<SwapReceipt, AgentError> {
        validate_service_name(service)?;
        let srv_dir = self.service_dir(service);
        crate::btrfs::restore_slot_from_latest_snapshot(
            &srv_dir,
            restore_slot,
            self.runner.as_ref(),
        )?;
        self.atomic_swap_active_slot(service, restore_slot)
    }

    /// Atomically swaps the active slot pointer (`/srv/muconde/<service>/current`):
    /// 1. Creates a temporary symlink `.current.tmp.<nonce>` pointing to `@a` or `@b`.
    /// 2. Atomically replaces `current` via `std::fs::rename` (POSIX rename(2) atomicity).
    /// 3. Triggers `systemctl restart <service>` and returns a `SwapReceipt`.
    pub fn atomic_swap_active_slot(
        &self,
        service: &str,
        target_slot: Slot,
    ) -> Result<SwapReceipt, AgentError> {
        validate_service_name(service)?;

        let srv_dir = self.service_dir(service);
        fs::create_dir_all(&srv_dir)?;

        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let tmp_symlink = srv_dir.join(format!(".current.tmp.{}", nonce));
        let current_symlink = srv_dir.join("current");

        // 1. Create temporary symlink pointing to target subvolume relative name (@a or @b)
        symlink(target_slot.as_str(), &tmp_symlink).map_err(AgentError::Io)?;

        // 2. Atomically replace current via POSIX rename(2)
        if let Err(e) = fs::rename(&tmp_symlink, &current_symlink) {
            let _ = fs::remove_file(&tmp_symlink);
            return Err(AgentError::Io(e));
        }

        // 3. On production root (/srv/muconde), activate static web bundle or binary before service restart
        if self.root_dir == Path::new("/srv/muconde") {
            let slot_dir = srv_dir.join(target_slot.as_str());
            if crate::btrfs::is_static_web_service(service) {
                let web_root = match service {
                    "muconsole" | "mu-console" => Some("/var/www/muconsole"),
                    "action-runner-web" | "mu-ci-web" => Some("/var/www/action-runner-web"),
                    _ => None,
                };
                if let Some(dest) = web_root {
                    let dist_dir = slot_dir.join("dist");
                    if dist_dir.is_dir() {
                        let _ = fs::create_dir_all(dest);
                        let src_dot = format!("{}/.", dist_dir.display());
                        let _ = self.runner.run_command("cp", &["-a", &src_dot, dest]);
                    }
                }
            } else {
                let staged_bin = slot_dir.join("bin").join(service);
                if staged_bin.is_file() {
                    if let Ok(meta) = fs::metadata(&staged_bin) {
                        if meta.len() > 1024 {
                            if let Some(bin_name) =
                                crate::btrfs::candidate_binary_names(service).first()
                            {
                                let dest_bin = format!("/usr/local/bin/{bin_name}");
                                let _ = self.runner.run_command(
                                    "install",
                                    &["-m", "755", staged_bin.to_str().unwrap_or(""), &dest_bin],
                                );
                            }
                        }
                    }
                }
            }
        }

        // 4. Trigger systemctl restart <service> via CommandRunner (skip self-restart of muconde-agent mid-RPC)
        if !(self.root_dir == Path::new("/srv/muconde")
            && matches!(service, "muconde-agent" | "mu-cd-agent"))
        {
            let restart_arg = service;
            self.runner
                .run_command("systemctl", &["restart", restart_arg])?;
        }

        let swapped_at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        tracing::info!(
            service = service,
            slot = target_slot.as_str(),
            swapped_at = swapped_at_epoch_ms,
            "Successfully executed atomic slot swap and triggered service restart"
        );

        Ok(SwapReceipt {
            service: service.to_string(),
            active_slot: target_slot,
            swapped_at_epoch_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::MockCommandRunner;
    use tempfile::tempdir;

    #[test]
    fn test_slot_conversion() {
        assert_eq!(Slot::from(DeploymentSlot::SlotA), Slot::A);
        assert_eq!(Slot::from(DeploymentSlot::SlotB), Slot::B);
        assert_eq!(DeploymentSlot::from(Slot::A), DeploymentSlot::SlotA);
        assert_eq!(DeploymentSlot::from(Slot::B), DeploymentSlot::SlotB);
        assert_eq!(Slot::A.as_str(), "@a");
        assert_eq!(Slot::B.as_str(), "@b");
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
        assert_eq!(Slot::from_target_str("@a"), Some(Slot::A));
        assert_eq!(Slot::from_target_str("/srv/muconde/svc/@b/"), Some(Slot::B));
        assert_eq!(Slot::from_target_str("@c"), None);
    }

    #[test]
    fn test_atomic_swap_active_slot() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        fs::create_dir_all(&root).unwrap();

        let service = "action-runner";
        let runner = Arc::new(MockCommandRunner::new(true));
        let manager = SlotManager::new(&root, runner.clone());

        // Prepare physical slots @a and @b
        let srv_dir = root.join(service);
        let slot_a = srv_dir.join("@a");
        let slot_b = srv_dir.join("@b");
        fs::create_dir_all(&slot_a).unwrap();
        fs::create_dir_all(&slot_b).unwrap();
        fs::write(slot_a.join("version.txt"), b"slot_a_v1").unwrap();
        fs::write(slot_b.join("version.txt"), b"slot_b_v2").unwrap();

        // 1. Initial swap to Slot::A
        let receipt_a = manager
            .atomic_swap_active_slot(service, Slot::A)
            .expect("swap to A");
        assert_eq!(receipt_a.service, service);
        assert_eq!(receipt_a.active_slot, Slot::A);
        assert!(receipt_a.swapped_at_epoch_ms > 0);

        // Verify active slot is A
        assert_eq!(manager.read_active_slot(service).unwrap(), Some(Slot::A));
        let content_a = fs::read_to_string(srv_dir.join("current").join("version.txt")).unwrap();
        assert_eq!(content_a, "slot_a_v1");

        // 2. Atomic swap to Slot::B
        let receipt_b = manager
            .atomic_swap_active_slot(service, Slot::B)
            .expect("swap to B");
        assert_eq!(receipt_b.active_slot, Slot::B);

        // Verify active slot switched to B with zero downtime
        assert_eq!(manager.read_active_slot(service).unwrap(), Some(Slot::B));
        let content_b = fs::read_to_string(srv_dir.join("current").join("version.txt")).unwrap();
        assert_eq!(content_b, "slot_b_v2");

        // 3. Atomic swap back to Slot::A
        let receipt_a2 = manager
            .atomic_swap_active_slot(service, Slot::A)
            .expect("swap back to A");
        assert_eq!(receipt_a2.active_slot, Slot::A);
        assert_eq!(manager.read_active_slot(service).unwrap(), Some(Slot::A));

        // Verify command calls to systemctl restart
        let calls = runner.recorded_calls();
        let restart_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.contains(&"restart".to_string()))
            .collect();
        assert_eq!(restart_calls.len(), 3);
        let expected_cmd: Vec<String> = vec!["systemctl".into(), "restart".into(), service.into()];
        assert_eq!(restart_calls[0], &expected_cmd);
    }

    #[test]
    fn test_path_traversal_rejection_in_swap() {
        let temp = tempdir().unwrap();
        let runner = Arc::new(MockCommandRunner::new(false));
        let manager = SlotManager::new(temp.path(), runner);

        let err = manager
            .atomic_swap_active_slot("../evil", Slot::A)
            .unwrap_err();
        assert!(matches!(err, AgentError::PathTraversal(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_resolve_target_slot_and_symmetric_rollback() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "mu-cd-agent";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let manager = SlotManager::new(&root, runner);

        // Uninitialized symlink defaults candidate to Slot::B
        assert_eq!(manager.resolve_target_slot(service).unwrap(), Slot::B);

        // Active @a -> candidate @b
        manager.atomic_swap_active_slot(service, Slot::A).unwrap();
        assert_eq!(manager.resolve_target_slot(service).unwrap(), Slot::B);

        // Active @b -> candidate @a; inferred rollback restores @a
        manager.atomic_swap_active_slot(service, Slot::B).unwrap();
        assert_eq!(manager.resolve_target_slot(service).unwrap(), Slot::A);
        let rb_to_a = manager.rollback_to_prior_slot(service, None).unwrap();
        assert_eq!(rb_to_a.active_slot, Slot::A);
        assert_eq!(manager.read_active_slot(service).unwrap(), Some(Slot::A));

        // Now swap @b -> @a leg: active is @a, rollback to explicit @b
        let rb_to_b = manager
            .rollback_to_prior_slot(service, Some(Slot::B))
            .unwrap();
        assert_eq!(rb_to_b.active_slot, Slot::B);
        assert_eq!(manager.read_active_slot(service).unwrap(), Some(Slot::B));
    }
}
