//! Post-swap health monitoring watchdog and autonomous sub-second rollback engine.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mu_cd_ipc::{
    ArtifactTaintNotification, HealthProbeTelemetry, IntegrationTestReport, RollbackCommand,
    SlotSwapCommand,
};
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::btrfs::{candidate_systemd_units, is_static_web_service, CommandRunner};
use crate::error::AgentError;
use crate::manifest::{DeploymentConfig, MuCdManifest};
use crate::slot::{is_production_cd_root, read_active_slot_at, Slot, SlotManager};

/// Current timestamp in milliseconds since Unix epoch.
pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Result of an individual health probe evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub systemd_active: bool,
    pub health_endpoint_ok: bool,
    pub latency_ms: u32,
    pub error_detail: Option<String>,
}

impl ProbeResult {
    pub fn is_healthy(&self) -> bool {
        self.systemd_active && self.health_endpoint_ok
    }
}

/// Abstract prober interface verifying systemd status and local health endpoints.
#[async_trait]
pub trait HealthProber: Send + Sync {
    async fn probe(&self, service: &str) -> Result<ProbeResult, AgentError>;
}

/// Real system prober checking systemd unit state (`ActiveState=active && SubState=running`)
/// and optional local health endpoint.
///
/// Static web services probe `nginx.service` and the active slot layout instead of a nonexistent
/// `<web-service>.service` unit; daemon services probe canonical and aliased systemd units.
pub struct SystemHealthProber {
    runner: Arc<dyn CommandRunner>,
    health_endpoint_ports: std::collections::HashMap<String, u16>,
    muconde_root: Option<PathBuf>,
}

impl SystemHealthProber {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            health_endpoint_ports: std::collections::HashMap::new(),
            muconde_root: None,
        }
    }

    pub fn with_endpoint(mut self, service: impl Into<String>, port: u16) -> Self {
        self.health_endpoint_ports.insert(service.into(), port);
        self
    }

    /// Configures the root directory used to inspect active slots and slot-bundled manifests.
    pub fn with_muconde_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.muconde_root = Some(root.into());
        self
    }

    fn probe_single_unit(&self, unit_name: &str) -> Result<(), String> {
        let output = self
            .runner
            .run_command(
                "systemctl",
                &["show", "-p", "ActiveState,SubState", unit_name],
            )
            .map_err(|e| format!("{unit_name}: systemctl failed: {e}"))?;
        let active = output.stdout.contains("ActiveState=active")
            && (output.stdout.contains("SubState=running")
                || output.stdout.contains("SubState=active"));
        if active {
            Ok(())
        } else {
            Err(format!("{unit_name}: {}", output.stdout.trim()))
        }
    }

    fn check_static_web_slot(&self, root: &Path, service: &str) -> Result<(), String> {
        let srv_dir = root.join(service);
        let slot = read_active_slot_at(&srv_dir)
            .map_err(|e| format!("failed reading active slot for '{service}': {e}"))?
            .ok_or_else(|| format!("active slot symlink missing for static web '{service}'"))?;
        let slot_dir = srv_dir.join(slot.as_str());
        if !slot_dir.is_dir() {
            return Err(format!(
                "active slot directory '{}' missing for static web '{service}'",
                slot_dir.display()
            ));
        }
        if is_production_cd_root(root) && !slot_dir.join("dist").is_dir() {
            return Err(format!(
                "staged dist directory '{}' missing for static web '{service}'",
                slot_dir.join("dist").display()
            ));
        }
        Ok(())
    }

    fn candidate_units_for_daemon(&self, service: &str) -> Vec<String> {
        let mut units = Vec::new();
        if let Some(ref root) = self.muconde_root {
            let slot_current = root.join(service).join("current");
            if let Ok(Some(manifest)) = MuCdManifest::load_optional_from_dir(&slot_current) {
                if let Some(unit) = manifest.deployment.normalized_systemd_unit() {
                    units.push(unit);
                }
            }
        }
        for unit in candidate_systemd_units(service) {
            if !units.contains(&unit) {
                units.push(unit);
            }
        }
        units
    }
}

#[async_trait]
impl HealthProber for SystemHealthProber {
    async fn probe(&self, service: &str) -> Result<ProbeResult, AgentError> {
        let start = Instant::now();

        // 1. Probe systemd unit state (static web probes nginx.service + active slot layout;
        //    daemons probe canonical and legacy unit aliases).
        let (systemd_active, error_detail) = if is_static_web_service(service) {
            match self.probe_single_unit("nginx.service") {
                Ok(()) => {
                    if let Some(ref root) = self.muconde_root {
                        match self.check_static_web_slot(root, service) {
                            Ok(()) => (true, None),
                            Err(err) => (false, Some(err)),
                        }
                    } else {
                        (true, None)
                    }
                }
                Err(err) => (false, Some(format!("systemd unit state: {err}"))),
            }
        } else {
            let candidates = self.candidate_units_for_daemon(service);
            let mut failures = Vec::new();
            let mut matched = false;
            for unit in &candidates {
                match self.probe_single_unit(unit) {
                    Ok(()) => {
                        matched = true;
                        break;
                    }
                    Err(err) => failures.push(err),
                }
            }
            if matched {
                (true, None)
            } else {
                (
                    false,
                    Some(format!("systemd unit state: {}", failures.join("; "))),
                )
            }
        };

        // 2. Probe local health endpoint if configured
        let mut health_endpoint_ok = true;
        let mut endpoint_error = None;

        if let Some(&port) = self.health_endpoint_ports.get(service) {
            let addr = format!("127.0.0.1:{}", port);
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(_) => {
                    health_endpoint_ok = true;
                }
                Err(e) => {
                    health_endpoint_ok = false;
                    endpoint_error = Some(format!("TCP probe to {} failed: {}", addr, e));
                }
            }
        }

        let latency_ms = start.elapsed().as_millis() as u32;

        let combined_error = match (error_detail, endpoint_error) {
            (Some(e1), Some(e2)) => Some(format!("{}; {}", e1, e2)),
            (Some(e), None) | (None, Some(e)) => Some(e),
            (None, None) => None,
        };

        Ok(ProbeResult {
            systemd_active,
            health_endpoint_ok,
            latency_ms,
            error_detail: combined_error,
        })
    }
}

/// Configurable mock prober for deterministic unit and integration tests.
pub struct MockHealthProber {
    pub is_active: AtomicBool,
    pub endpoint_ok: AtomicBool,
    pub latency_ms: u32,
    pub failure_reason: Option<String>,
}

impl MockHealthProber {
    pub fn new(healthy: bool) -> Self {
        Self {
            is_active: AtomicBool::new(healthy),
            endpoint_ok: AtomicBool::new(healthy),
            latency_ms: 5,
            failure_reason: if healthy {
                None
            } else {
                Some("Mock service simulated crash".into())
            },
        }
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.is_active.store(healthy, Ordering::SeqCst);
        self.endpoint_ok.store(healthy, Ordering::SeqCst);
    }
}

#[async_trait]
impl HealthProber for MockHealthProber {
    async fn probe(&self, _service: &str) -> Result<ProbeResult, AgentError> {
        let systemd_active = self.is_active.load(Ordering::SeqCst);
        let health_endpoint_ok = self.endpoint_ok.load(Ordering::SeqCst);

        let error_detail = if !systemd_active || !health_endpoint_ok {
            self.failure_reason.clone()
        } else {
            None
        };

        Ok(ProbeResult {
            systemd_active,
            health_endpoint_ok,
            latency_ms: self.latency_ms,
            error_detail,
        })
    }
}

/// Final outcome of the post-swap warmup watchdog monitor.
#[derive(Debug, PartialEq)]
pub enum WatchdogOutcome {
    /// Service successfully warmed up with consecutive healthy probes.
    WarmedUp {
        consecutive_successes: u32,
        total_probes: u32,
    },
    /// Watchdog triggered immediate autonomous rollback to Slot A.
    RolledBack {
        report: Box<IntegrationTestReport>,
        taint: Box<ArtifactTaintNotification>,
        elapsed_rollback_ms: u64,
    },
}

/// Autonomous post-swap watchdog monitor.
pub struct WatchdogMonitor {
    node_id: String,
    slot_manager: Arc<SlotManager>,
    prober: Arc<dyn HealthProber>,
    deployment: Option<DeploymentConfig>,
    cmd_systemd_unit: Option<String>,
}

impl WatchdogMonitor {
    pub fn new(
        node_id: impl Into<String>,
        slot_manager: Arc<SlotManager>,
        prober: Arc<dyn HealthProber>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            slot_manager,
            prober,
            deployment: None,
            cmd_systemd_unit: None,
        }
    }

    /// Configures declarative [`DeploymentConfig`] and systemd unit overrides applied during rollback.
    pub fn with_deployment(
        mut self,
        deployment: Option<DeploymentConfig>,
        cmd_systemd_unit: Option<String>,
    ) -> Self {
        self.deployment = deployment;
        self.cmd_systemd_unit = cmd_systemd_unit;
        self
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Autonomous sub-second (< 1s) rollback engine reverting the symlink to `restore_slot`
    /// and generating verification and artifact taint notifications.
    pub fn execute_rollback(
        &self,
        deployment_id: &str,
        service: &str,
        restore_slot: Slot,
        candidate_artifact_sha256: &str,
        reason: &str,
    ) -> Result<(IntegrationTestReport, ArtifactTaintNotification, u64), AgentError> {
        self.execute_rollback_with_deployment(
            deployment_id,
            service,
            restore_slot,
            candidate_artifact_sha256,
            reason,
            self.deployment.as_ref(),
            self.cmd_systemd_unit.as_deref(),
        )
    }

    /// Autonomous sub-second (< 1s) rollback engine with explicit [`DeploymentConfig`] and
    /// `systemd_unit` overrides.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_rollback_with_deployment(
        &self,
        deployment_id: &str,
        service: &str,
        restore_slot: Slot,
        candidate_artifact_sha256: &str,
        reason: &str,
        deployment: Option<&DeploymentConfig>,
        cmd_systemd_unit: Option<&str>,
    ) -> Result<(IntegrationTestReport, ArtifactTaintNotification, u64), AgentError> {
        let start = Instant::now();
        let effective_deployment = deployment.or(self.deployment.as_ref());
        let effective_unit = cmd_systemd_unit.or(self.cmd_systemd_unit.as_deref());

        // 1. Immediately revert active slot to `restore_slot` (restoring prior read-only snapshot if needed)
        self.slot_manager.rollback_to_prior_slot_with_deployment(
            service,
            Some(restore_slot),
            effective_deployment,
            effective_unit,
        )?;

        let elapsed_rollback_ms = start.elapsed().as_millis() as u64;

        tracing::warn!(
            deployment_id = deployment_id,
            service = service,
            restore_slot = restore_slot.as_str(),
            elapsed_ms = elapsed_rollback_ms,
            reason = reason,
            "Autonomous rollback successfully executed"
        );

        // 2. Construct IntegrationTestReport with failure details
        let report = IntegrationTestReport {
            deployment_id: deployment_id.to_string(),
            service_name: service.to_string(),
            artifact_sha256: candidate_artifact_sha256.to_string(),
            executed_tests: vec![
                "systemd_unit_active".to_string(),
                "health_endpoint_ready".to_string(),
            ],
            passed: false,
            failed_tests: vec![reason.to_string()],
            duration_ms: elapsed_rollback_ms,
            log_excerpt: Some(format!(
                "Autonomous watchdog rollback to {} triggered: {}",
                restore_slot.as_str(),
                reason
            )),
        };

        // 3. Construct ArtifactTaintNotification for controller & registry taint
        let taint = ArtifactTaintNotification {
            deployment_id: deployment_id.to_string(),
            service_name: service.to_string(),
            artifact_sha256: candidate_artifact_sha256.to_string(),
            tainted_at_epoch_ms: now_epoch_ms(),
            reason: reason.to_string(),
            rollback_completed: true,
        };

        Ok((report, taint, elapsed_rollback_ms))
    }

    /// Handles an explicit `RollbackCommand` received from `MuConDe-controller`.
    pub fn handle_rollback_command(
        &self,
        cmd: &RollbackCommand,
    ) -> Result<(IntegrationTestReport, ArtifactTaintNotification, u64), AgentError> {
        self.handle_rollback_command_with_deployment(cmd, None, None)
    }

    /// Handles an explicit `RollbackCommand` while applying explicit [`DeploymentConfig`] and
    /// `systemd_unit` overrides.
    pub fn handle_rollback_command_with_deployment(
        &self,
        cmd: &RollbackCommand,
        deployment: Option<&DeploymentConfig>,
        cmd_systemd_unit: Option<&str>,
    ) -> Result<(IntegrationTestReport, ArtifactTaintNotification, u64), AgentError> {
        self.execute_rollback_with_deployment(
            &cmd.deployment_id,
            &cmd.service_name,
            Slot::from(cmd.restore_slot),
            &cmd.failed_artifact_sha256,
            &cmd.reason,
            deployment,
            cmd_systemd_unit,
        )
    }

    fn rolled_back_outcome(
        &self,
        command: &SlotSwapCommand,
        restore_slot: Slot,
        candidate_artifact_sha256: &str,
        reason: &str,
        deployment: Option<&DeploymentConfig>,
    ) -> Result<WatchdogOutcome, AgentError> {
        let (report, taint, elapsed_rollback_ms) = self.execute_rollback_with_deployment(
            &command.deployment_id,
            &command.service_name,
            restore_slot,
            candidate_artifact_sha256,
            reason,
            deployment,
            Some(command.systemd_unit.as_str()),
        )?;
        Ok(WatchdogOutcome::RolledBack {
            report: Box::new(report),
            taint: Box::new(taint),
            elapsed_rollback_ms,
        })
    }

    /// Runs a bounded post-swap warmup watchdog monitor using default configured deployment overrides.
    pub async fn monitor_warmup(
        &self,
        command: &SlotSwapCommand,
        candidate_artifact_sha256: &str,
        expires_at_epoch_ms: u64,
        required_consecutive_successes: u32,
        telemetry_tx: Option<mpsc::Sender<HealthProbeTelemetry>>,
        rollback_rx: Option<mpsc::Receiver<String>>,
    ) -> Result<WatchdogOutcome, AgentError> {
        self.monitor_warmup_with_deployment(
            command,
            candidate_artifact_sha256,
            expires_at_epoch_ms,
            required_consecutive_successes,
            telemetry_tx,
            rollback_rx,
            None,
        )
        .await
    }

    /// Runs a bounded post-swap warmup watchdog monitor while applying explicit [`DeploymentConfig`]
    /// and `command.systemd_unit` overrides to any triggered rollback:
    /// - Checks health at 250ms intervals.
    /// - Emits `HealthProbeTelemetry` per probe tick over `telemetry_tx`.
    /// - Autonomously executes instant rollback to `command.from_slot` (< 1s) upon:
    ///   - Any unhealthy probe or process exit/crash.
    ///   - Deployment lease TTL expiration without controller promotion.
    ///   - External rollback signal via `rollback_rx`.
    #[allow(clippy::too_many_arguments)]
    pub async fn monitor_warmup_with_deployment(
        &self,
        command: &SlotSwapCommand,
        candidate_artifact_sha256: &str,
        expires_at_epoch_ms: u64,
        required_consecutive_successes: u32,
        telemetry_tx: Option<mpsc::Sender<HealthProbeTelemetry>>,
        mut rollback_rx: Option<mpsc::Receiver<String>>,
        deployment: Option<DeploymentConfig>,
    ) -> Result<WatchdogOutcome, AgentError> {
        let warmup_duration = Duration::from_secs(command.warmup_timeout_secs);
        let deadline = Instant::now() + warmup_duration;
        let mut ticker = interval(Duration::from_millis(250));
        let restore_slot = Slot::from(command.from_slot);

        let mut consecutive_successes: u32 = 0;
        let mut total_probes: u32 = 0;

        loop {
            tokio::select! {
                // Check if external rollback was requested
                Some(reason) = async {
                    match rollback_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    return self.rolled_back_outcome(
                        command,
                        restore_slot,
                        candidate_artifact_sha256,
                        &format!("External rollback requested: {}", reason),
                        deployment.as_ref(),
                    );
                }

                _ = ticker.tick() => {
                    total_probes += 1;
                    let current_time_ms = now_epoch_ms();

                    // 1. Invariant: Check lease TTL expiration
                    if current_time_ms >= expires_at_epoch_ms {
                        let reason = format!(
                            "Deployment lease TTL expired at {} ms (now: {} ms) without promotion",
                            expires_at_epoch_ms, current_time_ms
                        );
                        return self.rolled_back_outcome(
                            command,
                            restore_slot,
                            candidate_artifact_sha256,
                            &reason,
                            deployment.as_ref(),
                        );
                    }

                    // 2. Execute health probe
                    let probe_res = self.prober.probe(&command.service_name).await?;

                    // 3. Emit telemetry
                    let telemetry = HealthProbeTelemetry {
                        deployment_id: command.deployment_id.clone(),
                        node_id: self.node_id.clone(),
                        service_name: command.service_name.clone(),
                        active_slot: command.to_slot,
                        systemd_active: probe_res.systemd_active,
                        health_endpoint_ok: probe_res.health_endpoint_ok,
                        probe_latency_ms: probe_res.latency_ms,
                        timestamp_epoch_ms: current_time_ms,
                    };

                    if let Some(ref tx) = telemetry_tx {
                        let _ = tx.send(telemetry).await;
                    }

                    // 4. Invariant: If probe unhealthy, autonomously trigger immediate rollback
                    if !probe_res.is_healthy() {
                        let detail = probe_res
                            .error_detail
                            .unwrap_or_else(|| "Health probe assertion failed".into());
                        let reason = format!(
                            "Unhealthy probe: systemd_active={}, endpoint_ok={}, detail={}",
                            probe_res.systemd_active, probe_res.health_endpoint_ok, detail
                        );

                        return self.rolled_back_outcome(
                            command,
                            restore_slot,
                            candidate_artifact_sha256,
                            &reason,
                            deployment.as_ref(),
                        );
                    }

                    // Probe was healthy
                    consecutive_successes += 1;

                    // 5. Check if warm-up satisfied
                    if consecutive_successes >= required_consecutive_successes {
                        tracing::info!(
                            deployment_id = %command.deployment_id,
                            service = %command.service_name,
                            consecutive = consecutive_successes,
                            "Warmup health checks passed successfully"
                        );
                        return Ok(WatchdogOutcome::WarmedUp {
                            consecutive_successes,
                            total_probes,
                        });
                    }

                    // 6. Check warmup timeout deadline
                    if Instant::now() >= deadline {
                        let reason = format!(
                            "Warmup timeout ({}s) elapsed before achieving {} consecutive healthy probes (got {})",
                            command.warmup_timeout_secs, required_consecutive_successes, consecutive_successes
                        );
                        return self.rolled_back_outcome(
                            command,
                            restore_slot,
                            candidate_artifact_sha256,
                            &reason,
                            deployment.as_ref(),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::MockCommandRunner;
    use mu_cd_ipc::DeploymentSlot;
    use std::fs;
    use tempfile::tempdir;

    fn setup_env(service: &str) -> (tempfile::TempDir, Arc<SlotManager>, Arc<MockCommandRunner>) {
        let temp = tempdir().unwrap();
        let runner = Arc::new(MockCommandRunner::new(true));
        let slot_mgr = Arc::new(SlotManager::new(temp.path(), runner.clone()));

        // Prepare physical @a and @b
        let srv_dir = temp.path().join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        // Swap initially to @b for warmup monitoring
        slot_mgr.atomic_swap_active_slot(service, Slot::B).unwrap();

        (temp, slot_mgr, runner)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_healthy_warmup_satisfies_criteria() {
        let service = "action-runner";
        let (_temp, slot_mgr, _runner) = setup_env(service);

        let prober = Arc::new(MockHealthProber::new(true));
        let monitor = WatchdogMonitor::new("test-node", slot_mgr.clone(), prober);

        let (tx, mut rx) = mpsc::channel(16);

        let cmd = SlotSwapCommand {
            deployment_id: "dep-pass-1".into(),
            lease_id: "lease-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "action-runner.service".into(),
            warmup_timeout_secs: 10,
        };

        let outcome = monitor
            .monitor_warmup(
                &cmd,
                "sha-candidate-good",
                now_epoch_ms() + 60_000,
                3,
                Some(tx),
                None,
            )
            .await
            .expect("monitor warmup");

        match outcome {
            WatchdogOutcome::WarmedUp {
                consecutive_successes,
                total_probes,
            } => {
                assert_eq!(consecutive_successes, 3);
                assert!(total_probes >= 3);
            }
            WatchdogOutcome::RolledBack { .. } => panic!("Expected WarmedUp, got RolledBack"),
        }

        // Verify telemetry frames were emitted
        let mut telemetry_count = 0;
        while let Ok(telem) = rx.try_recv() {
            telemetry_count += 1;
            assert_eq!(telem.deployment_id, "dep-pass-1");
            assert!(telem.systemd_active);
            assert!(telem.health_endpoint_ok);
        }
        assert!(telemetry_count >= 3);

        // Active slot remains @b
        assert_eq!(slot_mgr.read_active_slot(service).unwrap(), Some(Slot::B));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_unhealthy_probe_triggers_immediate_subsecond_rollback() {
        let service = "muregist";
        let (_temp, slot_mgr, _runner) = setup_env(service);

        // Prober starts healthy, then fails
        let prober = Arc::new(MockHealthProber::new(true));
        let monitor = WatchdogMonitor::new("test-node", slot_mgr.clone(), prober.clone());

        let cmd = SlotSwapCommand {
            deployment_id: "dep-fail-1".into(),
            lease_id: "lease-2".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "muregist.service".into(),
            warmup_timeout_secs: 10,
        };

        // Prober immediately reports failure
        prober.set_healthy(false);

        let outcome = monitor
            .monitor_warmup(
                &cmd,
                "sha-candidate-bad",
                now_epoch_ms() + 60_000,
                3,
                None,
                None,
            )
            .await
            .expect("monitor warmup");

        match outcome {
            WatchdogOutcome::RolledBack {
                report,
                taint,
                elapsed_rollback_ms,
            } => {
                // Must be sub-second (< 1s / 1000ms) execution target per AGENTS.md and spec
                assert!(
                    elapsed_rollback_ms < 1000,
                    "Rollback must complete in < 1000ms, took {}ms",
                    elapsed_rollback_ms
                );
                assert_eq!(report.deployment_id, "dep-fail-1");
                assert_eq!(report.service_name, service);
                assert!(!report.passed);
                assert_eq!(taint.deployment_id, "dep-fail-1");
                assert!(taint.rollback_completed);
                assert_eq!(taint.artifact_sha256, "sha-candidate-bad");
            }
            WatchdogOutcome::WarmedUp { .. } => panic!("Expected RolledBack, got WarmedUp"),
        }

        // Active slot was atomically restored to @a
        assert_eq!(slot_mgr.read_active_slot(service).unwrap(), Some(Slot::A));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_lease_ttl_expiry_triggers_rollback() {
        let service = "model-runner";
        let (_temp, slot_mgr, _runner) = setup_env(service);

        let prober = Arc::new(MockHealthProber::new(true));
        let monitor = WatchdogMonitor::new("test-node", slot_mgr.clone(), prober);

        let cmd = SlotSwapCommand {
            deployment_id: "dep-lease-exp".into(),
            lease_id: "lease-3".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "model-runner.service".into(),
            warmup_timeout_secs: 30,
        };

        // Expire lease immediately (timestamp in the past)
        let expired_lease_time = now_epoch_ms().saturating_sub(100);

        let outcome = monitor
            .monitor_warmup(&cmd, "sha-model", expired_lease_time, 5, None, None)
            .await
            .expect("monitor warmup");

        match outcome {
            WatchdogOutcome::RolledBack {
                report,
                taint,
                elapsed_rollback_ms,
            } => {
                assert!(elapsed_rollback_ms < 1000);
                assert!(!report.passed);
                assert!(taint.reason.contains("Deployment lease TTL expired"));
            }
            WatchdogOutcome::WarmedUp { .. } => panic!("Expected RolledBack on expired lease"),
        }

        // Active slot restored to @a
        assert_eq!(slot_mgr.read_active_slot(service).unwrap(), Some(Slot::A));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_handle_rollback_command_direct() {
        let service = "muconde-agent";
        let (_temp, slot_mgr, _runner) = setup_env(service);

        let prober = Arc::new(MockHealthProber::new(true));
        let monitor = WatchdogMonitor::new("test-node", slot_mgr.clone(), prober);

        let rollback_cmd = RollbackCommand {
            deployment_id: "dep-direct-rb".into(),
            lease_id: "lease-direct".into(),
            service_name: service.into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: "sha-failed-direct".into(),
            reason: "Controller commanded abort".into(),
        };

        let (report, taint, elapsed_ms) = monitor
            .handle_rollback_command(&rollback_cmd)
            .expect("handle rollback");

        assert!(elapsed_ms < 1000);
        assert_eq!(report.deployment_id, "dep-direct-rb");
        assert!(!report.passed);
        assert_eq!(taint.artifact_sha256, "sha-failed-direct");
        assert!(taint.rollback_completed);
        assert_eq!(slot_mgr.read_active_slot(service).unwrap(), Some(Slot::A));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_reverse_ping_pong_b_to_a_rollback_restores_slot_b() {
        let service = "mu-cd-agent";
        let (temp, slot_mgr, _runner) = setup_env(service);

        // Start active on Slot::A (after swapping @b -> @a)
        slot_mgr.atomic_swap_active_slot(service, Slot::A).unwrap();
        let prober = Arc::new(MockHealthProber::new(false));
        let monitor = WatchdogMonitor::new("test-node", slot_mgr.clone(), prober);

        let (tx, mut rx) = mpsc::channel(8);
        let cmd = SlotSwapCommand {
            deployment_id: "dep-b-to-a-fail".into(),
            lease_id: "lease-rev".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotB,
            to_slot: DeploymentSlot::SlotA,
            systemd_unit: "mu-cd-agent.service".into(),
            warmup_timeout_secs: 10,
        };

        let outcome = monitor
            .monitor_warmup(
                &cmd,
                "sha-bad-a",
                now_epoch_ms() + 60_000,
                3,
                Some(tx),
                None,
            )
            .await
            .expect("monitor warmup");

        let telem = rx.recv().await.expect("probe telemetry emitted");
        assert_eq!(telem.active_slot, DeploymentSlot::SlotA);

        match outcome {
            WatchdogOutcome::RolledBack {
                report,
                taint,
                elapsed_rollback_ms,
            } => {
                assert!(elapsed_rollback_ms < 1000);
                assert!(!report.passed);
                assert!(report.log_excerpt.as_deref().unwrap().contains("@b"));
                assert_eq!(taint.artifact_sha256, "sha-bad-a");
            }
            WatchdogOutcome::WarmedUp { .. } => panic!("Expected rollback to Slot B"),
        }

        assert_eq!(slot_mgr.read_active_slot(service).unwrap(), Some(Slot::B));
        drop(temp);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_system_health_prober_checks_nginx_for_static_web_and_aliases_for_daemons() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("muconde");
        let runner = Arc::new(MockCommandRunner::new(true));
        runner.set_command_output(
            "systemctl show -p ActiveState,SubState nginx.service",
            crate::btrfs::CommandOutput {
                status: 0,
                stdout: "ActiveState=active\nSubState=running\n".into(),
                stderr: String::new(),
            },
        );

        let slot_mgr = SlotManager::new(&root, runner.clone());
        std::fs::create_dir_all(root.join("mu-console/@a/dist")).unwrap();
        slot_mgr
            .atomic_swap_active_slot("mu-console", Slot::A)
            .unwrap();

        let prober = SystemHealthProber::new(runner.clone()).with_muconde_root(&root);
        let static_res = prober.probe("mu-console").await.unwrap();
        assert!(static_res.is_healthy());
        assert!(
            !runner
                .recorded_calls()
                .iter()
                .any(|c| c.iter().any(|arg| arg == "mu-console.service")),
            "Static web health probe must query nginx.service, never mu-console.service"
        );

        // Missing active slot fails closed even if nginx.service is running
        let bad_res = prober.probe("mu-ci-web").await.unwrap();
        assert!(!bad_res.systemd_active);

        // Legacy daemon alias resolves via canonical unit when active
        runner.set_command_output(
            "systemctl show -p ActiveState,SubState mu-registry.service",
            crate::btrfs::CommandOutput {
                status: 0,
                stdout: "ActiveState=active\nSubState=running\n".into(),
                stderr: String::new(),
            },
        );
        let daemon_res = prober.probe("muregist").await.unwrap();
        assert!(daemon_res.is_healthy());
    }
}
