//! Post-swap health monitoring watchdog and autonomous sub-second rollback engine.

#![deny(unsafe_code)]

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

use crate::btrfs::CommandRunner;
use crate::error::AgentError;
use crate::slot::{Slot, SlotManager};

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
pub struct SystemHealthProber {
    runner: Arc<dyn CommandRunner>,
    health_endpoint_ports: std::collections::HashMap<String, u16>,
}

impl SystemHealthProber {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            health_endpoint_ports: std::collections::HashMap::new(),
        }
    }

    pub fn with_endpoint(mut self, service: impl Into<String>, port: u16) -> Self {
        self.health_endpoint_ports.insert(service.into(), port);
        self
    }
}

#[async_trait]
impl HealthProber for SystemHealthProber {
    async fn probe(&self, service: &str) -> Result<ProbeResult, AgentError> {
        let start = Instant::now();

        // 1. Probe systemd unit state
        let unit_name = if service.ends_with(".service") {
            service.to_string()
        } else {
            format!("{}.service", service)
        };

        let cmd_res = self.runner.run_command(
            "systemctl",
            &["show", "-p", "ActiveState,SubState", &unit_name],
        );

        let (systemd_active, error_detail) = match cmd_res {
            Ok(output) => {
                let stdout = output.stdout;
                let active = stdout.contains("ActiveState=active")
                    && (stdout.contains("SubState=running") || stdout.contains("SubState=active"));
                if !active {
                    (
                        false,
                        Some(format!("systemd unit state: {}", stdout.trim())),
                    )
                } else {
                    (true, None)
                }
            }
            Err(e) => (false, Some(format!("systemctl failed: {}", e))),
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
        }
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
        let start = Instant::now();

        // 1. Immediately revert active slot to `restore_slot` (restoring prior read-only snapshot if needed)
        self.slot_manager
            .rollback_to_prior_slot(service, Some(restore_slot))?;

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
        self.execute_rollback(
            &cmd.deployment_id,
            &cmd.service_name,
            Slot::from(cmd.restore_slot),
            &cmd.failed_artifact_sha256,
            &cmd.reason,
        )
    }

    /// Runs a bounded post-swap warmup watchdog monitor:
    /// - Checks health at 250ms intervals.
    /// - Emits `HealthProbeTelemetry` per probe tick over `telemetry_tx`.
    /// - Autonomously executes instant rollback to `command.from_slot` (< 1s) upon:
    ///   - Any unhealthy probe or process exit/crash.
    ///   - Deployment lease TTL expiration without controller promotion.
    ///   - External rollback signal via `rollback_rx`.
    pub async fn monitor_warmup(
        &self,
        command: &SlotSwapCommand,
        candidate_artifact_sha256: &str,
        expires_at_epoch_ms: u64,
        required_consecutive_successes: u32,
        telemetry_tx: Option<mpsc::Sender<HealthProbeTelemetry>>,
        mut rollback_rx: Option<mpsc::Receiver<String>>,
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
                    let (report, taint, elapsed_rollback_ms) = self.execute_rollback(
                        &command.deployment_id,
                        &command.service_name,
                        restore_slot,
                        candidate_artifact_sha256,
                        &format!("External rollback requested: {}", reason),
                    )?;
                    return Ok(WatchdogOutcome::RolledBack {
                        report: Box::new(report),
                        taint: Box::new(taint),
                        elapsed_rollback_ms,
                    });
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
                        let (report, taint, elapsed_rollback_ms) = self.execute_rollback(
                            &command.deployment_id,
                            &command.service_name,
                            restore_slot,
                            candidate_artifact_sha256,
                            &reason,
                        )?;
                        return Ok(WatchdogOutcome::RolledBack {
                            report: Box::new(report),
                            taint: Box::new(taint),
                            elapsed_rollback_ms,
                        });
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

                        let (report, taint, elapsed_rollback_ms) = self.execute_rollback(
                            &command.deployment_id,
                            &command.service_name,
                            restore_slot,
                            candidate_artifact_sha256,
                            &reason,
                        )?;

                        return Ok(WatchdogOutcome::RolledBack {
                            report: Box::new(report),
                            taint: Box::new(taint),
                            elapsed_rollback_ms,
                        });
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
                        let (report, taint, elapsed_rollback_ms) = self.execute_rollback(
                            &command.deployment_id,
                            &command.service_name,
                            restore_slot,
                            candidate_artifact_sha256,
                            &reason,
                        )?;
                        return Ok(WatchdogOutcome::RolledBack {
                            report: Box::new(report),
                            taint: Box::new(taint),
                            elapsed_rollback_ms,
                        });
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
}
