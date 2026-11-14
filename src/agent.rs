//! Network IPC agent daemon receiving controller deployment RPCs and managing node lifecycle.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mu_cd_ipc::framing::{
    read_frame, write_frame, IpcHeader, MSG_TYPE_ARTIFACT_TAINT, MSG_TYPE_HEALTH_PROBE,
    MSG_TYPE_HEARTBEAT, MSG_TYPE_IT_PROGRESS, MSG_TYPE_IT_REPORT, MSG_TYPE_ROLLBACK,
    MSG_TYPE_SLOT_SWAP, MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};
use mu_cd_ipc::{
    create_fory_runtime, ArtifactTaintNotification, HeartbeatTelemetry, IntegrationTestProgress,
    IntegrationTestReport, RollbackCommand, SlotSwapCommand, StageDeploymentRequest, TestState,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;

use crate::btrfs::{BtrfsManager, CommandRunner, SystemCommandRunner};
use crate::error::AgentError;
use crate::gate::{
    builtin_catalog, builtin_verdict, GateTest, GateTracker, IntegrationTestSelection,
};
use crate::manifest::{AbRulesConfig, MuCdManifest};
use crate::sandbox_it::{
    resolve_gate_plan_with_base, sanitize_and_bound_log_excerpt, unpack_verified_it_archive,
    DiscoveredItTest, ItArchiveFetcher, ItSandboxConfig, KernelSandboxedExecutor,
    RegistryAndCasFetcher, SandboxedCommandExecutor, MAX_LOG_EXCERPT_BYTES,
};
use crate::slot::{Slot, SlotManager};
use crate::telemetry::{
    now_unix_nano, trace_context_for_deployment, MuObserveCollectorSink, TelemetrySink,
    AGENT_SERVICE_NAME,
};
use crate::watchdog::{
    now_epoch_ms, HealthProber, SystemHealthProber, WatchdogMonitor, WatchdogOutcome,
};
use mu_observable_ipc::{OtelMetricEntry, OtelSpanEntry};

/// Configuration parameters for the MuConDe node agent daemon.
#[derive(Debug, Clone)]
pub struct MuConDeAgentConfig {
    pub node_id: String,
    pub listen_addr: String,
    pub muconde_root: PathBuf,
    pub tls_ca_path: Option<PathBuf>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub default_warmup_timeout_secs: u64,
    pub required_consecutive_successes: u32,
    pub collector_addr: Option<String>,
    /// Contract `integration_tests` selector (`"all"` by default).
    pub integration_tests: IntegrationTestSelection,
    /// Tests this agent can execute; `"all"` expands to this list.
    pub gate_catalog: Vec<GateTest>,
    /// Declarative A/B snapshot and critical rollback rules.
    pub ab_rules: AbRulesConfig,
    /// Optional SHA-256 digest of the CAS integration test `.tar.gz` bundle.
    pub it_archive_digest: Option<String>,
    /// Optional explicit canary bundle ID in `mu-registry`.
    pub it_bundle_id: Option<String>,
    /// Optional base URL of `mu-registry` HTTP/mTLS API.
    pub registry_url: Option<String>,
    /// Optional local CAS blob directory root for offline/on-node IT bundle lookups.
    pub cas_blobs_dir: Option<PathBuf>,
    /// `MuIsolation::KernelSandbox` constraints enforced for IT execution (`max_pids: 256`).
    pub it_sandbox: ItSandboxConfig,
}

impl Default for MuConDeAgentConfig {
    fn default() -> Self {
        Self {
            node_id: "worker-node".into(),
            listen_addr: "0.0.0.0:8446".into(),
            muconde_root: PathBuf::from("/srv/muconde"),
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            default_warmup_timeout_secs: 30,
            required_consecutive_successes: 3,
            collector_addr: std::env::var("MUOBSERVE_COLLECTOR_ADDR").ok(),
            integration_tests: IntegrationTestSelection::All,
            gate_catalog: builtin_catalog(),
            ab_rules: AbRulesConfig::default(),
            it_archive_digest: None,
            it_bundle_id: None,
            registry_url: None,
            cas_blobs_dir: None,
            it_sandbox: ItSandboxConfig::default(),
        }
    }
}

/// Builds rustls ServerConfig enforcing mutual TLS (mTLS) with client certificate verification.
pub fn build_tls_server_config(
    ca_cert_path: impl AsRef<Path>,
    server_cert_path: impl AsRef<Path>,
    server_key_path: impl AsRef<Path>,
) -> Result<rustls::ServerConfig, AgentError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca_file = File::open(ca_cert_path.as_ref()).map_err(AgentError::Io)?;
    let mut ca_reader = BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AgentError::Tls(format!("Failed to parse CA certificate PEM: {e}")))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| AgentError::Tls(format!("Failed to add CA cert to root store: {e}")))?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| AgentError::Tls(format!("Failed to build client verifier: {e}")))?;

    let srv_file = File::open(server_cert_path.as_ref()).map_err(AgentError::Io)?;
    let mut srv_reader = BufReader::new(srv_file);
    let srv_certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_reader_iter(&mut srv_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AgentError::Tls(format!("Failed to parse server cert PEM: {e}")))?;

    let key_file = File::open(server_key_path.as_ref()).map_err(AgentError::Io)?;
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer<'static> =
        rustls_pki_types::PrivateKeyDer::from_pem_reader(&mut key_reader)
            .map_err(|e| AgentError::Tls(format!("Failed to parse server private key: {e}")))?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(srv_certs, key)
        .map_err(|e| AgentError::Tls(format!("Failed to configure server cert: {e}")))?;

    Ok(config)
}

/// Best-effort emission of `IntegrationTestProgress` frames (`MSG_TYPE_IT_PROGRESS`).
///
/// Progress is advisory: a write failure (for example a 0.1.x controller that already
/// closed the stream) never aborts the gate. Returns the number of frames written.
pub async fn send_it_progress<S: AsyncWrite + Unpin>(
    stream: &mut S,
    fory: &fory::Fory,
    updates: &[IntegrationTestProgress],
    sequence: u64,
) -> usize {
    let mut sent = 0usize;
    for update in updates {
        let bytes = match fory.serialize(update) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize IntegrationTestProgress");
                continue;
            }
        };
        let hdr = IpcHeader::new(MSG_TYPE_IT_PROGRESS, bytes.len() as u32, 0, sequence);
        if write_frame(stream, &hdr, &bytes).await.is_ok() {
            sent += 1;
        }
    }
    sent
}

/// Ephemeral staging directory cleaned automatically when dropped.
struct EphemeralUnpackDir(PathBuf);

impl EphemeralUnpackDir {
    fn create(muconde_root: &Path, deployment_id: &str) -> Result<Self, AgentError> {
        let safe_dep: String = deployment_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let dir = muconde_root.join(".it-staging").join(format!(
            "{}-{}",
            safe_dep,
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for EphemeralUnpackDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn write_it_report_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    fory: &fory::Fory,
    report: &IntegrationTestReport,
    sequence: u64,
) -> Result<(), AgentError> {
    let report_bytes = fory
        .serialize(report)
        .map_err(|e| AgentError::Serialization(e.to_string()))?;
    let report_header = IpcHeader::new(MSG_TYPE_IT_REPORT, report_bytes.len() as u32, 0, sequence);
    write_frame(stream, &report_header, &report_bytes).await?;
    Ok(())
}

async fn write_taint_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    fory: &fory::Fory,
    taint: &ArtifactTaintNotification,
    sequence: u64,
) -> Result<(), AgentError> {
    let taint_bytes = fory
        .serialize(taint)
        .map_err(|e| AgentError::Serialization(e.to_string()))?;
    let taint_header = IpcHeader::new(
        MSG_TYPE_ARTIFACT_TAINT,
        taint_bytes.len() as u32,
        0,
        sequence,
    );
    write_frame(stream, &taint_header, &taint_bytes).await?;
    Ok(())
}

/// Continuous delivery node agent running as a resident systemd daemon.
pub struct MuConDeAgent {
    config: MuConDeAgentConfig,
    btrfs_manager: Arc<BtrfsManager>,
    slot_manager: Arc<SlotManager>,
    watchdog_monitor: Arc<WatchdogMonitor>,
    telemetry_sink: Arc<dyn TelemetrySink>,
    it_fetcher: Arc<dyn ItArchiveFetcher>,
    it_executor: Arc<dyn SandboxedCommandExecutor>,
    staged_digests: Arc<Mutex<HashMap<String, String>>>,
}

impl MuConDeAgent {
    pub fn new(
        config: MuConDeAgentConfig,
        runner: Arc<dyn CommandRunner>,
        prober: Arc<dyn HealthProber>,
    ) -> Self {
        let btrfs_manager = Arc::new(
            BtrfsManager::new(&config.muconde_root, runner.clone())
                .with_ab_rules(config.ab_rules.clone()),
        );
        let slot_manager = Arc::new(SlotManager::new(&config.muconde_root, runner));
        let watchdog_monitor = Arc::new(WatchdogMonitor::new(
            &config.node_id,
            slot_manager.clone(),
            prober,
        ));
        let telemetry_sink = Arc::new(MuObserveCollectorSink::new(config.collector_addr.clone()));
        let it_fetcher = Arc::new(RegistryAndCasFetcher {
            cas_dir: config.cas_blobs_dir.clone(),
            registry_url: config.registry_url.clone(),
            bundle_id: config.it_bundle_id.clone(),
            bearer_token: None,
            tls_ca_path: config.tls_ca_path.clone(),
            tls_cert_path: config.tls_cert_path.clone(),
            tls_key_path: config.tls_key_path.clone(),
        });
        let it_executor = Arc::new(KernelSandboxedExecutor);

        Self {
            config,
            btrfs_manager,
            slot_manager,
            watchdog_monitor,
            telemetry_sink,
            it_fetcher,
            it_executor,
            staged_digests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Replaces the default `MuObserveCollectorSink` with a custom [`TelemetrySink`].
    #[must_use]
    pub fn with_telemetry_sink(mut self, telemetry_sink: Arc<dyn TelemetrySink>) -> Self {
        self.telemetry_sink = telemetry_sink;
        self
    }

    /// Replaces the CAS / `mu-registry` integration test archive fetcher.
    #[must_use]
    pub fn with_it_fetcher(mut self, it_fetcher: Arc<dyn ItArchiveFetcher>) -> Self {
        self.it_fetcher = it_fetcher;
        self
    }

    /// Replaces the `KernelSandbox` integration test executor.
    #[must_use]
    pub fn with_it_executor(mut self, it_executor: Arc<dyn SandboxedCommandExecutor>) -> Self {
        self.it_executor = it_executor;
        self
    }

    fn resolve_service_contract(
        &self,
        service_name: &str,
        slot: Option<Slot>,
    ) -> Result<(IntegrationTestSelection, Option<String>, AbRulesConfig), AgentError> {
        let mut search_dirs = Vec::new();
        if let Some(s) = slot {
            search_dirs.push(self.btrfs_manager.slot_dir(service_name, s.as_str()));
        }
        search_dirs.push(self.btrfs_manager.service_dir(service_name));
        search_dirs.push(self.config.muconde_root.clone());

        for dir in search_dirs {
            if let Some(manifest) = MuCdManifest::load_optional_from_dir(&dir)? {
                let selection = manifest.selection()?;
                let digest = manifest
                    .it_archive_digest
                    .or_else(|| self.config.it_archive_digest.clone());
                return Ok((selection, digest, manifest.ab_rules));
            }
        }

        Ok((
            self.config.integration_tests.clone(),
            self.config.it_archive_digest.clone(),
            self.config.ab_rules.clone(),
        ))
    }

    fn clone_for_connection(&self) -> Self {
        Self {
            config: self.config.clone(),
            btrfs_manager: self.btrfs_manager.clone(),
            slot_manager: self.slot_manager.clone(),
            watchdog_monitor: self.watchdog_monitor.clone(),
            telemetry_sink: self.telemetry_sink.clone(),
            it_fetcher: self.it_fetcher.clone(),
            it_executor: self.it_executor.clone(),
            staged_digests: self.staged_digests.clone(),
        }
    }

    async fn emit_rollback_span(
        &self,
        cmd: &SlotSwapCommand,
        restore_slot: Slot,
        reason: &str,
        swap_trace_ctx: &mu_observable_ipc::TraceContext,
        swap_end_ns: i64,
        elapsed_rollback_ms: u64,
    ) {
        let rb_ctx = swap_trace_ctx.next_deterministic_child(1);
        let rb_end_ns = now_unix_nano().max(swap_end_ns);
        let rb_span = OtelSpanEntry {
            trace_id: rb_ctx.trace_id_hex(),
            span_id: rb_ctx.span_id_hex(),
            parent_span_id: Some(swap_trace_ctx.span_id_hex()),
            service_name: AGENT_SERVICE_NAME.to_string(),
            node_id: self.config.node_id.clone(),
            span_name: "muconde.agent.rollback".to_string(),
            span_kind: "INTERNAL".to_string(),
            start_time_unix_nano: swap_end_ns,
            end_time_unix_nano: rb_end_ns,
            duration_ns: elapsed_rollback_ms * 1_000_000,
            status_code: "ERROR".to_string(),
            status_message: Some(reason.to_string()),
            attributes_json: serde_json::json!({
                "deployment_id": cmd.deployment_id,
                "service_name": cmd.service_name,
                "restore_slot": restore_slot.as_str(),
                "reason": reason,
                "elapsed_rollback_ms": elapsed_rollback_ms,
            })
            .to_string(),
        };
        self.telemetry_sink.emit_spans(vec![rb_span]).await;
    }

    pub fn telemetry_sink(&self) -> &Arc<dyn TelemetrySink> {
        &self.telemetry_sink
    }

    pub fn default_with_root(node_id: &str, root: PathBuf) -> Self {
        let runner = Arc::new(SystemCommandRunner::new());
        let prober = Arc::new(SystemHealthProber::new(runner.clone()));
        let config = MuConDeAgentConfig {
            node_id: node_id.to_string(),
            muconde_root: root,
            ..Default::default()
        };
        Self::new(config, runner, prober)
    }

    pub fn config(&self) -> &MuConDeAgentConfig {
        &self.config
    }

    pub fn btrfs_manager(&self) -> &Arc<BtrfsManager> {
        &self.btrfs_manager
    }

    pub fn slot_manager(&self) -> &Arc<SlotManager> {
        &self.slot_manager
    }

    pub fn watchdog_monitor(&self) -> &Arc<WatchdogMonitor> {
        &self.watchdog_monitor
    }

    /// Handles a single incoming IPC bidirectional connection stream.
    pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
    ) -> Result<(), AgentError> {
        let fory = create_fory_runtime()?;

        loop {
            let (header, payload) = match read_frame(&mut stream).await {
                Ok(frame) => frame,
                Err(mu_cd_ipc::IpcError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    tracing::debug!("Client disconnected cleanly");
                    return Ok(());
                }
                Err(e) => return Err(AgentError::Ipc(e)),
            };

            match header.msg_type {
                MSG_TYPE_STAGE_DEPLOY_REQ => {
                    let req: StageDeploymentRequest = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    tracing::info!(
                        deployment_id = %req.deployment_id,
                        service = %req.service_name,
                        slot = ?req.target_slot,
                        "Received StageDeploymentRequest"
                    );

                    let start_ns = now_unix_nano();
                    let trace_ctx = trace_context_for_deployment(&req.deployment_id, 1);

                    // Locate staging candidate binary path
                    let candidate_path = self
                        .config
                        .muconde_root
                        .join("staging")
                        .join(&req.artifact_sha256);

                    if self.config.muconde_root == Path::new("/srv/muconde") {
                        let _ = self.btrfs_manager.ensure_candidate_artifact(
                            &req.service_name,
                            &req.artifact_sha256,
                            &candidate_path,
                        );
                    }

                    let resp = match self.resolve_service_contract(&req.service_name, None) {
                        Ok((_, _, ab_rules)) => self
                            .btrfs_manager
                            .handle_stage_deployment_request_with_rules(
                                &req,
                                &candidate_path,
                                "",
                                &ab_rules,
                            ),
                        Err(e) => mu_cd_ipc::StageDeploymentResponse {
                            deployment_id: req.deployment_id.clone(),
                            target_slot: req.target_slot,
                            btrfs_subvolume_path: self
                                .btrfs_manager
                                .slot_dir(&req.service_name, Slot::from(req.target_slot).as_str())
                                .to_string_lossy()
                                .to_string(),
                            staged_ok: false,
                            error_message: Some(e.to_string()),
                        },
                    };
                    if resp.staged_ok {
                        self.staged_digests
                            .lock()
                            .await
                            .insert(req.deployment_id.clone(), req.artifact_sha256.clone());
                    }

                    let end_ns = now_unix_nano().max(start_ns);
                    let duration_ns = (end_ns - start_ns) as u64;

                    let span = OtelSpanEntry {
                        trace_id: trace_ctx.trace_id_hex(),
                        span_id: trace_ctx.span_id_hex(),
                        parent_span_id: None,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        span_name: "muconde.agent.stage_deployment".to_string(),
                        span_kind: "SERVER".to_string(),
                        start_time_unix_nano: start_ns,
                        end_time_unix_nano: end_ns,
                        duration_ns,
                        status_code: if resp.staged_ok { "OK" } else { "ERROR" }.to_string(),
                        status_message: resp.error_message.clone(),
                        attributes_json: serde_json::json!({
                            "deployment_id": req.deployment_id,
                            "lease_id": req.lease_id,
                            "service_name": req.service_name,
                            "artifact_sha256": req.artifact_sha256,
                            "target_slot": format!("{:?}", resp.target_slot),
                            "btrfs_subvolume_path": resp.btrfs_subvolume_path,
                            "staged_ok": resp.staged_ok,
                        })
                        .to_string(),
                    };

                    let metric = OtelMetricEntry {
                        timestamp_unix_nano: end_ns,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        metric_name: "muconde.agent.stage_duration_ms".to_string(),
                        metric_unit: "ms".to_string(),
                        value_f64: (duration_ns as f64) / 1_000_000.0,
                        arch: std::env::consts::ARCH.to_string(),
                        cpu_cluster: None,
                        vlen_bits: None,
                        memlock_used_bytes: None,
                        memlock_limit_bytes: None,
                        trace_id: Some(trace_ctx.trace_id_hex()),
                        span_id: Some(trace_ctx.span_id_hex()),
                        attributes_json: serde_json::json!({
                            "deployment_id": req.deployment_id,
                            "service_name": req.service_name,
                            "staged_ok": resp.staged_ok,
                        })
                        .to_string(),
                    };

                    self.telemetry_sink.emit_spans(vec![span]).await;
                    self.telemetry_sink.emit_metrics(vec![metric]).await;

                    let resp_bytes = fory
                        .serialize(&resp)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    let resp_header = IpcHeader::new(
                        MSG_TYPE_STAGE_DEPLOY_RESP,
                        resp_bytes.len() as u32,
                        0,
                        header.sequence,
                    );

                    write_frame(&mut stream, &resp_header, &resp_bytes).await?;
                }

                MSG_TYPE_SLOT_SWAP => {
                    let cmd: SlotSwapCommand = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    tracing::info!(
                        deployment_id = %cmd.deployment_id,
                        service = %cmd.service_name,
                        from_slot = ?cmd.from_slot,
                        target_slot = ?cmd.to_slot,
                        "Received SlotSwapCommand"
                    );

                    self.execute_slot_swap_and_gate(&mut stream, &fory, header.sequence, cmd)
                        .await?;
                }

                MSG_TYPE_ROLLBACK => {
                    let cmd: RollbackCommand = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    tracing::warn!(
                        deployment_id = %cmd.deployment_id,
                        service = %cmd.service_name,
                        reason = %cmd.reason,
                        "Received RollbackCommand from controller"
                    );

                    let rb_start_ns = now_unix_nano();
                    let rb_trace_ctx = trace_context_for_deployment(&cmd.deployment_id, 3);

                    let (report, taint, elapsed_ms) =
                        self.watchdog_monitor.handle_rollback_command(&cmd)?;

                    let rb_end_ns = now_unix_nano().max(rb_start_ns);
                    let rb_dur_ns = (rb_end_ns - rb_start_ns) as u64;

                    let rb_span = OtelSpanEntry {
                        trace_id: rb_trace_ctx.trace_id_hex(),
                        span_id: rb_trace_ctx.span_id_hex(),
                        parent_span_id: None,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        span_name: "muconde.agent.rollback".to_string(),
                        span_kind: "SERVER".to_string(),
                        start_time_unix_nano: rb_start_ns,
                        end_time_unix_nano: rb_end_ns,
                        duration_ns: rb_dur_ns,
                        status_code: "OK".to_string(),
                        status_message: Some(cmd.reason.clone()),
                        attributes_json: serde_json::json!({
                            "deployment_id": cmd.deployment_id,
                            "lease_id": cmd.lease_id,
                            "service_name": cmd.service_name,
                            "restore_slot": format!("{:?}", cmd.restore_slot),
                            "failed_artifact_sha256": cmd.failed_artifact_sha256,
                            "reason": cmd.reason,
                            "elapsed_rollback_ms": elapsed_ms,
                        })
                        .to_string(),
                    };

                    let rb_metric = OtelMetricEntry {
                        timestamp_unix_nano: rb_end_ns,
                        service_name: AGENT_SERVICE_NAME.to_string(),
                        node_id: self.config.node_id.clone(),
                        metric_name: "muconde.agent.rollback_duration_ms".to_string(),
                        metric_unit: "ms".to_string(),
                        value_f64: elapsed_ms as f64,
                        arch: std::env::consts::ARCH.to_string(),
                        cpu_cluster: None,
                        vlen_bits: None,
                        memlock_used_bytes: None,
                        memlock_limit_bytes: None,
                        trace_id: Some(rb_trace_ctx.trace_id_hex()),
                        span_id: Some(rb_trace_ctx.span_id_hex()),
                        attributes_json: serde_json::json!({
                            "deployment_id": cmd.deployment_id,
                            "service_name": cmd.service_name,
                            "restore_slot": Slot::from(cmd.restore_slot).as_str(),
                        })
                        .to_string(),
                    };

                    self.telemetry_sink.emit_spans(vec![rb_span]).await;
                    self.telemetry_sink.emit_metrics(vec![rb_metric]).await;

                    let report_bytes = fory
                        .serialize(&report)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;
                    let report_header = IpcHeader::new(
                        MSG_TYPE_IT_REPORT,
                        report_bytes.len() as u32,
                        0,
                        header.sequence,
                    );
                    write_frame(&mut stream, &report_header, &report_bytes).await?;

                    let taint_bytes = fory
                        .serialize(&taint)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;
                    let taint_header = IpcHeader::new(
                        MSG_TYPE_ARTIFACT_TAINT,
                        taint_bytes.len() as u32,
                        0,
                        header.sequence,
                    );
                    write_frame(&mut stream, &taint_header, &taint_bytes).await?;
                }

                MSG_TYPE_HEARTBEAT => {
                    let hb = HeartbeatTelemetry {
                        node_id: self.config.node_id.clone(),
                        active_deployments: 0,
                        btrfs_free_bytes: 100 * 1024 * 1024 * 1024,
                        timestamp_epoch_ms: now_epoch_ms(),
                    };
                    let hb_bytes = fory
                        .serialize(&hb)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;
                    let hb_header = IpcHeader::new(
                        MSG_TYPE_HEARTBEAT,
                        hb_bytes.len() as u32,
                        0,
                        header.sequence,
                    );
                    write_frame(&mut stream, &hb_header, &hb_bytes).await?;
                }

                other => {
                    tracing::warn!("Unrecognized message type: 0x{:02X}", other);
                }
            }
        }
    }

    /// Daemon listener loop binding to `config.listen_addr` and serving incoming connections.
    pub async fn run(&self) -> Result<(), AgentError> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        tracing::info!(
            addr = %self.config.listen_addr,
            node_id = %self.config.node_id,
            "MuConDe-agent daemon listening for controller RPCs"
        );

        let tls_acceptor = if let (Some(ca), Some(cert), Some(key)) = (
            &self.config.tls_ca_path,
            &self.config.tls_cert_path,
            &self.config.tls_key_path,
        ) {
            let tls_config = build_tls_server_config(ca, cert, key)?;
            Some(TlsAcceptor::from(Arc::new(tls_config)))
        } else {
            None
        };

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            tracing::debug!(remote = %remote_addr, "Accepted incoming IPC connection");

            if let Some(ref acceptor) = tls_acceptor {
                let acceptor = acceptor.clone();
                let conn_agent = self.clone_for_connection();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = conn_agent.handle_connection(tls_stream).await {
                                tracing::error!("Connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("TLS handshake failed: {}", e);
                        }
                    }
                });
            } else {
                let conn_agent = self.clone_for_connection();

                tokio::spawn(async move {
                    if let Err(e) = conn_agent.handle_connection(stream).await {
                        tracing::error!("Connection error: {}", e);
                    }
                });
            }
        }
    }

    async fn prepare_gate_and_bundle(
        &self,
        cmd: &SlotSwapCommand,
        target_slot: Slot,
    ) -> Result<
        (
            Vec<GateTest>,
            Vec<DiscoveredItTest>,
            Option<EphemeralUnpackDir>,
            AbRulesConfig,
        ),
        AgentError,
    > {
        let (selection, it_digest_opt, ab_rules) =
            self.resolve_service_contract(&cmd.service_name, Some(target_slot))?;

        let mut unpack_guard = None;
        let mut unpacked_bundle = None;
        if let Some(ref digest) = it_digest_opt {
            let dir_guard =
                EphemeralUnpackDir::create(&self.config.muconde_root, &cmd.deployment_id)?;
            let archive_bytes = self.it_fetcher.fetch_it_archive(digest).await?;
            let bundle = unpack_verified_it_archive(&archive_bytes, digest, dir_guard.path())?;
            unpacked_bundle = Some(bundle);
            unpack_guard = Some(dir_guard);
        }

        let (gate_tests, custom_tests) = resolve_gate_plan_with_base(
            &self.config.gate_catalog,
            &selection,
            unpacked_bundle.as_ref(),
        )?;
        Ok((gate_tests, custom_tests, unpack_guard, ab_rules))
    }

    async fn execute_slot_swap_and_gate<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        sequence: u64,
        cmd: SlotSwapCommand,
    ) -> Result<(), AgentError> {
        let swap_start_ns = now_unix_nano();
        let swap_trace_ctx = trace_context_for_deployment(&cmd.deployment_id, 2);

        let target_slot = Slot::from(cmd.to_slot);
        let restore_slot = Slot::from(cmd.from_slot);
        let staged_sha = self
            .staged_digests
            .lock()
            .await
            .get(&cmd.deployment_id)
            .cloned();
        let disk_sha = self
            .btrfs_manager
            .read_slot_digest(&cmd.service_name, target_slot)
            .ok()
            .flatten();
        let candidate_sha256 = staged_sha
            .or(disk_sha)
            .unwrap_or_else(|| "candidate-sha".to_string());

        let _receipt = self
            .slot_manager
            .atomic_swap_active_slot(&cmd.service_name, target_slot)?;

        let swap_end_ns = now_unix_nano().max(swap_start_ns);
        let swap_dur_ns = (swap_end_ns - swap_start_ns) as u64;

        let swap_span = OtelSpanEntry {
            trace_id: swap_trace_ctx.trace_id_hex(),
            span_id: swap_trace_ctx.span_id_hex(),
            parent_span_id: None,
            service_name: AGENT_SERVICE_NAME.to_string(),
            node_id: self.config.node_id.clone(),
            span_name: "muconde.agent.slot_swap".to_string(),
            span_kind: "SERVER".to_string(),
            start_time_unix_nano: swap_start_ns,
            end_time_unix_nano: swap_end_ns,
            duration_ns: swap_dur_ns,
            status_code: "OK".to_string(),
            status_message: None,
            attributes_json: serde_json::json!({
                "deployment_id": cmd.deployment_id,
                "lease_id": cmd.lease_id,
                "service_name": cmd.service_name,
                "from_slot": format!("{:?}", cmd.from_slot),
                "to_slot": format!("{:?}", cmd.to_slot),
                "subvolume": target_slot.as_str(),
                "systemd_unit": cmd.systemd_unit,
            })
            .to_string(),
        };

        let slot_metric = OtelMetricEntry {
            timestamp_unix_nano: swap_end_ns,
            service_name: AGENT_SERVICE_NAME.to_string(),
            node_id: self.config.node_id.clone(),
            metric_name: "muconde.agent.active_slot".to_string(),
            metric_unit: "slot".to_string(),
            value_f64: match target_slot {
                Slot::A => 0.0,
                Slot::B => 1.0,
            },
            arch: std::env::consts::ARCH.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: Some(swap_trace_ctx.trace_id_hex()),
            span_id: Some(swap_trace_ctx.span_id_hex()),
            attributes_json: serde_json::json!({
                "deployment_id": cmd.deployment_id,
                "service_name": cmd.service_name,
                "subvolume": target_slot.as_str(),
            })
            .to_string(),
        };

        self.telemetry_sink.emit_spans(vec![swap_span]).await;
        self.telemetry_sink.emit_metrics(vec![slot_metric]).await;

        let (gate_tests, custom_tests, _unpack_guard, ab_rules) =
            match self.prepare_gate_and_bundle(&cmd, target_slot).await {
                Ok(plan) => plan,
                Err(gate_err) => {
                    return self
                        .handle_gate_preflight_failure(
                            stream,
                            fory,
                            sequence,
                            &cmd,
                            restore_slot,
                            &candidate_sha256,
                            &swap_trace_ctx,
                            swap_end_ns,
                            gate_err,
                        )
                        .await;
                }
            };

        let mut gate = GateTracker::new(&cmd.deployment_id, gate_tests);
        send_it_progress(stream, fory, &gate.pending_updates(), sequence).await;

        let custom_names: Vec<String> = custom_tests.iter().map(|t| t.name.clone()).collect();
        let mut warmup_running = Vec::new();
        for name in gate.names() {
            if !custom_names.contains(&name) {
                if let Some(upd) = gate.start_test(&name) {
                    warmup_running.push(upd);
                }
            }
        }
        send_it_progress(stream, fory, &warmup_running, sequence).await;

        let mut last_systemd_active: Option<bool> = None;
        let mut last_endpoint_ok: Option<bool> = None;

        let (tx, mut rx) = mpsc::channel(32);
        let monitor = self.watchdog_monitor.clone();
        let cmd_clone = cmd.clone();
        let cand_sha_clone = candidate_sha256.clone();
        let consecutive_req = self.config.required_consecutive_successes;
        let expires_at_ms = now_epoch_ms() + (cmd.warmup_timeout_secs * 1000);

        let outcome_task = tokio::spawn(async move {
            monitor
                .monitor_warmup(
                    &cmd_clone,
                    &cand_sha_clone,
                    expires_at_ms,
                    consecutive_req,
                    Some(tx),
                    None,
                )
                .await
        });

        while let Some(telem) = rx.recv().await {
            last_systemd_active = Some(telem.systemd_active);
            last_endpoint_ok = Some(telem.health_endpoint_ok);
            let ts_ns = now_unix_nano();
            let probe_attrs = serde_json::json!({
                "deployment_id": telem.deployment_id,
                "service_name": telem.service_name,
                "active_slot": format!("{:?}", telem.active_slot),
                "systemd_active": telem.systemd_active,
                "health_endpoint_ok": telem.health_endpoint_ok,
            })
            .to_string();

            let probe_metrics = vec![
                OtelMetricEntry {
                    timestamp_unix_nano: ts_ns,
                    service_name: AGENT_SERVICE_NAME.to_string(),
                    node_id: self.config.node_id.clone(),
                    metric_name: "muconde.agent.slot_probe_latency_ms".to_string(),
                    metric_unit: "ms".to_string(),
                    value_f64: f64::from(telem.probe_latency_ms),
                    arch: std::env::consts::ARCH.to_string(),
                    cpu_cluster: None,
                    vlen_bits: None,
                    memlock_used_bytes: None,
                    memlock_limit_bytes: None,
                    trace_id: Some(swap_trace_ctx.trace_id_hex()),
                    span_id: Some(swap_trace_ctx.span_id_hex()),
                    attributes_json: probe_attrs.clone(),
                },
                OtelMetricEntry {
                    timestamp_unix_nano: ts_ns,
                    service_name: AGENT_SERVICE_NAME.to_string(),
                    node_id: self.config.node_id.clone(),
                    metric_name: "muconde.agent.slot_probe_healthy".to_string(),
                    metric_unit: "1".to_string(),
                    value_f64: if telem.systemd_active && telem.health_endpoint_ok {
                        1.0
                    } else {
                        0.0
                    },
                    arch: std::env::consts::ARCH.to_string(),
                    cpu_cluster: None,
                    vlen_bits: None,
                    memlock_used_bytes: None,
                    memlock_limit_bytes: None,
                    trace_id: Some(swap_trace_ctx.trace_id_hex()),
                    span_id: Some(swap_trace_ctx.span_id_hex()),
                    attributes_json: probe_attrs,
                },
            ];
            self.telemetry_sink.emit_metrics(probe_metrics).await;

            let telem_bytes = fory
                .serialize(&telem)
                .map_err(|e| AgentError::Serialization(e.to_string()))?;
            let telem_header =
                IpcHeader::new(MSG_TYPE_HEALTH_PROBE, telem_bytes.len() as u32, 0, sequence);
            let _ = write_frame(stream, &telem_header, &telem_bytes).await;
        }

        match outcome_task.await {
            Ok(Ok(WatchdogOutcome::RolledBack {
                mut report,
                taint,
                elapsed_rollback_ms,
            })) => {
                self.emit_rollback_span(
                    &cmd,
                    restore_slot,
                    &taint.reason,
                    &swap_trace_ctx,
                    swap_end_ns,
                    elapsed_rollback_ms,
                )
                .await;

                let finished = gate.finish_remaining(|t| {
                    builtin_verdict(&t.name, last_systemd_active, last_endpoint_ok, false)
                });
                send_it_progress(stream, fory, &finished, sequence).await;

                report.executed_tests = gate.names();
                report.log_excerpt = report
                    .log_excerpt
                    .as_deref()
                    .map(|raw| sanitize_and_bound_log_excerpt(raw, MAX_LOG_EXCERPT_BYTES));
                write_it_report_frame(stream, fory, &report, sequence).await?;
                write_taint_frame(stream, fory, &taint, sequence).await?;
            }
            Ok(Ok(WatchdogOutcome::WarmedUp { .. })) => {
                let mut builtin_finished = Vec::new();
                for name in gate.names() {
                    if !custom_names.contains(&name) {
                        if let Some(upd) = gate.finish(&name, true) {
                            builtin_finished.push(upd);
                        }
                    }
                }
                send_it_progress(stream, fory, &builtin_finished, sequence).await;

                if custom_tests.is_empty() {
                    tracing::info!(
                        deployment_id = %cmd.deployment_id,
                        "Warmup completed successfully"
                    );
                } else {
                    self.run_sandboxed_it_tests(
                        stream,
                        fory,
                        sequence,
                        &cmd,
                        target_slot,
                        restore_slot,
                        &candidate_sha256,
                        &swap_trace_ctx,
                        swap_end_ns,
                        &mut gate,
                        &custom_tests,
                        &ab_rules,
                    )
                    .await?;
                }
            }
            Ok(Err(e)) => {
                let finished = gate.finish_remaining(|_| false);
                send_it_progress(stream, fory, &finished, sequence).await;
                tracing::error!("Watchdog error: {}", e);
            }
            Err(join_err) => {
                let finished = gate.finish_remaining(|_| false);
                send_it_progress(stream, fory, &finished, sequence).await;
                tracing::error!("Watchdog task join error: {}", join_err);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_gate_preflight_failure<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        sequence: u64,
        cmd: &SlotSwapCommand,
        restore_slot: Slot,
        candidate_sha256: &str,
        swap_trace_ctx: &mu_observable_ipc::TraceContext,
        swap_end_ns: i64,
        gate_err: AgentError,
    ) -> Result<(), AgentError> {
        let reason = gate_err.to_string();
        let failed_tests = match &gate_err {
            AgentError::UnknownIntegrationTests(missing) if !missing.is_empty() => missing.clone(),
            _ => vec!["it_bundle_verification".to_string()],
        };
        let gate_tests: Vec<GateTest> = failed_tests
            .iter()
            .map(|name| GateTest::new(name, true))
            .collect();
        let mut tracker = GateTracker::new(&cmd.deployment_id, gate_tests);
        send_it_progress(stream, fory, &tracker.pending_updates(), sequence).await;
        send_it_progress(stream, fory, &tracker.start_all(), sequence).await;
        let finished = tracker.finish_remaining(|_| false);
        send_it_progress(stream, fory, &finished, sequence).await;

        let (mut report, taint, elapsed_rollback_ms) = self.watchdog_monitor.execute_rollback(
            &cmd.deployment_id,
            &cmd.service_name,
            restore_slot,
            candidate_sha256,
            &reason,
        )?;
        self.emit_rollback_span(
            cmd,
            restore_slot,
            &taint.reason,
            swap_trace_ctx,
            swap_end_ns,
            elapsed_rollback_ms,
        )
        .await;

        report.executed_tests = failed_tests.clone();
        report.failed_tests = failed_tests;
        report.log_excerpt = Some(sanitize_and_bound_log_excerpt(
            &reason,
            MAX_LOG_EXCERPT_BYTES,
        ));
        write_it_report_frame(stream, fory, &report, sequence).await?;
        write_taint_frame(stream, fory, &taint, sequence).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_sandboxed_it_tests<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        sequence: u64,
        cmd: &SlotSwapCommand,
        target_slot: Slot,
        restore_slot: Slot,
        candidate_sha256: &str,
        swap_trace_ctx: &mu_observable_ipc::TraceContext,
        swap_end_ns: i64,
        gate: &mut GateTracker,
        custom_tests: &[DiscoveredItTest],
        ab_rules: &AbRulesConfig,
    ) -> Result<(), AgentError> {
        let suite_start = Instant::now();
        let mut aggregated_logs = String::new();

        for test in custom_tests {
            if let Some(running) = gate.start_test(&test.name) {
                send_it_progress(stream, fory, &[running], sequence).await;
            }

            let timeout = Duration::from_secs(
                test.timeout_secs
                    .unwrap_or(self.config.it_sandbox.per_test_timeout_secs),
            );
            let exec_res = self
                .it_executor
                .execute_in_sandbox(
                    test,
                    &test.working_dir,
                    &self.config.it_sandbox,
                    &cmd.service_name,
                    target_slot,
                    timeout,
                )
                .await;

            let (passed, detail_log) = match exec_res {
                Ok(out) => (out.passed, out.log_output),
                Err(err) => (false, format!("Sandbox execution failed: {err}")),
            };

            if !detail_log.is_empty() {
                aggregated_logs.push_str(&format!("[{}] {}\n", test.name, detail_log));
            }

            if let Some(done) = gate.finish(&test.name, passed) {
                send_it_progress(stream, fory, &[done], sequence).await;
            }

            if !passed && test.critical && ab_rules.auto_rollback_on_critical {
                let remaining_failed = gate.finish_remaining(|_| false);
                send_it_progress(stream, fory, &remaining_failed, sequence).await;

                let reason = format!("Critical sandboxed integration test '{}' failed", test.name);
                let (mut report, taint, elapsed_rollback_ms) =
                    self.watchdog_monitor.execute_rollback(
                        &cmd.deployment_id,
                        &cmd.service_name,
                        restore_slot,
                        candidate_sha256,
                        &reason,
                    )?;
                self.emit_rollback_span(
                    cmd,
                    restore_slot,
                    &taint.reason,
                    swap_trace_ctx,
                    swap_end_ns,
                    elapsed_rollback_ms,
                )
                .await;

                let mut failed = gate.names_in(TestState::Failed);
                if failed.is_empty() {
                    failed.push(test.name.clone());
                }
                report.executed_tests = gate.names();
                report.failed_tests = failed;
                report.passed = false;
                report.duration_ms = suite_start.elapsed().as_millis() as u64;
                report.log_excerpt = Some(sanitize_and_bound_log_excerpt(
                    if aggregated_logs.trim().is_empty() {
                        &reason
                    } else {
                        &aggregated_logs
                    },
                    MAX_LOG_EXCERPT_BYTES,
                ));

                write_it_report_frame(stream, fory, &report, sequence).await?;
                write_taint_frame(stream, fory, &taint, sequence).await?;
                return Ok(());
            }
        }

        let failed_tests = gate.names_in(TestState::Failed);
        let critical_failures = gate.critical_failures();
        let report = IntegrationTestReport {
            deployment_id: cmd.deployment_id.clone(),
            service_name: cmd.service_name.clone(),
            artifact_sha256: candidate_sha256.to_string(),
            executed_tests: gate.names(),
            passed: critical_failures.is_empty(),
            failed_tests,
            duration_ms: suite_start.elapsed().as_millis() as u64,
            log_excerpt: if aggregated_logs.trim().is_empty() {
                None
            } else {
                Some(sanitize_and_bound_log_excerpt(
                    &aggregated_logs,
                    MAX_LOG_EXCERPT_BYTES,
                ))
            },
        };
        write_it_report_frame(stream, fory, &report, sequence).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::MockCommandRunner;
    use crate::watchdog::MockHealthProber;
    use mu_cd_ipc::{
        ArtifactTaintNotification, DeploymentSlot, HealthProbeTelemetry, IntegrationTestReport,
        StageDeploymentResponse,
    };
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_stage_deployment_request_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        fs::create_dir_all(&root).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-test-1".into(),
            muconde_root: root.clone(),
            ..Default::default()
        };

        // Prepare dummy candidate binary in staging/
        let staging_dir = root.join("staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let artifact_hash = "abc123456789";
        fs::write(staging_dir.join(artifact_hash), b"binary_data").unwrap();

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));

        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        // 1. Client sends StageDeploymentRequest
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-ipc-1".into(),
            lease_id: "lease-1".into(),
            service_name: "action-runner".into(),
            artifact_sha256: artifact_hash.into(),
            target_slot: DeploymentSlot::SlotB,
        };

        let req_bytes = fory.serialize(&stage_req).unwrap();
        let req_header = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, req_bytes.len() as u32, 0, 1);
        write_frame(&mut client, &req_header, &req_bytes)
            .await
            .unwrap();

        // 2. Client receives StageDeploymentResponse
        let (resp_hdr, resp_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(resp_hdr.msg_type, MSG_TYPE_STAGE_DEPLOY_RESP);
        let resp: StageDeploymentResponse = fory.deserialize(&resp_payload).unwrap();
        assert_eq!(resp.deployment_id, "dep-ipc-1");
        assert!(resp.staged_ok);

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_slot_swap_and_telemetry_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "action-runner";

        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-test-swap".into(),
            muconde_root: root.clone(),
            required_consecutive_successes: 2,
            ..Default::default()
        };

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-swap-stream".into(),
            lease_id: "lease-stream".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "action-runner.service".into(),
            warmup_timeout_secs: 5,
        };

        let cmd_bytes = fory.serialize(&swap_cmd).unwrap();
        let cmd_header = IpcHeader::new(MSG_TYPE_SLOT_SWAP, cmd_bytes.len() as u32, 0, 100);
        write_frame(&mut client, &cmd_header, &cmd_bytes)
            .await
            .unwrap();

        // Read streamed HealthProbeTelemetry frames
        let mut telemetry_frames = 0;
        loop {
            tokio::select! {
                frame_res = read_frame(&mut client) => {
                    match frame_res {
                        Ok((hdr, payload)) => {
                            if hdr.msg_type == MSG_TYPE_HEALTH_PROBE {
                                telemetry_frames += 1;
                                let telem: HealthProbeTelemetry = fory.deserialize(&payload).unwrap();
                                assert_eq!(telem.deployment_id, "dep-swap-stream");
                                assert!(telem.systemd_active);
                                if telemetry_frames >= 2 {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => break,
            }
        }

        assert!(telemetry_frames >= 2);
        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_heartbeat_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-heartbeat".into(),
            muconde_root: root,
            ..Default::default()
        };

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        let hb = HeartbeatTelemetry {
            node_id: "node-heartbeat".into(),
            active_deployments: 0,
            btrfs_free_bytes: 50 * 1024 * 1024 * 1024,
            timestamp_epoch_ms: 12345678,
        };

        let hb_bytes = fory.serialize(&hb).unwrap();
        let hb_header = IpcHeader::new(MSG_TYPE_HEARTBEAT, hb_bytes.len() as u32, 0, 200);
        write_frame(&mut client, &hb_header, &hb_bytes)
            .await
            .unwrap();

        let (resp_hdr, resp_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(resp_hdr.msg_type, MSG_TYPE_HEARTBEAT);
        let resp_hb: HeartbeatTelemetry = fory.deserialize(&resp_payload).unwrap();
        assert_eq!(resp_hb.node_id, "node-heartbeat");

        drop(client);
        let _ = agent_task.await;
    }

    /// Drives one SlotSwapCommand and collects frames until `stop` returns true or 6 s elapse.
    async fn run_swap_and_collect(
        config: MuConDeAgentConfig,
        prober: Arc<MockHealthProber>,
        service: &str,
        stop: impl Fn(&[(u16, Vec<u8>)]) -> bool,
    ) -> Vec<(u16, Vec<u8>)> {
        let srv_dir = config.muconde_root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        let runner = Arc::new(MockCommandRunner::new(true));
        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-gate-1".into(),
            lease_id: "lease-gate-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let bytes = fory.serialize(&swap_cmd).unwrap();
        let hdr = IpcHeader::new(MSG_TYPE_SLOT_SWAP, bytes.len() as u32, 0, 7);
        write_frame(&mut client, &hdr, &bytes).await.unwrap();

        let mut frames = Vec::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(6);
        while !stop(&frames) {
            match tokio::time::timeout_at(deadline, read_frame(&mut client)).await {
                Ok(Ok((h, p))) => {
                    assert_eq!(h.sequence, 7, "frames echo the command sequence");
                    frames.push((h.msg_type, p));
                }
                _ => break,
            }
        }
        drop(client);
        let _ = agent_task.await;
        frames
    }

    fn progress_of(frames: &[(u16, Vec<u8>)]) -> Vec<IntegrationTestProgress> {
        let fory = create_fory_runtime().unwrap();
        frames
            .iter()
            .filter(|(t, _)| *t == MSG_TYPE_IT_PROGRESS)
            .map(|(_, p)| fory.deserialize(p).unwrap())
            .collect()
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_gate_emits_pending_running_passed_on_healthy_warmup() {
        use crate::gate::{TEST_HEALTH_ENDPOINT_READY, TEST_SYSTEMD_UNIT_ACTIVE};
        use mu_cd_ipc::TestState;

        let temp = tempdir().unwrap();
        let config = MuConDeAgentConfig {
            node_id: "node-gate".into(),
            muconde_root: temp.path().join("muconde"),
            required_consecutive_successes: 2,
            ..Default::default()
        };
        let frames = run_swap_and_collect(
            config,
            Arc::new(MockHealthProber::new(true)),
            "action-runner",
            |f| progress_of(f).len() >= 6,
        )
        .await;
        let progress = progress_of(&frames);
        assert_eq!(progress.len(), 6, "2 Pending + 2 Running + 2 Passed");
        let states: Vec<TestState> = progress.iter().map(|p| p.state).collect();
        assert_eq!(
            states,
            vec![
                TestState::Pending,
                TestState::Pending,
                TestState::Running,
                TestState::Running,
                TestState::Passed,
                TestState::Passed,
            ]
        );
        assert_eq!(progress[0].test_name, TEST_SYSTEMD_UNIT_ACTIVE);
        assert_eq!(progress[1].test_name, TEST_HEALTH_ENDPOINT_READY);
        assert!(progress.iter().all(|p| p.critical));
        assert!(progress.iter().all(|p| p.deployment_id == "dep-gate-1"));
        assert!(progress[..4].iter().all(|p| p.duration_ms == 0));
        // Two 250 ms probe ticks are needed, so Passed carries a real duration.
        assert!(
            progress[4].duration_ms >= 200,
            "{}",
            progress[4].duration_ms
        );
        // Pending/Running frames precede every health probe frame.
        let first_probe = frames
            .iter()
            .position(|(t, _)| *t == MSG_TYPE_HEALTH_PROBE)
            .unwrap();
        assert!(first_probe >= 4);
        // No aggregate report on success (unchanged behaviour).
        assert!(!frames.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_gate_reports_failed_critical_test_then_final_report_and_taint() {
        use crate::gate::{TEST_HEALTH_ENDPOINT_READY, TEST_SYSTEMD_UNIT_ACTIVE};
        use mu_cd_ipc::TestState;

        let temp = tempdir().unwrap();
        let config = MuConDeAgentConfig {
            node_id: "node-gate-fail".into(),
            muconde_root: temp.path().join("muconde"),
            ..Default::default()
        };
        // systemd unit up, health endpoint down.
        let prober = Arc::new(MockHealthProber::new(true));
        prober
            .endpoint_ok
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let frames = run_swap_and_collect(config, prober, "muregist", |f| {
            f.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;

        let progress = progress_of(&frames);
        assert_eq!(progress.len(), 6);
        let finals = &progress[4..];
        let sys = finals
            .iter()
            .find(|p| p.test_name == TEST_SYSTEMD_UNIT_ACTIVE)
            .unwrap();
        let hep = finals
            .iter()
            .find(|p| p.test_name == TEST_HEALTH_ENDPOINT_READY)
            .unwrap();
        assert_eq!(sys.state, TestState::Passed);
        assert_eq!(hep.state, TestState::Failed);
        assert!(hep.critical);

        // Order: final progress, then the aggregate IntegrationTestReport, then the taint.
        let types: Vec<u16> = frames.iter().map(|(t, _)| *t).collect();
        let last_progress = types
            .iter()
            .rposition(|t| *t == MSG_TYPE_IT_PROGRESS)
            .unwrap();
        let report_idx = types.iter().position(|t| *t == MSG_TYPE_IT_REPORT).unwrap();
        let taint_idx = types
            .iter()
            .position(|t| *t == MSG_TYPE_ARTIFACT_TAINT)
            .unwrap();
        assert!(last_progress < report_idx && report_idx < taint_idx);

        let fory = create_fory_runtime().unwrap();
        let report: IntegrationTestReport = fory.deserialize(&frames[report_idx].1).unwrap();
        assert!(!report.passed);
        assert_eq!(report.deployment_id, "dep-gate-1");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_gate_honours_selected_integration_tests() {
        use crate::gate::{IntegrationTestSelection, TEST_HEALTH_ENDPOINT_READY};

        let temp = tempdir().unwrap();
        let config = MuConDeAgentConfig {
            node_id: "node-gate-sel".into(),
            muconde_root: temp.path().join("muconde"),
            required_consecutive_successes: 1,
            integration_tests: IntegrationTestSelection::Selected(vec![
                TEST_HEALTH_ENDPOINT_READY.into()
            ]),
            ..Default::default()
        };
        let frames = run_swap_and_collect(
            config,
            Arc::new(MockHealthProber::new(true)),
            "action-runner",
            |f| progress_of(f).len() >= 3,
        )
        .await;
        let progress = progress_of(&frames);
        assert_eq!(progress.len(), 3);
        assert!(progress
            .iter()
            .all(|p| p.test_name == TEST_HEALTH_ENDPOINT_READY));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_send_it_progress_is_best_effort_on_closed_stream() {
        let fory = create_fory_runtime().unwrap();
        let (client, mut server) = tokio::io::duplex(1024);
        drop(client);
        let gate = GateTracker::new("dep-x", builtin_catalog());
        let sent = send_it_progress(&mut server, &fory, &gate.pending_updates(), 1).await;
        assert_eq!(sent, 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_build_tls_server_config() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let temp = tempdir().unwrap();

        // 1. Generate CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let ca_cert_path = temp.path().join("ca.crt");
        fs::write(&ca_cert_path, ca_cert.pem()).unwrap();

        // 2. Generate Server Certificate
        let server_key = KeyPair::generate().unwrap();
        let server_params = CertificateParams::new(vec!["node-a".to_string()]).unwrap();
        let server_cert = server_params.self_signed(&server_key).unwrap();

        let server_cert_path = temp.path().join("server.crt");
        let server_key_path = temp.path().join("server.key");
        fs::write(&server_cert_path, server_cert.pem()).unwrap();
        fs::write(&server_key_path, server_key.serialize_pem()).unwrap();

        // 3. Verify server config builds cleanly
        let config = build_tls_server_config(&ca_cert_path, &server_cert_path, &server_key_path);
        assert!(config.is_ok());

        // Error path: non-existent file
        let invalid =
            build_tls_server_config("nonexistent.crt", &server_cert_path, &server_key_path);
        assert!(invalid.is_err());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_rollback_command_over_duplex() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "muregist";

        // Setup physical slots
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));

        let config = MuConDeAgentConfig {
            node_id: "node-test-rb".into(),
            muconde_root: root.clone(),
            ..Default::default()
        };

        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));
        // Start on Slot B
        agent
            .slot_manager
            .atomic_swap_active_slot(service, Slot::B)
            .unwrap();

        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        // Send RollbackCommand
        let rollback_cmd = RollbackCommand {
            deployment_id: "dep-abort-1".into(),
            lease_id: "lease-abort".into(),
            service_name: service.into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: "bad-sha".into(),
            reason: "Controller commanded emergency rollback".into(),
        };

        let cmd_bytes = fory.serialize(&rollback_cmd).unwrap();
        let cmd_header = IpcHeader::new(MSG_TYPE_ROLLBACK, cmd_bytes.len() as u32, 0, 42);
        write_frame(&mut client, &cmd_header, &cmd_bytes)
            .await
            .unwrap();

        // Expect IntegrationTestReport
        let (rep_hdr, rep_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(rep_hdr.msg_type, MSG_TYPE_IT_REPORT);
        let report: IntegrationTestReport = fory.deserialize(&rep_payload).unwrap();
        assert_eq!(report.deployment_id, "dep-abort-1");
        assert!(!report.passed);

        // Expect ArtifactTaintNotification
        let (taint_hdr, taint_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(taint_hdr.msg_type, MSG_TYPE_ARTIFACT_TAINT);
        let taint: ArtifactTaintNotification = fory.deserialize(&taint_payload).unwrap();
        assert_eq!(taint.deployment_id, "dep-abort-1");
        assert!(taint.rollback_completed);

        // Verify active slot is reverted to A
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A)
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_emits_otel_spans_and_metrics_for_staging_swap_probes_and_rollback() {
        use crate::telemetry::RecordingTelemetrySink;

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "action-runner";

        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();

        let staging_dir = root.join("staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let artifact_hash = "sha256-candidate-otel";
        fs::write(staging_dir.join(artifact_hash), b"candidate_binary").unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));
        let recorder = Arc::new(RecordingTelemetrySink::new());

        let config = MuConDeAgentConfig {
            node_id: "worker-riscv64".into(),
            muconde_root: root.clone(),
            required_consecutive_successes: 2,
            ..Default::default()
        };

        let agent = Arc::new(
            MuConDeAgent::new(config, runner, prober).with_telemetry_sink(recorder.clone()),
        );
        let (mut client, server) = tokio::io::duplex(64 * 1024);

        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            agent_server.handle_connection(server).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();

        // 1. StageDeployment
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-otel-1".into(),
            lease_id: "lease-otel-1".into(),
            service_name: service.into(),
            artifact_sha256: artifact_hash.into(),
            target_slot: DeploymentSlot::SlotB,
        };
        let req_bytes = fory.serialize(&stage_req).unwrap();
        let req_header = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, req_bytes.len() as u32, 0, 1);
        write_frame(&mut client, &req_header, &req_bytes)
            .await
            .unwrap();
        let (_resp_hdr, _resp_payload) = read_frame(&mut client).await.unwrap();

        // 2. SlotSwap + Health Probes
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-otel-1".into(),
            lease_id: "lease-otel-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "action-runner.service".into(),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        let swap_header = IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2);
        write_frame(&mut client, &swap_header, &swap_bytes)
            .await
            .unwrap();

        let mut probes_received = 0;
        while probes_received < 2 {
            let (hdr, _payload) = read_frame(&mut client).await.unwrap();
            if hdr.msg_type == MSG_TYPE_HEALTH_PROBE {
                probes_received += 1;
            }
        }

        // 3. RollbackCommand
        let rollback_cmd = RollbackCommand {
            deployment_id: "dep-otel-1".into(),
            lease_id: "lease-otel-1".into(),
            service_name: service.into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: artifact_hash.into(),
            reason: "SLO latency breach".into(),
        };
        let rb_bytes = fory.serialize(&rollback_cmd).unwrap();
        let rb_header = IpcHeader::new(MSG_TYPE_ROLLBACK, rb_bytes.len() as u32, 0, 3);
        write_frame(&mut client, &rb_header, &rb_bytes)
            .await
            .unwrap();
        let _ = read_frame(&mut client).await.unwrap();
        let _ = read_frame(&mut client).await.unwrap();

        drop(client);
        let _ = agent_task.await;

        let spans = recorder.recorded_spans().await;
        let span_names: Vec<&str> = spans.iter().map(|s| s.span_name.as_str()).collect();
        assert!(span_names.contains(&"muconde.agent.stage_deployment"));
        assert!(span_names.contains(&"muconde.agent.slot_swap"));
        assert!(span_names.contains(&"muconde.agent.rollback"));

        let metrics = recorder.recorded_metrics().await;
        let metric_names: Vec<&str> = metrics.iter().map(|m| m.metric_name.as_str()).collect();
        assert!(metric_names.contains(&"muconde.agent.stage_duration_ms"));
        assert!(metric_names.contains(&"muconde.agent.active_slot"));
        assert!(metric_names.contains(&"muconde.agent.slot_probe_latency_ms"));
        assert!(metric_names.contains(&"muconde.agent.slot_probe_healthy"));
        assert!(metric_names.contains(&"muconde.agent.rollback_duration_ms"));
    }

    fn write_cas_blob(cas_dir: &std::path::Path, digest: &str, bytes: &[u8]) {
        let blob_dir = cas_dir.join("blobs").join("sha256").join(&digest[..2]);
        fs::create_dir_all(&blob_dir).unwrap();
        fs::write(blob_dir.join(digest), bytes).unwrap();
    }

    async fn read_frames_until(
        client: &mut tokio::io::DuplexStream,
        timeout_secs: u64,
        mut done: impl FnMut(&[(u16, Vec<u8>)]) -> bool,
    ) -> Vec<(u16, Vec<u8>)> {
        let mut frames = Vec::new();
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
        while !done(&frames) {
            match tokio::time::timeout_at(deadline, read_frame(client)).await {
                Ok(Ok((hdr, payload))) => frames.push((hdr.msg_type, payload)),
                _ => break,
            }
        }
        frames
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_sandboxed_it_pass_promotes_ping_pong_b_to_a() {
        use crate::sandbox_it::tests::build_test_tar_gz;
        use mu_cd_ipc::TestState;

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        let service = "action-runner";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        fs::write(srv_dir.join("@b").join("old-bin"), b"v1").unwrap();
        std::os::unix::fs::symlink("@b", srv_dir.join("current")).unwrap();

        let (archive, digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"it_custom_ok","command":"bin/pass.sh","critical":true,"timeout_secs":5}]}"#.as_slice(),
                0o644,
            ),
            (
                "bin/pass.sh",
                b"#!/bin/sh\necho \"custom pass ok\"\nexit 0\n".as_slice(),
                0o755,
            ),
        ]);
        write_cas_blob(&cas_dir, &digest, &archive);

        let mut config = MuConDeAgentConfig {
            node_id: "node-it-pass".into(),
            muconde_root: root,
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 2,
            integration_tests: IntegrationTestSelection::Selected(vec![
                "systemd_unit_active".into(),
                "health_endpoint_ready".into(),
                "it_custom_ok".into(),
            ]),
            it_archive_digest: Some(digest),
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        assert_eq!(config.it_sandbox.max_pids, 256);
        config.it_sandbox.per_test_timeout_secs = 5;

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));
        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));

        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let candidate_sha = "a".repeat(64);
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-it-pass".into(),
            lease_id: "lease-it-pass".into(),
            service_name: service.into(),
            artifact_sha256: candidate_sha,
            target_slot: DeploymentSlot::SlotA,
        };
        let req_bytes = fory.serialize(&stage_req).unwrap();
        let req_hdr = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, req_bytes.len() as u32, 0, 1);
        write_frame(&mut client, &req_hdr, &req_bytes)
            .await
            .unwrap();
        let (resp_hdr, resp_bytes) = read_frame(&mut client).await.unwrap();
        assert_eq!(resp_hdr.msg_type, MSG_TYPE_STAGE_DEPLOY_RESP);
        let resp: StageDeploymentResponse = fory.deserialize(&resp_bytes).unwrap();
        assert!(resp.staged_ok);
        assert_eq!(resp.target_slot, DeploymentSlot::SlotA);

        // Staging while @b was active must create a read-only snapshot of @b.
        assert!(!agent
            .btrfs_manager
            .list_snapshots(service)
            .unwrap()
            .is_empty());

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-it-pass".into(),
            lease_id: "lease-it-pass".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotB,
            to_slot: DeploymentSlot::SlotA,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        let swap_hdr = IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2);
        write_frame(&mut client, &swap_hdr, &swap_bytes)
            .await
            .unwrap();

        let frames = read_frames_until(&mut client, 8, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
        })
        .await;

        let progress = progress_of(&frames);
        assert!(progress
            .iter()
            .any(|p| p.test_name == "it_custom_ok" && p.state == TestState::Pending));
        assert!(progress
            .iter()
            .any(|p| p.test_name == "it_custom_ok" && p.state == TestState::Running));
        assert!(progress
            .iter()
            .any(|p| p.test_name == "it_custom_ok" && p.state == TestState::Passed));
        assert!(!progress.iter().any(|p| p.state == TestState::Failed));

        let (_, report_payload) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .expect("IntegrationTestReport must be emitted for sandboxed IT suite");
        let report: IntegrationTestReport = fory.deserialize(report_payload).unwrap();
        assert!(report.passed);
        assert!(report.failed_tests.is_empty());
        assert!(report.executed_tests.contains(&"it_custom_ok".to_string()));
        assert!(!frames.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT));
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A)
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_sandboxed_it_critical_failure_triggers_immediate_rollback_taint_and_sanitized_log(
    ) {
        use crate::sandbox_it::{tests::build_test_tar_gz, MAX_LOG_EXCERPT_BYTES};
        use mu_cd_ipc::TestState;
        use mu_observable_ipc::REDACTED_PLACEHOLDER;

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        let service = "action-runner";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

        let (archive, digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"it_fail_crit","command":"bin/fail.sh","critical":true,"timeout_secs":5}]}"#.as_slice(),
                0o644,
            ),
            (
                "bin/fail.sh",
                b"#!/bin/sh\necho \"fatal error token=secret-fail-val\"\nexit 1\n".as_slice(),
                0o755,
            ),
        ]);
        write_cas_blob(&cas_dir, &digest, &archive);

        let config = MuConDeAgentConfig {
            node_id: "node-it-fail".into(),
            muconde_root: root,
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 2,
            integration_tests: IntegrationTestSelection::Selected(vec![
                "systemd_unit_active".into(),
                "health_endpoint_ready".into(),
                "it_fail_crit".into(),
            ]),
            it_archive_digest: Some(digest),
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(true));
        let agent = Arc::new(MuConDeAgent::new(config, runner, prober));

        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let candidate_sha = "b".repeat(64);
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-it-fail".into(),
            lease_id: "lease-it-fail".into(),
            service_name: service.into(),
            artifact_sha256: candidate_sha.clone(),
            target_slot: DeploymentSlot::SlotB,
        };
        let req_bytes = fory.serialize(&stage_req).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, req_bytes.len() as u32, 0, 1),
            &req_bytes,
        )
        .await
        .unwrap();
        let _ = read_frame(&mut client).await.unwrap();

        let swap_start = std::time::Instant::now();
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-it-fail".into(),
            lease_id: "lease-it-fail".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2),
            &swap_bytes,
        )
        .await
        .unwrap();

        let frames = read_frames_until(&mut client, 8, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        assert!(swap_start.elapsed() < std::time::Duration::from_secs(2));

        let progress = progress_of(&frames);
        assert!(progress
            .iter()
            .any(|p| p.test_name == "it_fail_crit" && p.state == TestState::Failed));

        let (_, report_payload) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .expect("IntegrationTestReport must be emitted on failure");
        let report: IntegrationTestReport = fory.deserialize(report_payload).unwrap();
        assert!(!report.passed);
        assert!(report.failed_tests.contains(&"it_fail_crit".to_string()));
        let excerpt = report.log_excerpt.expect("log excerpt included on failure");
        assert!(excerpt.len() <= MAX_LOG_EXCERPT_BYTES);
        assert!(!excerpt.contains("secret-fail-val"));
        assert!(excerpt.contains(REDACTED_PLACEHOLDER));

        let (_, taint_payload) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
            .expect("ArtifactTaintNotification must be emitted on critical failure");
        let taint: ArtifactTaintNotification = fory.deserialize(taint_payload).unwrap();
        assert!(taint.rollback_completed);
        assert_eq!(taint.artifact_sha256, candidate_sha);

        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A)
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_sandboxed_it_fails_closed_on_unknown_test_and_sha256_mismatch() {
        use crate::sandbox_it::tests::build_test_tar_gz;
        use mu_cd_ipc::TestState;

        let service = "action-runner";
        let fory = create_fory_runtime().unwrap();

        // Case A: Preselected test absent from verified bundle fails closed & rolls back to @a.
        {
            let temp = tempdir().unwrap();
            let root = temp.path().join("muconde");
            let cas_dir = temp.path().join("cas");
            let srv_dir = root.join(service);
            fs::create_dir_all(srv_dir.join("@a")).unwrap();
            fs::create_dir_all(srv_dir.join("@b")).unwrap();
            std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

            let (archive, digest) = build_test_tar_gz(&[
                (
                    "manifest.json",
                    br#"{"tests":[{"name":"it_custom_ok","command":"bin/pass.sh","critical":true}]}"#.as_slice(),
                    0o644,
                ),
                ("bin/pass.sh", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
            ]);
            write_cas_blob(&cas_dir, &digest, &archive);

            let config = MuConDeAgentConfig {
                node_id: "node-absent-test".into(),
                muconde_root: root,
                default_warmup_timeout_secs: 5,
                required_consecutive_successes: 2,
                integration_tests: IntegrationTestSelection::Selected(vec![
                    "systemd_unit_active".into(),
                    "absent_test".into(),
                ]),
                it_archive_digest: Some(digest),
                cas_blobs_dir: Some(cas_dir),
                ..Default::default()
            };
            let agent = Arc::new(MuConDeAgent::new(
                config,
                Arc::new(MockCommandRunner::new(true)),
                Arc::new(MockHealthProber::new(true)),
            ));
            let (mut client, server) = tokio::io::duplex(256 * 1024);
            let agent_server = agent.clone();
            let agent_task = tokio::spawn(async move {
                let _ = agent_server.handle_connection(server).await;
            });

            let swap_cmd = SlotSwapCommand {
                deployment_id: "dep-absent-test".into(),
                lease_id: "lease-absent-test".into(),
                service_name: service.into(),
                from_slot: DeploymentSlot::SlotA,
                to_slot: DeploymentSlot::SlotB,
                systemd_unit: format!("{service}.service"),
                warmup_timeout_secs: 5,
            };
            let swap_bytes = fory.serialize(&swap_cmd).unwrap();
            write_frame(
                &mut client,
                &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 10),
                &swap_bytes,
            )
            .await
            .unwrap();

            let frames = read_frames_until(&mut client, 5, |fs| {
                fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                    && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
            })
            .await;

            assert!(progress_of(&frames)
                .iter()
                .any(|p| p.state == TestState::Failed));
            let (_, rep_p) = frames
                .iter()
                .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                .unwrap();
            let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
            assert!(!report.passed);
            assert!(report.failed_tests.contains(&"absent_test".to_string()));
            let (_, taint_p) = frames
                .iter()
                .find(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
                .unwrap();
            let taint: ArtifactTaintNotification = fory.deserialize(taint_p).unwrap();
            assert!(taint.rollback_completed);
            assert_eq!(
                agent.slot_manager.read_active_slot(service).unwrap(),
                Some(Slot::A)
            );
            drop(client);
            let _ = agent_task.await;
        }

        // Case B: Corrupted CAS bundle bytes fail SHA-256 verification closed & roll back to @b.
        {
            let temp = tempdir().unwrap();
            let root = temp.path().join("muconde");
            let cas_dir = temp.path().join("cas");
            let srv_dir = root.join(service);
            fs::create_dir_all(srv_dir.join("@a")).unwrap();
            fs::create_dir_all(srv_dir.join("@b")).unwrap();
            std::os::unix::fs::symlink("@b", srv_dir.join("current")).unwrap();

            let expected_digest = "c".repeat(64);
            write_cas_blob(&cas_dir, &expected_digest, b"corrupted-not-valid-tar-gz");

            let config = MuConDeAgentConfig {
                node_id: "node-digest-mismatch".into(),
                muconde_root: root,
                default_warmup_timeout_secs: 5,
                required_consecutive_successes: 2,
                integration_tests: IntegrationTestSelection::Selected(vec![
                    "systemd_unit_active".into(),
                    "it_custom_ok".into(),
                ]),
                it_archive_digest: Some(expected_digest),
                cas_blobs_dir: Some(cas_dir),
                ..Default::default()
            };
            let agent = Arc::new(MuConDeAgent::new(
                config,
                Arc::new(MockCommandRunner::new(true)),
                Arc::new(MockHealthProber::new(true)),
            ));
            let (mut client, server) = tokio::io::duplex(256 * 1024);
            let agent_server = agent.clone();
            let agent_task = tokio::spawn(async move {
                let _ = agent_server.handle_connection(server).await;
            });

            let swap_cmd = SlotSwapCommand {
                deployment_id: "dep-bad-sha".into(),
                lease_id: "lease-bad-sha".into(),
                service_name: service.into(),
                from_slot: DeploymentSlot::SlotB,
                to_slot: DeploymentSlot::SlotA,
                systemd_unit: format!("{service}.service"),
                warmup_timeout_secs: 5,
            };
            let swap_bytes = fory.serialize(&swap_cmd).unwrap();
            write_frame(
                &mut client,
                &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 11),
                &swap_bytes,
            )
            .await
            .unwrap();

            let frames = read_frames_until(&mut client, 5, |fs| {
                fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                    && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
            })
            .await;

            assert!(progress_of(&frames)
                .iter()
                .any(|p| p.state == TestState::Failed));
            let (_, rep_p) = frames
                .iter()
                .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                .unwrap();
            let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
            assert!(!report.passed);
            let (_, taint_p) = frames
                .iter()
                .find(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
                .unwrap();
            let taint: ArtifactTaintNotification = fory.deserialize(taint_p).unwrap();
            assert!(taint.rollback_completed);
            assert_eq!(
                agent.slot_manager.read_active_slot(service).unwrap(),
                Some(Slot::B)
            );
            drop(client);
            let _ = agent_task.await;
        }
    }
}
