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
    MSG_TYPE_SCENARIO_PLAN, MSG_TYPE_SCENARIO_PLAN_ACK, MSG_TYPE_SLOT_SWAP,
    MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};
use mu_cd_ipc::{
    create_fory_runtime, ArtifactTaintNotification, HeartbeatTelemetry, IntegrationTestProgress,
    IntegrationTestReport, RollbackCommand, ScenarioEnvVar, ScenarioExecutionPlan, ScenarioPlanAck,
    ScenarioTestSpec, SlotSwapCommand, StageDeploymentRequest, TestState,
};
use mu_ci_isolation::{NetworkEgressMode, MAX_K3_MEMLOCK_KB};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_rustls::TlsAcceptor;

use crate::btrfs::{BtrfsManager, CommandRunner, SystemCommandRunner};
use crate::error::AgentError;
use crate::gate::{
    builtin_catalog, builtin_verdict, GateTest, GateTracker, IntegrationTestSelection,
};
use crate::manifest::{AbRulesConfig, DeploymentConfig, MuCdManifest};
use crate::sandbox_it::{
    build_it_sandbox_plan, extract_scenario_tcp_endpoints, extract_scenario_unix_sockets,
    resolve_gate_plan_with_base, sanitize_and_bound_log_excerpt, unpack_verified_it_archive,
    validate_allowlisted_env, validate_ro_mounts, validate_scenario_args, validate_sha256_digest,
    wait_for_tcp_endpoints_ready, wait_for_unix_sockets_ready, DiscoveredItTest, ItArchiveFetcher,
    ItSandboxConfig, KernelSandboxedExecutor, RegistryAndCasFetcher, SandboxedCommandExecutor,
    UnpackedItBundle, MAX_IT_SANDBOX_PIDS, MAX_LOG_EXCERPT_BYTES, TCP_WARMUP_POLL_INTERVAL,
};
use crate::slot::{default_cd_root, is_production_cd_root, Slot, SlotManager};
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
    /// Optional Bearer authentication token for `mu-registry` artifact and IT archive fetches.
    pub registry_token: Option<String>,
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
            muconde_root: default_cd_root(),
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            default_warmup_timeout_secs: 30,
            required_consecutive_successes: 3,
            collector_addr: crate::first_non_empty_env(&[
                "MU_OBSERVABLE_COLLECTOR_ADDR",
                "MU_CD_AGENT_COLLECTOR_ADDR",
                "MUOBSERVE_COLLECTOR_ADDR",
            ]),
            integration_tests: IntegrationTestSelection::All,
            gate_catalog: builtin_catalog(),
            ab_rules: AbRulesConfig::default(),
            it_archive_digest: None,
            it_bundle_id: None,
            registry_url: None,
            registry_token: None,
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

async fn write_scenario_plan_ack_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    fory: &fory::Fory,
    ack: &ScenarioPlanAck,
    sequence: u64,
) -> Result<(), AgentError> {
    let ack_bytes = fory
        .serialize(ack)
        .map_err(|e| AgentError::Serialization(e.to_string()))?;
    let ack_header = IpcHeader::new(
        MSG_TYPE_SCENARIO_PLAN_ACK,
        ack_bytes.len() as u32,
        0,
        sequence,
    );
    write_frame(stream, &ack_header, &ack_bytes).await?;
    Ok(())
}

#[derive(Debug, Clone)]
enum StoredScenarioPlan {
    Accepted(Box<ScenarioExecutionPlan>),
    Rejected(String),
}

#[derive(Debug, Clone)]
struct PlannedSandboxedTest {
    test: DiscoveredItTest,
    sandbox_cfg: ItSandboxConfig,
}

fn merge_scenario_env(
    plan_env: &[ScenarioEnvVar],
    spec_env: &[ScenarioEnvVar],
) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::with_capacity(plan_env.len() + spec_env.len());
    for entry in plan_env.iter().chain(spec_env.iter()) {
        if let Some(existing) = merged.iter_mut().find(|(k, _)| k == &entry.key) {
            existing.1 = entry.value.clone();
        } else {
            merged.push((entry.key.clone(), entry.value.clone()));
        }
    }
    merged
}

fn merge_scenario_mounts(plan_mounts: &[String], spec_mounts: &[String]) -> Vec<PathBuf> {
    let mut merged = Vec::with_capacity(plan_mounts.len() + spec_mounts.len());
    for raw in plan_mounts.iter().chain(spec_mounts.iter()) {
        let p = PathBuf::from(raw);
        if !merged.contains(&p) {
            merged.push(p);
        }
    }
    merged
}

fn merge_scenario_args(plan_args: &[String], spec_args: &[String]) -> Vec<String> {
    let mut merged = Vec::with_capacity(plan_args.len() + spec_args.len());
    for arg in plan_args {
        merged.push(arg.clone());
    }
    for arg in spec_args {
        if arg.starts_with("--") && !arg.contains('=') && merged.iter().any(|a| a == arg) {
            continue;
        }
        merged.push(arg.clone());
    }
    merged
}

fn validate_scenario_execution_plan(plan: &ScenarioExecutionPlan) -> Result<(), AgentError> {
    if plan.deployment_id.trim().is_empty() {
        return Err(AgentError::Config(
            "ScenarioExecutionPlan deployment_id must not be empty".to_string(),
        ));
    }
    if plan.service_name.trim().is_empty() {
        return Err(AgentError::Config(
            "ScenarioExecutionPlan service_name must not be empty".to_string(),
        ));
    }
    if plan.selected_tests.is_empty() && plan.scenarios.is_empty() {
        return Err(AgentError::UnknownIntegrationTests(vec![
            "<empty_scenario_plan>".to_string(),
        ]));
    }
    if plan.max_pids > MAX_IT_SANDBOX_PIDS {
        return Err(AgentError::SandboxViolation(format!(
            "ScenarioExecutionPlan max_pids {} exceeds maximum of {MAX_IT_SANDBOX_PIDS}",
            plan.max_pids
        )));
    }
    if plan.max_memlock_kb > MAX_K3_MEMLOCK_KB {
        return Err(AgentError::SandboxViolation(format!(
            "ScenarioExecutionPlan max_memlock_kb {} exceeds bounded ceiling {MAX_K3_MEMLOCK_KB}",
            plan.max_memlock_kb
        )));
    }
    if let Some(ref digest) = plan.it_archive_digest {
        validate_sha256_digest(digest)?;
    }

    validate_scenario_args(&plan.args)?;
    let plan_mounts: Vec<PathBuf> = plan.ro_mounts.iter().map(PathBuf::from).collect();
    let validated_plan_mounts = validate_ro_mounts(&plan_mounts)?;
    let plan_env: Vec<(String, String)> = plan
        .env
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect();
    validate_allowlisted_env(&plan_env, &validated_plan_mounts)?;

    for spec in &plan.scenarios {
        if spec.name.trim().is_empty() {
            return Err(AgentError::Config(
                "ScenarioTestSpec name must not be empty".to_string(),
            ));
        }
        if spec.test_binary.trim().is_empty() {
            return Err(AgentError::Config(format!(
                "ScenarioTestSpec '{}' test_binary must not be empty",
                spec.name
            )));
        }
        if spec.timeout_secs == 0 {
            return Err(AgentError::Config(format!(
                "ScenarioTestSpec '{}' timeout_secs must be greater than 0",
                spec.name
            )));
        }
        let merged_args = merge_scenario_args(&plan.args, &spec.args);
        validate_scenario_args(&merged_args)?;
        let merged_mounts = merge_scenario_mounts(&plan.ro_mounts, &spec.ro_mounts);
        let validated_mounts = validate_ro_mounts(&merged_mounts)?;
        let merged_env = merge_scenario_env(&plan.env, &spec.env);
        validate_allowlisted_env(&merged_env, &validated_mounts)?;
    }

    Ok(())
}

fn find_bundle_test<'a>(
    bundle: Option<&'a UnpackedItBundle>,
    name: &str,
) -> Option<&'a DiscoveredItTest> {
    let bundle = bundle?;
    bundle.tests.iter().find(|t| {
        t.name == name
            || t.command_path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|stem| stem == name)
    })
}

fn build_scenario_sandbox_config(
    base: &ItSandboxConfig,
    plan: &ScenarioExecutionPlan,
    spec: Option<&ScenarioTestSpec>,
) -> ItSandboxConfig {
    let cidrs = match spec {
        Some(s) if !s.cidrs.is_empty() => s.cidrs.clone(),
        _ => plan.cidrs.clone(),
    };
    let network_mode = if cidrs.is_empty() {
        NetworkEgressMode::Offline
    } else {
        NetworkEgressMode::RestrictedCidrs(cidrs)
    };
    let ro_mounts = match spec {
        Some(s) => merge_scenario_mounts(&plan.ro_mounts, &s.ro_mounts),
        None => plan.ro_mounts.iter().map(PathBuf::from).collect(),
    };
    let allowlisted_env = match spec {
        Some(s) => merge_scenario_env(&plan.env, &s.env),
        None => plan
            .env
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect(),
    };
    let extra_args = match spec {
        Some(s) => merge_scenario_args(&plan.args, &s.args),
        None => plan.args.clone(),
    };
    ItSandboxConfig {
        max_pids: if plan.max_pids > 0 {
            plan.max_pids
        } else {
            base.max_pids
        },
        memlock_limit_kb: if plan.max_memlock_kb > 0 {
            plan.max_memlock_kb
        } else {
            base.memlock_limit_kb
        },
        network_mode,
        ro_mounts,
        allowlisted_env,
        extra_args,
        ..base.clone()
    }
}

fn prevalidate_planned_test(planned: &PlannedSandboxedTest) -> Result<(), AgentError> {
    let merged_args = merge_scenario_args(&planned.test.args, &planned.sandbox_cfg.extra_args);
    let mut argv = Vec::with_capacity(1 + merged_args.len());
    argv.push(planned.test.command_path.as_os_str().to_os_string());
    for arg in &merged_args {
        argv.push(std::ffi::OsString::from(arg));
    }
    let _ = build_it_sandbox_plan(&planned.test.working_dir, &argv, &planned.sandbox_cfg)?;
    Ok(())
}

fn resolve_scenario_execution_plan(
    base_catalog: &[GateTest],
    base_sandbox: &ItSandboxConfig,
    plan: &ScenarioExecutionPlan,
    unpacked_bundle: Option<&UnpackedItBundle>,
) -> Result<(Vec<GateTest>, Vec<PlannedSandboxedTest>), AgentError> {
    let mut missing = Vec::new();
    let mut push_missing = |name: &str| {
        if !missing.iter().any(|m: &String| m == name) {
            missing.push(name.to_string());
        }
    };

    let select_all = plan
        .selected_tests
        .iter()
        .any(|n| n.eq_ignore_ascii_case("all"));

    for spec in &plan.scenarios {
        if find_bundle_test(unpacked_bundle, &spec.test_binary).is_none()
            && find_bundle_test(unpacked_bundle, &spec.name).is_none()
        {
            push_missing(&spec.test_binary);
        }
    }

    for req in &plan.selected_tests {
        if req.eq_ignore_ascii_case("all") {
            continue;
        }
        if base_catalog.iter().any(|b| b.name == *req) {
            continue;
        }
        if plan
            .scenarios
            .iter()
            .any(|s| s.name == *req || s.test_binary == *req)
        {
            continue;
        }
        if find_bundle_test(unpacked_bundle, req).is_none() {
            push_missing(req);
        }
    }

    if !missing.is_empty() {
        return Err(AgentError::UnknownIntegrationTests(missing));
    }

    let mut gate_tests = Vec::new();
    let mut planned_custom = Vec::new();

    for builtin in base_catalog {
        if select_all || plan.selected_tests.iter().any(|n| n == &builtin.name) {
            gate_tests.push(builtin.clone());
        }
    }

    for spec in &plan.scenarios {
        let base_test = find_bundle_test(unpacked_bundle, &spec.test_binary)
            .or_else(|| find_bundle_test(unpacked_bundle, &spec.name))
            .ok_or_else(|| AgentError::UnknownIntegrationTests(vec![spec.test_binary.clone()]))?;
        let test = DiscoveredItTest {
            name: spec.name.clone(),
            command_path: base_test.command_path.clone(),
            args: base_test.args.clone(),
            critical: spec.critical,
            timeout_secs: Some(spec.timeout_secs),
            working_dir: base_test.working_dir.clone(),
        };
        let sandbox_cfg = build_scenario_sandbox_config(base_sandbox, plan, Some(spec));
        let planned = PlannedSandboxedTest { test, sandbox_cfg };
        prevalidate_planned_test(&planned)?;
        gate_tests.push(planned.test.as_gate_test());
        planned_custom.push(planned);
    }

    for req in &plan.selected_tests {
        if req.eq_ignore_ascii_case("all")
            || base_catalog.iter().any(|b| b.name == *req)
            || plan
                .scenarios
                .iter()
                .any(|s| s.name == *req || s.test_binary == *req)
        {
            continue;
        }
        let base_test = find_bundle_test(unpacked_bundle, req)
            .ok_or_else(|| AgentError::UnknownIntegrationTests(vec![req.clone()]))?;
        let sandbox_cfg = build_scenario_sandbox_config(base_sandbox, plan, None);
        let planned = PlannedSandboxedTest {
            test: base_test.clone(),
            sandbox_cfg,
        };
        prevalidate_planned_test(&planned)?;
        gate_tests.push(planned.test.as_gate_test());
        planned_custom.push(planned);
    }

    if select_all && plan.scenarios.is_empty() {
        if let Some(bundle) = unpacked_bundle {
            for base_test in &bundle.tests {
                if gate_tests.iter().any(|g| g.name == base_test.name) {
                    continue;
                }
                let sandbox_cfg = build_scenario_sandbox_config(base_sandbox, plan, None);
                let planned = PlannedSandboxedTest {
                    test: base_test.clone(),
                    sandbox_cfg,
                };
                prevalidate_planned_test(&planned)?;
                gate_tests.push(planned.test.as_gate_test());
                planned_custom.push(planned);
            }
        }
    }

    Ok((gate_tests, planned_custom))
}

const PENDING_SELF_UPGRADE_MAX_AGE_MS: u64 = 10 * 60 * 1000;
const SELF_UPGRADE_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const UNDELIVERED_REPORT_QUIET_WAIT: Duration = Duration::from_millis(150);
const DEFAULT_SELF_UPGRADE_FAILURE_WINDOW: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableEnvVar {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableScenarioTestSpec {
    name: String,
    test_binary: String,
    args: Vec<String>,
    env: Vec<SerializableEnvVar>,
    cidrs: Vec<String>,
    ro_mounts: Vec<String>,
    critical: bool,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableScenarioPlan {
    deployment_id: String,
    lease_id: String,
    service_name: String,
    node_id: String,
    policy_commit_sha: String,
    it_archive_digest: Option<String>,
    bundle_id: Option<String>,
    selected_tests: Vec<String>,
    scenarios: Vec<SerializableScenarioTestSpec>,
    env: Vec<SerializableEnvVar>,
    args: Vec<String>,
    cidrs: Vec<String>,
    ro_mounts: Vec<String>,
    max_pids: u32,
    max_memlock_kb: u64,
    auto_rollback_on_critical: bool,
}

impl From<&ScenarioExecutionPlan> for SerializableScenarioPlan {
    fn from(plan: &ScenarioExecutionPlan) -> Self {
        Self {
            deployment_id: plan.deployment_id.clone(),
            lease_id: plan.lease_id.clone(),
            service_name: plan.service_name.clone(),
            node_id: plan.node_id.clone(),
            policy_commit_sha: plan.policy_commit_sha.clone(),
            it_archive_digest: plan.it_archive_digest.clone(),
            bundle_id: plan.bundle_id.clone(),
            selected_tests: plan.selected_tests.clone(),
            scenarios: plan
                .scenarios
                .iter()
                .map(|s| SerializableScenarioTestSpec {
                    name: s.name.clone(),
                    test_binary: s.test_binary.clone(),
                    args: s.args.clone(),
                    env: s
                        .env
                        .iter()
                        .map(|e| SerializableEnvVar {
                            key: e.key.clone(),
                            value: e.value.clone(),
                        })
                        .collect(),
                    cidrs: s.cidrs.clone(),
                    ro_mounts: s.ro_mounts.clone(),
                    critical: s.critical,
                    timeout_secs: s.timeout_secs,
                })
                .collect(),
            env: plan
                .env
                .iter()
                .map(|e| SerializableEnvVar {
                    key: e.key.clone(),
                    value: e.value.clone(),
                })
                .collect(),
            args: plan.args.clone(),
            cidrs: plan.cidrs.clone(),
            ro_mounts: plan.ro_mounts.clone(),
            max_pids: plan.max_pids,
            max_memlock_kb: plan.max_memlock_kb,
            auto_rollback_on_critical: plan.auto_rollback_on_critical,
        }
    }
}

impl From<SerializableScenarioPlan> for ScenarioExecutionPlan {
    fn from(s: SerializableScenarioPlan) -> Self {
        Self {
            deployment_id: s.deployment_id,
            lease_id: s.lease_id,
            service_name: s.service_name,
            node_id: s.node_id,
            policy_commit_sha: s.policy_commit_sha,
            it_archive_digest: s.it_archive_digest,
            bundle_id: s.bundle_id,
            selected_tests: s.selected_tests,
            scenarios: s
                .scenarios
                .into_iter()
                .map(|sp| ScenarioTestSpec {
                    name: sp.name,
                    test_binary: sp.test_binary,
                    args: sp.args,
                    env: sp
                        .env
                        .into_iter()
                        .map(|e| ScenarioEnvVar {
                            key: e.key,
                            value: e.value,
                        })
                        .collect(),
                    cidrs: sp.cidrs,
                    ro_mounts: sp.ro_mounts,
                    critical: sp.critical,
                    timeout_secs: sp.timeout_secs,
                })
                .collect(),
            env: s
                .env
                .into_iter()
                .map(|e| ScenarioEnvVar {
                    key: e.key,
                    value: e.value,
                })
                .collect(),
            args: s.args,
            cidrs: s.cidrs,
            ro_mounts: s.ro_mounts,
            max_pids: s.max_pids,
            max_memlock_kb: s.max_memlock_kb,
            auto_rollback_on_critical: s.auto_rollback_on_critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingSelfUpgrade {
    deployment_id: String,
    lease_id: String,
    service_name: String,
    from_slot: String,
    to_slot: String,
    candidate_sha256: String,
    systemd_unit: String,
    warmup_timeout_secs: u64,
    scenario_plan: Option<SerializableScenarioPlan>,
    deployment_config: Option<DeploymentConfig>,
    rollback_deployment: Option<DeploymentConfig>,
    created_epoch_ms: u64,
}

/// Canonical persistent handoff path written prior to a detached agent self-restart.
pub fn pending_self_upgrade_path(muconde_root: &Path) -> PathBuf {
    muconde_root
        .join("mu-cd-agent")
        .join(".pending_self_upgrade.json")
}

fn write_pending_self_upgrade_atomic(
    path: &Path,
    pending: &PendingSelfUpgrade,
) -> Result<(), AgentError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(pending)
        .map_err(|e| AgentError::Serialization(format!("PendingSelfUpgrade JSON encode: {e}")))?;
    let tmp_path = path.with_file_name(format!(
        ".pending_self_upgrade.json.tmp.{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&tmp_path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(AgentError::Io(err));
    }
    Ok(())
}

fn claim_pending_self_upgrade(path: &Path) -> Result<Option<PendingSelfUpgrade>, AgentError> {
    let claimed_path = path.with_file_name(format!(
        ".pending_self_upgrade.json.claimed.{}",
        uuid::Uuid::new_v4().simple()
    ));
    match std::fs::rename(path, &claimed_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AgentError::Io(e)),
    }
    let raw = std::fs::read(&claimed_path);
    let _ = std::fs::remove_file(&claimed_path);
    let bytes = raw?;
    let pending: PendingSelfUpgrade = serde_json::from_slice(&bytes)
        .map_err(|e| AgentError::Config(format!("Invalid .pending_self_upgrade.json: {e}")))?;
    let age_ms = now_epoch_ms().saturating_sub(pending.created_epoch_ms);
    if age_ms >= PENDING_SELF_UPGRADE_MAX_AGE_MS {
        tracing::warn!(
            deployment_id = %pending.deployment_id,
            age_ms,
            "Ignoring expired .pending_self_upgrade.json (>10 min old)"
        );
        return Ok(None);
    }
    Ok(Some(pending))
}

async fn validate_self_upgrade_binary(bin_path: &Path, timeout: Duration) -> Result<(), String> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(bin_path)
            .arg("--version")
            .output(),
    )
    .await
    .map_err(|_| {
        format!(
            "Self-upgrade binary '{}' timed out after {}ms during --version validation",
            bin_path.display(),
            timeout.as_millis()
        )
    })?
    .map_err(|e| {
        format!(
            "Failed executing self-upgrade binary '{}' --version: {e}",
            bin_path.display()
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Self-upgrade binary '{}' --version exited with {}: {}",
            bin_path.display(),
            output.status,
            stderr.trim()
        ));
    }
    Ok(())
}

struct PendingReportChannel {
    deployment_id: String,
    rx: watch::Receiver<Option<IntegrationTestReport>>,
    created_epoch_ms: u64,
}

async fn await_pending_report(ch: &mut PendingReportChannel) -> Option<IntegrationTestReport> {
    if let Some(rep) = ch.rx.borrow().clone() {
        return Some(rep);
    }
    let elapsed_ms = now_epoch_ms().saturating_sub(ch.created_epoch_ms);
    let remaining_ms = PENDING_SELF_UPGRADE_MAX_AGE_MS.saturating_sub(elapsed_ms);
    if remaining_ms == 0 {
        return None;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(remaining_ms);
    loop {
        if let Some(rep) = ch.rx.borrow().clone() {
            return Some(rep);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return None;
        }
        match tokio::time::timeout(deadline - now, ch.rx.changed()).await {
            Ok(Ok(())) => continue,
            Ok(Err(_)) | Err(_) => return ch.rx.borrow().clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapConnectionAction {
    Continue,
    Close,
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
    staged_slots: Arc<Mutex<HashMap<String, (Slot, Slot)>>>,
    swap_units: Arc<Mutex<HashMap<String, String>>>,
    scenario_plans: Arc<Mutex<HashMap<String, StoredScenarioPlan>>>,
    undelivered_report: Arc<Mutex<Option<PendingReportChannel>>>,
    undelivered_report_notify: Arc<tokio::sync::Notify>,
    self_upgrade_failure_window: Duration,
}

struct ServiceContract {
    selection: IntegrationTestSelection,
    it_archive_digest: Option<String>,
    ab_rules: AbRulesConfig,
    deployment: Option<DeploymentConfig>,
}

fn validate_staging_artifact_token(raw: &str) -> Result<&str, AgentError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return Err(AgentError::BundleVerification(format!(
            "Unsafe artifact_sha256 identifier '{raw}'"
        )));
    }
    Ok(trimmed)
}

impl MuConDeAgent {
    pub fn new(
        config: MuConDeAgentConfig,
        runner: Arc<dyn CommandRunner>,
        prober: Arc<dyn HealthProber>,
    ) -> Self {
        let artifact_fetcher = RegistryAndCasFetcher {
            cas_dir: config.cas_blobs_dir.clone(),
            registry_url: config.registry_url.clone(),
            bundle_id: config.it_bundle_id.clone(),
            bearer_token: config.registry_token.clone(),
            tls_ca_path: config.tls_ca_path.clone(),
            tls_cert_path: config.tls_cert_path.clone(),
            tls_key_path: config.tls_key_path.clone(),
        };
        let btrfs_manager = Arc::new(
            BtrfsManager::new(&config.muconde_root, runner.clone())
                .with_ab_rules(config.ab_rules.clone())
                .with_cas_blobs_dir(config.cas_blobs_dir.clone())
                .with_artifact_fetcher(artifact_fetcher.clone()),
        );
        let slot_manager = Arc::new(SlotManager::new(&config.muconde_root, runner));
        let watchdog_monitor = Arc::new(WatchdogMonitor::new(
            &config.node_id,
            slot_manager.clone(),
            prober,
        ));
        let telemetry_sink = Arc::new(MuObserveCollectorSink::new(config.collector_addr.clone()));
        let it_fetcher = Arc::new(artifact_fetcher);
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
            staged_slots: Arc::new(Mutex::new(HashMap::new())),
            swap_units: Arc::new(Mutex::new(HashMap::new())),
            scenario_plans: Arc::new(Mutex::new(HashMap::new())),
            undelivered_report: Arc::new(Mutex::new(None)),
            undelivered_report_notify: Arc::new(tokio::sync::Notify::new()),
            self_upgrade_failure_window: DEFAULT_SELF_UPGRADE_FAILURE_WINDOW,
        }
    }

    /// Overrides the brief report-delivery wait window prior to self-restart after a failed
    /// post-restart self-upgrade gate (primarily for deterministic fast unit tests).
    #[must_use]
    pub fn with_self_upgrade_failure_window(mut self, window: Duration) -> Self {
        self.self_upgrade_failure_window = window;
        self
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
    ) -> Result<ServiceContract, AgentError> {
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
                return Ok(ServiceContract {
                    selection,
                    it_archive_digest: digest,
                    ab_rules: manifest.ab_rules,
                    deployment: Some(manifest.deployment),
                });
            }
        }

        Ok(ServiceContract {
            selection: self.config.integration_tests.clone(),
            it_archive_digest: self.config.it_archive_digest.clone(),
            ab_rules: self.config.ab_rules.clone(),
            deployment: None,
        })
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
            staged_slots: self.staged_slots.clone(),
            swap_units: self.swap_units.clone(),
            scenario_plans: self.scenario_plans.clone(),
            undelivered_report: self.undelivered_report.clone(),
            undelivered_report_notify: self.undelivered_report_notify.clone(),
            self_upgrade_failure_window: self.self_upgrade_failure_window,
        }
    }

    async fn arm_undelivered_report(
        &self,
        deployment_id: String,
    ) -> watch::Sender<Option<IntegrationTestReport>> {
        let (tx, rx) = watch::channel(None);
        *self.undelivered_report.lock().await = Some(PendingReportChannel {
            deployment_id,
            rx,
            created_epoch_ms: now_epoch_ms(),
        });
        self.undelivered_report_notify.notify_waiters();
        tx
    }

    async fn cache_undelivered_report(&self, report: IntegrationTestReport) {
        let deployment_id = report.deployment_id.clone();
        let (tx, rx) = watch::channel(Some(report));
        // `watch::Receiver::borrow()` retains the latest value even after `tx` is dropped.
        drop(tx);
        *self.undelivered_report.lock().await = Some(PendingReportChannel {
            deployment_id,
            rx,
            created_epoch_ms: now_epoch_ms(),
        });
        self.undelivered_report_notify.notify_waiters();
    }

    async fn has_fresh_undelivered_report(&self) -> bool {
        let mut guard = self.undelivered_report.lock().await;
        if let Some(ref ch) = *guard {
            if now_epoch_ms().saturating_sub(ch.created_epoch_ms) < PENDING_SELF_UPGRADE_MAX_AGE_MS
            {
                return true;
            }
            tracing::warn!(
                deployment_id = %ch.deployment_id,
                "Expiring stale undelivered_report entry (>10 min old)"
            );
            *guard = None;
        }
        false
    }

    async fn claim_undelivered_report(&self) -> Option<PendingReportChannel> {
        let mut guard = self.undelivered_report.lock().await;
        let ch = guard.take()?;
        if now_epoch_ms().saturating_sub(ch.created_epoch_ms) < PENDING_SELF_UPGRADE_MAX_AGE_MS {
            Some(ch)
        } else {
            None
        }
    }

    async fn deliver_or_cache_it_report<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        report: &IntegrationTestReport,
        sequence: u64,
    ) -> Result<bool, AgentError> {
        match write_it_report_frame(stream, fory, report, sequence).await {
            Ok(()) => Ok(true),
            Err(AgentError::Ipc(mu_cd_ipc::IpcError::Io(ref e)))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                tracing::warn!(
                    deployment_id = %report.deployment_id,
                    service = %report.service_name,
                    passed = report.passed,
                    error = %e,
                    "Controller disconnected before IntegrationTestReport write; caching report for reconnect"
                );
                self.cache_undelivered_report(report.clone()).await;
                Ok(false)
            }
            Err(e) => Err(e),
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
        let mut received_any_frame = false;

        loop {
            let (header, payload) = if !received_any_frame {
                // Register waiter before inspecting `undelivered_report` so a concurrent
                // `cache_undelivered_report` cannot race past `select!`.
                let notified = self.undelivered_report_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                if self.has_fresh_undelivered_report().await {
                    tokio::select! {
                        frame_res = read_frame(&mut stream) => {
                            received_any_frame = true;
                            match frame_res {
                                Ok(frame) => frame,
                                Err(mu_cd_ipc::IpcError::Io(ref e))
                                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                                {
                                    tracing::debug!("Client disconnected cleanly");
                                    return Ok(());
                                }
                                Err(e) => return Err(AgentError::Ipc(e)),
                            }
                        }
                        () = tokio::time::sleep(UNDELIVERED_REPORT_QUIET_WAIT) => {
                            if let Some(mut ch) = self.claim_undelivered_report().await {
                                tracing::info!(
                                    deployment_id = %ch.deployment_id,
                                    "Silent reconnecting controller detected; awaiting undelivered IntegrationTestReport"
                                );
                                if let Some(report) = await_pending_report(&mut ch).await {
                                    if let Err(err) =
                                        write_it_report_frame(&mut stream, &fory, &report, 0).await
                                    {
                                        tracing::warn!(
                                            deployment_id = %report.deployment_id,
                                            error = %err,
                                            "Failed writing cached IntegrationTestReport on reconnect; re-caching"
                                        );
                                        self.cache_undelivered_report(report).await;
                                        return Ok(());
                                    }
                                    tracing::info!(
                                        deployment_id = %report.deployment_id,
                                        passed = report.passed,
                                        "Delivered cached IntegrationTestReport to reconnecting controller"
                                    );
                                    received_any_frame = true;
                                }
                            }
                            continue;
                        }
                    }
                } else {
                    tokio::select! {
                        frame_res = read_frame(&mut stream) => {
                            received_any_frame = true;
                            match frame_res {
                                Ok(frame) => frame,
                                Err(mu_cd_ipc::IpcError::Io(ref e))
                                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                                {
                                    tracing::debug!("Client disconnected cleanly");
                                    return Ok(());
                                }
                                Err(e) => return Err(AgentError::Ipc(e)),
                            }
                        }
                        () = notified => {
                            // An in-flight gate cached an undelivered report while this silent
                            // reconnecting controller was already waiting.
                            continue;
                        }
                    }
                }
            } else {
                match read_frame(&mut stream).await {
                    Ok(frame) => {
                        received_any_frame = true;
                        frame
                    }
                    Err(mu_cd_ipc::IpcError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        tracing::debug!("Client disconnected cleanly");
                        return Ok(());
                    }
                    Err(e) => return Err(AgentError::Ipc(e)),
                }
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

                    let stage_res = async {
                        let artifact_token = validate_staging_artifact_token(&req.artifact_sha256)?;
                        let candidate_path = self
                            .config
                            .muconde_root
                            .join("staging")
                            .join(artifact_token);

                        let is_prod = is_production_cd_root(&self.config.muconde_root);
                        let has_artifact_source = self.config.registry_url.is_some()
                            || self.config.cas_blobs_dir.is_some();
                        let is_sha256 = validate_sha256_digest(artifact_token).is_ok();
                        let missing_local = !candidate_path.is_file();

                        if is_prod || has_artifact_source || is_sha256 || missing_local {
                            self.btrfs_manager
                                .ensure_candidate_artifact(
                                    &req.service_name,
                                    artifact_token,
                                    &candidate_path,
                                )
                                .await?;
                        }

                        let contract = self.resolve_service_contract(&req.service_name, None)?;
                        Ok::<_, AgentError>((candidate_path, contract))
                    }
                    .await;

                    let resp = match stage_res {
                        Ok((candidate_path, contract)) => self
                            .btrfs_manager
                            .handle_stage_deployment_request_with_rules(
                                &req,
                                &candidate_path,
                                "",
                                &contract.ab_rules,
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
                        let staged_slot = Slot::from(resp.target_slot);
                        let previous_active_slot = staged_slot.other();
                        self.staged_digests
                            .lock()
                            .await
                            .insert(req.deployment_id.clone(), req.artifact_sha256.clone());
                        self.staged_slots.lock().await.insert(
                            req.deployment_id.clone(),
                            (staged_slot, previous_active_slot),
                        );
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

                MSG_TYPE_SCENARIO_PLAN => {
                    let plan: ScenarioExecutionPlan = fory
                        .deserialize(&payload)
                        .map_err(|e| AgentError::Serialization(e.to_string()))?;

                    let ack = match validate_scenario_execution_plan(&plan) {
                        Ok(()) => {
                            tracing::info!(
                                deployment_id = %plan.deployment_id,
                                service = %plan.service_name,
                                policy_commit = %plan.policy_commit_sha,
                                selected_tests = plan.selected_tests.len(),
                                scenarios = plan.scenarios.len(),
                                "Stored validated ScenarioExecutionPlan"
                            );
                            let deployment_id = plan.deployment_id.clone();
                            let lease_id = plan.lease_id.clone();
                            self.scenario_plans.lock().await.insert(
                                deployment_id.clone(),
                                StoredScenarioPlan::Accepted(Box::new(plan)),
                            );
                            ScenarioPlanAck {
                                deployment_id,
                                lease_id,
                                accepted: true,
                                rejection_reason: None,
                            }
                        }
                        Err(err) => {
                            let safe_reason = sanitize_and_bound_log_excerpt(
                                &err.to_string(),
                                MAX_LOG_EXCERPT_BYTES,
                            );
                            tracing::warn!(
                                deployment_id = %plan.deployment_id,
                                service = %plan.service_name,
                                reason = %safe_reason,
                                "Rejected invalid ScenarioExecutionPlan (will fail closed on slot swap)"
                            );
                            if !plan.deployment_id.trim().is_empty() {
                                self.scenario_plans.lock().await.insert(
                                    plan.deployment_id.clone(),
                                    StoredScenarioPlan::Rejected(safe_reason.clone()),
                                );
                            }
                            ScenarioPlanAck {
                                deployment_id: plan.deployment_id,
                                lease_id: plan.lease_id,
                                accepted: false,
                                rejection_reason: Some(safe_reason),
                            }
                        }
                    };
                    let _ =
                        write_scenario_plan_ack_frame(&mut stream, &fory, &ack, header.sequence)
                            .await;
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

                    let action = self
                        .execute_slot_swap_and_gate(&mut stream, &fory, header.sequence, cmd)
                        .await?;
                    if action == SwapConnectionAction::Close {
                        return Ok(());
                    }
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

                    let mut effective_cmd = cmd.clone();
                    let requested_restore_slot = Slot::from(cmd.restore_slot);
                    if let Some((recorded_staged, recorded_prev)) =
                        self.staged_slots.lock().await.remove(&cmd.deployment_id)
                    {
                        if requested_restore_slot == recorded_staged {
                            tracing::warn!(
                                deployment_id = %cmd.deployment_id,
                                service = %cmd.service_name,
                                requested_restore = requested_restore_slot.as_str(),
                                enforced_restore = recorded_prev.as_str(),
                                "RollbackCommand targeted staged candidate slot; enforcing previous active slot"
                            );
                            effective_cmd.restore_slot =
                                mu_cd_ipc::DeploymentSlot::from(recorded_prev);
                        }
                    }
                    let restore_slot = Slot::from(effective_cmd.restore_slot);
                    let rb_deployment = self
                        .resolve_service_contract(&effective_cmd.service_name, Some(restore_slot))
                        .ok()
                        .and_then(|c| c.deployment);
                    let prior_cmd_unit = self
                        .swap_units
                        .lock()
                        .await
                        .get(&effective_cmd.deployment_id)
                        .cloned();

                    let (mut report, mut taint, elapsed_ms) = self
                        .watchdog_monitor
                        .handle_rollback_command_with_deployment(
                            &effective_cmd,
                            rb_deployment.as_ref(),
                            prior_cmd_unit.as_deref(),
                        )?;
                    let safe_rb_reason = sanitize_and_bound_log_excerpt(
                        &effective_cmd.reason,
                        MAX_LOG_EXCERPT_BYTES,
                    );
                    taint.reason =
                        sanitize_and_bound_log_excerpt(&taint.reason, MAX_LOG_EXCERPT_BYTES);
                    report.log_excerpt = report
                        .log_excerpt
                        .as_deref()
                        .map(|raw| sanitize_and_bound_log_excerpt(raw, MAX_LOG_EXCERPT_BYTES));

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
                        status_message: Some(safe_rb_reason.clone()),
                        attributes_json: serde_json::json!({
                            "deployment_id": effective_cmd.deployment_id,
                            "lease_id": effective_cmd.lease_id,
                            "service_name": effective_cmd.service_name,
                            "restore_slot": format!("{:?}", effective_cmd.restore_slot),
                            "failed_artifact_sha256": effective_cmd.failed_artifact_sha256,
                            "reason": safe_rb_reason,
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
                            "deployment_id": effective_cmd.deployment_id,
                            "service_name": effective_cmd.service_name,
                            "restore_slot": restore_slot.as_str(),
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
        self.run_with_listener(listener).await
    }

    /// Serves incoming mTLS or plaintext IPC connections on an already-bound `listener`.
    pub async fn run_with_listener(&self, listener: TcpListener) -> Result<(), AgentError> {
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

        self.spawn_pending_self_upgrade_if_present().await;

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
                                tracing::warn!("Connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("TLS handshake failed: {}", e);
                        }
                    }
                });
            } else {
                let conn_agent = self.clone_for_connection();

                tokio::spawn(async move {
                    if let Err(e) = conn_agent.handle_connection(stream).await {
                        tracing::warn!("Connection error: {}", e);
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
            Vec<PlannedSandboxedTest>,
            Option<EphemeralUnpackDir>,
            AbRulesConfig,
        ),
        AgentError,
    > {
        let contract = self.resolve_service_contract(&cmd.service_name, Some(target_slot))?;
        let stored_plan = self.scenario_plans.lock().await.remove(&cmd.deployment_id);

        match stored_plan {
            Some(StoredScenarioPlan::Rejected(reason)) => Err(AgentError::SandboxViolation(reason)),
            Some(StoredScenarioPlan::Accepted(plan)) => {
                if plan.service_name != cmd.service_name {
                    return Err(AgentError::Config(format!(
                        "ScenarioExecutionPlan service '{}' does not match SlotSwapCommand service '{}'",
                        plan.service_name, cmd.service_name
                    )));
                }
                if !plan.lease_id.is_empty() && plan.lease_id != cmd.lease_id {
                    return Err(AgentError::Config(format!(
                        "ScenarioExecutionPlan lease '{}' does not match SlotSwapCommand lease '{}'",
                        plan.lease_id, cmd.lease_id
                    )));
                }

                let mut unpack_guard = None;
                let mut unpacked_bundle = None;
                if let Some(ref digest) = plan.it_archive_digest {
                    let dir_guard =
                        EphemeralUnpackDir::create(&self.config.muconde_root, &cmd.deployment_id)?;
                    let archive_bytes = self
                        .it_fetcher
                        .fetch_it_archive_for_bundle(digest, plan.bundle_id.as_deref())
                        .await?;
                    let bundle =
                        unpack_verified_it_archive(&archive_bytes, digest, dir_guard.path())?;
                    unpacked_bundle = Some(bundle);
                    unpack_guard = Some(dir_guard);
                }

                let (gate_tests, planned_tests) = resolve_scenario_execution_plan(
                    &self.config.gate_catalog,
                    &self.config.it_sandbox,
                    &plan,
                    unpacked_bundle.as_ref(),
                )?;
                let mut ab_rules = contract.ab_rules;
                ab_rules.auto_rollback_on_critical = plan.auto_rollback_on_critical;
                Ok((gate_tests, planned_tests, unpack_guard, ab_rules))
            }
            None => {
                let mut unpack_guard = None;
                let mut unpacked_bundle = None;
                if let Some(ref digest) = contract.it_archive_digest {
                    let dir_guard =
                        EphemeralUnpackDir::create(&self.config.muconde_root, &cmd.deployment_id)?;
                    let archive_bytes = self.it_fetcher.fetch_it_archive(digest).await?;
                    let bundle =
                        unpack_verified_it_archive(&archive_bytes, digest, dir_guard.path())?;
                    unpacked_bundle = Some(bundle);
                    unpack_guard = Some(dir_guard);
                }

                let (gate_tests, custom_tests) = resolve_gate_plan_with_base(
                    &self.config.gate_catalog,
                    &contract.selection,
                    unpacked_bundle.as_ref(),
                )?;
                let planned_tests: Vec<PlannedSandboxedTest> = custom_tests
                    .into_iter()
                    .map(|test| PlannedSandboxedTest {
                        test,
                        sandbox_cfg: self.config.it_sandbox.clone(),
                    })
                    .collect();
                Ok((gate_tests, planned_tests, unpack_guard, contract.ab_rules))
            }
        }
    }

    async fn execute_slot_swap_and_gate<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        sequence: u64,
        cmd: SlotSwapCommand,
    ) -> Result<SwapConnectionAction, AgentError> {
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

        if let Some((recorded_staged, recorded_prev)) = self
            .staged_slots
            .lock()
            .await
            .get(&cmd.deployment_id)
            .copied()
        {
            if target_slot != recorded_staged || restore_slot != recorded_prev {
                self.handle_slot_inversion_rejection(
                    stream,
                    fory,
                    sequence,
                    &cmd,
                    recorded_staged,
                    recorded_prev,
                    &candidate_sha256,
                    &swap_trace_ctx,
                    swap_start_ns,
                )
                .await?;
                return Ok(SwapConnectionAction::Continue);
            }
        }

        let contract = self.resolve_service_contract(&cmd.service_name, Some(target_slot))?;
        let rollback_deployment = self
            .resolve_service_contract(&cmd.service_name, Some(restore_slot))
            .ok()
            .and_then(|c| c.deployment)
            .or_else(|| contract.deployment.clone());
        self.swap_units
            .lock()
            .await
            .insert(cmd.deployment_id.clone(), cmd.systemd_unit.clone());

        let is_self_upgrade = matches!(cmd.service_name.as_str(), "mu-cd-agent" | "muconde-agent")
            || contract
                .deployment
                .as_ref()
                .is_some_and(|d| d.self_upgrade_guard);
        let saved_scenario_plan = if is_self_upgrade {
            match self.scenario_plans.lock().await.get(&cmd.deployment_id) {
                Some(StoredScenarioPlan::Accepted(plan)) => {
                    Some(SerializableScenarioPlan::from(plan.as_ref()))
                }
                _ => None,
            }
        } else {
            None
        };

        // Pre-swap gate & IT bundle verification: fetch and verify it_archive_digest BEFORE
        // swapping/restarting the live service so services like mu-registry are never bounced
        // before their IT archive is fetched and bad archives never restart healthy services.
        let (gate_tests, custom_tests, _unpack_guard, ab_rules) =
            match self.prepare_gate_and_bundle(&cmd, target_slot).await {
                Ok(plan) => plan,
                Err(gate_err) => {
                    self.handle_gate_preflight_failure(
                        stream,
                        fory,
                        sequence,
                        &cmd,
                        restore_slot,
                        &candidate_sha256,
                        &swap_trace_ctx,
                        swap_start_ns,
                        gate_err,
                    )
                    .await?;
                    return Ok(SwapConnectionAction::Continue);
                }
            };

        if is_self_upgrade {
            return self
                .execute_self_upgrade_swap_and_handoff(
                    stream,
                    fory,
                    sequence,
                    &cmd,
                    target_slot,
                    restore_slot,
                    &candidate_sha256,
                    &swap_trace_ctx,
                    swap_start_ns,
                    contract.deployment.as_ref(),
                    rollback_deployment.as_ref(),
                    saved_scenario_plan,
                )
                .await;
        }

        let _receipt = self.slot_manager.atomic_swap_active_slot_with_deployment(
            &cmd.service_name,
            target_slot,
            contract.deployment.as_ref(),
            Some(&cmd.systemd_unit),
        )?;

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

        let mut gate = GateTracker::new(&cmd.deployment_id, gate_tests);
        send_it_progress(stream, fory, &gate.pending_updates(), sequence).await;

        let custom_names: Vec<String> = custom_tests.iter().map(|t| t.test.name.clone()).collect();
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
        let warmup_rollback_deployment = rollback_deployment.clone();

        let outcome_task = tokio::spawn(async move {
            monitor
                .monitor_warmup_with_deployment(
                    &cmd_clone,
                    &cand_sha_clone,
                    expires_at_ms,
                    consecutive_req,
                    Some(tx),
                    None,
                    warmup_rollback_deployment,
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
                mut taint,
                elapsed_rollback_ms,
            })) => {
                taint.reason = sanitize_and_bound_log_excerpt(&taint.reason, MAX_LOG_EXCERPT_BYTES);
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
                if self
                    .deliver_or_cache_it_report(stream, fory, &report, sequence)
                    .await?
                {
                    let _ = write_taint_frame(stream, fory, &taint, sequence).await;
                }
            }
            Ok(Ok(WatchdogOutcome::WarmedUp { .. })) => {
                self.wait_for_scenario_endpoints(&cmd, &custom_tests).await;

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
                    self.staged_slots.lock().await.remove(&cmd.deployment_id);
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
                        rollback_deployment.as_ref(),
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

        Ok(SwapConnectionAction::Continue)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_slot_inversion_rejection<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        sequence: u64,
        cmd: &SlotSwapCommand,
        recorded_staged: Slot,
        recorded_prev: Slot,
        candidate_sha256: &str,
        swap_trace_ctx: &mu_observable_ipc::TraceContext,
        swap_start_ns: i64,
    ) -> Result<(), AgentError> {
        let requested_to = Slot::from(cmd.to_slot);
        let requested_from = Slot::from(cmd.from_slot);
        let raw_reason = format!(
            "Slot inversion guard rejected SlotSwapCommand for deployment '{}': requested {} -> {}, but staged slot is {} (previous active {})",
            cmd.deployment_id,
            requested_from.as_str(),
            requested_to.as_str(),
            recorded_staged.as_str(),
            recorded_prev.as_str()
        );
        let safe_reason = sanitize_and_bound_log_excerpt(&raw_reason, MAX_LOG_EXCERPT_BYTES);
        tracing::error!(
            deployment_id = %cmd.deployment_id,
            service = %cmd.service_name,
            requested_from = requested_from.as_str(),
            requested_to = requested_to.as_str(),
            recorded_prev = recorded_prev.as_str(),
            recorded_staged = recorded_staged.as_str(),
            "Refusing SlotSwapCommand due to staged-slot mismatch (live slot preserved)"
        );

        let guard_test = "slot_inversion_guard".to_string();
        let mut tracker = GateTracker::new(
            &cmd.deployment_id,
            vec![GateTest::new(guard_test.clone(), true)],
        );
        send_it_progress(stream, fory, &tracker.pending_updates(), sequence).await;
        send_it_progress(stream, fory, &tracker.start_all(), sequence).await;
        let finished = tracker.finish_remaining(|_| false);
        send_it_progress(stream, fory, &finished, sequence).await;

        let end_ns = now_unix_nano().max(swap_start_ns);
        let err_span = OtelSpanEntry {
            trace_id: swap_trace_ctx.trace_id_hex(),
            span_id: swap_trace_ctx.span_id_hex(),
            parent_span_id: None,
            service_name: AGENT_SERVICE_NAME.to_string(),
            node_id: self.config.node_id.clone(),
            span_name: "muconde.agent.slot_swap".to_string(),
            span_kind: "SERVER".to_string(),
            start_time_unix_nano: swap_start_ns,
            end_time_unix_nano: end_ns,
            duration_ns: (end_ns - swap_start_ns) as u64,
            status_code: "ERROR".to_string(),
            status_message: Some(safe_reason.clone()),
            attributes_json: serde_json::json!({
                "deployment_id": cmd.deployment_id,
                "lease_id": cmd.lease_id,
                "service_name": cmd.service_name,
                "requested_from": requested_from.as_str(),
                "requested_to": requested_to.as_str(),
                "recorded_prev": recorded_prev.as_str(),
                "recorded_staged": recorded_staged.as_str(),
            })
            .to_string(),
        };
        self.telemetry_sink.emit_spans(vec![err_span]).await;

        let report = IntegrationTestReport {
            deployment_id: cmd.deployment_id.clone(),
            service_name: cmd.service_name.clone(),
            artifact_sha256: candidate_sha256.to_string(),
            executed_tests: vec![guard_test.clone()],
            passed: false,
            failed_tests: vec![guard_test],
            duration_ms: 0,
            log_excerpt: Some(safe_reason.clone()),
        };
        let taint = ArtifactTaintNotification {
            deployment_id: cmd.deployment_id.clone(),
            service_name: cmd.service_name.clone(),
            artifact_sha256: candidate_sha256.to_string(),
            tainted_at_epoch_ms: now_epoch_ms(),
            reason: safe_reason,
            rollback_completed: true,
        };
        write_it_report_frame(stream, fory, &report, sequence).await?;
        write_taint_frame(stream, fory, &taint, sequence).await?;
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
        swap_start_ns: i64,
        gate_err: AgentError,
    ) -> Result<(), AgentError> {
        let safe_reason =
            sanitize_and_bound_log_excerpt(&gate_err.to_string(), MAX_LOG_EXCERPT_BYTES);
        let failed_tests = match &gate_err {
            AgentError::UnknownIntegrationTests(missing) if !missing.is_empty() => missing.clone(),
            AgentError::SandboxViolation(_) => vec!["sandbox_policy_enforcement".to_string()],
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

        // Preflight runs BEFORE slot swap/restart, so live service remains untouched on restore_slot.
        self.emit_rollback_span(
            cmd,
            restore_slot,
            &safe_reason,
            swap_trace_ctx,
            swap_start_ns,
            0,
        )
        .await;

        let report = IntegrationTestReport {
            deployment_id: cmd.deployment_id.clone(),
            service_name: cmd.service_name.clone(),
            artifact_sha256: candidate_sha256.to_string(),
            executed_tests: failed_tests.clone(),
            passed: false,
            failed_tests,
            duration_ms: 0,
            log_excerpt: Some(safe_reason.clone()),
        };
        let taint = ArtifactTaintNotification {
            deployment_id: cmd.deployment_id.clone(),
            service_name: cmd.service_name.clone(),
            artifact_sha256: candidate_sha256.to_string(),
            tainted_at_epoch_ms: now_epoch_ms(),
            reason: safe_reason,
            rollback_completed: true,
        };
        if self
            .deliver_or_cache_it_report(stream, fory, &report, sequence)
            .await?
        {
            let _ = write_taint_frame(stream, fory, &taint, sequence).await;
        }
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
        custom_tests: &[PlannedSandboxedTest],
        ab_rules: &AbRulesConfig,
        rollback_deployment: Option<&DeploymentConfig>,
    ) -> Result<(), AgentError> {
        let suite_start = Instant::now();
        let mut aggregated_logs = String::new();

        for planned in custom_tests {
            let test = &planned.test;
            if let Some(running) = gate.start_test(&test.name) {
                send_it_progress(stream, fory, &[running], sequence).await;
            }

            let timeout = Duration::from_secs(
                test.timeout_secs
                    .unwrap_or(planned.sandbox_cfg.per_test_timeout_secs),
            );
            let exec_res = self
                .it_executor
                .execute_in_sandbox(
                    test,
                    &test.working_dir,
                    &planned.sandbox_cfg,
                    &cmd.service_name,
                    target_slot,
                    timeout,
                )
                .await;

            let (passed, detail_log) = match exec_res {
                Ok(out) => {
                    let raw = if !out.log_output.trim().is_empty() {
                        out.log_output
                    } else if !out.passed {
                        format!("exited with code {:?} (no output)", out.exit_code)
                    } else {
                        String::new()
                    };
                    let safe = if raw.is_empty() {
                        raw
                    } else {
                        sanitize_and_bound_log_excerpt(&raw, MAX_LOG_EXCERPT_BYTES)
                    };
                    (out.passed, safe)
                }
                Err(err) => (
                    false,
                    sanitize_and_bound_log_excerpt(
                        &format!("Sandbox execution failed: {err}"),
                        MAX_LOG_EXCERPT_BYTES,
                    ),
                ),
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

                let reason = sanitize_and_bound_log_excerpt(
                    &format!("Critical sandboxed integration test '{}' failed", test.name),
                    MAX_LOG_EXCERPT_BYTES,
                );
                let (mut report, taint, elapsed_rollback_ms) =
                    self.watchdog_monitor.execute_rollback_with_deployment(
                        &cmd.deployment_id,
                        &cmd.service_name,
                        restore_slot,
                        candidate_sha256,
                        &reason,
                        rollback_deployment,
                        Some(cmd.systemd_unit.as_str()),
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

                if self
                    .deliver_or_cache_it_report(stream, fory, &report, sequence)
                    .await?
                {
                    let _ = write_taint_frame(stream, fory, &taint, sequence).await;
                }
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
        if report.passed {
            self.staged_slots.lock().await.remove(&cmd.deployment_id);
        }
        let _ = self
            .deliver_or_cache_it_report(stream, fory, &report, sequence)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_self_upgrade_swap_and_handoff<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        fory: &fory::Fory,
        sequence: u64,
        cmd: &SlotSwapCommand,
        target_slot: Slot,
        restore_slot: Slot,
        candidate_sha256: &str,
        swap_trace_ctx: &mu_observable_ipc::TraceContext,
        swap_start_ns: i64,
        deployment: Option<&DeploymentConfig>,
        rollback_deployment: Option<&DeploymentConfig>,
        scenario_plan: Option<SerializableScenarioPlan>,
    ) -> Result<SwapConnectionAction, AgentError> {
        let swap_receipt = self.slot_manager.atomic_swap_active_slot_for_self_upgrade(
            &cmd.service_name,
            target_slot,
            deployment,
            Some(&cmd.systemd_unit),
        )?;

        if let Some(ref installed_bin) = swap_receipt.installed_binary_path {
            if let Err(err_msg) =
                validate_self_upgrade_binary(installed_bin, SELF_UPGRADE_VERSION_TIMEOUT).await
            {
                let rb_start = Instant::now();
                let _ = self.slot_manager.restore_slot_without_restart(
                    &cmd.service_name,
                    restore_slot,
                    rollback_deployment,
                    Some(&cmd.systemd_unit),
                );
                let elapsed_rollback_ms = rb_start.elapsed().as_millis() as u64;
                let safe_reason = sanitize_and_bound_log_excerpt(&err_msg, MAX_LOG_EXCERPT_BYTES);
                let test_name = "self_upgrade_binary_validation".to_string();
                let mut tracker = GateTracker::new(
                    &cmd.deployment_id,
                    vec![GateTest::new(test_name.clone(), true)],
                );
                send_it_progress(stream, fory, &tracker.pending_updates(), sequence).await;
                send_it_progress(stream, fory, &tracker.start_all(), sequence).await;
                let finished = tracker.finish_remaining(|_| false);
                send_it_progress(stream, fory, &finished, sequence).await;

                self.emit_rollback_span(
                    cmd,
                    restore_slot,
                    &safe_reason,
                    swap_trace_ctx,
                    swap_start_ns,
                    elapsed_rollback_ms,
                )
                .await;

                let report = IntegrationTestReport {
                    deployment_id: cmd.deployment_id.clone(),
                    service_name: cmd.service_name.clone(),
                    artifact_sha256: candidate_sha256.to_string(),
                    executed_tests: vec![test_name.clone()],
                    passed: false,
                    failed_tests: vec![test_name],
                    duration_ms: elapsed_rollback_ms,
                    log_excerpt: Some(safe_reason.clone()),
                };
                let taint = ArtifactTaintNotification {
                    deployment_id: cmd.deployment_id.clone(),
                    service_name: cmd.service_name.clone(),
                    artifact_sha256: candidate_sha256.to_string(),
                    tainted_at_epoch_ms: now_epoch_ms(),
                    reason: safe_reason,
                    rollback_completed: true,
                };
                if self
                    .deliver_or_cache_it_report(stream, fory, &report, sequence)
                    .await?
                {
                    let _ = write_taint_frame(stream, fory, &taint, sequence).await;
                }
                return Ok(SwapConnectionAction::Continue);
            }
        }

        let pending = PendingSelfUpgrade {
            deployment_id: cmd.deployment_id.clone(),
            lease_id: cmd.lease_id.clone(),
            service_name: cmd.service_name.clone(),
            from_slot: restore_slot.as_str().to_string(),
            to_slot: target_slot.as_str().to_string(),
            candidate_sha256: candidate_sha256.to_string(),
            systemd_unit: swap_receipt.resolved_unit.clone(),
            warmup_timeout_secs: cmd.warmup_timeout_secs,
            scenario_plan,
            deployment_config: deployment.cloned(),
            rollback_deployment: rollback_deployment.cloned(),
            created_epoch_ms: now_epoch_ms(),
        };
        let handoff_path = pending_self_upgrade_path(&self.config.muconde_root);
        write_pending_self_upgrade_atomic(&handoff_path, &pending)?;

        let swap_end_ns = now_unix_nano().max(swap_start_ns);
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
            duration_ns: (swap_end_ns - swap_start_ns) as u64,
            status_code: "OK".to_string(),
            status_message: None,
            attributes_json: serde_json::json!({
                "deployment_id": cmd.deployment_id,
                "lease_id": cmd.lease_id,
                "service_name": cmd.service_name,
                "from_slot": format!("{:?}", cmd.from_slot),
                "to_slot": format!("{:?}", cmd.to_slot),
                "subvolume": target_slot.as_str(),
                "systemd_unit": swap_receipt.resolved_unit,
                "self_upgrade_handoff": true,
            })
            .to_string(),
        };
        self.telemetry_sink.emit_spans(vec![swap_span]).await;

        self.slot_manager
            .run_systemctl_restart_no_block(&swap_receipt.resolved_unit)?;
        Ok(SwapConnectionAction::Close)
    }

    async fn spawn_pending_self_upgrade_if_present(&self) {
        let handoff_path = pending_self_upgrade_path(&self.config.muconde_root);
        let pending = match claim_pending_self_upgrade(&handoff_path) {
            Ok(Some(p)) => p,
            Ok(None) => return,
            Err(e) => {
                tracing::error!(
                    path = %handoff_path.display(),
                    error = %e,
                    "Failed loading .pending_self_upgrade.json on startup"
                );
                return;
            }
        };

        tracing::info!(
            deployment_id = %pending.deployment_id,
            service = %pending.service_name,
            from_slot = %pending.from_slot,
            to_slot = %pending.to_slot,
            "Claimed .pending_self_upgrade.json on startup; arming post-restart self-upgrade gate"
        );

        let report_tx = self
            .arm_undelivered_report(pending.deployment_id.clone())
            .await;
        if let Some(ref plan) = pending.scenario_plan {
            self.scenario_plans.lock().await.insert(
                pending.deployment_id.clone(),
                StoredScenarioPlan::Accepted(Box::new(ScenarioExecutionPlan::from(plan.clone()))),
            );
        }
        self.staged_digests.lock().await.insert(
            pending.deployment_id.clone(),
            pending.candidate_sha256.clone(),
        );
        if let (Some(to_slot), Some(from_slot)) = (
            Slot::from_target_str(&pending.to_slot),
            Slot::from_target_str(&pending.from_slot),
        ) {
            self.staged_slots
                .lock()
                .await
                .insert(pending.deployment_id.clone(), (to_slot, from_slot));
        }

        let bg_agent = self.clone_for_connection();
        tokio::spawn(async move {
            bg_agent
                .run_post_restart_self_upgrade_gate(pending, report_tx)
                .await;
        });
    }

    async fn run_post_restart_self_upgrade_gate(
        &self,
        pending: PendingSelfUpgrade,
        report_tx: watch::Sender<Option<IntegrationTestReport>>,
    ) {
        let suite_start = Instant::now();
        let swap_trace_ctx = trace_context_for_deployment(&pending.deployment_id, 2);
        let gate_start_ns = now_unix_nano();
        let target_slot = Slot::from_target_str(&pending.to_slot).unwrap_or(Slot::B);
        let restore_slot = Slot::from_target_str(&pending.from_slot).unwrap_or(Slot::A);

        let cmd = SlotSwapCommand {
            deployment_id: pending.deployment_id.clone(),
            lease_id: pending.lease_id.clone(),
            service_name: pending.service_name.clone(),
            from_slot: mu_cd_ipc::DeploymentSlot::from(restore_slot),
            to_slot: mu_cd_ipc::DeploymentSlot::from(target_slot),
            systemd_unit: pending.systemd_unit.clone(),
            warmup_timeout_secs: pending.warmup_timeout_secs,
        };

        let report = match self.prepare_gate_and_bundle(&cmd, target_slot).await {
            Ok((gate_tests, custom_tests, _unpack_guard, _ab_rules)) => {
                self.wait_for_scenario_endpoints(&cmd, &custom_tests).await;

                let mut gate = GateTracker::new(&cmd.deployment_id, gate_tests);
                let custom_names: Vec<String> =
                    custom_tests.iter().map(|t| t.test.name.clone()).collect();
                for name in gate.names() {
                    if !custom_names.contains(&name) {
                        let _ = gate.start_test(&name);
                        let _ = gate.finish(&name, true);
                    }
                }

                let mut aggregated_logs = String::new();
                for planned in &custom_tests {
                    let test = &planned.test;
                    let _ = gate.start_test(&test.name);
                    let timeout = Duration::from_secs(
                        test.timeout_secs
                            .unwrap_or(planned.sandbox_cfg.per_test_timeout_secs),
                    );
                    let exec_res = self
                        .it_executor
                        .execute_in_sandbox(
                            test,
                            &test.working_dir,
                            &planned.sandbox_cfg,
                            &cmd.service_name,
                            target_slot,
                            timeout,
                        )
                        .await;
                    let (passed, detail_log) = match exec_res {
                        Ok(out) => {
                            let raw = if !out.log_output.trim().is_empty() {
                                out.log_output
                            } else if !out.passed {
                                format!("exited with code {:?} (no output)", out.exit_code)
                            } else {
                                String::new()
                            };
                            let safe = if raw.is_empty() {
                                raw
                            } else {
                                sanitize_and_bound_log_excerpt(&raw, MAX_LOG_EXCERPT_BYTES)
                            };
                            (out.passed, safe)
                        }
                        Err(err) => (
                            false,
                            sanitize_and_bound_log_excerpt(
                                &format!("Sandbox execution failed: {err}"),
                                MAX_LOG_EXCERPT_BYTES,
                            ),
                        ),
                    };
                    if !detail_log.is_empty() {
                        aggregated_logs.push_str(&format!("[{}] {}\n", test.name, detail_log));
                    }
                    let _ = gate.finish(&test.name, passed);
                }

                let failed_tests = gate.names_in(TestState::Failed);
                let critical_failures = gate.critical_failures();
                IntegrationTestReport {
                    deployment_id: cmd.deployment_id.clone(),
                    service_name: cmd.service_name.clone(),
                    artifact_sha256: pending.candidate_sha256.clone(),
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
                }
            }
            Err(gate_err) => {
                let safe_reason =
                    sanitize_and_bound_log_excerpt(&gate_err.to_string(), MAX_LOG_EXCERPT_BYTES);
                IntegrationTestReport {
                    deployment_id: cmd.deployment_id.clone(),
                    service_name: cmd.service_name.clone(),
                    artifact_sha256: pending.candidate_sha256.clone(),
                    executed_tests: vec!["self_upgrade_post_restart_gate".to_string()],
                    passed: false,
                    failed_tests: vec!["self_upgrade_post_restart_gate".to_string()],
                    duration_ms: suite_start.elapsed().as_millis() as u64,
                    log_excerpt: Some(safe_reason),
                }
            }
        };

        if report.passed {
            self.staged_slots.lock().await.remove(&cmd.deployment_id);
            tracing::info!(
                deployment_id = %cmd.deployment_id,
                service = %cmd.service_name,
                "Post-restart self-upgrade gate PASSED; publishing report for controller reconnect"
            );
            let _ = report_tx.send(Some(report));
            return;
        }

        let rb_start = Instant::now();
        let rb_res = self.slot_manager.restore_slot_without_restart(
            &pending.service_name,
            restore_slot,
            pending.rollback_deployment.as_ref(),
            Some(&pending.systemd_unit),
        );
        let elapsed_rollback_ms = rb_start.elapsed().as_millis() as u64;
        if let Err(ref err) = rb_res {
            tracing::error!(
                deployment_id = %cmd.deployment_id,
                error = %err,
                "Failed restoring previous slot during post-restart self-upgrade rollback"
            );
        }
        let reason = report
            .log_excerpt
            .as_deref()
            .unwrap_or("Post-restart self-upgrade integration gate failed");
        self.emit_rollback_span(
            &cmd,
            restore_slot,
            reason,
            &swap_trace_ctx,
            gate_start_ns,
            elapsed_rollback_ms,
        )
        .await;
        tracing::warn!(
            deployment_id = %cmd.deployment_id,
            restore_slot = restore_slot.as_str(),
            elapsed_rollback_ms,
            "Post-restart self-upgrade gate FAILED; restored previous slot, publishing report before detached restart"
        );
        let _ = report_tx.send(Some(report));
        if !self.self_upgrade_failure_window.is_zero() {
            tokio::time::sleep(self.self_upgrade_failure_window).await;
        }
        if let Err(err) = self
            .slot_manager
            .run_systemctl_restart_no_block(&pending.systemd_unit)
        {
            tracing::error!(
                deployment_id = %cmd.deployment_id,
                unit = %pending.systemd_unit,
                error = %err,
                "Failed triggering detached rollback self-restart"
            );
        }
    }

    async fn wait_for_scenario_endpoints(
        &self,
        cmd: &SlotSwapCommand,
        custom_tests: &[PlannedSandboxedTest],
    ) {
        if cmd.warmup_timeout_secs == 0 {
            return;
        }
        let mut tcp_endpoints: Vec<(String, u16)> = Vec::new();
        let mut unix_sockets: Vec<PathBuf> = Vec::new();
        for planned in custom_tests {
            for ep in extract_scenario_tcp_endpoints(&planned.sandbox_cfg.allowlisted_env) {
                if !tcp_endpoints.contains(&ep) {
                    tcp_endpoints.push(ep);
                }
            }
            for sock in extract_scenario_unix_sockets(&planned.sandbox_cfg.allowlisted_env) {
                if !unix_sockets.contains(&sock) {
                    unix_sockets.push(sock);
                }
            }
        }
        let timeout = Duration::from_secs(cmd.warmup_timeout_secs);
        if !tcp_endpoints.is_empty() {
            if let Err(detail) =
                wait_for_tcp_endpoints_ready(&tcp_endpoints, timeout, TCP_WARMUP_POLL_INTERVAL)
                    .await
            {
                tracing::warn!(
                    deployment_id = %cmd.deployment_id,
                    service = %cmd.service_name,
                    detail = %detail,
                    "Warmup TCP readiness probe timed out; proceeding to sandboxed scenario probes"
                );
            }
        }
        if !unix_sockets.is_empty() {
            if let Err(detail) =
                wait_for_unix_sockets_ready(&unix_sockets, timeout, TCP_WARMUP_POLL_INTERVAL).await
            {
                tracing::warn!(
                    deployment_id = %cmd.deployment_id,
                    service = %cmd.service_name,
                    detail = %detail,
                    "Warmup Unix socket readiness probe timed out; proceeding to sandboxed scenario probes"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrfs::MockCommandRunner;
    use crate::sandbox_it::tests::build_test_tar_gz;
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
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};
        use mu_cd_ipc::TestState;
        use sha2::{Digest, Sha256};

        let temp = exec_tempdir();
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

        let candidate_bytes = b"#!/bin/sh\necho verified-candidate-v2\n";
        let candidate_sha = hex::encode(Sha256::digest(candidate_bytes));
        write_cas_blob(&cas_dir, &candidate_sha, candidate_bytes);

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
        use crate::sandbox_it::{
            tests::{build_test_tar_gz, exec_tempdir},
            MAX_LOG_EXCERPT_BYTES,
        };
        use mu_cd_ipc::TestState;
        use mu_observable_ipc::REDACTED_PLACEHOLDER;
        use sha2::{Digest, Sha256};

        let temp = exec_tempdir();
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

        let candidate_bytes = b"#!/bin/sh\necho verified-candidate-bad-it\n";
        let candidate_sha = hex::encode(Sha256::digest(candidate_bytes));
        write_cas_blob(&cas_dir, &candidate_sha, candidate_bytes);

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
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};
        use mu_cd_ipc::TestState;

        let service = "action-runner";
        let fory = create_fory_runtime().unwrap();

        // Case A: Preselected test absent from verified bundle fails closed & rolls back to @a.
        {
            let temp = exec_tempdir();
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
            let temp = exec_tempdir();
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

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_stage_deployment_request_fails_closed_on_invalid_missing_or_mismatched_cas_artifact(
    ) {
        use sha2::{Digest, Sha256};

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let valid_bytes = b"#!/bin/sh\necho ok\n";
        let valid_sha = hex::encode(Sha256::digest(valid_bytes));
        write_cas_blob(&cas_dir, &valid_sha, valid_bytes);

        let config = MuConDeAgentConfig {
            node_id: "node-cas-strict".into(),
            muconde_root: root.clone(),
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(MuConDeAgent::new(
            config,
            Arc::new(MockCommandRunner::new(true)),
            Arc::new(MockHealthProber::new(true)),
        ));

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });
        let fory = create_fory_runtime().unwrap();

        async fn send_stage(
            client: &mut tokio::io::DuplexStream,
            fory_ref: &fory::Fory,
            digest: String,
            seq: u64,
        ) -> StageDeploymentResponse {
            let req = StageDeploymentRequest {
                deployment_id: format!("dep-{seq}"),
                lease_id: "lease-strict".into(),
                service_name: "mu-cd-agent".into(),
                artifact_sha256: digest,
                target_slot: DeploymentSlot::SlotB,
            };
            let bytes = fory_ref.serialize(&req).unwrap();
            let hdr = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, bytes.len() as u32, 0, seq);
            write_frame(client, &hdr, &bytes).await.unwrap();
            let (_, resp_bytes) = read_frame(client).await.unwrap();
            fory_ref
                .deserialize::<StageDeploymentResponse>(&resp_bytes)
                .unwrap()
        }

        // 1. Path traversal token fails closed
        let r1 = send_stage(&mut client, &fory, "../evil".into(), 1).await;
        assert!(!r1.staged_ok);
        assert!(r1.error_message.is_some());

        // 2. Non-existent CAS digest fails closed
        let missing_sha = "d".repeat(64);
        let r2 = send_stage(&mut client, &fory, missing_sha, 2).await;
        assert!(!r2.staged_ok);
        assert!(r2.error_message.is_some());

        // 3. Mismatched pre-existing staging artifact fails closed and removes corrupt file
        let tampered_sha = "c".repeat(64);
        let staging_dir = root.join("staging");
        fs::create_dir_all(&staging_dir).unwrap();
        let tampered_path = staging_dir.join(&tampered_sha);
        fs::write(&tampered_path, b"corrupted-binary").unwrap();
        let r3 = send_stage(&mut client, &fory, tampered_sha, 3).await;
        assert!(!r3.staged_ok);
        assert!(r3.error_message.is_some());
        assert!(!tampered_path.exists());

        // 4. Verified CAS blob stages successfully
        let r4 = send_stage(&mut client, &fory, valid_sha, 4).await;
        assert!(r4.staged_ok);

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_rollback_paths_preserve_deployment_config_and_unit_overrides() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let service = "muregist";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a/.mucd")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();
        fs::write(
            srv_dir.join("@a/.mucd/mu-cd.yml"),
            "deployment:\n  systemd_unit: custom-registry-restore.service\n",
        )
        .unwrap();

        // Also seed a static web service to confirm MSG_TYPE_ROLLBACK suppresses systemctl restart
        let web_dir = root.join("mu-console");
        fs::create_dir_all(web_dir.join("@a/dist")).unwrap();
        fs::create_dir_all(web_dir.join("@b/dist")).unwrap();
        std::os::unix::fs::symlink("@b", web_dir.join("current")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let prober = Arc::new(MockHealthProber::new(false));
        let agent = Arc::new(MuConDeAgent::new(
            MuConDeAgentConfig {
                node_id: "node-rb-override".into(),
                muconde_root: root,
                default_warmup_timeout_secs: 5,
                required_consecutive_successes: 2,
                ..Default::default()
            },
            runner.clone(),
            prober,
        ));

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });
        let fory = create_fory_runtime().unwrap();

        // 1. Warmup failure triggers monitor_warmup_with_deployment -> rollback restarts manifest override unit
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-rb-override".into(),
            lease_id: "lease-rb".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "legacy-fallback.service".into(),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 1),
            &swap_bytes,
        )
        .await
        .unwrap();

        let _frames = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;

        let restart_calls: Vec<Vec<String>> = runner
            .recorded_calls()
            .into_iter()
            .filter(|c| c.len() >= 3 && c[0] == "systemctl" && c[1] == "restart")
            .collect();
        // Forward swap (@b has no override) uses command/alias unit; rollback to @a honors @a manifest systemd_unit
        assert_eq!(
            restart_calls.last().unwrap(),
            &vec![
                "systemctl".to_string(),
                "restart".to_string(),
                "custom-registry-restore.service".to_string()
            ]
        );

        // 2. Explicit MSG_TYPE_ROLLBACK respects prior SlotSwapCommand.systemd_unit when no manifest exists
        let calls_before_explicit = runner.recorded_calls().len();
        let rb_cmd = RollbackCommand {
            deployment_id: "dep-rb-override".into(),
            lease_id: "lease-rb".into(),
            service_name: "mu-ci-worker".into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: "deadbeef".into(),
            reason: "explicit rollback override test".into(),
        };
        fs::create_dir_all(agent.config.muconde_root.join("mu-ci-worker/@a")).unwrap();
        let rb_bytes = fory.serialize(&rb_cmd).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_ROLLBACK, rb_bytes.len() as u32, 0, 2),
            &rb_bytes,
        )
        .await
        .unwrap();
        let _rb_frames = read_frames_until(&mut client, 2, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let explicit_restarts: Vec<Vec<String>> = runner
            .recorded_calls()
            .into_iter()
            .skip(calls_before_explicit)
            .filter(|c| c.len() >= 3 && c[0] == "systemctl" && c[1] == "restart")
            .collect();
        assert_eq!(
            explicit_restarts,
            vec![vec![
                "systemctl".to_string(),
                "restart".to_string(),
                "legacy-fallback.service".to_string()
            ]]
        );

        // 3. Explicit MSG_TYPE_ROLLBACK on static web suppresses systemctl restart
        let calls_before_web = runner.recorded_calls().len();
        let web_rb = RollbackCommand {
            deployment_id: "dep-web-rb".into(),
            lease_id: "lease-web".into(),
            service_name: "mu-console".into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: "feedface".into(),
            reason: "static web rollback".into(),
        };
        let web_bytes = fory.serialize(&web_rb).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_ROLLBACK, web_bytes.len() as u32, 0, 3),
            &web_bytes,
        )
        .await
        .unwrap();
        let _web_frames = read_frames_until(&mut client, 2, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let web_restarts: Vec<Vec<String>> = runner
            .recorded_calls()
            .into_iter()
            .skip(calls_before_web)
            .filter(|c| c.len() >= 3 && c[0] == "systemctl" && c[1] == "restart")
            .collect();
        assert!(
            web_restarts.is_empty(),
            "Static web rollback must suppress systemctl restart"
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_plan_ipc_enforces_env_cidrs_ro_mounts_and_emits_ack() {
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};
        use mu_cd_ipc::TestState;
        use sha2::{Digest, Sha256};

        let temp = exec_tempdir();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        let cred_dir = temp.path().join("canary-creds");
        fs::create_dir_all(&cred_dir).unwrap();
        let ca_path = cred_dir.join("ca.crt");
        let tok_path = cred_dir.join("cd-readonly.token");
        fs::write(&ca_path, b"dummy-ca-pem").unwrap();
        fs::write(&tok_path, b"readonly-canary-token").unwrap();
        let ca_canon = fs::canonicalize(&ca_path).unwrap();
        let tok_canon = fs::canonicalize(&tok_path).unwrap();
        let root_canon = {
            fs::create_dir_all(&root).unwrap();
            fs::canonicalize(&root).unwrap()
        };
        let cred_canon = fs::canonicalize(&cred_dir).unwrap();

        let ceiling_path = temp.path().join("ceiling.yml");
        fs::write(
            &ceiling_path,
            format!(
                r#"node_id: "node-a"
arch: "x86_64"
allowed_backends:
  - Kernel
allowed_read_prefixes:
  - /usr
  - /bin
  - /lib
  - /lib64
  - /etc/ssl
  - /etc/hosts
  - /etc/resolv.conf
  - {cred}
  - {root}
allowed_write_prefixes:
  - /tmp
  - {root}
allowed_exec_prefixes:
  - /usr/bin
  - /bin
  - /usr/local/bin
  - {root}
allowed_egress_cidrs:
  - "127.0.0.1/32"
  - "192.0.2.10/32"
max_memlock_kb: 2097152
max_cpu_cores: 4
max_memory_mb: 4096
max_pids: 512
allow_spacemit_ai_thread: false
"#,
                cred = cred_canon.display(),
                root = root_canon.display(),
            ),
        )
        .unwrap();

        let service = "mu-ci-worker";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_mu_cd_agent","command":"bin/smoke_mu_cd_agent","args":["--nocapture"],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            (
                "bin/smoke_mu_cd_agent",
                b"#!/bin/sh\necho \"target=$MU_SMOKE_TARGET_URL ca=$MU_SMOKE_TLS_CA_FILE args=$*\"\nexit 0\n".as_slice(),
                0o755,
            ),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let candidate_bytes = b"#!/bin/sh\necho candidate-v3\n";
        let candidate_sha = hex::encode(Sha256::digest(candidate_bytes));
        write_cas_blob(&cas_dir, &candidate_sha, candidate_bytes);

        let mut config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root,
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        config.it_sandbox.host_ceiling_path = Some(ceiling_path);

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

        let fory = create_fory_runtime().unwrap();

        // Send 0x0D ScenarioExecutionPlan immediately followed by 0x06 SlotSwapCommand (non-blocking)
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-plan-ok".into(),
            lease_id: "lease-plan-ok".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            it_archive_digest: Some(it_digest),
            bundle_id: Some("bundle-99".into()),
            selected_tests: vec![
                "systemd_unit_active".into(),
                "health_endpoint_ready".into(),
                "smoke_mu_cd_agent".into(),
            ],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_mu_cd_agent_node_a".into(),
                test_binary: "smoke_mu_cd_agent".into(),
                args: vec!["--nocapture".into()],
                env: vec![
                    ScenarioEnvVar {
                        key: "MU_SMOKE_TARGET_URL".into(),
                        value: "https://node-a.example:8446".into(),
                    },
                    ScenarioEnvVar {
                        key: "MU_SMOKE_TLS_CA_FILE".into(),
                        value: ca_canon.display().to_string(),
                    },
                    ScenarioEnvVar {
                        key: "MU_SMOKE_BEARER_TOKEN_FILE".into(),
                        value: tok_canon.display().to_string(),
                    },
                    ScenarioEnvVar {
                        key: "MU_SMOKE_TIMEOUT_SECS".into(),
                        value: "10".into(),
                    },
                ],
                cidrs: vec!["192.0.2.10/32".into(), "127.0.0.1/32".into()],
                ro_mounts: vec![
                    ca_canon.display().to_string(),
                    tok_canon.display().to_string(),
                ],
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 50),
            &plan_bytes,
        )
        .await
        .unwrap();

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-plan-ok".into(),
            lease_id: "lease-plan-ok".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 51),
            &swap_bytes,
        )
        .await
        .unwrap();

        let frames = read_frames_until(&mut client, 8, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
        })
        .await;

        let (_, ack_payload) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_SCENARIO_PLAN_ACK)
            .expect("ScenarioPlanAck 0x0E must be emitted");
        let ack: ScenarioPlanAck = fory.deserialize(ack_payload).unwrap();
        assert!(ack.accepted);
        assert!(ack.rejection_reason.is_none());

        let progress = progress_of(&frames);
        assert!(progress
            .iter()
            .any(|p| p.test_name == "smoke_mu_cd_agent_node_a" && p.state == TestState::Passed));

        let (_, report_payload) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .expect("IntegrationTestReport must be emitted");
        let report: IntegrationTestReport = fory.deserialize(report_payload).unwrap();
        assert!(report.passed);
        assert!(report.failed_tests.is_empty());
        assert!(report
            .executed_tests
            .contains(&"smoke_mu_cd_agent_node_a".to_string()));
        let excerpt = report.log_excerpt.expect("stdout captured");
        assert!(excerpt.contains("target=https://node-a.example:8446"));
        assert!(excerpt.contains("args=--nocapture"));
        assert!(!frames.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT));
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::B)
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_plan_fails_closed_on_missing_required_test_without_stub_fallback() {
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};

        let service = "mu-cd-agent";
        let fory = create_fory_runtime().unwrap();

        // Case A: Required test missing from unpacked it_archive_digest
        // Case B: Required scenario with it_archive_digest = None (eliminating silent 2-check stub fallback)
        for (case_id, provide_archive) in [
            ("dep-missing-in-bundle", true),
            ("dep-missing-digest", false),
        ] {
            let temp = exec_tempdir();
            let root = temp.path().join("muconde");
            let cas_dir = temp.path().join("cas");
            let srv_dir = root.join(service);
            fs::create_dir_all(srv_dir.join("@a")).unwrap();
            fs::create_dir_all(srv_dir.join("@b")).unwrap();
            std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

            let it_digest = if provide_archive {
                let (archive, digest) = build_test_tar_gz(&[
                    (
                        "manifest.json",
                        br#"{"tests":[{"name":"smoke_other","command":"bin/other.sh","critical":true}]}"#.as_slice(),
                        0o644,
                    ),
                    ("bin/other.sh", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
                ]);
                write_cas_blob(&cas_dir, &digest, &archive);
                Some(digest)
            } else {
                None
            };

            let config = MuConDeAgentConfig {
                node_id: "node-a".into(),
                muconde_root: root,
                default_warmup_timeout_secs: 5,
                required_consecutive_successes: 1,
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

            let plan = ScenarioExecutionPlan {
                deployment_id: case_id.into(),
                lease_id: format!("lease-{case_id}"),
                service_name: service.into(),
                node_id: "node-a".into(),
                policy_commit_sha: "abcdef1234567890abcdef1234567890abcdef12".into(),
                it_archive_digest: it_digest,
                bundle_id: None,
                selected_tests: vec![
                    "systemd_unit_active".into(),
                    "health_endpoint_ready".into(),
                    "smoke_required_missing".into(),
                ],
                scenarios: vec![ScenarioTestSpec {
                    name: "smoke_required_missing".into(),
                    test_binary: "smoke_required_missing".into(),
                    args: vec!["--nocapture".into()],
                    env: Vec::new(),
                    cidrs: vec!["127.0.0.1/32".into()],
                    ro_mounts: Vec::new(),
                    critical: true,
                    timeout_secs: 10,
                }],
                env: Vec::new(),
                args: Vec::new(),
                cidrs: Vec::new(),
                ro_mounts: Vec::new(),
                max_pids: 256,
                max_memlock_kb: 65_536,
                auto_rollback_on_critical: true,
            };
            let plan_bytes = fory.serialize(&plan).unwrap();
            write_frame(
                &mut client,
                &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 60),
                &plan_bytes,
            )
            .await
            .unwrap();

            let swap_cmd = SlotSwapCommand {
                deployment_id: case_id.into(),
                lease_id: format!("lease-{case_id}"),
                service_name: service.into(),
                from_slot: DeploymentSlot::SlotA,
                to_slot: DeploymentSlot::SlotB,
                systemd_unit: format!("{service}.service"),
                warmup_timeout_secs: 5,
            };
            let swap_bytes = fory.serialize(&swap_cmd).unwrap();
            write_frame(
                &mut client,
                &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 61),
                &swap_bytes,
            )
            .await
            .unwrap();

            let frames = read_frames_until(&mut client, 5, |fs| {
                fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                    && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
            })
            .await;

            let (_, rep_p) = frames
                .iter()
                .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                .expect("IntegrationTestReport must be emitted on missing required test");
            let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
            assert!(!report.passed);
            assert!(report
                .failed_tests
                .contains(&"smoke_required_missing".to_string()));

            let (_, taint_p) = frames
                .iter()
                .find(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
                .expect("ArtifactTaintNotification must be emitted on missing required test");
            let taint: ArtifactTaintNotification = fory.deserialize(taint_p).unwrap();
            assert!(taint.rollback_completed);
            assert_eq!(
                agent.slot_manager.read_active_slot(service).unwrap(),
                Some(Slot::A)
            );

            drop(client);
            let _ = agent_task.await;
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_plan_fails_closed_on_sandbox_denial_and_disallowed_env_with_redaction() {
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};
        use mu_observable_ipc::REDACTED_PLACEHOLDER;

        let service = "mu-cd-agent";
        let fory = create_fory_runtime().unwrap();

        let temp = exec_tempdir();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();
        let root_canon = fs::canonicalize(&root).unwrap();

        let ceiling_path = temp.path().join("ceiling.yml");
        fs::write(
            &ceiling_path,
            format!(
                r#"node_id: "node-a"
arch: "x86_64"
allowed_backends:
  - Kernel
allowed_read_prefixes:
  - /usr
  - /bin
  - {root}
allowed_write_prefixes:
  - /tmp
  - {root}
allowed_exec_prefixes:
  - /usr/bin
  - /bin
  - {root}
allowed_egress_cidrs:
  - "192.0.2.10/32"
  - "127.0.0.1/32"
max_memlock_kb: 65536
max_cpu_cores: 4
max_memory_mb: 1024
max_pids: 256
allow_spacemit_ai_thread: false
"#,
                root = root_canon.display(),
            ),
        )
        .unwrap();

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_check","command":"bin/check.sh","critical":true}]}"#
                    .as_slice(),
                0o644,
            ),
            ("bin/check.sh", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let mut config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root,
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        config.it_sandbox.host_ceiling_path = Some(ceiling_path);

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

        // Case A: Out-of-ceiling CIDR 0.0.0.0/0 fails closed via SecurityGrantDenied -> rollback + taint
        let bad_cidr_plan = ScenarioExecutionPlan {
            deployment_id: "dep-bad-cidr".into(),
            lease_id: "lease-bad-cidr".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "abcdef1234567890abcdef1234567890abcdef12".into(),
            it_archive_digest: Some(it_digest.clone()),
            bundle_id: None,
            selected_tests: vec!["systemd_unit_active".into(), "smoke_check".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_check".into(),
                test_binary: "smoke_check".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["0.0.0.0/0".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let b1 = fory.serialize(&bad_cidr_plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, b1.len() as u32, 0, 70),
            &b1,
        )
        .await
        .unwrap();
        let swap1 = SlotSwapCommand {
            deployment_id: "dep-bad-cidr".into(),
            lease_id: "lease-bad-cidr".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let s1 = fory.serialize(&swap1).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, s1.len() as u32, 0, 71),
            &s1,
        )
        .await
        .unwrap();

        let frames1 = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let (_, rep1_p) = frames1
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .unwrap();
        let rep1: IntegrationTestReport = fory.deserialize(rep1_p).unwrap();
        assert!(!rep1.passed);
        assert!(rep1
            .failed_tests
            .contains(&"sandbox_policy_enforcement".to_string()));
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A)
        );

        // Case B: Rejected plan on 0x0D (disallowed LD_PRELOAD + embedded secret) still fails closed on 0x06
        let bad_env_plan = ScenarioExecutionPlan {
            deployment_id: "dep-bad-env".into(),
            lease_id: "lease-bad-env".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "abcdef1234567890abcdef1234567890abcdef12".into(),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec!["systemd_unit_active".into(), "smoke_check".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_check".into(),
                test_binary: "smoke_check".into(),
                args: Vec::new(),
                env: vec![ScenarioEnvVar {
                    key: "LD_PRELOAD".into(),
                    value: "token=super-secret-preload".into(),
                }],
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let b2 = fory.serialize(&bad_env_plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, b2.len() as u32, 0, 80),
            &b2,
        )
        .await
        .unwrap();
        let swap2 = SlotSwapCommand {
            deployment_id: "dep-bad-env".into(),
            lease_id: "lease-bad-env".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let s2 = fory.serialize(&swap2).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, s2.len() as u32, 0, 81),
            &s2,
        )
        .await
        .unwrap();

        let frames2 = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let (_, ack2_p) = frames2
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_SCENARIO_PLAN_ACK)
            .expect("ScenarioPlanAck 0x0E must be emitted on rejection");
        let ack2: ScenarioPlanAck = fory.deserialize(ack2_p).unwrap();
        assert!(!ack2.accepted);
        assert!(ack2.rejection_reason.is_some());

        let (_, rep2_p) = frames2
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .unwrap();
        let rep2: IntegrationTestReport = fory.deserialize(rep2_p).unwrap();
        assert!(!rep2.passed);
        assert!(!rep2
            .log_excerpt
            .as_deref()
            .unwrap_or("")
            .contains("super-secret-preload"));
        let (_, taint2_p) = frames2
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
            .unwrap();
        let taint2: ArtifactTaintNotification = fory.deserialize(taint2_p).unwrap();
        assert!(taint2.rollback_completed);
        assert!(!taint2.reason.contains("super-secret-preload"));
        assert!(!REDACTED_PLACEHOLDER.is_empty());
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A)
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_slot_inversion_guard_rejects_mismatched_swap_and_preserves_live_slot() {
        use sha2::{Digest, Sha256};

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-ci-controller";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a/bin")).unwrap();
        fs::create_dir_all(srv_dir.join("@b/bin")).unwrap();
        fs::write(srv_dir.join("@b/bin").join(service), b"live-slot-b-bin").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("@b", srv_dir.join("current")).unwrap();

        let candidate_bytes = b"candidate-slot-a-bin";
        let candidate_sha = hex::encode(Sha256::digest(candidate_bytes));
        write_cas_blob(&cas_dir, &candidate_sha, candidate_bytes);

        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(MuConDeAgent::new(
            config,
            Arc::new(MockCommandRunner::new(true)),
            Arc::new(MockHealthProber::new(true)),
        ));

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();

        // 1. Controller requests SlotB even though live `current -> @b`; agent stages into SlotA.
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-slot-inv-1".into(),
            lease_id: "lease-slot-inv-1".into(),
            service_name: service.into(),
            artifact_sha256: candidate_sha.clone(),
            target_slot: DeploymentSlot::SlotB,
        };
        let stage_bytes = fory.serialize(&stage_req).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, stage_bytes.len() as u32, 0, 1),
            &stage_bytes,
        )
        .await
        .unwrap();

        let (resp_hdr, resp_payload) = read_frame(&mut client).await.unwrap();
        assert_eq!(resp_hdr.msg_type, MSG_TYPE_STAGE_DEPLOY_RESP);
        let stage_resp: StageDeploymentResponse = fory.deserialize(&resp_payload).unwrap();
        assert!(stage_resp.staged_ok);
        assert_eq!(stage_resp.target_slot, DeploymentSlot::SlotA);

        // 2. Out-of-sync controller sends inverted SlotSwapCommand (SlotA -> SlotB).
        let bad_swap = SlotSwapCommand {
            deployment_id: "dep-slot-inv-1".into(),
            lease_id: "lease-slot-inv-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&bad_swap).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2),
            &swap_bytes,
        )
        .await
        .unwrap();

        let frames = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;

        let (_, rep_p) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .expect("IntegrationTestReport must be emitted");
        let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
        assert!(!report.passed);
        assert_eq!(
            report.failed_tests,
            vec!["slot_inversion_guard".to_string()]
        );
        assert!(report
            .log_excerpt
            .as_deref()
            .unwrap_or("")
            .contains("Slot inversion guard rejected"));

        let (_, taint_p) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
            .expect("ArtifactTaintNotification must be emitted");
        let taint: ArtifactTaintNotification = fory.deserialize(taint_p).unwrap();
        assert!(taint.rollback_completed);
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::B),
            "Live slot @b must remain completely untouched"
        );

        // 3. Even if the out-of-sync controller follows up with RollbackCommand(SlotA),
        //    the agent must never activate the staged candidate SlotA.
        let bad_rb = RollbackCommand {
            deployment_id: "dep-slot-inv-1".into(),
            lease_id: "lease-slot-inv-1".into(),
            service_name: service.into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: candidate_sha,
            reason: "Controller rollback Authorization: Bearer secret-rb-token-999".into(),
        };
        let rb_bytes = fory.serialize(&bad_rb).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_ROLLBACK, rb_bytes.len() as u32, 0, 3),
            &rb_bytes,
        )
        .await
        .unwrap();

        let rb_frames = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let (_, rb_rep_p) = rb_frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .unwrap();
        let rb_report: IntegrationTestReport = fory.deserialize(rb_rep_p).unwrap();
        assert!(!rb_report
            .log_excerpt
            .as_deref()
            .unwrap_or("")
            .contains("secret-rb-token-999"));
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::B),
            "Rollback guard must enforce previous active slot @b, never candidate @a"
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_warmup_tcp_readiness_probe_waits_for_delayed_listener() {
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};
        use mu_cd_ipc::{ScenarioEnvVar, ScenarioExecutionPlan, ScenarioTestSpec};
        use sha2::{Digest, Sha256};

        struct TcpConnectCheckExecutor {
            port: u16,
        }

        #[async_trait::async_trait]
        impl SandboxedCommandExecutor for TcpConnectCheckExecutor {
            async fn execute_in_sandbox(
                &self,
                test: &DiscoveredItTest,
                work_dir: &Path,
                sandbox_cfg: &ItSandboxConfig,
                _service_name: &str,
                _slot: Slot,
                _timeout: Duration,
            ) -> Result<crate::sandbox_it::SandboxedExecutionOutput, AgentError> {
                let mut argv = vec![test.command_path.as_os_str().to_os_string()];
                for arg in &sandbox_cfg.extra_args {
                    argv.push(std::ffi::OsString::from(arg));
                }
                let (effective_policy, execution_plan) =
                    build_it_sandbox_plan(work_dir, &argv, sandbox_cfg)?;
                let connected = std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok();
                Ok(crate::sandbox_it::SandboxedExecutionOutput {
                    passed: connected,
                    exit_code: Some(if connected { 0 } else { 1 }),
                    duration_ms: 5,
                    log_output: if connected {
                        "tcp_ready=true".to_string()
                    } else {
                        "tcp_ready=false (connection refused)".to_string()
                    },
                    effective_policy,
                    execution_plan,
                })
            }
        }

        let probe_sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe_sock.local_addr().unwrap().port();
        drop(probe_sock);

        let temp = exec_tempdir();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-ci-controller";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a/bin")).unwrap();
        fs::create_dir_all(srv_dir.join("@b/bin")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_delayed","command":"bin/smoke_delayed","args":["--nocapture"],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            ("bin/smoke_delayed", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let candidate_bytes = b"delayed-service-bin";
        let candidate_sha = hex::encode(Sha256::digest(candidate_bytes));
        write_cas_blob(&cas_dir, &candidate_sha, candidate_bytes);

        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(
            MuConDeAgent::new(
                config,
                Arc::new(MockCommandRunner::new(true)),
                Arc::new(MockHealthProber::new(true)),
            )
            .with_it_executor(Arc::new(TcpConnectCheckExecutor { port })),
        );

        // Bind the target TCP listener 600ms after the test begins so immediate execution would fail.
        let binder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .unwrap();
            for _ in 0..2 {
                let _ = listener.accept().await;
            }
        });

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-delayed-tcp".into(),
            lease_id: "lease-delayed-tcp".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "b".repeat(40),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec![
                "systemd_unit_active".into(),
                "health_endpoint_ready".into(),
                "smoke_delayed".into(),
            ],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_delayed_node_a".into(),
                test_binary: "smoke_delayed".into(),
                args: vec!["--nocapture".into()],
                env: vec![ScenarioEnvVar {
                    key: "MU_SMOKE_TARGET_URL".into(),
                    value: format!("http://127.0.0.1:{port}/health"),
                }],
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 10),
            &plan_bytes,
        )
        .await
        .unwrap();

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-delayed-tcp".into(),
            lease_id: "lease-delayed-tcp".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
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

        let frames = read_frames_until(&mut client, 8, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
        })
        .await;
        let (_, rep_p) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .expect("IntegrationTestReport must be emitted");
        let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
        assert!(
            report.passed,
            "Delayed-bind TCP readiness probe must wait until listener binds: {report:?}"
        );
        assert!(report
            .log_excerpt
            .as_deref()
            .unwrap_or("")
            .contains("tcp_ready=true"));

        drop(client);
        let _ = agent_task.await;
        let _ = binder.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_agent_it_report_log_excerpt_redacts_secrets_and_never_leaks() {
        use crate::sandbox_it::tests::{build_test_tar_gz, exec_tempdir};
        use mu_cd_ipc::{ScenarioExecutionPlan, ScenarioTestSpec};
        use mu_observable_ipc::REDACTED_PLACEHOLDER;
        use sha2::{Digest, Sha256};

        struct LeakyFailExecutor;

        #[async_trait::async_trait]
        impl SandboxedCommandExecutor for LeakyFailExecutor {
            async fn execute_in_sandbox(
                &self,
                test: &DiscoveredItTest,
                work_dir: &Path,
                sandbox_cfg: &ItSandboxConfig,
                _service_name: &str,
                _slot: Slot,
                _timeout: Duration,
            ) -> Result<crate::sandbox_it::SandboxedExecutionOutput, AgentError> {
                let argv = vec![test.command_path.as_os_str().to_os_string()];
                let (effective_policy, execution_plan) =
                    build_it_sandbox_plan(work_dir, &argv, sandbox_cfg)?;
                Ok(crate::sandbox_it::SandboxedExecutionOutput {
                    passed: false,
                    exit_code: Some(1),
                    duration_ms: 12,
                    log_output: concat!(
                        "probe failed 403 Authorization: Bearer canary-top-secret-token-777\n",
                        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIPayloadCanaryKey999\n-----END EC PRIVATE KEY-----\n",
                        "ghp_canarySecretPat1234567890"
                    )
                    .to_string(),
                    effective_policy,
                    execution_plan,
                })
            }
        }

        let temp = exec_tempdir();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-registry";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a/bin")).unwrap();
        fs::create_dir_all(srv_dir.join("@b/bin")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_redact","command":"bin/smoke_redact","args":[],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            ("bin/smoke_redact", b"#!/bin/sh\nexit 1\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let candidate_bytes = b"redact-check-bin";
        let candidate_sha = hex::encode(Sha256::digest(candidate_bytes));
        write_cas_blob(&cas_dir, &candidate_sha, candidate_bytes);

        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(
            MuConDeAgent::new(
                config,
                Arc::new(MockCommandRunner::new(true)),
                Arc::new(MockHealthProber::new(true)),
            )
            .with_it_executor(Arc::new(LeakyFailExecutor)),
        );

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-redact-1".into(),
            lease_id: "lease-redact-1".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "c".repeat(40),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec![
                "systemd_unit_active".into(),
                "health_endpoint_ready".into(),
                "smoke_redact".into(),
            ],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_redact".into(),
                test_binary: "smoke_redact".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 20),
            &plan_bytes,
        )
        .await
        .unwrap();

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-redact-1".into(),
            lease_id: "lease-redact-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: format!("{service}.service"),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 21),
            &swap_bytes,
        )
        .await
        .unwrap();

        let frames = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let (_, rep_p) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .expect("IntegrationTestReport must be emitted");
        let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
        assert!(!report.passed);
        let excerpt = report
            .log_excerpt
            .as_deref()
            .expect("Failed test report must include redacted log_excerpt");
        assert!(excerpt.len() <= MAX_LOG_EXCERPT_BYTES);
        assert!(
            excerpt.contains(REDACTED_PLACEHOLDER),
            "Expected redacted placeholder in excerpt: {excerpt}"
        );
        for leaked in [
            "canary-top-secret-token-777",
            "MHcCAQEEIPayloadCanaryKey999",
            "ghp_canarySecretPat1234567890",
        ] {
            assert!(
                !excerpt.contains(leaked),
                "Raw secret '{leaked}' must never leak into log_excerpt: {excerpt}"
            );
        }

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_preflight_it_bundle_failure_does_not_swap_or_restart_live_service() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-registry";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

        let runner = Arc::new(MockCommandRunner::new(true));
        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(MuConDeAgent::new(
            config,
            runner.clone(),
            Arc::new(MockHealthProber::new(true)),
        ));

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let missing_digest = "f".repeat(64);
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-preflight-no-bounce".into(),
            lease_id: "lease-preflight".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "a".repeat(40),
            it_archive_digest: Some(missing_digest),
            bundle_id: None,
            selected_tests: vec!["smoke_mu_registry".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_mu_registry".into(),
                test_binary: "smoke_mu_registry".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 1),
            &plan_bytes,
        )
        .await
        .unwrap();
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-preflight-no-bounce".into(),
            lease_id: "lease-preflight".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "muregist.service".into(),
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

        let frames = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let (_, rep_p) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .unwrap();
        let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
        assert!(!report.passed);
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A),
            "live slot must remain untouched on pre-swap IT bundle fetch failure"
        );
        assert!(
            !runner
                .recorded_calls()
                .iter()
                .map(|c| c.join(" "))
                .any(|c| c.contains("systemctl restart")),
            "pre-swap failure must issue zero systemctl restart commands, got: {:?}",
            runner.recorded_calls()
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_self_upgrade_pre_restart_corrupt_binary_rolls_back_under_100ms_without_restart() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-cd-agent";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a/bin")).unwrap();
        fs::create_dir_all(srv_dir.join("@b/bin")).unwrap();
        fs::write(srv_dir.join("@a/bin/mu-cd-agent"), b"#!/bin/sh\nexit 0\n").unwrap();
        // Corrupt / non-executable binary in @b/bin triggers immediate --version failure
        fs::write(
            srv_dir.join("@b/bin/mu-cd-agent"),
            b"\x7fELFcorrupt-not-valid",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                srv_dir.join("@a/bin/mu-cd-agent"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            fs::set_permissions(
                srv_dir.join("@b/bin/mu-cd-agent"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();
        }

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_mu_cd_agent","command":"bin/smoke_mu_cd_agent","args":[],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            ("bin/smoke_mu_cd_agent", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let runner = Arc::new(MockCommandRunner::new(true));
        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(MuConDeAgent::new(
            config,
            runner.clone(),
            Arc::new(MockHealthProber::new(true)),
        ));

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let agent_server = agent.clone();
        let agent_task = tokio::spawn(async move {
            let _ = agent_server.handle_connection(server).await;
        });

        let fory = create_fory_runtime().unwrap();
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-self-corrupt".into(),
            lease_id: "lease-self-corrupt".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "b".repeat(40),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec!["smoke_mu_cd_agent".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_mu_cd_agent".into(),
                test_binary: "smoke_mu_cd_agent".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut client,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 1),
            &plan_bytes,
        )
        .await
        .unwrap();
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-self-corrupt".into(),
            lease_id: "lease-self-corrupt".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "muconde-agent.service".into(),
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

        let frames = read_frames_until(&mut client, 5, |fs| {
            fs.iter().any(|(t, _)| *t == MSG_TYPE_IT_REPORT)
                && fs.iter().any(|(t, _)| *t == MSG_TYPE_ARTIFACT_TAINT)
        })
        .await;
        let (_, rep_p) = frames
            .iter()
            .find(|(t, _)| *t == MSG_TYPE_IT_REPORT)
            .unwrap();
        let report: IntegrationTestReport = fory.deserialize(rep_p).unwrap();
        assert!(!report.passed);
        assert!(report
            .failed_tests
            .contains(&"self_upgrade_binary_validation".to_string()));
        assert!(
            report.duration_ms < 100,
            "pre-restart corrupt binary rollback must complete in <100ms, took {}ms",
            report.duration_ms
        );
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A),
            "corrupt self-upgrade candidate must roll back symlink immediately to @a"
        );
        assert!(!pending_self_upgrade_path(&root).exists());
        assert!(
            !runner
                .recorded_calls()
                .iter()
                .map(|c| c.join(" "))
                .any(|c| c.contains("systemctl restart")),
            "corrupt self-upgrade binary must abort self-restart"
        );

        drop(client);
        let _ = agent_task.await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_self_upgrade_pass_and_post_restart_reconnect_handoff() {
        use crate::sandbox_it::SandboxedExecutionOutput;

        struct PassingSelfUpgradeExecutor {
            delay: Duration,
        }
        #[async_trait::async_trait]
        impl SandboxedCommandExecutor for PassingSelfUpgradeExecutor {
            async fn execute_in_sandbox(
                &self,
                test: &DiscoveredItTest,
                work_dir: &Path,
                sandbox_cfg: &ItSandboxConfig,
                _service: &str,
                _target_slot: Slot,
                _timeout: Duration,
            ) -> Result<SandboxedExecutionOutput, AgentError> {
                let argv = vec![test.command_path.as_os_str().to_os_string()];
                let (effective_policy, execution_plan) =
                    build_it_sandbox_plan(work_dir, &argv, sandbox_cfg)?;
                tokio::time::sleep(self.delay).await;
                Ok(SandboxedExecutionOutput {
                    passed: true,
                    exit_code: Some(0),
                    duration_ms: 10,
                    log_output: "smoke_mu_cd_agent ok".into(),
                    effective_policy,
                    execution_plan,
                })
            }
        }

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-cd-agent";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a/bin")).unwrap();
        fs::create_dir_all(srv_dir.join("@b/bin")).unwrap();
        fs::write(
            srv_dir.join("@a/bin/mu-cd-agent"),
            b"#!/bin/sh\necho mu-cd-agent 0.1.0\n",
        )
        .unwrap();
        fs::write(
            srv_dir.join("@b/bin/mu-cd-agent"),
            b"#!/bin/sh\necho mu-cd-agent 0.2.0\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                srv_dir.join("@a/bin/mu-cd-agent"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            fs::set_permissions(
                srv_dir.join("@b/bin/mu-cd-agent"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();
        }

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_mu_cd_agent","command":"bin/smoke_mu_cd_agent","args":[],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            ("bin/smoke_mu_cd_agent", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        // Phase 1: Old agent validates --version, persists 0600 .pending_self_upgrade.json,
        // runs systemctl restart --no-block, and closes stream cleanly.
        let runner1 = Arc::new(MockCommandRunner::new(true));
        let config1 = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir.clone()),
            ..Default::default()
        };
        let old_agent = Arc::new(MuConDeAgent::new(
            config1,
            runner1.clone(),
            Arc::new(MockHealthProber::new(true)),
        ));

        let (mut client1, server1) = tokio::io::duplex(64 * 1024);
        let old_task = tokio::spawn(async move {
            old_agent.handle_connection(server1).await.unwrap();
        });

        let fory = create_fory_runtime().unwrap();
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-self-pass".into(),
            lease_id: "lease-self-pass".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "c".repeat(40),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec!["smoke_mu_cd_agent".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_mu_cd_agent".into(),
                test_binary: "smoke_mu_cd_agent".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut client1,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 1),
            &plan_bytes,
        )
        .await
        .unwrap();
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-self-pass".into(),
            lease_id: "lease-self-pass".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "muconde-agent.service".into(),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        write_frame(
            &mut client1,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2),
            &swap_bytes,
        )
        .await
        .unwrap();

        // Drain ack until EOF caused by clean self-restart stream close
        let _ = read_frames_until(&mut client1, 3, |_| false).await;
        old_task.await.unwrap();

        let handoff_path = pending_self_upgrade_path(&root);
        assert!(handoff_path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&handoff_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, ".pending_self_upgrade.json must be 0600");
        }
        assert!(runner1
            .recorded_calls()
            .iter()
            .map(|c| c.join(" "))
            .any(|c| c.starts_with("systemctl restart --no-block ")));

        // Phase 2: Fresh restarted agent claims .pending_self_upgrade.json, serves normal
        // MSG_TYPE_HEARTBEAT RPC without consuming undelivered_report, and delivers the final
        // passing IntegrationTestReport to the silent reconnecting controller.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runner2 = Arc::new(MockCommandRunner::new(true));
        let config2 = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let new_agent = Arc::new(
            MuConDeAgent::new(config2, runner2, Arc::new(MockHealthProber::new(true)))
                .with_it_executor(Arc::new(PassingSelfUpgradeExecutor {
                    delay: Duration::from_millis(220),
                })),
        );
        let server_agent = new_agent.clone();
        let server_task = tokio::spawn(async move {
            let _ = server_agent.run_with_listener(listener).await;
        });

        // Probe heartbeat RPC immediately while post-restart gate is running (< 150ms):
        // must succeed normally and NOT consume undelivered_report.
        let mut hb_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let hb_hdr = IpcHeader::new(MSG_TYPE_HEARTBEAT, 0, 0, 99);
        write_frame(&mut hb_stream, &hb_hdr, &[]).await.unwrap();
        let (hb_resp_hdr, _) = read_frame(&mut hb_stream).await.unwrap();
        assert_eq!(hb_resp_hdr.msg_type, MSG_TYPE_HEARTBEAT);
        drop(hb_stream);

        // Silent reconnecting controller connects and awaits MSG_TYPE_IT_REPORT.
        let mut ctrl_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (rep_hdr, rep_payload) =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut ctrl_stream))
                .await
                .expect("timed out waiting for self-upgrade report")
                .unwrap();
        assert_eq!(rep_hdr.msg_type, MSG_TYPE_IT_REPORT);
        let report: IntegrationTestReport = fory.deserialize(&rep_payload).unwrap();
        assert!(report.passed);
        assert_eq!(report.deployment_id, "dep-self-pass");
        assert!(
            !handoff_path.exists(),
            "handoff file must be claimed/removed"
        );
        assert_eq!(
            new_agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::B)
        );

        server_task.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_self_upgrade_post_restart_gate_failure_restores_slot_delivers_report_and_restarts(
    ) {
        use crate::sandbox_it::SandboxedExecutionOutput;

        struct FailingSelfUpgradeExecutor;
        #[async_trait::async_trait]
        impl SandboxedCommandExecutor for FailingSelfUpgradeExecutor {
            async fn execute_in_sandbox(
                &self,
                test: &DiscoveredItTest,
                work_dir: &Path,
                sandbox_cfg: &ItSandboxConfig,
                _service: &str,
                _target_slot: Slot,
                _timeout: Duration,
            ) -> Result<SandboxedExecutionOutput, AgentError> {
                let argv = vec![test.command_path.as_os_str().to_os_string()];
                let (effective_policy, execution_plan) =
                    build_it_sandbox_plan(work_dir, &argv, sandbox_cfg)?;
                Ok(SandboxedExecutionOutput {
                    passed: false,
                    exit_code: Some(1),
                    duration_ms: 15,
                    log_output: "smoke_mu_cd_agent failed check".into(),
                    effective_policy,
                    execution_plan,
                })
            }
        }

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-cd-agent";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        fs::write(srv_dir.join("@a/mu-cd-agent"), b"prev-bin").unwrap();
        fs::write(srv_dir.join("@b/mu-cd-agent"), b"cand-bin").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("@b", srv_dir.join("current")).unwrap();

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_mu_cd_agent","command":"bin/smoke_mu_cd_agent","args":[],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            ("bin/smoke_mu_cd_agent", b"#!/bin/sh\nexit 1\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-self-fail-post".into(),
            lease_id: "lease-self-fail-post".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "d".repeat(40),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec!["smoke_mu_cd_agent".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_mu_cd_agent".into(),
                test_binary: "smoke_mu_cd_agent".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let pending = PendingSelfUpgrade {
            deployment_id: "dep-self-fail-post".into(),
            lease_id: "lease-self-fail-post".into(),
            service_name: service.into(),
            from_slot: "@a".into(),
            to_slot: "@b".into(),
            candidate_sha256: "e".repeat(64),
            systemd_unit: "muconde-agent.service".into(),
            warmup_timeout_secs: 5,
            scenario_plan: Some(SerializableScenarioPlan::from(&plan)),
            deployment_config: None,
            rollback_deployment: None,
            created_epoch_ms: now_epoch_ms(),
        };
        write_pending_self_upgrade_atomic(&pending_self_upgrade_path(&root), &pending).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let runner = Arc::new(MockCommandRunner::new(true));
        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(
            MuConDeAgent::new(
                config,
                runner.clone(),
                Arc::new(MockHealthProber::new(true)),
            )
            .with_it_executor(Arc::new(FailingSelfUpgradeExecutor))
            .with_self_upgrade_failure_window(Duration::from_millis(250)),
        );
        let server_agent = agent.clone();
        let server_task = tokio::spawn(async move {
            let _ = server_agent.run_with_listener(listener).await;
        });

        let fory = create_fory_runtime().unwrap();
        let mut ctrl_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (rep_hdr, rep_payload) =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut ctrl_stream))
                .await
                .expect("timed out waiting for failed self-upgrade report")
                .unwrap();
        assert_eq!(rep_hdr.msg_type, MSG_TYPE_IT_REPORT);
        let report: IntegrationTestReport = fory.deserialize(&rep_payload).unwrap();
        assert!(!report.passed);
        assert_eq!(report.deployment_id, "dep-self-fail-post");
        assert!(report
            .failed_tests
            .contains(&"smoke_mu_cd_agent".to_string()));
        assert_eq!(
            agent.slot_manager.read_active_slot(service).unwrap(),
            Some(Slot::A),
            "post-restart failure must restore @a"
        );

        // Wait for brief delivery window to trigger detached rollback restart
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(
            runner
                .recorded_calls()
                .iter()
                .map(|c| c.join(" "))
                .any(|c| c == "systemctl restart --no-block muconde-agent.service"),
            "expected detached rollback self-restart, got: {:?}",
            runner.recorded_calls()
        );

        server_task.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_controller_disconnect_caches_undelivered_report_for_reconnect() {
        use crate::sandbox_it::SandboxedExecutionOutput;

        struct DelayedPassExecutor;
        #[async_trait::async_trait]
        impl SandboxedCommandExecutor for DelayedPassExecutor {
            async fn execute_in_sandbox(
                &self,
                test: &DiscoveredItTest,
                work_dir: &Path,
                sandbox_cfg: &ItSandboxConfig,
                _service: &str,
                _target_slot: Slot,
                _timeout: Duration,
            ) -> Result<SandboxedExecutionOutput, AgentError> {
                let argv = vec![test.command_path.as_os_str().to_os_string()];
                let (effective_policy, execution_plan) =
                    build_it_sandbox_plan(work_dir, &argv, sandbox_cfg)?;
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(SandboxedExecutionOutput {
                    passed: true,
                    exit_code: Some(0),
                    duration_ms: 20,
                    log_output: "smoke_mu_cd_controller ok".into(),
                    effective_policy,
                    execution_plan,
                })
            }
        }

        let temp = tempdir().unwrap();
        let root = temp.path().join("muconde");
        let cas_dir = temp.path().join("cas");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&cas_dir).unwrap();

        let service = "mu-cd-controller";
        let srv_dir = root.join(service);
        fs::create_dir_all(srv_dir.join("@a")).unwrap();
        fs::create_dir_all(srv_dir.join("@b")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("@a", srv_dir.join("current")).unwrap();

        let (archive, it_digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"smoke_mu_cd_controller","command":"bin/smoke_mu_cd_controller","args":[],"critical":true,"timeout_secs":10}]}"#.as_slice(),
                0o644,
            ),
            ("bin/smoke_mu_cd_controller", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ]);
        write_cas_blob(&cas_dir, &it_digest, &archive);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = MuConDeAgentConfig {
            node_id: "node-a".into(),
            muconde_root: root.clone(),
            default_warmup_timeout_secs: 5,
            required_consecutive_successes: 1,
            cas_blobs_dir: Some(cas_dir),
            ..Default::default()
        };
        let agent = Arc::new(
            MuConDeAgent::new(
                config,
                Arc::new(MockCommandRunner::new(true)),
                Arc::new(MockHealthProber::new(true)),
            )
            .with_it_executor(Arc::new(DelayedPassExecutor)),
        );
        let server_agent = agent.clone();
        let server_task = tokio::spawn(async move {
            let _ = server_agent.run_with_listener(listener).await;
        });

        let fory = create_fory_runtime().unwrap();
        let mut conn1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let plan = ScenarioExecutionPlan {
            deployment_id: "dep-ctrl-self-1".into(),
            lease_id: "lease-ctrl-self-1".into(),
            service_name: service.into(),
            node_id: "node-a".into(),
            policy_commit_sha: "f".repeat(40),
            it_archive_digest: Some(it_digest),
            bundle_id: None,
            selected_tests: vec!["smoke_mu_cd_controller".into()],
            scenarios: vec![ScenarioTestSpec {
                name: "smoke_mu_cd_controller".into(),
                test_binary: "smoke_mu_cd_controller".into(),
                args: Vec::new(),
                env: Vec::new(),
                cidrs: vec!["127.0.0.1/32".into()],
                ro_mounts: Vec::new(),
                critical: true,
                timeout_secs: 10,
            }],
            env: Vec::new(),
            args: Vec::new(),
            cidrs: Vec::new(),
            ro_mounts: Vec::new(),
            max_pids: 256,
            max_memlock_kb: 65_536,
            auto_rollback_on_critical: true,
        };
        let plan_bytes = fory.serialize(&plan).unwrap();
        write_frame(
            &mut conn1,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan_bytes.len() as u32, 0, 1),
            &plan_bytes,
        )
        .await
        .unwrap();
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-ctrl-self-1".into(),
            lease_id: "lease-ctrl-self-1".into(),
            service_name: service.into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "muconde-controller.service".into(),
            warmup_timeout_secs: 5,
        };
        let swap_bytes = fory.serialize(&swap_cmd).unwrap();
        write_frame(
            &mut conn1,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap_bytes.len() as u32, 0, 2),
            &swap_bytes,
        )
        .await
        .unwrap();
        // Read scenario ack then drop connection to simulate mu-cd-controller restarting mid-gate
        let (ack_hdr, _) = read_frame(&mut conn1).await.unwrap();
        assert_eq!(ack_hdr.msg_type, MSG_TYPE_SCENARIO_PLAN_ACK);
        drop(conn1);

        // Wait for delayed test to finish and cache the undelivered report
        tokio::time::sleep(Duration::from_millis(350)).await;

        // Reconnecting restarted controller opens fresh silent stream and receives cached report
        let mut conn2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (rep_hdr, rep_payload) =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut conn2))
                .await
                .expect("timed out waiting for cached report on reconnect")
                .unwrap();
        assert_eq!(rep_hdr.msg_type, MSG_TYPE_IT_REPORT);
        let report: IntegrationTestReport = fory.deserialize(&rep_payload).unwrap();
        assert!(report.passed);
        assert_eq!(report.deployment_id, "dep-ctrl-self-1");

        // Second cycle: restarted controller reconnects EARLY (while delayed gate is STILL running),
        // exercising `undelivered_report_notify` wakeup without deadlock.
        let mut conn3 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut plan2 = plan.clone();
        plan2.deployment_id = "dep-ctrl-self-early".into();
        plan2.lease_id = "lease-ctrl-self-early".into();
        let plan2_bytes = fory.serialize(&plan2).unwrap();
        write_frame(
            &mut conn3,
            &IpcHeader::new(MSG_TYPE_SCENARIO_PLAN, plan2_bytes.len() as u32, 0, 1),
            &plan2_bytes,
        )
        .await
        .unwrap();
        let mut swap2 = swap_cmd.clone();
        swap2.deployment_id = "dep-ctrl-self-early".into();
        swap2.lease_id = "lease-ctrl-self-early".into();
        let swap2_bytes = fory.serialize(&swap2).unwrap();
        write_frame(
            &mut conn3,
            &IpcHeader::new(MSG_TYPE_SLOT_SWAP, swap2_bytes.len() as u32, 0, 2),
            &swap2_bytes,
        )
        .await
        .unwrap();
        let (ack2_hdr, _) = read_frame(&mut conn3).await.unwrap();
        assert_eq!(ack2_hdr.msg_type, MSG_TYPE_SCENARIO_PLAN_ACK);
        drop(conn3);

        // Immediately connect BEFORE DelayedPassExecutor's 200ms sleep completes
        let mut conn4 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (rep2_hdr, rep2_payload) =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut conn4))
                .await
                .expect("timed out waiting for early-reconnect cached report")
                .unwrap();
        assert_eq!(rep2_hdr.msg_type, MSG_TYPE_IT_REPORT);
        let report2: IntegrationTestReport = fory.deserialize(&rep2_payload).unwrap();
        assert!(report2.passed);
        assert_eq!(report2.deployment_id, "dep-ctrl-self-early");

        server_task.abort();
    }
}
