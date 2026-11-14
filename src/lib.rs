//! mu-cd-agent: Node-level continuous delivery daemon executing atomic
//! filesystem operations, dual A/B root subvolume switching, health probes,
//! and autonomous watchdog rollbacks.

#![deny(unsafe_code)]

pub mod agent;
pub mod btrfs;
pub mod error;
pub mod gate;
pub mod manifest;
pub mod sandbox_it;
pub mod slot;
pub mod telemetry;
pub mod watchdog;

pub use agent::{build_tls_server_config, send_it_progress, MuConDeAgent, MuConDeAgentConfig};
pub use btrfs::{
    validate_service_name, BtrfsManager, CommandOutput, CommandRunner, MockCommandRunner,
    PreparedStaging, SystemCommandRunner, ALLOWED_SERVICES,
};
pub use error::AgentError;
pub use gate::{
    builtin_catalog, expand_integration_tests, GateTest, GateTracker, IntegrationTestSelection,
    TEST_HEALTH_ENDPOINT_READY, TEST_SYSTEMD_UNIT_ACTIVE,
};
pub use manifest::{AbRulesConfig, MuCdManifest, RawIntegrationTestsField, DEFAULT_KEEP_SNAPSHOTS};
pub use sandbox_it::{
    build_it_sandbox_plan, canonical_sandbox_arch, resolve_gate_plan, resolve_gate_plan_with_base,
    sanitize_and_bound_log_excerpt, unpack_verified_it_archive, validate_sha256_digest,
    verify_sha256_bytes, DiscoveredItTest, ItArchiveFetcher, ItArchiveManifest, ItManifestEntry,
    ItSandboxConfig, KernelSandboxedExecutor, RegistryAndCasFetcher, SandboxedCommandExecutor,
    SandboxedExecutionOutput, UnpackedItBundle, DEFAULT_IT_MEMLOCK_KB,
    MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES, MAX_IT_SANDBOX_PIDS, MAX_LOG_EXCERPT_BYTES,
};
pub use slot::{Slot, SlotManager, SwapReceipt};
pub use telemetry::{
    now_unix_nano, trace_context_for_deployment, MuObserveCollectorSink, RecordingTelemetrySink,
    TelemetrySink, AGENT_SERVICE_NAME, DEFAULT_COLLECTOR_ADDR,
};
pub use watchdog::{
    now_epoch_ms, HealthProber, MockHealthProber, ProbeResult, SystemHealthProber, WatchdogMonitor,
    WatchdogOutcome,
};

/// Returns the compiled crate version.
pub fn agent_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
