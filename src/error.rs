//! Error types for the MuConDe node deployment agent.

#![deny(unsafe_code)]

use thiserror::Error;

/// Core error type representing any operational failure within MuConDe-agent.
#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Service name '{0}' is invalid: must match ^[a-z0-9-]+$")]
    InvalidServiceName(String),

    #[error("Path traversal attempt detected in service name: '{0}'")]
    PathTraversal(String),

    #[error("Service '{0}' is not in allowed services list")]
    ServiceNotAllowed(String),

    #[error("Command '{command}' failed with exit code {exit_code:?}: {stderr}")]
    CommandFailed {
        command: String,
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IPC error: {0}")]
    Ipc(#[from] mu_cd_ipc::IpcError),

    #[error("Serialization / Fory error: {0}")]
    Serialization(String),

    #[error("Slot error: {0}")]
    Slot(String),

    #[error("Watchdog timeout: deployment '{deployment_id}', service '{service}'")]
    WatchdogTimeout {
        deployment_id: String,
        service: String,
    },

    #[error("Lease TTL expired at {expires_at_epoch_ms} ms (current: {current_epoch_ms} ms)")]
    LeaseExpired {
        expires_at_epoch_ms: u64,
        current_epoch_ms: u64,
    },

    #[error("Health probe failed for '{service}': {reason}")]
    HealthProbeFailed { service: String, reason: String },

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("Unknown or unavailable integration test(s): {0:?}")]
    UnknownIntegrationTests(Vec<String>),

    #[error("Integration test bundle verification or unpack failed: {0}")]
    BundleVerification(String),

    #[error("Kernel sandbox policy or execution violation: {0}")]
    SandboxViolation(String),

    #[error("Manifest or configuration error: {0}")]
    Config(String),
}
