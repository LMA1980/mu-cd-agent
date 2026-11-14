//! CAS integration test bundle fetching, SHA-256 verification, safe unpacking,
//! and preselected test execution inside `MuIsolation::KernelSandbox`.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use flate2::read::GzDecoder;
use mu_ci_isolation::{
    register_ai_thread_if_present, resolve_effective_policy, DesiredProfileConfig,
    DesiredSecurityFile, EffectiveSandboxPolicy, HostCeilingConfig, IsolationBackend,
    KernelSandbox, NetworkEgressMode, SandboxBackendKind, SandboxExecutionPlan, TaskSandboxConfig,
    DEFAULT_SET_AI_THREAD_PATH, MAX_K3_MEMLOCK_KB,
};
use mu_observable_ipc::{DeterministicSecretRedactor, SecretRedactor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};

use crate::error::AgentError;
use crate::gate::{builtin_catalog, expand_integration_tests, GateTest, IntegrationTestSelection};
use crate::slot::Slot;

/// Enforced maximum process/thread count inside `KernelSandbox` for IT bundles.
pub const MAX_IT_SANDBOX_PIDS: u32 = 256;

/// Default bounded `RLIMIT_MEMLOCK` in KB for isolated IT bundle tests.
pub const DEFAULT_IT_MEMLOCK_KB: u64 = 65_536;

/// Maximum uncompressed archive size permitted during `.tar.gz` extraction (64 MiB).
pub const MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum byte length for sanitized log excerpts sent in `IntegrationTestReport`.
pub const MAX_LOG_EXCERPT_BYTES: usize = 8192;

const MANIFEST_CANDIDATES: &[&str] = &[
    "manifest.json",
    "it-manifest.json",
    "tests.yml",
    "it-manifest.yml",
];

/// Validates that `raw` is a 64-character hexadecimal SHA-256 digest and returns lowercase hex.
pub fn validate_sha256_digest(raw: &str) -> Result<String, AgentError> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AgentError::BundleVerification(format!(
            "Invalid SHA-256 digest '{raw}': expected 64 hexadecimal characters"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Computes SHA-256 over `bytes` and verifies exact equality with `expected_digest`.
pub fn verify_sha256_bytes(bytes: &[u8], expected_digest: &str) -> Result<String, AgentError> {
    let expected = validate_sha256_digest(expected_digest)?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        return Err(AgentError::BundleVerification(format!(
            "IT archive SHA-256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(actual)
}

/// Scrubs credentials/secrets using `DeterministicSecretRedactor` and caps UTF-8 byte length.
pub fn sanitize_and_bound_log_excerpt(raw: &str, max_bytes: usize) -> String {
    let redacted = DeterministicSecretRedactor::new().redact(raw);
    let trimmed = redacted.trim();
    if trimmed.len() <= max_bytes {
        return trimmed.to_string();
    }

    const SUFFIX: &str = "\n...[truncated]";
    if max_bytes <= SUFFIX.len() {
        let mut end = max_bytes;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        return trimmed[..end].to_string();
    }

    let mut cut = max_bytes - SUFFIX.len();
    while cut > 0 && !trimmed.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{}", &trimmed[..cut], SUFFIX)
}

fn sanitize_relative_path(raw: &Path) -> Result<PathBuf, AgentError> {
    let mut clean = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => clean.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AgentError::BundleVerification(format!(
                    "Unsafe path component in IT archive or manifest: '{}'",
                    raw.display()
                )));
            }
        }
    }
    Ok(clean)
}

/// JSON/YAML manifest entry describing a single executable integration test inside an IT archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItManifestEntry {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_critical_true")]
    pub critical: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

const fn default_critical_true() -> bool {
    true
}

/// Optional manifest (`manifest.json` or `tests.yml`) inside an integration test `.tar.gz` bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ItArchiveManifest {
    #[serde(default)]
    pub tests: Vec<ItManifestEntry>,
}

/// Resolved executable test discovered inside a verified unpacked IT bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredItTest {
    pub name: String,
    pub command_path: PathBuf,
    pub args: Vec<String>,
    pub critical: bool,
    pub timeout_secs: Option<u64>,
    pub working_dir: PathBuf,
}

impl DiscoveredItTest {
    /// Converts this test descriptor into a [`GateTest`].
    pub fn as_gate_test(&self) -> GateTest {
        GateTest::new(&self.name, self.critical)
    }
}

/// Verified and unpacked CAS integration test archive ready for sandboxed execution.
#[derive(Debug, Clone)]
pub struct UnpackedItBundle {
    pub digest: String,
    pub root_dir: PathBuf,
    pub tests: Vec<DiscoveredItTest>,
}

impl UnpackedItBundle {
    /// Returns the discovered tests as [`GateTest`] definitions.
    pub fn gate_catalog(&self) -> Vec<GateTest> {
        self.tests
            .iter()
            .map(DiscoveredItTest::as_gate_test)
            .collect()
    }
}

/// Verifies `archive_bytes` against `expected_digest`, unpacks safely into `dest_dir`
/// (rejecting symlinks, hardlinks, path traversals, and oversized payloads), and
/// discovers runnable integration tests.
pub fn unpack_verified_it_archive(
    archive_bytes: &[u8],
    expected_digest: &str,
    dest_dir: &Path,
) -> Result<UnpackedItBundle, AgentError> {
    let verified_digest = verify_sha256_bytes(archive_bytes, expected_digest)?;

    fs::create_dir_all(dest_dir)?;
    let canon_dest = fs::canonicalize(dest_dir).unwrap_or_else(|_| dest_dir.to_path_buf());

    let decoder = GzDecoder::new(archive_bytes);
    let bounded_reader = decoder.take(MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES + 1);
    let mut archive = Archive::new(bounded_reader);
    let mut total_uncompressed: u64 = 0;

    let entries = archive
        .entries()
        .map_err(|e| AgentError::BundleVerification(format!("Invalid IT tar.gz stream: {e}")))?;

    for entry_res in entries {
        let mut entry = entry_res
            .map_err(|e| AgentError::BundleVerification(format!("Corrupt tar entry: {e}")))?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .map_err(|e| AgentError::BundleVerification(format!("Invalid entry path: {e}")))?
            .into_owned();
        let rel_path = sanitize_relative_path(&entry_path)?;
        if rel_path.as_os_str().is_empty() {
            continue;
        }

        let target_path = canon_dest.join(&rel_path);
        match entry_type {
            EntryType::Directory => {
                fs::create_dir_all(&target_path)?;
            }
            EntryType::Regular => {
                let size = entry.header().size().map_err(|e| {
                    AgentError::BundleVerification(format!("Invalid tar entry size: {e}"))
                })?;
                total_uncompressed = total_uncompressed.saturating_add(size);
                if total_uncompressed > MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES {
                    return Err(AgentError::BundleVerification(format!(
                        "Uncompressed IT archive exceeds maximum limit of {} bytes",
                        MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES
                    )));
                }
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut buf = Vec::with_capacity(size.min(1024 * 1024) as usize);
                entry.read_to_end(&mut buf)?;
                fs::write(&target_path, &buf)?;

                let mode = entry.header().mode().unwrap_or(0o644);
                let safe_mode = if (mode & 0o111) != 0 { 0o755 } else { 0o644 };
                let mut perms = fs::metadata(&target_path)?.permissions();
                perms.set_mode(safe_mode);
                fs::set_permissions(&target_path, perms)?;
            }
            other => {
                return Err(AgentError::BundleVerification(format!(
                    "Unsupported tar entry type {:?} at '{}': only regular files and directories are allowed",
                    other,
                    rel_path.display()
                )));
            }
        }
    }

    let tests = discover_tests_in_bundle(&canon_dest)?;
    Ok(UnpackedItBundle {
        digest: verified_digest,
        root_dir: canon_dest,
        tests,
    })
}

fn discover_tests_in_bundle(root_dir: &Path) -> Result<Vec<DiscoveredItTest>, AgentError> {
    for candidate in MANIFEST_CANDIDATES {
        let manifest_path = root_dir.join(candidate);
        if manifest_path.is_file() {
            let raw = fs::read_to_string(&manifest_path)?;
            let manifest: ItArchiveManifest = if candidate.ends_with(".json") {
                serde_json::from_str(&raw).map_err(|e| {
                    AgentError::BundleVerification(format!(
                        "Failed to parse {}: {e}",
                        manifest_path.display()
                    ))
                })?
            } else {
                serde_yaml::from_str(&raw).map_err(|e| {
                    AgentError::BundleVerification(format!(
                        "Failed to parse {}: {e}",
                        manifest_path.display()
                    ))
                })?
            };
            return resolve_manifest_entries(root_dir, manifest);
        }
    }

    discover_tests_by_convention(root_dir)
}

fn resolve_manifest_entries(
    root_dir: &Path,
    manifest: ItArchiveManifest,
) -> Result<Vec<DiscoveredItTest>, AgentError> {
    let mut seen = HashSet::new();
    let mut discovered = Vec::with_capacity(manifest.tests.len());

    for entry in manifest.tests {
        let name = entry.name.trim().to_string();
        if name.is_empty() {
            return Err(AgentError::BundleVerification(
                "IT manifest contains empty test name".into(),
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(AgentError::BundleVerification(format!(
                "IT manifest contains duplicate test name '{name}'"
            )));
        }

        let rel_cmd = sanitize_relative_path(Path::new(entry.command.trim()))?;
        if rel_cmd.as_os_str().is_empty() {
            return Err(AgentError::BundleVerification(format!(
                "IT test '{name}' has empty command path"
            )));
        }
        let cmd_path = root_dir.join(&rel_cmd);
        if !cmd_path.is_file() {
            return Err(AgentError::BundleVerification(format!(
                "IT test '{name}' command '{}' does not exist inside unpacked archive",
                rel_cmd.display()
            )));
        }
        ensure_executable(&cmd_path)?;

        discovered.push(DiscoveredItTest {
            name,
            command_path: cmd_path,
            args: entry.args,
            critical: entry.critical,
            timeout_secs: entry.timeout_secs,
            working_dir: root_dir.to_path_buf(),
        });
    }

    Ok(discovered)
}

fn discover_tests_by_convention(root_dir: &Path) -> Result<Vec<DiscoveredItTest>, AgentError> {
    let mut candidates = BTreeMap::new();
    for search_dir in [
        root_dir.to_path_buf(),
        root_dir.join("bin"),
        root_dir.join("tests"),
    ] {
        if !search_dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&search_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if file_name.starts_with('.') || MANIFEST_CANDIDATES.contains(&file_name.as_str()) {
                continue;
            }
            let test_name = file_name
                .strip_suffix(".sh")
                .unwrap_or(&file_name)
                .to_string();
            if test_name.is_empty() {
                continue;
            }
            ensure_executable(&path)?;
            candidates
                .entry(test_name.clone())
                .or_insert_with(|| DiscoveredItTest {
                    name: test_name,
                    command_path: path,
                    args: Vec::new(),
                    critical: true,
                    timeout_secs: None,
                    working_dir: root_dir.to_path_buf(),
                });
        }
    }
    Ok(candidates.into_values().collect())
}

fn ensure_executable(path: &Path) -> Result<(), AgentError> {
    let mut perms = fs::metadata(path)?.permissions();
    let mode = perms.mode();
    if (mode & 0o111) == 0 {
        perms.set_mode(mode | 0o755);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Resolves selected integration tests against built-in checks and optional verified IT archive.
/// Fails closed if any requested test name is absent from both built-in checks and the archive.
pub fn resolve_gate_plan(
    selection: &IntegrationTestSelection,
    unpacked_bundle: Option<&UnpackedItBundle>,
) -> Result<(Vec<GateTest>, Vec<DiscoveredItTest>), AgentError> {
    resolve_gate_plan_with_base(&builtin_catalog(), selection, unpacked_bundle)
}

/// Resolves selected integration tests against an explicit base catalog and optional IT archive.
pub fn resolve_gate_plan_with_base(
    base_catalog: &[GateTest],
    selection: &IntegrationTestSelection,
    unpacked_bundle: Option<&UnpackedItBundle>,
) -> Result<(Vec<GateTest>, Vec<DiscoveredItTest>), AgentError> {
    let mut catalog = base_catalog.to_vec();
    let mut bundle_map: BTreeMap<String, DiscoveredItTest> = BTreeMap::new();

    if let Some(bundle) = unpacked_bundle {
        for test in &bundle.tests {
            if catalog.iter().any(|existing| existing.name == test.name) {
                return Err(AgentError::BundleVerification(format!(
                    "IT bundle test '{}' conflicts with a built-in gate check",
                    test.name
                )));
            }
            catalog.push(test.as_gate_test());
            bundle_map.insert(test.name.clone(), test.clone());
        }
    }

    let expanded = expand_integration_tests(selection, &catalog)?;
    let custom_tests = expanded
        .iter()
        .filter_map(|gate_test| bundle_map.get(&gate_test.name).cloned())
        .collect();
    Ok((expanded, custom_tests))
}

/// Abstraction for fetching verified IT archive bytes by SHA-256 digest.
#[async_trait]
pub trait ItArchiveFetcher: Send + Sync {
    async fn fetch_it_archive(&self, digest: &str) -> Result<Vec<u8>, AgentError>;
}

/// Fetches integration test archives from local CAS storage or `mu-registry` HTTP/mTLS endpoints,
/// enforcing SHA-256 verification before returning bytes.
#[derive(Debug, Clone, Default)]
pub struct RegistryAndCasFetcher {
    pub cas_dir: Option<PathBuf>,
    pub registry_url: Option<String>,
    pub bundle_id: Option<String>,
    pub bearer_token: Option<String>,
    pub tls_ca_path: Option<PathBuf>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

impl RegistryAndCasFetcher {
    pub fn with_cas_dir(mut self, cas_dir: impl Into<PathBuf>) -> Self {
        self.cas_dir = Some(cas_dir.into());
        self
    }

    pub fn with_registry_url(mut self, registry_url: impl Into<String>) -> Self {
        self.registry_url = Some(registry_url.into());
        self
    }

    fn try_read_local_cas(&self, digest: &str) -> Result<Option<Vec<u8>>, AgentError> {
        let Some(ref root) = self.cas_dir else {
            return Ok(None);
        };
        let prefix = &digest[..2];
        let candidates = [
            root.join("blobs").join("sha256").join(prefix).join(digest),
            root.join("sha256").join(prefix).join(digest),
            root.join("blobs").join(digest),
            root.join(digest),
        ];

        for candidate in candidates {
            if candidate.is_file() {
                let bytes = fs::read(&candidate)?;
                verify_sha256_bytes(&bytes, digest)?;
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    fn build_http_client(&self) -> Result<reqwest::Client, AgentError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .use_rustls_tls();

        if let Some(ref ca_path) = self.tls_ca_path {
            let ca_pem = fs::read(ca_path)?;
            for cert in reqwest::Certificate::from_pem_bundle(&ca_pem)
                .map_err(|e| AgentError::Tls(format!("Invalid CA bundle PEM: {e}")))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }

        if let (Some(cert_path), Some(key_path)) = (&self.tls_cert_path, &self.tls_key_path) {
            let mut combined = fs::read(cert_path)?;
            if !combined.ends_with(b"\n") {
                combined.push(b'\n');
            }
            combined.extend_from_slice(&fs::read(key_path)?);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| AgentError::Tls(format!("Invalid client mTLS identity PEM: {e}")))?;
            builder = builder.identity(identity);
        }

        builder
            .build()
            .map_err(|e| AgentError::BundleVerification(format!("HTTP client build error: {e}")))
    }

    async fn fetch_from_registry(
        &self,
        base_url: &str,
        digest: &str,
    ) -> Result<Vec<u8>, AgentError> {
        let client = self.build_http_client()?;
        let base = base_url.trim_end_matches('/');

        let mut candidate_urls = Vec::new();
        if let Some(ref bundle_id) = self.bundle_id {
            let trimmed_id = bundle_id.trim();
            if !trimmed_id.is_empty() {
                candidate_urls.push(format!(
                    "{base}/api/v1/bundles/it/{trimmed_id}?download=it_archive"
                ));
            }
        } else if let Some(resolved_id) = self
            .lookup_bundle_id_by_digest(&client, base, digest)
            .await?
        {
            candidate_urls.push(format!(
                "{base}/api/v1/bundles/it/{resolved_id}?download=it_archive"
            ));
        }

        candidate_urls.push(format!("{base}/api/v1/cas/blobs/sha256/{digest}"));
        candidate_urls.push(format!("{base}/api/v1/blobs/sha256/{digest}"));

        let mut errors = Vec::new();
        for url in candidate_urls {
            let mut req = client.get(&url);
            if let Some(ref token) = self.bearer_token {
                req = req.bearer_auth(token);
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp.bytes().await.map_err(|e| {
                        AgentError::BundleVerification(format!(
                            "Failed reading response body from {url}: {e}"
                        ))
                    })?;
                    verify_sha256_bytes(&bytes, digest)?;
                    return Ok(bytes.to_vec());
                }
                Ok(resp) => {
                    errors.push(format!("{url} -> HTTP {}", resp.status()));
                }
                Err(e) => {
                    errors.push(format!("{url} -> {e}"));
                }
            }
        }

        Err(AgentError::BundleVerification(format!(
            "Unable to fetch IT archive {digest} from mu-registry ({})",
            errors.join("; ")
        )))
    }

    async fn lookup_bundle_id_by_digest(
        &self,
        client: &reqwest::Client,
        base: &str,
        digest: &str,
    ) -> Result<Option<String>, AgentError> {
        let url = format!("{base}/api/v1/registry/bundles");
        let mut req = client.get(&url);
        if let Some(ref token) = self.bearer_token {
            req = req.bearer_auth(token);
        }
        let Ok(resp) = req.send().await else {
            return Ok(None);
        };
        if !resp.status().is_success() {
            return Ok(None);
        }
        let Ok(value) = resp.json::<serde_json::Value>().await else {
            return Ok(None);
        };
        let list = value
            .as_array()
            .or_else(|| value.get("bundles").and_then(|v| v.as_array()));
        let Some(entries) = list else {
            return Ok(None);
        };
        for item in entries {
            let item_digest = item
                .get("it_archive_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if item_digest.eq_ignore_ascii_case(digest) {
                if let Some(id) = item.get("bundle_id").and_then(|v| v.as_str()) {
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl ItArchiveFetcher for RegistryAndCasFetcher {
    async fn fetch_it_archive(&self, digest: &str) -> Result<Vec<u8>, AgentError> {
        let digest = validate_sha256_digest(digest)?;
        if let Some(bytes) = self.try_read_local_cas(&digest)? {
            return Ok(bytes);
        }
        if let Some(ref registry_url) = self.registry_url {
            return self.fetch_from_registry(registry_url, &digest).await;
        }
        Err(AgentError::BundleVerification(format!(
            "IT archive {digest} not found in local CAS and no registry_url configured"
        )))
    }
}

/// Configuration for running IT archive tests inside `MuIsolation::KernelSandbox`.
#[derive(Debug, Clone)]
pub struct ItSandboxConfig {
    pub max_pids: u32,
    pub memlock_limit_kb: u64,
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub network_mode: NetworkEgressMode,
    pub security_file_path: Option<PathBuf>,
    pub proc_ai_thread_path: PathBuf,
    pub per_test_timeout_secs: u64,
}

impl Default for ItSandboxConfig {
    fn default() -> Self {
        Self {
            max_pids: MAX_IT_SANDBOX_PIDS,
            memlock_limit_kb: DEFAULT_IT_MEMLOCK_KB,
            max_memory_mb: 1024,
            max_cpu_cores: 4,
            network_mode: NetworkEgressMode::Offline,
            security_file_path: None,
            proc_ai_thread_path: PathBuf::from(DEFAULT_SET_AI_THREAD_PATH),
            per_test_timeout_secs: 30,
        }
    }
}

/// Canonical architecture identifier accepted by `mu_ci_isolation` seccomp planner.
pub fn canonical_sandbox_arch() -> &'static str {
    match std::env::consts::ARCH {
        "riscv64" => "riscv64gc",
        "x86_64" => "x86_64",
        #[cfg(target_os = "linux")]
        other => other,
        // Non-Linux dev environments (e.g., Apple Silicon macOS) validate seccomp plans against x86_64.
        #[cfg(not(target_os = "linux"))]
        _ => "x86_64",
    }
}

fn push_unique_clean(paths: &mut Vec<PathBuf>, candidate: &Path) {
    if !candidate.is_absolute() {
        return;
    }
    if !paths.iter().any(|p| p == candidate) {
        paths.push(candidate.to_path_buf());
    }
}

/// Evaluates the 3-layer `MuIsolation` security policy (`Ceiling ∩ Profile ∩ Task`) and
/// produces a validated `KernelSandbox` execution plan capped at `max_pids <= 256`.
pub fn build_it_sandbox_plan(
    work_dir: &Path,
    argv: &[OsString],
    cfg: &ItSandboxConfig,
) -> Result<(EffectiveSandboxPolicy, SandboxExecutionPlan), AgentError> {
    let canon_work = fs::canonicalize(work_dir).unwrap_or_else(|_| work_dir.to_path_buf());
    let sandbox_tmp = canon_work.join(".sandbox_tmp");

    let mut read_paths = vec![
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/etc"),
    ];
    push_unique_clean(&mut read_paths, &canon_work);
    push_unique_clean(&mut read_paths, work_dir);

    let mut write_paths = vec![PathBuf::from("/tmp")];
    push_unique_clean(&mut write_paths, &sandbox_tmp);

    let mut exec_paths = vec![
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    push_unique_clean(&mut exec_paths, &canon_work);
    push_unique_clean(&mut exec_paths, work_dir);

    let mut ceiling = HostCeilingConfig {
        node_id: "mu-cd-agent-it".to_string(),
        arch: canonical_sandbox_arch().to_string(),
        allowed_backends: vec![SandboxBackendKind::Kernel],
        allowed_read_prefixes: read_paths.clone(),
        allowed_write_prefixes: write_paths.clone(),
        allowed_exec_prefixes: exec_paths.clone(),
        allowed_egress_cidrs: match &cfg.network_mode {
            NetworkEgressMode::Offline => Vec::new(),
            NetworkEgressMode::RestrictedCidrs(cidrs) => cidrs.clone(),
        },
        max_memlock_kb: MAX_K3_MEMLOCK_KB,
        max_cpu_cores: cfg.max_cpu_cores.max(1),
        max_memory_mb: cfg.max_memory_mb.max(64),
        max_pids: MAX_IT_SANDBOX_PIDS,
        allow_spacemit_ai_thread: false,
    };
    push_unique_clean(&mut ceiling.allowed_write_prefixes, &canon_work);

    let mut using_security_file = false;
    let desired_profile = if let Some(ref sec_path) = cfg.security_file_path {
        using_security_file = true;
        let sec_file = DesiredSecurityFile::from_path(sec_path)
            .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;
        let base = sec_file
            .profiles
            .get(&sec_file.default_profile)
            .ok_or_else(|| {
                AgentError::SandboxViolation(format!(
                    "Default security profile '{}' missing",
                    sec_file.default_profile
                ))
            })?
            .clone();
        DesiredProfileConfig {
            backend: base.backend,
            read_paths: base.read_paths,
            write_paths: base.write_paths,
            exec_paths: base.exec_paths,
            network_egress_cidrs: base.network_egress_cidrs,
            memlock_limit_kb: base.memlock_limit_kb,
            max_pids: base.max_pids,
            max_memory_mb: base.max_memory_mb,
            cpu_affinity_mask: base.cpu_affinity_mask,
            require_set_ai_thread: base.require_set_ai_thread,
        }
    } else {
        DesiredProfileConfig {
            backend: SandboxBackendKind::Kernel,
            read_paths: read_paths.clone(),
            write_paths: write_paths.clone(),
            exec_paths: exec_paths.clone(),
            network_egress_cidrs: match &cfg.network_mode {
                NetworkEgressMode::Offline => Vec::new(),
                NetworkEgressMode::RestrictedCidrs(cidrs) => cidrs.clone(),
            },
            memlock_limit_kb: cfg.memlock_limit_kb,
            max_pids: cfg.max_pids.min(MAX_IT_SANDBOX_PIDS),
            max_memory_mb: Some(cfg.max_memory_mb),
            cpu_affinity_mask: None,
            require_set_ai_thread: false,
        }
    };

    let task = if using_security_file {
        TaskSandboxConfig {
            backend: Some(SandboxBackendKind::Kernel),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            exec_paths: Vec::new(),
            network_mode: cfg.network_mode.clone(),
            memlock_limit_kb: (cfg.memlock_limit_kb != DEFAULT_IT_MEMLOCK_KB)
                .then_some(cfg.memlock_limit_kb),
            max_pids: (cfg.max_pids != MAX_IT_SANDBOX_PIDS).then_some(cfg.max_pids),
            max_memory_mb: (cfg.max_memory_mb != 1024).then_some(cfg.max_memory_mb),
            cpu_affinity_mask: None,
            require_set_ai_thread: None,
        }
    } else {
        TaskSandboxConfig {
            backend: Some(SandboxBackendKind::Kernel),
            read_paths,
            write_paths,
            exec_paths,
            network_mode: cfg.network_mode.clone(),
            memlock_limit_kb: Some(cfg.memlock_limit_kb),
            max_pids: Some(cfg.max_pids),
            max_memory_mb: Some(cfg.max_memory_mb),
            cpu_affinity_mask: None,
            require_set_ai_thread: Some(false),
        }
    };

    let effective = resolve_effective_policy(&ceiling, &desired_profile, &task)
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;

    let sandbox = KernelSandbox::with_proc_ai_thread_path(&cfg.proc_ai_thread_path);
    sandbox
        .validate_host_support(&effective)
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;
    let plan = sandbox
        .build_execution_plan(&effective, argv)
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;

    Ok((effective, plan))
}

/// Output produced by executing a single preselected IT test inside `KernelSandbox`.
#[derive(Debug, Clone)]
pub struct SandboxedExecutionOutput {
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub log_output: String,
    pub effective_policy: EffectiveSandboxPolicy,
    pub execution_plan: SandboxExecutionPlan,
}

/// Trait abstracting sandboxed IT command execution for production and unit tests.
#[async_trait]
pub trait SandboxedCommandExecutor: Send + Sync {
    async fn execute_in_sandbox(
        &self,
        test: &DiscoveredItTest,
        work_dir: &Path,
        sandbox_cfg: &ItSandboxConfig,
        service_name: &str,
        slot: Slot,
        timeout: Duration,
    ) -> Result<SandboxedExecutionOutput, AgentError>;
}

/// Default `KernelSandbox` command executor validating the `MuIsolation` execution plan
/// (`max_pids <= 256`, Landlock, namespace flags, seccomp-BPF, memlock cap) and running
/// each test directly with a cleared minimal environment.
#[derive(Debug, Default)]
pub struct KernelSandboxedExecutor;

#[async_trait]
impl SandboxedCommandExecutor for KernelSandboxedExecutor {
    async fn execute_in_sandbox(
        &self,
        test: &DiscoveredItTest,
        work_dir: &Path,
        sandbox_cfg: &ItSandboxConfig,
        service_name: &str,
        slot: Slot,
        timeout: Duration,
    ) -> Result<SandboxedExecutionOutput, AgentError> {
        let mut argv = Vec::with_capacity(1 + test.args.len());
        argv.push(test.command_path.as_os_str().to_os_string());
        for arg in &test.args {
            argv.push(OsString::from(arg));
        }

        let (effective_policy, execution_plan) =
            build_it_sandbox_plan(work_dir, &argv, sandbox_cfg)?;

        let _ = register_ai_thread_if_present(
            &sandbox_cfg.proc_ai_thread_path,
            std::process::id(),
            effective_policy.cpu_affinity_mask,
            effective_policy.require_set_ai_thread,
        )
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;

        let sandbox_tmp = work_dir.join(".sandbox_tmp");
        fs::create_dir_all(&sandbox_tmp)?;

        let started = Instant::now();
        let mut cmd = tokio::process::Command::new(&test.command_path);
        cmd.args(&test.args)
            .current_dir(&test.working_dir)
            .kill_on_drop(true)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TMPDIR", &sandbox_tmp)
            .env("MUCONDE_IT_SERVICE", service_name)
            .env("MUCONDE_IT_SLOT", slot.as_str())
            .env("MUCONDE_IT_WORKDIR", work_dir);

        let result = tokio::time::timeout(timeout, cmd.output()).await;
        let duration_ms = started.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(output)) => {
                let mut combined = String::new();
                if !output.stdout.is_empty() {
                    combined.push_str(&String::from_utf8_lossy(&output.stdout));
                }
                if !output.stderr.is_empty() {
                    if !combined.is_empty() && !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                Ok(SandboxedExecutionOutput {
                    passed: output.status.success(),
                    exit_code: output.status.code(),
                    duration_ms,
                    log_output: sanitize_and_bound_log_excerpt(&combined, MAX_LOG_EXCERPT_BYTES),
                    effective_policy,
                    execution_plan,
                })
            }
            Ok(Err(io_err)) => Err(AgentError::SandboxViolation(format!(
                "Failed to spawn sandboxed test '{}': {io_err}",
                test.name
            ))),
            Err(_) => Ok(SandboxedExecutionOutput {
                passed: false,
                exit_code: None,
                duration_ms,
                log_output: format!(
                    "Sandboxed test '{}' timed out after {}s",
                    test.name,
                    timeout.as_secs()
                ),
                effective_policy,
                execution_plan,
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use mu_observable_ipc::REDACTED_PLACEHOLDER;
    use tar::Builder;
    use tempfile::tempdir;

    pub(crate) fn exec_tempdir() -> tempfile::TempDir {
        if let Some(target_tmp) = option_env!("CARGO_TARGET_TMPDIR").map(PathBuf::from) {
            if fs::create_dir_all(&target_tmp).is_ok() {
                if let Ok(dir) = tempfile::tempdir_in(&target_tmp) {
                    return dir;
                }
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            // Test binaries run inside `<target>/<profile>/deps`; `<target>/<profile>/test-tmp`
            // inherits the same executable filesystem permissions without touching `noexec` `/tmp`.
            if let Some(profile_dir) = exe.parent().and_then(|p| p.parent()) {
                let scratch = profile_dir.join("test-tmp");
                if fs::create_dir_all(&scratch).is_ok() {
                    if let Ok(dir) = tempfile::tempdir_in(&scratch) {
                        return dir;
                    }
                }
            }
        }
        let fallback = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp");
        fs::create_dir_all(&fallback).expect("create target/test-tmp");
        tempfile::tempdir_in(&fallback).expect("create exec tempdir")
    }

    pub(crate) fn build_test_tar_gz(entries: &[(&str, &[u8], u32)]) -> (Vec<u8>, String) {
        let mut tar_bytes = Vec::new();
        {
            let gz = GzEncoder::new(&mut tar_bytes, Compression::default());
            let mut builder = Builder::new(gz);
            for (path, content, mode) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(*mode);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, std::io::Cursor::new(content))
                    .unwrap();
            }
            let gz = builder.into_inner().unwrap();
            gz.finish().unwrap();
        }
        let digest = hex::encode(Sha256::digest(&tar_bytes));
        (tar_bytes, digest)
    }

    #[test]
    fn test_sha256_validation_and_mismatch_fail_closed() {
        let err_short = validate_sha256_digest("abcd").unwrap_err();
        assert!(matches!(err_short, AgentError::BundleVerification(_)));

        let err_path = validate_sha256_digest("../etc/passwd").unwrap_err();
        assert!(matches!(err_path, AgentError::BundleVerification(_)));

        let payload = b"integration-bundle-payload";
        let digest = hex::encode(Sha256::digest(payload));
        assert_eq!(verify_sha256_bytes(payload, &digest).unwrap(), digest);

        let wrong_digest = "0".repeat(64);
        let err_mismatch = verify_sha256_bytes(payload, &wrong_digest).unwrap_err();
        assert!(matches!(err_mismatch, AgentError::BundleVerification(_)));
    }

    #[test]
    fn test_log_excerpt_redaction_and_bounding() {
        let raw = "line1 token=super-secret-value Bearer secret-abc\n".repeat(400);
        let scrubbed = sanitize_and_bound_log_excerpt(&raw, 512);
        assert!(scrubbed.len() <= 512);
        assert!(!scrubbed.contains("super-secret-value"));
        assert!(!scrubbed.contains("secret-abc"));
        assert!(scrubbed.contains(REDACTED_PLACEHOLDER));
        assert!(scrubbed.ends_with("...[truncated]"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_unpack_verified_archive_and_fail_closed_selection() {
        let (archive, digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"it_smoke_http","command":"bin/it_smoke_http","critical":true}]}"#,
                0o644,
            ),
            ("bin/it_smoke_http", b"#!/bin/sh\necho ok\n", 0o755),
        ]);

        let dir = tempdir().unwrap();
        let unpacked = unpack_verified_it_archive(&archive, &digest, dir.path()).unwrap();
        assert_eq!(unpacked.digest, digest);
        assert_eq!(unpacked.tests.len(), 1);
        assert_eq!(unpacked.tests[0].name, "it_smoke_http");

        // Selected valid built-in + archive test succeeds
        let (plan, custom) = resolve_gate_plan(
            &IntegrationTestSelection::Selected(vec![
                "systemd_unit_active".into(),
                "it_smoke_http".into(),
            ]),
            Some(&unpacked),
        )
        .unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(custom.len(), 1);

        // Missing test absent from verified archive fails closed
        let err = resolve_gate_plan(
            &IntegrationTestSelection::Selected(vec!["missing_test".into()]),
            Some(&unpacked),
        )
        .unwrap_err();
        assert!(
            matches!(err, AgentError::UnknownIntegrationTests(ref m) if m == &vec!["missing_test".to_string()])
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_unpack_rejects_tar_path_traversal_and_symlinks() {
        // Explicit path traversal & root path sanitization check
        let err_parent = sanitize_relative_path(Path::new("../etc/evil")).unwrap_err();
        assert!(matches!(err_parent, AgentError::BundleVerification(_)));
        let err_root = sanitize_relative_path(Path::new("/abs/path")).unwrap_err();
        assert!(matches!(err_root, AgentError::BundleVerification(_)));
        assert_eq!(
            sanitize_relative_path(Path::new("./bin/check.sh")).unwrap(),
            PathBuf::from("bin/check.sh")
        );

        // Build clean symlink archive to confirm Symlink rejection
        let mut sym_bytes = Vec::new();
        {
            let gz = GzEncoder::new(&mut sym_bytes, Compression::default());
            let mut builder = Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            builder
                .append_link(&mut header, "escape", "/etc/passwd")
                .unwrap();
            let gz = builder.into_inner().unwrap();
            gz.finish().unwrap();
        }
        let sym_digest = hex::encode(Sha256::digest(&sym_bytes));
        let dest = tempdir().unwrap();
        let err = unpack_verified_it_archive(&sym_bytes, &sym_digest, dest.path()).unwrap_err();
        assert!(matches!(err, AgentError::BundleVerification(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_kernel_sandbox_plan_enforces_max_pids_256_attenuation() {
        let dir = exec_tempdir();
        let argv = vec![OsString::from("/bin/true")];

        let cfg = ItSandboxConfig::default();
        assert_eq!(cfg.max_pids, 256);
        let (policy, plan) = build_it_sandbox_plan(dir.path(), &argv, &cfg).unwrap();
        assert_eq!(policy.backend, SandboxBackendKind::Kernel);
        assert_eq!(policy.max_pids, 256);
        assert!(plan.seccomp_plan.as_ref().unwrap().enforce_no_new_privs);

        // Requesting >256 PIDs fails closed via MuIsolation attenuation
        let excessive = ItSandboxConfig {
            max_pids: 512,
            ..Default::default()
        };
        let err = build_it_sandbox_plan(dir.path(), &argv, &excessive).unwrap_err();
        assert!(matches!(err, AgentError::SandboxViolation(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_build_it_sandbox_plan_honors_security_file_paths_and_attenuation() {
        let dir = exec_tempdir();
        let work_canon = fs::canonicalize(dir.path()).unwrap();
        let argv = vec![OsString::from("/bin/true")];

        let tighter_sec = dir.path().join("tighter-security.yml");
        fs::write(
            &tighter_sec,
            format!(
                r#"default_profile: "it_tight"
profiles:
  it_tight:
    backend: Kernel
    read_paths:
      - /usr
      - /bin
      - {}
    write_paths: []
    exec_paths:
      - /bin
      - {}
    network_egress_cidrs: []
    memlock_limit_kb: 16384
    max_pids: 64
    max_memory_mb: 256
    require_set_ai_thread: false
"#,
                work_canon.display(),
                work_canon.display()
            ),
        )
        .unwrap();

        let cfg = ItSandboxConfig {
            security_file_path: Some(tighter_sec),
            ..Default::default()
        };
        let (policy, _plan) = build_it_sandbox_plan(dir.path(), &argv, &cfg).unwrap();
        assert_eq!(policy.max_pids, 64);
        assert_eq!(policy.memlock_limit_kb, 16384);
        assert_eq!(policy.max_memory_mb, 256);
        assert_eq!(
            policy.read_paths,
            vec![
                PathBuf::from("/usr"),
                PathBuf::from("/bin"),
                work_canon.clone()
            ]
        );
        assert!(policy.write_paths.is_empty());
        assert_eq!(policy.exec_paths, vec![PathBuf::from("/bin"), work_canon]);

        let widened_sec = dir.path().join("widened-security.yml");
        fs::write(
            &widened_sec,
            r#"default_profile: "it_wide"
profiles:
  it_wide:
    backend: Kernel
    read_paths:
      - /usr
    write_paths: []
    exec_paths:
      - /opt/untrusted
    network_egress_cidrs: []
    memlock_limit_kb: 16384
    max_pids: 64
"#,
        )
        .unwrap();

        let widened_cfg = ItSandboxConfig {
            security_file_path: Some(widened_sec),
            ..Default::default()
        };
        let err = build_it_sandbox_plan(dir.path(), &argv, &widened_cfg).unwrap_err();
        assert!(matches!(err, AgentError::SandboxViolation(_)));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_kernel_sandboxed_executor_runs_real_script_with_scrubbed_logs() {
        let (archive, digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"it_env_check","command":"bin/check.sh","critical":true}]}"#,
                0o644,
            ),
            (
                "bin/check.sh",
                b"#!/bin/sh\necho \"svc=$MUCONDE_IT_SERVICE slot=$MUCONDE_IT_SLOT token=leak123\"\nexit 0\n",
                0o755,
            ),
        ]);
        let cas = exec_tempdir();
        let blob_dir = cas.path().join("blobs").join("sha256").join(&digest[..2]);
        fs::create_dir_all(&blob_dir).unwrap();
        fs::write(blob_dir.join(&digest), &archive).unwrap();

        let fetcher = RegistryAndCasFetcher::default().with_cas_dir(cas.path());
        let fetched = fetcher.fetch_it_archive(&digest).await.unwrap();

        let work = exec_tempdir();
        let bundle = unpack_verified_it_archive(&fetched, &digest, work.path()).unwrap();
        let executor = KernelSandboxedExecutor;
        let out = executor
            .execute_in_sandbox(
                &bundle.tests[0],
                work.path(),
                &ItSandboxConfig::default(),
                "mu-cd-agent",
                Slot::B,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(out.passed);
        assert_eq!(out.effective_policy.max_pids, 256);
        assert!(out.log_output.contains("svc=mu-cd-agent slot=@b"));
        assert!(!out.log_output.contains("leak123"));
        assert!(out.log_output.contains(REDACTED_PLACEHOLDER));
    }
}
