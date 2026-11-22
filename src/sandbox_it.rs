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
    normalize_clean_path, register_ai_thread_if_present, resolve_effective_policy,
    DesiredProfileConfig, DesiredSecurityFile, EffectiveSandboxPolicy, HostCeilingConfig,
    IsolationBackend, KernelSandbox, NetworkEgressMode, SandboxBackendKind, SandboxExecutionPlan,
    TaskSandboxConfig, DEFAULT_SET_AI_THREAD_PATH, MAX_K3_MEMLOCK_KB, READ_ACCESS,
};
use mu_observable_ipc::{DeterministicSecretRedactor, SecretRedactor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};

use crate::error::AgentError;
use crate::gate::{builtin_catalog, expand_integration_tests, GateTest, IntegrationTestSelection};
use crate::slot::Slot;

/// Default Layer 1 host ceiling configuration path loaded in production.
pub const DEFAULT_HOST_CEILING_PATH: &str = "/etc/mu-isolation/ceiling.yml";

/// Default Layer 2 CD canary profile path loaded in production when present.
pub const DEFAULT_CANARY_PROFILE_PATH: &str = "/etc/mu-isolation/cd-canary-profile.yml";

/// Maximum permitted scenario CLI arguments.
pub const MAX_SCENARIO_ARGS: usize = 32;

/// Maximum permitted UTF-8 byte length of a single scenario CLI argument.
pub const MAX_SCENARIO_ARG_BYTES: usize = 4096;

/// Exhaustive allowlist of scenario environment variables injected into sandboxed test processes.
pub const ALLOWED_SCENARIO_ENV_KEYS: &[&str] = &[
    "MU_SMOKE_TARGET_URL",
    "MU_SMOKE_TARGET_ADDR",
    "MU_SMOKE_TLS_CA_FILE",
    "MU_SMOKE_TLS_CERT_FILE",
    "MU_SMOKE_TLS_KEY_FILE",
    "MU_SMOKE_BEARER_TOKEN_FILE",
    "MU_SMOKE_TIMEOUT_SECS",
    "RUST_BACKTRACE",
    "RUST_LOG",
];

const FILE_MOUNT_ENV_KEYS: &[&str] = &[
    "MU_SMOKE_TLS_CA_FILE",
    "MU_SMOKE_TLS_CERT_FILE",
    "MU_SMOKE_TLS_KEY_FILE",
    "MU_SMOKE_BEARER_TOKEN_FILE",
];

const BASELINE_RUNTIME_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/lib",
    "/lib64",
    "/etc/ssl",
    "/etc/hosts",
    "/etc/resolv.conf",
];

const DEFAULT_CANARY_READ_PREFIXES: &[&str] =
    &["/etc/mu-cd-canary/tls", "/etc/mu-cd-canary/tokens"];

const SENSITIVE_ETC_WRITE_PREFIXES: &[&str] = &[
    "/etc/mu-cd-canary",
    "/etc/step-ca",
    "/etc/muconde",
    "/etc/mu-cd",
    "/etc/muregist",
    "/etc/action-runner",
];

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

pub(crate) fn sanitize_relative_path(raw: &Path) -> Result<PathBuf, AgentError> {
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

/// Artifact slot requested when fetching a digest-pinned payload from `mu-registry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryArtifactKind {
    Binary,
    ItArchive,
}

impl RegistryArtifactKind {
    fn download_query(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::ItArchive => "it_archive",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Binary => "candidate artifact",
            Self::ItArchive => "IT archive",
        }
    }
}

/// Abstraction for fetching verified IT archive bytes by SHA-256 digest.
#[async_trait]
pub trait ItArchiveFetcher: Send + Sync {
    async fn fetch_it_archive(&self, digest: &str) -> Result<Vec<u8>, AgentError>;

    /// Fetches verified IT archive bytes, optionally hinting an explicit `bundle_id` in `mu-registry`.
    async fn fetch_it_archive_for_bundle(
        &self,
        digest: &str,
        _bundle_id: Option<&str>,
    ) -> Result<Vec<u8>, AgentError> {
        self.fetch_it_archive(digest).await
    }
}

/// Fetches candidate artifacts and integration test archives from local CAS storage or
/// `mu-registry` HTTP/mTLS endpoints, enforcing SHA-256 verification before returning bytes.
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

    pub fn with_bundle_id(mut self, bundle_id: impl Into<String>) -> Self {
        self.bundle_id = Some(bundle_id.into());
        self
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Fetch and verify any CAS blob or registered bundle artifact by exact SHA-256 digest.
    pub async fn fetch_artifact_by_digest(
        &self,
        digest: &str,
        preferred_kind: RegistryArtifactKind,
    ) -> Result<Vec<u8>, AgentError> {
        let digest = validate_sha256_digest(digest)?;
        if let Some(bytes) = self.try_read_local_cas(&digest)? {
            return Ok(bytes);
        }
        if let Some(ref registry_url) = self.registry_url {
            return self
                .fetch_from_registry(registry_url, &digest, preferred_kind)
                .await;
        }
        Err(AgentError::BundleVerification(format!(
            "{} {digest} not found in local CAS and no registry_url configured",
            preferred_kind.label()
        )))
    }

    /// Fetch and SHA-256-verify a candidate deployment artifact (binary or bundle tarball).
    pub async fn fetch_candidate_artifact(&self, digest: &str) -> Result<Vec<u8>, AgentError> {
        self.fetch_artifact_by_digest(digest, RegistryArtifactKind::Binary)
            .await
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
        preferred_kind: RegistryArtifactKind,
    ) -> Result<Vec<u8>, AgentError> {
        let client = self.build_http_client()?;
        let base = base_url.trim_end_matches('/');

        let mut candidate_urls = Vec::new();
        if let Some(ref bundle_id) = self.bundle_id {
            let trimmed_id = bundle_id.trim();
            if !trimmed_id.is_empty() {
                candidate_urls.push(format!(
                    "{base}/api/v1/bundles/it/{trimmed_id}?download={}",
                    preferred_kind.download_query()
                ));
            }
        } else if let Some((resolved_id, matched_kind)) = self
            .lookup_bundle_id_by_digest(&client, base, digest, preferred_kind)
            .await?
        {
            candidate_urls.push(format!(
                "{base}/api/v1/bundles/it/{resolved_id}?download={}",
                matched_kind.download_query()
            ));
        }

        candidate_urls.push(format!("{base}/api/v1/cas/blobs/sha256/{digest}"));
        candidate_urls.push(format!("{base}/api/v1/blobs/sha256/{digest}"));
        candidate_urls.push(format!("{base}/api/v1/blobs/{digest}"));

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
            "Unable to fetch {} {digest} from mu-registry ({})",
            preferred_kind.label(),
            errors.join("; ")
        )))
    }

    async fn lookup_bundle_id_by_digest(
        &self,
        client: &reqwest::Client,
        base: &str,
        digest: &str,
        preferred_kind: RegistryArtifactKind,
    ) -> Result<Option<(String, RegistryArtifactKind)>, AgentError> {
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
        let search_order = match preferred_kind {
            RegistryArtifactKind::Binary => [
                ("binary_digest", RegistryArtifactKind::Binary),
                ("it_archive_digest", RegistryArtifactKind::ItArchive),
            ],
            RegistryArtifactKind::ItArchive => [
                ("it_archive_digest", RegistryArtifactKind::ItArchive),
                ("binary_digest", RegistryArtifactKind::Binary),
            ],
        };
        for (field, kind) in search_order {
            for item in entries {
                let item_digest = item.get(field).and_then(|v| v.as_str()).unwrap_or("");
                if item_digest.eq_ignore_ascii_case(digest) {
                    if let Some(id) = item.get("bundle_id").and_then(|v| v.as_str()) {
                        return Ok(Some((id.to_string(), kind)));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl ItArchiveFetcher for RegistryAndCasFetcher {
    async fn fetch_it_archive(&self, digest: &str) -> Result<Vec<u8>, AgentError> {
        self.fetch_artifact_by_digest(digest, RegistryArtifactKind::ItArchive)
            .await
    }

    async fn fetch_it_archive_for_bundle(
        &self,
        digest: &str,
        bundle_id: Option<&str>,
    ) -> Result<Vec<u8>, AgentError> {
        if let Some(id) = bundle_id.map(str::trim).filter(|s| !s.is_empty()) {
            let mut scoped = self.clone();
            scoped.bundle_id = Some(id.to_string());
            return scoped
                .fetch_artifact_by_digest(digest, RegistryArtifactKind::ItArchive)
                .await;
        }
        self.fetch_it_archive(digest).await
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
    /// Optional Layer 1 host ceiling YAML path (`/etc/mu-isolation/ceiling.yml` in production).
    pub host_ceiling_path: Option<PathBuf>,
    /// Optional Layer 2 desired security profile YAML path.
    pub security_file_path: Option<PathBuf>,
    /// Scenario read-only Landlock credential/CA mounts (never writable or executable).
    pub ro_mounts: Vec<PathBuf>,
    /// Explicitly allowlisted scenario environment variables injected after `cmd.env_clear()`.
    pub allowlisted_env: Vec<(String, String)>,
    /// Explicitly bounded scenario CLI arguments appended to the test command.
    pub extra_args: Vec<String>,
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
            host_ceiling_path: None,
            security_file_path: None,
            ro_mounts: Vec::new(),
            allowlisted_env: Vec::new(),
            extra_args: Vec::new(),
            proc_ai_thread_path: PathBuf::from(DEFAULT_SET_AI_THREAD_PATH),
            per_test_timeout_secs: 30,
        }
    }
}

/// Normalizes architecture labels for `mu_ci_isolation` seccomp-BPF planner compatibility.
///
/// `aarch64` / `arm64` shares the Linux `asm-generic` syscall table with `riscv64gc` for the
/// kernel-surface denylist enforced by `SeccompFilterBuilder`.
pub fn normalize_sandbox_arch(raw: &str) -> String {
    match raw.trim() {
        "aarch64" | "arm64" | "riscv64" => "riscv64gc".to_string(),
        other => other.to_string(),
    }
}

/// Canonical architecture identifier accepted by `mu_ci_isolation` seccomp planner.
pub fn canonical_sandbox_arch() -> &'static str {
    match std::env::consts::ARCH {
        "riscv64" | "aarch64" => "riscv64gc",
        "x86_64" => "x86_64",
        #[cfg(target_os = "linux")]
        other => other,
        // Non-Linux dev environments (e.g., Apple Silicon macOS) validate seccomp plans against x86_64.
        #[cfg(not(target_os = "linux"))]
        _ => "x86_64",
    }
}

fn push_unique_clean(paths: &mut Vec<PathBuf>, candidate: &Path) {
    let Some(clean) = normalize_clean_path(candidate) else {
        return;
    };
    if !paths.iter().any(|p| p == &clean) {
        paths.push(clean);
    }
}

fn is_covered_by_prefixes(candidate: &Path, prefixes: &[PathBuf]) -> bool {
    let Some(clean_candidate) = normalize_clean_path(candidate) else {
        return false;
    };
    prefixes.iter().any(|prefix| {
        normalize_clean_path(prefix)
            .is_some_and(|clean_prefix| clean_candidate.starts_with(&clean_prefix))
    })
}

/// Validates scenario read-only Landlock mount paths (strictly normalized absolute, non-root,
/// zero `..` traversal, zero NUL bytes).
pub fn validate_ro_mounts(mounts: &[PathBuf]) -> Result<Vec<PathBuf>, AgentError> {
    let mut validated = Vec::with_capacity(mounts.len());
    for mount in mounts {
        let Some(as_str) = mount.to_str() else {
            return Err(AgentError::SandboxViolation(
                "Read-only mount path is not valid UTF-8".to_string(),
            ));
        };
        if as_str.contains('\0') {
            return Err(AgentError::SandboxViolation(
                "Read-only mount path contains forbidden NUL byte".to_string(),
            ));
        }
        let Some(clean) = normalize_clean_path(mount) else {
            return Err(AgentError::SandboxViolation(format!(
                "Read-only mount '{}' must be a clean absolute path without '..'",
                mount.display()
            )));
        };
        if clean == Path::new("/") {
            return Err(AgentError::SandboxViolation(
                "Read-only mount cannot be bare root '/'".to_string(),
            ));
        }
        if !validated.iter().any(|p| p == &clean) {
            validated.push(clean);
        }
    }
    Ok(validated)
}

/// Validates scenario CLI arguments (`<= 32` entries, `<= 4096` bytes each, zero NUL bytes).
pub fn validate_scenario_args(args: &[String]) -> Result<(), AgentError> {
    if args.len() > MAX_SCENARIO_ARGS {
        return Err(AgentError::SandboxViolation(format!(
            "Scenario argument count {} exceeds maximum of {MAX_SCENARIO_ARGS}",
            args.len()
        )));
    }
    for arg in args {
        if arg.contains('\0') {
            return Err(AgentError::SandboxViolation(
                "Scenario argument contains forbidden NUL byte".to_string(),
            ));
        }
        if arg.len() > MAX_SCENARIO_ARG_BYTES {
            return Err(AgentError::SandboxViolation(format!(
                "Scenario argument length {} exceeds maximum of {MAX_SCENARIO_ARG_BYTES} bytes",
                arg.len()
            )));
        }
    }
    Ok(())
}

/// Validates scenario environment overrides against the fixed `ALLOWED_SCENARIO_ENV_KEYS`
/// allowlist, rejecting NUL bytes, invalid `RUST_BACKTRACE`/`MU_SMOKE_TIMEOUT_SECS` values, and
/// any `MU_SMOKE_*_FILE` value not present in `validated_ro_mounts`.
pub fn validate_allowlisted_env(
    env: &[(String, String)],
    validated_ro_mounts: &[PathBuf],
) -> Result<(), AgentError> {
    for (key, value) in env {
        if key.is_empty() || key.contains('\0') || value.contains('\0') {
            return Err(AgentError::SandboxViolation(
                "Scenario environment variable key/value cannot be empty or contain NUL bytes"
                    .to_string(),
            ));
        }
        if !ALLOWED_SCENARIO_ENV_KEYS.contains(&key.as_str()) {
            return Err(AgentError::SandboxViolation(format!(
                "Scenario environment variable '{key}' is not in the explicit allowlist"
            )));
        }
        if key == "RUST_BACKTRACE" && value != "0" && value != "1" {
            return Err(AgentError::SandboxViolation(format!(
                "Scenario RUST_BACKTRACE must be '0' or '1', got '{value}'"
            )));
        }
        if key == "MU_SMOKE_TIMEOUT_SECS" {
            let parsed = value.trim().parse::<u64>().map_err(|_| {
                AgentError::SandboxViolation(format!(
                    "Scenario MU_SMOKE_TIMEOUT_SECS must be a positive integer, got '{value}'"
                ))
            })?;
            if parsed == 0 {
                return Err(AgentError::SandboxViolation(
                    "Scenario MU_SMOKE_TIMEOUT_SECS must be greater than 0".to_string(),
                ));
            }
        }
        if FILE_MOUNT_ENV_KEYS.contains(&key.as_str()) {
            let Some(clean_file) = normalize_clean_path(Path::new(value)) else {
                return Err(AgentError::SandboxViolation(format!(
                    "Scenario file env '{key}' path '{value}' must be a clean absolute path"
                )));
            };
            if clean_file == Path::new("/") || !validated_ro_mounts.contains(&clean_file) {
                return Err(AgentError::SandboxViolation(format!(
                    "Scenario file env '{key}' path '{}' is not covered by validated ro_mounts",
                    clean_file.display()
                )));
            }
        }
    }
    Ok(())
}

fn normalize_network_mode(mode: &NetworkEgressMode) -> NetworkEgressMode {
    match mode {
        NetworkEgressMode::Offline => NetworkEgressMode::Offline,
        NetworkEgressMode::RestrictedCidrs(cidrs) if cidrs.is_empty() => NetworkEgressMode::Offline,
        NetworkEgressMode::RestrictedCidrs(cidrs) => {
            NetworkEgressMode::RestrictedCidrs(cidrs.clone())
        }
    }
}

fn resolve_host_ceiling(
    cfg: &ItSandboxConfig,
    canon_work: &Path,
    work_dir: &Path,
    sandbox_tmp: &Path,
) -> Result<HostCeilingConfig, AgentError> {
    if let Some(ref ceiling_path) = cfg.host_ceiling_path {
        let mut ceiling = HostCeilingConfig::from_path(ceiling_path).map_err(|e| {
            AgentError::SandboxViolation(format!(
                "Failed to load Layer 1 host ceiling '{}': {e}",
                ceiling_path.display()
            ))
        })?;
        ceiling.arch = normalize_sandbox_arch(&ceiling.arch);
        ceiling.max_pids = ceiling.max_pids.min(MAX_IT_SANDBOX_PIDS);
        return Ok(ceiling);
    }

    let mut allowed_read_prefixes: Vec<PathBuf> = BASELINE_RUNTIME_READ_PATHS
        .iter()
        .chain(DEFAULT_CANARY_READ_PREFIXES.iter())
        .map(PathBuf::from)
        .collect();
    push_unique_clean(&mut allowed_read_prefixes, canon_work);
    push_unique_clean(&mut allowed_read_prefixes, work_dir);

    let mut allowed_write_prefixes = vec![PathBuf::from("/tmp")];
    push_unique_clean(&mut allowed_write_prefixes, sandbox_tmp);
    push_unique_clean(&mut allowed_write_prefixes, canon_work);

    let mut allowed_exec_prefixes = vec![
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    push_unique_clean(&mut allowed_exec_prefixes, canon_work);
    push_unique_clean(&mut allowed_exec_prefixes, work_dir);

    Ok(HostCeilingConfig {
        node_id: "mu-cd-agent-it".to_string(),
        arch: canonical_sandbox_arch().to_string(),
        allowed_backends: vec![SandboxBackendKind::Kernel],
        allowed_read_prefixes,
        allowed_write_prefixes,
        allowed_exec_prefixes,
        allowed_egress_cidrs: vec!["127.0.0.0/8".to_string()],
        max_memlock_kb: MAX_K3_MEMLOCK_KB,
        max_cpu_cores: cfg.max_cpu_cores.max(1),
        max_memory_mb: cfg.max_memory_mb.max(64),
        max_pids: MAX_IT_SANDBOX_PIDS,
        allow_spacemit_ai_thread: false,
    })
}

fn build_profile_and_task(
    cfg: &ItSandboxConfig,
    ceiling: &HostCeilingConfig,
    canon_work: &Path,
    work_dir: &Path,
    sandbox_tmp: &Path,
    validated_ro_mounts: &[PathBuf],
    network_mode: NetworkEgressMode,
) -> Result<(DesiredProfileConfig, TaskSandboxConfig), AgentError> {
    if let Some(ref sec_path) = cfg.security_file_path {
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

        let task_read_paths = if validated_ro_mounts.is_empty() {
            Vec::new()
        } else {
            let mut reads = Vec::new();
            for runtime_path in BASELINE_RUNTIME_READ_PATHS {
                let p = Path::new(runtime_path);
                if is_covered_by_prefixes(p, &base.read_paths) {
                    push_unique_clean(&mut reads, p);
                }
            }
            if is_covered_by_prefixes(canon_work, &base.read_paths) {
                push_unique_clean(&mut reads, canon_work);
            }
            for mount in validated_ro_mounts {
                push_unique_clean(&mut reads, mount);
            }
            reads
        };

        let task = TaskSandboxConfig {
            backend: Some(SandboxBackendKind::Kernel),
            read_paths: task_read_paths,
            write_paths: Vec::new(),
            exec_paths: Vec::new(),
            network_mode,
            memlock_limit_kb: (cfg.memlock_limit_kb != DEFAULT_IT_MEMLOCK_KB)
                .then_some(cfg.memlock_limit_kb),
            max_pids: (cfg.max_pids != MAX_IT_SANDBOX_PIDS).then_some(cfg.max_pids),
            max_memory_mb: (cfg.max_memory_mb != 1024).then_some(cfg.max_memory_mb),
            cpu_affinity_mask: None,
            require_set_ai_thread: None,
        };
        return Ok((base, task));
    }

    let mut read_paths = Vec::new();
    for runtime_path in BASELINE_RUNTIME_READ_PATHS {
        let p = Path::new(runtime_path);
        if is_covered_by_prefixes(p, &ceiling.allowed_read_prefixes) {
            push_unique_clean(&mut read_paths, p);
        }
    }
    push_unique_clean(&mut read_paths, canon_work);
    if is_covered_by_prefixes(work_dir, &ceiling.allowed_read_prefixes) {
        push_unique_clean(&mut read_paths, work_dir);
    }
    for mount in validated_ro_mounts {
        push_unique_clean(&mut read_paths, mount);
    }

    let mut write_paths = Vec::new();
    let tmp_path = Path::new("/tmp");
    if is_covered_by_prefixes(tmp_path, &ceiling.allowed_write_prefixes) {
        push_unique_clean(&mut write_paths, tmp_path);
    }
    push_unique_clean(&mut write_paths, sandbox_tmp);

    let mut exec_paths = Vec::new();
    for exec_default in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let p = Path::new(exec_default);
        if is_covered_by_prefixes(p, &ceiling.allowed_exec_prefixes) {
            push_unique_clean(&mut exec_paths, p);
        }
    }
    push_unique_clean(&mut exec_paths, canon_work);
    if is_covered_by_prefixes(work_dir, &ceiling.allowed_exec_prefixes) {
        push_unique_clean(&mut exec_paths, work_dir);
    }

    let ceiling_memlock = ceiling.max_memlock_kb.min(MAX_K3_MEMLOCK_KB);
    let desired_profile = DesiredProfileConfig {
        backend: SandboxBackendKind::Kernel,
        read_paths: read_paths.clone(),
        write_paths: write_paths.clone(),
        exec_paths: exec_paths.clone(),
        network_egress_cidrs: ceiling.allowed_egress_cidrs.clone(),
        memlock_limit_kb: ceiling_memlock,
        max_pids: ceiling.max_pids.min(MAX_IT_SANDBOX_PIDS),
        max_memory_mb: Some(ceiling.max_memory_mb),
        cpu_affinity_mask: None,
        require_set_ai_thread: false,
    };

    let task = TaskSandboxConfig {
        backend: Some(SandboxBackendKind::Kernel),
        read_paths,
        write_paths,
        exec_paths,
        network_mode,
        memlock_limit_kb: Some(cfg.memlock_limit_kb),
        max_pids: Some(cfg.max_pids),
        max_memory_mb: Some(cfg.max_memory_mb),
        cpu_affinity_mask: None,
        require_set_ai_thread: Some(false),
    };

    Ok((desired_profile, task))
}

fn verify_ro_mounts_strictly_readonly(
    validated_ro_mounts: &[PathBuf],
    effective: &EffectiveSandboxPolicy,
    plan: &SandboxExecutionPlan,
) -> Result<(), AgentError> {
    for wp in &effective.write_paths {
        for forbidden in SENSITIVE_ETC_WRITE_PREFIXES {
            if wp.starts_with(forbidden) {
                return Err(AgentError::SandboxViolation(format!(
                    "Credential directory '{}' must never be writable inside sandbox",
                    wp.display()
                )));
            }
        }
    }
    for mount in validated_ro_mounts {
        if effective.write_paths.contains(mount) || effective.exec_paths.contains(mount) {
            return Err(AgentError::SandboxViolation(format!(
                "Read-only credential mount '{}' cannot have write or exec access",
                mount.display()
            )));
        }
        let rule = plan
            .landlock_rules
            .iter()
            .find(|r| &r.path == mount)
            .ok_or_else(|| {
                AgentError::SandboxViolation(format!(
                    "Read-only credential mount '{}' missing from Landlock execution plan",
                    mount.display()
                ))
            })?;
        if rule.access_mask != READ_ACCESS {
            return Err(AgentError::SandboxViolation(format!(
                "Read-only credential mount '{}' must have READ_ACCESS only, got mask {:#x}",
                mount.display(),
                rule.access_mask
            )));
        }
    }
    Ok(())
}

/// Evaluates the 3-layer `MuIsolation` security policy (`Ceiling ∩ Profile ∩ Task`) and
/// produces a validated `KernelSandbox` execution plan capped at `max_pids <= 256`.
pub fn build_it_sandbox_plan(
    work_dir: &Path,
    argv: &[OsString],
    cfg: &ItSandboxConfig,
) -> Result<(EffectiveSandboxPolicy, SandboxExecutionPlan), AgentError> {
    validate_scenario_args(&cfg.extra_args)?;
    let validated_ro_mounts = validate_ro_mounts(&cfg.ro_mounts)?;
    validate_allowlisted_env(&cfg.allowlisted_env, &validated_ro_mounts)?;

    let canon_work = fs::canonicalize(work_dir).unwrap_or_else(|_| work_dir.to_path_buf());
    let sandbox_tmp = canon_work.join(".sandbox_tmp");
    let ceiling = resolve_host_ceiling(cfg, &canon_work, work_dir, &sandbox_tmp)?;
    let network_mode = normalize_network_mode(&cfg.network_mode);
    let (desired_profile, task) = build_profile_and_task(
        cfg,
        &ceiling,
        &canon_work,
        work_dir,
        &sandbox_tmp,
        &validated_ro_mounts,
        network_mode,
    )?;

    let effective = resolve_effective_policy(&ceiling, &desired_profile, &task)
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;

    let sandbox = KernelSandbox::with_proc_ai_thread_path(&cfg.proc_ai_thread_path);
    sandbox
        .validate_host_support(&effective)
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;
    let plan = sandbox
        .build_execution_plan(&effective, argv)
        .map_err(|e| AgentError::SandboxViolation(e.to_string()))?;

    verify_ro_mounts_strictly_readonly(&validated_ro_mounts, &effective, &plan)?;

    Ok((effective, plan))
}

fn merge_effective_args(base: &[String], extra: &[String]) -> Result<Vec<String>, AgentError> {
    validate_scenario_args(base)?;
    validate_scenario_args(extra)?;
    let mut merged = Vec::with_capacity(base.len() + extra.len());
    for arg in base {
        merged.push(arg.clone());
    }
    for arg in extra {
        if arg.starts_with("--") && !arg.contains('=') && merged.iter().any(|a| a == arg) {
            continue;
        }
        merged.push(arg.clone());
    }
    validate_scenario_args(&merged)?;
    Ok(merged)
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
/// each test directly with a cleared minimal environment plus explicitly allowlisted vars.
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
        let effective_args = merge_effective_args(&test.args, &sandbox_cfg.extra_args)?;
        let mut argv = Vec::with_capacity(1 + effective_args.len());
        argv.push(test.command_path.as_os_str().to_os_string());
        for arg in &effective_args {
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
        cmd.args(&effective_args)
            .current_dir(&test.working_dir)
            .kill_on_drop(true)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TMPDIR", &sandbox_tmp)
            .env("MU_CD_IT_SERVICE", service_name)
            .env("MU_CD_IT_SLOT", slot.as_str())
            .env("MU_CD_IT_WORKDIR", work_dir)
            .env("MUCONDE_IT_SERVICE", service_name)
            .env("MUCONDE_IT_SLOT", slot.as_str())
            .env("MUCONDE_IT_WORKDIR", work_dir);
        for (key, value) in &sandbox_cfg.allowlisted_env {
            cmd.env(key, value);
        }

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
                log_output: sanitize_and_bound_log_excerpt(
                    &format!(
                        "Sandboxed test '{}' timed out after {}s",
                        test.name,
                        timeout.as_secs()
                    ),
                    MAX_LOG_EXCERPT_BYTES,
                ),
                effective_policy,
                execution_plan,
            }),
        }
    }
}

/// Default retry cadence when waiting for scenario TCP endpoints to bind during warmup.
pub const TCP_WARMUP_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Per-attempt TCP connect timeout during warmup readiness probing.
pub const TCP_WARMUP_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Parses a `"host:port"` or `"[ipv6]:port"` endpoint string into `(host, port)`.
pub fn parse_tcp_endpoint_from_addr(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port_str) = rest.split_once("]:")?;
        if host.is_empty() || host.contains('/') {
            return None;
        }
        let port: u16 = port_str.parse().ok()?;
        return (port > 0).then(|| (host.to_string(), port));
    }
    let (host, port_str) = trimmed.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') || host.contains('/') {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    (port > 0).then(|| (host.to_string(), port))
}

/// Parses an `http://` or `https://` target URL into `(host, port)`, applying default ports
/// (`80` / `443`) when omitted.
pub fn parse_tcp_endpoint_from_url(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    let (scheme, after_scheme) = trimmed.split_once("://")?;
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        80
    } else if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        return None;
    };

    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    if authority.is_empty() || authority.chars().any(char::is_whitespace) {
        return None;
    }
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }

    if let Some(rest) = host_port.strip_prefix('[') {
        let (host, trailing) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = if trailing.is_empty() {
            default_port
        } else {
            let port_str = trailing.strip_prefix(':')?;
            let parsed: u16 = port_str.parse().ok()?;
            if parsed == 0 {
                return None;
            }
            parsed
        };
        return Some((host.to_string(), port));
    }

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        if host.is_empty() || host.contains(':') {
            return None;
        }
        let port: u16 = port_str.parse().ok()?;
        (port > 0).then(|| (host.to_string(), port))
    } else {
        Some((host_port.to_string(), default_port))
    }
}

/// Extracts deduplicated `(host, port)` TCP targets from a scenario's allowlisted environment
/// variables (`MU_SMOKE_TARGET_ADDR` and `MU_SMOKE_TARGET_URL`).
pub fn extract_scenario_tcp_endpoints(allowlisted_env: &[(String, String)]) -> Vec<(String, u16)> {
    let mut endpoints: Vec<(String, u16)> = Vec::new();
    for (key, value) in allowlisted_env {
        let parsed = match key.as_str() {
            "MU_SMOKE_TARGET_ADDR" => parse_tcp_endpoint_from_addr(value),
            "MU_SMOKE_TARGET_URL" => parse_tcp_endpoint_from_url(value),
            _ => None,
        };
        if let Some(ep) = parsed {
            if !endpoints.contains(&ep) {
                endpoints.push(ep);
            }
        }
    }
    endpoints
}

/// Polls each `(host, port)` endpoint at `poll_interval` cadence up to `timeout` until every
/// target accepts a TCP connection.
pub async fn wait_for_tcp_endpoints_ready(
    endpoints: &[(String, u16)],
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), String> {
    if endpoints.is_empty() {
        return Ok(());
    }

    let deadline = Instant::now() + timeout;
    let poll = if poll_interval.is_zero() {
        Duration::from_millis(50)
    } else {
        poll_interval
    };

    for (host, port) in endpoints {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let attempt_timeout =
                TCP_WARMUP_CONNECT_TIMEOUT.min(remaining.max(Duration::from_millis(50)));
            let last_err = match tokio::time::timeout(
                attempt_timeout,
                tokio::net::TcpStream::connect((host.as_str(), *port)),
            )
            .await
            {
                Ok(Ok(_stream)) => break,
                Ok(Err(err)) => err.to_string(),
                Err(_) => "connect attempt timed out".to_string(),
            };

            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "Warmup TCP readiness probe timed out after {}ms for {host}:{port} ({last_err})",
                    timeout.as_millis()
                ));
            }
            tokio::time::sleep(poll.min(deadline.saturating_duration_since(now))).await;
        }
    }

    Ok(())
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
        #[cfg(miri)]
        const REPEATS: usize = 25;
        #[cfg(not(miri))]
        const REPEATS: usize = 400;
        let raw = "line1 token=super-secret-value Bearer secret-abc\n".repeat(REPEATS);
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

    async fn spawn_mock_registry_server<F>(handler: F) -> String
    where
        F: Fn(&str) -> (u16, &'static str, Vec<u8>) + Send + Sync + 'static,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = std::sync::Arc::new(handler);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let (status, content_type, body) = handler(path);
                    let reason = match status {
                        200 => "OK",
                        404 => "Not Found",
                        _ => "Error",
                    };
                    let header = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_registry_fetcher_resolves_binary_and_it_archive_and_fails_closed() {
        let bin_bytes = b"\x7fELF-candidate-binary-payload".to_vec();
        let bin_digest = hex::encode(Sha256::digest(&bin_bytes));
        let (it_bytes, it_digest) = build_test_tar_gz(&[(
            "manifest.json",
            br#"{"tests":[{"name":"it_smoke","command":"bin/run.sh","critical":true}]}"#,
            0o644,
        )]);
        let cas_only_bytes = b"direct-cas-blob-payload".to_vec();
        let cas_only_digest = hex::encode(Sha256::digest(&cas_only_bytes));
        let bad_digest = "f".repeat(64);

        let bin_digest_srv = bin_digest.clone();
        let it_digest_srv = it_digest.clone();
        let cas_digest_srv = cas_only_digest.clone();
        let bin_bytes_srv = bin_bytes.clone();
        let it_bytes_srv = it_bytes.clone();
        let cas_bytes_srv = cas_only_bytes.clone();

        let base_url = spawn_mock_registry_server(move |path| match path {
            "/api/v1/registry/bundles" => {
                let json = format!(
                    r#"{{"total":1,"bundles":[{{"bundle_id":"bundle-42","service_name":"mu-cd-agent","binary_digest":"{bin_digest_srv}","it_archive_digest":"{it_digest_srv}"}}]}}"#
                );
                (200, "application/json", json.into_bytes())
            }
            "/api/v1/bundles/it/bundle-42?download=binary" => {
                (200, "application/octet-stream", bin_bytes_srv.clone())
            }
            "/api/v1/bundles/it/bundle-42?download=it_archive" => {
                (200, "application/gzip", it_bytes_srv.clone())
            }
            p if p == format!("/api/v1/cas/blobs/sha256/{cas_digest_srv}") => {
                (200, "application/octet-stream", cas_bytes_srv.clone())
            }
            p if p.contains("ffffffff") => {
                (200, "application/octet-stream", b"tampered-bytes".to_vec())
            }
            _ => (404, "text/plain", b"not found".to_vec()),
        })
        .await;

        let fetcher = RegistryAndCasFetcher::default()
            .with_registry_url(base_url)
            .with_bearer_token("test-token");

        let got_bin = fetcher.fetch_candidate_artifact(&bin_digest).await.unwrap();
        assert_eq!(got_bin, bin_bytes);

        let got_it = fetcher.fetch_it_archive(&it_digest).await.unwrap();
        assert_eq!(got_it, it_bytes);

        let got_cas = fetcher
            .fetch_candidate_artifact(&cas_only_digest)
            .await
            .unwrap();
        assert_eq!(got_cas, cas_only_bytes);

        let mismatch_err = fetcher
            .fetch_candidate_artifact(&bad_digest)
            .await
            .unwrap_err();
        assert!(matches!(mismatch_err, AgentError::BundleVerification(_)));

        let missing_digest = "e".repeat(64);
        let missing_err = fetcher
            .fetch_candidate_artifact(&missing_digest)
            .await
            .unwrap_err();
        assert!(matches!(missing_err, AgentError::BundleVerification(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_monotonic_host_ceiling_restricted_cidrs_and_ro_mounts() {
        use mu_ci_isolation::CLONE_NEWNET;

        let dir = exec_tempdir();
        let work_canon = fs::canonicalize(dir.path()).unwrap();
        let argv = vec![OsString::from("/bin/true")];

        let ceiling_path = dir.path().join("ceiling.yml");
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
  - /etc/mu-cd-canary/tls
  - /etc/mu-cd-canary/tokens
  - {work}
allowed_write_prefixes:
  - /tmp
  - {work}
allowed_exec_prefixes:
  - /usr/bin
  - /bin
  - /usr/local/bin
  - {work}
allowed_egress_cidrs:
  - "127.0.0.0/8"
  - "192.0.2.10/32"
max_memlock_kb: 2097152
max_cpu_cores: 4
max_memory_mb: 4096
max_pids: 512
allow_spacemit_ai_thread: false
"#,
                work = work_canon.display()
            ),
        )
        .unwrap();

        let profile_path = dir.path().join("cd-canary-profile.yml");
        fs::write(
            &profile_path,
            format!(
                r#"default_profile: "cd_canary"
profiles:
  cd_canary:
    backend: Kernel
    read_paths:
      - /usr
      - /bin
      - /lib
      - /lib64
      - /etc/ssl
      - /etc/hosts
      - /etc/resolv.conf
      - /etc/mu-cd-canary/tls
      - /etc/mu-cd-canary/tokens
      - {work}
    write_paths:
      - /tmp
      - {work}
    exec_paths:
      - /usr/bin
      - /bin
      - {work}
    network_egress_cidrs:
      - "127.0.0.1/32"
      - "192.0.2.10/32"
    memlock_limit_kb: 65536
    max_pids: 256
    max_memory_mb: 1024
    require_set_ai_thread: false
"#,
                work = work_canon.display()
            ),
        )
        .unwrap();

        let ca_mount = PathBuf::from("/etc/mu-cd-canary/tls/ca.crt");
        let tok_mount = PathBuf::from("/etc/mu-cd-canary/tokens/cd-readonly.token");
        let valid_cfg = ItSandboxConfig {
            host_ceiling_path: Some(ceiling_path.clone()),
            security_file_path: Some(profile_path.clone()),
            network_mode: NetworkEgressMode::RestrictedCidrs(vec![
                "192.0.2.10/32".to_string(),
                "127.0.0.1/32".to_string(),
            ]),
            ro_mounts: vec![ca_mount.clone(), tok_mount.clone()],
            allowlisted_env: vec![
                (
                    "MU_SMOKE_TARGET_URL".to_string(),
                    "https://node-a.example:8444".to_string(),
                ),
                (
                    "MU_SMOKE_TLS_CA_FILE".to_string(),
                    ca_mount.display().to_string(),
                ),
                (
                    "MU_SMOKE_BEARER_TOKEN_FILE".to_string(),
                    tok_mount.display().to_string(),
                ),
                ("MU_SMOKE_TIMEOUT_SECS".to_string(), "10".to_string()),
                ("RUST_BACKTRACE".to_string(), "1".to_string()),
            ],
            extra_args: vec!["--nocapture".to_string()],
            ..Default::default()
        };

        let (policy, plan) = build_it_sandbox_plan(dir.path(), &argv, &valid_cfg).unwrap();
        assert_eq!(policy.max_pids, 256);
        assert_eq!(policy.memlock_limit_kb, 65_536);
        assert_eq!(
            policy.network_mode,
            NetworkEgressMode::RestrictedCidrs(vec![
                "192.0.2.10/32".to_string(),
                "127.0.0.1/32".to_string(),
            ])
        );
        assert!(!plan.namespace_flags.unwrap().contains(CLONE_NEWNET));
        // Credential mounts must be strictly READ_ACCESS and narrowed from directory prefixes
        assert!(!policy
            .read_paths
            .contains(&PathBuf::from("/etc/mu-cd-canary/tls")));
        assert!(!policy
            .read_paths
            .contains(&PathBuf::from("/etc/mu-cd-canary/tokens")));
        for mount in [&ca_mount, &tok_mount] {
            let rule = plan
                .landlock_rules
                .iter()
                .find(|r| &r.path == mount)
                .expect("mount present in Landlock rules");
            assert_eq!(rule.access_mask, READ_ACCESS);
        }

        // Empty RestrictedCidrs normalizes to Offline with CLONE_NEWNET
        let offline_cfg = ItSandboxConfig {
            network_mode: NetworkEgressMode::RestrictedCidrs(Vec::new()),
            ..valid_cfg.clone()
        };
        let (off_policy, off_plan) =
            build_it_sandbox_plan(dir.path(), &argv, &offline_cfg).unwrap();
        assert_eq!(off_policy.network_mode, NetworkEgressMode::Offline);
        assert!(off_plan.namespace_flags.unwrap().contains(CLONE_NEWNET));

        // Out-of-ceiling CIDRs fail closed (SecurityGrantDenied)
        for bad_cidr in ["0.0.0.0/0", "198.51.100.1/32"] {
            let bad = ItSandboxConfig {
                network_mode: NetworkEgressMode::RestrictedCidrs(vec![bad_cidr.to_string()]),
                ..valid_cfg.clone()
            };
            let err = build_it_sandbox_plan(dir.path(), &argv, &bad).unwrap_err();
            assert!(matches!(err, AgentError::SandboxViolation(_)));
        }

        // Unpermitted or traversal RO mounts fail closed
        for bad_mount in [
            "/etc/shadow",
            "/etc/muconde/tls/client.key",
            "/etc/mu-cd-canary/../shadow",
        ] {
            let bad = ItSandboxConfig {
                ro_mounts: vec![PathBuf::from(bad_mount)],
                allowlisted_env: Vec::new(),
                ..valid_cfg.clone()
            };
            let err = build_it_sandbox_plan(dir.path(), &argv, &bad).unwrap_err();
            assert!(matches!(err, AgentError::SandboxViolation(_)));
        }

        // Requesting >256 PIDs fails closed even though host ceiling allows 512 for CI builds
        let too_many_pids = ItSandboxConfig {
            max_pids: 257,
            ..valid_cfg.clone()
        };
        assert!(matches!(
            build_it_sandbox_plan(dir.path(), &argv, &too_many_pids),
            Err(AgentError::SandboxViolation(_))
        ));

        // Requesting memlock above profile ceiling fails closed
        let too_much_memlock = ItSandboxConfig {
            memlock_limit_kb: 131_072,
            ..valid_cfg.clone()
        };
        assert!(matches!(
            build_it_sandbox_plan(dir.path(), &argv, &too_much_memlock),
            Err(AgentError::SandboxViolation(_))
        ));

        // Missing host ceiling file fails closed
        let missing_ceiling = ItSandboxConfig {
            host_ceiling_path: Some(dir.path().join("nonexistent-ceiling.yml")),
            ..Default::default()
        };
        assert!(matches!(
            build_it_sandbox_plan(dir.path(), &argv, &missing_ceiling),
            Err(AgentError::SandboxViolation(_))
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_aarch64_ceiling_arch_normalization_builds_valid_seccomp_plan() {
        assert_eq!(normalize_sandbox_arch("aarch64"), "riscv64gc");
        assert_eq!(normalize_sandbox_arch("arm64"), "riscv64gc");
        assert_eq!(normalize_sandbox_arch("x86_64"), "x86_64");

        let dir = exec_tempdir();
        let work_canon = fs::canonicalize(dir.path()).unwrap();
        let ceiling_path = dir.path().join("arm64-ceiling.yml");
        fs::write(
            &ceiling_path,
            format!(
                r#"node_id: "worker-aarch64"
arch: "aarch64"
allowed_backends:
  - Kernel
allowed_read_prefixes:
  - /usr
  - /bin
  - {work}
allowed_write_prefixes:
  - /tmp
  - {work}
allowed_exec_prefixes:
  - /usr/bin
  - /bin
  - {work}
allowed_egress_cidrs:
  - "127.0.0.1/32"
max_memlock_kb: 524288
max_cpu_cores: 4
max_memory_mb: 3584
max_pids: 512
allow_spacemit_ai_thread: false
"#,
                work = work_canon.display()
            ),
        )
        .unwrap();

        let cfg = ItSandboxConfig {
            host_ceiling_path: Some(ceiling_path),
            ..Default::default()
        };
        let argv = vec![OsString::from("/bin/true")];
        let (policy, plan) = build_it_sandbox_plan(dir.path(), &argv, &cfg).unwrap();
        assert_eq!(policy.arch, "riscv64gc");
        let seccomp = plan.seccomp_plan.expect("seccomp plan present");
        assert!(seccomp.enforce_no_new_privs);
        assert_eq!(seccomp.target_arch, "riscv64");
        assert_eq!(seccomp.denied_syscalls.len(), 16);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_allowlisted_env_and_args_validation_and_runtime_isolation() {
        // 1. Disallowed env keys rejected fail-closed
        for bad_key in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PATH",
            "HOME",
            "SECRET_TOKEN",
        ] {
            let err = validate_allowlisted_env(&[(bad_key.to_string(), "x".to_string())], &[])
                .unwrap_err();
            assert!(matches!(err, AgentError::SandboxViolation(_)));
        }
        // 2. MU_SMOKE_*_FILE missing from ro_mounts rejected
        let err = validate_allowlisted_env(
            &[(
                "MU_SMOKE_BEARER_TOKEN_FILE".to_string(),
                "/etc/mu-cd-canary/tokens/cd-readonly.token".to_string(),
            )],
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, AgentError::SandboxViolation(_)));

        // 3. Invalid RUST_BACKTRACE, timeout, NUL bytes, and oversized args rejected
        assert!(
            validate_allowlisted_env(&[("RUST_BACKTRACE".into(), "full".into())], &[]).is_err()
        );
        assert!(
            validate_allowlisted_env(&[("MU_SMOKE_TIMEOUT_SECS".into(), "0".into())], &[]).is_err()
        );
        assert!(validate_allowlisted_env(&[("RUST_LOG".into(), "info\0bad".into())], &[]).is_err());
        let too_many_args: Vec<String> = (0..=MAX_SCENARIO_ARGS).map(|i| format!("a{i}")).collect();
        assert!(validate_scenario_args(&too_many_args).is_err());
        assert!(validate_scenario_args(&["x".repeat(MAX_SCENARIO_ARG_BYTES + 1)]).is_err());
        assert!(validate_scenario_args(&["bad\0arg".to_string()]).is_err());

        // 4. Real execution: env_clear drops host env, injects allowlisted env, deduplicates --nocapture
        let (archive, digest) = build_test_tar_gz(&[
            (
                "manifest.json",
                br#"{"tests":[{"name":"it_allowlist","command":"bin/check.sh","args":["--nocapture"],"critical":true}]}"#,
                0o644,
            ),
            (
                "bin/check.sh",
                b"#!/bin/sh\necho \"args=$* url=$MU_SMOKE_TARGET_URL bt=$RUST_BACKTRACE home=${HOME:-UNSET}\"\nexit 0\n",
                0o755,
            ),
        ]);
        let work = exec_tempdir();
        let bundle = unpack_verified_it_archive(&archive, &digest, work.path()).unwrap();
        let ca_file = work.path().join("ca.crt");
        fs::write(&ca_file, b"dummy-ca").unwrap();
        let ca_canon = fs::canonicalize(&ca_file).unwrap();

        let cfg = ItSandboxConfig {
            ro_mounts: vec![ca_canon.clone()],
            allowlisted_env: vec![
                (
                    "MU_SMOKE_TARGET_URL".to_string(),
                    "http://127.0.0.1:8080/health".to_string(),
                ),
                (
                    "MU_SMOKE_TLS_CA_FILE".to_string(),
                    ca_canon.display().to_string(),
                ),
                ("RUST_BACKTRACE".to_string(), "1".to_string()),
            ],
            extra_args: vec!["--nocapture".to_string(), "smoke_filter".to_string()],
            ..Default::default()
        };

        let out = KernelSandboxedExecutor
            .execute_in_sandbox(
                &bundle.tests[0],
                work.path(),
                &cfg,
                "mu-cd-agent",
                Slot::B,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(out.passed);
        assert!(out.log_output.contains("args=--nocapture smoke_filter"));
        assert!(out.log_output.contains("url=http://127.0.0.1:8080/health"));
        assert!(out.log_output.contains("bt=1"));
        assert!(out.log_output.contains("home=UNSET"));
    }

    #[test]
    fn test_deterministic_secret_redactor_scrubs_pem_bearer_kv_pats_aws_and_truncation_boundary() {
        let raw = concat!(
            "pem_ec=-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIPayloadSecretECKey123456\n-----END EC PRIVATE KEY-----\n",
            "pem_pkcs8=-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH\n-----END PRIVATE KEY-----\n",
            "auth=Authorization: Bearer eyJcanary.secret.jwt\n",
            "lower=bearer another-secret-bearer\n",
            "kv token=tok_val_1 secret=sec_val_2 password=pw_val_3 api_key=ak_val_4 apikey=ak_val_5 client_secret=cs_val_6 webhook_secret=ws_val_7\n",
            "gh ghp_111111aaaa gho_222222bbbb ghs_333333cccc ghu_444444dddd ghr_555555eeee github_pat_666666_ffff\n",
            "aws AKIAIOSFODNN7EXAMPLE ASIAIOSFODNN7TEMPKEY\n",
        );
        let scrubbed = sanitize_and_bound_log_excerpt(raw, MAX_LOG_EXCERPT_BYTES);
        for leaked in [
            "MHcCAQEEIPayloadSecretECKey123456",
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH",
            "eyJcanary.secret.jwt",
            "another-secret-bearer",
            "tok_val_1",
            "sec_val_2",
            "pw_val_3",
            "ak_val_4",
            "ak_val_5",
            "cs_val_6",
            "ws_val_7",
            "ghp_111111aaaa",
            "gho_222222bbbb",
            "ghs_333333cccc",
            "ghu_444444dddd",
            "ghr_555555eeee",
            "github_pat_666666_ffff",
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7TEMPKEY",
        ] {
            assert!(
                !scrubbed.contains(leaked),
                "secret '{leaked}' must be redacted from excerpt: {scrubbed}"
            );
        }
        assert!(scrubbed.contains(REDACTED_PLACEHOLDER));

        // Secret straddling the 8192-byte truncation boundary must be redacted BEFORE truncation
        #[cfg(miri)]
        let max_bound = 256usize;
        #[cfg(not(miri))]
        let max_bound = MAX_LOG_EXCERPT_BYTES;
        let pad = "a".repeat(max_bound.saturating_sub(24));
        let boundary_input = format!("{pad} Authorization: Bearer boundary-secret-token-999999999");
        let bounded = sanitize_and_bound_log_excerpt(&boundary_input, max_bound);
        assert!(bounded.len() <= max_bound);
        assert!(!bounded.contains("boundary-secret-token"));
        assert!(!bounded.contains("boundary-sec"));
        assert!(bounded.ends_with("...[truncated]"));
    }

    #[test]
    fn test_parse_tcp_endpoints_from_url_and_addr() {
        assert_eq!(
            parse_tcp_endpoint_from_addr("node-a.example:8446"),
            Some(("node-a.example".to_string(), 8446))
        );
        assert_eq!(
            parse_tcp_endpoint_from_addr("[::1]:9443"),
            Some(("::1".to_string(), 9443))
        );
        assert_eq!(parse_tcp_endpoint_from_addr("node-a.example:0"), None);
        assert_eq!(parse_tcp_endpoint_from_addr("no-port"), None);
        assert_eq!(parse_tcp_endpoint_from_addr("bad host:8080"), None);

        assert_eq!(
            parse_tcp_endpoint_from_url("http://192.0.2.10:8000/health?ready=1"),
            Some(("192.0.2.10".to_string(), 8000))
        );
        assert_eq!(
            parse_tcp_endpoint_from_url("https://cd.example:8445/api/health"),
            Some(("cd.example".to_string(), 8445))
        );
        assert_eq!(
            parse_tcp_endpoint_from_url("http://192.0.2.10/status"),
            Some(("192.0.2.10".to_string(), 80))
        );
        assert_eq!(
            parse_tcp_endpoint_from_url("https://registry.example"),
            Some(("registry.example".to_string(), 443))
        );
        assert_eq!(
            parse_tcp_endpoint_from_url("http://[::1]:8080/health"),
            Some(("::1".to_string(), 8080))
        );
        assert_eq!(
            parse_tcp_endpoint_from_url("https://[::1]/health"),
            Some(("::1".to_string(), 443))
        );
        assert_eq!(parse_tcp_endpoint_from_url("ftp://192.0.2.10:21"), None);
        assert_eq!(parse_tcp_endpoint_from_url("http://192.0.2.10:0"), None);

        let env = vec![
            (
                "MU_SMOKE_TARGET_URL".to_string(),
                "http://192.0.2.10:8000/health".to_string(),
            ),
            (
                "MU_SMOKE_TARGET_ADDR".to_string(),
                "192.0.2.10:8000".to_string(),
            ),
            (
                "MU_SMOKE_TARGET_ADDR".to_string(),
                "node-b.example:8446".to_string(),
            ),
            ("RUST_BACKTRACE".to_string(), "1".to_string()),
        ];
        assert_eq!(
            extract_scenario_tcp_endpoints(&env),
            vec![
                ("192.0.2.10".to_string(), 8000),
                ("node-b.example".to_string(), 8446),
            ]
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_wait_for_tcp_endpoints_ready_succeeds_after_delayed_bind() {
        let probe_sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe_sock.local_addr().unwrap().port();
        drop(probe_sock);

        let binder = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(350)).await;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .unwrap();
            let _ = listener.accept().await;
        });

        let endpoints = vec![("127.0.0.1".to_string(), port)];
        let start = Instant::now();
        wait_for_tcp_endpoints_ready(
            &endpoints,
            Duration::from_secs(3),
            Duration::from_millis(100),
        )
        .await
        .expect("delayed loopback listener must become ready within warmup timeout");
        assert!(start.elapsed() >= Duration::from_millis(250));
        binder.await.unwrap();

        // Unbound port fails cleanly when timeout elapses
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_port = unused.local_addr().unwrap().port();
        drop(unused);
        let err = wait_for_tcp_endpoints_ready(
            &[("127.0.0.1".to_string(), unused_port)],
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(err.contains("Warmup TCP readiness probe timed out"));
    }
}
