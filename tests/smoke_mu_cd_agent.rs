#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mu_cd_agent::{MockCommandRunner, MockHealthProber, MuConDeAgent, MuConDeAgentConfig};
use mu_cd_ipc::framing::{read_frame, write_frame, IpcHeader, MSG_TYPE_HEARTBEAT};
use mu_cd_ipc::{create_fory_runtime, HeartbeatTelemetry};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const DEFAULT_SMOKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_addr: Option<String>,
    tls_ca_file: Option<PathBuf>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    server_name: Option<String>,
    #[allow(dead_code)]
    bearer_token: Option<String>,
    timeout: Duration,
}

impl SmokeConfig {
    fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let tls_ca_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CA_FILE")?;
        let tls_cert_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CERT_FILE")?;
        let tls_key_file = non_empty_path(&lookup, "MU_SMOKE_TLS_KEY_FILE")?;

        if tls_cert_file.is_some() != tls_key_file.is_some() {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set when configuring client mTLS"
                    .to_string(),
            );
        }

        if let Some(ref ca_path) = tls_ca_file {
            load_certs(ca_path, "MU_SMOKE_TLS_CA_FILE")?;
        }
        if let (Some(ref cert_path), Some(ref key_path)) = (&tls_cert_file, &tls_key_file) {
            load_certs(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            load_key(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
        }

        let bearer_token = match non_empty_path(&lookup, "MU_SMOKE_BEARER_TOKEN_FILE")? {
            Some(path) => Some(read_trimmed_secret(&path, "MU_SMOKE_BEARER_TOKEN_FILE")?),
            None => None,
        };

        let timeout_secs = match non_empty_var(&lookup, "MU_SMOKE_TIMEOUT_SECS") {
            Some(raw) => {
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': {e}"))?;
                if parsed == 0 {
                    return Err("MU_SMOKE_TIMEOUT_SECS must be greater than 0".to_string());
                }
                parsed
            }
            None => DEFAULT_SMOKE_TIMEOUT_SECS,
        };

        let target_addr = non_empty_var(&lookup, "MU_SMOKE_TARGET_ADDR")
            .or_else(|| non_empty_var(&lookup, "MU_SMOKE_TARGET_URL"))
            .map(|raw| normalize_target_addr(&raw));

        let server_name = non_empty_var(&lookup, "MU_SMOKE_TLS_SERVER_NAME");

        Ok(Self {
            target_addr,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            server_name,
            bearer_token,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn normalize_target_addr(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let stripped = trimmed
        .strip_prefix("tls://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

fn non_empty_var<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn non_empty_path<F>(lookup: &F, key: &str) -> Result<Option<PathBuf>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err(format!("{key} was set but empty"))
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        None => Ok(None),
    }
}

fn read_trimmed_secret(path: &Path, var_name: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Failed to read {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{var_name} at '{}' is empty after trimming (fail closed)",
            path.display()
        ));
    }
    Ok(trimmed.to_string())
}

fn load_certs(path: &Path, var_name: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            format!(
                "Invalid PEM certificate in {var_name} at '{}': {e}",
                path.display()
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "{var_name} at '{}' contains zero certificates",
            path.display()
        ));
    }
    Ok(certs)
}

fn load_key(path: &Path, var_name: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| {
        format!(
            "Invalid PEM private key in {var_name} at '{}': {e}",
            path.display()
        )
    })
}

fn build_tls_connector(
    ca_path: &Path,
    client_identity: Option<(&Path, &Path)>,
) -> Result<TlsConnector, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca_certs = load_certs(ca_path, "MU_SMOKE_TLS_CA_FILE")?;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| format!("Failed adding CA cert to root store: {e}"))?;
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
    let client_cfg = match client_identity {
        Some((cert_path, key_path)) => {
            let certs = load_certs(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            let key = load_key(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("Invalid client mTLS cert/key pair: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };

    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

fn server_name_from_addr(target_addr: &str, override_name: Option<&str>) -> ServerName<'static> {
    if let Some(name) = override_name {
        return ServerName::try_from(name.to_string()).expect("valid server name override");
    }
    let host = if let Some(rest) = target_addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(target_addr)
    } else {
        target_addr.split(':').next().unwrap_or(target_addr)
    };
    ServerName::try_from(host.to_string()).expect("valid host server name")
}

struct EphemeralPki {
    ca_path: PathBuf,
    srv_cert_path: PathBuf,
    srv_key_path: PathBuf,
    cli_cert_path: PathBuf,
    cli_key_path: PathBuf,
    rogue_cert_path: PathBuf,
    rogue_key_path: PathBuf,
}

fn generate_ephemeral_pki(dir: &Path) -> EphemeralPki {
    let mut ca_params = CertificateParams::new(vec!["mu-cd-agent-smoke-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mu-cd-agent-smoke-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let srv_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_issuer).unwrap();

    let cli_params = CertificateParams::new(vec!["mu-cd-controller".to_string()]).unwrap();
    let cli_key = KeyPair::generate().unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_issuer).unwrap();

    // Rogue CA & client certificate to verify untrusted client rejection
    let mut rogue_ca_params = CertificateParams::new(vec!["rogue-ca".to_string()]).unwrap();
    rogue_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let rogue_ca_key = KeyPair::generate().unwrap();
    let rogue_issuer = Issuer::from_params(&rogue_ca_params, &rogue_ca_key);
    let rogue_cli_params = CertificateParams::new(vec!["rogue-client".to_string()]).unwrap();
    let rogue_cli_key = KeyPair::generate().unwrap();
    let rogue_cli_cert = rogue_cli_params
        .signed_by(&rogue_cli_key, &rogue_issuer)
        .unwrap();

    let ca_path = dir.join("ca.crt");
    let srv_cert_path = dir.join("server.crt");
    let srv_key_path = dir.join("server.key");
    let cli_cert_path = dir.join("client.crt");
    let cli_key_path = dir.join("client.key");
    let rogue_cert_path = dir.join("rogue-client.crt");
    let rogue_key_path = dir.join("rogue-client.key");

    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&srv_cert_path, srv_cert.pem()).unwrap();
    std::fs::write(&srv_key_path, srv_key.serialize_pem()).unwrap();
    std::fs::write(&cli_cert_path, cli_cert.pem()).unwrap();
    std::fs::write(&cli_key_path, cli_key.serialize_pem()).unwrap();
    std::fs::write(&rogue_cert_path, rogue_cli_cert.pem()).unwrap();
    std::fs::write(&rogue_key_path, rogue_cli_key.serialize_pem()).unwrap();

    EphemeralPki {
        ca_path,
        srv_cert_path,
        srv_key_path,
        cli_cert_path,
        cli_key_path,
        rogue_cert_path,
        rogue_key_path,
    }
}

async fn assert_unauthenticated_rejected(
    target_addr: &str,
    server_name: ServerName<'static>,
    ca_path: Option<&Path>,
    rogue_identity: Option<(&Path, &Path)>,
    timeout: Duration,
) {
    let fory = create_fory_runtime().expect("fory runtime");
    let hb = HeartbeatTelemetry {
        node_id: "smoke-probe".to_string(),
        active_deployments: 0,
        btrfs_free_bytes: 0,
        timestamp_epoch_ms: 1,
    };
    let hb_bytes = fory.serialize(&hb).unwrap();
    let hdr = IpcHeader::new(MSG_TYPE_HEARTBEAT, hb_bytes.len() as u32, 0, 99);

    // 1. Raw plaintext connection without TLS must never receive a HEARTBEAT frame
    let tcp_res = tokio::time::timeout(timeout, TcpStream::connect(target_addr)).await;
    if let Ok(Ok(mut raw_tcp)) = tcp_res {
        let _ = write_frame(&mut raw_tcp, &hdr, &hb_bytes).await;
        let read_res = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut raw_tcp)).await;
        assert!(
            !matches!(read_res, Ok(Ok(_))),
            "plaintext TCP connection without mTLS must be rejected fail-closed"
        );
    }

    // 2. TLS connection without a client certificate must fail closed
    if let Some(ca) = ca_path {
        let no_client_conn = build_tls_connector(ca, None).unwrap();
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
            .await
            .expect("tcp connect timeout")
            .expect("tcp connect");
        if let Ok(Ok(mut tls_stream)) =
            tokio::time::timeout(timeout, no_client_conn.connect(server_name.clone(), tcp)).await
        {
            let _ = write_frame(&mut tls_stream, &hdr, &hb_bytes).await;
            let frame_res =
                tokio::time::timeout(Duration::from_secs(2), read_frame(&mut tls_stream)).await;
            assert!(
                !matches!(frame_res, Ok(Ok(_))),
                "TLS connection missing client cert must not receive IPC response"
            );
        }

        // 3. Untrusted client cert signed by a rogue CA must fail closed
        if let Some((rogue_cert, rogue_key)) = rogue_identity {
            let rogue_conn = build_tls_connector(ca, Some((rogue_cert, rogue_key))).unwrap();
            let tcp = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
                .await
                .expect("tcp connect timeout")
                .expect("tcp connect");
            if let Ok(Ok(mut tls_stream)) =
                tokio::time::timeout(timeout, rogue_conn.connect(server_name, tcp)).await
            {
                let _ = write_frame(&mut tls_stream, &hdr, &hb_bytes).await;
                let frame_res =
                    tokio::time::timeout(Duration::from_secs(2), read_frame(&mut tls_stream)).await;
                assert!(
                    !matches!(frame_res, Ok(Ok(_))),
                    "TLS connection with untrusted client cert must fail closed"
                );
            }
        }
    }
}

async fn run_mtls_heartbeat_probe(
    target_addr: &str,
    server_name: ServerName<'static>,
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
    timeout: Duration,
) -> HeartbeatTelemetry {
    let connector = build_tls_connector(ca_path, Some((cert_path, key_path)))
        .expect("build mTLS client connector");
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
        .await
        .expect("TCP connect timeout")
        .expect("TCP connect to mu-cd-agent");
    let mut tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .expect("mTLS handshake timeout")
        .expect("mTLS handshake with mu-cd-agent");

    let fory = create_fory_runtime().expect("create fory runtime");
    let req_hb = HeartbeatTelemetry {
        node_id: "smoke-probe-client".to_string(),
        active_deployments: 0,
        btrfs_free_bytes: 0,
        timestamp_epoch_ms: 1_700_000_000_000,
    };
    let payload = fory.serialize(&req_hb).expect("serialize heartbeat");
    let req_seq = 4242u64;
    let req_hdr = IpcHeader::new(MSG_TYPE_HEARTBEAT, payload.len() as u32, 0, req_seq);

    tokio::time::timeout(timeout, write_frame(&mut tls_stream, &req_hdr, &payload))
        .await
        .expect("heartbeat write timeout")
        .expect("write heartbeat frame");

    let (resp_hdr, resp_payload) = tokio::time::timeout(timeout, read_frame(&mut tls_stream))
        .await
        .expect("heartbeat read timeout")
        .expect("read heartbeat response frame");
    assert_eq!(resp_hdr.msg_type, MSG_TYPE_HEARTBEAT);
    assert_eq!(resp_hdr.sequence, req_seq);

    let resp_hb: HeartbeatTelemetry = fory
        .deserialize(&resp_payload)
        .expect("deserialize HeartbeatTelemetry");
    assert!(!resp_hb.node_id.trim().is_empty());
    assert!(resp_hb.timestamp_epoch_ms > 0);
    resp_hb
}

#[test]
#[cfg_attr(miri, ignore)]
fn smoke_config_validates_tls_and_bearer_paths_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let pki = generate_ephemeral_pki(temp.path());
    let token_path = temp.path().join("bearer.token");
    std::fs::write(&token_path, "  smoke-agent-token \n").unwrap();

    let ok_env = HashMap::from([
        ("MU_SMOKE_TARGET_ADDR", "127.0.0.1:8446".to_string()),
        (
            "MU_SMOKE_TLS_CA_FILE",
            pki.ca_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CERT_FILE",
            pki.cli_cert_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_KEY_FILE",
            pki.cli_key_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_BEARER_TOKEN_FILE",
            token_path.to_string_lossy().into_owned(),
        ),
    ]);
    let cfg = SmokeConfig::from_lookup(|k| ok_env.get(k).cloned()).unwrap();
    assert_eq!(cfg.target_addr.as_deref(), Some("127.0.0.1:8446"));
    assert_eq!(cfg.timeout, Duration::from_secs(10));

    // Missing CA file must fail closed
    let missing_ca = HashMap::from([(
        "MU_SMOKE_TLS_CA_FILE",
        temp.path()
            .join("missing-ca.crt")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_ca.get(k).cloned()).is_err());

    // Missing client key file must fail closed
    let missing_key = HashMap::from([
        (
            "MU_SMOKE_TLS_CERT_FILE",
            pki.cli_cert_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_KEY_FILE",
            temp.path()
                .join("missing.key")
                .to_string_lossy()
                .into_owned(),
        ),
    ]);
    assert!(SmokeConfig::from_lookup(|k| missing_key.get(k).cloned()).is_err());

    // Unreadable bearer token file must fail closed
    let missing_token = HashMap::from([(
        "MU_SMOKE_BEARER_TOKEN_FILE",
        temp.path()
            .join("missing.token")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_token.get(k).cloned()).is_err());
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_mu_cd_agent_mtls_heartbeat_and_fail_closed_rejection() {
    let cfg = SmokeConfig::from_env().expect("valid MU_SMOKE_* environment configuration");

    if let Some(ref target_addr) = cfg.target_addr {
        let ca = cfg
            .tls_ca_file
            .as_deref()
            .expect("MU_SMOKE_TLS_CA_FILE required in live mTLS agent probe mode");
        let cert = cfg
            .tls_cert_file
            .as_deref()
            .expect("MU_SMOKE_TLS_CERT_FILE required in live mTLS agent probe mode");
        let key = cfg
            .tls_key_file
            .as_deref()
            .expect("MU_SMOKE_TLS_KEY_FILE required in live mTLS agent probe mode");
        let server_name = server_name_from_addr(target_addr, cfg.server_name.as_deref());

        assert_unauthenticated_rejected(
            target_addr,
            server_name.clone(),
            Some(ca),
            None,
            cfg.timeout,
        )
        .await;
        let _hb =
            run_mtls_heartbeat_probe(target_addr, server_name, ca, cert, key, cfg.timeout).await;
        return;
    }

    // Ephemeral mode: spin up real MuConDeAgent mTLS listener on 127.0.0.1:0
    let temp = tempfile::tempdir().unwrap();
    let pki = generate_ephemeral_pki(temp.path());
    let muconde_root = temp.path().join("muconde-root");
    std::fs::create_dir_all(&muconde_root).unwrap();

    let runner = Arc::new(MockCommandRunner::new(false));
    let prober = Arc::new(MockHealthProber::new(true));
    let agent_cfg = MuConDeAgentConfig {
        node_id: "node-a".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        muconde_root: muconde_root.clone(),
        tls_ca_path: Some(pki.ca_path.clone()),
        tls_cert_path: Some(pki.srv_cert_path.clone()),
        tls_key_path: Some(pki.srv_key_path.clone()),
        ..Default::default()
    };

    let agent = Arc::new(MuConDeAgent::new(agent_cfg, runner.clone(), prober));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bound_addr = listener.local_addr().unwrap().to_string();
    let agent_task = tokio::spawn(async move {
        let _ = agent.run_with_listener(listener).await;
    });

    let server_name = server_name_from_addr(&bound_addr, Some("localhost"));
    assert_unauthenticated_rejected(
        &bound_addr,
        server_name.clone(),
        Some(&pki.ca_path),
        Some((&pki.rogue_cert_path, &pki.rogue_key_path)),
        cfg.timeout,
    )
    .await;

    let hb = run_mtls_heartbeat_probe(
        &bound_addr,
        server_name,
        &pki.ca_path,
        &pki.cli_cert_path,
        &pki.cli_key_path,
        cfg.timeout,
    )
    .await;
    assert_eq!(hb.node_id, "node-a");
    assert_eq!(hb.active_deployments, 0);

    // Zero Btrfs/systemd/slot mutations occurred
    assert!(
        runner.calls.lock().unwrap().is_empty(),
        "heartbeat smoke probe must execute zero Btrfs or systemd commands"
    );
    assert_eq!(
        std::fs::read_dir(&muconde_root).unwrap().count(),
        0,
        "heartbeat smoke probe must not create or alter slot directories"
    );

    agent_task.abort();
}
