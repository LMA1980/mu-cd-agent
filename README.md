# mu-cd-agent

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-cd-agent/card.svg" alt="mu-cd-agent Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-agent/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-agent/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-agent/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-cd-agent/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

Node-level continuous delivery daemon in the [`mu-cd`](https://github.com/LMA1980/mu-cd) workspace executing per-service A/B Btrfs subvolume staging, atomic symlink switching, sandboxed integration-test (IT) bundle verification, health probes, and autonomous lease-watchdog rollbacks.

Resident systemd daemon operating natively across heterogeneous cluster nodes: SpacemiT K3 RISC-V (`worker-riscv64`), Intel N100 (`node-a`), and Intel Xeon (`node-b`), driven by [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller) over [`mu-cd-ipc`](https://github.com/LMA1980/mu-cd-ipc).

______________________________________________________________________

## Core Capabilities

- **Per-Service Symmetric A/B Btrfs Slots (`@a` \<-> `@b`)**:
  - Stages allowlisted platform services (`ALLOWED_SERVICES`) into isolated per-service Btrfs subvolumes under `MUCONDE_ROOT` (`/srv/muconde/<service>/@a` and `@b`, never the host OS rootfs).
  - Maintains `<service>/current` as an atomic symlink pointing to the active slot (`@a` or `@b`), alternating symmetrically across deployments.
  - Supports static web bundle staging (`dist/`) into `web_root` under `/var/www/` or `/srv/www/` (for `mu-console` / `mu-ci-web`) with `nginx.service` reload, as well as daemon binary installation (`install -m 755`) and `systemd` unit lifecycle control.
- **Pre-Deployment Anchor Snapshots & Retention**:
  - Creates read-only Btrfs CoW snapshots (`btrfs subvolume snapshot -r`) into `/srv/muconde/<service>/snapshots/@snap-<digest>` prior to mutating the candidate slot, pruning older snapshots per `ab_rules.keep_snapshots`.
- **CAS & `mu-registry` IT Bundle Verification + `KernelSandbox` Gate**:
  - Fetches candidate release artifacts and `.tar.gz` integration-test (IT) archives from local CAS blob storage (`MUCONDE_CAS_BLOBS_DIR` / `MUREGIST_CAS_BLOBS_DIR`) or [`mu-registry`](https://github.com/LMA1980/mu-registry) (`MUCONDE_REGISTRY_URL` / `MUREGIST_URL`).
  - Verifies SHA-256 digests (`validate_sha256_digest`, `verify_sha256_bytes`), safely unpacks bounded archives (`MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES = 64 MiB`), and runs preselected tests inside [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation) `KernelSandbox` (`MAX_IT_SANDBOX_PIDS = 256`, `DEFAULT_IT_MEMLOCK_KB = 65_536`).
- **Local Health Probes, Watchdogs & OTEL Telemetry**:
  - Executes warmup health probes against the swapped slot, enforces TTL deployment lease watchdogs for autonomous sub-second rollback on heartbeat/lease expiry, and streams `MUOB`-framed OTEL spans/logs (`mu-observable-ipc`) to [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector) (`MUOBSERVE_COLLECTOR_ADDR`).

______________________________________________________________________

## Per-Service Btrfs Subvolume Layout (`MUCONDE_ROOT`)

```text
/srv/muconde/                          (MUCONDE_ROOT)
└── <service>/                         (allowlisted service name)
    ├── @a                             (Slot A subvolume / staged artifact or dist/)
    ├── @b                             (Slot B subvolume / staged artifact or dist/)
    ├── current -> @a | @b             (atomic symlink switched via rename)
    └── snapshots/
        ├── .retention.json            (ordered snapshot retention manifest)
        └── @snap-<digest>             (read-only Btrfs CoW rollback anchor)
```

For static web services (`mu-console`, `mu-ci-web`), `<service>/current/dist/` is deployed atomically to `web_root` (such as `/var/www/mu-ci-web` under `/var/www/` or `/srv/www/`).

______________________________________________________________________

## Autonomous Rollback Automata

```text
[ mu-cd-controller Commands ] ──> Lease (TTL: 300s)
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
     [ Warmup, Health Probes & IT Gate Pass ]   [ Gate Fail OR Lease Expired ]
                        │                               │
                        ▼                               ▼
          Commit Active Slot (@a <-> @b)    Atomic Symlink Rollback (<service>/current)
         (Next rollout targets other slot)    (Restore previous slot / @snap-<digest>)
```

______________________________________________________________________

## Integration-Gate Progress (`IntegrationTestProgress`)

After every `SlotSwapCommand`, the agent streams per-test progress on the same connection (`MSG_TYPE_IT_PROGRESS = 0x0C`, `mu-cd-ipc` 0.2.0) so [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller) and [`mu-console`](https://github.com/LMA1980/mu-console) display live gate status:

1. `Pending` for every test in the gate (contract `integration_tests`, with `"all"` expanded to the agent's catalog), with `duration_ms = 0`.
1. `Running` for every test once the warmup watchdog starts.
1. `Passed` / `Failed` with `duration_ms`, followed by the aggregate `IntegrationTestReport` (final verdict) and `ArtifactTaintNotification` on rollback.

| Test                    | Critical | Verdict                                                  |
| ----------------------- | -------- | -------------------------------------------------------- |
| `systemd_unit_active`   | yes      | unit reached `ActiveState=active` during warmup          |
| `health_endpoint_ready` | yes      | local health endpoint accepted connections during warmup |

- Progress frames are best-effort: write failures never abort the gate, and older controllers skip unknown `0x0C` frames.

______________________________________________________________________

## Configuration

| Variable                                                                     | Default             | Purpose                                                                                               |
| ---------------------------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------------------- |
| `MUCONDE_NODE_ID`                                                            | `worker-node`       | Logical node identifier (`node-a`, `node-b`, `worker-riscv64`)                                        |
| `MUCONDE_LISTEN_ADDR`                                                        | `0.0.0.0:8446`      | mTLS agent IPC listen address                                                                         |
| `MUCONDE_ROOT`                                                               | `/srv/muconde`      | Base directory for per-service `@a`/`@b`/`current`/`snapshots` subvolumes                             |
| `MUCONDE_TLS_CA_CERT` / `MUCONDE_TLS_SERVER_CERT` / `MUCONDE_TLS_SERVER_KEY` | unset               | `step-ca` mTLS credentials for `mu-cd-ipc`                                                            |
| `MUCONDE_MANIFEST_DIR`                                                       | `.`                 | Directory searched for `.mucd/mu-cd.yml` (fallback `.muconde/MuConDe.yml`)                            |
| `MUCONDE_INTEGRATION_TESTS`                                                  | `all` (or manifest) | `"all"` or comma-separated gate test selector                                                         |
| `MUCONDE_IT_ARCHIVE_DIGEST` / `MUCONDE_IT_BUNDLE_ID`                         | unset               | Optional CAS SHA-256 digest / bundle ID for sandboxed IT bundle execution                             |
| `MUCONDE_REGISTRY_URL` / `MUREGIST_URL`                                      | unset               | [`mu-registry`](https://github.com/LMA1980/mu-registry) endpoint for artifact and IT bundle downloads |
| `MUCONDE_REGISTRY_TOKEN_FILE` / `MUREGIST_TOKEN_FILE` (or `*_TOKEN`)         | unset               | Registry bearer token (file path fails closed if unreadable)                                          |
| `MUCONDE_CAS_BLOBS_DIR` / `MUREGIST_CAS_BLOBS_DIR`                           | unset               | Local CAS blob directory for direct digest lookup                                                     |
| `MUOBSERVE_COLLECTOR_ADDR`                                                   | unset               | [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector) `MUOB` TCP endpoint   |

______________________________________________________________________

## Operational Invariants

1. **Non-Destructive Rollback**: Rollback operations atomically restore `<service>/current` and verified Btrfs snapshots (`@snap-<digest>`); never perform blind directory deletions or partial cleanup.
1. **Atomic Binary Installation**: Daemon and service binary updates use `install -m 755` rather than `cp` to prevent `ETXTBSY` (Text file busy) errors.
1. **Fail-Closed Watchdog**: On lease expiry or network partition during staging, the agent rolls back the candidate slot rather than leaving unverified services running.

______________________________________________________________________

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See [LICENSE](LICENSE) for details.
