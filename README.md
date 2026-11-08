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

---

Node-level continuous delivery daemon executing atomic filesystem operations, dual A/B root subvolume switching, health probes, and autonomous watchdog rollbacks.

Resident systemd daemon operating natively across heterogeneous cluster nodes: SpacemiT K3 RISC-V (`worker-riscv64`), Intel N100 (`node-a`), and Intel Xeon (`storage-node`).

---

## Core Capabilities

- **Dual A/B Btrfs Root Slots**:
  - Maintains dual root subvolume slots (`@root_a` for active production, `@root_b` for canary staging).
  - Isolates ephemeral staging state with shared persistent data (`@data`, `@logs`).
- **Atomic Subvolume Snapshots**:
  - Uses instantaneous Btrfs CoW snapshots (`btrfs subvolume snapshot`).
  - Creates pre-deployment rollback anchor snapshots prior to stage mutation.
- **Local Health Probes & Watchdogs**:
  - Executes local HTTP, TCP, and systemd unit readiness probes against the staged service in Slot B.
  - Streams real-time probe telemetry to `mu-cd-controller` over `mu-cd-ipc`.
- **Autonomous Rollback Watchdog**:
  - Enforces local hardware and software lease watchdogs.
  - If controller heartbeat or lease renewal drops during an in-flight deployment, the agent autonomously reverts the active subvolume and restarts production services in < 1 second.

---

## Btrfs Subvolume Topology

```text
/dev/nvme0n1p2 (Btrfs Pool)
├── @root_a          (Active Slot A - mounted at /)
├── @root_b          (Staging Slot B - mounted at /mnt/slot_b during canary)
├── @snapshots/      (Pre-deployment anchor snapshots: @root_a_snap_<timestamp>)
├── @data            (Shared persistent application state)
└── @logs            (Unified systemd and audit journals)
```

---

## Autonomous Rollback Automata

```text
[ Controller Commands ] ──> Lease (TTL: 300s)
                                │
                ┌───────────────┴───────────────┐
                ▼                               ▼
        [ Health Probes Pass ]          [ Health Probe Fail OR Lease Expired ]
                │                               │
                ▼                               ▼
      Atomic Promotion Swap           Autonomous Btrfs Snapshot Rollback
   (@root_b promoted to active)      (Revert to @root_a_snap_<timestamp>)
```

---

## Integration-Gate Progress (`IntegrationTestProgress`)

After every `SlotSwapCommand` the agent streams per-test progress on the same connection
(`MSG_TYPE_IT_PROGRESS = 0x0C`, `mu-cd-ipc` 0.2.0) so the controller and MuConsole can show
the gate live:

1. `Pending` for every test in the gate (the contract's `integration_tests`, with `"all"` expanded
   to the agent's catalog), all with `duration_ms = 0`.
2. `Running` for every test once the warmup watchdog starts.
3. `Passed` / `Failed` with `duration_ms`, before the existing aggregate `IntegrationTestReport`
   (which remains the final verdict) and `ArtifactTaintNotification` on rollback.

| Test | Critical | Verdict |
|---|---|---|
| `systemd_unit_active` | yes | unit reached `ActiveState=active` during warmup |
| `health_endpoint_ready` | yes | local health endpoint accepted connections during warmup |

- `MUCONDE_INTEGRATION_TESTS` (optional): `all` (default) or a comma-separated list. Names the
  agent cannot execute are logged and skipped.
- Progress frames are best-effort: a write failure (for example a 0.1.x controller that closed the
  stream) never aborts the gate. Old controllers skip the unknown `0x0C` frames.

---

## Operational Invariants

1. **Non-Destructive Rollback**: Rollback operations restore exact verified Btrfs snapshots; never perform blind directory deletions or partial cleanup.
2. **Atomic Binary Installation**: Daemon and service binary updates strictly use `install -m 755` rather than `cp` to avoid `ETXTBSY` (Text file busy) execution errors.
3. **Fail-Closed Watchdog**: In the event of network partition during active staging, the local agent defaults to rolling back Slot B rather than leaving unverified services running.

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
