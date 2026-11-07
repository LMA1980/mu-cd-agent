---
name: mu-cd-agent
description: "Execute atomic binary installation, dual A/B subvolume switching, health probes, and watchdog rollbacks with mu-cd-agent."
---

# `mu-cd-agent` Node Deployment & Atomic Rollout Invariants

## 1. Atomic Binary & Subvolume Switching

- Always install updated service binaries atomically (e.g., staging + `rename` or `install -m 755`) instead of in-place `cp` to prevent `Text file busy` (`ETXTBSY`) errors on running systemd daemons.
- Stream integration-test progress events over `mu-cd-ipc` during pre-activation checks and enforce autonomous watchdog rollbacks if post-switch health probes fail.
