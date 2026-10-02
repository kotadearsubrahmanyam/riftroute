# RiftRoute Phase 4 — Relay Node Architecture

## 1. System Overview

**RiftRoute** is an India-first gaming network intelligence and route optimization platform.
**Phase 4** introduces the **Relay Node Architecture & Evaluation** subsystem.

The fundamental engineering mandate of Phase 4 is:
> **RELAY INFRASTRUCTURE + MEASUREMENT ONLY.**
> Build the relay and measure the relay. DO NOT use the relay to carry live game traffic.

```
+-----------------------------------------------------------------------------+
|                                RIFTROUTE CLIENT                              |
|                          (core/rust/rift-baseline)                          |
|                                                                             |
|  +-----------------------+     +-------------------+     +----------------+  |
|  | RouteIntelligence     |     | RelayRegistry     |     | Comparison     |  |
|  | (Direct Tracert Probes|     | (Candidate Nodes) |     | Engine (Deltas)|  |
|  +-----------+-----------+     +---------+---------+     +-------+--------+  |
|              |                           |                       |           |
|              |                           v                       |           |
|              |                 +-------------------+             |           |
|              |                 | RelayClient       |             |           |
|              |                 | (Ed25519 Handshake|             |           |
|              |                 +---------+---------+             |           |
+--------------|---------------------------|-----------------------|-----------+
               |                           | (TCP 44321 Control)   |
               |                           | Length-Framed JSON    |
               |                           v                       |
               |                 +-------------------+             |
               |                 | RIFTROUTE RELAY   |             |
               |                 | (core/rust/       |             |
               |                 |  rift-relay)      |             |
               |                 |                   |             |
               |                 | * Daemon Server   |             |
               |                 | * AuthManager     |             |
               |                 | * HealthTracker   |             |
               |                 | * Probe Engine    |             |
               |                 +---------+---------+             |
               |                           | (Safe Ping/TCP Probe) |
               v                           v                       v
+-----------------------------------------------------------------------------+
|                            DESTINATION GAME SERVER                          |
|                             (e.g., 1.1.1.1, AWS, Azure)                     |
+-----------------------------------------------------------------------------+
```

---

## 2. Workspace & Crate Decomposition

The codebase is organized into a Cargo workspace with two decoupled crates:

1. **`rift-relay` (`core/rust/rift-relay`)**:
   - Standalone, cross-platform Linux and Windows relay daemon (`rift-relay.exe` / `rift-relay`).
   - Unprivileged daemon providing diagnostic probe execution via TCP control channel.
   - Manages cryptographic identity, challenge nonces, session TTLs, and health metrics.
   - Contains zero client logic and zero route optimization code.

2. **`rift-baseline` (`core/rust/rift-baseline`)**:
   - Primary diagnostic CLI and analysis platform.
   - Interacts with `rift-relay` via `rift_baseline::relay::client::RelayClient`.
   - Manages local candidate registry (`data/relay/registry.json`).
   - Executes direct path baseline measurements and compares them objectively against composed relay measurements.

---

## 3. Remote Infrastructure Disclosure

In accordance with Phase 4 governance requirements:
- **`REMOTE_RELAY_VALIDATION = NOT_AVAILABLE`**
  No external VPS was provisioned by the user during this session. In strict compliance with the anti-hallucination mandate, remote cloud deployment was NOT faked.
- **`LOCAL_RELAY_VALIDATION = VERIFIED`**
  Full end-to-end functionality (daemon initialization, TCP binding, cryptographic handshake, ping probing, health tracking, and comparison calculations) was verified against the local relay node (`relay_local_01` on `127.0.0.1:44321`).

Seeded candidate nodes (`relay_in_mum_01`, `relay_in_maa_01`, `relay_sg_sin_01`) remain marked as `Unverified` and `Offline` in the registry until authentic cloud infrastructure is connected.

---

## 4. Deployment Models

### 4.1 Container Deployment (Docker)
- Hardened multi-stage [Dockerfile](file:///d:/network%20optimiser/docker/relay/Dockerfile) using `debian:bookworm-slim`.
- Drops all Linux capabilities except `CAP_NET_RAW` (required for ICMP sockets).
- Runs as dedicated unprivileged user `riftrelay` (UID 10001).
- Orchestrated via [compose.yaml](file:///d:/network%20optimiser/docker/relay/compose.yaml) with read-only root filesystem.

### 4.2 Host Service Deployment (systemd)
- Hardened [rift-relay.service](file:///d:/network%20optimiser/deploy/systemd/rift-relay.service) unit.
- Sandboxed with `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, and `PrivateDevices=yes`.
- Restricts address families to `AF_INET AF_INET6 AF_UNIX`.
