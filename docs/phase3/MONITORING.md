# RiftRoute Phase 3 — Dynamic Route Performance Monitoring

## 1. Architectural Overview

Phase 3 introduces continuous, deterministic, and non-invasive **Dynamic Route Performance Monitoring & Path Degrade Detection** for RiftRoute. Building upon the foundation of Phase 0 (System Inventory & Baseline Diagnostics), Phase 0.5 (Passive UDP Flow Analysis), Phase 1 (Route Intelligence & Fingerprinting), and Phase 2 (Candidate Path Discovery & Evaluation), Phase 3 operates strictly under the **OBSERVATION ONLY** principle.

```
       +-------------------------------------------------------+
       |             RiftRoute Monitoring Engine               |
       |                                                       |
       |   +-------------------+       +-------------------+   |
       |   | Target Resolution | ----> | Safe Windows      |   |
       |   | (Manual/Candidate)|       | Tracert Dispatch  |   |
       |   +-------------------+       +-------------------+   |
       |                                         |             |
       |                                         v             |
       |   +-------------------+       +-------------------+   |
       |   | Baseline Shield   | <---- | Sample Processing |   |
       |   | (Contamination)   |       | & Extraction      |   |
       |   +-------------------+       +-------------------+   |
       |             |                           |             |
       |             v                           v             |
       |   +-------------------+       +-------------------+   |
       |   | 4-State Machine   | ----> | Audited Event     |   |
       |   | (Hysteresis)      |       | Persistence       |   |
       |   +-------------------+       +-------------------+   |
       +-------------------------------------------------------+
```

### Governing Rule: Observation Only
Phase 3 detects and reports degradation. It **does NOT**:
- Modify Windows routing tables
- Perform route switching or rerouting
- Deploy or connect to VPNs or WireGuard tunnels
- Deploy proxies, relays, or shadow infrastructure
- Intercept, modify, or inject packets (no WFP, no WinDivert)
- Change DNS, firewall, or adapter settings
- Select a "best route" or rank routing alternatives

Every output produced follows the core formula:
$$\text{Output} = \text{Measurement} + \text{Baseline} + \text{Deviation} + \text{Audited Event}$$

---

## 2. Measurement Pacing and Safety

To prevent self-induced network congestion and preserve local network stability, monitoring follows strict pacing rules:

1. **Sequential Single-Target Execution**: Probes are dispatched strictly sequentially. No overlapping traceroute processes are ever initiated.
2. **Deterministic Interval Pacing**: Configurable cycle pacing (default: 30 seconds, bounded tests: 5 seconds). If a measurement takes longer than the interval, the scheduler proceeds immediately to the next cycle without queuing concurrent processes.
3. **Safety Timeout**: Every probe execution is bound by Windows process safety timeouts (`timeout_secs`, default 120s), preventing hung child processes.
4. **Graceful Cancellation**: Controlled shutdown is supported via thread-safe `Arc<AtomicBool>` flags or sample-count limits.

---

## 3. Candidate Path Integration

Monitoring targets can be initialized from:
1. **Directly Observed Sockets**: Discovered through Phase 0.5 and Phase 2 candidate extraction (e.g. `20.205.179.128:27528`).
2. **Candidate ID**: Resolved from existing candidate inventories in `data/route/candidates/`.
3. **Explicit Destination**: User-specified IP address or hostname.

The target definition preserves endpoint identity, service name, transport protocol, target port, and `EvidenceLevel` (`DirectlyObserved`, `CorroboratedGameCluster`, `AssociatedGameService`, `InferredTelemetry`).

---

## 4. Scientific Integrity & Disclaimers

Every monitoring sample, report, and event emitted contains the mandatory scientific disclaimer:

> **Traceroute RTT reflects ICMP control-plane generation latency, not in-game UDP gameplay latency. Route degradation events indicate empirical path variation and do not modify network routing.**

Key diagnostic distinctions enforced:
- **Probe RTT vs Game Ping**: Intermediate and final-hop traceroute times measure ICMP Time Exceeded generation on router control planes, labeled as `final_hop_rtt_ms` / `probe_final_hop_rtt_ms`, never as `pubg_ping_ms`.
- **Timeouts (`*`)**: Intermediate hops timing out indicate control-plane rate limiting or firewall ACLs, and must **never** be reported as game packet loss.
