# RiftRoute Phase 4 — Measurement & Path Composition

## 1. Composed Path Latency Arithmetic

A central scientific principle of RiftRoute is that a relay-assisted path is composed of two distinct physical network segments:

1. **Leg 1**: Client $\to$ Relay transit latency ($RTT_{C \to R}$).
2. **Leg 2**: Relay $\to$ Destination transit latency ($RTT_{R \to D}$).

The composed latency estimate is calculated as:

$$\text{Composed RTT Estimate} = RTT_{C \to R} + RTT_{R \to D}$$

### 1.1 Strict Empirical Labeling
To prevent confusing arithmetic estimates with live game traffic latency, the data model explicitly distinguishes composed estimates from direct measurements:

```json
{
  "client_to_relay_probe_rtt_ms": 0.28,
  "relay_to_destination_probe_rtt_ms": 11.00,
  "composed_relay_rtt_ms": 11.28,
  "is_composed_estimate": true,
  "scientific_disclaimer": "Composed relay path latency is a diagnostic arithmetic estimate (leg 1 + leg 2) and reflects ICMP control-plane RTT, not in-game UDP gameplay latency."
}
```

---

## 2. Direct vs. Relay Path Comparison Metrics

When comparing a direct path against a candidate relay path, the comparison engine calculates the following metrics:

### 2.1 Latency Deltas
- **Median RTT Delta**:
  $$\Delta_{\text{median}} = \text{Composed RTT} - \text{Direct Median RTT}$$
- **p95 Latency Delta**:
  $$\Delta_{p95} = \text{Composed } p95 - \text{Direct } p95$$
- **Jitter Delta**:
  $$\Delta_{\text{jitter}} = \text{Composed Jitter} - \text{Direct Jitter}$$

### 2.2 Overhead Metrics
- **Network Path Overhead**:
  The additional roundtrip network latency introduced by diverting traffic through the intermediate relay node.
- **Control Plane Overhead**:
  The wall-clock duration required to conduct mutual authentication, issue diagnostic commands, execute remote probes, and retrieve framed results.

### 2.3 Route Divergence Analysis
The engine compares the canonical route fingerprint of the direct path against the fingerprint of Leg 2 (Relay $\to$ Destination), identifying:
- Divergence points in intermediate autonomous systems (ASNs).
- Intermediate transit providers used by the relay vs. the client's direct ISP.
- Total hop count variance.

---

## 3. Objective Reporting & No Premature Optimization

In accordance with Phase 4 guidelines:
1. **NO "Best Relay" Selection**:
   The engine reports factual measurements only. It does not rank or automatically switch traffic to any relay.
2. **Transparency on Overhead**:
   If a relay introduces latency overhead (e.g. $+0.28\text{ ms}$ on localhost or $+15\text{ ms}$ due to geometric detours), this overhead is highlighted transparently in both text and JSON outputs.
3. **Observation-Only Rule**:
   All measurements are conducted via ICMP Echo and TCP SYN probes. No gaming traffic is diverted or simulated.
