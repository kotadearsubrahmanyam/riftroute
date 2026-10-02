# RiftRoute Phase 3 — Route Degradation Detection Engine

## 1. Performance Baseline Model

The monitoring engine establishes an empirical baseline before evaluating degradation.

### Initial Establishment
- A minimum number of initial valid samples (`baseline_sample_count`, default: 5) must be collected.
- Statistical metrics computed across the initial sample window:
  - Median RTT ($p_{50}$)
  - 95th Percentile RTT ($p_{95}$)
  - 99th Percentile RTT ($p_{99}$)
  - Min / Max RTT
  - Standard Deviation
  - Mean Absolute Packet Delay Variation (MAPDV Jitter)
  - Dominant Route Fingerprint (most frequent SHA-256 canonical path hash)
  - Route Transition Rate (%)
  - Median Hop Count

### Rolling Window Adaptation
- Once established, the baseline adapts to long-term diurnal network trends using a rolling window of recent samples (`rolling_window_size`, default: 20 samples).

---

## 2. Baseline Contamination Protection (The "Contamination Shield")

### The Problem
If a network path experiences persistent degradation (e.g. latency jumping from 60 ms to 150 ms due to international transit congestion), a naïve rolling baseline would incorporate the degraded 150 ms samples. After 20 samples, the baseline would become 150 ms, falsely declaring the degraded route "Normal" and resolving the alert prematurely.

### The RiftRoute Solution
The `BaselineEngine` implements active **Contamination Protection**:
1. When the session state transitions to `Suspected` or `Degraded`, the baseline is immediately **FROZEN** (`is_frozen = true`).
2. Degraded samples are recorded in the session history for auditing, but **excluded from baseline recalculation**.
3. The baseline remains anchored at its pre-incident healthy parameters until confirmed recovery has taken place (`Recovered` event emitted).

```
   State == Normal:    [Sample N] ----> Rolling Window Update ----> Baseline Updates
   State == Degraded:  [Sample N] ----> Contamination Shield ----> Baseline FROZEN (No Drift)
```

---

## 3. The Core Diagnostic Law: ROUTE_CHANGED != ROUTE_DEGRADED

A fundamental networking tenet implemented in RiftRoute is that a change in route path (e.g., BGP route flapping, upstream ISP multi-homing shifts) is **NOT** inherently an incident of network degradation:

- A path change that results in identical or lower latency is recorded as `RouteChanged` with severity `Info`.
- The session state remains `Normal`.
- Only if the path shift is accompanied by sustained latency or jitter degradation does the engine escalate to `Degraded`.

---

## 4. Evaluation Thresholds & Hysteresis

To eliminate false alarms caused by transient consumer broadband spikes, the evaluation engine enforces two-layer hysteresis:

### Dual Latency Condition
An observation is anomalous only if it violates **both** relative and absolute constraints:
$$\Delta \text{RTT} \ge \text{latency\_absolute\_delta\_ms} \quad (20\text{ ms})$$
$$\frac{\Delta \text{RTT}}{\text{Baseline RTT}} \times 100\% \ge \text{latency\_relative\_pct} \quad (30\%)$$

### Confirmation Hysteresis (Persistence)
- **1st Anomaly**: State transitions from `Normal` to `Suspected`. No degradation event is emitted.
- **2nd Anomaly**: State remains `Suspected`.
- **3rd Anomaly**: If `consecutive_anomalous_samples >= confirmation_samples` (default: 3), the degradation is declared confirmed. State transitions to `Degraded` and an audited event is recorded.
- **Transient Spike**: If sample 2 returns to normal, the state resets immediately from `Suspected` to `Normal` with zero noise.

### Recovery Hysteresis
- When in `Degraded` state, returning to normal values transitions to `Recovering`.
- It requires `recovery_samples` (default: 3) consecutive normal samples before declaring full restoration (`Recovered` event).
