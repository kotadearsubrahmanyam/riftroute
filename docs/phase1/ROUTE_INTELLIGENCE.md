# RiftRoute Phase 1: Advanced Route Intelligence & Network Measurement Engine

## 1. Overview & Objective
Phase 1 transforms RiftRoute from endpoint-level traffic observation into an empirical network path measurement engine.

It establishes safe, non-invasive Windows route observation, robust multi-sample traceroute parsing, hop-level RTT extraction, deterministic route fingerprinting, pairwise route comparison, and longitudinal route stability analysis.

### Strict Phase Boundaries
- **In Scope:** Route observation, safe Windows `tracert` execution, parser normalization, hop RTT distribution statistics, deterministic route fingerprinting, snapshot comparison, route stability tracking, CLI integration, reports, and independent cross-validation.
- **Out of Scope (Forbidden):** Route optimization, route switching, VPN, WireGuard, relay servers, tunneling, packet injection, packet modification, WFP, WinDivert, firewall/DNS alterations, proxying, NAT manipulation, and AI/ML.

---

## 2. Core Scientific Rules

1. **Probe RTT $\ne$ Game Application RTT:**
   Traceroute Round-Trip Time measures the latency required for an intermediate router to receive an ICMP Echo packet, process TTL expiration on its control plane, and generate an ICMP Time Exceeded (Type 11, Code 0) datagram back to the sender. Router control planes prioritize forwarding plane traffic and frequently rate-limit or deprioritize ICMP generation. Traceroute RTT must **never** be labeled as "game latency" or "PUBG ping".
2. **Router Timeout $\ne$ Packet Loss:**
   A timeout (`*`) in traceroute indicates that a specific router did not return an ICMP Time Exceeded message within the probe window. Routers often silently drop TTL-expired diagnostic packets by policy while forwarding payload packets without delay. Timeouts must **never** be interpreted as game packet loss.
3. **Traffic Role Classification is Hypothesized:**
   Observed endpoints from Phase 0.5 captures are empirical observations, not permanent server declarations. Endpoints may change across game matches.

---

## 3. System Architecture

```
+-----------------------------------------------------------------------------------+
|                              Target Destination                                   |
|               (Strictly validated IPv4, IPv6, or RFC 1123 Hostname)               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               TracertExecutor (Direct Process Execution, No Shell)                 |
| - Fixed execution path, argument array isolation                                  |
| - Configurable execution safety timeout (default: 90s) & process termination      |
| - Captures stdout, stderr, exit code, execution duration                          |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|               TracertParser & Hop Normalization Engine                            |
| - Tokenizes hop number, per-probe RTTs (<1ms, \d+ ms, *), and target endpoint     |
| - Preserves numeric IPs (-d), bracketed hostnames, and admin filtering errors     |
| - Tracks timeout counts (e.g. 1/3, 2/3, 3/3) without discarding raw information    |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         HopStatsEngine & Distribution                             |
| - Exact linear-interpolation percentiles (min, median, mean, p95, p99, max)      |
| - Sample standard deviation & MAPDV (RFC 5481) probe jitter                       |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     RouteFingerprintEngine (SHA-256)                              |
| - Canonical path encoding: "1:<ip>|2:<ip>|3:TIMEOUT|...|N:<ip>"                  |
| - Preserves hop positions, timeout locations, and router identities               |
| - Cryptographic SHA-256 digest + concise 16-hex prefix                            |
+-----------------------------------------------------------------------------------+
                   |                                             |
                   v                                             v
+-------------------------------------+       +-------------------------------------+
|        RouteComparisonEngine        |       |        RouteStabilityEngine         |
| - Pairwise snapshot diff            |       | - Multi-snapshot path distribution  |
| - Structural change classification  |       | - Dominant path % & transition rate |
| - Hop median RTT delta tracking     |       | - Hop position variability matrix   |
+-------------------------------------+       +-------------------------------------+
                   |                                             |
                   +----------------------+----------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               RouteReportRenderer & Session Persistence                           |
| - Human-readable formatted console reports                                        |
| - Complete machine-readable JSON artifacts in data/route/snapshots/               |
+-----------------------------------------------------------------------------------+
```

---

## 4. Route Fingerprint Specification

To compare routes over time, RiftRoute computes a deterministic, position-preserving route fingerprint:

1. **Ordering:** Hops are ordered strictly by hop index $1, 2, \dots, N$.
2. **Hop Encoding:**
   - Responding Hop: `"<hop_number>:<primary_ip>"` (IP normalized to lowercase trimmed string).
   - Timeout Hop: `"<hop_number>:TIMEOUT"` (explicitly preserves timeout position).
3. **Delimiter:** Hops are delimited by the pipe character (`|`).
   *Example Canonical Path:*
   `1:192.168.1.1|2:223.230.16.1|3:59.144.94.157|4:182.79.243.234|5:182.79.223.41|6:1.1.1.1`
4. **Hashing:**
   $$\text{SHA-256}(\text{Canonical Path UTF-8 Bytes})$$
   - `fingerprint`: First 16 hexadecimal characters uppercase (64 bits of entropy).
   - `fingerprint_sha256`: Full 64 hexadecimal characters.

---

## 5. CLI Usage Reference

```powershell
# Help display
cargo run --release --bin rift-baseline -- route --help
cargo run --release --bin rift-baseline -- route measure --help
cargo run --release --bin rift-baseline -- route compare --help
cargo run --release --bin rift-baseline -- route stability --help

# 1. Measure network path to destination
cargo run --release --bin rift-baseline -- route measure 1.1.1.1 -m 15 -w 1000 --save

# 2. Measure with JSON output
cargo run --release --bin rift-baseline -- --json route measure 1.1.1.1 -m 15

# 3. Compare two route snapshots
cargo run --release --bin rift-baseline -- route compare data/route/snapshots/snap1.json data/route/snapshots/snap2.json

# 4. Analyze route stability across snapshots
cargo run --release --bin rift-baseline -- route stability data/route/snapshots/snap1.json data/route/snapshots/snap2.json
```

---

## 6. Empirical Measurement Results

Real measurements collected on Windows 11 development machine (Wi-Fi, ACT Fibernet, Andhra Pradesh, India):

### Summary Table

| Destination | Target Classification | Total Hops | Responding Hops | Timeout Hops | Path Median RTT | Dominant Fingerprint | Stability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `192.168.1.1` | Local Gateway | 1 | 1 | 0 | 0.5 - 1.0 ms | `29776D29CF693ADE` | 100.0% (5/5 runs) |
| `1.1.1.1` | Cloudflare DNS (Anycast) | 6 | 6 | 0 | 11.0 ms | `064DEE4B85A3144A` | 100.0% (5/5 runs) |
| `8.8.8.8` | Google DNS (Anycast) | 8 | 8 | 0 | 26.0 ms | `76455440DB0C1BD1` | 100.0% (Single run) |
| `20.205.179.128`| PUBG Endpoint (Azure) | 20 | 7 | 13 | 62.0 ms | `9718DCB2AE6A739E` | 100.0% (Single run) |

---

## 7. Independent Cross-Validation

To verify implementation correctness, an independent Python script ([`tests/route_intelligence/cross_validation.py`](file:///d:/network%20optimiser/tests/route_intelligence/cross_validation.py)) was executed against all 12 generated snapshot files in `data/route/snapshots/`.

- **Total Structural & Numerical Checks:** 99
- **Passed Checks:** 99
- **Discrepancies:** 0 (100% exact match across all hops, statistics, and SHA-256 fingerprints).
