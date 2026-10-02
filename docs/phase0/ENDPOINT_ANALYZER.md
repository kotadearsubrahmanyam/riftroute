# RiftRoute Phase 0.5: Passive Game Endpoint Analyzer

## 1. Overview & Purpose
Phase 0.5 introduces passive game endpoint analysis into the `rift-baseline` diagnostic engine.

The analyzer processes passive packet capture metadata exports (e.g., from TShark/Wireshark) to characterize UDP traffic generated during online gaming sessions without sending a single active probe, modifying routing tables, or installing intrusive kernel drivers.

Motivated by investigating observed ~200 ms PUBG PC latency from Andhra Pradesh, India, Phase 0.5 extracts fine-grained empirical characteristics of game-related network streams.

---

## 2. Architectural Design

```
+---------------------------------------------------------------------------------+
|                                 Capture File                                    |
|   (TShark TSV export: frame.time_relative, ip.src, udp.srcport, ip.dst, ...)    |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       CaptureParser (UTF-8 / UTF-16 LE / BE)                    |
| - Automatic BOM detection & decoding (handles Windows PowerShell UTF-16LE)      |
| - Strict line-by-line whitespace tokenization and validation                    |
| - Non-panicking malformed record tracking                                       |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       Bidirectional Endpoint Normalization                      |
| - RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) private IP mapping       |
| - Bidirectional flow grouping key: (Local Endpoint <-> Remote Endpoint)        |
| - Consistent TX (outbound) / RX (inbound) classification                        |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                         Statistical Metrics Engine                              |
| - Frame size percentiles (min, mean, median, p95, p99, max, std dev) per dir   |
| - Inter-arrival gap statistics & distribution buckets (>10ms, >25ms, etc.)      |
| - Deterministic burst grouping (packets within <= 10.0 ms)                      |
| - Stream continuity & stability assessment                                      |
| - Traffic volume ranking & endpoint classification                              |
+---------------------------------------------------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       Report Generation (Text & JSON)                           |
| - Human-readable summary with formatting, tables, and integrity disclaimers     |
| - Complete machine-readable JSON schema                                         |
+---------------------------------------------------------------------------------+
```

---

## 3. CLI Usage

The analyzer is integrated directly into the `rift-baseline` CLI via the `analyze-endpoints` subcommand:

```powershell
# Human-readable console analysis
cargo run --release --bin rift-baseline -- analyze-endpoints path/to/capture.txt

# Save human-readable report to file
cargo run --release --bin rift-baseline -- analyze-endpoints path/to/capture.txt -o reports/phase0/analysis.txt

# Structured JSON output to console
cargo run --release --bin rift-baseline -- --json analyze-endpoints path/to/capture.txt

# Save JSON report to file
cargo run --release --bin rift-baseline -- --json analyze-endpoints path/to/capture.txt -o reports/phase0/analysis.json
```

---

## 4. Empirical Evaluation: `pubg_endpoints_60s.txt`

The analyzer was validated against a 60-second capture captured during an active PUBG PC session (`pubg_endpoints_60s.txt`):

### Capture Metadata
- **Total Lines Read:** 9,003
- **Valid Packets Parsed:** 9,003
- **Malformed Lines:** 0
- **Duration:** 59.8707 seconds
- **Total Frame Bytes:** 797,737 bytes (779.04 KB)
- **Distinct Endpoints Discovered:** 2

---

### Endpoint Comparison Table

| Metric | Endpoint #1 (Highest Traffic) | Endpoint #2 (Secondary) |
| :--- | :--- | :--- |
| **Remote Socket** | `20.205.179.128:27528` | `85.236.96.163:25138` |
| **Local Socket** | `192.168.1.14:50837` | `192.168.1.14:25628` |
| **Protocol** | UDP | UDP |
| **Traffic Classification** | Highest Traffic Endpoint | Secondary Endpoint |
| **Total Packets** | 7,679 (85.29% of capture) | 1,324 (14.71% of capture) |
| **TX Packets (Client -> Srv)** | 4,718 (61.44%) | 1,205 (91.01%) |
| **RX Packets (Srv -> Client)** | 2,961 (38.56%) | 119 (8.99%) |
| **Total Bytes** | 681,177 bytes (85.39%) | 116,560 bytes (14.61%) |
| **TX Bytes** | 317,553 bytes (46.62%) | 98,554 bytes (84.55%) |
| **RX Bytes** | 363,624 bytes (53.38%) | 18,006 bytes (15.45%) |
| **Overall Packet Rate** | 128.26 pps | 22.14 pps |
| **TX Packet Rate** | 78.80 pps | 20.15 pps |
| **RX Packet Rate** | 49.46 pps | 1.99 pps |
| **TX Packet Size (Median/Mean)**| 64.0 B / 67.3 B | 86.0 B / 81.8 B |
| **RX Packet Size (Median/Mean)**| 93.0 B / 122.8 B | 174.0 B / 151.3 B |
| **Inter-Arrival Mean Gap** | 7.80 ms | 45.20 ms |
| **Inter-Arrival Median Gap** | 4.17 ms | 20.78 ms |
| **Inter-Arrival p95 / Max Gap** | 27.50 ms / 103.56 ms | 80.73 ms / 260.13 ms |
| **Bursts (<= 10ms threshold)** | 1,508 bursts (avg 5.09 pkts) | 1,249 bursts (avg 1.06 pkts) |
| **Stream Continuity** | Continuously Active (100.0%) | Continuously Active (99.88%) |
| **Measured RTT** | NOT MEASURED | NOT MEASURED |
| **Measured Packet Loss** | NOT MEASURED | NOT MEASURED |

---

## 5. Traffic Characterization & Insights

### Stream #1 (`20.205.179.128:27528`): High-Frequency Game State Stream
- **Volume & Cadence:** Dominates the session with 7,679 packets at ~128.3 packets/second.
- **Client Transmission:** The client transmits small player updates at ~78.8 Hz (median 64 bytes).
- **Server Reception:** The server transmits game state updates at ~49.5 Hz (median 93 bytes, reaching up to 1,241 bytes during complex state updates).
- **Burst Pattern:** Packets frequently arrive in micro-bursts averaging 5 packets within <= 14.8 ms windows.
- **Hypothesis:** This stream exhibits all behavioral characteristics of the main real-time authoritative simulation/replication channel.

### Stream #2 (`85.236.96.163:25138`): Asymmetric Low-Frequency Auxiliary Stream
- **Volume & Cadence:** Low traffic volume (1,324 packets at ~22.1 pps).
- **Asymmetry:** Highly asymmetric transmission: 91% TX vs 9% RX (client transmits 1,205 packets; server returns only 119 packets at ~2 pps).
- **Packet Sizes:** Fixed, highly uniform client packet sizes (median 86 bytes, std dev 5.8 bytes).
- **Hypothesis:** Characteristic of auxiliary telemetry, anti-cheat heartbeat/challenge-response, or voice signaling.

---

## 6. Measurement Integrity & Phase Boundaries

1. **Passive RTT Policy:** Standard UDP headers contain neither sequence numbers nor acknowledgment flags. Without proprietary knowledge of game protocol wire formats, matching outbound packets with inbound replies is statistically invalid and prone to massive error. RTT is therefore explicitly reported as `NOT MEASURED`.
2. **Passive Packet Loss Policy:** Because UDP does not enforce transport-level sequence counters, missing packets cannot be inferred from gaps in arrival times (which often reflect variable frame rates, ticks, or dead reckoning). Packet loss is explicitly reported as `NOT MEASURED`.
3. **Endpoint Classification Rule:** While Stream #1 is the highest-volume endpoint, RiftRoute adheres to the rule that traffic volume alone does not prove an endpoint is the authoritative gameplay server. In all reports, it is classified strictly as `"Highest Traffic Endpoint"`.
