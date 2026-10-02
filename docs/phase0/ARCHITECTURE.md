# Phase 0 Architecture: `rift-baseline`

## Design Goals
1. **Zero System Alteration:** Read-only diagnostic operations. No modification to routing tables, DNS, adapters, firewalls, or packet flows.
2. **Deterministic & Statistical Rigor:** Statistically robust calculations for RTT, RFC 3550 jitter, RFC 5481 MAPDV, and packet loss.
3. **ICMP Deprioritization Awareness:** Multi-hop route analyzer explicitly detects and isolates ICMP rate-limiting artifacts on transit routers from real packet forwarding latency.
4. **Non-Invasive Process Mapping:** Connects socket endpoints to process names without DLL injection, process hooking, or memory inspection.

## Architecture Diagram

```
+-------------------------------------------------------------------------+
|                           rift-baseline CLI                             |
|                                                                         |
|  [Cli Parser] ---> [Config Manager]                                      |
+---------+------------------+------------------+-----------------+-------+
          |                  |                  |                 |
          v                  v                  v                 v
   +--------------+   +---------------+   +------------+   +--------------+
   | SystemEngine |   | NetworkEngine |   | RouteEngine|   | ProcessEngine|
   +--------------+   +---------------+   +------------+   +--------------+
          |                  |                  |                 |
          |                  |                  |                 |
          v                  v                  v                 v
   [WMI/NetIP/      [ICMP Probes,       [tracert parser  [tasklist &      ]
    route print]     Stats: RFC 3550     Latency step-    netstat -ano,   ]
    HTTPS ASN        & MAPDV Jitter]     classifier]      Game signatures ]
          |                  |                  |                 |
          +------------------+------------------+-----------------+
                             |
                             v
                 +-----------------------+
                 |    ReportGenerator    |
                 +-----------------------+
                             |
                +------------+------------+
                |                         |
                v                         v
     JSON Session Schema          Human-Readable Report
  (data/baseline/sessions/)         (reports/phase0/)
```

## Module Overview
- `stats.rs`: Mathematical statistics engine. Implements mean, median, min, max, sample standard deviation, RFC 3550 interarrival jitter ($J(i) = J(i-1) + \frac{|D| - J(i-1)}{16}$), and MAPDV jitter.
- `config.rs`: Safe configuration management with bounded probe counts and interval pacing.
- `system.rs`: Local network adapter, gateway, DNS, routing table, and external ISP identity resolution.
- `connectivity.rs`: ICMP ping probe execution, timeout handling, and sequence tracking.
- `route.rs`: Route analyzer with step-change classification (`Observed`, `PotentiallySignificant`, `Inconclusive`).
- `process.rs`: Active socket inventory mapping PIDs to process names, matching game signatures.
- `game_test.rs`: User-driven PUBG PC baseline investigation workflow.
- `report.rs`: Machine-readable JSON and Markdown report generation.
