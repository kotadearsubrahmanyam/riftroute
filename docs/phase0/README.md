# RiftRoute Phase 0: Foundation & Baseline Network Intelligence

## Overview
Phase 0 establishes an empirical baseline of the developer/user's network environment without altering routing, firewall, or adapter configuration.

The primary motivating real-world observation is a player located in Andhra Pradesh, India observing approximately ~200 ms latency in PUBG PC. Phase 0 investigates this observation scientifically through controlled, non-invasive observation.

## Component: `rift-baseline`
`rift-baseline` is a standalone, read-only diagnostic CLI built in Rust.

### Capabilities:
- **System Network Inventory (`rift-baseline system`):** Inspects active network interface, adapter model, default gateway, DNS servers, interface metric, private network range, routing table, and verified ISP/ASN metadata.
- **Controlled Latency & Jitter Measurement (`rift-baseline connectivity`):** Performs controlled ICMP pings (default 30 probes), calculating min, max, mean, median, sample standard deviation, RFC 3550 interarrival jitter, and MAPDV (RFC 5481) jitter.
- **Route Progression Analysis (`rift-baseline route <destination>`):** Performs multi-hop traceroute with hop-by-hop latency classification (`Observed`, `PotentiallySignificant`, `Inconclusive`). Distinguishes intermediate router ICMP deprioritization from forwarding delays.
- **Active Connection & Game Discovery (`rift-baseline game`):** Non-invasively inventories active sockets and identifies processes associated with competitive FPS games (`TslGame.exe`, `cs2.exe`, `VALORANT.exe`, `Discovery.exe`).
- **User-Driven PUBG Baseline Test (`rift-baseline game-test`):** Controlled procedure to capture observable game server endpoints during live gameplay.
- **Passive Game Endpoint Analyzer (`rift-baseline analyze-endpoints`):** Parses TShark/Wireshark UDP packet metadata captures, characterizes bidirectional flows, traffic distributions, and micro-bursting without active network probing.
- **Full Consolidated Baseline Report (`rift-baseline report`):** Generates structured machine-readable JSON in `data/baseline/sessions/` and human-readable Markdown reports in `reports/phase0/`.

## Usage
```powershell
# Display help and version
cargo run --release --bin rift-baseline -- --help
cargo run --release --bin rift-baseline -- --version

# System network inventory
cargo run --release --bin rift-baseline -- system
cargo run --release --bin rift-baseline -- --json system

# Connectivity baseline (30 probes per destination)
cargo run --release --bin rift-baseline -- connectivity --probes 30 --interval 100

# Route trace to destination
cargo run --release --bin rift-baseline -- route 1.1.1.1 --max-hops 15

# Game activity scan
cargo run --release --bin rift-baseline -- game

# Interactive PUBG test
cargo run --release --bin rift-baseline -- game-test

# Passive game endpoint analysis
cargo run --release --bin rift-baseline -- analyze-endpoints data/baseline/raw/pubg_endpoints_60s.txt
cargo run --release --bin rift-baseline -- --json analyze-endpoints data/baseline/raw/pubg_endpoints_60s.txt -o reports/phase0/pubg_endpoints_60s_analysis.json

# Complete baseline diagnostic audit
cargo run --release --bin rift-baseline -- report
```
