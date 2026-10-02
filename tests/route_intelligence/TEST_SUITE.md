# RiftRoute Phase 1 — Route Intelligence Test Suite Documentation

## Test Categories

### 1. Unit Tests (`core/rust/rift-baseline/src/route_intelligence/`)
- **Parser Tests (`parser.rs`):**
  - Standard numeric tracert output (`-d`).
  - Sub-millisecond `<1 ms` token conversion to 0.5 ms.
  - Complete timeouts (`* * * Request timed out.`).
  - Mixed responding / timeout probes (`* 12 ms *`).
  - Reverse-DNS resolved hostnames with bracketed IP (`router [1.1.1.1]`).
  - Administrative error messages (`Destination host unreachable`).
  - IPv6 hop parsing (`2405:201:2000::1`).
- **Statistics Tests (`hop.rs`):**
  - Single sample edge case (min = median = mean = max, std dev = 0).
  - Multi-sample percentile calculations (linear interpolation at 50th, 95th, 99th percentiles).
  - MAPDV probe jitter calculation across consecutive samples.
  - Empty sample handling (returns None).
- **Fingerprint Tests (`fingerprint.rs`):**
  - Canonical path generation with hop position and timeout preservation.
  - Identical paths yield identical 16-hex and 64-hex SHA-256 digests.
  - Altering an IP changes the fingerprint.
  - Shifting timeout position changes the fingerprint.
- **Comparison Tests (`comparison.rs`):**
  - Identical snapshots detect identical fingerprint and 0 hop differences.
  - Address change detection (`HopDiffType::AddressChanged`).
  - Timeout to responding transition (`HopDiffType::TimeoutToResponding`).
  - Responding to timeout transition (`HopDiffType::RespondingToTimeout`).
  - Hop addition and removal (`HopDiffType::HopAdded`, `HopDiffType::HopRemoved`).
  - Hop median RTT delta calculations.
- **Stability Tests (`stability.rs`):**
  - Single snapshot analysis.
  - Multiple snapshots with route transition detection and frequency ranking.
  - Empty snapshot collection error handling.
- **Security Validation Tests (`tracert.rs`):**
  - Rejection of shell injection characters (`;`, `&`, `|`, `$`, `\n`, etc.).
  - Rejection of command-line flag injection (`-d`, `/flag`).
  - Rejection of empty, whitespace, and excessive length (>253 chars) destinations.
  - Acceptance of valid IPv4, IPv6, and RFC 1123 hostnames.

### 2. Integration Tests (`core/rust/rift-baseline/tests/cli_tests.rs`)
- `test_cli_route_help`
- `test_cli_route_measure_help`
- `test_cli_route_compare_help`
- `test_cli_route_stability_help`
- `test_cli_route_measure_invalid_destination`
- `test_cli_route_compare_snapshots`
- `test_cli_route_stability_snapshots`

### 3. Regression Tests
- All 30 Phase 0 unit tests and 5 CLI integration tests continue to pass without modification.
- All Phase 0.5 endpoint analyzer tests (unit + real 60s capture tests) continue to pass.

### 4. Independent Python Cross-Validation (`tests/route_intelligence/cross_validation.py`)
- Ingests all real snapshot JSON files in `data/route/snapshots/`.
- Independently tokenizes raw tracert lines.
- Independently computes percentiles, std dev, jitter, canonical paths, and SHA-256 digests.
- Asserts 100% agreement against Rust outputs.
