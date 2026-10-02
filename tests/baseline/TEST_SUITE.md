# Phase 0 Baseline Test Suite Documentation

## Test Structure
The Phase 0 test suite consists of deterministic unit tests and end-to-end integration tests.

### 1. Deterministic Unit Tests (21 Tests)
Located in `core/rust/rift-baseline/src/`:
- **`stats::tests` (7 tests):**
  - `test_empty_probes`: Empty slice produces safe zeroed statistics without panics.
  - `test_all_failed_probes`: Complete timeout series yields 100.0% packet loss and `None` for RTT metrics.
  - `test_single_probe`: Single probe yields exact RTT for min, max, mean, median, with 0.0 std dev and jitter.
  - `test_median_odd_and_even`: Exact median computation for odd and even sample sizes.
  - `test_packet_loss_calculation`: Ratio of timeouts to total samples is mathematically exact.
  - `test_known_statistics`: Verifies arithmetic mean, variance, and sample standard deviation against exact manual derivations.
  - `test_rfc3550_jitter_exact`: Validates RFC 3550 exponential moving average jitter formula ($J(i) = J(i-1) + \frac{|D| - J(i-1)}{16}$).
- **`config::tests` (3 tests):**
  - `test_default_config_valid`: Validates default configuration bounds.
  - `test_validation_probe_bounds`: Enforces probe bounds (1..=100) and rate-limit intervals (>= 20ms).
  - `test_serialization_roundtrip`: Verifies JSON serde roundtrip.
- **`connectivity::tests` (4 tests):**
  - `test_parse_ping_success`: Parses standard Windows `ping.exe` output (`time=14ms`).
  - `test_parse_ping_sub_millisecond`: Handles Windows `time<1ms` sub-millisecond replies.
  - `test_parse_ping_timeout`: Handles `Request timed out`.
  - `test_parse_ping_unreachable`: Handles `Destination host unreachable`.
- **`route::tests` (3 tests):**
  - `test_parse_rtt_token`: Handles token formats (`<1 ms`, `12 ms`, `*`).
  - `test_parse_tracert_output_with_deprioritization`: Tests that intermediate hop RTT spikes that do not persist downstream are classified as `Inconclusive` (ICMP deprioritization).
  - `test_parse_tracert_output_with_sustained_increase`: Tests that sustained step-changes across all subsequent hops are classified as `PotentiallySignificant`.
- **`process::tests` (2 tests):**
  - `test_known_games_signatures`: Matches known process names (`TslGame.exe`, `cs2.exe`, `VALORANT.exe`, `Discovery.exe`).
  - `test_parse_netstat_sample`: Parses mock TCP and UDP socket listings.
- **`system::tests` (2 tests):**
  - `test_isp_metadata_struct`: Struct serialization and field validation.
  - `test_route_entry_serialization`: Routing table entry serde validation.

### 2. Integration Tests (5 Tests)
Located in `core/rust/rift-baseline/tests/cli_tests.rs`:
- `test_cli_help_flag`: Executes `rift-baseline --help` and asserts exit code 0 and presence of all subcommands.
- `test_cli_version_flag`: Executes `rift-baseline --version` and asserts exit code 0 and version string.
- `test_cli_system_json`: Executes `rift-baseline --json system` and asserts valid JSON structure.
- `test_cli_connectivity_probes`: Executes `rift-baseline --json connectivity --probes 2 --interval 20` and asserts valid array of baseline results.
- `test_cli_invalid_probe_count`: Executes with invalid flag (`--probes 0`) and asserts non-zero exit code and human-readable error.

## Reproducing the Tests
```powershell
cd "d:\network optimiser\core\rust\rift-baseline"

# Run all unit and integration tests
cargo test

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test cli_tests
```
