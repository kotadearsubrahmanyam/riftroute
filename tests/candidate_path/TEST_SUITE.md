# RiftRoute Phase 2 — Test Suite & Verification Matrix

## 1. Overview

Phase 2 introduces route candidate discovery, repeated longitudinal measurement series, value-neutral candidate comparison, and multi-candidate path diversity synthesis. This test suite verifies the complete mathematical, topological, and operational correctness of Phase 2 across Rust unit tests, Rust CLI integration tests, and an independent Python cross-validation engine.

---

## 2. Test Execution Commands

```powershell
# Run all Rust unit and integration tests (Phase 0, 0.5, 1, and 2)
cargo test

# Run candidate path unit tests only
cargo test candidate_path

# Run CLI integration tests
cargo test --test cli_tests

# Run Phase 2 independent Python cross-validation
python tests/candidate_path/cross_validation.py

# Run Phase 1 independent Python cross-validation
python tests/route_intelligence/cross_validation.py
```

---

## 3. Test Inventory Matrix

### Rust Unit Tests (`core/rust/rift-baseline/src/candidate_path/`)

| Module | Test Name | Purpose | Result |
| :--- | :--- | :--- | :--- |
| `discovery.rs` | `test_is_private_or_loopback` | Verifies RFC 1918 private/loopback/wildcard IP exclusion | **PASS** |
| `discovery.rs` | `test_parse_socket_string` | Tests parsing of `IP:port` and numeric sockets | **PASS** |
| `discovery.rs` | `test_deduplicate_candidates` | Verifies deduplication and observation count aggregation | **PASS** |
| `diversity.rs` | `test_classify_identical_snapshots` | Tests classification of identical route runs -> `SameObservedPath` | **PASS** |
| `diversity.rs` | `test_classify_minor_response_variation` | Tests matching router IPs with transient timeouts -> `MinorResponseVariation` | **PASS** |
| `diversity.rs` | `test_classify_structural_variation` | Tests diverging router IPs -> `StructuralRouteVariation` | **PASS** |
| `diversity.rs` | `test_classify_insufficient_evidence` | Tests single snapshot behavior -> `InsufficientEvidence` | **PASS** |
| `measurement.rs` | `test_from_snapshots_metrics` | Tests statistical calculation of percentiles, dominance %, and transitions | **PASS** |
| `measurement.rs` | `test_identical_path_classification` | Tests series path classification and 0 transition rate | **PASS** |
| `comparison.rs` | `test_candidate_comparison_structural_variation` | Tests pairwise candidate delta calculations and structural differences | **PASS** |
| `comparison.rs` | `test_analyze_diversity` | Tests multi-candidate synthesis and unique fingerprint counts | **PASS** |

### Rust CLI Integration Tests (`core/rust/rift-baseline/tests/cli_tests.rs`)

| Test Name | Invocation Tested | Purpose | Result |
| :--- | :--- | :--- | :--- |
| `test_cli_route_candidates_help` | `route candidates --help` | Validates CLI subcommand registration and help text | **PASS** |
| `test_cli_route_candidates_discover_from_capture_json` | `route candidates discover --capture-file <PATH> --json` | Validates JSON array candidate extraction from real TShark capture | **PASS** |
| `test_cli_route_candidates_discover_text` | `route candidates discover --capture-file <PATH>` | Validates text report rendering for candidate discovery | **PASS** |
| `test_cli_route_candidates_compare_and_analyze` | `route candidates compare` & `analyze` | Validates pairwise comparison and directory-wide diversity analysis | **PASS** |

### Independent Python Cross-Validation (`tests/candidate_path/cross_validation.py`)

- **Total Verification Checks**: 44
- **Passed Checks**: 44
- **Failures / Discrepancies**: 0
- **Validations Covered**:
  - Independent percentile and MAPDV jitter calculations
  - Independent dominant fingerprint and route transition rate calculations
  - Independent hop count and sample count validations
  - Real disk artifact integrity across `data/route/candidates/`, `data/route/measurements/`, and `reports/phase2/`
  - Architectural status and scientific disclaimer verification

---

## 4. Overall Test Suite Status

- Total Rust Tests: **87 passed, 0 failed, 0 ignored**
  - Unit tests: 67 passed
  - CLI tests: 20 passed
- Total Python Cross-Validation Checks: **143 passed, 0 failed**
  - Phase 1 cross-validation: 99 passed
  - Phase 2 cross-validation: 44 passed
- Compiler Warnings: **0**
- Regressions: **0**
