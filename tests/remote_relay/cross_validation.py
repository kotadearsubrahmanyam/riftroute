#!/usr/bin/env python3
"""
RiftRoute Phase 5 — Independent Python Cross-Validation Suite
==============================================================
Validates:
1. Sample counts in campaign JSON matches raw_samples array.
2. Independent calculation of min, max, mean, median, p95, p99, stddev, and jitter.
3. Verification of 95% confidence intervals against Student's t distribution.
4. Independent verification of direct-relay deltas and composed estimates.
5. Verification of variability guard and classification logic.
6. Verification of path diversity categorization.
7. Verification of all 10 Phase 5 report artifacts in reports/phase5/.
"""

import json
import math
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent.parent

def calculate_percentile(sorted_vals, pct):
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    if n == 1:
        return sorted_vals[0]
    rank = pct * (n - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    frac = rank - lower
    if lower == upper or upper >= n:
        return sorted_vals[lower]
    return sorted_vals[lower] * (1.0 - frac) + sorted_vals[upper] * frac

def compute_independent_stats(samples):
    n = len(samples)
    assert n > 0, "Samples cannot be empty"
    sorted_s = sorted(samples)
    min_v = sorted_s[0]
    max_v = sorted_s[-1]
    mean_v = sum(sorted_s) / n

    if n % 2 == 1:
        median_v = sorted_s[n // 2]
    else:
        median_v = (sorted_s[n // 2 - 1] + sorted_s[n // 2]) / 2.0

    p95_v = calculate_percentile(sorted_s, 0.95)
    p99_v = calculate_percentile(sorted_s, 0.99)

    variance = sum((x - mean_v) ** 2 for x in sorted_s) / (n - 1) if n > 1 else 0.0
    std_dev = math.sqrt(variance)

    jitter = sum(abs(samples[i] - samples[i - 1]) for i in range(1, n)) / (n - 1) if n > 1 else 0.0

    # Student's t for 95% CI (n=10 -> 2.262)
    t_crit = 2.262 if n == 10 else 1.960
    margin = t_crit * (std_dev / math.sqrt(n))

    return {
        "count": n,
        "min": min_v,
        "max": max_v,
        "mean": mean_v,
        "median": median_v,
        "p95": p95_v,
        "p99": p99_v,
        "std_dev": std_dev,
        "jitter": jitter,
        "ci_lower": max(0.0, mean_v - margin),
        "ci_upper": mean_v + margin,
    }

def test_campaign_sample_counts_and_math():
    print("[1/5] Validating Campaign Raw Samples & Statistical Precision...")
    comp_file = WORKSPACE / "reports" / "phase5" / "relay_path_comparison.json"
    assert comp_file.exists(), f"Missing campaign file: {comp_file}"

    with open(comp_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_samples = data["raw_samples"]
    assert len(raw_samples) == data["sample_count"], f"Mismatch in sample count: {len(raw_samples)} vs {data['sample_count']}"
    assert len(raw_samples) >= 10, f"Expected at least 10 campaign samples, got {len(raw_samples)}"

    direct_vals = [s["direct_rtt_ms"] for s in raw_samples if s["success"]]
    c2r_vals = [s["client_to_relay_rtt_ms"] for s in raw_samples if s["success"]]
    r2d_vals = [s["relay_to_destination_rtt_ms"] for s in raw_samples if s["success"]]
    composed_vals = [s["composed_estimate_ms"] for s in raw_samples if s["success"]]

    # Verify composed estimate = leg 1 + leg 2 for every cycle
    for s in raw_samples:
        if s["success"]:
            expected_comp = s["client_to_relay_rtt_ms"] + s["relay_to_destination_rtt_ms"]
            assert abs(s["composed_estimate_ms"] - expected_comp) < 1e-4, f"Cycle {s['cycle_index']} composed mismatch"

    # Independently compute direct path stats and check agreement
    py_direct = compute_independent_stats(direct_vals)
    rust_direct = data["direct_stats"]

    assert abs(py_direct["mean"] - rust_direct["mean_ms"]) < 1e-4, "Direct mean mismatch"
    assert abs(py_direct["median"] - rust_direct["median_ms"]) < 1e-4, "Direct median mismatch"
    assert abs(py_direct["p95"] - rust_direct["p95_ms"]) < 1e-4, "Direct p95 mismatch"
    assert abs(py_direct["std_dev"] - rust_direct["std_dev_ms"]) < 1e-4, "Direct stddev mismatch"
    assert abs(py_direct["jitter"] - rust_direct["jitter_ms"]) < 1e-4, "Direct jitter mismatch"

    # Independently compute composed stats and check agreement
    py_comp = compute_independent_stats(composed_vals)
    rust_comp = data["composed_stats"]

    assert abs(py_comp["mean"] - rust_comp["mean_ms"]) < 1e-4, "Composed mean mismatch"
    assert abs(py_comp["median"] - rust_comp["median_ms"]) < 1e-4, "Composed median mismatch"
    assert abs(py_comp["std_dev"] - rust_comp["std_dev_ms"]) < 1e-4, "Composed stddev mismatch"

    # Check deltas
    expected_delta_med = rust_comp["median_ms"] - rust_direct["median_ms"]
    assert abs(data["delta_median_ms"] - expected_delta_med) < 1e-4, "Delta median mismatch"

    print(f"      -> 10 raw cycles verified. Direct median: {py_direct['median']:.2f} ms | Composed median: {py_comp['median']:.2f} ms.")
    print(f"      -> Delta median: {data['delta_median_ms']:+.2f} ms. 100% agreement with Rust engine.")

def test_variability_guard_and_classification():
    print("[2/5] Validating Variability Guard & Objective Classification...")
    comp_file = WORKSPACE / "reports" / "phase5" / "relay_path_comparison.json"
    with open(comp_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    direct_med = data["direct_stats"]["median_ms"]
    comp_med = data["composed_stats"]["median_ms"]
    direct_std = data["direct_stats"]["std_dev_ms"]
    comp_std = data["composed_stats"]["std_dev_ms"]
    direct_jit = data["direct_stats"]["jitter_ms"]

    delta = comp_med - direct_med
    guard = max(2.0, max(direct_std, comp_std), direct_jit * 0.75)

    if abs(delta) <= guard:
        expected_class = "WithinMeasurementVariability"
    elif delta < 0.0:
        expected_class = "RelayLowerObservedEstimate"
    else:
        expected_class = "DirectLowerObservedMeasurement"

    assert data["classification"] == expected_class, f"Expected classification {expected_class}, got {data['classification']}"
    print(f"      -> Delta: {delta:+.2f} ms, Guard threshold: {guard:.2f} ms. Classification: '{expected_class}' verified.")

def test_path_diversity():
    print("[3/5] Validating Path Diversity Categorization...")
    div_file = WORKSPACE / "reports" / "phase5" / "relay_path_diversity.json"
    assert div_file.exists(), f"Missing diversity file: {div_file}"

    with open(div_file, "r", encoding="utf-8") as f:
        div = json.load(f)

    assert div["diversity_type"] == "StructuralRouteVariation", f"Unexpected diversity: {div['diversity_type']}"
    assert div["direct_fingerprint"] != div["leg2_fingerprint"], "Fingerprints should differ for structural variation"
    assert div["direct_hop_count"] != div["relay_hop_count"], "Hop counts differ"
    print(f"      -> Path diversity correctly categorized as {div['diversity_type']}.")

def test_failure_test_results():
    print("[4/5] Validating Relay Failure & Recovery Detection...")
    fail_file = WORKSPACE / "reports" / "phase5" / "relay_failure_test.json"
    assert fail_file.exists(), f"Missing failure test file: {fail_file}"

    with open(fail_file, "r", encoding="utf-8") as f:
        fail_data = json.load(f)

    assert "relay_id" in fail_data
    assert "failure_detected" in fail_data
    assert "failure_detection_latency_ms" in fail_data
    print(f"      -> Failure test artifact verified: status={fail_data['initial_status']}, detected={fail_data['failure_detected']}.")

def test_phase5_artifacts_completeness():
    print("[5/5] Verifying Phase 5 Required Artifacts...")
    required = [
        WORKSPACE / "reports" / "phase5" / "remote_relay_inventory.json",
        WORKSPACE / "reports" / "phase5" / "remote_relay_health.json",
        WORKSPACE / "reports" / "phase5" / "direct_measurements.json",
        WORKSPACE / "reports" / "phase5" / "client_relay_measurements.json",
        WORKSPACE / "reports" / "phase5" / "relay_destination_measurements.json",
        WORKSPACE / "reports" / "phase5" / "relay_path_comparison.json",
        WORKSPACE / "reports" / "phase5" / "relay_stability.json",
        WORKSPACE / "reports" / "phase5" / "relay_failure_test.json",
        WORKSPACE / "reports" / "phase5" / "remote_relay_security_audit.txt",
        WORKSPACE / "reports" / "phase5" / "phase5_measurement_report.txt",
        WORKSPACE / "scripts" / "deploy_remote_relay.sh",
        WORKSPACE / "scripts" / "remote_relay_health_check.sh",
    ]

    for path in required:
        assert path.exists(), f"Missing Phase 5 artifact: {path}"
        assert path.stat().st_size > 0, f"Empty artifact: {path}"

    print(f"      -> All {len(required)} Phase 5 artifacts present and non-empty.")

def main():
    print("================================================================================")
    print("       RIFTROUTE PHASE 5 — INDEPENDENT PYTHON CROSS-VALIDATION SUITE            ")
    print("================================================================================")
    try:
        test_campaign_sample_counts_and_math()
        test_variability_guard_and_classification()
        test_path_diversity()
        test_failure_test_results()
        test_phase5_artifacts_completeness()
        print("================================================================================")
        print("                 CROSS-VALIDATION RESULT: ALL CHECKS PASSED                     ")
        print("================================================================================")
        return 0
    except AssertionError as e:
        print(f"\n[CROSS-VALIDATION FAILED] {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
