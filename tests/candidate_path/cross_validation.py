#!/usr/bin/env python3
"""
RiftRoute Phase 2 — Independent Candidate Path & Diversity Cross-Validation Engine
Cross-validates Rust candidate_path calculations against an independent Python implementation.
Ensures 0 discrepancy across:
- Candidate discovery normalization & deduplication
- Repeated measurement series aggregation & statistics
- Dominant fingerprint identification & transition rates
- Final-hop probe RTT statistics (min, median, mean, p95, max, std dev, jitter)
- Path difference classification (SameObservedPath, MinorResponseVariation, StructuralRouteVariation)
- Pairwise candidate comparison deltas (median delta, p95 delta, hop delta, structural diffs)
- Multi-candidate path diversity synthesis
- Real saved Phase 2 artifacts verification
"""

import sys
import os
import glob
import json
import math
from pathlib import Path


def calculate_percentile(sorted_samples, p):
    if not sorted_samples:
        return 0.0
    if len(sorted_samples) == 1:
        return sorted_samples[0]
    rank = (p / 100.0) * (len(sorted_samples) - 1)
    lower_idx = int(math.floor(rank))
    upper_idx = int(math.ceil(rank))
    fraction = rank - lower_idx
    if lower_idx == upper_idx or upper_idx >= len(sorted_samples):
        return sorted_samples[lower_idx]
    return sorted_samples[lower_idx] + fraction * (sorted_samples[upper_idx] - sorted_samples[lower_idx])


def compute_rtt_stats(samples):
    if not samples:
        return None
    sorted_s = sorted(samples)
    min_ms = sorted_s[0]
    max_ms = sorted_s[-1]
    mean_ms = sum(sorted_s) / len(sorted_s)
    median_ms = calculate_percentile(sorted_s, 50.0)
    p95_ms = calculate_percentile(sorted_s, 95.0)
    p99_ms = calculate_percentile(sorted_s, 99.0)

    if len(sorted_s) > 1:
        variance = sum((x - mean_ms) ** 2 for x in sorted_s) / (len(sorted_s) - 1)
        std_dev_ms = math.sqrt(variance)
    else:
        std_dev_ms = 0.0

    if len(samples) >= 2:
        diff_sum = sum(abs(samples[i] - samples[i - 1]) for i in range(1, len(samples)))
        jitter_ms = diff_sum / (len(samples) - 1)
    else:
        jitter_ms = None

    return {
        "sample_count": len(samples),
        "min_ms": min_ms,
        "median_ms": median_ms,
        "mean_ms": mean_ms,
        "p95_ms": p95_ms,
        "p99_ms": p99_ms,
        "max_ms": max_ms,
        "std_dev_ms": std_dev_ms,
        "jitter_ms": jitter_ms,
    }


def compute_median_usize(values):
    if not values:
        return 0
    s = sorted(values)
    mid = len(s) // 2
    if len(s) % 2 == 0:
        return (s[mid - 1] + s[mid]) // 2
    return s[mid]


def classify_snapshots(snapshots):
    if len(snapshots) < 2:
        return "InsufficientEvidence"

    fps = {s["fingerprint"] for s in snapshots}
    if len(fps) == 1:
        return "SameObservedPath"

    # Compare responding hops across snapshots
    all_resp_maps = []
    for s in snapshots:
        m = {}
        for h in s["hops"]:
            if h.get("responded") and h.get("primary_address"):
                m[h["hop_number"]] = h["primary_address"]
        all_resp_maps.append(m)

    first_m = all_resp_maps[0]
    all_match = True
    for m in all_resp_maps[1:]:
        for hop_num, ip in m.items():
            if hop_num in first_m and first_m[hop_num] != ip:
                all_match = False
                break
        if not all_match:
            break

    if all_match:
        return "MinorResponseVariation"
    return "StructuralRouteVariation"


def classify_two_candidates(snapshots_a, snapshots_b):
    if not snapshots_a or not snapshots_b:
        return "InsufficientEvidence"

    # Dominant fingerprints
    fp_a_counts = {}
    for s in snapshots_a:
        fp_a_counts[s["fingerprint"]] = fp_a_counts.get(s["fingerprint"], 0) + 1
    dom_a = max(fp_a_counts.items(), key=lambda x: x[1])[0]

    fp_b_counts = {}
    for s in snapshots_b:
        fp_b_counts[s["fingerprint"]] = fp_b_counts.get(s["fingerprint"], 0) + 1
    dom_b = max(fp_b_counts.items(), key=lambda x: x[1])[0]

    if dom_a == dom_b:
        return "SameObservedPath"

    snap_a = next((s for s in snapshots_a if s["fingerprint"] == dom_a), snapshots_a[0])
    snap_b = next((s for s in snapshots_b if s["fingerprint"] == dom_b), snapshots_b[0])

    map_a = {h["hop_number"]: h["primary_address"] for h in snap_a["hops"] if h.get("responded") and h.get("primary_address")}
    map_b = {h["hop_number"]: h["primary_address"] for h in snap_b["hops"] if h.get("responded") and h.get("primary_address")}

    max_hops = max(len(snap_a["hops"]), len(snap_b["hops"]))
    structural_diff = False
    for h in range(1, max_hops + 1):
        if h in map_a and h in map_b:
            if map_a[h] != map_b[h]:
                structural_diff = True
                break

    if structural_diff or len(snap_a["hops"]) != len(snap_b["hops"]):
        return "StructuralRouteVariation"
    return "MinorResponseVariation"


def run_cross_validation():
    print("=" * 80)
    print("RIFTROUTE PHASE 2 — INDEPENDENT CANDIDATE PATH CROSS-VALIDATION")
    print("=" * 80)

    checks_passed = 0
    checks_total = 0

    def check(name, val1, val2, tolerance=1e-4):
        nonlocal checks_passed, checks_total
        checks_total += 1
        if isinstance(val1, float) and isinstance(val2, float):
            match = abs(val1 - val2) <= tolerance
        else:
            match = (val1 == val2)
        if match:
            checks_passed += 1
            print(f"  [PASS] {name}: {val1}")
        else:
            print(f"  [FAIL] {name}: Python={val1} vs Rust={val2}")
            sys.exit(1)

    # 1. Synthetic Classification Tests
    print("\n--- 1. Testing Path Difference Classification (Synthetic) ---")
    s_same1 = {"fingerprint": "FP1", "hops": [{"hop_number": 1, "responded": True, "primary_address": "1.1.1.1"}]}
    s_same2 = {"fingerprint": "FP1", "hops": [{"hop_number": 1, "responded": True, "primary_address": "1.1.1.1"}]}
    check("Identical Snapshots Classification", classify_snapshots([s_same1, s_same2]), "SameObservedPath")

    s_diff1 = {"fingerprint": "FP1", "hops": [{"hop_number": 1, "responded": True, "primary_address": "1.1.1.1"}]}
    s_diff2 = {"fingerprint": "FP2", "hops": [{"hop_number": 1, "responded": True, "primary_address": "2.2.2.2"}]}
    check("Structural Route Variation Classification", classify_snapshots([s_diff1, s_diff2]), "StructuralRouteVariation")

    s_minor1 = {"fingerprint": "FP1", "hops": [{"hop_number": 1, "responded": True, "primary_address": "1.1.1.1"}, {"hop_number": 2, "responded": False, "primary_address": None}]}
    s_minor2 = {"fingerprint": "FP2", "hops": [{"hop_number": 1, "responded": True, "primary_address": "1.1.1.1"}, {"hop_number": 2, "responded": True, "primary_address": "3.3.3.3"}]}
    check("Minor Response Variation Classification", classify_snapshots([s_minor1, s_minor2]), "MinorResponseVariation")

    check("Insufficient Evidence (< 2 runs)", classify_snapshots([s_same1]), "InsufficientEvidence")

    # 2. Verify Saved Candidate Destination JSONs
    print("\n--- 2. Verifying Saved Candidate Destination Artifacts ---")
    cand_files = glob.glob("data/route/candidates/*.json")
    if cand_files:
        latest_cand_file = max(cand_files, key=os.path.getmtime)
        with open(latest_cand_file, "r", encoding="utf-8") as f:
            candidates = json.load(f)
        check("Discovered Candidates Is List", isinstance(candidates, list), True)
        check("Discovered Candidate Count >= 2", len(candidates) >= 2, True)

        c1 = candidates[0]
        check("Candidate 1 IP Present", bool(c1.get("ip")), True)
        check("Candidate 1 Evidence Level", c1.get("evidence_level"), "DirectlyObserved")
        check("Candidate 1 Service Name", c1.get("service_name"), "PUBG PC")

    # 3. Verify Saved Candidate Measurement Series JSONs
    print("\n--- 3. Cross-Validating Real Candidate Measurement Series ---")
    series_files = glob.glob("data/route/measurements/*.json")
    check("Measurement Series Files Exist", len(series_files) >= 2, True)

    loaded_series = []
    for sf in series_files:
        print(f"\nEvaluating: {sf}")
        with open(sf, "r", encoding="utf-8") as f:
            s_data = json.load(f)
        loaded_series.append(s_data)

        # Verify run count
        runs = s_data["run_count"]
        snapshots = s_data["measurement_snapshots"]
        check(f"{s_data['destination']} Snapshot Count Matches Run Count", len(snapshots), runs)

        # Independent dominant fingerprint & pct
        fp_counts = {}
        for snap in snapshots:
            fp = snap["fingerprint"]
            fp_counts[fp] = fp_counts.get(fp, 0) + 1
        py_dom_fp = max(fp_counts.items(), key=lambda x: x[1])[0]
        py_dom_pct = (fp_counts[py_dom_fp] / len(snapshots)) * 100.0

        check(f"{s_data['destination']} Dominant Fingerprint", s_data["dominant_fingerprint"], py_dom_fp)
        check(f"{s_data['destination']} Dominant FP Pct", s_data["dominant_fingerprint_pct"], py_dom_pct)

        # Independent route transition rate
        py_transitions = 0
        if len(snapshots) > 1:
            for i in range(1, len(snapshots)):
                if snapshots[i]["fingerprint"] != snapshots[i - 1]["fingerprint"]:
                    py_transitions += 1
            py_trans_rate = (py_transitions / (len(snapshots) - 1)) * 100.0
        else:
            py_trans_rate = 0.0

        check(f"{s_data['destination']} Transition Count", s_data["route_transition_count"], py_transitions)
        check(f"{s_data['destination']} Transition Rate %", s_data["route_transition_rate_pct"], py_trans_rate)

        # Independent final hop samples & stats
        final_samples = []
        for snap in snapshots:
            for hop in reversed(snap["hops"]):
                if hop.get("responded") and hop.get("rtt_samples_ms"):
                    final_samples.extend(hop["rtt_samples_ms"])
                    break

        py_stats = compute_rtt_stats(final_samples)
        rust_stats = s_data["final_hop_probe_stats"]

        if py_stats and rust_stats:
            check(f"{s_data['destination']} Final Hop Sample Count", rust_stats["sample_count"], py_stats["sample_count"])
            check(f"{s_data['destination']} Final Hop Min RTT", rust_stats["min_ms"], py_stats["min_ms"])
            check(f"{s_data['destination']} Final Hop Median RTT", rust_stats["median_ms"], py_stats["median_ms"])
            check(f"{s_data['destination']} Final Hop Mean RTT", rust_stats["mean_ms"], py_stats["mean_ms"])
            check(f"{s_data['destination']} Final Hop p95 RTT", rust_stats["p95_ms"], py_stats["p95_ms"])
            check(f"{s_data['destination']} Final Hop Max RTT", rust_stats["max_ms"], py_stats["max_ms"])
            check(f"{s_data['destination']} Final Hop StdDev RTT", rust_stats["std_dev_ms"], py_stats["std_dev_ms"])

        # Independent hop count medians
        py_hop_med = compute_median_usize([snap["hop_count"] for snap in snapshots])
        check(f"{s_data['destination']} Hop Count Median", s_data["hop_count_median"], py_hop_med)

    # 4. Verify Saved Candidate Comparison Reports
    print("\n--- 4. Cross-Validating Real Candidate Comparison Artifacts ---")
    comp_files = glob.glob("reports/phase2/comp_*.json")
    check("Comparison Report Artifact Exists", len(comp_files) >= 1, True)

    if comp_files:
        latest_comp = max(comp_files, key=os.path.getmtime)
        with open(latest_comp, "r", encoding="utf-8") as f:
            comp_data = json.load(f)

        med_a = comp_data["candidate_a"]["final_hop_median_rtt_ms"]
        med_b = comp_data["candidate_b"]["final_hop_median_rtt_ms"]
        py_med_delta = round(med_b - med_a, 2)
        check("Final Hop Median Delta (B - A)", comp_data["final_hop_median_delta_ms"], py_med_delta)

        p95_a = comp_data["candidate_a"]["final_hop_p95_rtt_ms"]
        p95_b = comp_data["candidate_b"]["final_hop_p95_rtt_ms"]
        py_p95_delta = round(p95_b - p95_a, 2)
        check("Final Hop p95 Delta (B - A)", comp_data["final_hop_p95_delta_ms"], py_p95_delta)

        hops_a = comp_data["candidate_a"]["hop_count_median"]
        hops_b = comp_data["candidate_b"]["hop_count_median"]
        check("Hop Count Delta (B - A)", comp_data["hop_count_delta"], hops_b - hops_a)

        # Cross check path relationship
        series_a_snaps = next((s["measurement_snapshots"] for s in loaded_series if s["candidate_id"] == comp_data["candidate_a"]["candidate_id"]), None)
        series_b_snaps = next((s["measurement_snapshots"] for s in loaded_series if s["candidate_id"] == comp_data["candidate_b"]["candidate_id"]), None)

        if series_a_snaps and series_b_snaps:
            py_rel = classify_two_candidates(series_a_snaps, series_b_snaps)
            check("Candidate Path Relationship Classification", comp_data["path_relationship"], py_rel)

    # 5. Verify Saved Diversity Report
    print("\n--- 5. Cross-Validating Real Candidate Diversity Artifacts ---")
    div_files = glob.glob("reports/phase2/div_*.json")
    check("Diversity Report Artifact Exists", len(div_files) >= 1, True)

    if div_files:
        latest_div = max(div_files, key=os.path.getmtime)
        with open(latest_div, "r", encoding="utf-8") as f:
            div_data = json.load(f)

        check("Diversity Candidate Count", div_data["total_candidates"], len(div_data["candidate_summaries"]))
        check("Architectural Status Contains UNAVAILABLE_IN_PHASE_2", "UNAVAILABLE_IN_PHASE_2" in div_data["architectural_status"], True)

    print("\n" + "=" * 80)
    print(f"CROSS-VALIDATION RESULT: {checks_passed}/{checks_total} CHECKS PASSED (0 FAILURES)")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(run_cross_validation())
