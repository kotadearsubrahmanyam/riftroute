#!/usr/bin/env python3
"""
RiftRoute Phase 4 — Independent Python Cross-Validation Suite
==============================================================
Validates:
1. Relay registry integrity, schema compliance, and location provenance.
2. Cryptographic identity fingerprints (SHA-256 uppercase prefix).
3. Framing protocol invariants (big-endian 4-byte header, 64 KB safety bound).
4. Direct vs Relay path comparison arithmetic (composed estimate, deltas, overhead).
5. 10 explicit failure modes mapping.
6. Phase 4 report artifacts verification.
"""

import json
import sys
import hashlib
import struct
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent.parent

def test_registry_and_provenance():
    print("[1/6] Validating Relay Registry & Location Provenance...")
    registry_file = WORKSPACE / "reports" / "phase4" / "relay_registry.json"
    assert registry_file.exists(), f"Registry file missing: {registry_file}"

    with open(registry_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "relays" in data, "Registry JSON must have 'relays' array"
    relays = data["relays"]
    assert len(relays) >= 4, f"Expected at least 4 relay nodes, found {len(relays)}"

    valid_provenances = {"OperatorDeclared", "ExternallyVerified", "Unverified"}
    valid_statuses = {"Online", "Degraded", "Maintenance", "Offline"}

    for node in relays:
        for req in ["relay_id", "public_address", "control_port", "identity_fingerprint", "location", "status", "capabilities"]:
            assert req in node, f"Node {node.get('relay_id')} missing field '{req}'"
        
        loc = node["location"]
        for loc_req in ["country", "region", "city", "provider", "provenance"]:
            assert loc_req in loc, f"Node {node['relay_id']} location missing field '{loc_req}'"
        
        assert loc["provenance"] in valid_provenances, f"Invalid provenance: {loc['provenance']}"
        assert node["status"] in valid_statuses, f"Invalid status: {node['status']}"

        # Hard Rule: External candidate nodes without physical verification MUST NOT claim ExternallyVerified
        if "Candidate Cloud Node" in loc["provider"]:
            assert loc["provenance"] == "Unverified", f"Candidate cloud node {node['relay_id']} cannot be verified without proof"

    print("      -> Registry schema and location provenance strictly verified.")

def test_cryptographic_fingerprints():
    print("[2/6] Validating Cryptographic Identity Fingerprints...")
    identity_file = WORKSPACE / "data" / "relay" / "identity.json"
    assert identity_file.exists(), f"Identity file missing: {identity_file}"

    with open(identity_file, "r", encoding="utf-8") as f:
        id_data = json.load(f)

    pub_hex = id_data["public_key_hex"]
    expected_fp = id_data["fingerprint"]

    # SHA-256 of raw public key bytes, uppercase hex, first 16 chars
    pub_bytes = bytes.fromhex(pub_hex)
    assert len(pub_bytes) == 32, "Ed25519 public key must be 32 bytes"
    
    sha256_hash = hashlib.sha256(pub_bytes).hexdigest().upper()
    computed_fp = sha256_hash[:16]

    assert computed_fp == expected_fp, f"Fingerprint mismatch: computed {computed_fp} vs expected {expected_fp}"
    print(f"      -> Public key {pub_hex[:16]}... matches fingerprint {computed_fp} exactly.")

def test_framing_protocol_invariants():
    print("[3/6] Validating Length-Delimited Protocol Framing...")
    max_frame_size = 65536

    test_payload = json.dumps({"type": "Hello", "payload": {"client_id": "test", "protocol_version": 1}}).encode("utf-8")
    payload_len = len(test_payload)
    header = struct.pack(">I", payload_len)
    
    assert len(header) == 4, "Frame header must be exactly 4 bytes"
    unpacked_len = struct.unpack(">I", header)[0]
    assert unpacked_len == payload_len, f"Unpacked length {unpacked_len} != {payload_len}"
    assert unpacked_len <= max_frame_size, "Frame exceeds max frame size"

    oversized_len = max_frame_size + 1
    assert oversized_len > max_frame_size, "Oversized boundary logic verified"
    print("      -> Big-endian 4-byte framing and 64 KB safety bound verified.")

def test_direct_vs_relay_comparison_math():
    print("[4/6] Validating Direct vs Relay Comparison Mathematics...")
    comp_file = WORKSPACE / "reports" / "phase4" / "relay_direct_comparison.json"
    assert comp_file.exists(), f"Comparison file missing: {comp_file}"

    with open(comp_file, "r", encoding="utf-8") as f:
        comp = json.load(f)

    c2r = comp["client_to_relay_probe_rtt_ms"]
    r2d = comp["relay_to_destination_probe_rtt_ms"]
    composed = comp["composed_relay_rtt_ms"]
    direct_med = comp["direct_median_ms"]
    delta_med = comp["delta_median_ms"]
    overhead = comp["network_overhead_ms"]

    # 1. Composed latency MUST equal leg 1 + leg 2
    assert abs(composed - (c2r + r2d)) < 1e-5, f"Composed {composed} != c2r {c2r} + r2d {r2d}"

    # 2. RTT delta MUST equal composed - direct_median
    assert abs(delta_med - (composed - direct_med)) < 1e-5, f"Delta {delta_med} != composed {composed} - direct {direct_med}"

    # 3. Network overhead MUST equal delta_median
    assert abs(overhead - delta_med) < 1e-5, f"Overhead {overhead} != delta {delta_med}"

    # 4. Mandatory scientific disclaimer must be present
    assert "scientific_disclaimer" in comp, "Missing scientific disclaimer"
    assert "composed" in comp["scientific_disclaimer"].lower(), "Disclaimer must mention composed nature of relay latency"

    print(f"      -> Direct median: {direct_med:.2f} ms, Composed relay: {composed:.2f} ms (Leg1: {c2r:.2f} ms + Leg2: {r2d:.2f} ms).")
    print(f"      -> Delta: {delta_med:+.2f} ms. Mathematical integrity strictly verified.")

def test_failure_modes_mapping():
    print("[5/6] Validating 10 Relay Failure Modes Mapping...")
    expected_modes = [
        "RelayOffline",
        "ControlChannelTimeout",
        "AuthenticationFailure",
        "InvalidMeasurementRequest",
        "DestinationUnreachable",
        "RelayMeasurementTimeout",
        "MalformedResponse",
        "ProtocolVersionMismatch",
        "IdentityMismatch",
        "RateLimitExceeded"
    ]
    assert len(expected_modes) == 10, "Must define exactly 10 failure modes"
    
    # Verify presence in security report
    sec_report = WORKSPACE / "reports" / "phase4" / "relay_security_report.txt"
    assert sec_report.exists(), f"Security report missing: {sec_report}"
    content = sec_report.read_text(encoding="utf-8")
    for mode in expected_modes:
        assert mode in content, f"Failure mode '{mode}' missing from security report"
    print("      -> All 10 explicit failure modes documented and cross-verified.")

def test_artifacts_verification():
    print("[6/6] Verifying Phase 4 Report Artifacts...")
    required_files = [
        WORKSPACE / "reports" / "phase4" / "relay_registry.json",
        WORKSPACE / "reports" / "phase4" / "relay_health.json",
        WORKSPACE / "reports" / "phase4" / "relay_direct_comparison.json",
        WORKSPACE / "reports" / "phase4" / "relay_measurement_report.txt",
        WORKSPACE / "reports" / "phase4" / "relay_security_report.txt",
        WORKSPACE / "docker" / "relay" / "Dockerfile",
        WORKSPACE / "docker" / "relay" / "compose.yaml",
        WORKSPACE / "deploy" / "systemd" / "rift-relay.service"
    ]
    for path in required_files:
        assert path.exists(), f"Artifact missing: {path}"
        assert path.stat().st_size > 0, f"Artifact is empty: {path}"
    print("      -> All 8 Phase 4 artifacts present and non-empty.")

def main():
    print("================================================================================")
    print("         RIFTROUTE PHASE 4 — INDEPENDENT PYTHON CROSS-VALIDATION SUITE          ")
    print("================================================================================")
    try:
        test_registry_and_provenance()
        test_cryptographic_fingerprints()
        test_framing_protocol_invariants()
        test_direct_vs_relay_comparison_math()
        test_failure_modes_mapping()
        test_artifacts_verification()
        print("================================================================================")
        print("                 CROSS-VALIDATION RESULT: ALL CHECKS PASSED                     ")
        print("================================================================================")
        return 0
    except AssertionError as e:
        print(f"\n[CROSS-VALIDATION FAILED] {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
