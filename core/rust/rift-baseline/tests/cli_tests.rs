use std::process::Command;

#[test]
fn test_cli_help_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .arg("--help")
        .output()
        .expect("Failed to execute rift-baseline --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rift-baseline"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("system"));
    assert!(stdout.contains("connectivity"));
    assert!(stdout.contains("route"));
    assert!(stdout.contains("game"));
    assert!(stdout.contains("game-test"));
    assert!(stdout.contains("report"));
}

#[test]
fn test_cli_version_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .arg("--version")
        .output()
        .expect("Failed to execute rift-baseline --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rift-baseline 0.1.0"));
}

#[test]
fn test_cli_system_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["--json", "system"])
        .output()
        .expect("Failed to execute rift-baseline --json system");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("system command output should be valid JSON");

    assert!(val.get("os").is_some());
    assert!(val.get("active_interface").is_some());
    assert!(val.get("default_gateway").is_some());
    assert!(val.get("isp_info").is_some());
}

#[test]
fn test_cli_connectivity_probes() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["--json", "connectivity", "--probes", "2", "--interval", "20"])
        .output()
        .expect("Failed to execute rift-baseline connectivity");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("connectivity output should be valid JSON");

    let arr = val.as_array().expect("connectivity output should be an array of baselines");
    assert!(!arr.is_empty());
}

#[test]
fn test_cli_invalid_probe_count() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["connectivity", "--probes", "0"])
        .output()
        .expect("Failed to execute rift-baseline connectivity");

    // Probe count 0 violates validation, should fail with exit code 1
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Probe count must be greater than 0"));
}

#[test]
fn test_cli_analyze_endpoints_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["analyze-endpoints", "--help"])
        .output()
        .expect("Failed to execute rift-baseline analyze-endpoints --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analyze passive TShark UDP packet capture metadata file"));
    assert!(stdout.contains("<FILE>"));
}

#[test]
fn test_cli_analyze_endpoints_file_not_found() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["analyze-endpoints", "non_existent_capture_file_9999.txt"])
        .output()
        .expect("Failed to execute rift-baseline analyze-endpoints");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to open capture file") || stderr.contains("Failed to analyze capture file"));
}

#[test]
fn test_cli_analyze_endpoints_with_real_capture_json() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let capture_path = std::path::Path::new(manifest_dir)
        .join("../../../data/baseline/raw/pubg_endpoints_60s.txt");

    if !capture_path.exists() {
        eprintln!("Skipping test: capture file not found at {:?}", capture_path);
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["--json", "analyze-endpoints", capture_path.to_str().unwrap()])
        .output()
        .expect("Failed to execute rift-baseline --json analyze-endpoints");

    assert!(output.status.success(), "Command failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout)
        .expect("analyze-endpoints JSON should be valid");

    let capture = val.get("capture").expect("capture metadata object must exist");
    assert_eq!(capture.get("total_lines_read").unwrap().as_u64().unwrap(), 9003);
    assert_eq!(capture.get("malformed_lines").unwrap().as_u64().unwrap(), 0);
    assert_eq!(capture.get("distinct_endpoints_count").unwrap().as_u64().unwrap(), 2);

    let endpoints = val.get("endpoints").expect("endpoints array must exist").as_array().unwrap();
    assert_eq!(endpoints.len(), 2);

    // Flow 1: 20.205.179.128:27528
    let f1 = &endpoints[0];
    assert_eq!(f1.get("rank").unwrap().as_u64().unwrap(), 1);
    assert_eq!(f1.get("classification").unwrap().as_str().unwrap(), "Highest Traffic Endpoint");
    assert_eq!(f1.get("remote_ip").unwrap().as_str().unwrap(), "20.205.179.128");
    assert_eq!(f1.get("remote_port").unwrap().as_u64().unwrap(), 27528);
    assert_eq!(f1.get("total_packets").unwrap().as_u64().unwrap(), 7679);
    assert_eq!(f1.get("tx_packets").unwrap().as_u64().unwrap(), 4718);
    assert_eq!(f1.get("rx_packets").unwrap().as_u64().unwrap(), 2961);
    assert_eq!(f1.get("total_bytes").unwrap().as_u64().unwrap(), 681177);
    assert_eq!(f1.get("tx_bytes").unwrap().as_u64().unwrap(), 317553);
    assert_eq!(f1.get("rx_bytes").unwrap().as_u64().unwrap(), 363624);
    assert_eq!(f1.get("rtt"), Some(&serde_json::Value::Null));
    assert_eq!(f1.get("packet_loss"), Some(&serde_json::Value::Null));

    // Flow 2: 85.236.96.163:25138
    let f2 = &endpoints[1];
    assert_eq!(f2.get("rank").unwrap().as_u64().unwrap(), 2);
    assert_eq!(f2.get("classification").unwrap().as_str().unwrap(), "Secondary Endpoint");
    assert_eq!(f2.get("remote_ip").unwrap().as_str().unwrap(), "85.236.96.163");
    assert_eq!(f2.get("remote_port").unwrap().as_u64().unwrap(), 25138);
    assert_eq!(f2.get("total_packets").unwrap().as_u64().unwrap(), 1324);
    assert_eq!(f2.get("tx_packets").unwrap().as_u64().unwrap(), 1205);
    assert_eq!(f2.get("rx_packets").unwrap().as_u64().unwrap(), 119);
    assert_eq!(f2.get("total_bytes").unwrap().as_u64().unwrap(), 116560);
    assert_eq!(f2.get("tx_bytes").unwrap().as_u64().unwrap(), 98554);
    assert_eq!(f2.get("rx_bytes").unwrap().as_u64().unwrap(), 18006);
}

#[test]
fn test_cli_analyze_endpoints_with_real_capture_text() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let capture_path = std::path::Path::new(manifest_dir)
        .join("../../../data/baseline/raw/pubg_endpoints_60s.txt");

    if !capture_path.exists() {
        eprintln!("Skipping test: capture file not found at {:?}", capture_path);
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["analyze-endpoints", capture_path.to_str().unwrap()])
        .output()
        .expect("Failed to execute rift-baseline analyze-endpoints");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RiftRoute Passive Endpoint Analysis"));
    assert!(stdout.contains("Endpoint #1: Highest Traffic Endpoint (UDP)"));
    assert!(stdout.contains("20.205.179.128:27528"));
    assert!(stdout.contains("Endpoint #2: Secondary Endpoint (UDP)"));
    assert!(stdout.contains("85.236.96.163:25138"));
    assert!(stdout.contains("NOT MEASURED (Passive UDP capture lacks protocol-level request/response correlation)"));
    assert!(stdout.contains("NOT MEASURED (UDP transport layer has no native sequence numbers)"));
}

#[test]
fn test_cli_route_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["route", "--help"])
        .output()
        .expect("Failed to execute rift-baseline route --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("measure"));
    assert!(stdout.contains("compare"));
    assert!(stdout.contains("stability"));
}

#[test]
fn test_cli_route_measure_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["route", "measure", "--help"])
        .output()
        .expect("Failed to execute rift-baseline route measure --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<DESTINATION>"));
    assert!(stdout.contains("--max-hops"));
    assert!(stdout.contains("--timeout-ms"));
    assert!(stdout.contains("--resolve"));
    assert!(stdout.contains("--save"));
}

#[test]
fn test_cli_route_compare_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["route", "compare", "--help"])
        .output()
        .expect("Failed to execute rift-baseline route compare --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<PREVIOUS>"));
    assert!(stdout.contains("<CURRENT>"));
}

#[test]
fn test_cli_route_stability_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["route", "stability", "--help"])
        .output()
        .expect("Failed to execute rift-baseline route stability --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("<INPUTS>"));
}

#[test]
fn test_cli_route_measure_invalid_destination() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["route", "measure", "1.1.1.1; echo evil"])
        .output()
        .expect("Failed to execute rift-baseline route measure with injection attempt");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Destination contains illegal character") || stderr.contains("Route measurement failed"));
}

#[test]
fn test_cli_route_compare_snapshots() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let snap1_path = temp_dir.path().join("snap1.json");
    let snap2_path = temp_dir.path().join("snap2.json");

    let snap1_json = r#"{
      "measurement_id": "route_20261002_000001_AAAA",
      "timestamp_utc": "2026-10-02T10:00:00Z",
      "destination": "1.1.1.1",
      "destination_ip": "1.1.1.1",
      "destination_port": null,
      "probe_method": "Windows Tracert",
      "resolve_hostnames": false,
      "active_interface": "Wi-Fi",
      "source_ipv4": "192.168.1.14",
      "default_gateway": "192.168.1.1",
      "hop_count": 2,
      "responding_hops": 2,
      "timeout_hops": 0,
      "hops": [
        {
          "hop_number": 1,
          "addresses": ["192.168.1.1"],
          "primary_address": "192.168.1.1",
          "hostname": null,
          "rtt_samples_ms": [1.0, 1.0, 1.0],
          "responded": true,
          "timeout_count": 0,
          "probe_count": 3,
          "rtt_stats": {
            "sample_count": 3,
            "min_ms": 1.0,
            "median_ms": 1.0,
            "mean_ms": 1.0,
            "p95_ms": 1.0,
            "p99_ms": 1.0,
            "max_ms": 1.0,
            "std_dev_ms": 0.0,
            "jitter_ms": 0.0
          },
          "is_timeout": false,
          "raw_line": ""
        },
        {
          "hop_number": 2,
          "addresses": ["1.1.1.1"],
          "primary_address": "1.1.1.1",
          "hostname": null,
          "rtt_samples_ms": [10.0, 11.0, 10.0],
          "responded": true,
          "timeout_count": 0,
          "probe_count": 3,
          "rtt_stats": {
            "sample_count": 3,
            "min_ms": 10.0,
            "median_ms": 10.0,
            "mean_ms": 10.3,
            "p95_ms": 10.9,
            "p99_ms": 11.0,
            "max_ms": 11.0,
            "std_dev_ms": 0.58,
            "jitter_ms": 0.5
          },
          "is_timeout": false,
          "raw_line": ""
        }
      ],
      "fingerprint": "1111222233334444",
      "fingerprint_sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
      "canonical_path": "1:192.168.1.1|2:1.1.1.1",
      "measurement_duration_ms": 500,
      "scientific_disclaimer": "probe RTT is not game RTT"
    }"#;

    let snap2_json = r#"{
      "measurement_id": "route_20261002_000002_BBBB",
      "timestamp_utc": "2026-10-02T10:05:00Z",
      "destination": "1.1.1.1",
      "destination_ip": "1.1.1.1",
      "destination_port": null,
      "probe_method": "Windows Tracert",
      "resolve_hostnames": false,
      "active_interface": "Wi-Fi",
      "source_ipv4": "192.168.1.14",
      "default_gateway": "192.168.1.1",
      "hop_count": 2,
      "responding_hops": 2,
      "timeout_hops": 0,
      "hops": [
        {
          "hop_number": 1,
          "addresses": ["192.168.1.1"],
          "primary_address": "192.168.1.1",
          "hostname": null,
          "rtt_samples_ms": [1.0, 1.0, 1.0],
          "responded": true,
          "timeout_count": 0,
          "probe_count": 3,
          "rtt_stats": {
            "sample_count": 3,
            "min_ms": 1.0,
            "median_ms": 1.0,
            "mean_ms": 1.0,
            "p95_ms": 1.0,
            "p99_ms": 1.0,
            "max_ms": 1.0,
            "std_dev_ms": 0.0,
            "jitter_ms": 0.0
          },
          "is_timeout": false,
          "raw_line": ""
        },
        {
          "hop_number": 2,
          "addresses": ["1.0.0.1"],
          "primary_address": "1.0.0.1",
          "hostname": null,
          "rtt_samples_ms": [12.0, 12.0, 12.0],
          "responded": true,
          "timeout_count": 0,
          "probe_count": 3,
          "rtt_stats": {
            "sample_count": 3,
            "min_ms": 12.0,
            "median_ms": 12.0,
            "mean_ms": 12.0,
            "p95_ms": 12.0,
            "p99_ms": 12.0,
            "max_ms": 12.0,
            "std_dev_ms": 0.0,
            "jitter_ms": 0.0
          },
          "is_timeout": false,
          "raw_line": ""
        }
      ],
      "fingerprint": "5555666677778888",
      "fingerprint_sha256": "555566667777888899990000aaaabbbbccccddddeeeeffff1111222233334444",
      "canonical_path": "1:192.168.1.1|2:1.0.0.1",
      "measurement_duration_ms": 520,
      "scientific_disclaimer": "probe RTT is not game RTT"
    }"#;

    std::fs::write(&snap1_path, snap1_json).expect("write snap1");
    std::fs::write(&snap2_path, snap2_json).expect("write snap2");

    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args([
            "--json",
            "route",
            "compare",
            snap1_path.to_str().unwrap(),
            snap2_path.to_str().unwrap(),
        ])
        .output()
        .expect("execute route compare");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(val.get("fingerprint_identical").unwrap().as_bool().unwrap(), false);
    assert_eq!(val.get("hop_differences").unwrap().as_array().unwrap().len(), 1);
    assert_eq!(
        val["hop_differences"][0]["diff_type"].as_str().unwrap(),
        "AddressChanged"
    );
}

#[test]
fn test_cli_route_stability_snapshots() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
    let snap1_path = temp_dir.path().join("snap1.json");
    let snap2_path = temp_dir.path().join("snap2.json");

    let snap_base = r#"{
      "measurement_id": "route_20261002_000001_AAAA",
      "timestamp_utc": "2026-10-02T10:00:00Z",
      "destination": "1.1.1.1",
      "destination_ip": "1.1.1.1",
      "destination_port": null,
      "probe_method": "Windows Tracert",
      "resolve_hostnames": false,
      "active_interface": "Wi-Fi",
      "source_ipv4": "192.168.1.14",
      "default_gateway": "192.168.1.1",
      "hop_count": 1,
      "responding_hops": 1,
      "timeout_hops": 0,
      "hops": [
        {
          "hop_number": 1,
          "addresses": ["192.168.1.1"],
          "primary_address": "192.168.1.1",
          "hostname": null,
          "rtt_samples_ms": [1.0],
          "responded": true,
          "timeout_count": 0,
          "probe_count": 3,
          "rtt_stats": null,
          "is_timeout": false,
          "raw_line": ""
        }
      ],
      "fingerprint": "1111222233334444",
      "fingerprint_sha256": "1111222233334444",
      "canonical_path": "1:192.168.1.1",
      "measurement_duration_ms": 300,
      "scientific_disclaimer": ""
    }"#;

    std::fs::write(&snap1_path, snap_base).expect("write snap1");
    std::fs::write(&snap2_path, snap_base).expect("write snap2");

    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args([
            "--json",
            "route",
            "stability",
            temp_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("execute route stability");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    assert_eq!(val.get("total_snapshots").unwrap().as_u64().unwrap(), 2);
    assert_eq!(val.get("unique_fingerprints_count").unwrap().as_u64().unwrap(), 1);
    assert_eq!(val.get("dominant_fingerprint").unwrap().as_str().unwrap(), "1111222233334444");
    assert_eq!(val.get("dominant_fingerprint_pct").unwrap().as_f64().unwrap(), 100.0);
}

#[test]
fn test_cli_route_candidates_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args(["route", "candidates", "--help"])
        .output()
        .expect("execute route candidates --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("discover"));
    assert!(stdout.contains("measure"));
    assert!(stdout.contains("compare"));
    assert!(stdout.contains("analyze"));
}

#[test]
fn test_cli_route_candidates_discover_from_capture_json() {
    let capture_path = std::path::Path::new("../../../data/baseline/raw/pubg_endpoints_60s.txt");
    if !capture_path.exists() {
        // Try relative to workspace
        let fallback = std::path::Path::new("data/baseline/raw/pubg_endpoints_60s.txt");
        if !fallback.exists() {
            return; // Skip if test fixture not present
        }
    }

    let p = if capture_path.exists() { capture_path } else { std::path::Path::new("data/baseline/raw/pubg_endpoints_60s.txt") };

    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args([
            "--json",
            "route",
            "candidates",
            "discover",
            "--capture-file",
            p.to_str().unwrap(),
        ])
        .output()
        .expect("execute route candidates discover");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON array");
    assert!(val.is_array());
    let arr = val.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0].get("service_name").unwrap().as_str().unwrap(), "PUBG PC");
    assert!(arr[0].get("candidate_id").is_some());
    assert!(arr[0].get("ip").is_some());
}

#[test]
fn test_cli_route_candidates_discover_text() {
    let capture_path = std::path::Path::new("../../../data/baseline/raw/pubg_endpoints_60s.txt");
    let p = if capture_path.exists() {
        capture_path
    } else {
        std::path::Path::new("data/baseline/raw/pubg_endpoints_60s.txt")
    };
    if !p.exists() {
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args([
            "route",
            "candidates",
            "discover",
            "--capture-file",
            p.to_str().unwrap(),
        ])
        .output()
        .expect("execute route candidates discover text");

    assert!(output.status.success(), "Stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RIFTROUTE CANDIDATE DISCOVERY REPORT"));
    assert!(stdout.contains("CANDIDATE ENDPOINTS:"));
    assert!(stdout.contains("PUBG PC"));
}

#[test]
fn test_cli_route_candidates_compare_and_analyze() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let series_a_path = temp_dir.path().join("series_a.json");
    let series_b_path = temp_dir.path().join("series_b.json");

    let series_a_json = r#"{
      "candidate_id": "cand_20_205_179_128_7000",
      "destination": "20.205.179.128",
      "target_ip": "20.205.179.128",
      "target_port": 7000,
      "service_name": "PUBG PC",
      "run_count": 2,
      "measurement_snapshots": [
        {
          "measurement_id": "m1",
          "timestamp_utc": "2026-10-02T10:00:00Z",
          "destination": "20.205.179.128",
          "destination_ip": "20.205.179.128",
          "destination_port": 7000,
          "probe_method": "Windows Tracert",
          "resolve_hostnames": false,
          "active_interface": "Wi-Fi",
          "source_ipv4": "192.168.1.14",
          "default_gateway": "192.168.1.1",
          "hop_count": 2,
          "responding_hops": 2,
          "timeout_hops": 0,
          "hops": [
            {
              "hop_number": 1,
              "addresses": ["192.168.1.1"],
              "primary_address": "192.168.1.1",
              "hostname": null,
              "rtt_samples_ms": [1.0],
              "responded": true,
              "timeout_count": 0,
              "probe_count": 1,
              "rtt_stats": null,
              "is_timeout": false,
              "raw_line": ""
            },
            {
              "hop_number": 2,
              "addresses": ["20.205.179.128"],
              "primary_address": "20.205.179.128",
              "hostname": null,
              "rtt_samples_ms": [55.0],
              "responded": true,
              "timeout_count": 0,
              "probe_count": 1,
              "rtt_stats": null,
              "is_timeout": false,
              "raw_line": ""
            }
          ],
          "fingerprint": "FP_A_SNAP",
          "fingerprint_sha256": "FP_A_SNAP",
          "canonical_path": "1:192.168.1.1->2:20.205.179.128",
          "measurement_duration_ms": 1000,
          "scientific_disclaimer": ""
        }
      ],
      "measurement_ids": ["m1"],
      "unique_fingerprints": ["FP_A_SNAP"],
      "dominant_fingerprint": "FP_A_SNAP",
      "dominant_fingerprint_pct": 100.0,
      "path_difference_classification": "SameObservedPath",
      "final_hop_probe_stats": {
        "sample_count": 1,
        "min_ms": 55.0,
        "median_ms": 55.0,
        "mean_ms": 55.0,
        "p95_ms": 55.0,
        "p99_ms": 55.0,
        "max_ms": 55.0,
        "std_dev_ms": 0.0,
        "jitter_ms": null
      },
      "hop_count_median": 2,
      "responding_hop_count_median": 2,
      "timeout_hop_count_median": 0,
      "route_transition_count": 0,
      "route_transition_rate_pct": 0.0,
      "execution_window_start": "2026-10-02T10:00:00Z",
      "execution_window_end": "2026-10-02T10:01:00Z",
      "scientific_disclaimer": "Disclaimer"
    }"#;

    let series_b_json = r#"{
      "candidate_id": "cand_85_236_96_163_8000",
      "destination": "85.236.96.163",
      "target_ip": "85.236.96.163",
      "target_port": 8000,
      "service_name": "PUBG PC",
      "run_count": 2,
      "measurement_snapshots": [
        {
          "measurement_id": "m2",
          "timestamp_utc": "2026-10-02T10:00:00Z",
          "destination": "85.236.96.163",
          "destination_ip": "85.236.96.163",
          "destination_port": 8000,
          "probe_method": "Windows Tracert",
          "resolve_hostnames": false,
          "active_interface": "Wi-Fi",
          "source_ipv4": "192.168.1.14",
          "default_gateway": "192.168.1.1",
          "hop_count": 2,
          "responding_hops": 2,
          "timeout_hops": 0,
          "hops": [
            {
              "hop_number": 1,
              "addresses": ["192.168.1.1"],
              "primary_address": "192.168.1.1",
              "hostname": null,
              "rtt_samples_ms": [1.0],
              "responded": true,
              "timeout_count": 0,
              "probe_count": 1,
              "rtt_stats": null,
              "is_timeout": false,
              "raw_line": ""
            },
            {
              "hop_number": 2,
              "addresses": ["85.236.96.163"],
              "primary_address": "85.236.96.163",
              "hostname": null,
              "rtt_samples_ms": [145.0],
              "responded": true,
              "timeout_count": 0,
              "probe_count": 1,
              "rtt_stats": null,
              "is_timeout": false,
              "raw_line": ""
            }
          ],
          "fingerprint": "FP_B_SNAP",
          "fingerprint_sha256": "FP_B_SNAP",
          "canonical_path": "1:192.168.1.1->2:85.236.96.163",
          "measurement_duration_ms": 1000,
          "scientific_disclaimer": ""
        }
      ],
      "measurement_ids": ["m2"],
      "unique_fingerprints": ["FP_B_SNAP"],
      "dominant_fingerprint": "FP_B_SNAP",
      "dominant_fingerprint_pct": 100.0,
      "path_difference_classification": "SameObservedPath",
      "final_hop_probe_stats": {
        "sample_count": 1,
        "min_ms": 145.0,
        "median_ms": 145.0,
        "mean_ms": 145.0,
        "p95_ms": 145.0,
        "p99_ms": 145.0,
        "max_ms": 145.0,
        "std_dev_ms": 0.0,
        "jitter_ms": null
      },
      "hop_count_median": 2,
      "responding_hop_count_median": 2,
      "timeout_hop_count_median": 0,
      "route_transition_count": 0,
      "route_transition_rate_pct": 0.0,
      "execution_window_start": "2026-10-02T10:00:00Z",
      "execution_window_end": "2026-10-02T10:01:00Z",
      "scientific_disclaimer": "Disclaimer"
    }"#;

    std::fs::write(&series_a_path, series_a_json).expect("write series_a");
    std::fs::write(&series_b_path, series_b_json).expect("write series_b");

    // 1. Test compare
    let output_comp = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args([
            "--json",
            "route",
            "candidates",
            "compare",
            series_a_path.to_str().unwrap(),
            series_b_path.to_str().unwrap(),
        ])
        .output()
        .expect("execute route candidates compare");

    assert!(output_comp.status.success(), "Stderr: {}", String::from_utf8_lossy(&output_comp.stderr));
    let stdout_comp = String::from_utf8_lossy(&output_comp.stdout);
    let val_comp: serde_json::Value = serde_json::from_str(&stdout_comp).expect("valid JSON compare");
    assert_eq!(val_comp.get("path_relationship").unwrap().as_str().unwrap(), "StructuralRouteVariation");
    assert_eq!(val_comp.get("final_hop_median_delta_ms").unwrap().as_f64().unwrap(), 90.0);

    // 2. Test analyze
    let output_ana = Command::new(env!("CARGO_BIN_EXE_rift-baseline"))
        .args([
            "--json",
            "route",
            "candidates",
            "analyze",
            "--measurements-dir",
            temp_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("execute route candidates analyze");

    assert!(output_ana.status.success(), "Stderr: {}", String::from_utf8_lossy(&output_ana.stderr));
    let stdout_ana = String::from_utf8_lossy(&output_ana.stdout);
    let val_ana: serde_json::Value = serde_json::from_str(&stdout_ana).expect("valid JSON analyze");
    assert_eq!(val_ana.get("total_candidates").unwrap().as_u64().unwrap(), 2);
    assert_eq!(val_ana.get("structural_variation_count").unwrap().as_u64().unwrap(), 1);
}


