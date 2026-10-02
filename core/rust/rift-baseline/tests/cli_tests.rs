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

