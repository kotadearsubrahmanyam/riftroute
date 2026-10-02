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
