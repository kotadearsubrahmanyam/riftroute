use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Strict validation of user-provided network destinations to prevent shell injection,
/// flag injection, or malformed input.
pub fn validate_destination(dest: &str) -> Result<String, String> {
    let trimmed = dest.trim();
    if trimmed.is_empty() {
        return Err("Destination cannot be empty.".to_string());
    }

    if trimmed.len() > 253 {
        return Err("Destination exceeds maximum length of 253 characters.".to_string());
    }

    // Disallow leading hyphen (prevents flag injection into tracert command line)
    if trimmed.starts_with('-') || trimmed.starts_with('/') {
        return Err("Destination cannot begin with '-' or '/'.".to_string());
    }

    // Disallow shell metacharacters, spaces, control characters
    let forbidden_chars = [
        ' ', '\t', '\r', '\n', ';', '&', '|', '$', '`', '<', '>', '(', ')',
        '{', '}', '"', '\'', '\\', '!', '?', '*', '[', ']'
    ];
    if let Some(c) = trimmed.chars().find(|c| forbidden_chars.contains(c)) {
        return Err(format!("Destination contains illegal character '{}'.", c));
    }

    // 1. Check if valid IPv4 address
    if Ipv4Addr::from_str(trimmed).is_ok() {
        return Ok(trimmed.to_string());
    }

    // 2. Check if valid IPv6 address
    if Ipv6Addr::from_str(trimmed).is_ok() {
        return Ok(trimmed.to_string());
    }

    // 3. Check if valid RFC 1123 DNS hostname
    // Labels separated by dots; each label 1-63 chars, containing alphanumeric and hyphens (not leading/trailing)
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.is_empty() {
        return Err("Invalid hostname format.".to_string());
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("Hostname labels must be between 1 and 63 characters.".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Hostname labels cannot start or end with a hyphen.".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("Hostname labels must contain only alphanumeric characters and hyphens.".to_string());
        }
    }

    Ok(trimmed.to_string())
}

/// Execution metadata and captured output from a Windows tracert diagnostic invocation.
pub struct TracertExecutionResult {
    pub destination: String,
    pub command_args: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration: Duration,
    pub timed_out: bool,
}

pub struct TracertExecutor;

impl TracertExecutor {
    /// Execute Windows tracert under strict process isolation and timeout constraints.
    pub fn execute(
        destination: &str,
        max_hops: u8,
        timeout_ms: u64,
        resolve_hostnames: bool,
        max_execution_duration: Duration,
    ) -> Result<TracertExecutionResult, String> {
        let valid_dest = validate_destination(destination)?;
        let max_hops_clamped = max_hops.clamp(1, 64);
        let timeout_ms_clamped = timeout_ms.clamp(100, 10000);

        let mut args = Vec::new();
        if !resolve_hostnames {
            args.push("-d".to_string());
        }
        args.push("-h".to_string());
        args.push(max_hops_clamped.to_string());
        args.push("-w".to_string());
        args.push(timeout_ms_clamped.to_string());
        args.push(valid_dest.clone());

        let start_time = Instant::now();

        // Spawn child process directly without shell interpreter
        let mut child = Command::new("tracert")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn tracert: {}. Verify Windows environment.", e))?;

        // Enforce execution timeout via polling with sleep
        let poll_interval = Duration::from_millis(100);
        let mut timed_out = false;

        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    break;
                }
                Ok(None) => {
                    if start_time.elapsed() >= max_execution_duration {
                        let _ = child.kill();
                        timed_out = true;
                        break;
                    }
                    std::thread::sleep(poll_interval);
                }
                Err(e) => {
                    let _ = child.kill();
                    return Err(format!("Error while monitoring tracert process: {}", e));
                }
            }
        }

        let duration = start_time.elapsed();

        if timed_out {
            return Err(format!(
                "tracert execution exceeded safety timeout of {} seconds and was terminated.",
                max_execution_duration.as_secs()
            ));
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed to retrieve tracert output: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok(TracertExecutionResult {
            destination: valid_dest,
            command_args: args,
            stdout,
            stderr,
            exit_code: output.status.code(),
            duration,
            timed_out: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_ipv4() {
        assert_eq!(validate_destination("1.1.1.1").unwrap(), "1.1.1.1");
        assert_eq!(validate_destination("192.168.1.1").unwrap(), "192.168.1.1");
        assert_eq!(validate_destination("20.205.179.128").unwrap(), "20.205.179.128");
    }

    #[test]
    fn test_validate_valid_ipv6() {
        assert_eq!(validate_destination("2606:4700:4700::1111").unwrap(), "2606:4700:4700::1111");
        assert_eq!(validate_destination("::1").unwrap(), "::1");
    }

    #[test]
    fn test_validate_valid_hostname() {
        assert_eq!(validate_destination("one.one.one.one").unwrap(), "one.one.one.one");
        assert_eq!(validate_destination("dns.google").unwrap(), "dns.google");
        assert_eq!(validate_destination("my-router-01.local").unwrap(), "my-router-01.local");
    }

    #[test]
    fn test_validate_rejects_empty_or_whitespace() {
        assert!(validate_destination("").is_err());
        assert!(validate_destination("   ").is_err());
    }

    #[test]
    fn test_validate_rejects_command_injection() {
        assert!(validate_destination("1.1.1.1; echo evil").is_err());
        assert!(validate_destination("1.1.1.1 & calc.exe").is_err());
        assert!(validate_destination("1.1.1.1 | dir").is_err());
        assert!(validate_destination("`calc`").is_err());
        assert!(validate_destination("$PATH").is_err());
        assert!(validate_destination("1.1.1.1\nevil").is_err());
    }

    #[test]
    fn test_validate_rejects_flag_injection() {
        assert!(validate_destination("-d 1.1.1.1").is_err());
        assert!(validate_destination("/flag").is_err());
        assert!(validate_destination("-h 1").is_err());
    }
}
