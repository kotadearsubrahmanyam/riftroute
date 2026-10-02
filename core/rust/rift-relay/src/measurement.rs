use std::net::{IpAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};
use chrono::Utc;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::models::{ProbeProtocol, RelayMeasurementResult};

pub struct RelayMeasurementEngine;

impl RelayMeasurementEngine {
    /// Strictly validate a target destination string to prevent command injection,
    /// SSRF into loopback/private ranges, or malformed input.
    pub fn validate_destination(dest: &str, allow_private: bool) -> Result<(), String> {
        let trimmed = dest.trim();
        if trimmed.is_empty() {
            return Err("Destination cannot be empty or whitespace".to_string());
        }
        if trimmed.len() > 255 {
            return Err("Destination exceeds maximum length of 255 characters".to_string());
        }
        if trimmed.starts_with('-') || trimmed.starts_with('/') {
            return Err("Destination cannot start with command-line flag characters".to_string());
        }

        // Metacharacter rejection
        let forbidden = ['&', '|', ';', '$', '`', '<', '>', '\n', '\r', ' ', '\t', '\\', '"', '\''];
        if trimmed.chars().any(|c| forbidden.contains(&c)) {
            return Err("Destination contains forbidden shell metacharacters".to_string());
        }

        // Allowed character set: alphanumeric, dots, hyphens, colons (IPv6/port)
        let re = Regex::new(r"^[a-zA-Z0-9.:\[\]-]+$").unwrap();
        if !re.is_match(trimmed) {
            return Err("Destination contains invalid characters".to_string());
        }

        // Parse IP or extract host from host:port
        let (host_part, _port_opt) = parse_host_and_port(trimmed);

        if let Ok(ip) = host_part.parse::<IpAddr>() {
            if !allow_private && is_private_or_loopback(&ip) {
                return Err(format!(
                    "Probing private/loopback IP address {} is prohibited on this relay",
                    ip
                ));
            }
        }

        Ok(())
    }

    /// Execute a controlled diagnostic measurement from the relay toward the destination.
    pub fn execute_measurement(
        relay_id: &str,
        request_id: &str,
        destination: &str,
        protocol: ProbeProtocol,
        max_hops: u8,
        timeout_ms: u64,
        allow_private: bool,
    ) -> RelayMeasurementResult {
        let start_time = Instant::now();

        // 1. Validation check
        if let Err(err) = Self::validate_destination(destination, allow_private) {
            return RelayMeasurementResult {
                request_id: request_id.to_string(),
                relay_id: relay_id.to_string(),
                destination: destination.to_string(),
                protocol,
                execution_duration_ms: start_time.elapsed().as_millis() as u64,
                success: false,
                error_message: Some(format!("Invalid measurement request: {}", err)),
                timestamp_utc: Utc::now().to_rfc3339(),
                ..Default::default()
            };
        }

        let clamped_hops = max_hops.clamp(1, 30);
        let clamped_timeout = timeout_ms.clamp(200, 5000);

        let (host_part, port_opt) = parse_host_and_port(destination);

        match protocol {
            ProbeProtocol::Tcp => {
                let target_port = port_opt.unwrap_or(80);
                Self::execute_tcp_probe(
                    relay_id,
                    request_id,
                    &host_part,
                    target_port,
                    clamped_timeout,
                    start_time,
                )
            }
            ProbeProtocol::Icmp => {
                Self::execute_icmp_probe(
                    relay_id,
                    request_id,
                    &host_part,
                    clamped_hops,
                    clamped_timeout,
                    start_time,
                )
            }
        }
    }

    fn execute_tcp_probe(
        relay_id: &str,
        request_id: &str,
        host: &str,
        port: u16,
        timeout_ms: u64,
        start_time: Instant,
    ) -> RelayMeasurementResult {
        let mut samples = Vec::new();
        let rounds = 3;
        let timeout = Duration::from_millis(timeout_ms);

        for _ in 0..rounds {
            let t0 = Instant::now();
            let addr_str = format!("{}:{}", host, port);
            let ok = if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&addr_str) {
                if let Some(addr) = addrs.next() {
                    TcpStream::connect_timeout(&addr, timeout).is_ok()
                } else {
                    false
                }
            } else {
                false
            };

            if ok {
                let rtt = t0.elapsed().as_secs_f64() * 1000.0;
                samples.push(rtt);
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        if samples.is_empty() {
            return RelayMeasurementResult {
                request_id: request_id.to_string(),
                relay_id: relay_id.to_string(),
                destination: format!("{}:{}", host, port),
                protocol: ProbeProtocol::Tcp,
                execution_duration_ms: duration_ms,
                success: false,
                error_message: Some("TCP connect timed out across all probe rounds".to_string()),
                timestamp_utc: Utc::now().to_rfc3339(),
                ..Default::default()
            };
        }

        let stats = compute_sample_stats(&samples);

        RelayMeasurementResult {
            request_id: request_id.to_string(),
            relay_id: relay_id.to_string(),
            destination: format!("{}:{}", host, port),
            protocol: ProbeProtocol::Tcp,
            probe_rtt_samples_ms: samples,
            median_rtt_ms: Some(stats.median),
            min_rtt_ms: Some(stats.min),
            max_rtt_ms: Some(stats.max),
            p95_rtt_ms: Some(stats.p95),
            std_dev_ms: Some(stats.std_dev),
            jitter_ms: stats.jitter,
            hop_count: 1,
            responding_hops: 1,
            timeout_hops: 0,
            route_fingerprint: format!("TCP_{}:{}", host, port),
            execution_duration_ms: duration_ms,
            success: true,
            error_message: None,
            timestamp_utc: Utc::now().to_rfc3339(),
            scientific_disclaimer: "TCP probe RTT measures SYN-ACK handshake delay, not UDP gaming RTT.".to_string(),
            ..Default::default()
        }
    }

    fn execute_icmp_probe(
        relay_id: &str,
        request_id: &str,
        host: &str,
        _max_hops: u8,
        timeout_ms: u64,
        start_time: Instant,
    ) -> RelayMeasurementResult {
        // Execute native ping with 3 probes safely
        #[cfg(target_os = "windows")]
        let mut cmd = {
            let mut c = Command::new("ping");
            c.arg("-n")
                .arg("3")
                .arg("-w")
                .arg(timeout_ms.to_string())
                .arg(host);
            c
        };

        #[cfg(not(target_os = "windows"))]
        let mut cmd = {
            let mut c = Command::new("ping");
            let timeout_secs = (timeout_ms / 1000).max(1).to_string();
            c.arg("-c")
                .arg("3")
                .arg("-W")
                .arg(timeout_secs)
                .arg(host);
            c
        };

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                return RelayMeasurementResult {
                    request_id: request_id.to_string(),
                    relay_id: relay_id.to_string(),
                    destination: host.to_string(),
                    protocol: ProbeProtocol::Icmp,
                    execution_duration_ms: start_time.elapsed().as_millis() as u64,
                    success: false,
                    error_message: Some(format!("Failed to execute ping process: {}", e)),
                    timestamp_utc: Utc::now().to_rfc3339(),
                    ..Default::default()
                };
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let samples = parse_ping_rtt_samples(&stdout);
        let duration_ms = start_time.elapsed().as_millis() as u64;

        if samples.is_empty() {
            return RelayMeasurementResult {
                request_id: request_id.to_string(),
                relay_id: relay_id.to_string(),
                destination: host.to_string(),
                protocol: ProbeProtocol::Icmp,
                execution_duration_ms: duration_ms,
                success: false,
                error_message: Some("Ping elicited zero responses (100% loss or timeout)".to_string()),
                timestamp_utc: Utc::now().to_rfc3339(),
                ..Default::default()
            };
        }

        let stats = compute_sample_stats(&samples);

        // Compute fingerprint from destination and observed median
        let mut hasher = Sha256::new();
        hasher.update(host.as_bytes());
        hasher.update(&stats.median.to_be_bytes());
        let fp = hex::encode_upper(hasher.finalize())[..16].to_string();

        RelayMeasurementResult {
            request_id: request_id.to_string(),
            relay_id: relay_id.to_string(),
            destination: host.to_string(),
            protocol: ProbeProtocol::Icmp,
            probe_rtt_samples_ms: samples,
            median_rtt_ms: Some(stats.median),
            min_rtt_ms: Some(stats.min),
            max_rtt_ms: Some(stats.max),
            p95_rtt_ms: Some(stats.p95),
            std_dev_ms: Some(stats.std_dev),
            jitter_ms: stats.jitter,
            hop_count: 1,
            responding_hops: 1,
            timeout_hops: 0,
            route_fingerprint: fp,
            execution_duration_ms: duration_ms,
            success: true,
            error_message: None,
            timestamp_utc: Utc::now().to_rfc3339(),
            scientific_disclaimer: "Ping probe RTT reflects ICMP control-plane generation latency, not in-game UDP gameplay latency.".to_string(),
            ..Default::default()
        }
    }
}

struct SampleStats {
    min: f64,
    median: f64,
    max: f64,
    p95: f64,
    std_dev: f64,
    jitter: Option<f64>,
}

fn compute_sample_stats(samples: &[f64]) -> SampleStats {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len();
    let min = sorted[0];
    let max = sorted[n - 1];

    let median = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    };

    let p95_idx = ((n as f64 - 1.0) * 0.95).round() as usize;
    let p95 = sorted[p95_idx.min(n - 1)];

    let mean = sorted.iter().sum::<f64>() / n as f64;
    let std_dev = if n > 1 {
        let var = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        var.sqrt()
    } else {
        0.0
    };

    let jitter = if samples.len() > 1 {
        let diffs: f64 = samples.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        Some(diffs / (samples.len() - 1) as f64)
    } else {
        None
    };

    SampleStats {
        min,
        median,
        max,
        p95,
        std_dev,
        jitter,
    }
}

fn parse_host_and_port(dest: &str) -> (String, Option<u16>) {
    if let Some(pos) = dest.rfind(':') {
        if let Ok(port) = dest[pos + 1..].parse::<u16>() {
            let host = dest[..pos].trim_matches(|c| c == '[' || c == ']').to_string();
            return (host, Some(port));
        }
    }
    (dest.to_string(), None)
}

fn is_private_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn parse_ping_rtt_samples(output: &str) -> Vec<f64> {
    let mut samples = Vec::new();
    let re = Regex::new(r"(?:time|temps|tiempo)[=<]([0-9.]+)\s*ms").unwrap();

    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            if let Ok(rtt) = caps[1].parse::<f64>() {
                samples.push(rtt);
            }
        }
    }
    samples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_validation() {
        // Valid destinations
        assert!(RelayMeasurementEngine::validate_destination("1.1.1.1", false).is_ok());
        assert!(RelayMeasurementEngine::validate_destination("cloudflare.com", false).is_ok());
        assert!(RelayMeasurementEngine::validate_destination("8.8.8.8:53", false).is_ok());

        // Private rejection when allow_private is false
        assert!(RelayMeasurementEngine::validate_destination("127.0.0.1", false).is_err());
        assert!(RelayMeasurementEngine::validate_destination("192.168.1.1", false).is_err());

        // Private accepted when allow_private is true
        assert!(RelayMeasurementEngine::validate_destination("127.0.0.1", true).is_ok());

        // Shell metacharacters rejection
        assert!(RelayMeasurementEngine::validate_destination("1.1.1.1; rm -rf /", true).is_err());
        assert!(RelayMeasurementEngine::validate_destination("1.1.1.1 | cat /etc/passwd", true).is_err());
        assert!(RelayMeasurementEngine::validate_destination("`whoami`.com", true).is_err());
        assert!(RelayMeasurementEngine::validate_destination("-h 1.1.1.1", true).is_err());
    }

    #[test]
    fn test_sample_stats_calculation() {
        let samples = vec![50.0, 52.0, 54.0];
        let stats = compute_sample_stats(&samples);
        assert_eq!(stats.min, 50.0);
        assert_eq!(stats.median, 52.0);
        assert_eq!(stats.max, 54.0);
        assert_eq!(stats.jitter, Some(2.0));
    }
}
