use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use crate::config::{BaselineConfig, Destination};
use crate::stats::RttStats;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeResult {
    pub seq: usize,
    pub timestamp: String,
    pub rtt_ms: Option<f64>,
    pub success: bool,
    pub error_msg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DestinationBaseline {
    pub destination: Destination,
    pub timestamp: String,
    pub probes: Vec<ProbeResult>,
    pub stats: RttStats,
}

pub struct ConnectivityTester;

impl ConnectivityTester {
    /// Run baseline measurements against a destination according to configuration.
    pub fn probe_destination(dest: &Destination, config: &BaselineConfig) -> DestinationBaseline {
        let timestamp = Utc::now().to_rfc3339();
        let mut probes = Vec::with_capacity(config.probe_count);

        for seq in 1..=config.probe_count {
            let probe_ts = Utc::now().to_rfc3339();
            let result = Self::ping_once(&dest.target, config.timeout_ms);

            probes.push(ProbeResult {
                seq,
                timestamp: probe_ts,
                rtt_ms: result.rtt_ms,
                success: result.success,
                error_msg: result.error_msg,
            });

            if seq < config.probe_count && config.interval_ms > 0 {
                sleep(Duration::from_millis(config.interval_ms));
            }
        }

        let raw_rtts: Vec<Option<f64>> = probes.iter().map(|p| p.rtt_ms).collect();
        let stats = RttStats::compute(&raw_rtts);

        DestinationBaseline {
            destination: dest.clone(),
            timestamp,
            probes,
            stats,
        }
    }

    /// Execute a single ICMP ping probe against a target IP/hostname.
    pub fn ping_once(target: &str, timeout_ms: u64) -> SinglePingResult {
        let output = match Command::new("ping")
            .args(["-n", "1", "-w", &timeout_ms.to_string(), target])
            .output()
        {
            Ok(out) => out,
            Err(e) => {
                return SinglePingResult {
                    rtt_ms: None,
                    success: false,
                    error_msg: Some(format!("Failed to spawn ping process: {}", e)),
                };
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_ping_output(&stdout)
    }

    /// Parse RTT from Windows ping.exe output string.
    pub fn parse_ping_output(output: &str) -> SinglePingResult {
        let time_re = Regex::new(r"time[=<]([0-9.]+)ms").unwrap();

        if output.contains("Request timed out") {
            return SinglePingResult {
                rtt_ms: None,
                success: false,
                error_msg: Some("Request timed out".to_string()),
            };
        }

        if output.contains("Destination host unreachable") {
            return SinglePingResult {
                rtt_ms: None,
                success: false,
                error_msg: Some("Destination host unreachable".to_string()),
            };
        }

        if output.contains("time<1ms") {
            return SinglePingResult {
                rtt_ms: Some(0.5),
                success: true,
                error_msg: None,
            };
        }

        if let Some(captures) = time_re.captures(output) {
            if let Some(matched) = captures.get(1) {
                if let Ok(rtt) = matched.as_str().parse::<f64>() {
                    return SinglePingResult {
                        rtt_ms: Some(rtt),
                        success: true,
                        error_msg: None,
                    };
                }
            }
        }

        SinglePingResult {
            rtt_ms: None,
            success: false,
            error_msg: Some("No valid response parsed from ping output".to_string()),
        }
    }
}

pub struct SinglePingResult {
    pub rtt_ms: Option<f64>,
    pub success: bool,
    pub error_msg: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_success() {
        let sample = "Reply from 1.1.1.1: bytes=32 time=14ms TTL=57";
        let res = ConnectivityTester::parse_ping_output(sample);
        assert!(res.success);
        assert_eq!(res.rtt_ms, Some(14.0));
        assert!(res.error_msg.is_none());
    }

    #[test]
    fn test_parse_ping_sub_millisecond() {
        let sample = "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64";
        let res = ConnectivityTester::parse_ping_output(sample);
        assert!(res.success);
        assert_eq!(res.rtt_ms, Some(0.5));
    }

    #[test]
    fn test_parse_ping_timeout() {
        let sample = "Request timed out.";
        let res = ConnectivityTester::parse_ping_output(sample);
        assert!(!res.success);
        assert!(res.rtt_ms.is_none());
        assert_eq!(res.error_msg, Some("Request timed out".to_string()));
    }

    #[test]
    fn test_parse_ping_unreachable() {
        let sample = "Reply from 192.168.1.1: Destination host unreachable.";
        let res = ConnectivityTester::parse_ping_output(sample);
        assert!(!res.success);
        assert!(res.rtt_ms.is_none());
    }
}
