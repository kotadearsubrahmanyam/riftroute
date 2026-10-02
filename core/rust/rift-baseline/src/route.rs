use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LatencySignificance {
    Observed,
    PotentiallySignificant,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hop {
    pub hop: u8,
    pub rtt1_ms: Option<f64>,
    pub rtt2_ms: Option<f64>,
    pub rtt3_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub ip_or_host: String,
    pub is_timeout: bool,
    pub latency_delta_ms: Option<f64>,
    pub significance: LatencySignificance,
    pub commentary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteTrace {
    pub destination: String,
    pub max_hops: u8,
    pub hops: Vec<Hop>,
    pub route_fingerprint: String,
    pub analysis_summary: String,
    pub timestamp: String,
}

pub struct RouteAnalyzer;

impl RouteAnalyzer {
    /// Execute traceroute against a destination and produce an empirical route trace and analysis.
    pub fn trace(destination: &str, max_hops: u8) -> RouteTrace {
        let timestamp = Utc::now().to_rfc3339();
        let output = match Command::new("tracert")
            .args(["-d", "-h", &max_hops.to_string(), "-w", "1000", destination])
            .output()
        {
            Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(e) => format!("Failed to execute tracert: {}", e),
        };

        Self::parse_tracert_output(destination, max_hops, &output, timestamp)
    }

    /// Parse Windows tracert standard output and perform scientific latency increase analysis.
    pub fn parse_tracert_output(
        destination: &str,
        max_hops: u8,
        output: &str,
        timestamp: String,
    ) -> RouteTrace {
        let hop_re = Regex::new(
            r"^\s*(\d+)\s+([<\d*]+(?:\s*ms)?)\s+([<\d*]+(?:\s*ms)?)\s+([<\d*]+(?:\s*ms)?)\s+(.+)$",
        )
        .unwrap();

        let mut raw_hops = Vec::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(caps) = hop_re.captures(trimmed) {
                let hop_num: u8 = caps[1].parse().unwrap_or(0);
                let rtt1 = Self::parse_rtt_token(&caps[2]);
                let rtt2 = Self::parse_rtt_token(&caps[3]);
                let rtt3 = Self::parse_rtt_token(&caps[4]);
                let endpoint = caps[5].trim().to_string();

                let valid_rtts: Vec<f64> = [rtt1, rtt2, rtt3].into_iter().flatten().collect();
                let min_rtt_ms = valid_rtts.into_iter().reduce(f64::min);
                let is_timeout = endpoint.contains("Request timed out") || min_rtt_ms.is_none();

                raw_hops.push((hop_num, rtt1, rtt2, rtt3, min_rtt_ms, endpoint, is_timeout));
            }
        }

        // Analyze latency deltas and classify significance
        let mut hops = Vec::new();
        let mut fingerprint_parts = Vec::new();

        for i in 0..raw_hops.len() {
            let (hop_num, rtt1, rtt2, rtt3, min_rtt, ref endpoint, is_timeout) = raw_hops[i];

            let prev_min_rtt = if i > 0 {
                // Find most recent previous hop with a valid min_rtt
                (0..i)
                    .rev()
                    .find_map(|idx| raw_hops[idx].4)
            } else {
                None
            };

            let delta = match (min_rtt, prev_min_rtt) {
                (Some(curr), Some(prev)) => Some(curr - prev),
                _ => None,
            };

            // Classify significance
            let (significance, commentary) = if is_timeout {
                (
                    LatencySignificance::Inconclusive,
                    "Router did not respond with ICMP Time Exceeded (ICMP filtered or rate-limited)."
                        .to_string(),
                )
            } else if let Some(d) = delta {
                if d > 20.0 {
                    // Check if subsequent hops remain elevated
                    let subsequent_rtts: Vec<f64> = (i + 1..raw_hops.len())
                        .filter_map(|idx| raw_hops[idx].4)
                        .collect();

                    let curr_rtt = min_rtt.unwrap_or(0.0);
                    let all_subsequent_high = !subsequent_rtts.is_empty()
                        && subsequent_rtts.iter().all(|&r| r >= curr_rtt - 10.0);

                    if all_subsequent_high {
                        (
                            LatencySignificance::PotentiallySignificant,
                            format!(
                                "Observed sustained latency step-change (+{:.1} ms) preserved through subsequent hops.",
                                d
                            ),
                        )
                    } else {
                        (
                            LatencySignificance::Inconclusive,
                            format!(
                                "Observed transient RTT spike (+{:.1} ms) on this hop, but downstream hops returned to lower RTT. Consistent with ICMP rate-limiting/control-plane deprioritization, not true forwarding delay.",
                                d
                            ),
                        )
                    }
                } else {
                    (
                        LatencySignificance::Observed,
                        format!("Normal progression ({:+.1} ms delta).", d),
                    )
                }
            } else {
                (
                    LatencySignificance::Observed,
                    "Initial observable hop.".to_string(),
                )
            };

            let fp_label = if is_timeout {
                "*".to_string()
            } else {
                endpoint.clone()
            };
            fingerprint_parts.push(fp_label);

            hops.push(Hop {
                hop: hop_num,
                rtt1_ms: rtt1,
                rtt2_ms: rtt2,
                rtt3_ms: rtt3,
                min_rtt_ms: min_rtt,
                ip_or_host: endpoint.clone(),
                is_timeout,
                latency_delta_ms: delta,
                significance,
                commentary,
            });
        }

        let route_fingerprint = fingerprint_parts.join(" -> ");

        // Generate summary
        let significant_count = hops
            .iter()
            .filter(|h| h.significance == LatencySignificance::PotentiallySignificant)
            .count();

        let analysis_summary = if significant_count > 0 {
            format!(
                "Trace to {} completed ({} hops). Detected {} potentially significant sustained latency transition(s).",
                destination,
                hops.len(),
                significant_count
            )
        } else {
            format!(
                "Trace to {} completed ({} hops). Route progression is stable without anomalous step-changes.",
                destination,
                hops.len()
            )
        };

        RouteTrace {
            destination: destination.to_string(),
            max_hops,
            hops,
            route_fingerprint,
            analysis_summary,
            timestamp,
        }
    }

    fn parse_rtt_token(token: &str) -> Option<f64> {
        let trimmed = token.trim();
        if trimmed == "*" {
            return None;
        }
        if trimmed == "<1 ms" || trimmed == "<1ms" {
            return Some(0.5);
        }
        let re = Regex::new(r"(\d+)\s*ms").unwrap();
        if let Some(caps) = re.captures(trimmed) {
            caps[1].parse::<f64>().ok()
        } else {
            trimmed.parse::<f64>().ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rtt_token() {
        assert_eq!(RouteAnalyzer::parse_rtt_token("<1 ms"), Some(0.5));
        assert_eq!(RouteAnalyzer::parse_rtt_token("12 ms"), Some(12.0));
        assert_eq!(RouteAnalyzer::parse_rtt_token("*"), None);
    }

    #[test]
    fn test_parse_tracert_output_with_deprioritization() {
        let sample = r#"
Tracing route to 1.1.1.1 over a maximum of 5 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    10 ms    10 ms    10 ms  10.0.0.1
  3    95 ms    90 ms    92 ms  172.16.0.1
  4    12 ms    11 ms    12 ms  1.1.1.1

Trace complete.
"#;
        let trace = RouteAnalyzer::parse_tracert_output(
            "1.1.1.1",
            5,
            sample,
            "2026-10-02T16:00:00Z".to_string(),
        );
        assert_eq!(trace.hops.len(), 4);
        assert_eq!(trace.hops[0].min_rtt_ms, Some(1.0));
        assert_eq!(trace.hops[1].min_rtt_ms, Some(10.0));
        assert_eq!(trace.hops[2].min_rtt_ms, Some(90.0));
        assert_eq!(trace.hops[3].min_rtt_ms, Some(11.0));

        // Hop 3 spiked to 90ms, but hop 4 returned to 11ms -> must be classified as Inconclusive (ICMP deprioritization)!
        assert_eq!(
            trace.hops[2].significance,
            LatencySignificance::Inconclusive
        );
        assert!(trace.hops[2]
            .commentary
            .contains("ICMP rate-limiting/control-plane deprioritization"));
    }

    #[test]
    fn test_parse_tracert_output_with_sustained_increase() {
        let sample = r#"
Tracing route to 203.0.113.1 over a maximum of 4 hops

  1     1 ms     1 ms     1 ms  192.168.1.1
  2    12 ms    12 ms    12 ms  10.0.0.1
  3   185 ms   180 ms   182 ms  198.51.100.1
  4   190 ms   188 ms   189 ms  203.0.113.1

Trace complete.
"#;
        let trace = RouteAnalyzer::parse_tracert_output(
            "203.0.113.1",
            4,
            sample,
            "2026-10-02T16:00:00Z".to_string(),
        );
        assert_eq!(trace.hops.len(), 4);
        // Hop 3 jumped from 12ms to 180ms (+168ms), and hop 4 remained high (188ms)
        // This is a sustained step-change -> PotentiallySignificant!
        assert_eq!(
            trace.hops[2].significance,
            LatencySignificance::PotentiallySignificant
        );
    }
}
