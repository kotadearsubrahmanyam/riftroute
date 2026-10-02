use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::hop::HopStatsEngine;
use super::models::RouteHop;

/// Parser for standard Windows tracert console output.
pub struct TracertParser;

impl TracertParser {
    /// Parse raw stdout from Windows tracert into normalized `RouteHop` structures.
    pub fn parse(stdout: &str) -> Vec<RouteHop> {
        let mut hops = Vec::new();

        // Regex to identify lines starting with a hop number: e.g. "  1   ..."
        let hop_line_re = Regex::new(r"^\s*(\d+)\s+(.+)$").unwrap();

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(caps) = hop_line_re.captures(line) {
                let hop_num: u8 = match caps[1].parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                let remainder = &caps[2];
                let hop = Self::parse_hop_remainder(hop_num, remainder, line);
                hops.push(hop);
            }
        }

        hops
    }

    fn parse_hop_remainder(hop_num: u8, remainder: &str, raw_line: &str) -> RouteHop {
        let rtt_token_re = Regex::new(r"(<1\s*ms|\d+\s*ms|\*)").unwrap();
        let matches: Vec<_> = rtt_token_re.find_iter(remainder).collect();

        let mut rtt_samples = Vec::new();
        let mut timeout_count = 0;
        let mut last_match_end = 0;

        for m in &matches {
            let token = m.as_str().trim();
            if token == "*" {
                timeout_count += 1;
            } else if token.starts_with("<1") {
                // Sub-millisecond delay: represent as 0.5 ms
                rtt_samples.push(0.5);
            } else if let Some(ms_str) = token.split_whitespace().next() {
                if let Ok(val) = ms_str.parse::<f64>() {
                    rtt_samples.push(val);
                }
            }
            last_match_end = m.end();
        }

        let probe_count = matches.len().max(3); // Standard tracert dispatches 3 probes
        let trailing_text = if last_match_end < remainder.len() {
            remainder[last_match_end..].trim()
        } else {
            ""
        };

        // Extract IP address and hostname from trailing text
        // Possible formats:
        // 1. "192.168.1.1" (numeric IP)
        // 2. "router.isp.com [223.230.16.1]" (hostname + IP)
        // 3. "Request timed out."
        // 4. "Destination host unreachable."
        // 5. "2405:201:2000::1" (IPv6)
        let (primary_address, hostname, is_admin_error) = Self::parse_endpoint(trailing_text);

        let responded = !rtt_samples.is_empty() && !primary_address.is_none();
        let is_timeout = timeout_count >= probe_count || (rtt_samples.is_empty() && !responded);

        let addresses = if let Some(ref addr) = primary_address {
            vec![addr.clone()]
        } else {
            Vec::new()
        };

        let rtt_stats = if responded {
            HopStatsEngine::compute_stats(&rtt_samples)
        } else {
            None
        };

        RouteHop {
            hop_number: hop_num,
            addresses,
            primary_address,
            hostname,
            rtt_samples_ms: rtt_samples,
            responded: responded && !is_admin_error,
            timeout_count,
            probe_count,
            rtt_stats,
            is_timeout,
            raw_line: raw_line.to_string(),
        }
    }

    /// Extract (IP, Hostname, isAdminError) from trailing tracert text.
    fn parse_endpoint(text: &str) -> (Option<String>, Option<String>, bool) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return (None, None, false);
        }

        // Administrative or timeout messages
        if trimmed.eq_ignore_ascii_case("Request timed out.")
            || trimmed.contains("timed out")
        {
            return (None, None, false);
        }

        if trimmed.contains("unreachable")
            || trimmed.contains("failure")
            || trimmed.contains("Transmit error")
        {
            return (None, Some(trimmed.to_string()), true);
        }

        // Check if format is "hostname [IP]"
        let bracket_re = Regex::new(r"^(.*?)\s*\[([a-fA-F0-9:.]+)\]$").unwrap();
        if let Some(caps) = bracket_re.captures(trimmed) {
            let host_part = caps[1].trim().to_string();
            let ip_part = caps[2].trim().to_string();
            let hostname = if host_part.is_empty() { None } else { Some(host_part) };
            return (Some(ip_part), hostname, false);
        }

        // Check if standalone IPv4
        if Ipv4Addr::from_str(trimmed).is_ok() {
            return (Some(trimmed.to_string()), None, false);
        }

        // Check if standalone IPv6
        if Ipv6Addr::from_str(trimmed).is_ok() {
            return (Some(trimmed.to_string()), None, false);
        }

        // Fallback: hostname or unbracketed name
        (Some(trimmed.to_string()), None, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_numeric_output() {
        let sample = r#"
Tracing route to 1.1.1.1 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2    10 ms    11 ms    10 ms  223.230.16.1
  3    12 ms    12 ms    12 ms  59.144.94.165
  4     *        *        *     Request timed out.
  5    14 ms    15 ms    14 ms  1.1.1.1

Trace complete.
"#;
        let hops = TracertParser::parse(sample);
        assert_eq!(hops.len(), 5);

        // Hop 1: <1 ms
        assert_eq!(hops[0].hop_number, 1);
        assert_eq!(hops[0].primary_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].rtt_samples_ms, vec![0.5, 0.5, 0.5]);
        assert!(hops[0].responded);
        assert!(!hops[0].is_timeout);

        // Hop 2
        assert_eq!(hops[1].hop_number, 2);
        assert_eq!(hops[1].primary_address.as_deref(), Some("223.230.16.1"));
        assert_eq!(hops[1].rtt_samples_ms, vec![10.0, 11.0, 10.0]);

        // Hop 4: Timeout
        assert_eq!(hops[3].hop_number, 4);
        assert_eq!(hops[3].primary_address, None);
        assert!(hops[3].rtt_samples_ms.is_empty());
        assert!(!hops[3].responded);
        assert!(hops[3].is_timeout);
        assert_eq!(hops[3].timeout_count, 3);

        // Hop 5: Final
        assert_eq!(hops[4].hop_number, 5);
        assert_eq!(hops[4].primary_address.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn test_parse_hostname_and_bracketed_ip() {
        let sample = r#"
  1     1 ms     1 ms     1 ms  gateway.home [192.168.1.1]
  2    15 ms    14 ms    15 ms  act-bb-router.actcorp.in [223.230.16.1]
"#;
        let hops = TracertParser::parse(sample);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].primary_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].hostname.as_deref(), Some("gateway.home"));

        assert_eq!(hops[1].primary_address.as_deref(), Some("223.230.16.1"));
        assert_eq!(hops[1].hostname.as_deref(), Some("act-bb-router.actcorp.in"));
    }

    #[test]
    fn test_parse_partial_timeouts() {
        let sample = r#"
  3     *       12 ms     *     59.144.94.165
"#;
        let hops = TracertParser::parse(sample);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].hop_number, 3);
        assert_eq!(hops[0].primary_address.as_deref(), Some("59.144.94.165"));
        assert_eq!(hops[0].rtt_samples_ms, vec![12.0]);
        assert_eq!(hops[0].timeout_count, 2);
        assert!(hops[0].responded);
        assert!(!hops[0].is_timeout);
    }

    #[test]
    fn test_parse_administrative_error() {
        let sample = r#"
  4  Destination host unreachable.
"#;
        let hops = TracertParser::parse(sample);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].hop_number, 4);
        assert_eq!(hops[0].responded, false);
    }

    #[test]
    fn test_parse_ipv6() {
        let sample = r#"
  1     2 ms     2 ms     2 ms  2405:201:2000::1
"#;
        let hops = TracertParser::parse(sample);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].primary_address.as_deref(), Some("2405:201:2000::1"));
        assert_eq!(hops[0].rtt_samples_ms, vec![2.0, 2.0, 2.0]);
    }
}
