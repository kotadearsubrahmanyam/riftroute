use super::models::{HopDiffType, HopDifference, HopRttChange, RouteComparison, RouteSnapshot};

/// Scientific comparison engine between two route snapshots.
pub struct RouteComparisonEngine;

impl RouteComparisonEngine {
    /// Compare two route snapshots and identify path structure, hop identity, and latency differences.
    pub fn compare(previous: &RouteSnapshot, current: &RouteSnapshot) -> RouteComparison {
        let fingerprint_identical = previous.fingerprint == current.fingerprint;
        let hop_count_delta = current.hops.len() as i64 - previous.hops.len() as i64;

        let max_hops = previous.hops.len().max(current.hops.len());
        let mut hop_differences = Vec::new();
        let mut rtt_changes = Vec::new();

        for i in 1..=max_hops {
            let hop_num = i as u8;
            let prev_hop = previous.hops.iter().find(|h| h.hop_number == hop_num);
            let curr_hop = current.hops.iter().find(|h| h.hop_number == hop_num);

            match (prev_hop, curr_hop) {
                (Some(p), Some(c)) => {
                    let prev_addr = p.primary_address.clone();
                    let curr_addr = c.primary_address.clone();

                    if !p.responded && c.responded {
                        hop_differences.push(HopDifference {
                            hop_number: hop_num,
                            diff_type: HopDiffType::TimeoutToResponding,
                            previous_address: None,
                            current_address: curr_addr.clone(),
                            description: format!(
                                "Hop {} previously timed out (*); now responds with {}",
                                hop_num,
                                curr_addr.as_deref().unwrap_or("unknown")
                            ),
                        });
                    } else if p.responded && !c.responded {
                        hop_differences.push(HopDifference {
                            hop_number: hop_num,
                            diff_type: HopDiffType::RespondingToTimeout,
                            previous_address: prev_addr.clone(),
                            current_address: None,
                            description: format!(
                                "Hop {} previously responded with {}; now timed out (*)",
                                hop_num,
                                prev_addr.as_deref().unwrap_or("unknown")
                            ),
                        });
                    } else if p.responded && c.responded {
                        if prev_addr != curr_addr {
                            hop_differences.push(HopDifference {
                                hop_number: hop_num,
                                diff_type: HopDiffType::AddressChanged,
                                previous_address: prev_addr.clone(),
                                current_address: curr_addr.clone(),
                                description: format!(
                                    "Hop {} IP changed from {} to {}",
                                    hop_num,
                                    prev_addr.as_deref().unwrap_or("unknown"),
                                    curr_addr.as_deref().unwrap_or("unknown")
                                ),
                            });
                        }
                    }

                    // Compare RTT if both responded
                    if let (Some(p_stats), Some(c_stats)) = (&p.rtt_stats, &c.rtt_stats) {
                        let delta_med = c_stats.median_ms - p_stats.median_ms;
                        let target_addr = curr_addr.or(prev_addr).unwrap_or_else(|| "N/A".to_string());

                        rtt_changes.push(HopRttChange {
                            hop_number: hop_num,
                            address: target_addr,
                            previous_median_ms: Some(p_stats.median_ms),
                            current_median_ms: Some(c_stats.median_ms),
                            delta_median_ms: Some(delta_med),
                        });
                    }
                }
                (None, Some(c)) => {
                    hop_differences.push(HopDifference {
                        hop_number: hop_num,
                        diff_type: HopDiffType::HopAdded,
                        previous_address: None,
                        current_address: c.primary_address.clone(),
                        description: format!(
                            "Hop {} added in current route ({})",
                            hop_num,
                            c.primary_address.as_deref().unwrap_or("TIMEOUT")
                        ),
                    });
                }
                (Some(p), None) => {
                    hop_differences.push(HopDifference {
                        hop_number: hop_num,
                        diff_type: HopDiffType::HopRemoved,
                        previous_address: p.primary_address.clone(),
                        current_address: None,
                        description: format!(
                            "Hop {} present in previous route ({}) but absent in current",
                            hop_num,
                            p.primary_address.as_deref().unwrap_or("TIMEOUT")
                        ),
                    });
                }
                (None, None) => {}
            }
        }

        let summary = if fingerprint_identical {
            format!(
                "Routes are structurally identical (fingerprint: {}). Evaluated {} hops.",
                previous.fingerprint, previous.hops.len()
            )
        } else {
            format!(
                "Route changed: previous fingerprint {} -> current fingerprint {}. Detected {} hop-level structural difference(s).",
                previous.fingerprint, current.fingerprint, hop_differences.len()
            )
        };

        RouteComparison {
            previous_id: previous.measurement_id.clone(),
            previous_timestamp: previous.timestamp_utc.clone(),
            previous_fingerprint: previous.fingerprint.clone(),
            current_id: current.measurement_id.clone(),
            current_timestamp: current.timestamp_utc.clone(),
            current_fingerprint: current.fingerprint.clone(),
            destination: current.destination.clone(),
            fingerprint_identical,
            hop_count_delta,
            hop_differences,
            rtt_changes,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_intelligence::models::{HopRttStats, RouteHop};

    fn make_test_snapshot(id: &str, hops: Vec<RouteHop>, fp: &str) -> RouteSnapshot {
        RouteSnapshot {
            measurement_id: id.to_string(),
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            destination: "1.1.1.1".to_string(),
            destination_ip: Some("1.1.1.1".to_string()),
            destination_port: None,
            probe_method: "Windows Tracert".to_string(),
            resolve_hostnames: false,
            active_interface: Some("Wi-Fi".to_string()),
            source_ipv4: Some("192.168.1.14".to_string()),
            default_gateway: Some("192.168.1.1".to_string()),
            hop_count: hops.len(),
            responding_hops: hops.iter().filter(|h| h.responded).count(),
            timeout_hops: hops.iter().filter(|h| h.is_timeout).count(),
            hops,
            fingerprint: fp.to_string(),
            fingerprint_sha256: fp.to_string(),
            canonical_path: "".to_string(),
            measurement_duration_ms: 1200,
            scientific_disclaimer: "".to_string(),
        }
    }

    fn make_hop(num: u8, ip: Option<&str>, median_ms: Option<f64>) -> RouteHop {
        let responded = ip.is_some();
        let rtt_stats = median_ms.map(|m| HopRttStats {
            sample_count: 3,
            min_ms: m - 1.0,
            median_ms: m,
            mean_ms: m,
            p95_ms: m + 1.0,
            p99_ms: m + 1.0,
            max_ms: m + 1.0,
            std_dev_ms: 1.0,
            jitter_ms: Some(0.5),
        });

        RouteHop {
            hop_number: num,
            addresses: ip.map(|s| vec![s.to_string()]).unwrap_or_default(),
            primary_address: ip.map(|s| s.to_string()),
            hostname: None,
            rtt_samples_ms: if responded { vec![10.0, 10.0, 10.0] } else { vec![] },
            responded,
            timeout_count: if responded { 0 } else { 3 },
            probe_count: 3,
            rtt_stats,
            is_timeout: !responded,
            raw_line: "".to_string(),
        }
    }

    #[test]
    fn test_compare_identical_snapshots() {
        let hops1 = vec![
            make_hop(1, Some("192.168.1.1"), Some(1.0)),
            make_hop(2, Some("223.230.16.1"), Some(10.0)),
        ];
        let hops2 = hops1.clone();

        let s1 = make_test_snapshot("snap1", hops1, "AAAABBBBCCCCDDDD");
        let s2 = make_test_snapshot("snap2", hops2, "AAAABBBBCCCCDDDD");

        let comp = RouteComparisonEngine::compare(&s1, &s2);
        assert!(comp.fingerprint_identical);
        assert_eq!(comp.hop_count_delta, 0);
        assert!(comp.hop_differences.is_empty());
        assert_eq!(comp.rtt_changes.len(), 2);
        assert_eq!(comp.rtt_changes[0].delta_median_ms, Some(0.0));
    }

    #[test]
    fn test_compare_address_changed() {
        let s1 = make_test_snapshot("snap1", vec![
            make_hop(1, Some("192.168.1.1"), Some(1.0)),
            make_hop(2, Some("223.230.16.1"), Some(10.0)),
        ], "AAA");
        let s2 = make_test_snapshot("snap2", vec![
            make_hop(1, Some("192.168.1.1"), Some(1.0)),
            make_hop(2, Some("223.230.16.99"), Some(12.0)), // changed IP
        ], "BBB");

        let comp = RouteComparisonEngine::compare(&s1, &s2);
        assert!(!comp.fingerprint_identical);
        assert_eq!(comp.hop_differences.len(), 1);
        assert_eq!(comp.hop_differences[0].diff_type, HopDiffType::AddressChanged);
        assert_eq!(comp.hop_differences[0].hop_number, 2);
    }

    #[test]
    fn test_compare_timeout_transitions() {
        let s1 = make_test_snapshot("snap1", vec![
            make_hop(1, None, None), // timeout
        ], "AAA");
        let s2 = make_test_snapshot("snap2", vec![
            make_hop(1, Some("192.168.1.1"), Some(1.0)), // now responding
        ], "BBB");

        let comp = RouteComparisonEngine::compare(&s1, &s2);
        assert!(!comp.fingerprint_identical);
        assert_eq!(comp.hop_differences.len(), 1);
        assert_eq!(comp.hop_differences[0].diff_type, HopDiffType::TimeoutToResponding);
    }

    #[test]
    fn test_compare_hop_added_and_removed() {
        let s1 = make_test_snapshot("snap1", vec![
            make_hop(1, Some("192.168.1.1"), Some(1.0)),
        ], "AAA");
        let s2 = make_test_snapshot("snap2", vec![
            make_hop(1, Some("192.168.1.1"), Some(1.0)),
            make_hop(2, Some("223.230.16.1"), Some(10.0)), // added
        ], "BBB");

        let comp = RouteComparisonEngine::compare(&s1, &s2);
        assert_eq!(comp.hop_count_delta, 1);
        assert_eq!(comp.hop_differences.len(), 1);
        assert_eq!(comp.hop_differences[0].diff_type, HopDiffType::HopAdded);
    }
}
