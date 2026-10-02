use std::collections::{BTreeMap, HashMap, HashSet};

use super::models::{
    FingerprintFrequency, HopVariability, RouteSnapshot, RouteStabilityReport,
};

/// Engine for evaluating path persistence and route stability across longitudinal measurement sessions.
pub struct RouteStabilityEngine;

impl RouteStabilityEngine {
    /// Analyze stability characteristics from an array of route snapshots.
    pub fn analyze(snapshots: &[RouteSnapshot]) -> Result<RouteStabilityReport, String> {
        if snapshots.is_empty() {
            return Err("Cannot analyze stability on an empty snapshot collection.".to_string());
        }

        // Sort chronologically by timestamp
        let mut sorted = snapshots.to_vec();
        sorted.sort_by(|a, b| a.timestamp_utc.cmp(&b.timestamp_utc));

        let destination = sorted[0].destination.clone();
        let analysis_window_start = sorted[0].timestamp_utc.clone();
        let analysis_window_end = sorted[sorted.len() - 1].timestamp_utc.clone();
        let total_snapshots = sorted.len();

        // 1. Calculate fingerprint frequencies
        let mut fp_counts: HashMap<String, (usize, String)> = HashMap::new();
        for s in &sorted {
            let entry = fp_counts
                .entry(s.fingerprint.clone())
                .or_insert((0, s.measurement_id.clone()));
            entry.0 += 1;
        }

        let mut fingerprint_frequencies: Vec<FingerprintFrequency> = fp_counts
            .into_iter()
            .map(|(fp, (count, sample_id))| {
                let percentage = (count as f64 / total_snapshots as f64) * 100.0;
                FingerprintFrequency {
                    fingerprint: fp,
                    count,
                    percentage,
                    sample_snapshot_id: sample_id,
                }
            })
            .collect();

        // Sort by frequency count descending
        fingerprint_frequencies.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });

        let unique_fingerprints_count = fingerprint_frequencies.len();
        let dominant = &fingerprint_frequencies[0];
        let dominant_fingerprint = dominant.fingerprint.clone();
        let dominant_fingerprint_pct = dominant.percentage;

        // 2. Calculate consecutive route transitions
        let mut route_change_count = 0;
        if total_snapshots > 1 {
            for i in 1..total_snapshots {
                if sorted[i].fingerprint != sorted[i - 1].fingerprint {
                    route_change_count += 1;
                }
            }
        }

        let route_change_rate_pct = if total_snapshots > 1 {
            (route_change_count as f64 / (total_snapshots - 1) as f64) * 100.0
        } else {
            0.0
        };

        // 3. Hop-level variability per hop position
        let max_hops = sorted.iter().map(|s| s.hops.len()).max().unwrap_or(0);
        let mut hop_address_map: BTreeMap<u8, HashSet<String>> = BTreeMap::new();
        let mut hop_timeout_map: BTreeMap<u8, usize> = BTreeMap::new();

        for s in &sorted {
            for hop in &s.hops {
                let num = hop.hop_number;
                if hop.responded {
                    if let Some(ref addr) = hop.primary_address {
                        hop_address_map.entry(num).or_default().insert(addr.clone());
                    }
                } else {
                    *hop_timeout_map.entry(num).or_default() += 1;
                }
            }
        }

        let mut hop_variability = Vec::new();
        for hop_num in 1..=max_hops as u8 {
            let unique_addrs: Vec<String> = hop_address_map
                .get(&hop_num)
                .cloned()
                .map(|set| {
                    let mut v: Vec<String> = set.into_iter().collect();
                    v.sort();
                    v
                })
                .unwrap_or_default();

            let timeout_cnt = *hop_timeout_map.get(&hop_num).unwrap_or(&0);
            let timeout_frequency_pct = (timeout_cnt as f64 / total_snapshots as f64) * 100.0;

            // Stable if exactly 1 responding address and 0 timeouts, OR 0 addresses and 100% timeouts
            let is_stable = (unique_addrs.len() == 1 && timeout_cnt == 0)
                || (unique_addrs.is_empty() && timeout_cnt == total_snapshots);

            hop_variability.push(HopVariability {
                hop_number: hop_num,
                unique_addresses: unique_addrs,
                timeout_count: timeout_cnt,
                timeout_frequency_pct,
                is_stable,
            });
        }

        let stability_summary = if unique_fingerprints_count == 1 {
            format!(
                "Route is perfectly stable across {} snapshot(s). Dominant path ({}) observed 100.0% of the time with 0 route changes.",
                total_snapshots, dominant_fingerprint
            )
        } else {
            format!(
                "Route variability observed across {} snapshots: {} unique fingerprint(s) detected. Dominant path ({}) occurred in {:.1}% of observations. Recorded {} transition(s) ({:.1}% transition rate).",
                total_snapshots,
                unique_fingerprints_count,
                dominant_fingerprint,
                dominant_fingerprint_pct,
                route_change_count,
                route_change_rate_pct
            )
        };

        Ok(RouteStabilityReport {
            destination,
            analysis_window_start,
            analysis_window_end,
            total_snapshots,
            unique_fingerprints_count,
            fingerprint_frequencies,
            dominant_fingerprint,
            dominant_fingerprint_pct,
            route_change_count,
            route_change_rate_pct,
            hop_variability,
            stability_summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_intelligence::models::RouteHop;

    fn make_test_snapshot(id: &str, ts: &str, fp: &str) -> RouteSnapshot {
        RouteSnapshot {
            measurement_id: id.to_string(),
            timestamp_utc: ts.to_string(),
            destination: "1.1.1.1".to_string(),
            destination_ip: Some("1.1.1.1".to_string()),
            destination_port: None,
            probe_method: "Windows Tracert".to_string(),
            resolve_hostnames: false,
            active_interface: Some("Wi-Fi".to_string()),
            source_ipv4: Some("192.168.1.14".to_string()),
            default_gateway: Some("192.168.1.1".to_string()),
            hop_count: 2,
            responding_hops: 2,
            timeout_hops: 0,
            hops: vec![
                RouteHop {
                    hop_number: 1,
                    addresses: vec!["192.168.1.1".to_string()],
                    primary_address: Some("192.168.1.1".to_string()),
                    hostname: None,
                    rtt_samples_ms: vec![1.0],
                    responded: true,
                    timeout_count: 0,
                    probe_count: 3,
                    rtt_stats: None,
                    is_timeout: false,
                    raw_line: "".to_string(),
                },
                RouteHop {
                    hop_number: 2,
                    addresses: vec!["1.1.1.1".to_string()],
                    primary_address: Some("1.1.1.1".to_string()),
                    hostname: None,
                    rtt_samples_ms: vec![10.0],
                    responded: true,
                    timeout_count: 0,
                    probe_count: 3,
                    rtt_stats: None,
                    is_timeout: false,
                    raw_line: "".to_string(),
                },
            ],
            fingerprint: fp.to_string(),
            fingerprint_sha256: fp.to_string(),
            canonical_path: "".to_string(),
            measurement_duration_ms: 500,
            scientific_disclaimer: "".to_string(),
        }
    }

    #[test]
    fn test_stability_single_snapshot() {
        let s = make_test_snapshot("s1", "2026-10-02T10:00:00Z", "FP_AAA");
        let rep = RouteStabilityEngine::analyze(&[s]).unwrap();

        assert_eq!(rep.total_snapshots, 1);
        assert_eq!(rep.unique_fingerprints_count, 1);
        assert_eq!(rep.dominant_fingerprint, "FP_AAA");
        assert_eq!(rep.dominant_fingerprint_pct, 100.0);
        assert_eq!(rep.route_change_count, 0);
    }

    #[test]
    fn test_stability_multiple_snapshots_with_changes() {
        let s1 = make_test_snapshot("s1", "2026-10-02T10:00:00Z", "FP_AAA");
        let s2 = make_test_snapshot("s2", "2026-10-02T10:01:00Z", "FP_AAA");
        let s3 = make_test_snapshot("s3", "2026-10-02T10:02:00Z", "FP_BBB"); // change
        let s4 = make_test_snapshot("s4", "2026-10-02T10:03:00Z", "FP_AAA"); // change back

        let rep = RouteStabilityEngine::analyze(&[s1, s2, s3, s4]).unwrap();

        assert_eq!(rep.total_snapshots, 4);
        assert_eq!(rep.unique_fingerprints_count, 2);
        assert_eq!(rep.dominant_fingerprint, "FP_AAA");
        assert_eq!(rep.dominant_fingerprint_pct, 75.0);
        assert_eq!(rep.route_change_count, 2);
    }

    #[test]
    fn test_stability_empty_error() {
        assert!(RouteStabilityEngine::analyze(&[]).is_err());
    }
}
