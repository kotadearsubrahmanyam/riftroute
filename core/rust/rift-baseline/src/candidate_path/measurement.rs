use chrono::Utc;
use std::collections::HashMap;
use std::time::Duration;

use super::diversity::PathDiversityEngine;
use super::models::{CandidateDestination, CandidateMeasurementSeries};
use crate::route_intelligence::hop::HopStatsEngine;
use crate::route_intelligence::models::RouteSnapshot;
use crate::route_intelligence::RouteIntelligence;

/// Engine for executing repeated longitudinal route measurements toward candidate destinations.
pub struct CandidateMeasurementEngine;

impl CandidateMeasurementEngine {
    /// Execute repeated route measurements toward a candidate destination.
    pub fn measure_candidate(
        candidate: &CandidateDestination,
        runs: usize,
        max_hops: u8,
        timeout_ms: u64,
        interval_ms: u64,
        resolve_hostnames: bool,
        max_execution_duration: Duration,
    ) -> Result<CandidateMeasurementSeries, String> {
        let runs = if runs == 0 { 5 } else { runs };
        let execution_window_start = Utc::now().to_rfc3339();
        let mut snapshots = Vec::with_capacity(runs);

        for run_idx in 0..runs {
            if run_idx > 0 && interval_ms > 0 {
                std::thread::sleep(Duration::from_millis(interval_ms));
            }

            let snapshot = RouteIntelligence::measure(
                &candidate.ip,
                max_hops,
                timeout_ms,
                resolve_hostnames,
                max_execution_duration,
            )?;
            snapshots.push(snapshot);
        }

        let execution_window_end = Utc::now().to_rfc3339();
        Self::build_series(
            candidate,
            snapshots,
            execution_window_start,
            execution_window_end,
        )
    }

    /// Construct a CandidateMeasurementSeries from a pre-existing vector of RouteSnapshots.
    /// Useful for testing, offline replays, or post-hoc series construction.
    pub fn from_snapshots(
        candidate: &CandidateDestination,
        snapshots: Vec<RouteSnapshot>,
    ) -> Result<CandidateMeasurementSeries, String> {
        if snapshots.is_empty() {
            return Err("Cannot construct measurement series from empty snapshots.".to_string());
        }

        let start = snapshots[0].timestamp_utc.clone();
        let end = snapshots[snapshots.len() - 1].timestamp_utc.clone();
        Self::build_series(candidate, snapshots, start, end)
    }

    fn build_series(
        candidate: &CandidateDestination,
        snapshots: Vec<RouteSnapshot>,
        execution_window_start: String,
        execution_window_end: String,
    ) -> Result<CandidateMeasurementSeries, String> {
        if snapshots.is_empty() {
            return Err("Cannot build candidate series with zero snapshots.".to_string());
        }

        let run_count = snapshots.len();
        let measurement_ids: Vec<String> = snapshots.iter().map(|s| s.measurement_id.clone()).collect();

        // 1. Calculate unique and dominant fingerprints
        let mut fp_counts: HashMap<String, usize> = HashMap::new();
        let mut unique_fingerprints = Vec::new();
        for s in &snapshots {
            let count = fp_counts.entry(s.fingerprint.clone()).or_insert(0);
            if *count == 0 {
                unique_fingerprints.push(s.fingerprint.clone());
            }
            *count += 1;
        }

        let mut dominant_fp = String::new();
        let mut dom_count = 0;
        for fp in &unique_fingerprints {
            let count = fp_counts.get(fp).copied().unwrap_or(0);
            if count > dom_count {
                dom_count = count;
                dominant_fp = fp.clone();
            }
        }
        let dominant_fingerprint_pct = (dom_count as f64 / run_count as f64) * 100.0;

        // 2. Classify path difference across runs
        let path_difference_classification = PathDiversityEngine::classify_snapshots(&snapshots);

        // 3. Final responding hop probe RTT samples aggregation
        let mut final_hop_samples: Vec<f64> = Vec::new();
        for s in &snapshots {
            if let Some(final_hop) = s
                .hops
                .iter()
                .rev()
                .find(|h| h.responded && !h.rtt_samples_ms.is_empty())
            {
                final_hop_samples.extend_from_slice(&final_hop.rtt_samples_ms);
            }
        }
        let final_hop_probe_stats = HopStatsEngine::compute_stats(&final_hop_samples);

        // 4. Medians of hop counts
        let hop_counts: Vec<usize> = snapshots.iter().map(|s| s.hop_count).collect();
        let responding_counts: Vec<usize> = snapshots.iter().map(|s| s.responding_hops).collect();
        let timeout_counts: Vec<usize> = snapshots.iter().map(|s| s.timeout_hops).collect();

        let hop_count_median = PathDiversityEngine::median_usize(&hop_counts);
        let responding_hop_count_median = PathDiversityEngine::median_usize(&responding_counts);
        let timeout_hop_count_median = PathDiversityEngine::median_usize(&timeout_counts);

        // 5. Route transitions across consecutive runs
        let mut route_transition_count = 0;
        if snapshots.len() > 1 {
            for i in 1..snapshots.len() {
                if snapshots[i].fingerprint != snapshots[i - 1].fingerprint {
                    route_transition_count += 1;
                }
            }
        }
        let route_transition_rate_pct = if snapshots.len() > 1 {
            (route_transition_count as f64 / (snapshots.len() - 1) as f64) * 100.0
        } else {
            0.0
        };

        let scientific_disclaimer = "Traceroute RTT and hop data reflect ICMP Time Exceeded generation latencies by intermediate router control planes. They must not be equated to in-game UDP gameplay round-trip times (probe_final_hop_rtt_ms != pubg_ping_ms). Route measurements do not modify, optimize, or steer network traffic.".to_string();

        Ok(CandidateMeasurementSeries {
            candidate_id: candidate.candidate_id.clone(),
            destination: candidate.ip.clone(),
            target_ip: candidate.ip.clone(),
            target_port: candidate.port,
            service_name: candidate.service_name.clone(),
            run_count,
            measurement_snapshots: snapshots,
            measurement_ids,
            unique_fingerprints,
            dominant_fingerprint: dominant_fp,
            dominant_fingerprint_pct,
            path_difference_classification,
            final_hop_probe_stats,
            hop_count_median,
            responding_hop_count_median,
            timeout_hop_count_median,
            route_transition_count,
            route_transition_rate_pct,
            execution_window_start,
            execution_window_end,
            scientific_disclaimer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_path::models::{EvidenceLevel, PathDifferenceClassification};
    use crate::route_intelligence::models::RouteHop;

    fn make_test_candidate(id: &str, ip: &str, port: u16) -> CandidateDestination {
        CandidateDestination {
            candidate_id: id.to_string(),
            ip: ip.to_string(),
            port: Some(port),
            protocol: "UDP".to_string(),
            service_name: "PUBG PC".to_string(),
            process_name: Some("TslGame.exe".to_string()),
            local_port: Some(51234),
            discovery_method: "Test".to_string(),
            evidence_level: EvidenceLevel::DirectlyObserved,
            first_seen_utc: "2026-10-02T10:00:00Z".to_string(),
            last_seen_utc: "2026-10-02T10:00:00Z".to_string(),
            observation_count: 100,
            role_hypothesis: "Authoritative Gameplay".to_string(),
        }
    }

    fn make_hop(num: u8, ip: Option<&str>, rtt: f64) -> RouteHop {
        let responded = ip.is_some();
        RouteHop {
            hop_number: num,
            addresses: ip.map(|s| vec![s.to_string()]).unwrap_or_default(),
            primary_address: ip.map(|s| s.to_string()),
            hostname: None,
            rtt_samples_ms: if responded { vec![rtt, rtt + 1.0, rtt + 2.0] } else { vec![] },
            responded,
            timeout_count: if responded { 0 } else { 3 },
            probe_count: 3,
            rtt_stats: None,
            is_timeout: !responded,
            raw_line: "".to_string(),
        }
    }

    fn make_snapshot(id: &str, fp: &str, final_rtt: f64) -> RouteSnapshot {
        let hops = vec![
            make_hop(1, Some("192.168.1.1"), 1.0),
            make_hop(2, Some("223.230.16.1"), 15.0),
            make_hop(3, Some("20.205.179.128"), final_rtt),
        ];
        RouteSnapshot {
            measurement_id: id.to_string(),
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            destination: "20.205.179.128".to_string(),
            destination_ip: Some("20.205.179.128".to_string()),
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
            measurement_duration_ms: 1500,
            scientific_disclaimer: "".to_string(),
        }
    }

    #[test]
    fn test_from_snapshots_metrics() {
        let cand = make_test_candidate("cand_1", "20.205.179.128", 7000);
        let s1 = make_snapshot("s1", "FP_A", 60.0);
        let s2 = make_snapshot("s2", "FP_A", 62.0);
        let s3 = make_snapshot("s3", "FP_B", 64.0);

        let series = CandidateMeasurementEngine::from_snapshots(&cand, vec![s1, s2, s3]).unwrap();

        assert_eq!(series.run_count, 3);
        assert_eq!(series.dominant_fingerprint, "FP_A");
        assert!((series.dominant_fingerprint_pct - 66.666).abs() < 0.1);
        assert_eq!(series.unique_fingerprints.len(), 2);
        assert_eq!(series.hop_count_median, 3);
        assert_eq!(series.responding_hop_count_median, 3);
        assert_eq!(series.timeout_hop_count_median, 0);
        assert_eq!(series.route_transition_count, 1);
        assert_eq!(series.route_transition_rate_pct, 50.0);

        // Final hop stats
        let stats = series.final_hop_probe_stats.as_ref().unwrap();
        assert_eq!(stats.sample_count, 9); // 3 samples * 3 snapshots
        assert!(stats.min_ms >= 60.0);
        assert!(stats.max_ms <= 66.0);
    }

    #[test]
    fn test_identical_path_classification() {
        let cand = make_test_candidate("cand_2", "8.8.8.8", 53);
        let s1 = make_snapshot("s1", "FP_SAME", 25.0);
        let s2 = make_snapshot("s2", "FP_SAME", 26.0);

        let series = CandidateMeasurementEngine::from_snapshots(&cand, vec![s1, s2]).unwrap();

        assert_eq!(series.path_difference_classification, PathDifferenceClassification::SameObservedPath);
        assert_eq!(series.route_transition_count, 0);
        assert_eq!(series.route_transition_rate_pct, 0.0);
    }
}
