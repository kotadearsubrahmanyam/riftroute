use chrono::Utc;
use std::collections::{HashMap, HashSet};

use super::diversity::PathDiversityEngine;
use super::models::{
    CandidateComparisonReport, CandidateMeasurementSeries, CandidatePathDiversityReport,
    PathDifferenceClassification,
};
use crate::route_intelligence::models::RouteSnapshot;

/// Engine for objective, value-neutral comparative route evaluation.
pub struct CandidateComparisonEngine;

impl CandidateComparisonEngine {
    /// Compare two candidate measurement series and produce an objective comparison report.
    pub fn compare(
        series_a: &CandidateMeasurementSeries,
        series_b: &CandidateMeasurementSeries,
    ) -> CandidateComparisonReport {
        let comparison_id = format!(
            "comp_{}_{}_{}",
            series_a.candidate_id,
            series_b.candidate_id,
            Utc::now().format("%Y%m%d%H%M%S")
        );
        let timestamp_utc = Utc::now().to_rfc3339();

        let path_relationship = PathDiversityEngine::classify_two_candidates(
            &series_a.measurement_snapshots,
            &series_b.measurement_snapshots,
        );

        let final_hop_median_delta_ms = match (
            series_a.final_hop_probe_stats.as_ref(),
            series_b.final_hop_probe_stats.as_ref(),
        ) {
            (Some(a), Some(b)) => Some(((b.median_ms - a.median_ms) * 100.0).round() / 100.0),
            _ => None,
        };

        let final_hop_p95_delta_ms = match (
            series_a.final_hop_probe_stats.as_ref(),
            series_b.final_hop_probe_stats.as_ref(),
        ) {
            (Some(a), Some(b)) => Some(((b.p95_ms - a.p95_ms) * 100.0).round() / 100.0),
            _ => None,
        };

        let hop_count_delta = series_b.hop_count_median as i64 - series_a.hop_count_median as i64;

        // Extract structural differences between representative dominant snapshots
        let structural_differences = Self::find_structural_differences(series_a, series_b);

        // Factual, value-neutral summary
        let path_rel_str = match path_relationship {
            PathDifferenceClassification::SameObservedPath => "identical observed paths",
            PathDifferenceClassification::MinorResponseVariation => {
                "minor intermediate response variation with matching responding hops"
            }
            PathDifferenceClassification::StructuralRouteVariation => {
                "divergent structural paths across intermediate and/or terminal hops"
            }
            PathDifferenceClassification::InsufficientEvidence => "insufficient repeated measurements",
        };

        let rtt_comp = match (
            series_a.final_hop_probe_stats.as_ref(),
            series_b.final_hop_probe_stats.as_ref(),
        ) {
            (Some(a), Some(b)) => format!(
                "Candidate A final-hop probe median is {:.2} ms (p95: {:.2} ms); Candidate B final-hop probe median is {:.2} ms (p95: {:.2} ms), delta (B - A): {:+.2} ms.",
                a.median_ms, a.p95_ms, b.median_ms, b.p95_ms, b.median_ms - a.median_ms
            ),
            _ => "One or both candidates lacked responding final-hop probe samples.".to_string(),
        };

        let factual_comparison_summary = format!(
            "Evaluation between Candidate A ({}) and Candidate B ({}): Routes exhibit {}. {} Hop count delta (B - A): {:+} hops.",
            series_a.destination, series_b.destination, path_rel_str, rtt_comp, hop_count_delta
        );

        let scientific_disclaimer = "Route comparisons reflect ICMP traceroute probe measurements and topological router vantage points. Probe latency deltas must not be equated to in-game UDP gameplay round-trip times (probe_final_hop_rtt_ms != pubg_ping_ms). RiftRoute does not rank candidates or switch routes automatically; latency differences reflect different physical hosting locations and transit paths.".to_string();

        CandidateComparisonReport {
            comparison_id,
            timestamp_utc,
            candidate_a: series_a.to_summary(),
            candidate_b: series_b.to_summary(),
            path_relationship,
            final_hop_median_delta_ms,
            final_hop_p95_delta_ms,
            hop_count_delta,
            structural_differences,
            factual_comparison_summary,
            scientific_disclaimer,
        }
    }

    /// Analyze path diversity across a collection of candidate measurement series.
    pub fn analyze_diversity(
        series_list: &[CandidateMeasurementSeries],
    ) -> CandidatePathDiversityReport {
        let report_id = format!("div_{}", Utc::now().format("%Y%m%d_%H%M%S"));
        let timestamp_utc = Utc::now().to_rfc3339();

        let service_name = if !series_list.is_empty() {
            series_list[0].service_name.clone()
        } else {
            "Unknown".to_string()
        };

        let total_candidates = series_list.len();
        let candidate_summaries = series_list.iter().map(|s| s.to_summary()).collect();

        let mut unique_fps = HashSet::new();
        for s in series_list {
            unique_fps.insert(s.dominant_fingerprint.clone());
        }
        let unique_fingerprints_across_all_candidates = unique_fps.into_iter().collect();

        // Pairwise comparison counts
        let mut structural_variation_count = 0;
        let mut shared_path_count = 0;

        for i in 0..series_list.len() {
            for j in (i + 1)..series_list.len() {
                let rel = PathDiversityEngine::classify_two_candidates(
                    &series_list[i].measurement_snapshots,
                    &series_list[j].measurement_snapshots,
                );
                match rel {
                    PathDifferenceClassification::StructuralRouteVariation => {
                        structural_variation_count += 1;
                    }
                    PathDifferenceClassification::SameObservedPath
                    | PathDifferenceClassification::MinorResponseVariation => {
                        shared_path_count += 1;
                    }
                    PathDifferenceClassification::InsufficientEvidence => {}
                }
            }
        }

        let architectural_status = "Direct Client Routing Only (Phase 2). Relay-backed routing is UNAVAILABLE_IN_PHASE_2. Observed path diversity reflects physical server hosting locations and upstream BGP/transit differences.".to_string();
        let scientific_disclaimer = "Candidate path diversity measures empirical routing topology divergence. It does not manipulate traffic or deploy virtual relays.".to_string();

        CandidatePathDiversityReport {
            report_id,
            timestamp_utc,
            service_name,
            total_candidates,
            candidate_summaries,
            unique_fingerprints_across_all_candidates,
            structural_variation_count,
            shared_path_count,
            architectural_status,
            scientific_disclaimer,
        }
    }

    fn find_structural_differences(
        series_a: &CandidateMeasurementSeries,
        series_b: &CandidateMeasurementSeries,
    ) -> Vec<String> {
        let mut diffs = Vec::new();

        let rep_a = series_a
            .measurement_snapshots
            .iter()
            .find(|s| s.fingerprint == series_a.dominant_fingerprint)
            .or_else(|| series_a.measurement_snapshots.first());

        let rep_b = series_b
            .measurement_snapshots
            .iter()
            .find(|s| s.fingerprint == series_b.dominant_fingerprint)
            .or_else(|| series_b.measurement_snapshots.first());

        let (snap_a, snap_b) = match (rep_a, rep_b) {
            (Some(a), Some(b)) => (a, b),
            _ => return vec!["Insufficient snapshot data for structural diff.".to_string()],
        };

        let map_a = hop_address_map(snap_a);
        let map_b = hop_address_map(snap_b);

        let max_hops = snap_a.hops.len().max(snap_b.hops.len());
        for h in 1..=max_hops as u8 {
            let addr_a = map_a.get(&h);
            let addr_b = map_b.get(&h);

            match (addr_a, addr_b) {
                (Some(a), Some(b)) if a != b => {
                    diffs.push(format!("Hop {}: Candidate A traversed {} vs Candidate B traversed {}", h, a, b));
                }
                (Some(a), None) => {
                    diffs.push(format!("Hop {}: Candidate A traversed {} vs Candidate B timed out (*)", h, a));
                }
                (None, Some(b)) => {
                    diffs.push(format!("Hop {}: Candidate A timed out (*) vs Candidate B traversed {}", h, b));
                }
                _ => {}
            }
        }

        if snap_a.hops.len() != snap_b.hops.len() {
            diffs.push(format!(
                "Total hop count: Candidate A ({} hops) vs Candidate B ({} hops)",
                snap_a.hops.len(),
                snap_b.hops.len()
            ));
        }

        diffs
    }
}

fn hop_address_map(snapshot: &RouteSnapshot) -> HashMap<u8, String> {
    let mut map = HashMap::new();
    for hop in &snapshot.hops {
        if hop.responded {
            if let Some(ref addr) = hop.primary_address {
                map.insert(hop.hop_number, addr.clone());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_path::measurement::CandidateMeasurementEngine;
    use crate::candidate_path::models::{CandidateDestination, EvidenceLevel};
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
            role_hypothesis: "Gameplay Stream".to_string(),
        }
    }

    fn make_hop(num: u8, ip: Option<&str>, rtt: f64) -> RouteHop {
        let responded = ip.is_some();
        RouteHop {
            hop_number: num,
            addresses: ip.map(|s| vec![s.to_string()]).unwrap_or_default(),
            primary_address: ip.map(|s| s.to_string()),
            hostname: None,
            rtt_samples_ms: if responded { vec![rtt] } else { vec![] },
            responded,
            timeout_count: if responded { 0 } else { 3 },
            probe_count: 3,
            rtt_stats: None,
            is_timeout: !responded,
            raw_line: "".to_string(),
        }
    }

    fn make_snapshot(dest: &str, fp: &str, hops: Vec<RouteHop>) -> RouteSnapshot {
        RouteSnapshot {
            measurement_id: "test".to_string(),
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            destination: dest.to_string(),
            destination_ip: Some(dest.to_string()),
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
            measurement_duration_ms: 1000,
            scientific_disclaimer: "".to_string(),
        }
    }

    #[test]
    fn test_candidate_comparison_structural_variation() {
        let cand_a = make_test_candidate("cand_a", "20.205.179.128", 7000);
        let cand_b = make_test_candidate("cand_b", "85.236.96.163", 8000);

        let hops_a = vec![
            make_hop(1, Some("192.168.1.1"), 1.0),
            make_hop(2, Some("223.230.16.1"), 10.0),
            make_hop(3, Some("20.205.179.128"), 55.0),
        ];
        let hops_b = vec![
            make_hop(1, Some("192.168.1.1"), 1.0),
            make_hop(2, Some("182.79.243.1"), 12.0),
            make_hop(3, Some("85.236.96.163"), 145.0),
        ];

        let s_a1 = make_snapshot("20.205.179.128", "FP_A", hops_a.clone());
        let s_a2 = make_snapshot("20.205.179.128", "FP_A", hops_a);

        let s_b1 = make_snapshot("85.236.96.163", "FP_B", hops_b.clone());
        let s_b2 = make_snapshot("85.236.96.163", "FP_B", hops_b);

        let series_a = CandidateMeasurementEngine::from_snapshots(&cand_a, vec![s_a1, s_a2]).unwrap();
        let series_b = CandidateMeasurementEngine::from_snapshots(&cand_b, vec![s_b1, s_b2]).unwrap();

        let report = CandidateComparisonEngine::compare(&series_a, &series_b);

        assert_eq!(report.path_relationship, PathDifferenceClassification::StructuralRouteVariation);
        assert_eq!(report.final_hop_median_delta_ms, Some(90.0));
        assert_eq!(report.hop_count_delta, 0);
        assert!(!report.structural_differences.is_empty());
        assert!(report.structural_differences[0].contains("Hop 2: Candidate A traversed 223.230.16.1 vs Candidate B traversed 182.79.243.1"));
    }

    #[test]
    fn test_analyze_diversity() {
        let cand_a = make_test_candidate("cand_a", "20.205.179.128", 7000);
        let cand_b = make_test_candidate("cand_b", "85.236.96.163", 8000);

        let hops_a = vec![make_hop(1, Some("192.168.1.1"), 1.0), make_hop(2, Some("20.205.179.128"), 55.0)];
        let hops_b = vec![make_hop(1, Some("192.168.1.1"), 1.0), make_hop(2, Some("85.236.96.163"), 145.0)];

        let s_a = make_snapshot("20.205.179.128", "FP_A", hops_a);
        let s_b = make_snapshot("85.236.96.163", "FP_B", hops_b);

        let series_a = CandidateMeasurementEngine::from_snapshots(&cand_a, vec![s_a]).unwrap();
        let series_b = CandidateMeasurementEngine::from_snapshots(&cand_b, vec![s_b]).unwrap();

        let div = CandidateComparisonEngine::analyze_diversity(&[series_a, series_b]);

        assert_eq!(div.total_candidates, 2);
        assert_eq!(div.unique_fingerprints_across_all_candidates.len(), 2);
        assert_eq!(div.structural_variation_count, 1);
        assert_eq!(div.shared_path_count, 0);
    }
}
