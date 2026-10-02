use std::collections::{HashMap, HashSet};

use super::models::PathDifferenceClassification;
use crate::route_intelligence::models::RouteSnapshot;

/// Engine for evaluating path diversity and genuine path differences without speculation.
pub struct PathDiversityEngine;

impl PathDiversityEngine {
    /// Classify the structural path relationship across repeated measurements toward a destination.
    pub fn classify_snapshots(snapshots: &[RouteSnapshot]) -> PathDifferenceClassification {
        if snapshots.len() < 2 {
            return PathDifferenceClassification::InsufficientEvidence;
        }

        // Extract responding IP sequences and timeout positions for each snapshot
        let mut distinct_fingerprints = HashSet::new();
        let mut responding_ip_sequences = Vec::new();
        let mut timeout_positions_set = HashSet::new();

        for s in snapshots {
            distinct_fingerprints.insert(s.fingerprint.clone());

            let mut resp_seq = Vec::new();
            let mut timeouts = Vec::new();

            for hop in &s.hops {
                if hop.responded {
                    if let Some(ref addr) = hop.primary_address {
                        resp_seq.push((hop.hop_number, addr.clone()));
                    }
                } else {
                    timeouts.push(hop.hop_number);
                }
            }

            responding_ip_sequences.push(resp_seq);
            timeout_positions_set.insert(timeouts);
        }

        // If only 1 unique fingerprint exists across all runs, path is structurally identical
        if distinct_fingerprints.len() == 1 {
            return PathDifferenceClassification::SameObservedPath;
        }

        // Check if all responding IP sequences are identical (ignoring intermediate timeouts)
        let first_resp = &responding_ip_sequences[0];
        let all_responding_match = responding_ip_sequences.iter().all(|seq| {
            // Verify common responding hop numbers have identical IPs
            let seq_map: HashMap<u8, &String> = seq.iter().map(|(h, ip)| (*h, ip)).collect();
            let first_map: HashMap<u8, &String> = first_resp.iter().map(|(h, ip)| (*h, ip)).collect();

            let mut common_hops_match = true;
            for (h, ip) in &seq_map {
                if let Some(f_ip) = first_map.get(h) {
                    if ip != f_ip {
                        common_hops_match = false;
                        break;
                    }
                }
            }
            common_hops_match
        });

        if all_responding_match {
            // If responding IPs matched wherever present, but timeout locations fluctuated
            PathDifferenceClassification::MinorResponseVariation
        } else {
            // Consistent structural change in intermediate or terminal router IPs
            PathDifferenceClassification::StructuralRouteVariation
        }
    }

    /// Classify the structural path relationship between two distinct candidates (e.g. Candidate A vs Candidate B).
    pub fn classify_two_candidates(
        snapshots_a: &[RouteSnapshot],
        snapshots_b: &[RouteSnapshot],
    ) -> PathDifferenceClassification {
        if snapshots_a.is_empty() || snapshots_b.is_empty() {
            return PathDifferenceClassification::InsufficientEvidence;
        }

        let dominant_fp_a = get_dominant_fingerprint(snapshots_a);
        let dominant_fp_b = get_dominant_fingerprint(snapshots_b);

        if dominant_fp_a == dominant_fp_b {
            return PathDifferenceClassification::SameObservedPath;
        }

        let rep_a = snapshots_a.iter().find(|s| s.fingerprint == dominant_fp_a).unwrap_or(&snapshots_a[0]);
        let rep_b = snapshots_b.iter().find(|s| s.fingerprint == dominant_fp_b).unwrap_or(&snapshots_b[0]);

        // Check if responding hops differ structurally
        let map_a: HashMap<u8, &String> = rep_a
            .hops
            .iter()
            .filter(|h| h.responded && h.primary_address.is_some())
            .map(|h| (h.hop_number, h.primary_address.as_ref().unwrap()))
            .collect();

        let map_b: HashMap<u8, &String> = rep_b
            .hops
            .iter()
            .filter(|h| h.responded && h.primary_address.is_some())
            .map(|h| (h.hop_number, h.primary_address.as_ref().unwrap()))
            .collect();

        let mut structural_difference_found = false;
        let max_hops = rep_a.hops.len().max(rep_b.hops.len());

        for h in 1..=max_hops as u8 {
            if let (Some(ip_a), Some(ip_b)) = (map_a.get(&h), map_b.get(&h)) {
                if ip_a != ip_b {
                    structural_difference_found = true;
                    break;
                }
            }
        }

        if structural_difference_found || rep_a.hops.len() != rep_b.hops.len() {
            PathDifferenceClassification::StructuralRouteVariation
        } else {
            PathDifferenceClassification::MinorResponseVariation
        }
    }

    /// Calculate median value of a slice of usize.
    pub fn median_usize(values: &[usize]) -> usize {
        if values.is_empty() {
            return 0;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        }
    }
}

fn get_dominant_fingerprint(snapshots: &[RouteSnapshot]) -> String {
    let mut counts = HashMap::new();
    let mut order = Vec::new();
    for s in snapshots {
        let count = counts.entry(&s.fingerprint).or_insert(0);
        if *count == 0 {
            order.push(&s.fingerprint);
        }
        *count += 1;
    }
    let mut dom = "";
    let mut max_c = 0;
    for fp in order {
        let c = counts[fp];
        if c > max_c {
            max_c = c;
            dom = fp;
        }
    }
    dom.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_intelligence::models::RouteHop;

    fn make_test_snapshot(fp: &str, hops: Vec<RouteHop>) -> RouteSnapshot {
        RouteSnapshot {
            measurement_id: "test".to_string(),
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
            measurement_duration_ms: 1000,
            scientific_disclaimer: "".to_string(),
        }
    }

    fn make_hop(num: u8, ip: Option<&str>) -> RouteHop {
        let responded = ip.is_some();
        RouteHop {
            hop_number: num,
            addresses: ip.map(|s| vec![s.to_string()]).unwrap_or_default(),
            primary_address: ip.map(|s| s.to_string()),
            hostname: None,
            rtt_samples_ms: if responded { vec![10.0] } else { vec![] },
            responded,
            timeout_count: if responded { 0 } else { 3 },
            probe_count: 3,
            rtt_stats: None,
            is_timeout: !responded,
            raw_line: "".to_string(),
        }
    }

    #[test]
    fn test_classify_identical_snapshots() {
        let s1 = make_test_snapshot("FP1", vec![make_hop(1, Some("192.168.1.1")), make_hop(2, Some("1.1.1.1"))]);
        let s2 = make_test_snapshot("FP1", vec![make_hop(1, Some("192.168.1.1")), make_hop(2, Some("1.1.1.1"))]);

        assert_eq!(
            PathDiversityEngine::classify_snapshots(&[s1, s2]),
            PathDifferenceClassification::SameObservedPath
        );
    }

    #[test]
    fn test_classify_minor_response_variation() {
        let s1 = make_test_snapshot("FP1", vec![
            make_hop(1, Some("192.168.1.1")),
            make_hop(2, None), // timeout on hop 2
            make_hop(3, Some("1.1.1.1")),
        ]);
        let s2 = make_test_snapshot("FP2", vec![
            make_hop(1, Some("192.168.1.1")),
            make_hop(2, Some("10.0.0.1")), // responded on hop 2
            make_hop(3, Some("1.1.1.1")),
        ]);

        assert_eq!(
            PathDiversityEngine::classify_snapshots(&[s1, s2]),
            PathDifferenceClassification::MinorResponseVariation
        );
    }

    #[test]
    fn test_classify_structural_variation() {
        let s1 = make_test_snapshot("FP1", vec![
            make_hop(1, Some("192.168.1.1")),
            make_hop(2, Some("223.230.16.1")),
            make_hop(3, Some("1.1.1.1")),
        ]);
        let s2 = make_test_snapshot("FP2", vec![
            make_hop(1, Some("192.168.1.1")),
            make_hop(2, Some("182.79.243.1")), // different router IP
            make_hop(3, Some("1.1.1.1")),
        ]);

        assert_eq!(
            PathDiversityEngine::classify_snapshots(&[s1, s2]),
            PathDifferenceClassification::StructuralRouteVariation
        );
    }

    #[test]
    fn test_classify_insufficient_evidence() {
        let s1 = make_test_snapshot("FP1", vec![make_hop(1, Some("192.168.1.1"))]);
        assert_eq!(
            PathDiversityEngine::classify_snapshots(&[s1]),
            PathDifferenceClassification::InsufficientEvidence
        );
    }
}
