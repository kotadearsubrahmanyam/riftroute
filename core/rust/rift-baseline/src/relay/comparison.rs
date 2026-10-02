use chrono::Utc;

use crate::relay::models::{DirectVsRelayComparison, RelayMeasurementResult, RelayNode};
use crate::route_intelligence::models::RouteSnapshot;

pub struct ComparisonEngine;

impl ComparisonEngine {
    /// Factual, objective comparison between Direct Client -> Destination baseline
    /// and Relay-Assisted (Client -> Relay + Relay -> Destination) path.
    ///
    /// Hard constraints:
    /// - PROHIBITS "BEST_RELAY", "WINNER", or "OPTIMAL_ROUTE".
    /// - Output reflects only observed RTT deltas and structural path differences.
    pub fn compare(
        relay: &RelayNode,
        target_destination: &str,
        direct_snapshot: &RouteSnapshot,
        client_to_relay_rtt_ms: f64,
        relay_measurement: &RelayMeasurementResult,
        control_roundtrip_ms: f64,
    ) -> DirectVsRelayComparison {
        // Direct metrics
        let direct_median = direct_snapshot
            .hops
            .last()
            .and_then(|h| h.rtt_stats.as_ref())
            .map(|s| s.median_ms)
            .unwrap_or(0.0);

        let direct_p95 = direct_snapshot
            .hops
            .last()
            .and_then(|h| h.rtt_stats.as_ref())
            .map(|s| s.p95_ms)
            .unwrap_or(direct_median);

        let direct_jitter = direct_snapshot
            .hops
            .last()
            .and_then(|h| h.rtt_stats.as_ref())
            .and_then(|s| s.jitter_ms);

        // Relay metrics
        let r2d_median = relay_measurement.median_rtt_ms.unwrap_or(0.0);
        let r2d_p95 = relay_measurement.p95_rtt_ms.unwrap_or(r2d_median);

        let composed_rtt = client_to_relay_rtt_ms + r2d_median;

        let delta_median = composed_rtt - direct_median;
        let delta_p95 = (client_to_relay_rtt_ms + r2d_p95) - direct_p95;

        let delta_jitter = match (relay_measurement.jitter_ms, direct_jitter) {
            (Some(rj), Some(dj)) => Some(rj - dj),
            _ => None,
        };

        // Path difference description
        let mut diff_notes = Vec::new();
        if direct_snapshot.fingerprint != relay_measurement.route_fingerprint {
            diff_notes.push(format!(
                "Route structures diverge: Direct path fingerprint '{}' vs Relay leg fingerprint '{}'",
                direct_snapshot.fingerprint, relay_measurement.route_fingerprint
            ));
        } else {
            diff_notes.push("Direct path and relay-egress share identical route fingerprint prefix".to_string());
        }

        diff_notes.push(format!(
            "Hop topology: Direct path {} hops vs Relay leg {} hops (Client->Relay transit introduced)",
            direct_snapshot.hop_count, relay_measurement.hop_count
        ));

        let summary = diff_notes.join("; ");

        DirectVsRelayComparison {
            target_destination: target_destination.to_string(),
            relay_id: relay.relay_id.clone(),
            relay_endpoint: format!("{}:{}", relay.public_address, relay.control_port),
            direct_median_ms: direct_median,
            direct_p95_ms: direct_p95,
            direct_jitter_ms: direct_jitter,
            direct_fingerprint: direct_snapshot.fingerprint.clone(),
            direct_hop_count: direct_snapshot.hop_count,
            client_to_relay_probe_rtt_ms: client_to_relay_rtt_ms,
            relay_to_destination_probe_rtt_ms: r2d_median,
            composed_relay_rtt_ms: composed_rtt,
            delta_median_ms: delta_median,
            delta_p95_ms: delta_p95,
            delta_jitter_ms: delta_jitter,
            path_difference_summary: summary,
            network_overhead_ms: delta_median.max(0.0),
            control_plane_roundtrip_ms: control_roundtrip_ms,
            timestamp_utc: Utc::now().to_rfc3339(),
            scientific_disclaimer: "Comparison reflects ICMP/TCP diagnostic probe latency differences. Composed relay latency is leg 1 + leg 2 arithmetic estimate and does not represent live UDP gaming traffic.".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::models::{LocationMetadata, ProbeProtocol, RelayNode, RelayStatusType};
    use crate::route_intelligence::models::{HopRttStats, RouteHop, RouteSnapshot};

    fn make_test_relay() -> RelayNode {
        RelayNode {
            relay_id: "relay_test_01".to_string(),
            public_address: "127.0.0.1".to_string(),
            control_port: 44321,
            identity_fingerprint: "FP_RELAY".to_string(),
            public_key_hex: "00".repeat(32),
            location: LocationMetadata::default(),
            protocol_version: 1,
            capabilities: vec!["ping".to_string()],
            status: RelayStatusType::Online,
            last_seen_utc: None,
            notes: "".to_string(),
        }
    }

    fn make_test_direct_snapshot(median: f64, p95: f64, jitter: f64, fp: &str) -> RouteSnapshot {
        let final_hop = RouteHop {
            hop_number: 10,
            addresses: vec!["20.205.179.128".to_string()],
            primary_address: Some("20.205.179.128".to_string()),
            hostname: None,
            rtt_samples_ms: vec![median, p95],
            responded: true,
            timeout_count: 0,
            probe_count: 2,
            rtt_stats: Some(HopRttStats {
                sample_count: 2,
                min_ms: median - 1.0,
                median_ms: median,
                mean_ms: median,
                p95_ms: p95,
                p99_ms: p95,
                max_ms: p95,
                std_dev_ms: 1.0,
                jitter_ms: Some(jitter),
            }),
            is_timeout: false,
            raw_line: "".to_string(),
        };

        RouteSnapshot {
            measurement_id: "meas_direct_01".to_string(),
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            destination: "20.205.179.128".to_string(),
            destination_ip: Some("20.205.179.128".to_string()),
            destination_port: Some(27528),
            probe_method: "tracert".to_string(),
            resolve_hostnames: false,
            active_interface: None,
            source_ipv4: None,
            default_gateway: None,
            hop_count: 10,
            responding_hops: 10,
            timeout_hops: 0,
            hops: vec![final_hop],
            fingerprint: fp.to_string(),
            fingerprint_sha256: fp.to_string(),
            canonical_path: "path".to_string(),
            measurement_duration_ms: 500,
            scientific_disclaimer: "test".to_string(),
        }
    }

    #[test]
    fn test_direct_vs_relay_comparison_math() {
        let relay = make_test_relay();
        let direct_snap = make_test_direct_snapshot(60.0, 62.0, 1.5, "FP_DIRECT_01");

        let relay_res = RelayMeasurementResult {
            request_id: "req_01".to_string(),
            relay_id: "relay_test_01".to_string(),
            destination: "20.205.179.128".to_string(),
            destination_ip: Some("20.205.179.128".to_string()),
            protocol: ProbeProtocol::Icmp,
            probe_rtt_samples_ms: vec![50.0, 50.5, 51.0],
            median_rtt_ms: Some(50.5),
            min_rtt_ms: Some(50.0),
            max_rtt_ms: Some(51.0),
            p95_rtt_ms: Some(51.0),
            std_dev_ms: Some(0.5),
            jitter_ms: Some(0.5),
            hop_count: 6,
            responding_hops: 6,
            timeout_hops: 0,
            route_fingerprint: "FP_RELAY_EGRESS_01".to_string(),
            execution_duration_ms: 200,
            success: true,
            error_message: None,
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            scientific_disclaimer: "test".to_string(),
        };

        let c2r_rtt = 15.0; // Client -> Relay is 15 ms
        let control_rt = 35.0;

        let comp = ComparisonEngine::compare(
            &relay,
            "20.205.179.128",
            &direct_snap,
            c2r_rtt,
            &relay_res,
            control_rt,
        );

        assert_eq!(comp.direct_median_ms, 60.0);
        assert_eq!(comp.client_to_relay_probe_rtt_ms, 15.0);
        assert_eq!(comp.relay_to_destination_probe_rtt_ms, 50.5);
        assert_eq!(comp.composed_relay_rtt_ms, 65.5); // 15 + 50.5
        assert_eq!(comp.delta_median_ms, 5.5); // 65.5 - 60.0
        assert_eq!(comp.delta_p95_ms, 4.0); // (15 + 51) - 62
        assert_eq!(comp.delta_jitter_ms, Some(-1.0)); // 0.5 - 1.5
        assert_eq!(comp.network_overhead_ms, 5.5);
        assert!(comp.path_difference_summary.contains("Route structures diverge"));
    }
}
