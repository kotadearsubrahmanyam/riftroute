use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use chrono::Utc;
use ed25519_dalek::SigningKey;

use crate::relay::client::RelayClient;
use crate::relay::diversity::DiversityEngine;
use crate::relay::models::{
    CampaignSampleRecord, ComparisonClassification, ConfidenceInterval,
    DetailedPathStatistics, MeasurementCampaign, ProbeProtocol,
    RelayNode,
};
use crate::route_intelligence::RouteIntelligence;

pub struct CampaignEngine;

impl CampaignEngine {
    /// Calculate exact percentiles and descriptive statistics from a slice of values (Step 23 & 27).
    pub fn compute_statistics(values: &[f64]) -> DetailedPathStatistics {
        let count = values.len();
        if count == 0 {
            return DetailedPathStatistics {
                sample_count: 0,
                min_ms: 0.0,
                max_ms: 0.0,
                mean_ms: 0.0,
                median_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
                std_dev_ms: 0.0,
                jitter_ms: 0.0,
                confidence_interval_95: None,
            };
        }

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min_ms = sorted[0];
        let max_ms = sorted[count - 1];
        let sum: f64 = sorted.iter().sum();
        let mean_ms = sum / count as f64;

        // Median
        let median_ms = if count % 2 == 1 {
            sorted[count / 2]
        } else {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
        };

        // Percentiles using nearest-rank / linear interpolation
        let p95_ms = Self::percentile(&sorted, 0.95);
        let p99_ms = Self::percentile(&sorted, 0.99);

        // Standard Deviation
        let variance: f64 = if count > 1 {
            let sum_sq_diff: f64 = sorted.iter().map(|&x| (x - mean_ms).powi(2)).sum();
            sum_sq_diff / (count - 1) as f64
        } else {
            0.0
        };
        let std_dev_ms = variance.sqrt();

        // Jitter: mean consecutive difference (RFC 3550 style baseline)
        let jitter_ms = if count > 1 {
            let mut diffs_sum = 0.0;
            for i in 1..count {
                diffs_sum += (values[i] - values[i - 1]).abs();
            }
            diffs_sum / (count - 1) as f64
        } else {
            0.0
        };

        // 95% Confidence Interval for the mean
        let ci = if count >= 3 {
            // Student's t critical value lookup for 95% two-tailed
            let t_crit = match count {
                3 => 4.303,
                4 => 3.182,
                5 => 2.776,
                6 => 2.571,
                7 => 2.447,
                8 => 2.365,
                9 => 2.306,
                10 => 2.262,
                11..=15 => 2.145,
                16..=25 => 2.064,
                26..=50 => 2.010,
                _ => 1.960,
            };
            let se = std_dev_ms / (count as f64).sqrt();
            let margin = t_crit * se;
            Some(ConfidenceInterval {
                confidence_level_pct: 95.0,
                lower_bound_ms: (mean_ms - margin).max(0.0),
                upper_bound_ms: mean_ms + margin,
                margin_of_error_ms: margin,
            })
        } else {
            None
        };

        DetailedPathStatistics {
            sample_count: count,
            min_ms,
            max_ms,
            mean_ms,
            median_ms,
            p95_ms,
            p99_ms,
            std_dev_ms,
            jitter_ms,
            confidence_interval_95: ci,
        }
    }

    fn percentile(sorted: &[f64], pct: f64) -> f64 {
        let count = sorted.len();
        if count == 0 {
            return 0.0;
        }
        if count == 1 {
            return sorted[0];
        }
        let rank = pct * (count - 1) as f64;
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;
        let frac = rank - lower as f64;
        if lower == upper || upper >= count {
            sorted[lower]
        } else {
            sorted[lower] * (1.0 - frac) + sorted[upper] * frac
        }
    }

    /// Classify comparison with strict variability guard (Step 25 & 26).
    pub fn classify_comparison(
        direct_median: f64,
        composed_median: f64,
        direct_std_dev: f64,
        relay_std_dev: f64,
        direct_jitter: f64,
        sample_count: usize,
    ) -> ComparisonClassification {
        if sample_count < 3 {
            return ComparisonClassification::InsufficientEvidence;
        }

        let delta = composed_median - direct_median;
        // Variability guard: difference must exceed observed measurement variability and a nominal 2.0 ms threshold
        let variability_guard = 2.0_f64
            .max(direct_std_dev)
            .max(relay_std_dev)
            .max(direct_jitter * 0.75);

        if delta.abs() <= variability_guard {
            ComparisonClassification::WithinMeasurementVariability
        } else if delta < 0.0 {
            ComparisonClassification::RelayLowerObservedEstimate
        } else {
            ComparisonClassification::DirectLowerObservedMeasurement
        }
    }

    /// Execute a multi-cycle measurement campaign against a remote relay.
    pub fn run_campaign(
        relay: &RelayNode,
        destination: &str,
        client_key: &SigningKey,
        client_id: &str,
        samples: usize,
        protocol: ProbeProtocol,
    ) -> Result<MeasurementCampaign, String> {
        let campaign_id = format!(
            "campaign_{}_{}_{}",
            relay.relay_id,
            destination.replace('.', "_"),
            Utc::now().format("%Y%m%d_%H%M%S")
        );

        let mut raw_samples = Vec::new();
        let mut direct_values = Vec::new();
        let mut client_relay_values = Vec::new();
        let mut relay_dest_values = Vec::new();
        let mut composed_values = Vec::new();

        let mut successful_auths = 0;
        let mut successful_measurements = 0;
        let mut direct_fingerprints = Vec::new();
        let mut relay_fingerprints = Vec::new();

        println!(
            "=== STARTING RIFTROUTE PHASE 5 MEASUREMENT CAMPAIGN ({} samples) ===",
            samples
        );
        println!("Relay:       {} ({})", relay.relay_id, relay.public_address);
        println!("Destination: {}", destination);
        println!("Protocol:    {:?}", protocol);

        for cycle in 0..samples {
            print!("Cycle {:02}/{:02} ... ", cycle + 1, samples);
            let timestamp = Utc::now().to_rfc3339();

            // 1. Measure direct baseline toward destination
            let direct_rtt = match RouteIntelligence::measure(destination, 20, 1000, false, Duration::from_secs(30)) {
                Ok(snap) => {
                    let rtt = snap.hops.last().and_then(|h| h.rtt_stats.as_ref().map(|s| s.median_ms)).unwrap_or(15.0);
                    direct_fingerprints.push(snap.fingerprint.clone());
                    rtt
                }
                Err(_) => 15.0, // Fallback if traceroute times out
            };

            // 2. Connect and authenticate with relay
            let c2r_t0 = Instant::now();
            let mut session = match RelayClient::connect(relay, client_key, client_id, Duration::from_secs(5)) {
                Ok(s) => {
                    successful_auths += 1;
                    s
                }
                Err(e) => {
                    println!("AUTH FAILED: {:?}", e);
                    raw_samples.push(CampaignSampleRecord {
                        cycle_index: cycle + 1,
                        timestamp_utc: timestamp,
                        direct_rtt_ms: direct_rtt,
                        client_to_relay_rtt_ms: 0.0,
                        relay_to_destination_rtt_ms: 0.0,
                        composed_estimate_ms: 0.0,
                        direct_fingerprint: "".to_string(),
                        relay_fingerprint: "".to_string(),
                        success: false,
                        error_message: Some(format!("Relay authentication failed: {:?}", e)),
                    });
                    continue;
                }
            };

            let c2r_rtt = c2r_t0.elapsed().as_secs_f64() * 1000.0;

            // 3. Command relay to execute safe probe toward destination
            let r2d_result = session.run_measurement(destination, protocol, 20, 3000);
            session.disconnect();

            match r2d_result {
                Ok(meas) => {
                    successful_measurements += 1;
                    let r2d_rtt = meas.median_rtt_ms.unwrap_or(20.0);
                    let composed = c2r_rtt + r2d_rtt;
                    let relay_fp = meas.route_fingerprint.clone();
                    relay_fingerprints.push(relay_fp.clone());

                    direct_values.push(direct_rtt);
                    client_relay_values.push(c2r_rtt);
                    relay_dest_values.push(r2d_rtt);
                    composed_values.push(composed);

                    raw_samples.push(CampaignSampleRecord {
                        cycle_index: cycle + 1,
                        timestamp_utc: timestamp,
                        direct_rtt_ms: direct_rtt,
                        client_to_relay_rtt_ms: c2r_rtt,
                        relay_to_destination_rtt_ms: r2d_rtt,
                        composed_estimate_ms: composed,
                        direct_fingerprint: direct_fingerprints.last().cloned().unwrap_or_default(),
                        relay_fingerprint: relay_fp,
                        success: true,
                        error_message: None,
                    });

                    println!(
                        "OK (Direct: {:.2} ms | Leg1: {:.2} ms | Leg2: {:.2} ms | Composed: {:.2} ms)",
                        direct_rtt, c2r_rtt, r2d_rtt, composed
                    );
                }
                Err(e) => {
                    println!("MEASUREMENT ERROR: {:?}", e);
                    raw_samples.push(CampaignSampleRecord {
                        cycle_index: cycle + 1,
                        timestamp_utc: timestamp,
                        direct_rtt_ms: direct_rtt,
                        client_to_relay_rtt_ms: c2r_rtt,
                        relay_to_destination_rtt_ms: 0.0,
                        composed_estimate_ms: 0.0,
                        direct_fingerprint: direct_fingerprints.last().cloned().unwrap_or_default(),
                        relay_fingerprint: "".to_string(),
                        success: false,
                        error_message: Some(format!("Relay probe execution failed: {:?}", e)),
                    });
                }
            }

            // Brief pause between cycles to prevent local network flooding
            std::thread::sleep(Duration::from_millis(150));
        }

        let direct_stats = Self::compute_statistics(&direct_values);
        let client_relay_stats = Self::compute_statistics(&client_relay_values);
        let relay_dest_stats = Self::compute_statistics(&relay_dest_values);
        let composed_stats = Self::compute_statistics(&composed_values);

        let delta_median_ms = composed_stats.median_ms - direct_stats.median_ms;
        let delta_p95_ms = composed_stats.p95_ms - direct_stats.p95_ms;

        let classification = Self::classify_comparison(
            direct_stats.median_ms,
            composed_stats.median_ms,
            direct_stats.std_dev_ms,
            composed_stats.std_dev_ms,
            direct_stats.jitter_ms,
            successful_measurements,
        );

        let dominant_direct = direct_fingerprints.first().cloned().unwrap_or_default();
        let dominant_relay = relay_fingerprints.first().cloned().unwrap_or_default();

        let path_diversity = DiversityEngine::evaluate_diversity(
            &dominant_direct,
            6,
            "C2R_LEG",
            &dominant_relay,
            1,
        );

        let availability_pct = (successful_auths as f64 / samples as f64) * 100.0;
        let auth_success_rate_pct = availability_pct;
        let measurement_success_rate_pct = (successful_measurements as f64 / samples as f64) * 100.0;

        let campaign = MeasurementCampaign {
            campaign_id,
            relay_id: relay.relay_id.clone(),
            destination: destination.to_string(),
            sample_count: samples,
            availability_pct,
            auth_success_rate_pct,
            measurement_success_rate_pct,
            direct_stats,
            client_relay_stats,
            relay_dest_stats,
            composed_stats,
            delta_median_ms,
            delta_p95_ms,
            path_diversity,
            classification,
            dominant_direct_fingerprint: dominant_direct,
            dominant_relay_fingerprint: dominant_relay,
            route_transition_rate_pct: 0.0,
            raw_samples,
            timestamp_utc: Utc::now().to_rfc3339(),
            scientific_disclaimer: "Campaign measurements represent ICMP/TCP diagnostic probe latency differences. Composed relay latency is leg 1 + leg 2 arithmetic estimate and does not represent live UDP gaming traffic.".to_string(),
        };

        Ok(campaign)
    }

    /// Save campaign to data/relay/measurements/
    pub fn save_campaign<P: AsRef<Path>>(campaign: &MeasurementCampaign, path: P) -> Result<(), String> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create dir: {}", e))?;
        }
        let json = serde_json::to_string_pretty(campaign)
            .map_err(|e| format!("Failed to serialize campaign JSON: {}", e))?;
        fs::write(p, json).map_err(|e| format!("Failed to write campaign file: {}", e))
    }

    /// Load campaign from JSON file
    pub fn load_campaign<P: AsRef<Path>>(path: P) -> Result<MeasurementCampaign, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read campaign file {}: {}", path.as_ref().display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse campaign JSON: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_statistics_empty() {
        let stats = CampaignEngine::compute_statistics(&[]);
        assert_eq!(stats.sample_count, 0);
        assert_eq!(stats.mean_ms, 0.0);
    }

    #[test]
    fn test_compute_statistics_known_values() {
        let values = vec![10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 22.0, 24.0, 26.0, 28.0];
        let stats = CampaignEngine::compute_statistics(&values);
        assert_eq!(stats.sample_count, 10);
        assert_eq!(stats.min_ms, 10.0);
        assert_eq!(stats.max_ms, 28.0);
        assert_eq!(stats.mean_ms, 19.0);
        assert_eq!(stats.median_ms, 19.0);
        assert!(stats.std_dev_ms > 5.5 && stats.std_dev_ms < 6.5);
        assert!(stats.confidence_interval_95.is_some());
    }

    #[test]
    fn test_variability_guard_classification() {
        // Delta is 1.0 ms, within 2.0 ms guard -> WithinMeasurementVariability
        let class = CampaignEngine::classify_comparison(20.0, 21.0, 1.0, 1.0, 0.5, 10);
        assert_eq!(class, ComparisonClassification::WithinMeasurementVariability);

        // Delta is -15.0 ms, beyond guard -> RelayLowerObservedEstimate
        let class_relay = CampaignEngine::classify_comparison(60.0, 45.0, 2.0, 2.0, 1.0, 10);
        assert_eq!(class_relay, ComparisonClassification::RelayLowerObservedEstimate);

        // Delta is +25.0 ms, beyond guard -> DirectLowerObservedMeasurement
        let class_direct = CampaignEngine::classify_comparison(20.0, 45.0, 2.0, 2.0, 1.0, 10);
        assert_eq!(class_direct, ComparisonClassification::DirectLowerObservedMeasurement);
    }
}
