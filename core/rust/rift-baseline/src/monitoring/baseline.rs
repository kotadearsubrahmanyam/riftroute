use chrono::Utc;
use std::collections::HashMap;

use super::models::{DegradationThresholds, MonitoringBaseline, MonitoringSample, MonitoringState};
use crate::candidate_path::diversity::PathDiversityEngine;
use crate::route_intelligence::hop::HopStatsEngine;

/// Engine for computing, maintaining, and protecting route performance baselines.
pub struct BaselineEngine;

impl BaselineEngine {
    /// Compute a deterministic baseline from a slice of valid monitoring samples.
    pub fn compute_baseline(
        target_id: &str,
        samples: &[MonitoringSample],
        thresholds: &DegradationThresholds,
    ) -> Result<MonitoringBaseline, String> {
        let valid_samples: Vec<&MonitoringSample> = samples
            .iter()
            .filter(|s| !s.is_failure && s.final_hop_rtt_ms.is_some())
            .collect();

        if valid_samples.len() < thresholds.baseline_sample_count {
            return Err(format!(
                "Insufficient valid samples ({}/{}) to establish baseline for target {}",
                valid_samples.len(),
                thresholds.baseline_sample_count,
                target_id
            ));
        }

        // Take the most recent `rolling_window_size` samples if more exist
        let window = if valid_samples.len() > thresholds.rolling_window_size {
            &valid_samples[valid_samples.len() - thresholds.rolling_window_size..]
        } else {
            &valid_samples[..]
        };

        let sample_count = window.len();
        let rtt_values: Vec<f64> = window
            .iter()
            .filter_map(|s| s.final_hop_rtt_ms)
            .collect();

        let rtt_stats = HopStatsEngine::compute_stats(&rtt_values)
            .ok_or_else(|| "Failed to compute distributional stats from valid RTT samples".to_string())?;

        // Jitter baseline: mean of sample jitters or computed jitter from rtt_stats
        let jitter_samples: Vec<f64> = window
            .iter()
            .filter_map(|s| s.jitter_ms)
            .collect();
        let baseline_jitter = if !jitter_samples.is_empty() {
            jitter_samples.iter().sum::<f64>() / jitter_samples.len() as f64
        } else {
            rtt_stats.jitter_ms.unwrap_or(0.0)
        };

        // Fingerprint distribution & dominant fingerprint
        let mut fp_counts: HashMap<String, usize> = HashMap::new();
        let mut unique_fps = Vec::new();
        for s in window {
            let count = fp_counts.entry(s.route_fingerprint.clone()).or_insert(0);
            if *count == 0 {
                unique_fps.push(s.route_fingerprint.clone());
            }
            *count += 1;
        }

        let mut dominant_fp = String::new();
        let mut max_count = 0;
        for fp in &unique_fps {
            let count = fp_counts.get(fp).copied().unwrap_or(0);
            if count > max_count {
                max_count = count;
                dominant_fp = fp.clone();
            }
        }
        let dominant_fingerprint_pct = (max_count as f64 / sample_count as f64) * 100.0;

        // Route transitions in window
        let mut transitions = 0;
        if sample_count > 1 {
            for i in 1..sample_count {
                if window[i].route_fingerprint != window[i - 1].route_fingerprint {
                    transitions += 1;
                }
            }
        }
        let route_transition_rate_pct = if sample_count > 1 {
            (transitions as f64 / (sample_count - 1) as f64) * 100.0
        } else {
            0.0
        };

        // Hop counts
        let hop_counts: Vec<usize> = window.iter().map(|s| s.hop_count).collect();
        let resp_counts: Vec<usize> = window.iter().map(|s| s.responding_hops).collect();
        let time_counts: Vec<usize> = window.iter().map(|s| s.timeout_hops).collect();

        let hop_count_median = PathDiversityEngine::median_usize(&hop_counts);
        let responding_hop_count_median = PathDiversityEngine::median_usize(&resp_counts);
        let timeout_hop_count_median = PathDiversityEngine::median_usize(&time_counts);

        let raw_sample_ids: Vec<String> = window.iter().map(|s| s.sample_id.clone()).collect();
        let baseline_id = format!("base_{}_{}", target_id, Utc::now().format("%Y%m%d%H%M%S"));

        Ok(MonitoringBaseline {
            baseline_id,
            target_id: target_id.to_string(),
            created_at_utc: Utc::now().to_rfc3339(),
            sample_count,
            baseline_method: format!("RollingWindow({})", thresholds.rolling_window_size),
            median_rtt_ms: rtt_stats.median_ms,
            p95_rtt_ms: rtt_stats.p95_ms,
            p99_rtt_ms: rtt_stats.p99_ms,
            min_rtt_ms: rtt_stats.min_ms,
            max_rtt_ms: rtt_stats.max_ms,
            std_dev_ms: rtt_stats.std_dev_ms,
            jitter_ms: baseline_jitter,
            dominant_fingerprint: dominant_fp,
            dominant_fingerprint_pct,
            unique_fingerprints_count: unique_fps.len(),
            route_transition_rate_pct,
            hop_count_median,
            responding_hop_count_median,
            timeout_hop_count_median,
            is_frozen: false,
            raw_sample_ids,
        })
    }

    /// Update rolling baseline with baseline contamination protection.
    /// If the monitoring state is DEGRADED or SUSPECTED, the baseline is FROZEN
    /// to prevent anomalous latencies from absorbing into the baseline.
    pub fn update_rolling_baseline(
        current_baseline: Option<&MonitoringBaseline>,
        target_id: &str,
        samples: &[MonitoringSample],
        state: &MonitoringState,
        thresholds: &DegradationThresholds,
    ) -> Option<MonitoringBaseline> {
        // Step 18: Baseline Contamination Protection
        if *state == MonitoringState::Degraded || *state == MonitoringState::Suspected {
            if let Some(b) = current_baseline {
                let mut frozen = b.clone();
                frozen.is_frozen = true;
                return Some(frozen);
            }
        }

        // Under Normal or Recovering state, recompute from rolling window of valid samples
        match Self::compute_baseline(target_id, samples, thresholds) {
            Ok(new_baseline) => Some(new_baseline),
            Err(_) => current_baseline.cloned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(id: &str, rtt: f64, jitter: f64, fp: &str) -> MonitoringSample {
        MonitoringSample {
            sample_id: id.to_string(),
            target_id: "target_test".to_string(),
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            measurement_id: format!("meas_{}", id),
            route_fingerprint: fp.to_string(),
            canonical_path: "1:1.1.1.1".to_string(),
            final_hop_rtt_ms: Some(rtt),
            final_hop_p95_ms: Some(rtt + 2.0),
            final_hop_p99_ms: Some(rtt + 4.0),
            final_hop_min_ms: Some(rtt - 2.0),
            final_hop_max_ms: Some(rtt + 5.0),
            final_hop_std_dev_ms: Some(1.5),
            jitter_ms: Some(jitter),
            hop_count: 5,
            responding_hops: 5,
            timeout_hops: 0,
            measurement_duration_ms: 500,
            is_failure: false,
            failure_reason: None,
            target_unreachable: false,
        }
    }

    #[test]
    fn test_baseline_insufficient_samples() {
        let thresholds = DegradationThresholds {
            baseline_sample_count: 5,
            ..Default::default()
        };
        let samples = vec![
            make_sample("s1", 60.0, 1.5, "FP1"),
            make_sample("s2", 61.0, 1.6, "FP1"),
        ];

        let res = BaselineEngine::compute_baseline("target_test", &samples, &thresholds);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Insufficient valid samples"));
    }

    #[test]
    fn test_baseline_from_five_samples() {
        let thresholds = DegradationThresholds {
            baseline_sample_count: 5,
            ..Default::default()
        };
        let samples = vec![
            make_sample("s1", 58.0, 1.0, "FP1"),
            make_sample("s2", 60.0, 1.5, "FP1"),
            make_sample("s3", 62.0, 2.0, "FP1"),
            make_sample("s4", 60.0, 1.5, "FP1"),
            make_sample("s5", 60.0, 1.5, "FP2"),
        ];

        let base = BaselineEngine::compute_baseline("target_test", &samples, &thresholds).unwrap();
        assert_eq!(base.sample_count, 5);
        assert_eq!(base.median_rtt_ms, 60.0);
        assert_eq!(base.dominant_fingerprint, "FP1");
        assert_eq!(base.dominant_fingerprint_pct, 80.0);
        assert_eq!(base.unique_fingerprints_count, 2);
        assert_eq!(base.is_frozen, false);
    }

    #[test]
    fn test_baseline_contamination_protection() {
        let thresholds = DegradationThresholds {
            baseline_sample_count: 5,
            ..Default::default()
        };
        let samples = vec![
            make_sample("s1", 60.0, 1.5, "FP1"),
            make_sample("s2", 60.0, 1.5, "FP1"),
            make_sample("s3", 60.0, 1.5, "FP1"),
            make_sample("s4", 60.0, 1.5, "FP1"),
            make_sample("s5", 60.0, 1.5, "FP1"),
        ];

        let base = BaselineEngine::compute_baseline("target_test", &samples, &thresholds).unwrap();
        assert_eq!(base.median_rtt_ms, 60.0);

        // Simulate degraded samples coming in
        let degraded_samples = vec![
            make_sample("s1", 60.0, 1.5, "FP1"),
            make_sample("s2", 60.0, 1.5, "FP1"),
            make_sample("s3", 60.0, 1.5, "FP1"),
            make_sample("s4", 60.0, 1.5, "FP1"),
            make_sample("s5", 60.0, 1.5, "FP1"),
            make_sample("s6", 120.0, 10.0, "FP1"),
            make_sample("s7", 125.0, 11.0, "FP1"),
            make_sample("s8", 130.0, 12.0, "FP1"),
        ];

        // While in Degraded state, baseline must be frozen and retain original 60.0ms median
        let updated = BaselineEngine::update_rolling_baseline(
            Some(&base),
            "target_test",
            &degraded_samples,
            &MonitoringState::Degraded,
            &thresholds,
        )
        .unwrap();

        assert_eq!(updated.is_frozen, true);
        assert_eq!(updated.median_rtt_ms, 60.0);
    }
}
