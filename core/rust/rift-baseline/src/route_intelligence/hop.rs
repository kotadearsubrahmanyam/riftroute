use super::models::HopRttStats;

/// Scientific statistical engine for route hop RTT samples.
pub struct HopStatsEngine;

impl HopStatsEngine {
    /// Calculate comprehensive distributional statistics from a collection of valid RTT samples.
    pub fn compute_stats(samples: &[f64]) -> Option<HopRttStats> {
        if samples.is_empty() {
            return None;
        }

        let sample_count = samples.len();
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min_ms = sorted[0];
        let max_ms = sorted[sample_count - 1];
        let sum: f64 = sorted.iter().sum();
        let mean_ms = sum / sample_count as f64;

        let median_ms = Self::calculate_percentile(&sorted, 50.0);
        let p95_ms = Self::calculate_percentile(&sorted, 95.0);
        let p99_ms = Self::calculate_percentile(&sorted, 99.0);

        let std_dev_ms = if sample_count > 1 {
            let variance: f64 = sorted
                .iter()
                .map(|val| {
                    let diff = val - mean_ms;
                    diff * diff
                })
                .sum::<f64>()
                / (sample_count - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        // Mean Absolute Packet Delay Variation (MAPDV / RFC 5481) between consecutive samples
        let jitter_ms = if samples.len() >= 2 {
            let mut diff_sum = 0.0;
            for i in 1..samples.len() {
                diff_sum += (samples[i] - samples[i - 1]).abs();
            }
            Some(diff_sum / (samples.len() - 1) as f64)
        } else {
            None
        };

        Some(HopRttStats {
            sample_count,
            min_ms,
            median_ms,
            mean_ms,
            p95_ms,
            p99_ms,
            max_ms,
            std_dev_ms,
            jitter_ms,
        })
    }

    /// Calculate percentile using linear interpolation between closest ranks.
    pub fn calculate_percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
        if sorted_samples.is_empty() {
            return 0.0;
        }
        if sorted_samples.len() == 1 {
            return sorted_samples[0];
        }

        let p = (percentile / 100.0).clamp(0.0, 1.0);
        let rank = p * (sorted_samples.len() - 1) as f64;
        let lower_idx = rank.floor() as usize;
        let upper_idx = rank.ceil() as usize;
        let fraction = rank - lower_idx as f64;

        if lower_idx == upper_idx || upper_idx >= sorted_samples.len() {
            sorted_samples[lower_idx]
        } else {
            sorted_samples[lower_idx] + fraction * (sorted_samples[upper_idx] - sorted_samples[lower_idx])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_stats_single_sample() {
        let stats = HopStatsEngine::compute_stats(&[15.0]).unwrap();
        assert_eq!(stats.sample_count, 1);
        assert_eq!(stats.min_ms, 15.0);
        assert_eq!(stats.max_ms, 15.0);
        assert_eq!(stats.mean_ms, 15.0);
        assert_eq!(stats.median_ms, 15.0);
        assert_eq!(stats.std_dev_ms, 0.0);
        assert_eq!(stats.jitter_ms, None);
    }

    #[test]
    fn test_compute_stats_three_samples() {
        let stats = HopStatsEngine::compute_stats(&[10.0, 12.0, 14.0]).unwrap();
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.min_ms, 10.0);
        assert_eq!(stats.median_ms, 12.0);
        assert_eq!(stats.mean_ms, 12.0);
        assert_eq!(stats.max_ms, 14.0);
        assert!((stats.std_dev_ms - 2.0).abs() < 1e-6);
        // Consecutive deltas: |12 - 10| = 2, |14 - 12| = 2. Avg = 2.0
        assert_eq!(stats.jitter_ms, Some(2.0));
    }

    #[test]
    fn test_compute_stats_empty() {
        assert!(HopStatsEngine::compute_stats(&[]).is_none());
    }

    #[test]
    fn test_calculate_percentiles() {
        let data = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(HopStatsEngine::calculate_percentile(&data, 0.0), 10.0);
        assert_eq!(HopStatsEngine::calculate_percentile(&data, 50.0), 30.0);
        assert_eq!(HopStatsEngine::calculate_percentile(&data, 100.0), 50.0);
    }
}
