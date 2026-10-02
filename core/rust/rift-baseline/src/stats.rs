use serde::{Deserialize, Serialize};

/// Statistics for a collection of Round-Trip Time (RTT) measurements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RttStats {
    pub total_probes: usize,
    pub successful_probes: usize,
    pub failed_probes: usize,
    pub packet_loss_pct: f64,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub mean_ms: Option<f64>,
    pub median_ms: Option<f64>,
    pub std_dev_ms: Option<f64>,
    /// Jitter calculated according to RFC 3550 (Interarrival Jitter estimate using 1/16 smoothing)
    pub rfc3550_jitter_ms: Option<f64>,
    /// Mean Absolute Packet Delay Variation (MAPDV / RFC 5481) between consecutive successful probes
    pub mapdv_jitter_ms: Option<f64>,
}

impl RttStats {
    /// Compute statistics from a slice of probe results where None represents a timeout/failed probe.
    pub fn compute(probes: &[Option<f64>]) -> Self {
        let total_probes = probes.len();
        if total_probes == 0 {
            return Self {
                total_probes: 0,
                successful_probes: 0,
                failed_probes: 0,
                packet_loss_pct: 0.0,
                min_ms: None,
                max_ms: None,
                mean_ms: None,
                median_ms: None,
                std_dev_ms: None,
                rfc3550_jitter_ms: None,
                mapdv_jitter_ms: None,
            };
        }

        let successful_samples: Vec<f64> = probes.iter().filter_map(|&rtt| rtt).collect();
        let successful_probes = successful_samples.len();
        let failed_probes = total_probes - successful_probes;
        let packet_loss_pct = (failed_probes as f64 / total_probes as f64) * 100.0;

        if successful_probes == 0 {
            return Self {
                total_probes,
                successful_probes: 0,
                failed_probes,
                packet_loss_pct,
                min_ms: None,
                max_ms: None,
                mean_ms: None,
                median_ms: None,
                std_dev_ms: None,
                rfc3550_jitter_ms: None,
                mapdv_jitter_ms: None,
            };
        }

        // Min and Max
        let min_ms = successful_samples.iter().cloned().reduce(f64::min);
        let max_ms = successful_samples.iter().cloned().reduce(f64::max);

        // Mean
        let sum: f64 = successful_samples.iter().sum();
        let mean_ms = sum / successful_probes as f64;

        // Median (using sorted copy)
        let mut sorted = successful_samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_ms = if successful_probes % 2 == 1 {
            sorted[successful_probes / 2]
        } else {
            let mid = successful_probes / 2;
            (sorted[mid - 1] + sorted[mid]) / 2.0
        };

        // Sample Standard Deviation: sqrt( sum( (x - mean)^2 ) / (N - 1) )
        let std_dev_ms = if successful_probes > 1 {
            let variance = successful_samples
                .iter()
                .map(|&x| (x - mean_ms).powi(2))
                .sum::<f64>()
                / (successful_probes - 1) as f64;
            Some(variance.sqrt())
        } else {
            Some(0.0)
        };

        // RFC 3550 Jitter:
        // J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
        // where D(i-1, i) = RTT_i - RTT_{i-1}
        let rfc3550_jitter_ms = if successful_probes >= 2 {
            let mut j = 0.0;
            for i in 1..successful_probes {
                let d = (successful_samples[i] - successful_samples[i - 1]).abs();
                j += (d - j) / 16.0;
            }
            Some(j)
        } else {
            Some(0.0)
        };

        // Mean Absolute Packet Delay Variation (MAPDV / RFC 5481 / RFC 3393):
        // MAPDV = 1 / (N - 1) * sum( |RTT_{i+1} - RTT_i| )
        let mapdv_jitter_ms = if successful_probes >= 2 {
            let diff_sum: f64 = successful_samples
                .windows(2)
                .map(|w| (w[1] - w[0]).abs())
                .sum();
            Some(diff_sum / (successful_probes - 1) as f64)
        } else {
            Some(0.0)
        };

        Self {
            total_probes,
            successful_probes,
            failed_probes,
            packet_loss_pct,
            min_ms,
            max_ms,
            mean_ms: Some(mean_ms),
            median_ms: Some(median_ms),
            std_dev_ms,
            rfc3550_jitter_ms,
            mapdv_jitter_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_probes() {
        let stats = RttStats::compute(&[]);
        assert_eq!(stats.total_probes, 0);
        assert_eq!(stats.successful_probes, 0);
        assert_eq!(stats.failed_probes, 0);
        assert_eq!(stats.packet_loss_pct, 0.0);
        assert!(stats.min_ms.is_none());
        assert!(stats.mean_ms.is_none());
    }

    #[test]
    fn test_all_failed_probes() {
        let stats = RttStats::compute(&[None, None, None, None]);
        assert_eq!(stats.total_probes, 4);
        assert_eq!(stats.successful_probes, 0);
        assert_eq!(stats.failed_probes, 4);
        assert_eq!(stats.packet_loss_pct, 100.0);
        assert!(stats.min_ms.is_none());
        assert!(stats.mean_ms.is_none());
    }

    #[test]
    fn test_single_probe() {
        let stats = RttStats::compute(&[Some(42.0)]);
        assert_eq!(stats.total_probes, 1);
        assert_eq!(stats.successful_probes, 1);
        assert_eq!(stats.failed_probes, 0);
        assert_eq!(stats.packet_loss_pct, 0.0);
        assert_eq!(stats.min_ms, Some(42.0));
        assert_eq!(stats.max_ms, Some(42.0));
        assert_eq!(stats.mean_ms, Some(42.0));
        assert_eq!(stats.median_ms, Some(42.0));
        assert_eq!(stats.std_dev_ms, Some(0.0));
        assert_eq!(stats.rfc3550_jitter_ms, Some(0.0));
        assert_eq!(stats.mapdv_jitter_ms, Some(0.0));
    }

    #[test]
    fn test_median_odd_and_even() {
        // Odd: 10, 20, 30 -> median = 20
        let odd_stats = RttStats::compute(&[Some(30.0), Some(10.0), Some(20.0)]);
        assert_eq!(odd_stats.median_ms, Some(20.0));

        // Even: 10, 20, 30, 40 -> median = (20 + 30) / 2 = 25
        let even_stats = RttStats::compute(&[Some(40.0), Some(10.0), Some(30.0), Some(20.0)]);
        assert_eq!(even_stats.median_ms, Some(25.0));
    }

    #[test]
    fn test_packet_loss_calculation() {
        let probes = vec![Some(20.0), None, Some(22.0), None];
        let stats = RttStats::compute(&probes);
        assert_eq!(stats.total_probes, 4);
        assert_eq!(stats.successful_probes, 2);
        assert_eq!(stats.failed_probes, 2);
        assert_eq!(stats.packet_loss_pct, 50.0);
        assert_eq!(stats.min_ms, Some(20.0));
        assert_eq!(stats.max_ms, Some(22.0));
        assert_eq!(stats.mean_ms, Some(21.0));
    }

    #[test]
    fn test_known_statistics() {
        // Sample: [10.0, 12.0, 14.0, 16.0, 18.0]
        // Mean = 70 / 5 = 14.0
        // Differences from mean: -4, -2, 0, 2, 4
        // Squared differences: 16 + 4 + 0 + 4 + 16 = 40
        // Variance = 40 / 4 = 10.0
        // Std Dev = sqrt(10) ~= 3.16227766
        let probes = vec![Some(10.0), Some(12.0), Some(14.0), Some(16.0), Some(18.0)];
        let stats = RttStats::compute(&probes);
        assert_eq!(stats.mean_ms, Some(14.0));
        assert_eq!(stats.median_ms, Some(14.0));
        let std_dev = stats.std_dev_ms.unwrap();
        assert!((std_dev - 3.162277).abs() < 1e-4);

        // Consecutive differences: each step is 2.0
        // MAPDV = (2 + 2 + 2 + 2) / 4 = 2.0
        assert_eq!(stats.mapdv_jitter_ms, Some(2.0));
    }

    #[test]
    fn test_rfc3550_jitter_exact() {
        // Probes: [10.0, 26.0]
        // D(0, 1) = |26 - 10| = 16.0
        // J(1) = 0 + (16.0 - 0) / 16 = 1.0
        let probes = vec![Some(10.0), Some(26.0)];
        let stats = RttStats::compute(&probes);
        assert_eq!(stats.rfc3550_jitter_ms, Some(1.0));
        assert_eq!(stats.mapdv_jitter_ms, Some(16.0));
    }
}
