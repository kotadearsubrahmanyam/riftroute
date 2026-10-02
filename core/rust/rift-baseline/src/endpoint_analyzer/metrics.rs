use super::models::{
    BurstStatistics, DirectionRatio, EndpointFlowReport, EndpointKey, EndpointStability, FlowPacket,
    GapCounts, InterArrivalStatistics, PacketDirection, PacketSizeStatistics,
};

pub struct MetricsCalculator;

impl MetricsCalculator {
    /// Calculate complete endpoint flow report from a slice of FlowPackets.
    pub fn analyze_flow(
        key: &EndpointKey,
        packets: &[FlowPacket],
        rank: usize,
        total_capture_duration: f64,
    ) -> EndpointFlowReport {
        let total_packets = packets.len();
        assert!(total_packets > 0, "Flow must contain at least one packet");

        let first_packet_ts = packets.first().unwrap().timestamp;
        let last_packet_ts = packets.last().unwrap().timestamp;
        let flow_duration_seconds = (last_packet_ts - first_packet_ts).max(0.0);

        let mut tx_packets = 0;
        let mut rx_packets = 0;
        let mut tx_bytes = 0;
        let mut rx_bytes = 0;
        let mut tx_sizes = Vec::new();
        let mut rx_sizes = Vec::new();
        let mut all_sizes = Vec::with_capacity(total_packets);

        for p in packets {
            all_sizes.push(p.frame_length);
            match p.direction {
                PacketDirection::Tx => {
                    tx_packets += 1;
                    tx_bytes += p.frame_length as usize;
                    tx_sizes.push(p.frame_length);
                }
                PacketDirection::Rx => {
                    rx_packets += 1;
                    rx_bytes += p.frame_length as usize;
                    rx_sizes.push(p.frame_length);
                }
            }
        }

        let total_bytes = tx_bytes + rx_bytes;

        // Packet rates (per second)
        let effective_duration = if flow_duration_seconds > 0.0 {
            flow_duration_seconds
        } else {
            1.0
        };

        let packet_rate_total = total_packets as f64 / effective_duration;
        let packet_rate_tx = tx_packets as f64 / effective_duration;
        let packet_rate_rx = rx_packets as f64 / effective_duration;

        // Direction ratios
        let direction_ratio = DirectionRatio {
            tx_packet_pct: if total_packets > 0 {
                (tx_packets as f64 / total_packets as f64) * 100.0
            } else {
                0.0
            },
            rx_packet_pct: if total_packets > 0 {
                (rx_packets as f64 / total_packets as f64) * 100.0
            } else {
                0.0
            },
            tx_byte_pct: if total_bytes > 0 {
                (tx_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            },
            rx_byte_pct: if total_bytes > 0 {
                (rx_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            },
        };

        // Size statistics
        let tx_packet_size = Self::calculate_size_statistics(&tx_sizes);
        let rx_packet_size = Self::calculate_size_statistics(&rx_sizes);
        let overall_packet_size = Self::calculate_size_statistics(&all_sizes);

        // Inter-arrival gaps
        let mut gaps_ms = Vec::new();
        let mut gaps_over_10ms = 0;
        let mut gaps_over_25ms = 0;
        let mut gaps_over_50ms = 0;
        let mut gaps_over_100ms = 0;
        let mut gaps_over_250ms = 0;
        let mut gaps_over_500ms = 0;
        let mut gaps_over_1s = 0;

        for w in packets.windows(2) {
            let gap_sec = w[1].timestamp - w[0].timestamp;
            let gap_ms = (gap_sec * 1000.0).max(0.0);
            gaps_ms.push(gap_ms);

            if gap_ms > 10.0 {
                gaps_over_10ms += 1;
            }
            if gap_ms > 25.0 {
                gaps_over_25ms += 1;
            }
            if gap_ms > 50.0 {
                gaps_over_50ms += 1;
            }
            if gap_ms > 100.0 {
                gaps_over_100ms += 1;
            }
            if gap_ms > 250.0 {
                gaps_over_250ms += 1;
            }
            if gap_ms > 500.0 {
                gaps_over_500ms += 1;
            }
            if gap_ms > 1000.0 {
                gaps_over_1s += 1;
            }
        }

        let gaps = GapCounts {
            gaps_over_10ms,
            gaps_over_25ms,
            gaps_over_50ms,
            gaps_over_100ms,
            gaps_over_250ms,
            gaps_over_500ms,
        };

        let inter_arrival = Self::calculate_inter_arrival_statistics(&gaps_ms);

        // Burst statistics (burst threshold = 10ms / 0.010s)
        let bursts = Self::calculate_burst_statistics(packets, 0.010);

        // Stability
        let longest_inactivity_gap_ms = gaps_ms.iter().cloned().reduce(f64::max).unwrap_or(0.0);
        let is_continuously_active = longest_inactivity_gap_ms <= 1000.0;
        let active_duration_ratio = if total_capture_duration > 0.0 {
            (flow_duration_seconds / total_capture_duration).min(1.0)
        } else {
            1.0
        };

        let criteria_commentary = if is_continuously_active {
            format!(
                "Continuously active stream (longest gap: {:.1} ms <= 1000 ms threshold; active duration ratio: {:.1}%)",
                longest_inactivity_gap_ms, active_duration_ratio * 100.0
            )
        } else {
            format!(
                "Discontinuous/bursty stream (longest gap: {:.1} ms > 1000 ms threshold; {} gap(s) > 1s)",
                longest_inactivity_gap_ms, gaps_over_1s
            )
        };

        let stability = EndpointStability {
            is_continuously_active,
            active_duration_ratio,
            longest_inactivity_gap_ms,
            gaps_over_100ms_count: gaps_over_100ms,
            gaps_over_500ms_count: gaps_over_500ms,
            gaps_over_1s_count: gaps_over_1s,
            criteria_commentary,
        };

        let classification = if rank == 1 {
            "Highest Traffic Endpoint".to_string()
        } else {
            "Secondary Endpoint".to_string()
        };

        EndpointFlowReport {
            rank,
            classification,
            local_ip: key.local_ip.clone(),
            local_port: key.local_port,
            remote_ip: key.remote_ip.clone(),
            remote_port: key.remote_port,
            protocol: key.protocol.clone(),
            first_packet_ts,
            last_packet_ts,
            flow_duration_seconds,
            total_packets,
            tx_packets,
            rx_packets,
            total_bytes,
            tx_bytes,
            rx_bytes,
            packet_rate_total,
            packet_rate_tx,
            packet_rate_rx,
            tx_packet_size,
            rx_packet_size,
            overall_packet_size,
            inter_arrival,
            gaps,
            bursts,
            direction_ratio,
            stability,
            rtt: None,
            rtt_note: "NOT MEASURED (Passive UDP capture lacks protocol-level request/response correlation)".to_string(),
            packet_loss: None,
            packet_loss_note: "NOT MEASURED (UDP transport layer has no native sequence numbers)".to_string(),
        }
    }

    /// Calculate summary statistics (min, max, mean, median, std_dev, p95, p99) for packet sizes.
    pub fn calculate_size_statistics(sizes: &[u32]) -> Option<PacketSizeStatistics> {
        if sizes.is_empty() {
            return None;
        }

        let min_bytes = *sizes.iter().min().unwrap();
        let max_bytes = *sizes.iter().max().unwrap();
        let sum: u64 = sizes.iter().map(|&s| s as u64).sum();
        let count = sizes.len();
        let mean_bytes = sum as f64 / count as f64;

        let mut sorted = sizes.to_vec();
        sorted.sort_unstable();

        let median_bytes = Self::percentile_u32(&sorted, 50.0);
        let p95_bytes = Self::percentile_u32(&sorted, 95.0);
        let p99_bytes = Self::percentile_u32(&sorted, 99.0);

        let std_dev_bytes = if count > 1 {
            let variance = sorted
                .iter()
                .map(|&s| ((s as f64) - mean_bytes).powi(2))
                .sum::<f64>()
                / (count - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        Some(PacketSizeStatistics {
            min_bytes,
            max_bytes,
            mean_bytes,
            median_bytes,
            std_dev_bytes,
            p95_bytes,
            p99_bytes,
        })
    }

    /// Calculate inter-arrival gap statistics from gap measurements in milliseconds.
    pub fn calculate_inter_arrival_statistics(gaps_ms: &[f64]) -> Option<InterArrivalStatistics> {
        if gaps_ms.is_empty() {
            return None;
        }

        let min_gap_ms = gaps_ms.iter().cloned().reduce(f64::min).unwrap_or(0.0);
        let max_gap_ms = gaps_ms.iter().cloned().reduce(f64::max).unwrap_or(0.0);
        let sum: f64 = gaps_ms.iter().sum();
        let count = gaps_ms.len();
        let mean_gap_ms = sum / count as f64;

        let mut sorted = gaps_ms.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let median_gap_ms = Self::percentile_f64(&sorted, 50.0);
        let p95_gap_ms = Self::percentile_f64(&sorted, 95.0);
        let p99_gap_ms = Self::percentile_f64(&sorted, 99.0);

        let std_dev_ms = if count > 1 {
            let variance = sorted
                .iter()
                .map(|&g| (g - mean_gap_ms).powi(2))
                .sum::<f64>()
                / (count - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        Some(InterArrivalStatistics {
            min_gap_ms,
            mean_gap_ms,
            median_gap_ms,
            p95_gap_ms,
            p99_gap_ms,
            max_gap_ms,
            std_dev_ms,
        })
    }

    /// Deterministic burst calculation: packets with inter-arrival <= threshold_sec belong to the same burst.
    pub fn calculate_burst_statistics(packets: &[FlowPacket], threshold_sec: f64) -> BurstStatistics {
        if packets.is_empty() {
            return BurstStatistics {
                burst_count: 0,
                avg_packets_per_burst: 0.0,
                max_packets_in_burst: 0,
                avg_burst_duration_ms: 0.0,
                max_burst_duration_ms: 0.0,
                burst_rule: format!("Consecutive packets with gap <= {:.1} ms", threshold_sec * 1000.0),
            };
        }

        let mut bursts = Vec::new();
        let mut cur_burst_packets = 1;
        let mut cur_burst_start = packets[0].timestamp;
        let mut cur_burst_end = packets[0].timestamp;

        for i in 1..packets.len() {
            let gap = packets[i].timestamp - packets[i - 1].timestamp;
            if gap <= threshold_sec {
                cur_burst_packets += 1;
                cur_burst_end = packets[i].timestamp;
            } else {
                let duration_ms = ((cur_burst_end - cur_burst_start) * 1000.0).max(0.0);
                bursts.push((cur_burst_packets, duration_ms));
                cur_burst_packets = 1;
                cur_burst_start = packets[i].timestamp;
                cur_burst_end = packets[i].timestamp;
            }
        }
        // Finalize last burst
        let duration_ms = ((cur_burst_end - cur_burst_start) * 1000.0).max(0.0);
        bursts.push((cur_burst_packets, duration_ms));

        let burst_count = bursts.len();
        let total_packets: usize = bursts.iter().map(|b| b.0).sum();
        let max_packets_in_burst = bursts.iter().map(|b| b.0).max().unwrap_or(0);
        let total_duration_ms: f64 = bursts.iter().map(|b| b.1).sum();
        let max_burst_duration_ms = bursts.iter().map(|b| b.1).reduce(f64::max).unwrap_or(0.0);

        let avg_packets_per_burst = if burst_count > 0 {
            total_packets as f64 / burst_count as f64
        } else {
            0.0
        };

        let avg_burst_duration_ms = if burst_count > 0 {
            total_duration_ms / burst_count as f64
        } else {
            0.0
        };

        BurstStatistics {
            burst_count,
            avg_packets_per_burst,
            max_packets_in_burst,
            avg_burst_duration_ms,
            max_burst_duration_ms,
            burst_rule: format!("Consecutive packets with gap <= {:.1} ms", threshold_sec * 1000.0),
        }
    }

    /// Calculate percentile using standard linear interpolation on a sorted slice.
    pub fn percentile_f64(sorted: &[f64], p: f64) -> f64 {
        assert!(!sorted.is_empty());
        if sorted.len() == 1 {
            return sorted[0];
        }

        let rank = (p / 100.0) * (sorted.len() - 1) as f64;
        let lower_idx = rank.floor() as usize;
        let upper_idx = (lower_idx + 1).min(sorted.len() - 1);
        let fraction = rank - lower_idx as f64;

        sorted[lower_idx] + fraction * (sorted[upper_idx] - sorted[lower_idx])
    }

    /// Calculate percentile on a sorted slice of u32, returning f64.
    pub fn percentile_u32(sorted: &[u32], p: f64) -> f64 {
        assert!(!sorted.is_empty());
        if sorted.len() == 1 {
            return sorted[0] as f64;
        }

        let rank = (p / 100.0) * (sorted.len() - 1) as f64;
        let lower_idx = rank.floor() as usize;
        let upper_idx = (lower_idx + 1).min(sorted.len() - 1);
        let fraction = rank - lower_idx as f64;

        (sorted[lower_idx] as f64) + fraction * ((sorted[upper_idx] as f64) - (sorted[lower_idx] as f64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentile_calculations() {
        let v = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(MetricsCalculator::percentile_f64(&v, 0.0), 10.0);
        assert_eq!(MetricsCalculator::percentile_f64(&v, 50.0), 30.0);
        assert_eq!(MetricsCalculator::percentile_f64(&v, 100.0), 50.0);
    }

    #[test]
    fn test_burst_detection() {
        // Packets at 0.000, 0.005, 0.008 (gap <= 10ms -> Burst 1, 3 pkts, dur 8ms)
        // Packet at 0.050 (gap 42ms > 10ms -> Burst 2, 1 pkt, dur 0ms)
        // Packet at 0.054 (gap 4ms <= 10ms -> Burst 2, 2 pkts, dur 4ms)
        let packets = vec![
            FlowPacket { timestamp: 0.000, direction: PacketDirection::Tx, frame_length: 64 },
            FlowPacket { timestamp: 0.005, direction: PacketDirection::Tx, frame_length: 64 },
            FlowPacket { timestamp: 0.008, direction: PacketDirection::Tx, frame_length: 64 },
            FlowPacket { timestamp: 0.050, direction: PacketDirection::Rx, frame_length: 128 },
            FlowPacket { timestamp: 0.054, direction: PacketDirection::Rx, frame_length: 128 },
        ];

        let bursts = MetricsCalculator::calculate_burst_statistics(&packets, 0.010);
        assert_eq!(bursts.burst_count, 2);
        assert_eq!(bursts.max_packets_in_burst, 3);
        assert_eq!(bursts.avg_packets_per_burst, 2.5);
        assert_eq!(bursts.max_burst_duration_ms, 8.0);
    }

    #[test]
    fn test_flow_packet_counts_and_bytes() {
        let key = EndpointKey {
            local_ip: "192.168.1.14".to_string(),
            local_port: 50000,
            remote_ip: "20.205.179.128".to_string(),
            remote_port: 27528,
            protocol: "UDP".to_string(),
        };

        let packets = vec![
            FlowPacket { timestamp: 0.000, direction: PacketDirection::Tx, frame_length: 70 },
            FlowPacket { timestamp: 0.010, direction: PacketDirection::Rx, frame_length: 130 },
            FlowPacket { timestamp: 0.020, direction: PacketDirection::Tx, frame_length: 80 },
        ];

        let rep = MetricsCalculator::analyze_flow(&key, &packets, 1, 0.020);
        assert_eq!(rep.total_packets, 3);
        assert_eq!(rep.tx_packets, 2);
        assert_eq!(rep.rx_packets, 1);
        assert_eq!(rep.total_bytes, 280);
        assert_eq!(rep.tx_bytes, 150);
        assert_eq!(rep.rx_bytes, 130);
        assert_eq!(rep.classification, "Highest Traffic Endpoint");
    }
}
