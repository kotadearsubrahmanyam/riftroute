use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PacketDirection {
    Tx, // Local -> Remote (Outbound)
    Rx, // Remote -> Local (Inbound)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointKey {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
}

impl EndpointKey {
    /// Deterministically normalize an IP:port pair into an EndpointKey.
    /// If one endpoint is private/local and the other public, the private IP is designated local.
    /// If both are private or both public, lexicographical ordering is used.
    pub fn normalize(
        src_ip_str: &str,
        src_port: u16,
        dst_ip_str: &str,
        dst_port: u16,
        protocol: &str,
    ) -> (Self, PacketDirection) {
        let src_is_private = is_private_ip(src_ip_str);
        let dst_is_private = is_private_ip(dst_ip_str);

        if src_is_private && !dst_is_private {
            // Source is local private IP, Destination is remote public IP -> TX
            (
                Self {
                    local_ip: src_ip_str.to_string(),
                    local_port: src_port,
                    remote_ip: dst_ip_str.to_string(),
                    remote_port: dst_port,
                    protocol: protocol.to_string(),
                },
                PacketDirection::Tx,
            )
        } else if !src_is_private && dst_is_private {
            // Destination is local private IP, Source is remote public IP -> RX
            (
                Self {
                    local_ip: dst_ip_str.to_string(),
                    local_port: dst_port,
                    remote_ip: src_ip_str.to_string(),
                    remote_port: src_port,
                    protocol: protocol.to_string(),
                },
                PacketDirection::Rx,
            )
        } else {
            // Both private or both public: deterministic comparison
            let ep_src = (src_ip_str, src_port);
            let ep_dst = (dst_ip_str, dst_port);

            if ep_src <= ep_dst {
                (
                    Self {
                        local_ip: src_ip_str.to_string(),
                        local_port: src_port,
                        remote_ip: dst_ip_str.to_string(),
                        remote_port: dst_port,
                        protocol: protocol.to_string(),
                    },
                    PacketDirection::Tx,
                )
            } else {
                (
                    Self {
                        local_ip: dst_ip_str.to_string(),
                        local_port: dst_port,
                        remote_ip: src_ip_str.to_string(),
                        remote_port: src_port,
                        protocol: protocol.to_string(),
                    },
                    PacketDirection::Rx,
                )
            }
        }
    }
}

/// Helper function to detect RFC 1918 private IPs, link-local, and loopback.
pub fn is_private_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 10.0.0.0/8
                octets[0] == 10
                // 172.16.0.0/12
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                // 192.168.0.0/16
                || (octets[0] == 192 && octets[1] == 168)
                // 127.0.0.0/8 loopback
                || octets[0] == 127
                // 169.254.0.0/16 link-local
                || (octets[0] == 169 && octets[1] == 254)
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    } else {
        // Fallback string prefix check
        ip_str.starts_with("192.168.")
            || ip_str.starts_with("10.")
            || ip_str.starts_with("127.")
            || ip_str.starts_with("169.254.")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacketRecord {
    pub timestamp: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub frame_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowPacket {
    pub timestamp: f64,
    pub direction: PacketDirection,
    pub frame_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketSizeStatistics {
    pub min_bytes: u32,
    pub max_bytes: u32,
    pub mean_bytes: f64,
    pub median_bytes: f64,
    pub std_dev_bytes: f64,
    pub p95_bytes: f64,
    pub p99_bytes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterArrivalStatistics {
    pub min_gap_ms: f64,
    pub mean_gap_ms: f64,
    pub median_gap_ms: f64,
    pub p95_gap_ms: f64,
    pub p99_gap_ms: f64,
    pub max_gap_ms: f64,
    pub std_dev_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GapCounts {
    pub gaps_over_10ms: usize,
    pub gaps_over_25ms: usize,
    pub gaps_over_50ms: usize,
    pub gaps_over_100ms: usize,
    pub gaps_over_250ms: usize,
    pub gaps_over_500ms: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BurstStatistics {
    pub burst_count: usize,
    pub avg_packets_per_burst: f64,
    pub max_packets_in_burst: usize,
    pub avg_burst_duration_ms: f64,
    pub max_burst_duration_ms: f64,
    pub burst_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectionRatio {
    pub tx_packet_pct: f64,
    pub rx_packet_pct: f64,
    pub tx_byte_pct: f64,
    pub rx_byte_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointStability {
    pub is_continuously_active: bool,
    pub active_duration_ratio: f64,
    pub longest_inactivity_gap_ms: f64,
    pub gaps_over_100ms_count: usize,
    pub gaps_over_500ms_count: usize,
    pub gaps_over_1s_count: usize,
    pub criteria_commentary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointFlowReport {
    pub rank: usize,
    pub classification: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub first_packet_ts: f64,
    pub last_packet_ts: f64,
    pub flow_duration_seconds: f64,
    pub total_packets: usize,
    pub tx_packets: usize,
    pub rx_packets: usize,
    pub total_bytes: usize,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub packet_rate_total: f64,
    pub packet_rate_tx: f64,
    pub packet_rate_rx: f64,
    pub tx_packet_size: Option<PacketSizeStatistics>,
    pub rx_packet_size: Option<PacketSizeStatistics>,
    pub overall_packet_size: Option<PacketSizeStatistics>,
    pub inter_arrival: Option<InterArrivalStatistics>,
    pub gaps: GapCounts,
    pub bursts: BurstStatistics,
    pub direction_ratio: DirectionRatio,
    pub stability: EndpointStability,
    pub rtt: Option<f64>,
    pub rtt_note: String,
    pub packet_loss: Option<f64>,
    pub packet_loss_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaptureMetadata {
    pub file_path: String,
    pub total_lines_read: usize,
    pub valid_packets: usize,
    pub malformed_lines: usize,
    pub capture_duration_seconds: f64,
    pub first_timestamp: f64,
    pub last_timestamp: f64,
    pub total_bytes: usize,
    pub distinct_endpoints_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointAnalysisReport {
    pub capture: CaptureMetadata,
    pub endpoints: Vec<EndpointFlowReport>,
    pub analysis_timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_normalization_bidirectional() {
        let (key1, dir1) = EndpointKey::normalize(
            "192.168.1.14",
            50837,
            "20.205.179.128",
            27528,
            "UDP",
        );
        let (key2, dir2) = EndpointKey::normalize(
            "20.205.179.128",
            27528,
            "192.168.1.14",
            50837,
            "UDP",
        );

        // Both directions normalize to the identical flow key
        assert_eq!(key1, key2);
        assert_eq!(key1.local_ip, "192.168.1.14");
        assert_eq!(key1.local_port, 50837);
        assert_eq!(key1.remote_ip, "20.205.179.128");
        assert_eq!(key1.remote_port, 27528);

        // Directions are correctly identified relative to local endpoint
        assert_eq!(dir1, PacketDirection::Tx);
        assert_eq!(dir2, PacketDirection::Rx);
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("192.168.1.14"));
        assert!(is_private_ip("10.0.0.5"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("20.205.179.128"));
        assert!(!is_private_ip("85.236.96.163"));
        assert!(!is_private_ip("8.8.8.8"));
    }
}
