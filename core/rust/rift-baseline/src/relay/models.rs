pub use rift_relay::models::{
    LocationMetadata, LocationProvenance, ProbeProtocol, RelayFailureMode, RelayHealth,
    RelayMeasurementResult, RelayNode, RelayStatusType,
};
pub use rift_relay::protocol::{ProtocolFraming, RelayMessage, MAX_FRAME_SIZE, PROTOCOL_VERSION};

use serde::{Deserialize, Serialize};

/// Stored cryptographic identity for the RiftRoute client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub client_id: String,
    pub public_key_hex: String,
    pub private_key_hex: Option<String>,
    pub created_at_utc: String,
}

/// Representation of a relay-assisted end-to-end network path (Step 19 & 20).
/// Strictly distinguishes composed estimate from direct measured values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayPath {
    pub relay_id: String,
    pub destination: String,
    pub client_relay_fingerprint: String,
    pub relay_destination_fingerprint: String,
    pub client_to_relay_probe_rtt_ms: f64,
    pub relay_to_destination_probe_rtt_ms: f64,
    /// Composed latency estimate (client_to_relay + relay_to_destination).
    /// Hard requirement: Explicitly marked as composed estimate, NOT actual direct game ping.
    pub composed_estimate_ms: f64,
    pub is_composed_estimate: bool,
    pub timestamp_utc: String,
    pub scientific_disclaimer: String,
}

impl RelayPath {
    pub fn compose(
        relay_id: String,
        destination: String,
        client_relay_fp: String,
        relay_dest_fp: String,
        c2r_rtt: f64,
        r2d_rtt: f64,
        timestamp_utc: String,
    ) -> Self {
        Self {
            relay_id,
            destination,
            client_relay_fingerprint: client_relay_fp,
            relay_destination_fingerprint: relay_dest_fp,
            client_to_relay_probe_rtt_ms: c2r_rtt,
            relay_to_destination_probe_rtt_ms: r2d_rtt,
            composed_estimate_ms: c2r_rtt + r2d_rtt,
            is_composed_estimate: true,
            timestamp_utc,
            scientific_disclaimer: "Composed relay path latency is a diagnostic arithmetic estimate (leg 1 + leg 2) and reflects ICMP control-plane RTT, not in-game UDP gameplay latency.".to_string(),
        }
    }
}

/// Factual empirical comparison between Direct path and Relay-assisted path (Step 21 & 22).
/// Hard constraint: PROHIBITS "BEST_RELAY", "WINNER", or "OPTIMAL_ROUTE".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectVsRelayComparison {
    pub target_destination: String,
    pub relay_id: String,
    pub relay_endpoint: String,
    pub direct_median_ms: f64,
    pub direct_p95_ms: f64,
    pub direct_jitter_ms: Option<f64>,
    pub direct_fingerprint: String,
    pub direct_hop_count: usize,
    pub client_to_relay_probe_rtt_ms: f64,
    pub relay_to_destination_probe_rtt_ms: f64,
    pub composed_relay_rtt_ms: f64,
    pub delta_median_ms: f64,
    pub delta_p95_ms: f64,
    pub delta_jitter_ms: Option<f64>,
    pub path_difference_summary: String,
    pub network_overhead_ms: f64,
    pub control_plane_roundtrip_ms: f64,
    pub timestamp_utc: String,
    pub scientific_disclaimer: String,
}
