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

/// Structural path diversity relationship between direct path and relay path (Step 19 & 39).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PathDiversityType {
    SameObservedPath,
    MinorResponseVariation,
    StructuralRouteVariation,
    InsufficientEvidence,
}

impl std::fmt::Display for PathDiversityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SameObservedPath => write!(f, "SAME_OBSERVED_PATH"),
            Self::MinorResponseVariation => write!(f, "MINOR_RESPONSE_VARIATION"),
            Self::StructuralRouteVariation => write!(f, "STRUCTURAL_ROUTE_VARIATION"),
            Self::InsufficientEvidence => write!(f, "INSUFFICIENT_EVIDENCE"),
        }
    }
}

/// Structured outcome of path diversity analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathDiversityResult {
    pub diversity_type: PathDiversityType,
    pub direct_fingerprint: String,
    pub leg1_fingerprint: String,
    pub leg2_fingerprint: String,
    pub direct_hop_count: usize,
    pub relay_hop_count: usize,
    pub shared_hops_count: usize,
    pub distinct_hops_count: usize,
    pub rationale: String,
}

/// Descriptive classification of comparative path performance (Step 25).
/// Hard requirement: These are descriptive classifications, NOT routing decisions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComparisonClassification {
    RelayLowerObservedEstimate,
    DirectLowerObservedMeasurement,
    WithinMeasurementVariability,
    InsufficientEvidence,
}

impl std::fmt::Display for ComparisonClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RelayLowerObservedEstimate => write!(f, "RELAY_LOWER_OBSERVED_ESTIMATE"),
            Self::DirectLowerObservedMeasurement => write!(f, "DIRECT_LOWER_OBSERVED_MEASUREMENT"),
            Self::WithinMeasurementVariability => write!(f, "WITHIN_MEASUREMENT_VARIABILITY"),
            Self::InsufficientEvidence => write!(f, "INSUFFICIENT_EVIDENCE"),
        }
    }
}

/// 95% Confidence Interval for latency samples (Step 27).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceInterval {
    pub confidence_level_pct: f64,
    pub lower_bound_ms: f64,
    pub upper_bound_ms: f64,
    pub margin_of_error_ms: f64,
}

/// Comprehensive statistical metrics across a measurement series (Step 23 & 27).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetailedPathStatistics {
    pub sample_count: usize,
    pub min_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub std_dev_ms: f64,
    pub jitter_ms: f64,
    pub confidence_interval_95: Option<ConfidenceInterval>,
}

/// Raw record of a single measurement cycle in a campaign (Step 21 & 22).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CampaignSampleRecord {
    pub cycle_index: usize,
    pub timestamp_utc: String,
    pub direct_rtt_ms: f64,
    pub client_to_relay_rtt_ms: f64,
    pub relay_to_destination_rtt_ms: f64,
    pub composed_estimate_ms: f64,
    pub direct_fingerprint: String,
    pub relay_fingerprint: String,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Full longitudinal measurement campaign report (Step 21, 22, 23, 24).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeasurementCampaign {
    pub campaign_id: String,
    pub relay_id: String,
    pub destination: String,
    pub sample_count: usize,
    pub availability_pct: f64,
    pub auth_success_rate_pct: f64,
    pub measurement_success_rate_pct: f64,
    pub direct_stats: DetailedPathStatistics,
    pub client_relay_stats: DetailedPathStatistics,
    pub relay_dest_stats: DetailedPathStatistics,
    pub composed_stats: DetailedPathStatistics,
    pub delta_median_ms: f64,
    pub delta_p95_ms: f64,
    pub path_diversity: PathDiversityResult,
    pub classification: ComparisonClassification,
    pub dominant_direct_fingerprint: String,
    pub dominant_relay_fingerprint: String,
    pub route_transition_rate_pct: f64,
    pub raw_samples: Vec<CampaignSampleRecord>,
    pub timestamp_utc: String,
    pub scientific_disclaimer: String,
}

/// Result of controlled relay failure & recovery lifecycle experiment (Step 29).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayFailureTestResult {
    pub relay_id: String,
    pub initial_status: RelayStatusType,
    pub failure_detected: bool,
    pub failure_mode_observed: Option<RelayFailureMode>,
    pub failure_detection_latency_ms: f64,
    pub recovery_detected: bool,
    pub recovery_detection_latency_ms: f64,
    pub timestamp_utc: String,
}

/// Result of controlled rate-limiting validation test (Step 31).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitTestResult {
    pub relay_id: String,
    pub configured_limit_per_min: usize,
    pub total_requests_sent: usize,
    pub successful_requests: usize,
    pub rate_limited_requests: usize,
    pub rate_limit_enforced: bool,
    pub timestamp_utc: String,
}
