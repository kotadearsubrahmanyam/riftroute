use serde::{Deserialize, Serialize};

/// Statistical characteristics of Round-Trip Time (RTT) samples at a single route hop.
/// Traceroute RTT reflects ICMP Time Exceeded generation latency from control plane, NOT game RTT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HopRttStats {
    pub sample_count: usize,
    pub min_ms: f64,
    pub median_ms: f64,
    pub mean_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub std_dev_ms: f64,
    /// Interarrival probe jitter (mean absolute delay variation between consecutive successful probes)
    pub jitter_ms: Option<f64>,
}

/// A single intermediate or terminal router hop along an observed network path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteHop {
    pub hop_number: u8,
    /// All responding IP addresses or hostnames observed across probe samples for this hop
    pub addresses: Vec<String>,
    /// Primary observable IP address (first or consistent responding IP)
    pub primary_address: Option<String>,
    /// Resolved reverse-DNS hostname if available
    pub hostname: Option<String>,
    /// All valid RTT samples recorded for this hop in milliseconds
    pub rtt_samples_ms: Vec<f64>,
    /// Whether at least one probe elicited an ICMP response
    pub responded: bool,
    /// Number of probes that timed out ('*' tokens)
    pub timeout_count: usize,
    /// Total probes dispatched for this hop (typically 3)
    pub probe_count: usize,
    /// Statistical breakdown of RTT samples (None if all probes timed out)
    pub rtt_stats: Option<HopRttStats>,
    /// Whether all dispatched probes timed out
    pub is_timeout: bool,
    /// Raw unparsed tokens for diagnostic reproducibility
    pub raw_line: String,
}

/// A complete, point-in-time empirical measurement of a network route toward a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteSnapshot {
    pub measurement_id: String,
    pub timestamp_utc: String,
    pub destination: String,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub probe_method: String,
    pub resolve_hostnames: bool,
    pub active_interface: Option<String>,
    pub source_ipv4: Option<String>,
    pub default_gateway: Option<String>,
    pub hop_count: usize,
    pub responding_hops: usize,
    pub timeout_hops: usize,
    pub hops: Vec<RouteHop>,
    /// Deterministic 16-character canonical route fingerprint (prefix of SHA-256)
    pub fingerprint: String,
    /// Full 64-character SHA-256 hexadecimal digest of canonical route structure
    pub fingerprint_sha256: String,
    /// Canonical hop-by-hop string representation used for fingerprint hashing
    pub canonical_path: String,
    pub measurement_duration_ms: u64,
    /// Scientific integrity notice regarding probe RTT vs application latency
    pub scientific_disclaimer: String,
}

/// Categorization of structural changes between two hops at the same route position.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HopDiffType {
    Unchanged,
    AddressChanged,
    TimeoutToResponding,
    RespondingToTimeout,
    HopAdded,
    HopRemoved,
}

/// Structural difference observed at a specific hop position between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HopDifference {
    pub hop_number: u8,
    pub diff_type: HopDiffType,
    pub previous_address: Option<String>,
    pub current_address: Option<String>,
    pub description: String,
}

/// RTT difference observed at a specific responding hop between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HopRttChange {
    pub hop_number: u8,
    pub address: String,
    pub previous_median_ms: Option<f64>,
    pub current_median_ms: Option<f64>,
    pub delta_median_ms: Option<f64>,
}

/// Empirical comparison between two route snapshots for the same or different destinations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteComparison {
    pub previous_id: String,
    pub previous_timestamp: String,
    pub previous_fingerprint: String,
    pub current_id: String,
    pub current_timestamp: String,
    pub current_fingerprint: String,
    pub destination: String,
    pub fingerprint_identical: bool,
    pub hop_count_delta: i64,
    pub hop_differences: Vec<HopDifference>,
    pub rtt_changes: Vec<HopRttChange>,
    pub summary: String,
}

/// Occurrence frequency of a specific route fingerprint in an observation window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FingerprintFrequency {
    pub fingerprint: String,
    pub count: usize,
    pub percentage: f64,
    pub sample_snapshot_id: String,
}

/// Hop-level variability metrics across multiple chronological route snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HopVariability {
    pub hop_number: u8,
    pub unique_addresses: Vec<String>,
    pub timeout_count: usize,
    pub timeout_frequency_pct: f64,
    pub is_stable: bool,
}

/// Multi-session route stability and path persistence analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteStabilityReport {
    pub destination: String,
    pub analysis_window_start: String,
    pub analysis_window_end: String,
    pub total_snapshots: usize,
    pub unique_fingerprints_count: usize,
    pub fingerprint_frequencies: Vec<FingerprintFrequency>,
    pub dominant_fingerprint: String,
    pub dominant_fingerprint_pct: f64,
    pub route_change_count: usize,
    pub route_change_rate_pct: f64,
    pub hop_variability: Vec<HopVariability>,
    pub stability_summary: String,
}
