use serde::{Deserialize, Serialize};
use crate::route_intelligence::models::{HopRttStats, RouteSnapshot};

/// Categorization of engineering evidence backing a candidate destination or path observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceLevel {
    /// Raw empirical data directly captured from OS sockets, raw packets, or responding ICMP hops
    DirectlyObserved,
    /// Statistically computed or derived from directly observed data (e.g. fingerprints, percentiles)
    Derived,
    /// Plausible network engineering interpretation (e.g. transit peering or multi-hop transition)
    Inferred,
    /// Physical or proprietary properties that cannot be validated passively
    Unverified,
}

/// Objective classification of path differences across repeated measurements or distinct candidates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PathDifferenceClassification {
    /// Responding hop IP sequences are structurally identical across runs
    SameObservedPath,
    /// Same responding router IPs, but intermediate timeout pattern differed (transient ICMP rate-limiting/filtering)
    MinorResponseVariation,
    /// Distinct responding router IP addresses consistently observed between runs or candidates
    StructuralRouteVariation,
    /// Insufficient repeated measurements to make a defensible path determination (< 2 runs or inconclusive)
    InsufficientEvidence,
}

/// A normalized network destination identified as a candidate endpoint for a target game or service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateDestination {
    pub candidate_id: String,
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub service_name: String,
    pub process_name: Option<String>,
    pub local_port: Option<u16>,
    pub discovery_method: String,
    pub evidence_level: EvidenceLevel,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    pub observation_count: usize,
    pub role_hypothesis: String,
}

/// A longitudinal series of repeated route measurements toward a single candidate destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateMeasurementSeries {
    pub candidate_id: String,
    pub destination: String,
    pub target_ip: String,
    pub target_port: Option<u16>,
    pub service_name: String,
    pub run_count: usize,
    pub measurement_snapshots: Vec<RouteSnapshot>,
    pub measurement_ids: Vec<String>,
    pub unique_fingerprints: Vec<String>,
    pub dominant_fingerprint: String,
    pub dominant_fingerprint_pct: f64,
    pub path_difference_classification: PathDifferenceClassification,
    /// Latency characteristics of the final responding hop (explicitly labeled as probe RTT, NOT game ping)
    pub final_hop_probe_stats: Option<HopRttStats>,
    pub hop_count_median: usize,
    pub responding_hop_count_median: usize,
    pub timeout_hop_count_median: usize,
    pub route_transition_count: usize,
    pub route_transition_rate_pct: f64,
    pub execution_window_start: String,
    pub execution_window_end: String,
    pub scientific_disclaimer: String,
}

/// Concise summary of a candidate measurement series used for pairwise candidate comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateMeasurementSeriesSummary {
    pub candidate_id: String,
    pub destination: String,
    pub target_ip: String,
    pub target_port: Option<u16>,
    pub service_name: String,
    pub run_count: usize,
    pub dominant_fingerprint: String,
    pub dominant_fingerprint_pct: f64,
    pub final_hop_median_rtt_ms: Option<f64>,
    pub final_hop_p95_rtt_ms: Option<f64>,
    pub final_hop_max_rtt_ms: Option<f64>,
    pub final_hop_std_dev_ms: Option<f64>,
    pub hop_count_median: usize,
    pub responding_hop_count_median: usize,
    pub timeout_hop_count_median: usize,
    pub route_transition_rate_pct: f64,
    pub path_difference_classification: PathDifferenceClassification,
}

/// Objective, value-neutral comparison between two candidate measurement series.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidateComparisonReport {
    pub comparison_id: String,
    pub timestamp_utc: String,
    pub candidate_a: CandidateMeasurementSeriesSummary,
    pub candidate_b: CandidateMeasurementSeriesSummary,
    pub path_relationship: PathDifferenceClassification,
    pub final_hop_median_delta_ms: Option<f64>,
    pub final_hop_p95_delta_ms: Option<f64>,
    pub hop_count_delta: i64,
    pub structural_differences: Vec<String>,
    pub factual_comparison_summary: String,
    pub scientific_disclaimer: String,
}

/// Path diversity report synthesizing observations across multiple candidate destinations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CandidatePathDiversityReport {
    pub report_id: String,
    pub timestamp_utc: String,
    pub service_name: String,
    pub total_candidates: usize,
    pub candidate_summaries: Vec<CandidateMeasurementSeriesSummary>,
    pub unique_fingerprints_across_all_candidates: Vec<String>,
    pub structural_variation_count: usize,
    pub shared_path_count: usize,
    pub architectural_status: String,
    pub scientific_disclaimer: String,
}

impl CandidateMeasurementSeries {
    pub fn to_summary(&self) -> CandidateMeasurementSeriesSummary {
        CandidateMeasurementSeriesSummary {
            candidate_id: self.candidate_id.clone(),
            destination: self.destination.clone(),
            target_ip: self.target_ip.clone(),
            target_port: self.target_port,
            service_name: self.service_name.clone(),
            run_count: self.run_count,
            dominant_fingerprint: self.dominant_fingerprint.clone(),
            dominant_fingerprint_pct: self.dominant_fingerprint_pct,
            final_hop_median_rtt_ms: self.final_hop_probe_stats.as_ref().map(|s| s.median_ms),
            final_hop_p95_rtt_ms: self.final_hop_probe_stats.as_ref().map(|s| s.p95_ms),
            final_hop_max_rtt_ms: self.final_hop_probe_stats.as_ref().map(|s| s.max_ms),
            final_hop_std_dev_ms: self.final_hop_probe_stats.as_ref().map(|s| s.std_dev_ms),
            hop_count_median: self.hop_count_median,
            responding_hop_count_median: self.responding_hop_count_median,
            timeout_hop_count_median: self.timeout_hop_count_median,
            route_transition_rate_pct: self.route_transition_rate_pct,
            path_difference_classification: self.path_difference_classification.clone(),
        }
    }
}
