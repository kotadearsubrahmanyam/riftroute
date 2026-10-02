use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::candidate_path::models::{CandidateDestination, EvidenceLevel};
use crate::route_intelligence::models::RouteSnapshot;

/// Monitored network destination with preserved discovery evidence and operational configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitoringTarget {
    pub target_id: String,
    pub candidate_id: Option<String>,
    pub destination: String,
    pub destination_ip: String,
    pub target_port: Option<u16>,
    pub protocol: String,
    pub service_name: String,
    pub evidence_level: EvidenceLevel,
    pub enabled: bool,
    pub created_at_utc: String,
    pub notes: String,
}

impl MonitoringTarget {
    pub fn from_candidate(cand: &CandidateDestination) -> Self {
        Self {
            target_id: format!("target_{}", cand.candidate_id),
            candidate_id: Some(cand.candidate_id.clone()),
            destination: cand.ip.clone(),
            destination_ip: cand.ip.clone(),
            target_port: cand.port,
            protocol: cand.protocol.clone(),
            service_name: cand.service_name.clone(),
            evidence_level: cand.evidence_level.clone(),
            enabled: true,
            created_at_utc: Utc::now().to_rfc3339(),
            notes: format!("Derived from CandidateDestination ({})", cand.role_hypothesis),
        }
    }

    pub fn from_destination(dest: &str, port: Option<u16>, service: Option<&str>) -> Self {
        let now = Utc::now().to_rfc3339();
        let target_id = format!(
            "target_{}_{}",
            dest.replace('.', "_").replace(':', "_"),
            port.unwrap_or(0)
        );
        Self {
            target_id,
            candidate_id: None,
            destination: dest.to_string(),
            destination_ip: dest.to_string(),
            target_port: port,
            protocol: "ICMP/IP".to_string(),
            service_name: service.unwrap_or("Manual Target").to_string(),
            evidence_level: EvidenceLevel::DirectlyObserved,
            enabled: true,
            created_at_utc: now,
            notes: "Explicitly specified target for route monitoring".to_string(),
        }
    }
}

/// A normalized point-in-time probe sample collected during active route monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitoringSample {
    pub sample_id: String,
    pub target_id: String,
    pub timestamp_utc: String,
    pub measurement_id: String,
    pub route_fingerprint: String,
    pub canonical_path: String,
    pub final_hop_rtt_ms: Option<f64>,
    pub final_hop_p95_ms: Option<f64>,
    pub final_hop_p99_ms: Option<f64>,
    pub final_hop_min_ms: Option<f64>,
    pub final_hop_max_ms: Option<f64>,
    pub final_hop_std_dev_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub hop_count: usize,
    pub responding_hops: usize,
    pub timeout_hops: usize,
    pub measurement_duration_ms: u64,
    pub is_failure: bool,
    pub failure_reason: Option<String>,
    pub target_unreachable: bool,
}

impl MonitoringSample {
    pub fn from_snapshot(target_id: &str, snap: &RouteSnapshot) -> Self {
        let sample_id = format!("sample_{}", snap.measurement_id);

        // Find final responding hop
        let final_hop = snap
            .hops
            .iter()
            .rev()
            .find(|h| h.responded && !h.rtt_samples_ms.is_empty());

        let (final_rtt, p95, p99, min_rtt, max_rtt, std_dev, jitter) = match final_hop {
            Some(h) => {
                if let Some(ref st) = h.rtt_stats {
                    (
                        Some(st.median_ms),
                        Some(st.p95_ms),
                        Some(st.p99_ms),
                        Some(st.min_ms),
                        Some(st.max_ms),
                        Some(st.std_dev_ms),
                        st.jitter_ms,
                    )
                } else if !h.rtt_samples_ms.is_empty() {
                    (
                        Some(h.rtt_samples_ms[0]),
                        Some(h.rtt_samples_ms[0]),
                        Some(h.rtt_samples_ms[0]),
                        Some(h.rtt_samples_ms[0]),
                        Some(h.rtt_samples_ms[0]),
                        Some(0.0),
                        None,
                    )
                } else {
                    (None, None, None, None, None, None, None)
                }
            }
            None => (None, None, None, None, None, None, None),
        };

        let target_unreachable = snap.responding_hops == 0
            || (snap.destination_ip.is_some()
                && !snap
                    .hops
                    .iter()
                    .any(|h| h.primary_address == snap.destination_ip));

        Self {
            sample_id,
            target_id: target_id.to_string(),
            timestamp_utc: snap.timestamp_utc.clone(),
            measurement_id: snap.measurement_id.clone(),
            route_fingerprint: snap.fingerprint.clone(),
            canonical_path: snap.canonical_path.clone(),
            final_hop_rtt_ms: final_rtt,
            final_hop_p95_ms: p95,
            final_hop_p99_ms: p99,
            final_hop_min_ms: min_rtt,
            final_hop_max_ms: max_rtt,
            final_hop_std_dev_ms: std_dev,
            jitter_ms: jitter,
            hop_count: snap.hop_count,
            responding_hops: snap.responding_hops,
            timeout_hops: snap.timeout_hops,
            measurement_duration_ms: snap.measurement_duration_ms,
            is_failure: false,
            failure_reason: None,
            target_unreachable,
        }
    }

    pub fn failure(target_id: &str, reason: &str) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            sample_id: format!("sample_fail_{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
            target_id: target_id.to_string(),
            timestamp_utc: now,
            measurement_id: "failure".to_string(),
            route_fingerprint: "NONE".to_string(),
            canonical_path: "".to_string(),
            final_hop_rtt_ms: None,
            final_hop_p95_ms: None,
            final_hop_p99_ms: None,
            final_hop_min_ms: None,
            final_hop_max_ms: None,
            final_hop_std_dev_ms: None,
            jitter_ms: None,
            hop_count: 0,
            responding_hops: 0,
            timeout_hops: 0,
            measurement_duration_ms: 0,
            is_failure: true,
            failure_reason: Some(reason.to_string()),
            target_unreachable: true,
        }
    }
}

/// Baseline network behavior established for a monitored route target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitoringBaseline {
    pub baseline_id: String,
    pub target_id: String,
    pub created_at_utc: String,
    pub sample_count: usize,
    pub baseline_method: String,
    pub median_rtt_ms: f64,
    pub p95_rtt_ms: f64,
    pub p99_rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub std_dev_ms: f64,
    pub jitter_ms: f64,
    pub dominant_fingerprint: String,
    pub dominant_fingerprint_pct: f64,
    pub unique_fingerprints_count: usize,
    pub route_transition_rate_pct: f64,
    pub hop_count_median: usize,
    pub responding_hop_count_median: usize,
    pub timeout_hop_count_median: usize,
    pub is_frozen: bool,
    pub raw_sample_ids: Vec<String>,
}

/// Configurable thresholds governing route degradation detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DegradationThresholds {
    pub baseline_sample_count: usize,
    pub rolling_window_size: usize,
    pub latency_relative_pct: f64,
    pub latency_absolute_delta_ms: f64,
    pub p95_relative_pct: f64,
    pub jitter_relative_pct: f64,
    pub jitter_absolute_delta_ms: f64,
    pub detect_route_change: bool,
    pub stability_transition_rate_threshold_pct: f64,
    pub confirmation_samples: usize,
    pub recovery_samples: usize,
    pub critical_latency_relative_pct: f64,
    pub critical_latency_absolute_delta_ms: f64,
}

impl Default for DegradationThresholds {
    fn default() -> Self {
        Self {
            baseline_sample_count: 5,
            rolling_window_size: 20,
            latency_relative_pct: 30.0,
            latency_absolute_delta_ms: 20.0,
            p95_relative_pct: 40.0,
            jitter_relative_pct: 100.0,
            jitter_absolute_delta_ms: 5.0,
            detect_route_change: true,
            stability_transition_rate_threshold_pct: 50.0,
            confirmation_samples: 3,
            recovery_samples: 3,
            critical_latency_relative_pct: 100.0,
            critical_latency_absolute_delta_ms: 60.0,
        }
    }
}

/// Taxonomy of discrete route monitoring degradation and lifecycle events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DegradationEventType {
    RouteChanged,
    LatencyDegraded,
    JitterDegraded,
    PathStabilityDegraded,
    HopStructureChanged,
    MeasurementFailure,
    TargetUnreachable,
    Recovered,
}

/// Measurement-level severity classification for degradation events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DegradationSeverity {
    Info,
    Warning,
    Critical,
}

/// Finite state machine lifecycle states for route health monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MonitoringState {
    Normal,
    Suspected,
    Degraded,
    Recovering,
}

/// An audited, machine-readable degradation or lifecycle event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DegradationEvent {
    pub event_id: String,
    pub target_id: String,
    pub timestamp_utc: String,
    pub event_type: DegradationEventType,
    pub state: MonitoringState,
    pub severity: DegradationSeverity,
    pub evidence_description: String,
    pub baseline_median_rtt_ms: Option<f64>,
    pub observed_median_rtt_ms: Option<f64>,
    pub median_delta_ms: Option<f64>,
    pub median_relative_change_pct: Option<f64>,
    pub baseline_jitter_ms: Option<f64>,
    pub observed_jitter_ms: Option<f64>,
    pub baseline_fingerprint: Option<String>,
    pub observed_fingerprint: Option<String>,
    pub consecutive_count: usize,
    pub measurement_ids: Vec<String>,
    pub resolved_at_utc: Option<String>,
    pub scientific_disclaimer: String,
}

/// Complete historical and real-time session tracking a monitored target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitoringSession {
    pub session_id: String,
    pub target: MonitoringTarget,
    pub start_time_utc: String,
    pub end_time_utc: Option<String>,
    pub interval_seconds: u64,
    pub thresholds: DegradationThresholds,
    pub samples: Vec<MonitoringSample>,
    pub baseline: Option<MonitoringBaseline>,
    pub events: Vec<DegradationEvent>,
    pub current_state: MonitoringState,
    pub consecutive_anomalous_samples: usize,
    pub consecutive_recovery_samples: usize,
    pub total_samples_collected: usize,
    pub total_degradations_detected: usize,
    pub total_recoveries_detected: usize,
    pub total_failures_encountered: usize,
    pub is_active: bool,
    pub scientific_disclaimer: String,
}

impl MonitoringSession {
    pub fn new(target: MonitoringTarget, interval_seconds: u64, thresholds: DegradationThresholds) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            session_id: format!("session_{}_{}", target.target_id, Utc::now().format("%Y%m%d_%H%M%S")),
            target,
            start_time_utc: now,
            end_time_utc: None,
            interval_seconds,
            thresholds,
            samples: Vec::new(),
            baseline: None,
            events: Vec::new(),
            current_state: MonitoringState::Normal,
            consecutive_anomalous_samples: 0,
            consecutive_recovery_samples: 0,
            total_samples_collected: 0,
            total_degradations_detected: 0,
            total_recoveries_detected: 0,
            total_failures_encountered: 0,
            is_active: true,
            scientific_disclaimer: "Traceroute RTT reflects ICMP control-plane generation latency, not in-game UDP gameplay latency. Route degradation events indicate empirical path variation and do not modify network routing.".to_string(),
        }
    }
}
