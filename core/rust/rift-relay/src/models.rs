use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Origin and reliability classification of relay location metadata.
/// Hard requirement: NEVER equate IP geolocation with physical location without verified evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocationProvenance {
    OperatorDeclared,
    ExternallyVerified,
    Unverified,
}

impl Default for LocationProvenance {
    fn default() -> Self {
        Self::OperatorDeclared
    }
}

/// Structured location and provider metadata for a RiftRoute relay node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocationMetadata {
    pub country: String,
    pub region: String,
    pub city: String,
    pub provider: String,
    pub asn: Option<u32>,
    pub provenance: LocationProvenance,
}

impl Default for LocationMetadata {
    fn default() -> Self {
        Self {
            country: "Unknown".to_string(),
            region: "Unknown".to_string(),
            city: "Unknown".to_string(),
            provider: "Unknown".to_string(),
            asn: None,
            provenance: LocationProvenance::Unverified,
        }
    }
}

/// Operational status of a relay node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayStatusType {
    Online,
    Degraded,
    Maintenance,
    Offline,
}

impl Default for RelayStatusType {
    fn default() -> Self {
        Self::Online
    }
}

/// Comprehensive model for a registered RiftRoute Relay Node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayNode {
    pub relay_id: String,
    pub public_address: String,
    pub control_port: u16,
    pub identity_fingerprint: String,
    pub public_key_hex: String,
    pub location: LocationMetadata,
    pub protocol_version: u32,
    pub capabilities: Vec<String>,
    pub status: RelayStatusType,
    pub last_seen_utc: Option<String>,
    pub notes: String,
}

impl RelayNode {
    pub fn new(
        relay_id: String,
        public_address: String,
        control_port: u16,
        public_key_hex: String,
        identity_fingerprint: String,
        location: LocationMetadata,
    ) -> Self {
        Self {
            relay_id,
            public_address,
            control_port,
            identity_fingerprint,
            public_key_hex,
            location,
            protocol_version: 1,
            capabilities: vec!["ping".to_string(), "traceroute".to_string(), "tcp_probe".to_string()],
            status: RelayStatusType::Online,
            last_seen_utc: Some(Utc::now().to_rfc3339()),
            notes: "".to_string(),
        }
    }
}

/// Real-time health metrics of a running RiftRoute relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayHealth {
    pub relay_id: String,
    pub is_alive: bool,
    pub uptime_seconds: u64,
    pub cpu_usage_pct: f32,
    pub memory_used_bytes: u64,
    pub active_measurement_jobs: usize,
    pub total_measurements_completed: u64,
    pub last_successful_measurement_utc: Option<String>,
    pub status: RelayStatusType,
}

/// Explicit failure modes for relay control, authentication, and execution (Step 23).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayFailureMode {
    RelayOffline,
    ControlChannelTimeout,
    AuthenticationFailure,
    InvalidMeasurementRequest,
    DestinationUnreachable,
    RelayMeasurementTimeout,
    MalformedResponse,
    ProtocolVersionMismatch,
    IdentityMismatch,
    RateLimitExceeded,
}

impl std::fmt::Display for RelayFailureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for RelayFailureMode {}

/// Approved diagnostic measurement protocols supported by the relay.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeProtocol {
    Icmp,
    Tcp,
}

impl Default for ProbeProtocol {
    fn default() -> Self {
        Self::Icmp
    }
}

/// Structured empirical measurement returned by a relay measuring toward a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayMeasurementResult {
    pub request_id: String,
    pub relay_id: String,
    pub destination: String,
    pub destination_ip: Option<String>,
    pub protocol: ProbeProtocol,
    pub probe_rtt_samples_ms: Vec<f64>,
    pub median_rtt_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub p95_rtt_ms: Option<f64>,
    pub std_dev_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub hop_count: usize,
    pub responding_hops: usize,
    pub timeout_hops: usize,
    pub route_fingerprint: String,
    pub execution_duration_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub timestamp_utc: String,
    pub scientific_disclaimer: String,
}

impl Default for RelayMeasurementResult {
    fn default() -> Self {
        Self {
            request_id: "".to_string(),
            relay_id: "".to_string(),
            destination: "".to_string(),
            destination_ip: None,
            protocol: ProbeProtocol::Icmp,
            probe_rtt_samples_ms: Vec::new(),
            median_rtt_ms: None,
            min_rtt_ms: None,
            max_rtt_ms: None,
            p95_rtt_ms: None,
            std_dev_ms: None,
            jitter_ms: None,
            hop_count: 0,
            responding_hops: 0,
            timeout_hops: 0,
            route_fingerprint: "NONE".to_string(),
            execution_duration_ms: 0,
            success: false,
            error_message: None,
            timestamp_utc: Utc::now().to_rfc3339(),
            scientific_disclaimer: "Traceroute/ping probe RTT reflects control-plane generation latency, not in-game UDP gameplay latency.".to_string(),
        }
    }
}
