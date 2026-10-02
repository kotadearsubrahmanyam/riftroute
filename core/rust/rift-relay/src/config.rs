use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::auth::AuthorizedClient;
use crate::models::{LocationMetadata, LocationProvenance};

/// Comprehensive runtime configuration for a RiftRoute Relay daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub relay_id: String,
    pub listen_address: String,
    pub control_port: u16,
    pub identity_path: PathBuf,
    pub authorized_clients_path: Option<PathBuf>,
    pub authorized_clients: Vec<AuthorizedClient>,
    pub location: LocationMetadata,
    pub max_concurrent_jobs: usize,
    pub max_request_size_bytes: usize,
    pub rate_limit_per_minute: usize,
    pub allow_private_targets: bool,
    pub challenge_ttl_seconds: i64,
    pub session_ttl_minutes: i64,
    pub log_level: String,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relay_id: "relay_in_01".to_string(),
            listen_address: "0.0.0.0".to_string(),
            control_port: 44321,
            identity_path: PathBuf::from("data/relay/identity.json"),
            authorized_clients_path: None,
            authorized_clients: Vec::new(),
            location: LocationMetadata {
                country: "IN".to_string(),
                region: "AP".to_string(),
                city: "Vijayawada".to_string(),
                provider: "Dedicated Relay Node".to_string(),
                asn: None,
                provenance: LocationProvenance::OperatorDeclared,
            },
            max_concurrent_jobs: 5,
            max_request_size_bytes: 65536,
            rate_limit_per_minute: 60,
            allow_private_targets: false,
            challenge_ttl_seconds: 30,
            session_ttl_minutes: 60,
            log_level: "info".to_string(),
        }
    }
}

impl RelayConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read relay config {}: {}", path.as_ref().display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse relay config JSON: {}", e))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize relay config: {}", e))?;
        fs::write(p, json).map_err(|e| format!("Failed to write relay config: {}", e))?;
        Ok(())
    }
}
