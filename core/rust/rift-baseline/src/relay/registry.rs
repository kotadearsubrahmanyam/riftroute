use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::relay::models::{
    LocationMetadata, LocationProvenance, RelayNode, RelayStatusType,
};

/// Local registry managing known RiftRoute relay nodes (Step 24).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayRegistry {
    pub relays: Vec<RelayNode>,
    #[serde(skip)]
    registry_path: PathBuf,
}

impl RelayRegistry {
    pub fn new() -> Self {
        Self {
            relays: Vec::new(),
            registry_path: PathBuf::from("data/relay/registry.json"),
        }
    }

    /// Load or create the default local relay registry.
    pub fn load_or_init<P: AsRef<Path>>(path: P) -> Self {
        let p = path.as_ref();
        if p.exists() {
            if let Ok(content) = fs::read_to_string(p) {
                if let Ok(mut reg) = serde_json::from_str::<RelayRegistry>(&content) {
                    reg.registry_path = p.to_path_buf();
                    return reg;
                }
            }
        }

        let mut reg = Self::new();
        reg.registry_path = p.to_path_buf();
        reg.seed_defaults();
        let _ = reg.save();
        reg
    }

    /// Populate candidate relay entries (Mumbai, Chennai, Singapore, Local).
    pub fn seed_defaults(&mut self) {
        if !self.relays.is_empty() {
            return;
        }

        // Local development relay
        self.relays.push(RelayNode {
            relay_id: "relay_local_01".to_string(),
            public_address: "127.0.0.1".to_string(),
            control_port: 44321,
            identity_fingerprint: "LOCAL_DEV_RELAY".to_string(),
            public_key_hex: "00".repeat(32),
            location: LocationMetadata {
                country: "IN".to_string(),
                region: "Localhost".to_string(),
                city: "Localhost".to_string(),
                provider: "Loopback".to_string(),
                asn: None,
                provenance: LocationProvenance::OperatorDeclared,
            },
            protocol_version: 1,
            capabilities: vec!["ping".to_string(), "tcp_probe".to_string()],
            status: RelayStatusType::Online,
            last_seen_utc: Some(chrono::Utc::now().to_rfc3339()),
            notes: "Local loopback testing relay".to_string(),
        });

        // Mumbai candidate (unverified/offline until provisioned)
        self.relays.push(RelayNode {
            relay_id: "relay_in_mum_01".to_string(),
            public_address: "13.232.0.1".to_string(), // AWS Mumbai representative prefix
            control_port: 44321,
            identity_fingerprint: "UNVERIFIED_MUMBAI".to_string(),
            public_key_hex: "".to_string(),
            location: LocationMetadata {
                country: "IN".to_string(),
                region: "MH".to_string(),
                city: "Mumbai".to_string(),
                provider: "Candidate Cloud Node".to_string(),
                asn: Some(16509),
                provenance: LocationProvenance::Unverified,
            },
            protocol_version: 1,
            capabilities: vec!["ping".to_string(), "traceroute".to_string()],
            status: RelayStatusType::Offline,
            last_seen_utc: None,
            notes: "Candidate node in Mumbai, India".to_string(),
        });

        // Chennai candidate
        self.relays.push(RelayNode {
            relay_id: "relay_in_maa_01".to_string(),
            public_address: "14.139.160.1".to_string(),
            control_port: 44321,
            identity_fingerprint: "UNVERIFIED_CHENNAI".to_string(),
            public_key_hex: "".to_string(),
            location: LocationMetadata {
                country: "IN".to_string(),
                region: "TN".to_string(),
                city: "Chennai".to_string(),
                provider: "Candidate Cloud Node".to_string(),
                asn: None,
                provenance: LocationProvenance::Unverified,
            },
            protocol_version: 1,
            capabilities: vec!["ping".to_string(), "traceroute".to_string()],
            status: RelayStatusType::Offline,
            last_seen_utc: None,
            notes: "Candidate node in Chennai, India".to_string(),
        });

        // Singapore candidate
        self.relays.push(RelayNode {
            relay_id: "relay_sg_sin_01".to_string(),
            public_address: "20.205.179.1".to_string(),
            control_port: 44321,
            identity_fingerprint: "UNVERIFIED_SINGAPORE".to_string(),
            public_key_hex: "".to_string(),
            location: LocationMetadata {
                country: "SG".to_string(),
                region: "Singapore".to_string(),
                city: "Singapore".to_string(),
                provider: "Candidate Cloud Node".to_string(),
                asn: Some(8075),
                provenance: LocationProvenance::Unverified,
            },
            protocol_version: 1,
            capabilities: vec!["ping".to_string(), "traceroute".to_string()],
            status: RelayStatusType::Offline,
            last_seen_utc: None,
            notes: "Candidate node in Singapore gaming hub".to_string(),
        });
    }

    /// Save the registry to its persistence path.
    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.registry_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize registry: {}", e))?;
        fs::write(&self.registry_path, json)
            .map_err(|e| format!("Failed to write registry file: {}", e))?;
        Ok(())
    }

    /// Register or update a relay in the registry.
    pub fn register(&mut self, node: RelayNode) -> Result<(), String> {
        if let Some(existing) = self.relays.iter_mut().find(|r| r.relay_id == node.relay_id) {
            *existing = node;
        } else {
            self.relays.push(node);
        }
        self.save()
    }

    /// Look up a relay by its relay_id or public address.
    pub fn get(&self, id_or_addr: &str) -> Option<&RelayNode> {
        self.relays.iter().find(|r| r.relay_id == id_or_addr || r.public_address == id_or_addr)
    }

    /// List all known relays.
    pub fn list(&self) -> &[RelayNode] {
        &self.relays
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_seed_and_lookup() {
        let mut reg = RelayRegistry::new();
        reg.seed_defaults();

        assert_eq!(reg.list().len(), 4);
        assert!(reg.get("relay_local_01").is_some());
        assert!(reg.get("relay_in_mum_01").is_some());
        assert!(reg.get("127.0.0.1").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_register_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let mut reg = RelayRegistry::load_or_init(&path);

        let custom = RelayNode {
            relay_id: "relay_custom_01".to_string(),
            public_address: "1.2.3.4".to_string(),
            control_port: 44321,
            identity_fingerprint: "FP_CUSTOM".to_string(),
            public_key_hex: "0102".to_string(),
            location: LocationMetadata::default(),
            protocol_version: 1,
            capabilities: vec!["ping".to_string()],
            status: RelayStatusType::Online,
            last_seen_utc: None,
            notes: "Test node".to_string(),
        };

        reg.register(custom).unwrap();
        assert_eq!(reg.list().len(), 5);

        // Reload from disk
        let reloaded = RelayRegistry::load_or_init(&path);
        assert_eq!(reloaded.list().len(), 5);
        assert!(reloaded.get("relay_custom_01").is_some());
    }
}
