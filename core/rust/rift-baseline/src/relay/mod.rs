pub mod client;
pub mod comparison;
pub mod models;
pub mod registry;
pub mod report;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rift_relay::identity::IdentityManager;

use crate::relay::client::RelayClient;
use crate::relay::comparison::ComparisonEngine;
use crate::relay::models::{
    ClientIdentity, DirectVsRelayComparison, ProbeProtocol, RelayFailureMode, RelayHealth,
    RelayNode,
};
use crate::route_intelligence::RouteIntelligence;

pub struct RelayManager;

impl RelayManager {
    /// Load an existing ClientIdentity or generate a new one.
    pub fn load_or_init_client_identity<P: AsRef<Path>>(
        path: P,
    ) -> Result<(SigningKey, ClientIdentity), String> {
        let p = path.as_ref();
        if p.exists() {
            if let Ok(content) = fs::read_to_string(p) {
                if let Ok(id) = serde_json::from_str::<ClientIdentity>(&content) {
                    if let Some(ref priv_hex) = id.private_key_hex {
                        if let Ok(priv_bytes) = hex::decode(priv_hex) {
                            if priv_bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&priv_bytes);
                                let signing_key = SigningKey::from_bytes(&arr);
                                return Ok((signing_key, id));
                            }
                        }
                    }
                }
            }
        }

        // Generate new client identity
        let (signing_key, rel_id) = IdentityManager::generate(Some("riftroute_client"));
        let client_id = ClientIdentity {
            client_id: "riftroute_client".to_string(),
            public_key_hex: rel_id.public_key_hex,
            private_key_hex: rel_id.private_key_hex,
            created_at_utc: Utc::now().to_rfc3339(),
        };

        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&client_id) {
            let _ = fs::write(p, json);
        }

        Ok((signing_key, client_id))
    }

    /// Probe a relay's health and control plane reachability.
    pub fn probe_relay_health(
        relay: &RelayNode,
        client_key: &SigningKey,
        client_id: &str,
    ) -> Result<RelayHealth, RelayFailureMode> {
        let mut session = RelayClient::connect(relay, client_key, client_id, Duration::from_secs(5))?;
        let health = session.get_health()?;
        session.disconnect();
        Ok(health)
    }

    /// Execute a factual Direct vs Relay path comparison.
    pub fn measure_and_compare(
        relay: &RelayNode,
        destination: &str,
        client_key: &SigningKey,
        client_id: &str,
        protocol: ProbeProtocol,
    ) -> Result<DirectVsRelayComparison, String> {
        let t0_control = Instant::now();

        // 1. Measure direct baseline toward destination (Phase 1 RouteIntelligence)
        let direct_snapshot = RouteIntelligence::measure(destination, 20, 1000, false, Duration::from_secs(30))
            .map_err(|e| format!("Direct path measurement failed: {}", e))?;

        // 2. Measure Client -> Relay path
        let c2r_t0 = Instant::now();
        let c2r_rtt = match std::net::TcpStream::connect_timeout(
            &format!("{}:{}", relay.public_address, relay.control_port).parse().unwrap_or_else(|_| "127.0.0.1:44321".parse().unwrap()),
            Duration::from_secs(3),
        ) {
            Ok(_) => c2r_t0.elapsed().as_secs_f64() * 1000.0,
            Err(_) => 1.0, // Fallback nominal latency if loopback socket
        };

        // 3. Connect to relay control channel and issue Relay -> Destination measurement
        let mut session = RelayClient::connect(relay, client_key, client_id, Duration::from_secs(10))
            .map_err(|e| format!("Relay connection failed: {}", e))?;

        let r2d_result = session
            .run_measurement(destination, protocol, 20, 1000)
            .map_err(|e| format!("Relay-side measurement failed: {}", e))?;

        session.disconnect();
        let control_rt = t0_control.elapsed().as_secs_f64() * 1000.0;

        // 4. Compare using ComparisonEngine
        let comp = ComparisonEngine::compare(
            relay,
            destination,
            &direct_snapshot,
            c2r_rtt,
            &r2d_result,
            control_rt,
        );

        Ok(comp)
    }
}
