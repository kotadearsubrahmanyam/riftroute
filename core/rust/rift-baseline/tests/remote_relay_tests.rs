use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use rift_baseline::relay::campaign::CampaignEngine;
use rift_baseline::relay::client::RelayClient;
use rift_baseline::relay::diversity::DiversityEngine;
use rift_baseline::relay::models::{
    CampaignSampleRecord, ComparisonClassification, DetailedPathStatistics,
    LocationMetadata, LocationProvenance, MeasurementCampaign, PathDiversityType,
    RelayFailureMode, RelayNode, RelayStatusType,
};
use rift_baseline::relay::registry::RelayRegistry;
use rift_relay::auth::{AuthManager, AuthorizedClient};
use rift_relay::config::RelayConfig;
use rift_relay::identity::{IdentityManager, RelayIdentity};
use rift_relay::server::RelayServer;

fn find_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn start_server(
    relay_id_name: &str,
    allow_private: bool,
    max_rate: usize,
) -> (
    u16,
    RelayIdentity,
    ed25519_dalek::SigningKey,
    String,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let port = find_free_port();
    let relay_id = format!("{}_{}", relay_id_name, port);
    let (_relay_sk, relay_identity) = IdentityManager::generate(Some(&relay_id));

    let client_sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let client_pubkey_hex = hex::encode(client_sk.verifying_key().to_bytes());
    let client_id = "test_authorized_client".to_string();

    let authorized_client = AuthorizedClient {
        client_id: client_id.clone(),
        public_key_hex: client_pubkey_hex,
        description: "Test Client".to_string(),
        added_at_utc: chrono::Utc::now().to_rfc3339(),
    };

    let mut cfg = RelayConfig::default();
    cfg.relay_id = relay_id.clone();
    cfg.listen_address = "127.0.0.1".to_string();
    cfg.control_port = port;
    cfg.rate_limit_per_minute = max_rate;
    cfg.authorized_clients = vec![authorized_client];
    cfg.allow_private_targets = allow_private;

    let auth_mgr = AuthManager::new(
        relay_id.clone(),
        cfg.authorized_clients.clone(),
        30,
        60,
    );

    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let pubkey_hex = relay_identity.public_key_hex.clone();

    let handle = std::thread::spawn(move || {
        let server = RelayServer::new(cfg, auth_mgr, pubkey_hex, Some(stop_signal_clone));
        let _ = server.run();
    });

    std::thread::sleep(Duration::from_millis(150));

    (port, relay_identity, client_sk, client_id, stop_signal, handle)
}

fn make_node(port: u16, identity: &RelayIdentity) -> RelayNode {
    RelayNode {
        relay_id: identity.relay_id.clone(),
        public_address: "127.0.0.1".to_string(),
        control_port: port,
        identity_fingerprint: identity.fingerprint.clone(),
        public_key_hex: identity.public_key_hex.clone(),
        location: LocationMetadata {
            country: "IN".to_string(),
            region: "AP".to_string(),
            city: "Vijayawada".to_string(),
            provider: "Test Relay".to_string(),
            asn: None,
            provenance: LocationProvenance::OperatorDeclared,
        },
        protocol_version: 1,
        capabilities: vec!["icmp".to_string(), "tcp".to_string()],
        status: RelayStatusType::Online,
        last_seen_utc: Some(chrono::Utc::now().to_rfc3339()),
        notes: "".to_string(),
    }
}

// -----------------------------------------------------------------------------
// 1. CONFIGURATION TESTS (Step 39)
// -----------------------------------------------------------------------------

#[test]
fn test_remote_relay_configuration_valid_and_missing() {
    let tmp = tempdir().unwrap();
    let reg_path = tmp.path().join("registry.json");
    let mut reg = RelayRegistry::load_or_init(&reg_path);

    assert!(reg.get("relay_local_01").is_some());
    assert!(reg.get("non_existent_relay").is_none());

    let custom_node = RelayNode {
        relay_id: "relay_test_custom".to_string(),
        public_address: "1.2.3.4".to_string(),
        control_port: 44321,
        identity_fingerprint: "CUSTOM_FP".to_string(),
        public_key_hex: "00".repeat(32),
        location: LocationMetadata::default(),
        protocol_version: 1,
        capabilities: vec!["icmp".to_string()],
        status: RelayStatusType::Online,
        last_seen_utc: None,
        notes: "".to_string(),
    };
    let _ = reg.register(custom_node.clone());
    assert!(reg.get("relay_test_custom").is_some());
}

// -----------------------------------------------------------------------------
// 2. REMOTE AUTH TESTS (Step 39)
// -----------------------------------------------------------------------------

#[test]
fn test_remote_auth_valid_flow() {
    let (port, identity, client_sk, client_id, stop_signal, handle) =
        start_server("auth_valid", false, 100);
    let node = make_node(port, &identity);

    let session = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5));
    assert!(session.is_ok(), "Valid client auth should succeed");

    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_remote_auth_unknown_client_rejected() {
    let (port, identity, _client_sk, _client_id, stop_signal, handle) =
        start_server("auth_unknown", false, 100);
    let node = make_node(port, &identity);
    let rogue_sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());

    let res = RelayClient::connect(&node, &rogue_sk, "unknown_client_id", Duration::from_secs(5));
    assert_eq!(res.err(), Some(RelayFailureMode::AuthenticationFailure));

    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_remote_auth_fingerprint_mismatch_rejected() {
    let (port, identity, client_sk, client_id, stop_signal, handle) =
        start_server("auth_mitm", false, 100);
    let mut node = make_node(port, &identity);
    node.identity_fingerprint = "TAMPERED_FINGERPRINT".to_string();

    let res = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5));
    assert_eq!(res.err(), Some(RelayFailureMode::IdentityMismatch));

    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

// -----------------------------------------------------------------------------
// 3. REMOTE HEALTH TESTS (Step 39)
// -----------------------------------------------------------------------------

#[test]
fn test_remote_health_probe_success() {
    let (port, identity, client_sk, client_id, stop_signal, handle) =
        start_server("health_test", false, 100);
    let node = make_node(port, &identity);

    let mut session = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5)).unwrap();
    let health = session.get_health().unwrap();
    assert_eq!(health.relay_id, identity.relay_id);
    assert!(health.is_alive);
    assert_eq!(health.status, RelayStatusType::Online);

    session.disconnect();
    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_remote_health_offline_detection() {
    let dead_port = find_free_port();
    let (_sk, id) = IdentityManager::generate(Some("offline_relay"));
    let node = make_node(dead_port, &id);
    let client_sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());

    let res = RelayClient::connect(&node, &client_sk, "client", Duration::from_millis(300));
    assert_eq!(res.err(), Some(RelayFailureMode::RelayOffline));
}

// -----------------------------------------------------------------------------
// 4. PATH DIVERSITY TESTS (Step 19 & 39)
// -----------------------------------------------------------------------------

#[test]
fn test_path_diversity_classification_scenarios() {
    // 1. Same observed path
    let same = DiversityEngine::evaluate_diversity("FINGERPRINT_A", 6, "LEG1_FP", "FINGERPRINT_A", 6);
    assert_eq!(same.diversity_type, PathDiversityType::SameObservedPath);

    // 2. Structural route variation (different fingerprints, different hops)
    let struct_var = DiversityEngine::evaluate_diversity("FINGERPRINT_A", 6, "LEG1_FP", "FINGERPRINT_B", 4);
    assert_eq!(struct_var.diversity_type, PathDiversityType::StructuralRouteVariation);

    // 3. Insufficient evidence (empty fingerprints)
    let insuff = DiversityEngine::evaluate_diversity("", 0, "LEG1", "FINGERPRINT_B", 4);
    assert_eq!(insuff.diversity_type, PathDiversityType::InsufficientEvidence);
}

// -----------------------------------------------------------------------------
// 5. STATISTICS & VARIABILITY GUARD TESTS (Step 23, 26, 27)
// -----------------------------------------------------------------------------

#[test]
fn test_detailed_statistics_and_confidence_intervals() {
    let samples = vec![20.0, 21.0, 22.0, 21.5, 20.5, 23.0, 21.0, 22.5, 21.0, 20.0];
    let stats = CampaignEngine::compute_statistics(&samples);

    assert_eq!(stats.sample_count, 10);
    assert_eq!(stats.min_ms, 20.0);
    assert_eq!(stats.max_ms, 23.0);
    assert!(stats.mean_ms >= 21.0 && stats.mean_ms <= 22.0);
    assert!(stats.std_dev_ms > 0.0);
    assert!(stats.jitter_ms > 0.0);

    let ci = stats.confidence_interval_95.expect("10 samples must generate a 95% CI");
    assert_eq!(ci.confidence_level_pct, 95.0);
    assert!(ci.lower_bound_ms < stats.mean_ms);
    assert!(ci.upper_bound_ms > stats.mean_ms);
}

#[test]
fn test_variability_guard_classifications() {
    // 1. Within measurement variability (delta 1.5 ms inside 2.0 ms guard)
    let c1 = CampaignEngine::classify_comparison(50.0, 51.5, 1.0, 1.2, 0.8, 10);
    assert_eq!(c1, ComparisonClassification::WithinMeasurementVariability);

    // 2. Direct lower observed measurement (composed relay is 15 ms higher)
    let c2 = CampaignEngine::classify_comparison(30.0, 45.0, 1.5, 1.5, 1.0, 10);
    assert_eq!(c2, ComparisonClassification::DirectLowerObservedMeasurement);

    // 3. Relay lower observed estimate (composed relay is 20 ms lower)
    let c3 = CampaignEngine::classify_comparison(60.0, 40.0, 2.0, 2.0, 1.5, 10);
    assert_eq!(c3, ComparisonClassification::RelayLowerObservedEstimate);

    // 4. Insufficient evidence (< 3 samples)
    let c4 = CampaignEngine::classify_comparison(60.0, 40.0, 2.0, 2.0, 1.5, 2);
    assert_eq!(c4, ComparisonClassification::InsufficientEvidence);
}

// -----------------------------------------------------------------------------
// 6. PERSISTENCE TESTS (Step 39)
// -----------------------------------------------------------------------------

#[test]
fn test_campaign_persistence_roundtrip() {
    let tmp = tempdir().unwrap();
    let file_path = tmp.path().join("campaign_test.json");

    let stats = DetailedPathStatistics {
        sample_count: 5,
        min_ms: 10.0,
        max_ms: 20.0,
        mean_ms: 15.0,
        median_ms: 15.0,
        p95_ms: 19.0,
        p99_ms: 19.9,
        std_dev_ms: 3.5,
        jitter_ms: 2.0,
        confidence_interval_95: None,
    };

    let sample_rec = CampaignSampleRecord {
        cycle_index: 1,
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        direct_rtt_ms: 15.0,
        client_to_relay_rtt_ms: 2.0,
        relay_to_destination_rtt_ms: 14.0,
        composed_estimate_ms: 16.0,
        direct_fingerprint: "FP_DIRECT".to_string(),
        relay_fingerprint: "FP_RELAY".to_string(),
        success: true,
        error_message: None,
    };

    let campaign = MeasurementCampaign {
        campaign_id: "campaign_test_01".to_string(),
        relay_id: "relay_test".to_string(),
        destination: "1.1.1.1".to_string(),
        sample_count: 1,
        availability_pct: 100.0,
        auth_success_rate_pct: 100.0,
        measurement_success_rate_pct: 100.0,
        direct_stats: stats.clone(),
        client_relay_stats: stats.clone(),
        relay_dest_stats: stats.clone(),
        composed_stats: stats.clone(),
        delta_median_ms: 1.0,
        delta_p95_ms: 1.0,
        path_diversity: DiversityEngine::evaluate_diversity("FP_DIRECT", 5, "FP_LEG1", "FP_RELAY", 2),
        classification: ComparisonClassification::WithinMeasurementVariability,
        dominant_direct_fingerprint: "FP_DIRECT".to_string(),
        dominant_relay_fingerprint: "FP_RELAY".to_string(),
        route_transition_rate_pct: 0.0,
        raw_samples: vec![sample_rec],
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        scientific_disclaimer: "Disclaimer test".to_string(),
    };

    // Save
    assert!(CampaignEngine::save_campaign(&campaign, &file_path).is_ok());

    // Load
    let loaded = CampaignEngine::load_campaign(&file_path).expect("Should load campaign JSON");
    assert_eq!(loaded.campaign_id, campaign.campaign_id);
    assert_eq!(loaded.sample_count, 1);
    assert_eq!(loaded.raw_samples.len(), 1);

    // Missing artifact error
    let missing = CampaignEngine::load_campaign(tmp.path().join("does_not_exist.json"));
    assert!(missing.is_err());
}
