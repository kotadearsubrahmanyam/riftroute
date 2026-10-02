use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rift_baseline::relay::client::RelayClient;
use rift_baseline::relay::models::{
    LocationMetadata, LocationProvenance, ProbeProtocol, RelayFailureMode, RelayNode,
    RelayStatusType,
};
use rift_relay::auth::{AuthManager, AuthorizedClient};
use rift_relay::config::RelayConfig;
use rift_relay::identity::{IdentityManager, RelayIdentity};
use rift_relay::server::RelayServer;

fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn start_test_server(
    allow_private: bool,
) -> (
    u16,
    RelayIdentity,
    ed25519_dalek::SigningKey,
    String,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let port = find_free_port();
    let relay_id = format!("relay_test_{}", port);
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
            provider: "Localhost Test".to_string(),
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

#[test]
fn test_e2e_successful_handshake_health_capabilities() {
    let (port, identity, client_sk, client_id, stop_signal, handle) = start_test_server(false);
    let node = make_node(port, &identity);

    let mut session = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5))
        .expect("Handshake should succeed");

    assert_eq!(session.relay_id, identity.relay_id);
    assert!(!session.session_token.is_empty());
    assert!(session.connect_latency_ms >= 0.0);
    assert!(session.auth_latency_ms >= 0.0);

    // Test get_health
    let health = session.get_health().expect("Health check should succeed");
    assert_eq!(health.relay_id, identity.relay_id);
    assert_eq!(health.status, RelayStatusType::Online);
    assert_eq!(health.active_measurement_jobs, 0);

    // Test get_capabilities
    let caps = session.get_capabilities().expect("Capabilities query should succeed");
    assert!(caps.contains(&"icmp".to_string()));
    assert!(caps.contains(&"tcp".to_string()));

    // Graceful disconnect
    session.disconnect();

    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_failure_mode_relay_offline() {
    let port = find_free_port(); // port is not listening
    let (_sk, identity) = IdentityManager::generate(Some("relay_offline_test"));
    let node = make_node(port, &identity);
    let client_sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());

    let res = RelayClient::connect(&node, &client_sk, "client_01", Duration::from_millis(500));
    assert_eq!(res.err(), Some(RelayFailureMode::RelayOffline));
}

#[test]
fn test_failure_mode_identity_mismatch() {
    let (port, identity, client_sk, client_id, stop_signal, handle) = start_test_server(false);
    let mut node = make_node(port, &identity);
    // Tamper with expected fingerprint
    node.identity_fingerprint = "0000000000000000".to_string();

    let res = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5));
    assert_eq!(res.err(), Some(RelayFailureMode::IdentityMismatch));

    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_failure_mode_authentication_failure() {
    let (port, identity, _client_sk, _client_id, stop_signal, handle) = start_test_server(false);
    let node = make_node(port, &identity);
    // Connect with un-whitelisted client
    let rogue_sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());

    let res = RelayClient::connect(&node, &rogue_sk, "rogue_client", Duration::from_secs(5));
    assert_eq!(res.err(), Some(RelayFailureMode::AuthenticationFailure));

    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_failure_mode_invalid_measurement_request() {
    let (port, identity, client_sk, client_id, stop_signal, handle) = start_test_server(false);
    let node = make_node(port, &identity);

    let mut session = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5))
        .expect("Handshake should succeed");

    // Command injection target should be rejected
    let res = session.run_measurement("8.8.8.8; ls", ProbeProtocol::Icmp, 10, 1000);
    assert_eq!(res.err(), Some(RelayFailureMode::InvalidMeasurementRequest));

    // Private IP should be rejected since allow_private is false
    let res_private = session.run_measurement("127.0.0.1", ProbeProtocol::Icmp, 10, 1000);
    assert_eq!(res_private.err(), Some(RelayFailureMode::InvalidMeasurementRequest));

    session.disconnect();
    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_e2e_measurement_allowed_private() {
    let (port, identity, client_sk, client_id, stop_signal, handle) = start_test_server(true);
    let node = make_node(port, &identity);

    let mut session = RelayClient::connect(&node, &client_sk, &client_id, Duration::from_secs(5))
        .expect("Handshake should succeed");

    // Probing 127.0.0.1 is allowed in private mode
    let res = session.run_measurement("127.0.0.1", ProbeProtocol::Icmp, 2, 2000);
    assert!(res.is_ok(), "Measurement on 127.0.0.1 with allow_private should succeed: {:?}", res.err());
    let measurement = res.unwrap();
    assert_eq!(measurement.destination, "127.0.0.1");
    assert_eq!(measurement.protocol, ProbeProtocol::Icmp);

    session.disconnect();
    stop_signal.store(true, Ordering::Relaxed);
    let _ = handle.join();
}
