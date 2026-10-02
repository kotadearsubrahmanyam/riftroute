use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::auth::AuthManager;
use crate::config::RelayConfig;
use crate::health::HealthTracker;
use crate::measurement::RelayMeasurementEngine;
use crate::models::{RelayFailureMode, RelayHealth};
use crate::protocol::{ProtocolFraming, RelayMessage, MAX_FRAME_SIZE, PROTOCOL_VERSION};

/// In-memory IP rate limiter to protect against request flooding.
struct RateLimiter {
    max_per_minute: usize,
    history: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    fn new(max_per_minute: usize) -> Self {
        Self {
            max_per_minute,
            history: HashMap::new(),
        }
    }

    fn check_and_record(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        let one_minute_ago = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);

        let timestamps = self.history.entry(ip.to_string()).or_default();
        timestamps.retain(|&t| t > one_minute_ago);

        if timestamps.len() >= self.max_per_minute {
            false
        } else {
            timestamps.push(now);
            true
        }
    }
}

/// The multi-threaded TCP Relay Daemon.
pub struct RelayServer {
    config: RelayConfig,
    identity_pubkey_hex: String,
    auth_mgr: Arc<AuthManager>,
    health: Arc<HealthTracker>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    stop_signal: Arc<AtomicBool>,
}

impl RelayServer {
    pub fn new(
        config: RelayConfig,
        auth_mgr: AuthManager,
        identity_pubkey_hex: String,
        stop_signal: Option<Arc<AtomicBool>>,
    ) -> Self {
        let health = Arc::new(HealthTracker::new(config.relay_id.clone()));
        let rl = Arc::new(Mutex::new(RateLimiter::new(config.rate_limit_per_minute)));
        let stop = stop_signal.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

        Self {
            config,
            identity_pubkey_hex,
            auth_mgr: Arc::new(auth_mgr),
            health,
            rate_limiter: rl,
            stop_signal: stop,
        }
    }

    pub fn health_snapshot(&self) -> RelayHealth {
        self.health.get_health_snapshot()
    }

    /// Run the server loop. Blocks until stop_signal is triggered or an unrecoverable error occurs.
    pub fn run(&self) -> Result<(), String> {
        let bind_addr = format!("{}:{}", self.config.listen_address, self.config.control_port);
        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| format!("Failed to bind relay server to {}: {}", bind_addr, e))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set nonblocking mode: {}", e))?;

        println!(
            "[RELAY SERVER] Listening on {} (relay_id: {}, protocol_version: {})",
            bind_addr, self.config.relay_id, PROTOCOL_VERSION
        );

        while !self.stop_signal.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, peer_addr)) => {
                    let config = self.config.clone();
                    let identity_pubkey_hex = self.identity_pubkey_hex.clone();
                    let auth_mgr = Arc::clone(&self.auth_mgr);
                    let health = Arc::clone(&self.health);
                    let rl = Arc::clone(&self.rate_limiter);

                    thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, peer_addr, config, identity_pubkey_hex, auth_mgr, health, rl) {
                            eprintln!("[CONN ERROR] {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("[ACCEPT ERROR] {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }

        println!("[RELAY SERVER] Gracefully shutting down...");
        Ok(())
    }

    fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        config: RelayConfig,
        identity_pubkey_hex: String,
        auth_mgr: Arc<AuthManager>,
        health: Arc<HealthTracker>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
    ) -> Result<(), String> {
        stream
            .set_nonblocking(false)
            .map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;

        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut writer = BufWriter::new(stream);

        let peer_ip = peer_addr.ip().to_string();

        loop {
            let msg = match ProtocolFraming::read_frame(&mut reader, MAX_FRAME_SIZE) {
                Ok(m) => m,
                Err(e) => {
                    if e.contains("Zero-length") || e.contains("header") {
                        break; // Normal disconnection
                    }
                    // Malformed frame or oversized
                    let err_msg = RelayMessage::Error {
                        request_id: None,
                        failure_mode: RelayFailureMode::MalformedResponse,
                        message: format!("Protocol error: {}", e),
                    };
                    let _ = ProtocolFraming::write_frame(&mut writer, &err_msg);
                    return Err(e);
                }
            };

            // Rate limiter check
            {
                let mut rl = rate_limiter.lock().unwrap();
                if !rl.check_and_record(&peer_ip) {
                    let err_msg = RelayMessage::Error {
                        request_id: None,
                        failure_mode: RelayFailureMode::RateLimitExceeded,
                        message: "Rate limit exceeded (too many requests per minute)".to_string(),
                    };
                    ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                    return Err("Rate limit exceeded".to_string());
                }
            }

            match msg {
                RelayMessage::Hello {
                    client_id,
                    protocol_version,
                    ..
                } => {
                    if protocol_version != PROTOCOL_VERSION {
                        let err_msg = RelayMessage::Error {
                            request_id: None,
                            failure_mode: RelayFailureMode::ProtocolVersionMismatch,
                            message: format!(
                                "Supported protocol version is {}, client requested {}",
                                PROTOCOL_VERSION, protocol_version
                            ),
                        };
                        ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                        break;
                    }

                    match auth_mgr.create_challenge(&client_id) {
                        Ok(nonce) => {
                            let challenge = RelayMessage::AuthChallenge {
                                challenge_nonce: nonce,
                                relay_id: config.relay_id.clone(),
                                relay_pubkey_hex: identity_pubkey_hex.clone(),
                                timestamp_utc: chrono::Utc::now().to_rfc3339(),
                            };
                            ProtocolFraming::write_frame(&mut writer, &challenge)?;
                        }
                        Err(err) => {
                            let err_msg = RelayMessage::Error {
                                request_id: None,
                                failure_mode: RelayFailureMode::AuthenticationFailure,
                                message: err,
                            };
                            ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                            break;
                        }
                    }
                }

                RelayMessage::AuthResponse {
                    client_id,
                    signature_hex,
                    ..
                } => {
                    match auth_mgr.verify_challenge_response(&client_id, &signature_hex) {
                        Ok(token) => {
                            let res = RelayMessage::AuthResult {
                                success: true,
                                session_token: Some(token),
                                error: None,
                            };
                            ProtocolFraming::write_frame(&mut writer, &res)?;
                        }
                        Err(err) => {
                            let res = RelayMessage::Error {
                                request_id: None,
                                failure_mode: RelayFailureMode::AuthenticationFailure,
                                message: err,
                            };
                            ProtocolFraming::write_frame(&mut writer, &res)?;
                            break;
                        }
                    }
                }

                RelayMessage::GetStatus {
                    session_token,
                    request_id,
                } => {
                    if let Err(err) = auth_mgr.validate_session(&session_token) {
                        let err_msg = RelayMessage::Error {
                            request_id: Some(request_id),
                            failure_mode: RelayFailureMode::AuthenticationFailure,
                            message: err,
                        };
                        ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                        break;
                    }

                    let h = health.get_health_snapshot();
                    let resp = RelayMessage::StatusResponse {
                        request_id,
                        health: h,
                    };
                    ProtocolFraming::write_frame(&mut writer, &resp)?;
                }

                RelayMessage::GetCapabilities {
                    session_token,
                    request_id,
                } => {
                    if let Err(err) = auth_mgr.validate_session(&session_token) {
                        let err_msg = RelayMessage::Error {
                            request_id: Some(request_id),
                            failure_mode: RelayFailureMode::AuthenticationFailure,
                            message: err,
                        };
                        ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                        break;
                    }

                    let resp = RelayMessage::CapabilitiesResponse {
                        request_id,
                        capabilities: vec![
                            "icmp".to_string(),
                            "tcp".to_string(),
                            "ping".to_string(),
                            "tcp_probe".to_string(),
                        ],
                    };
                    ProtocolFraming::write_frame(&mut writer, &resp)?;
                }

                RelayMessage::RunMeasurement {
                    session_token,
                    request_id,
                    destination,
                    protocol,
                    max_hops,
                    timeout_ms,
                } => {
                    if let Err(err) = auth_mgr.validate_session(&session_token) {
                        let err_msg = RelayMessage::Error {
                            request_id: Some(request_id),
                            failure_mode: RelayFailureMode::AuthenticationFailure,
                            message: err,
                        };
                        ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                        break;
                    }

                    // Check concurrent job limits
                    if health.active_jobs_count() >= config.max_concurrent_jobs {
                        let err_msg = RelayMessage::Error {
                            request_id: Some(request_id),
                            failure_mode: RelayFailureMode::RateLimitExceeded,
                            message: format!(
                                "Relay is currently executing maximum concurrent jobs ({})",
                                config.max_concurrent_jobs
                            ),
                        };
                        ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                        continue;
                    }

                    health.start_job();
                    let res = RelayMeasurementEngine::execute_measurement(
                        &config.relay_id,
                        &request_id,
                        &destination,
                        protocol,
                        max_hops,
                        timeout_ms,
                        config.allow_private_targets,
                    );
                    health.finish_job(res.success);

                    let resp = RelayMessage::MeasurementResponse {
                        request_id,
                        result: res,
                    };
                    ProtocolFraming::write_frame(&mut writer, &resp)?;
                }

                RelayMessage::Goodbye { session_token } => {
                    auth_mgr.revoke_session(&session_token);
                    break;
                }

                _ => {
                    // Unhandled or out-of-order message
                    let err_msg = RelayMessage::Error {
                        request_id: None,
                        failure_mode: RelayFailureMode::MalformedResponse,
                        message: "Unexpected message type for current state".to_string(),
                    };
                    ProtocolFraming::write_frame(&mut writer, &err_msg)?;
                    break;
                }
            }
        }

        Ok(())
    }
}
