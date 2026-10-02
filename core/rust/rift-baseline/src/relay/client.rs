use std::io::{BufReader, BufWriter};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rift_relay::identity::IdentityManager;

use crate::relay::models::{
    ProbeProtocol, ProtocolFraming, RelayFailureMode, RelayHealth, RelayMeasurementResult,
    RelayMessage, RelayNode, MAX_FRAME_SIZE, PROTOCOL_VERSION,
};

/// An established, authenticated control session with a RiftRoute relay.
pub struct RelayClientSession {
    pub relay_id: String,
    pub session_token: String,
    stream_reader: BufReader<TcpStream>,
    stream_writer: BufWriter<TcpStream>,
    pub connect_latency_ms: f64,
    pub auth_latency_ms: f64,
}

fn next_request_id() -> String {
    format!(
        "req_{}_{}",
        Utc::now().format("%Y%m%d%H%M%S%3f"),
        hex::encode(rand::random::<[u8; 4]>())
    )
}

impl RelayClientSession {
    /// Request current health metrics and operational status from the relay.
    pub fn get_health(&mut self) -> Result<RelayHealth, RelayFailureMode> {
        let request_id = next_request_id();
        let msg = RelayMessage::GetStatus {
            session_token: self.session_token.clone(),
            request_id: request_id.clone(),
        };

        ProtocolFraming::write_frame(&mut self.stream_writer, &msg)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        let resp = ProtocolFraming::read_frame(&mut self.stream_reader, MAX_FRAME_SIZE)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        match resp {
            RelayMessage::StatusResponse { health, .. } => Ok(health),
            RelayMessage::Error { failure_mode, .. } => Err(failure_mode),
            _ => Err(RelayFailureMode::MalformedResponse),
        }
    }

    /// Request supported diagnostic capabilities from the relay.
    pub fn get_capabilities(&mut self) -> Result<Vec<String>, RelayFailureMode> {
        let request_id = next_request_id();
        let msg = RelayMessage::GetCapabilities {
            session_token: self.session_token.clone(),
            request_id,
        };

        ProtocolFraming::write_frame(&mut self.stream_writer, &msg)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        let resp = ProtocolFraming::read_frame(&mut self.stream_reader, MAX_FRAME_SIZE)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        match resp {
            RelayMessage::CapabilitiesResponse { capabilities, .. } => Ok(capabilities),
            RelayMessage::Error { failure_mode, .. } => Err(failure_mode),
            _ => Err(RelayFailureMode::MalformedResponse),
        }
    }

    /// Request the relay to execute a safe diagnostic measurement toward a destination.
    pub fn run_measurement(
        &mut self,
        destination: &str,
        protocol: ProbeProtocol,
        max_hops: u8,
        timeout_ms: u64,
    ) -> Result<RelayMeasurementResult, RelayFailureMode> {
        let request_id = next_request_id();
        let msg = RelayMessage::RunMeasurement {
            session_token: self.session_token.clone(),
            request_id: request_id.clone(),
            destination: destination.to_string(),
            protocol,
            max_hops,
            timeout_ms,
        };

        ProtocolFraming::write_frame(&mut self.stream_writer, &msg)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        let resp = ProtocolFraming::read_frame(&mut self.stream_reader, MAX_FRAME_SIZE)
            .map_err(|_| RelayFailureMode::RelayMeasurementTimeout)?;

        match resp {
            RelayMessage::MeasurementResponse { result, .. } => {
                if !result.success {
                    if let Some(ref err) = result.error_message {
                        if err.contains("Invalid measurement request") {
                            return Err(RelayFailureMode::InvalidMeasurementRequest);
                        }
                        if err.contains("zero responses") || err.contains("unreachable") {
                            return Err(RelayFailureMode::DestinationUnreachable);
                        }
                    }
                }
                Ok(result)
            }
            RelayMessage::Error { failure_mode, .. } => Err(failure_mode),
            _ => Err(RelayFailureMode::MalformedResponse),
        }
    }

    /// Gracefully terminate the control session.
    pub fn disconnect(&mut self) {
        let msg = RelayMessage::Goodbye {
            session_token: self.session_token.clone(),
        };
        let _ = ProtocolFraming::write_frame(&mut self.stream_writer, &msg);
    }
}

/// Client connector managing mutual authentication and relay connection establishment.
pub struct RelayClient;

impl RelayClient {
    /// Connect to a relay, perform mutual cryptographic authentication, and establish session.
    pub fn connect(
        relay: &RelayNode,
        client_signing_key: &SigningKey,
        client_id: &str,
        timeout: Duration,
    ) -> Result<RelayClientSession, RelayFailureMode> {
        let addr_str = format!("{}:{}", relay.public_address, relay.control_port);
        let t0 = Instant::now();

        let socket_addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|_| RelayFailureMode::RelayOffline)?
            .collect();

        if socket_addrs.is_empty() {
            return Err(RelayFailureMode::RelayOffline);
        }

        let stream = TcpStream::connect_timeout(&socket_addrs[0], timeout)
            .map_err(|_| RelayFailureMode::RelayOffline)?;

        let connect_latency = t0.elapsed().as_secs_f64() * 1000.0;

        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        let mut reader = BufReader::new(stream.try_clone().map_err(|_| RelayFailureMode::ControlChannelTimeout)?);
        let mut writer = BufWriter::new(stream);

        // 1. Send Hello
        let client_pub = hex::encode(client_signing_key.verifying_key().to_bytes());
        let hello = RelayMessage::Hello {
            client_id: client_id.to_string(),
            client_pubkey_hex: client_pub,
            protocol_version: PROTOCOL_VERSION,
        };

        ProtocolFraming::write_frame(&mut writer, &hello)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        // 2. Read AuthChallenge
        let auth_t0 = Instant::now();
        let resp = ProtocolFraming::read_frame(&mut reader, MAX_FRAME_SIZE)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        let (challenge_nonce, challenge_relay_id, relay_pubkey) = match resp {
            RelayMessage::AuthChallenge {
                challenge_nonce,
                relay_id,
                relay_pubkey_hex,
                ..
            } => (challenge_nonce, relay_id, relay_pubkey_hex),
            RelayMessage::Error { failure_mode, .. } => return Err(failure_mode),
            RelayMessage::AuthResult { success: false, .. } => return Err(RelayFailureMode::AuthenticationFailure),
            _ => return Err(RelayFailureMode::MalformedResponse),
        };

        // 3. Cryptographic Identity Verification (Step 4 & 5)
        // Verify that the relay responding matches the registered identity
        if challenge_relay_id != relay.relay_id {
            return Err(RelayFailureMode::IdentityMismatch);
        }
        if !relay_pubkey.is_empty() {
            if let Ok(fp) = IdentityManager::calculate_fingerprint(&relay_pubkey) {
                if fp != relay.identity_fingerprint {
                    return Err(RelayFailureMode::IdentityMismatch);
                }
            }
        }

        // 4. Sign challenge nonce
        let message_to_sign = format!(
            "riftroute_auth:{}:{}:{}",
            challenge_nonce, relay.relay_id, client_id
        );
        let signature_hex = IdentityManager::sign_message(client_signing_key, message_to_sign.as_bytes());

        // 5. Send AuthResponse
        let auth_resp = RelayMessage::AuthResponse {
            client_id: client_id.to_string(),
            signature_hex,
            timestamp_utc: Utc::now().to_rfc3339(),
        };

        ProtocolFraming::write_frame(&mut writer, &auth_resp)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        // 6. Read AuthResult
        let auth_result = ProtocolFraming::read_frame(&mut reader, MAX_FRAME_SIZE)
            .map_err(|_| RelayFailureMode::ControlChannelTimeout)?;

        let session_token = match auth_result {
            RelayMessage::AuthResult {
                success,
                session_token,
                ..
            } => {
                if !success || session_token.is_none() {
                    return Err(RelayFailureMode::AuthenticationFailure);
                }
                session_token.unwrap()
            }
            RelayMessage::Error { failure_mode, .. } => return Err(failure_mode),
            _ => return Err(RelayFailureMode::MalformedResponse),
        };

        let auth_latency = auth_t0.elapsed().as_secs_f64() * 1000.0;

        Ok(RelayClientSession {
            relay_id: relay.relay_id.clone(),
            session_token,
            stream_reader: reader,
            stream_writer: writer,
            connect_latency_ms: connect_latency,
            auth_latency_ms: auth_latency,
        })
    }
}
