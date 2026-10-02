use std::io::{Read, Write};
use serde::{Deserialize, Serialize};

use crate::models::{ProbeProtocol, RelayFailureMode, RelayHealth, RelayMeasurementResult};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 65536; // 64 KB safety bound

/// Strict, structured messages exchanged between RiftRoute Client and Relay.
/// Absolutely NO arbitrary command execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum RelayMessage {
    /// Initial client handshake initiation
    Hello {
        client_id: String,
        client_pubkey_hex: String,
        protocol_version: u32,
    },
    /// Relay responds with cryptographic challenge nonce
    AuthChallenge {
        challenge_nonce: String,
        relay_id: String,
        relay_pubkey_hex: String,
        timestamp_utc: String,
    },
    /// Client signs the challenge nonce to prove private key ownership
    AuthResponse {
        client_id: String,
        signature_hex: String,
        timestamp_utc: String,
    },
    /// Relay acknowledges authentication result
    AuthResult {
        success: bool,
        session_token: Option<String>,
        error: Option<String>,
    },
    /// Client requests current relay health status
    GetStatus {
        session_token: String,
        request_id: String,
    },
    /// Relay status response
    StatusResponse {
        request_id: String,
        health: RelayHealth,
    },
    /// Client requests list of supported capabilities
    GetCapabilities {
        session_token: String,
        request_id: String,
    },
    /// Relay capabilities response
    CapabilitiesResponse {
        request_id: String,
        capabilities: Vec<String>,
    },
    /// Client requests a safe, controlled measurement toward a target
    RunMeasurement {
        session_token: String,
        request_id: String,
        destination: String,
        protocol: ProbeProtocol,
        max_hops: u8,
        timeout_ms: u64,
    },
    /// Relay measurement results response
    MeasurementResponse {
        request_id: String,
        result: RelayMeasurementResult,
    },
    /// Protocol or operational error
    Error {
        request_id: Option<String>,
        failure_mode: RelayFailureMode,
        message: String,
    },
    /// Graceful session termination
    Goodbye {
        session_token: String,
    },
}

pub struct ProtocolFraming;

impl ProtocolFraming {
    /// Read a length-delimited JSON frame from a stream with size bounds.
    pub fn read_frame<R: Read>(reader: &mut R, max_size: usize) -> Result<RelayMessage, String> {
        let mut len_bytes = [0u8; 4];
        reader
            .read_exact(&mut len_bytes)
            .map_err(|e| format!("Failed to read frame length header: {}", e))?;

        let frame_len = u32::from_be_bytes(len_bytes) as usize;
        if frame_len == 0 {
            return Err("Received invalid zero-length frame".to_string());
        }
        if frame_len > max_size {
            return Err(format!(
                "Frame length {} exceeds maximum allowed size {}",
                frame_len, max_size
            ));
        }

        let mut payload = vec![0u8; frame_len];
        reader
            .read_exact(&mut payload)
            .map_err(|e| format!("Failed to read frame payload: {}", e))?;

        serde_json::from_slice(&payload)
            .map_err(|e| format!("Failed to deserialize RelayMessage JSON: {}", e))
    }

    /// Write a length-delimited JSON frame to a stream.
    pub fn write_frame<W: Write>(writer: &mut W, msg: &RelayMessage) -> Result<(), String> {
        let payload = serde_json::to_vec(msg)
            .map_err(|e| format!("Failed to serialize RelayMessage: {}", e))?;

        if payload.len() > MAX_FRAME_SIZE {
            return Err(format!(
                "Serialized frame length {} exceeds maximum size {}",
                payload.len(),
                MAX_FRAME_SIZE
            ));
        }

        let len_bytes = (payload.len() as u32).to_be_bytes();
        writer
            .write_all(&len_bytes)
            .map_err(|e| format!("Failed to write frame length header: {}", e))?;
        writer
            .write_all(&payload)
            .map_err(|e| format!("Failed to write frame payload: {}", e))?;
        writer
            .flush()
            .map_err(|e| format!("Failed to flush stream: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_framing_roundtrip() {
        let msg = RelayMessage::Hello {
            client_id: "client_alice".to_string(),
            client_pubkey_hex: "01020304".to_string(),
            protocol_version: 1,
        };

        let mut buffer = Vec::new();
        ProtocolFraming::write_frame(&mut buffer, &msg).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = ProtocolFraming::read_frame(&mut cursor, MAX_FRAME_SIZE).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_oversized_frame_rejection() {
        let mut buffer = Vec::new();
        // Artificially large header (70 KB)
        buffer.extend_from_slice(&(70000u32).to_be_bytes());
        buffer.extend(vec![0u8; 100]);

        let mut cursor = Cursor::new(buffer);
        let result = ProtocolFraming::read_frame(&mut cursor, MAX_FRAME_SIZE);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum allowed size"));
    }
}
