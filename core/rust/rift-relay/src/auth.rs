use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Duration, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::identity::IdentityManager;

/// Authorized client identity entry permitted to connect and issue measurements to the relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizedClient {
    pub client_id: String,
    pub public_key_hex: String,
    pub description: String,
    pub added_at_utc: String,
}

/// An active, authenticated client session.
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub session_token: String,
    pub client_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

/// Pending authentication challenge awaiting client signature.
#[derive(Debug, Clone)]
struct PendingChallenge {
    pub nonce: String,
    pub client_id: String,
    pub expires_at: DateTime<Utc>,
}

/// Engine managing relay authorization, challenge-response handshakes, and replay protection.
pub struct AuthManager {
    relay_id: String,
    authorized_clients: HashMap<String, AuthorizedClient>,
    pending_challenges: Arc<Mutex<HashMap<String, PendingChallenge>>>,
    active_sessions: Arc<Mutex<HashMap<String, AuthenticatedSession>>>,
    challenge_ttl_seconds: i64,
    session_ttl_minutes: i64,
}

impl AuthManager {
    pub fn new(
        relay_id: String,
        authorized_clients: Vec<AuthorizedClient>,
        challenge_ttl_seconds: i64,
        session_ttl_minutes: i64,
    ) -> Self {
        let mut map = HashMap::new();
        for client in authorized_clients {
            map.insert(client.client_id.clone(), client);
        }

        Self {
            relay_id,
            authorized_clients: map,
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            challenge_ttl_seconds,
            session_ttl_minutes,
        }
    }

    /// Add an authorized client to the in-memory whitelist.
    pub fn add_authorized_client(&mut self, client: AuthorizedClient) {
        self.authorized_clients.insert(client.client_id.clone(), client);
    }

    /// Verify if a client is in the authorization list.
    pub fn is_client_authorized(&self, client_id: &str) -> bool {
        self.authorized_clients.contains_key(client_id)
    }

    /// Issue a new cryptographic challenge nonce for an authorized client.
    pub fn create_challenge(&self, client_id: &str) -> Result<String, String> {
        if !self.is_client_authorized(client_id) {
            return Err(format!("Client '{}' is not authorized on this relay", client_id));
        }

        let mut rng = rand::rng();
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let expires = Utc::now() + Duration::seconds(self.challenge_ttl_seconds);

        let mut pending = self.pending_challenges.lock().unwrap();
        // Housekeep expired challenges
        pending.retain(|_, v| v.expires_at > Utc::now());

        pending.insert(
            nonce.clone(),
            PendingChallenge {
                nonce: nonce.clone(),
                client_id: client_id.to_string(),
                expires_at: expires,
            },
        );

        Ok(nonce)
    }

    /// Verify client's challenge response signature and generate an authenticated session token.
    pub fn verify_challenge_response(
        &self,
        client_id: &str,
        signature_hex: &str,
    ) -> Result<String, String> {
        let client = self
            .authorized_clients
            .get(client_id)
            .ok_or_else(|| format!("Unauthorized client: {}", client_id))?;

        // Find and consume the pending challenge for this client (one-time use, prevents replay)
        let mut pending = self.pending_challenges.lock().unwrap();
        let challenge_key = pending
            .iter()
            .find(|(_, v)| v.client_id == client_id && v.expires_at > Utc::now())
            .map(|(k, _)| k.clone())
            .ok_or_else(|| "No active, unexpired challenge found for client".to_string())?;

        let challenge = pending.remove(&challenge_key).unwrap();

        // Structured canonical payload that client was expected to sign:
        // "riftroute_auth:<challenge_nonce>:<relay_id>:<client_id>"
        let expected_payload = format!(
            "riftroute_auth:{}:{}:{}",
            challenge.nonce, self.relay_id, client_id
        );

        let valid = IdentityManager::verify_signature(
            &client.public_key_hex,
            expected_payload.as_bytes(),
            signature_hex,
        )?;

        if !valid {
            return Err("Cryptographic signature verification failed".to_string());
        }

        // Generate session token
        let mut rng = rand::rng();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes);
        let session_token = hex::encode(token_bytes);

        let now = Utc::now();
        let expires = now + Duration::minutes(self.session_ttl_minutes);

        let mut sessions = self.active_sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires_at > now);

        sessions.insert(
            session_token.clone(),
            AuthenticatedSession {
                session_token: session_token.clone(),
                client_id: client_id.to_string(),
                created_at: now,
                expires_at: expires,
                last_active_at: now,
            },
        );

        Ok(session_token)
    }

    /// Validate that an incoming request possesses a valid, non-expired session token.
    pub fn validate_session(&self, token: &str) -> Result<String, String> {
        let mut sessions = self.active_sessions.lock().unwrap();
        let now = Utc::now();

        if let Some(session) = sessions.get_mut(token) {
            if session.expires_at < now {
                sessions.remove(token);
                return Err("Session token has expired".to_string());
            }
            session.last_active_at = now;
            Ok(session.client_id.clone())
        } else {
            Err("Invalid or unknown session token".to_string())
        }
    }

    /// Terminate an active session.
    pub fn revoke_session(&self, token: &str) {
        let mut sessions = self.active_sessions.lock().unwrap();
        sessions.remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_handshake_flow() {
        let (client_signing_key, client_id_record) = IdentityManager::generate(Some("client_alice"));
        let auth_client = AuthorizedClient {
            client_id: "client_alice".to_string(),
            public_key_hex: client_id_record.public_key_hex.clone(),
            description: "Test Client".to_string(),
            added_at_utc: Utc::now().to_rfc3339(),
        };

        let auth_mgr = AuthManager::new("relay_mumbai_01".to_string(), vec![auth_client], 30, 60);

        // 1. Unknown client rejected
        assert!(auth_mgr.create_challenge("client_bob").is_err());

        // 2. Authorized client gets challenge
        let nonce = auth_mgr.create_challenge("client_alice").unwrap();

        // 3. Client constructs expected message and signs it
        let message = format!("riftroute_auth:{}:relay_mumbai_01:client_alice", nonce);
        let signature = IdentityManager::sign_message(&client_signing_key, message.as_bytes());

        // 4. Relay verifies and issues session token
        let token = auth_mgr.verify_challenge_response("client_alice", &signature).unwrap();
        assert_eq!(token.len(), 64);

        // 5. Token is valid
        let validated_client = auth_mgr.validate_session(&token).unwrap();
        assert_eq!(validated_client, "client_alice");

        // 6. Replay attack rejection: reusing signature fails because challenge was consumed
        assert!(auth_mgr.verify_challenge_response("client_alice", &signature).is_err());
    }
}
