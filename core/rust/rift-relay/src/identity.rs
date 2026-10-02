use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stored cryptographic identity record for a RiftRoute Relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayIdentity {
    pub relay_id: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub created_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex: Option<String>,
}

pub struct IdentityManager;

impl IdentityManager {
    /// Generate a brand new cryptographic Ed25519 identity keypair.
    pub fn generate(relay_id: Option<&str>) -> (SigningKey, RelayIdentity) {
        let mut csprng = rand::rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let pub_bytes = verifying_key.to_bytes();
        let pub_hex = hex::encode(pub_bytes);

        // Fingerprint is the first 16 uppercase hex chars of SHA-256 of public key
        let mut hasher = Sha256::new();
        hasher.update(&pub_bytes);
        let hash_bytes = hasher.finalize();
        let full_fingerprint = hex::encode_upper(hash_bytes);
        let short_fingerprint = full_fingerprint[..16].to_string();

        let id = relay_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("relay_{}", &short_fingerprint.to_lowercase()));

        let identity = RelayIdentity {
            relay_id: id,
            public_key_hex: pub_hex,
            fingerprint: short_fingerprint,
            created_at_utc: Utc::now().to_rfc3339(),
            private_key_hex: Some(hex::encode(signing_key.to_bytes())),
        };

        (signing_key, identity)
    }

    /// Save identity to a JSON file. Private key is included.
    pub fn save_identity<P: AsRef<Path>>(
        identity: &RelayIdentity,
        path: P,
    ) -> Result<PathBuf, String> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        let json = serde_json::to_string_pretty(identity)
            .map_err(|e| format!("Failed to serialize identity: {}", e))?;

        fs::write(p, json).map_err(|e| format!("Failed to write identity file: {}", e))?;
        Ok(p.to_path_buf())
    }

    /// Load identity from a JSON file and reconstruct the SigningKey.
    pub fn load_identity<P: AsRef<Path>>(path: P) -> Result<(SigningKey, RelayIdentity), String> {
        let p = path.as_ref();
        let content = fs::read_to_string(p)
            .map_err(|e| format!("Failed to read identity from {}: {}", p.display(), e))?;

        let identity: RelayIdentity = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse identity JSON: {}", e))?;

        let priv_hex = identity
            .private_key_hex
            .as_ref()
            .ok_or_else(|| "Identity file does not contain a private key".to_string())?;

        let priv_bytes = hex::decode(priv_hex)
            .map_err(|e| format!("Invalid hex private key: {}", e))?;

        if priv_bytes.len() != 32 {
            return Err(format!(
                "Invalid private key length: expected 32 bytes, got {}",
                priv_bytes.len()
            ));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&priv_bytes);
        let signing_key = SigningKey::from_bytes(&key_arr);

        Ok((signing_key, identity))
    }

    /// Sign an arbitrary byte slice using a SigningKey.
    pub fn sign_message(key: &SigningKey, message: &[u8]) -> String {
        let signature = key.sign(message);
        hex::encode(signature.to_bytes())
    }

    /// Verify an Ed25519 signature against a public key hex string.
    pub fn verify_signature(
        pubkey_hex: &str,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool, String> {
        let pub_bytes = hex::decode(pubkey_hex)
            .map_err(|e| format!("Invalid public key hex: {}", e))?;

        if pub_bytes.len() != 32 {
            return Err(format!(
                "Invalid public key length: expected 32 bytes, got {}",
                pub_bytes.len()
            ));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pub_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| format!("Invalid Ed25519 verifying key: {}", e))?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?;

        if sig_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: expected 64 bytes, got {}",
                sig_bytes.len()
            ));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    /// Calculate fingerprint from public key hex.
    pub fn calculate_fingerprint(pubkey_hex: &str) -> Result<String, String> {
        let pub_bytes = hex::decode(pubkey_hex)
            .map_err(|e| format!("Invalid public key hex: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&pub_bytes);
        let hash = hex::encode_upper(hasher.finalize());
        Ok(hash[..16].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_signing() {
        let (signing_key, identity) = IdentityManager::generate(Some("relay_test_01"));
        assert_eq!(identity.relay_id, "relay_test_01");
        assert_eq!(identity.public_key_hex.len(), 64);
        assert_eq!(identity.fingerprint.len(), 16);

        let message = b"riftroute_auth_challenge_nonce_12345";
        let sig_hex = IdentityManager::sign_message(&signing_key, message);
        assert_eq!(sig_hex.len(), 128); // 64 bytes * 2

        let verified = IdentityManager::verify_signature(&identity.public_key_hex, message, &sig_hex).unwrap();
        assert!(verified);

        // Verification fails if message is tampered
        let tampered = b"riftroute_auth_challenge_tampered";
        let false_verified = IdentityManager::verify_signature(&identity.public_key_hex, tampered, &sig_hex).unwrap();
        assert!(!false_verified);
    }
}
