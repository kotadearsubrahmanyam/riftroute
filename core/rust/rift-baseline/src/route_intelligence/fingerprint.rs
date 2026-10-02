use sha2::{Digest, Sha256};
use super::models::RouteHop;

/// Generator of canonical route representations and cryptographic route fingerprints.
pub struct RouteFingerprintEngine;

impl RouteFingerprintEngine {
    /// Build a deterministic canonical path string from a sequence of route hops.
    /// Format: "1:<ip_or_TIMEOUT>|2:<ip_or_TIMEOUT>|...|N:<ip_or_TIMEOUT>"
    ///
    /// Rules:
    /// 1. Hop position is strictly preserved: `"<hop_number>:<identity>"`.
    /// 2. If the hop completely timed out (`responded == false` or `is_timeout == true`), identity is `"TIMEOUT"`.
    /// 3. If the hop responded, identity is the primary IP address normalized to lowercase trimmed string.
    ///    If hostname was captured, reverse DNS does not replace the IP unless no numeric IP exists.
    /// 4. Hops are separated by the pipe character `'|'`.
    pub fn build_canonical_path(hops: &[RouteHop]) -> String {
        let mut parts = Vec::with_capacity(hops.len());

        for hop in hops {
            let label = if hop.responded && hop.primary_address.is_some() {
                hop.primary_address
                    .as_ref()
                    .unwrap()
                    .trim()
                    .to_lowercase()
            } else if hop.responded && !hop.addresses.is_empty() {
                hop.addresses[0].trim().to_lowercase()
            } else {
                "TIMEOUT".to_string()
            };

            parts.push(format!("{}:{}", hop.hop_number, label));
        }

        parts.join("|")
    }

    /// Compute deterministic fingerprints from a canonical path string.
    /// Returns (concise_16_char_fingerprint, full_64_char_sha256).
    pub fn compute_fingerprints(canonical_path: &str) -> (String, String) {
        let mut hasher = Sha256::new();
        hasher.update(canonical_path.as_bytes());
        let digest = hasher.finalize();

        let full_sha256 = format!("{:x}", digest);
        // Take first 16 hex characters for readable yet high-entropy fingerprint
        let concise = full_sha256[0..16].to_uppercase();

        (concise, full_sha256)
    }

    /// Compute fingerprints directly from a list of route hops.
    pub fn fingerprint_route(hops: &[RouteHop]) -> (String, String, String) {
        let canonical_path = Self::build_canonical_path(hops);
        let (concise, full_sha256) = Self::compute_fingerprints(&canonical_path);
        (concise, full_sha256, canonical_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hop(num: u8, ip: Option<&str>, responded: bool) -> RouteHop {
        RouteHop {
            hop_number: num,
            addresses: ip.map(|s| vec![s.to_string()]).unwrap_or_default(),
            primary_address: ip.map(|s| s.to_string()),
            hostname: None,
            rtt_samples_ms: if responded { vec![10.0, 11.0, 10.0] } else { vec![] },
            responded,
            timeout_count: if responded { 0 } else { 3 },
            probe_count: 3,
            rtt_stats: None,
            is_timeout: !responded,
            raw_line: "".to_string(),
        }
    }

    #[test]
    fn test_canonical_path_generation() {
        let hops = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, None, false),
            make_test_hop(3, Some("59.144.94.165"), true),
        ];

        let path = RouteFingerprintEngine::build_canonical_path(&hops);
        assert_eq!(path, "1:192.168.1.1|2:TIMEOUT|3:59.144.94.165");
    }

    #[test]
    fn test_identical_routes_produce_identical_fingerprints() {
        let hops1 = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, Some("223.230.16.1"), true),
        ];
        let hops2 = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, Some("223.230.16.1"), true),
        ];

        let (fp1, sha1, _) = RouteFingerprintEngine::fingerprint_route(&hops1);
        let (fp2, sha2, _) = RouteFingerprintEngine::fingerprint_route(&hops2);

        assert_eq!(fp1, fp2);
        assert_eq!(sha1, sha2);
        assert_eq!(fp1.len(), 16);
    }

    #[test]
    fn test_hop_address_change_changes_fingerprint() {
        let hops1 = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, Some("223.230.16.1"), true),
        ];
        let hops2 = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, Some("223.230.16.99"), true), // changed
        ];

        let (fp1, _, _) = RouteFingerprintEngine::fingerprint_route(&hops1);
        let (fp2, _, _) = RouteFingerprintEngine::fingerprint_route(&hops2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_timeout_position_change_changes_fingerprint() {
        let hops1 = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, None, false), // timeout at 2
            make_test_hop(3, Some("59.144.94.165"), true),
        ];
        let hops2 = vec![
            make_test_hop(1, Some("192.168.1.1"), true),
            make_test_hop(2, Some("59.144.94.165"), true),
            make_test_hop(3, None, false), // timeout at 3
        ];

        let (fp1, _, _) = RouteFingerprintEngine::fingerprint_route(&hops1);
        let (fp2, _, _) = RouteFingerprintEngine::fingerprint_route(&hops2);

        assert_ne!(fp1, fp2);
    }
}
