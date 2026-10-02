use chrono::Utc;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

use super::models::{CandidateDestination, EvidenceLevel};
use crate::endpoint_analyzer::EndpointAnalyzer;
use crate::process::ProcessManager;
use crate::route_intelligence::models::RouteSnapshot;

/// Discovery engine for identifying candidate network endpoints non-invasively.
pub struct CandidateDiscoveryEngine;

impl CandidateDiscoveryEngine {
    /// Discover candidate endpoints from a TShark packet metadata capture export (Phase 0.5).
    pub fn discover_from_capture_file<P: AsRef<Path>>(
        capture_path: P,
    ) -> Result<Vec<CandidateDestination>, String> {
        let analysis = EndpointAnalyzer::analyze_file(capture_path.as_ref())?;
        let now = Utc::now().to_rfc3339();

        let mut candidates = Vec::new();
        for ep in &analysis.endpoints {
            let candidate_id = format!(
                "cand_{}_{}",
                ep.remote_ip.replace('.', "_").replace(':', "_"),
                ep.remote_port
            );

            let role_hyp = match ep.rank {
                1 => "Highest Traffic UDP Endpoint (Authoritative Gameplay Stream Hypothesis)".to_string(),
                _ => format!("Secondary UDP Endpoint #{} (Auxiliary / Signaling Hypothesis)", ep.rank),
            };

            candidates.push(CandidateDestination {
                candidate_id,
                ip: ep.remote_ip.clone(),
                port: Some(ep.remote_port),
                protocol: ep.protocol.clone(),
                service_name: "PUBG PC".to_string(),
                process_name: Some("TslGame.exe".to_string()),
                local_port: Some(ep.local_port),
                discovery_method: "Passive TShark UDP Capture Analysis".to_string(),
                evidence_level: EvidenceLevel::DirectlyObserved,
                first_seen_utc: now.clone(),
                last_seen_utc: now.clone(),
                observation_count: ep.total_packets,
                role_hypothesis: role_hyp,
            });
        }

        Ok(candidates)
    }

    /// Discover candidate endpoints from running game process sockets (Phase 0).
    pub fn discover_from_game_processes() -> Vec<CandidateDestination> {
        let inventory = ProcessManager::scan_game_activity();
        let now = Utc::now().to_rfc3339();
        let mut candidates = Vec::new();

        for game in &inventory.detected_games {
            for conn in &game.connections {
                let remote = &conn.remote_address;
                // Exclude empty, wildcard, loopback, or private networks
                if remote.is_empty()
                    || remote.starts_with("0.0.0.0")
                    || remote.starts_with("127.")
                    || remote.starts_with("*:")
                {
                    continue;
                }

                let (ip_str, port_opt) = parse_socket_string(remote);
                if ip_str.is_empty() || is_private_or_loopback(&ip_str) {
                    continue;
                }

                let local_port = parse_socket_string(&conn.local_address).1;
                let candidate_id = format!(
                    "cand_{}_{}",
                    ip_str.replace('.', "_").replace(':', "_"),
                    port_opt.unwrap_or(0)
                );

                candidates.push(CandidateDestination {
                    candidate_id,
                    ip: ip_str,
                    port: port_opt,
                    protocol: conn.protocol.clone(),
                    service_name: game.game.clone(),
                    process_name: Some(game.name.clone()),
                    local_port,
                    discovery_method: "Active Process Socket Inspection".to_string(),
                    evidence_level: EvidenceLevel::DirectlyObserved,
                    first_seen_utc: now.clone(),
                    last_seen_utc: now.clone(),
                    observation_count: 1,
                    role_hypothesis: format!("Active {} Socket Endpoint ({:?})", conn.protocol, conn.classification),
                });
            }
        }

        Self::deduplicate_candidates(candidates)
    }

    /// Discover candidate destinations from snapshot files in a directory or single snapshot file.
    pub fn discover_from_snapshot_dir<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<CandidateDestination>, String> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(format!("Snapshot path does not exist: {}", p.display()));
        }

        let mut snapshots = Vec::new();
        if p.is_dir() {
            let entries = std::fs::read_dir(p).map_err(|e| e.to_string())?;
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.extension().map_or(false, |ext| ext == "json") {
                    if let Ok(content) = std::fs::read_to_string(&entry_path) {
                        if let Ok(snap) = serde_json::from_str::<RouteSnapshot>(&content) {
                            snapshots.push(snap);
                        }
                    }
                }
            }
        } else if let Ok(content) = std::fs::read_to_string(p) {
            if let Ok(snap) = serde_json::from_str::<RouteSnapshot>(&content) {
                snapshots.push(snap);
            }
        }

        Ok(Self::discover_from_snapshots(&snapshots))
    }

    /// Discover candidate destinations from pre-existing route snapshots.
    pub fn discover_from_snapshots(snapshots: &[RouteSnapshot]) -> Vec<CandidateDestination> {
        let now = Utc::now().to_rfc3339();
        let mut candidates = Vec::new();

        for s in snapshots {
            let target_ip = s.destination_ip.clone().unwrap_or_else(|| s.destination.clone());
            if is_private_or_loopback(&target_ip) {
                continue;
            }

            let candidate_id = format!(
                "cand_{}_{}",
                target_ip.replace('.', "_").replace(':', "_"),
                s.destination_port.unwrap_or(0)
            );

            let service_name = if s.destination.contains("1.1.1.1") || s.destination.contains("cloudflare") {
                "Cloudflare DNS".to_string()
            } else if s.destination.contains("8.8.8.8") || s.destination.contains("google") {
                "Google DNS".to_string()
            } else {
                "Observed Network Destination".to_string()
            };

            candidates.push(CandidateDestination {
                candidate_id,
                ip: target_ip,
                port: s.destination_port,
                protocol: "ICMP/IP".to_string(),
                service_name,
                process_name: None,
                local_port: None,
                discovery_method: "Historical Route Snapshot".to_string(),
                evidence_level: EvidenceLevel::Derived,
                first_seen_utc: s.timestamp_utc.clone(),
                last_seen_utc: now.clone(),
                observation_count: 1,
                role_hypothesis: format!("Measured Route Target ({})", s.fingerprint),
            });
        }

        Self::deduplicate_candidates(candidates)
    }

    /// Deduplicate candidates by `(ip, port, protocol)`.
    pub fn deduplicate_candidates(candidates: Vec<CandidateDestination>) -> Vec<CandidateDestination> {
        let mut map: HashMap<(String, Option<u16>, String), CandidateDestination> = HashMap::new();

        for c in candidates {
            let key = (c.ip.clone(), c.port, c.protocol.clone());
            map.entry(key)
                .and_modify(|existing| {
                    existing.observation_count += c.observation_count;
                    if c.last_seen_utc > existing.last_seen_utc {
                        existing.last_seen_utc = c.last_seen_utc.clone();
                    }
                })
                .or_insert(c);
        }

        let mut out: Vec<CandidateDestination> = map.into_values().collect();
        out.sort_by(|a, b| b.observation_count.cmp(&a.observation_count).then_with(|| a.ip.cmp(&b.ip)));
        out
    }
}

fn parse_socket_string(s: &str) -> (String, Option<u16>) {
    if let Some(pos) = s.rfind(':') {
        let ip_part = &s[..pos];
        let port_part = &s[pos + 1..];
        let port = port_part.parse::<u16>().ok();
        (ip_part.to_string(), port)
    } else {
        (s.to_string(), None)
    }
}

fn is_private_or_loopback(ip_str: &str) -> bool {
    if let Ok(ipv4) = Ipv4Addr::from_str(ip_str) {
        return ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() || ipv4.is_unspecified();
    }
    if let Ok(ipv6) = Ipv6Addr::from_str(ip_str) {
        return ipv6.is_loopback() || ipv6.is_unspecified();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socket_string() {
        let (ip, port) = parse_socket_string("20.205.179.128:27528");
        assert_eq!(ip, "20.205.179.128");
        assert_eq!(port, Some(27528));

        let (ip2, port2) = parse_socket_string("1.1.1.1");
        assert_eq!(ip2, "1.1.1.1");
        assert_eq!(port2, None);
    }

    #[test]
    fn test_is_private_or_loopback() {
        assert!(is_private_or_loopback("192.168.1.1"));
        assert!(is_private_or_loopback("10.0.0.1"));
        assert!(is_private_or_loopback("127.0.0.1"));
        assert!(!is_private_or_loopback("1.1.1.1"));
        assert!(!is_private_or_loopback("20.205.179.128"));
    }

    #[test]
    fn test_deduplicate_candidates() {
        let c1 = CandidateDestination {
            candidate_id: "c1".to_string(),
            ip: "20.205.179.128".to_string(),
            port: Some(27528),
            protocol: "UDP".to_string(),
            service_name: "PUBG PC".to_string(),
            process_name: Some("TslGame.exe".to_string()),
            local_port: Some(50000),
            discovery_method: "Test".to_string(),
            evidence_level: EvidenceLevel::DirectlyObserved,
            first_seen_utc: "2026-10-02T10:00:00Z".to_string(),
            last_seen_utc: "2026-10-02T10:00:00Z".to_string(),
            observation_count: 5,
            role_hypothesis: "Test".to_string(),
        };

        let mut c2 = c1.clone();
        c2.last_seen_utc = "2026-10-02T10:05:00Z".to_string();
        c2.observation_count = 10;

        let deduped = CandidateDiscoveryEngine::deduplicate_candidates(vec![c1, c2]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].observation_count, 15);
        assert_eq!(deduped[0].last_seen_utc, "2026-10-02T10:05:00Z");
    }
}
