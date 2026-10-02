pub mod comparison;
pub mod fingerprint;
pub mod hop;
pub mod models;
pub mod parser;
pub mod report;
pub mod stability;
pub mod tracert;

use chrono::Utc;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::system::SystemInventory;
use comparison::RouteComparisonEngine;
use fingerprint::RouteFingerprintEngine;
use models::{RouteComparison, RouteSnapshot, RouteStabilityReport};
use parser::TracertParser;
use stability::RouteStabilityEngine;
use tracert::TracertExecutor;

/// Primary orchestrator for the RiftRoute Advanced Route Intelligence & Measurement Engine.
pub struct RouteIntelligence;

impl RouteIntelligence {
    /// Execute a safe Windows tracert route measurement, normalize hops, compute RTT statistics,
    /// and generate a deterministic route snapshot.
    pub fn measure(
        destination: &str,
        max_hops: u8,
        timeout_ms: u64,
        resolve_hostnames: bool,
        max_execution_duration: Duration,
    ) -> Result<RouteSnapshot, String> {
        let timestamp_utc = Utc::now().to_rfc3339();

        // Query active interface and gateway non-invasively via Phase 0 SystemInventory
        let sys_inv = SystemInventory::collect();
        let active_interface = Some(sys_inv.active_interface);
        let source_ipv4 = Some(sys_inv.ipv4_address);
        let default_gateway = Some(sys_inv.default_gateway);

        // Execute tracert
        let exec_result = TracertExecutor::execute(
            destination,
            max_hops,
            timeout_ms,
            resolve_hostnames,
            max_execution_duration,
        )?;

        // Parse hops
        let hops = TracertParser::parse(&exec_result.stdout);
        let hop_count = hops.len();
        let responding_hops = hops.iter().filter(|h| h.responded).count();
        let timeout_hops = hops.iter().filter(|h| h.is_timeout).count();

        // Compute route fingerprints
        let (fingerprint, fingerprint_sha256, canonical_path) =
            RouteFingerprintEngine::fingerprint_route(&hops);

        // Extract destination IP from final responding hop or tracert header if present
        let destination_ip = hops
            .last()
            .and_then(|h| h.primary_address.clone())
            .or_else(|| {
                // If destination itself was an IP, use that
                if std::net::Ipv4Addr::from_str(destination).is_ok()
                    || std::net::Ipv6Addr::from_str(destination).is_ok()
                {
                    Some(destination.to_string())
                } else {
                    None
                }
            });

        let measurement_id = format!(
            "route_{}_{}",
            Utc::now().format("%Y%m%d_%H%M%S"),
            &fingerprint[0..8]
        );

        let scientific_disclaimer = "Traceroute probe RTT reflects ICMP Time Exceeded generation latency from router control planes, NOT actual game client-server application latency. Router timeouts ('*') indicate ICMP rate-limiting or filtering, NOT packet loss.".to_string();

        Ok(RouteSnapshot {
            measurement_id,
            timestamp_utc,
            destination: destination.to_string(),
            destination_ip,
            destination_port: None,
            probe_method: "Windows Tracert (ICMP Echo / Time Exceeded)".to_string(),
            resolve_hostnames,
            active_interface,
            source_ipv4,
            default_gateway,
            hop_count,
            responding_hops,
            timeout_hops,
            hops,
            fingerprint,
            fingerprint_sha256,
            canonical_path,
            measurement_duration_ms: exec_result.duration.as_millis() as u64,
            scientific_disclaimer,
        })
    }

    /// Load a previously saved route snapshot JSON from disk.
    pub fn load_snapshot<P: AsRef<Path>>(path: P) -> Result<RouteSnapshot, String> {
        let mut file = File::open(path.as_ref())
            .map_err(|e| format!("Failed to open snapshot file '{}': {}", path.as_ref().display(), e))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Failed to read snapshot file: {}", e))?;

        serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse snapshot JSON in '{}': {}", path.as_ref().display(), e))
    }

    /// Load all route snapshot JSON files from a specified directory.
    pub fn load_snapshots_from_dir<P: AsRef<Path>>(dir: P) -> Result<Vec<RouteSnapshot>, String> {
        let read_dir = std::fs::read_dir(dir.as_ref())
            .map_err(|e| format!("Failed to read directory '{}': {}", dir.as_ref().display(), e))?;

        let mut snapshots = Vec::new();
        for entry in read_dir {
            let entry = entry.map_err(|e| format!("Error traversing directory: {}", e))?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                if let Ok(snap) = Self::load_snapshot(&path) {
                    snapshots.push(snap);
                }
            }
        }

        if snapshots.is_empty() {
            return Err(format!("No valid route snapshot JSON files found in '{}'.", dir.as_ref().display()));
        }

        snapshots.sort_by(|a, b| a.timestamp_utc.cmp(&b.timestamp_utc));
        Ok(snapshots)
    }

    /// Compare two in-memory route snapshots.
    pub fn compare(previous: &RouteSnapshot, current: &RouteSnapshot) -> RouteComparison {
        RouteComparisonEngine::compare(previous, current)
    }

    /// Compare two route snapshots loaded from disk files.
    pub fn compare_files<P1: AsRef<Path>, P2: AsRef<Path>>(
        previous_path: P1,
        current_path: P2,
    ) -> Result<RouteComparison, String> {
        let prev = Self::load_snapshot(previous_path)?;
        let curr = Self::load_snapshot(current_path)?;
        Ok(Self::compare(&prev, &curr))
    }

    /// Analyze route stability from a slice of snapshots.
    pub fn analyze_stability(snapshots: &[RouteSnapshot]) -> Result<RouteStabilityReport, String> {
        RouteStabilityEngine::analyze(snapshots)
    }

    /// Analyze route stability from a list of paths (directories or individual files).
    pub fn analyze_stability_from_paths(paths: &[PathBuf]) -> Result<RouteStabilityReport, String> {
        let mut all_snapshots = Vec::new();

        for p in paths {
            if p.is_dir() {
                let from_dir = Self::load_snapshots_from_dir(p)?;
                all_snapshots.extend(from_dir);
            } else if p.is_file() {
                let snap = Self::load_snapshot(p)?;
                all_snapshots.push(snap);
            }
        }

        if all_snapshots.is_empty() {
            return Err("No route snapshots were loaded from the provided paths.".to_string());
        }

        Self::analyze_stability(&all_snapshots)
    }
}
