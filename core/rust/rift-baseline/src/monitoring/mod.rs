pub mod baseline;
pub mod evaluator;
pub mod models;
pub mod report;
pub mod scheduler;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use models::{DegradationThresholds, MonitoringSession, MonitoringTarget};
use report::MonitoringReportRenderer;
use scheduler::MonitoringScheduler;
use crate::candidate_path::models::CandidateDestination;
use crate::candidate_path::CandidateManager;
use crate::route_intelligence::models::RouteSnapshot;

/// Primary facade for RiftRoute dynamic route performance monitoring and degradation detection.
pub struct MonitoringManager;

impl MonitoringManager {
    /// Resolve or construct a MonitoringTarget from a file path, candidate ID, or IP string.
    pub fn resolve_target(target_str: &str) -> Result<MonitoringTarget, String> {
        let path = Path::new(target_str);
        if path.exists() && path.extension().map_or(false, |ext| ext == "json") {
            // Check if it's already a MonitoringTarget JSON
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(target) = serde_json::from_str::<MonitoringTarget>(&content) {
                    return Ok(target);
                }
                // Check if it's a CandidateDestination JSON
                if let Ok(cand) = serde_json::from_str::<CandidateDestination>(&content) {
                    return Ok(MonitoringTarget::from_candidate(&cand));
                }
                // Check if it's a CandidateDestination list
                if let Ok(cands) = serde_json::from_str::<Vec<CandidateDestination>>(&content) {
                    if let Some(first) = cands.into_iter().next() {
                        return Ok(MonitoringTarget::from_candidate(&first));
                    }
                }
            }
        }

        // Check data/monitoring/targets/
        let targets_dir = Path::new("data/monitoring/targets");
        if targets_dir.exists() {
            if let Ok(entries) = fs::read_dir(targets_dir) {
                for entry in entries.flatten() {
                    let ep = entry.path();
                    if ep.extension().map_or(false, |ext| ext == "json") {
                        if let Ok(target) = Self::load_target(&ep) {
                            if target.target_id == target_str || target.destination == target_str {
                                return Ok(target);
                            }
                        }
                    }
                }
            }
        }

        // Check Phase 2 candidates
        let candidates_dir = Path::new("data/route/candidates");
        if candidates_dir.exists() {
            if let Ok(entries) = fs::read_dir(candidates_dir) {
                for entry in entries.flatten() {
                    let ep = entry.path();
                    if ep.extension().map_or(false, |ext| ext == "json") {
                        if let Ok(cands) = CandidateManager::load_candidates_from_file(&ep) {
                            for c in cands {
                                if c.candidate_id == target_str || c.ip == target_str {
                                    return Ok(MonitoringTarget::from_candidate(&c));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Direct parse as IP or IP:port
        let (ip_str, port_opt) = parse_target_str(target_str);
        Ok(MonitoringTarget::from_destination(&ip_str, port_opt, None))
    }

    /// Load a MonitoringTarget from a JSON file.
    pub fn load_target<P: AsRef<Path>>(path: P) -> Result<MonitoringTarget, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read target file {}: {}", path.as_ref().display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse MonitoringTarget JSON: {}", e))
    }

    /// Save a MonitoringTarget to a directory.
    pub fn save_target<P: AsRef<Path>>(target: &MonitoringTarget, dir: P) -> Result<PathBuf, String> {
        MonitoringReportRenderer::save_target(target, dir)
    }

    /// Load a MonitoringSession from a JSON file.
    pub fn load_session<P: AsRef<Path>>(path: P) -> Result<MonitoringSession, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read session file {}: {}", path.as_ref().display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse MonitoringSession JSON: {}", e))
    }

    /// Save a MonitoringSession to a directory.
    pub fn save_session<P: AsRef<Path>>(session: &MonitoringSession, dir: P) -> Result<PathBuf, String> {
        MonitoringReportRenderer::save_session(session, dir)
    }

    /// Run a controlled live monitoring session against a target.
    pub fn run_monitoring(
        target: MonitoringTarget,
        interval_seconds: u64,
        max_samples: Option<usize>,
        thresholds: DegradationThresholds,
        max_hops: u8,
        probe_timeout_ms: u64,
        resolve_hostnames: bool,
        process_timeout_secs: u64,
        stop_signal: Option<Arc<AtomicBool>>,
    ) -> Result<MonitoringSession, String> {
        let mut session = MonitoringSession::new(target, interval_seconds, thresholds);
        MonitoringScheduler::run_session(
            &mut session,
            max_samples,
            max_hops,
            probe_timeout_ms,
            resolve_hostnames,
            process_timeout_secs,
            stop_signal,
        )?;
        Ok(session)
    }

    /// Replay an array of pre-recorded snapshots for deterministic offline evaluation.
    pub fn replay_snapshots(
        target: MonitoringTarget,
        snapshots: &[RouteSnapshot],
        interval_seconds: u64,
        thresholds: DegradationThresholds,
    ) -> MonitoringSession {
        MonitoringScheduler::replay_snapshots(target, snapshots, interval_seconds, thresholds)
    }

    /// Replay pre-recorded snapshots loaded from a directory or single snapshot file.
    pub fn replay_snapshots_from_path<P: AsRef<Path>>(
        target: MonitoringTarget,
        path: P,
        interval_seconds: u64,
        thresholds: DegradationThresholds,
    ) -> Result<MonitoringSession, String> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(format!("Snapshots path does not exist: {}", p.display()));
        }

        let mut snapshots = Vec::new();
        if p.is_dir() {
            let mut entries: Vec<PathBuf> = fs::read_dir(p)
                .map_err(|e| e.to_string())?
                .flatten()
                .map(|e| e.path())
                .filter(|e| e.extension().map_or(false, |ext| ext == "json"))
                .collect();
            // Sort by filename for deterministic chronological sequence
            entries.sort();

            for ep in entries {
                if let Ok(content) = fs::read_to_string(&ep) {
                    if let Ok(snap) = serde_json::from_str::<RouteSnapshot>(&content) {
                        snapshots.push(snap);
                    }
                }
            }
        } else if let Ok(content) = fs::read_to_string(p) {
            if let Ok(snap) = serde_json::from_str::<RouteSnapshot>(&content) {
                snapshots.push(snap);
            } else if let Ok(snaps) = serde_json::from_str::<Vec<RouteSnapshot>>(&content) {
                snapshots.extend(snaps);
            }
        }

        if snapshots.is_empty() {
            return Err(format!("No valid RouteSnapshot JSON found at {}", p.display()));
        }

        Ok(Self::replay_snapshots(target, &snapshots, interval_seconds, thresholds))
    }
}

fn parse_target_str(s: &str) -> (String, Option<u16>) {
    if let Some(pos) = s.rfind(':') {
        if let Ok(port) = s[pos + 1..].parse::<u16>() {
            let ip = s[..pos].trim_matches(|c| c == '[' || c == ']').to_string();
            return (ip, Some(port));
        }
    }
    (s.to_string(), None)
}
