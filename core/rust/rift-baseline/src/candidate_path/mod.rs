pub mod comparison;
pub mod discovery;
pub mod diversity;
pub mod measurement;
pub mod models;
pub mod report;

use chrono::Utc;
use std::fs;
use std::path::Path;
use std::time::Duration;

use comparison::CandidateComparisonEngine;
use discovery::CandidateDiscoveryEngine;
use measurement::CandidateMeasurementEngine;
use models::{
    CandidateComparisonReport, CandidateDestination, CandidateMeasurementSeries,
    CandidatePathDiversityReport, EvidenceLevel,
};

/// High-level facade for RiftRoute candidate path discovery, repeated measurement, and comparative evaluation.
pub struct CandidateManager;

impl CandidateManager {
    /// Discover candidate endpoints using available non-invasive sources.
    pub fn discover_endpoints<P: AsRef<Path>>(
        capture_file: Option<P>,
        from_processes: bool,
        snapshot_dir: Option<P>,
    ) -> Result<Vec<CandidateDestination>, String> {
        let mut all_candidates = Vec::new();

        if let Some(cap_path) = capture_file {
            let cap_candidates = CandidateDiscoveryEngine::discover_from_capture_file(cap_path)?;
            all_candidates.extend(cap_candidates);
        }

        if from_processes {
            let proc_candidates = CandidateDiscoveryEngine::discover_from_game_processes();
            all_candidates.extend(proc_candidates);
        }

        if let Some(snap_dir) = snapshot_dir {
            let snap_candidates = CandidateDiscoveryEngine::discover_from_snapshot_dir(snap_dir)?;
            all_candidates.extend(snap_candidates);
        }

        if all_candidates.is_empty() {
            // If no explicit sources specified, attempt active game processes
            let proc_candidates = CandidateDiscoveryEngine::discover_from_game_processes();
            all_candidates.extend(proc_candidates);
        }

        let deduped = CandidateDiscoveryEngine::deduplicate_candidates(all_candidates);
        Ok(deduped)
    }

    /// Measure a candidate target through repeated longitudinal route measurements.
    pub fn measure_candidate(
        target_or_id: &str,
        runs: usize,
        max_hops: u8,
        timeout_ms: u64,
        interval_ms: u64,
        resolve_hostnames: bool,
        timeout_secs: u64,
    ) -> Result<CandidateMeasurementSeries, String> {
        let candidate = Self::resolve_candidate(target_or_id)?;
        let max_duration = Duration::from_secs(timeout_secs);

        CandidateMeasurementEngine::measure_candidate(
            &candidate,
            runs,
            max_hops,
            timeout_ms,
            interval_ms,
            resolve_hostnames,
            max_duration,
        )
    }

    /// Compare two candidate measurement series.
    pub fn compare(
        series_a: &CandidateMeasurementSeries,
        series_b: &CandidateMeasurementSeries,
    ) -> CandidateComparisonReport {
        CandidateComparisonEngine::compare(series_a, series_b)
    }

    /// Compare two candidate measurement series loaded from disk files.
    pub fn compare_from_files<P: AsRef<Path>>(
        path_a: P,
        path_b: P,
    ) -> Result<CandidateComparisonReport, String> {
        let series_a = Self::load_series_from_file(path_a)?;
        let series_b = Self::load_series_from_file(path_b)?;
        Ok(Self::compare(&series_a, &series_b))
    }

    /// Synthesize path diversity across all candidate series files in a directory.
    pub fn analyze_diversity_from_dir<P: AsRef<Path>>(
        dir: P,
    ) -> Result<CandidatePathDiversityReport, String> {
        let dir_path = dir.as_ref();
        if !dir_path.exists() {
            return Err(format!("Directory does not exist: {}", dir_path.display()));
        }

        let entries = fs::read_dir(dir_path).map_err(|e| e.to_string())?;
        let mut series_list = Vec::new();

        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map_or(false, |ext| ext == "json") {
                if let Ok(series) = Self::load_series_from_file(&p) {
                    series_list.push(series);
                }
            }
        }

        if series_list.is_empty() {
            return Err(format!(
                "No valid CandidateMeasurementSeries JSON files found in {}",
                dir_path.display()
            ));
        }

        Ok(CandidateComparisonEngine::analyze_diversity(&series_list))
    }

    /// Load a CandidateMeasurementSeries from a JSON file.
    pub fn load_series_from_file<P: AsRef<Path>>(path: P) -> Result<CandidateMeasurementSeries, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse candidate series JSON {}: {}", path.as_ref().display(), e))
    }

    /// Load candidate destinations from a JSON file.
    pub fn load_candidates_from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<CandidateDestination>, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse candidate list JSON: {}", e))
    }

    fn resolve_candidate(target_or_id: &str) -> Result<CandidateDestination, String> {
        let path = Path::new(target_or_id);
        if path.exists() && path.extension().map_or(false, |ext| ext == "json") {
            // Check if it's a single candidate JSON or a list
            if let Ok(cands) = Self::load_candidates_from_file(path) {
                if let Some(first) = cands.into_iter().next() {
                    return Ok(first);
                }
            }
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(cand) = serde_json::from_str::<CandidateDestination>(&content) {
                    return Ok(cand);
                }
            }
        }

        // Check if candidates exist in data/route/candidates/
        let candidates_dir = Path::new("data/route/candidates");
        if candidates_dir.exists() {
            if let Ok(entries) = fs::read_dir(candidates_dir) {
                for entry in entries.flatten() {
                    let ep = entry.path();
                    if ep.extension().map_or(false, |ext| ext == "json") {
                        if let Ok(cands) = Self::load_candidates_from_file(&ep) {
                            for c in cands {
                                if c.candidate_id == target_or_id || c.ip == target_or_id {
                                    return Ok(c);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Parse as direct IP or IP:port
        let (ip_str, port_opt) = parse_target_str(target_or_id);
        let now = Utc::now().to_rfc3339();
        let candidate_id = format!(
            "cand_{}_{}",
            ip_str.replace('.', "_").replace(':', "_"),
            port_opt.unwrap_or(0)
        );

        Ok(CandidateDestination {
            candidate_id,
            ip: ip_str,
            port: port_opt,
            protocol: "ICMP/Traceroute".to_string(),
            service_name: "Direct Route Target".to_string(),
            process_name: None,
            local_port: None,
            discovery_method: "CLI Target Invocation".to_string(),
            evidence_level: EvidenceLevel::DirectlyObserved,
            first_seen_utc: now.clone(),
            last_seen_utc: now,
            observation_count: 1,
            role_hypothesis: "Direct User Specified Route Target".to_string(),
        })
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
