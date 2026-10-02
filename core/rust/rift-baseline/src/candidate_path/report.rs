use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

use super::models::{
    CandidateComparisonReport, CandidateDestination, CandidateMeasurementSeries,
    CandidatePathDiversityReport,
};

/// Renderer for candidate discovery, measurement series, comparative reports, and diversity summaries.
pub struct CandidateReportRenderer;

impl CandidateReportRenderer {
    pub fn format_discovery_text(candidates: &[CandidateDestination]) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                     RIFTROUTE CANDIDATE DISCOVERY REPORT                       \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Discovered Candidates: {}\n", candidates.len()));
        out.push_str(&format!("Timestamp (UTC):       {}\n\n", Utc::now().to_rfc3339()));

        out.push_str("CANDIDATE ENDPOINTS:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "{:<22} {:<24} {:<8} {:<10} {:<12}\n",
            "CANDIDATE ID", "ENDPOINT", "PROTO", "SERVICE", "EVIDENCE"
        ));
        out.push_str("--------------------------------------------------------------------------------\n");

        for c in candidates {
            let ep = match c.port {
                Some(p) => format!("{}:{}", c.ip, p),
                None => c.ip.clone(),
            };
            out.push_str(&format!(
                "{:<22} {:<24} {:<8} {:<10} {:<12?}\n",
                c.candidate_id, ep, c.protocol, c.service_name, c.evidence_level
            ));
            out.push_str(&format!("  -> Role Hypothesis: {}\n", c.role_hypothesis));
            out.push_str(&format!("  -> Discovery:       {}\n", c.discovery_method));
        }

        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("METHODOLOGY & GOVERNANCE:\n");
        out.push_str("All endpoints identified non-invasively via passive packet metadata parsing or\n");
        out.push_str("active OS socket state inspection. No traffic modification or redirection occurred.\n");
        out.push_str("================================================================================\n");
        out
    }

    pub fn format_discovery_json(candidates: &[CandidateDestination]) -> Result<String, String> {
        serde_json::to_string_pretty(candidates).map_err(|e| e.to_string())
    }

    pub fn format_measurement_series_text(series: &CandidateMeasurementSeries) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                     RIFTROUTE CANDIDATE MEASUREMENT SERIES                     \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Candidate ID:            {}\n", series.candidate_id));
        let ep = match series.target_port {
            Some(p) => format!("{}:{}", series.target_ip, p),
            None => series.target_ip.clone(),
        };
        out.push_str(&format!("Target Endpoint:         {}\n", ep));
        out.push_str(&format!("Service:                 {}\n", series.service_name));
        out.push_str(&format!("Run Count:               {}\n", series.run_count));
        out.push_str(&format!(
            "Execution Window:        {} -> {}\n\n",
            series.execution_window_start, series.execution_window_end
        ));

        out.push_str("ROUTE PATH CHARACTERISTICS:\n");
        out.push_str(&format!("Dominant Fingerprint:    {}\n", series.dominant_fingerprint));
        out.push_str(&format!(
            "Dominant Fingerprint %:  {:.1}%\n",
            series.dominant_fingerprint_pct
        ));
        out.push_str(&format!(
            "Unique Fingerprints:     {}\n",
            series.unique_fingerprints.len()
        ));
        out.push_str(&format!(
            "Path Classification:     {:?}\n",
            series.path_difference_classification
        ));
        out.push_str(&format!(
            "Route Transitions:       {} ({:.1}% transition rate)\n\n",
            series.route_transition_count, series.route_transition_rate_pct
        ));

        out.push_str("HOP COUNT DISTRIBUTION (MEDIANS):\n");
        out.push_str(&format!("Total Hops:              {}\n", series.hop_count_median));
        out.push_str(&format!(
            "Responding Hops:         {}\n",
            series.responding_hop_count_median
        ));
        out.push_str(&format!(
            "Timeout Hops:            {}\n\n",
            series.timeout_hop_count_median
        ));

        out.push_str("FINAL-HOP PROBE RTT STATISTICS (ICMP CONTROL PLANE):\n");
        if let Some(ref stats) = series.final_hop_probe_stats {
            out.push_str(&format!("Sample Count:            {}\n", stats.sample_count));
            out.push_str(&format!("Min Probe RTT:           {:.2} ms\n", stats.min_ms));
            out.push_str(&format!("Median Probe RTT:        {:.2} ms\n", stats.median_ms));
            out.push_str(&format!("Mean Probe RTT:          {:.2} ms\n", stats.mean_ms));
            out.push_str(&format!("p95 Probe RTT:           {:.2} ms\n", stats.p95_ms));
            out.push_str(&format!("p99 Probe RTT:           {:.2} ms\n", stats.p99_ms));
            out.push_str(&format!("Max Probe RTT:           {:.2} ms\n", stats.max_ms));
            out.push_str(&format!("Std Deviation:           {:.2} ms\n", stats.std_dev_ms));
            let jitter_str = match stats.jitter_ms {
                Some(j) => format!("{:.2} ms", j),
                None => "N/A".to_string(),
            };
            out.push_str(&format!("Probe Jitter:            {}\n\n", jitter_str));
        } else {
            out.push_str("No responding final-hop RTT samples recorded across runs.\n\n");
        }

        out.push_str("INDIVIDUAL MEASUREMENT SNAPSHOTS:\n");
        for (i, s) in series.measurement_snapshots.iter().enumerate() {
            out.push_str(&format!(
                "  Run #{:<2}: ID: {} | Hops: {:<2} (Resp: {:<2}, Drop: {:<2}) | FP: {} | Dur: {} ms\n",
                i + 1,
                s.measurement_id,
                s.hop_count,
                s.responding_hops,
                s.timeout_hops,
                s.fingerprint,
                s.measurement_duration_ms
            ));
        }

        out.push_str("\nSCIENTIFIC DISCLAIMER:\n");
        out.push_str(&series.scientific_disclaimer);
        out.push_str("\n================================================================================\n");
        out
    }

    pub fn format_measurement_series_json(
        series: &CandidateMeasurementSeries,
    ) -> Result<String, String> {
        serde_json::to_string_pretty(series).map_err(|e| e.to_string())
    }

    pub fn format_comparison_text(report: &CandidateComparisonReport) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                     RIFTROUTE CANDIDATE COMPARISON REPORT                      \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Comparison ID:           {}\n", report.comparison_id));
        out.push_str(&format!("Timestamp (UTC):         {}\n\n", report.timestamp_utc));

        out.push_str("CANDIDATE METRICS COMPARISON:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "METRIC", "CANDIDATE A", "CANDIDATE B"
        ));
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Candidate ID", report.candidate_a.candidate_id, report.candidate_b.candidate_id
        ));
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Destination", report.candidate_a.destination, report.candidate_b.destination
        ));
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Service", report.candidate_a.service_name, report.candidate_b.service_name
        ));
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Dominant Fingerprint",
            report.candidate_a.dominant_fingerprint,
            report.candidate_b.dominant_fingerprint
        ));
        out.push_str(&format!(
            "{:<24} {:<25.1}% {:<25.1}%\n",
            "Dominant FP %",
            report.candidate_a.dominant_fingerprint_pct,
            report.candidate_b.dominant_fingerprint_pct
        ));
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Hops (Median)",
            report.candidate_a.hop_count_median,
            report.candidate_b.hop_count_median
        ));
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Responding Hops",
            report.candidate_a.responding_hop_count_median,
            report.candidate_b.responding_hop_count_median
        ));
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Timeout Hops",
            report.candidate_a.timeout_hop_count_median,
            report.candidate_b.timeout_hop_count_median
        ));

        let med_a_str = report
            .candidate_a
            .final_hop_median_rtt_ms
            .map(|v| format!("{:.2} ms", v))
            .unwrap_or_else(|| "N/A".to_string());
        let med_b_str = report
            .candidate_b
            .final_hop_median_rtt_ms
            .map(|v| format!("{:.2} ms", v))
            .unwrap_or_else(|| "N/A".to_string());
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Final Hop Median RTT", med_a_str, med_b_str
        ));

        let p95_a_str = report
            .candidate_a
            .final_hop_p95_rtt_ms
            .map(|v| format!("{:.2} ms", v))
            .unwrap_or_else(|| "N/A".to_string());
        let p95_b_str = report
            .candidate_b
            .final_hop_p95_rtt_ms
            .map(|v| format!("{:.2} ms", v))
            .unwrap_or_else(|| "N/A".to_string());
        out.push_str(&format!(
            "{:<24} {:<26} {:<26}\n",
            "Final Hop p95 RTT", p95_a_str, p95_b_str
        ));

        out.push_str(&format!(
            "{:<24} {:<25.1}% {:<25.1}%\n",
            "Route Transition Rate",
            report.candidate_a.route_transition_rate_pct,
            report.candidate_b.route_transition_rate_pct
        ));
        out.push_str("--------------------------------------------------------------------------------\n\n");

        out.push_str("COMPARATIVE EVALUATION:\n");
        out.push_str(&format!(
            "Path Relationship:       {:?}\n",
            report.path_relationship
        ));
        if let Some(delta) = report.final_hop_median_delta_ms {
            out.push_str(&format!(
                "Final Hop Median Delta:  {:+.2} ms (Candidate B - Candidate A)\n",
                delta
            ));
        }
        if let Some(p95_delta) = report.final_hop_p95_delta_ms {
            out.push_str(&format!(
                "Final Hop p95 Delta:     {:+.2} ms (Candidate B - Candidate A)\n",
                p95_delta
            ));
        }
        out.push_str(&format!(
            "Hop Count Delta:         {:+0} hops (Candidate B - Candidate A)\n\n",
            report.hop_count_delta
        ));

        out.push_str("STRUCTURAL PATH DIFFERENCES:\n");
        if report.structural_differences.is_empty() {
            out.push_str("  None (matching intermediate and terminal responding hops).\n");
        } else {
            for diff in &report.structural_differences {
                out.push_str(&format!("  * {}\n", diff));
            }
        }
        out.push_str("\n");

        out.push_str("FACTUAL COMPARISON SUMMARY:\n");
        out.push_str(&report.factual_comparison_summary);
        out.push_str("\n\nSCIENTIFIC DISCLAIMER:\n");
        out.push_str(&report.scientific_disclaimer);
        out.push_str("\n================================================================================\n");
        out
    }

    pub fn format_comparison_json(report: &CandidateComparisonReport) -> Result<String, String> {
        serde_json::to_string_pretty(report).map_err(|e| e.to_string())
    }

    pub fn format_diversity_text(report: &CandidatePathDiversityReport) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                   RIFTROUTE CANDIDATE PATH DIVERSITY REPORT                    \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Report ID:               {}\n", report.report_id));
        out.push_str(&format!("Timestamp (UTC):         {}\n", report.timestamp_utc));
        out.push_str(&format!("Service:                 {}\n", report.service_name));
        out.push_str(&format!("Candidates Analyzed:     {}\n", report.total_candidates));
        out.push_str(&format!(
            "Unique Dominant Paths:   {}\n",
            report.unique_fingerprints_across_all_candidates.len()
        ));
        out.push_str(&format!(
            "Structural Divergences:  {} pairwise\n",
            report.structural_variation_count
        ));
        out.push_str(&format!(
            "Shared Path Pairs:       {} pairwise\n\n",
            report.shared_path_count
        ));

        out.push_str("CANDIDATE PATH OVERVIEW:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "{:<20} {:<20} {:<10} {:<10} {:<6}\n",
            "CANDIDATE ID", "DESTINATION", "MED RTT", "p95 RTT", "HOPS"
        ));
        out.push_str("--------------------------------------------------------------------------------\n");

        for c in &report.candidate_summaries {
            let med_str = c
                .final_hop_median_rtt_ms
                .map(|v| format!("{:.1} ms", v))
                .unwrap_or_else(|| "N/A".to_string());
            let p95_str = c
                .final_hop_p95_rtt_ms
                .map(|v| format!("{:.1} ms", v))
                .unwrap_or_else(|| "N/A".to_string());
            out.push_str(&format!(
                "{:<20} {:<20} {:<10} {:<10} {:<6}\n",
                c.candidate_id, c.destination, med_str, p95_str, c.hop_count_median
            ));
            out.push_str(&format!(
                "  -> Dominant FP: {} ({:.1}%) | Trans: {:.1}%\n",
                c.dominant_fingerprint, c.dominant_fingerprint_pct, c.route_transition_rate_pct
            ));
        }

        out.push_str("--------------------------------------------------------------------------------\n\n");
        out.push_str("ARCHITECTURAL STATUS:\n");
        out.push_str(&report.architectural_status);
        out.push_str("\n\nSCIENTIFIC DISCLAIMER:\n");
        out.push_str(&report.scientific_disclaimer);
        out.push_str("\n================================================================================\n");
        out
    }

    pub fn format_diversity_json(report: &CandidatePathDiversityReport) -> Result<String, String> {
        serde_json::to_string_pretty(report).map_err(|e| e.to_string())
    }

    // Persistence helpers

    pub fn save_discovery<P: AsRef<Path>>(
        candidates: &[CandidateDestination],
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!("candidates_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let path = dir.join(filename);
        let json = Self::format_discovery_json(candidates)?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn save_measurement_series<P: AsRef<Path>>(
        series: &CandidateMeasurementSeries,
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!(
            "candidate_series_{}_{}.json",
            series.candidate_id,
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        let path = dir.join(filename);
        let json = Self::format_measurement_series_json(series)?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn save_comparison<P: AsRef<Path>>(
        report: &CandidateComparisonReport,
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!("{}.json", report.comparison_id);
        let path = dir.join(filename);
        let json = Self::format_comparison_json(report)?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn save_diversity<P: AsRef<Path>>(
        report: &CandidatePathDiversityReport,
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!("{}.json", report.report_id);
        let path = dir.join(filename);
        let json = Self::format_diversity_json(report)?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }
}
