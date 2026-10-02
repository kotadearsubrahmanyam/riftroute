use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::connectivity::DestinationBaseline;
use crate::process::ProcessInventory;
use crate::route::RouteTrace;
use crate::system::SystemInventory;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameTestSummary {
    pub game_title: String,
    pub process_name: String,
    pub pid: Option<u32>,
    pub candidate_endpoints: Vec<String>,
    pub candidate_baselines: Vec<DestinationBaseline>,
    pub candidate_traces: Vec<RouteTrace>,
    pub observed_latency_ms: Option<f64>,
    pub user_reported_latency_ms: f64,
    pub commentary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineSession {
    pub session_id: String,
    pub timestamp: String,
    pub tool_version: String,
    pub system_inventory: SystemInventory,
    pub connectivity_baselines: Vec<DestinationBaseline>,
    pub route_traces: Vec<RouteTrace>,
    pub process_inventory: ProcessInventory,
    pub game_test_summary: Option<GameTestSummary>,
    pub findings: Vec<String>,
    pub hypotheses: Vec<String>,
    pub unknowns: Vec<String>,
    pub recommendations: Vec<String>,
}

pub struct ReportGenerator;

impl ReportGenerator {
    /// Save session data as structured machine-readable JSON in the sessions directory.
    pub fn save_session_json(session: &BaselineSession, base_dir: &str) -> Result<PathBuf, String> {
        let sessions_dir = Path::new(base_dir).join("sessions");
        create_dir_all(&sessions_dir)
            .map_err(|e| format!("Failed to create sessions directory: {}", e))?;

        let file_path = sessions_dir.join(format!("{}.json", session.session_id));
        let json_str = serde_json::to_string_pretty(session)
            .map_err(|e| format!("Failed to serialize session JSON: {}", e))?;

        let mut file = File::create(&file_path)
            .map_err(|e| format!("Failed to create JSON session file: {}", e))?;
        file.write_all(json_str.as_bytes())
            .map_err(|e| format!("Failed to write JSON session file: {}", e))?;

        Ok(file_path)
    }

    /// Generate a human-readable Markdown baseline report.
    pub fn generate_markdown_report(
        session: &BaselineSession,
        reports_dir: &str,
    ) -> Result<PathBuf, String> {
        let reports_path = Path::new(reports_dir);
        create_dir_all(reports_path)
            .map_err(|e| format!("Failed to create reports directory: {}", e))?;

        let file_path = reports_path.join(format!("{}_report.md", session.session_id));
        let mut f = File::create(&file_path)
            .map_err(|e| format!("Failed to create report file: {}", e))?;

        let mut md = String::new();
        md.push_str(&format!("# RiftRoute Phase 0 Baseline Report\n\n"));
        md.push_str(&format!("- **Session ID:** `{}`\n", session.session_id));
        md.push_str(&format!("- **Generated At:** {}\n", session.timestamp));
        md.push_str(&format!("- **Tool Version:** `{}`\n\n", session.tool_version));

        // 1. Environment
        let sys = &session.system_inventory;
        md.push_str("## 1. Environment & Local Network\n\n");
        md.push_str(&format!("- **OS:** {}\n", sys.os));
        md.push_str(&format!("- **Active Interface:** {} ({})\n", sys.active_interface, sys.interface_description));
        md.push_str(&format!("- **Local IPv4:** `{}`\n", sys.ipv4_address));
        md.push_str(&format!("- **Default Gateway:** `{}`\n", sys.default_gateway));
        md.push_str(&format!("- **DNS Servers:** `{}`\n", sys.dns_servers.join(", ")));
        md.push_str(&format!("- **Interface Metric:** {}\n", sys.interface_metric));
        md.push_str(&format!("- **ISP / Organization:** {} ({})\n", sys.isp_info.organization, sys.isp_info.asn));
        md.push_str(&format!("- **ISP Location:** {}, {}, {}\n\n", sys.isp_info.city, sys.isp_info.region, sys.isp_info.country));

        // 2. Internet Baseline
        md.push_str("## 2. Internet Connectivity Baseline\n\n");
        md.push_str("| Destination | Target | Probes | Loss % | Min (ms) | Median (ms) | Mean (ms) | Max (ms) | StdDev (ms) | RFC3550 Jitter (ms) | MAPDV Jitter (ms) |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for b in &session.connectivity_baselines {
            let s = &b.stats;
            md.push_str(&format!(
                "| {} | `{}` | {}/{} | {:.1}% | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.2} | {:.2} |\n",
                b.destination.name,
                b.destination.target,
                s.successful_probes,
                s.total_probes,
                s.packet_loss_pct,
                s.min_ms.unwrap_or(0.0),
                s.median_ms.unwrap_or(0.0),
                s.mean_ms.unwrap_or(0.0),
                s.max_ms.unwrap_or(0.0),
                s.std_dev_ms.unwrap_or(0.0),
                s.rfc3550_jitter_ms.unwrap_or(0.0),
                s.mapdv_jitter_ms.unwrap_or(0.0),
            ));
        }
        md.push_str("\n");

        // 3. Route Analysis
        md.push_str("## 3. Route Analysis & Fingerprints\n\n");
        for r in &session.route_traces {
            md.push_str(&format!("### Route to `{}`\n\n", r.destination));
            md.push_str(&format!("- **Analysis Summary:** {}\n", r.analysis_summary));
            md.push_str(&format!("- **Route Fingerprint:** `{}`\n\n", r.route_fingerprint));
            md.push_str("| Hop | Min RTT (ms) | Endpoint | Latency Delta | Significance | Commentary |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for h in &r.hops {
                let min_str = h.min_rtt_ms.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "*".to_string());
                let delta_str = h.latency_delta_ms.map(|v| format!("{:+.1}", v)).unwrap_or_else(|| "-".to_string());
                let sig_str = format!("{:?}", h.significance);
                md.push_str(&format!(
                    "| {} | {} | `{}` | {} | {} | {} |\n",
                    h.hop, min_str, h.ip_or_host, delta_str, sig_str, h.commentary
                ));
            }
            md.push_str("\n");
        }

        // 4. Game Connectivity
        md.push_str("## 4. Game Connectivity Inventory\n\n");
        md.push_str(&format!("- **Total Active System Connections:** {}\n", session.process_inventory.total_active_connections));
        md.push_str(&format!("- **Detected Game Processes:** {}\n\n", session.process_inventory.detected_games.len()));

        if session.process_inventory.detected_games.is_empty() {
            md.push_str("*No running supported game processes (PUBG PC, CS2, VALORANT, THE FINALS) were detected during this sampling run.*\n\n");
        } else {
            for g in &session.process_inventory.detected_games {
                md.push_str(&format!("### {} (PID: `{}`)\n\n", g.game, g.pid));
                md.push_str("| Protocol | Local Address | Remote Address | State | Classification |\n");
                md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
                for c in &g.connections {
                    md.push_str(&format!(
                        "| {} | `{}` | `{}` | {} | {:?} |\n",
                        c.protocol, c.local_address, c.remote_address, c.state, c.classification
                    ));
                }
                md.push_str("\n");
            }
        }

        // 5. PUBG Baseline Investigation
        md.push_str("## 5. PUBG Baseline Investigation\n\n");
        if let Some(gt) = &session.game_test_summary {
            md.push_str(&format!("- **Game Target:** {}\n", gt.game_title));
            md.push_str(&format!("- **Process:** `{}` (PID: {:?})\n", gt.process_name, gt.pid));
            md.push_str(&format!("- **User-Reported Real-World Latency:** {:.1} ms\n", gt.user_reported_latency_ms));
            if let Some(obs) = gt.observed_latency_ms {
                md.push_str(&format!("- **Empirically Observed Latency to Candidates:** {:.1} ms\n", obs));
            } else {
                md.push_str("- **Empirically Observed Latency:** None (No active game match session detected)\n");
            }
            md.push_str(&format!("- **Candidate Endpoints Identified:** {}\n", gt.candidate_endpoints.len()));
            for ep in &gt.candidate_endpoints {
                md.push_str(&format!("  - `OBSERVED`: `{}`\n", ep));
            }
            md.push_str(&format!("- **Commentary:** {}\n\n", gt.commentary));
        } else {
            md.push_str("- **Status:** Standalone baseline mode (User-driven interactive game session not invoked in this run).\n\n");
        }

        // 6. Findings (OBSERVED Facts)
        md.push_str("## 6. Findings (OBSERVED Facts)\n\n");
        for f in &session.findings {
            md.push_str(&format!("- [OBSERVED] {}\n", f));
        }
        md.push_str("\n");

        // 7. Hypotheses (Requiring Verification)
        md.push_str("## 7. Hypotheses (Requiring Verification)\n\n");
        for h in &session.hypotheses {
            md.push_str(&format!("- [HYPOTHESIS] {}\n", h));
        }
        md.push_str("\n");

        // 8. Unknowns
        md.push_str("## 8. Unknowns (Information Not Yet Obtainable)\n\n");
        for u in &session.unknowns {
            md.push_str(&format!("- [UNKNOWN] {}\n", u));
        }
        md.push_str("\n");

        // 9. Recommendations for Phase 1
        md.push_str("## 9. Recommendations for Phase 1\n\n");
        for r in &session.recommendations {
            md.push_str(&format!("- {}\n", r));
        }
        md.push_str("\n");

        f.write_all(md.as_bytes())
            .map_err(|e| format!("Failed to write report file: {}", e))?;

        Ok(file_path)
    }
}
