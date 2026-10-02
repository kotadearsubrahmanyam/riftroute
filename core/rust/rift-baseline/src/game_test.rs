use std::collections::HashSet;

use crate::config::{BaselineConfig, Destination};
use crate::connectivity::ConnectivityTester;
use crate::process::ProcessManager;
use crate::report::GameTestSummary;
use crate::route::RouteAnalyzer;

pub struct GameTester;

impl GameTester {
    /// Execute a controlled, non-invasive PUBG baseline investigation test.
    pub fn run_pubg_test(config: &BaselineConfig) -> GameTestSummary {
        let process_inventory = ProcessManager::scan_game_activity();
        let pubg_proc = process_inventory
            .detected_games
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case("TslGame.exe"));

        if let Some(proc) = pubg_proc {
            println!("[FOUND] PUBG PC process detected! (PID: {})", proc.pid);
            println!("[INFO] Inspecting active socket connections non-invasively...");

            let mut candidate_set = HashSet::new();
            for c in &proc.connections {
                let remote = &c.remote_address;
                // Exclude loopback, unspecified, and local broadcast addresses
                if !remote.starts_with("0.0.0.0")
                    && !remote.starts_with("127.")
                    && !remote.starts_with("*:")
                    && !remote.is_empty()
                {
                    // Extract IP part without port
                    let ip = remote.split(':').next().unwrap_or(remote);
                    if !ip.is_empty() && !ip.starts_with("192.168.") && !ip.starts_with("10.") {
                        candidate_set.insert(ip.to_string());
                    }
                }
            }

            let candidate_endpoints: Vec<String> = candidate_set.into_iter().collect();
            println!(
                "[INFO] Discovered {} candidate external endpoint(s).",
                candidate_endpoints.len()
            );

            let mut candidate_baselines = Vec::new();
            let mut candidate_traces = Vec::new();
            let mut observed_rtts = Vec::new();

            for ep in &candidate_endpoints {
                println!("[PROBING] Measuring candidate endpoint: {}", ep);
                let dest = Destination {
                    name: format!("Candidate PUBG Endpoint ({})", ep),
                    target: ep.clone(),
                    purpose: "Candidate game server RTT investigation".to_string(),
                    protocol: "ICMP".to_string(),
                    port: None,
                };

                let baseline = ConnectivityTester::probe_destination(&dest, config);
                if let Some(med) = baseline.stats.median_ms {
                    observed_rtts.push(med);
                }
                candidate_baselines.push(baseline);

                println!("[TRACING] Tracing route to candidate endpoint: {}", ep);
                let trace = RouteAnalyzer::trace(ep, config.max_hops);
                candidate_traces.push(trace);
            }

            let mean_observed = if !observed_rtts.is_empty() {
                let sum: f64 = observed_rtts.iter().sum();
                Some(sum / observed_rtts.len() as f64)
            } else {
                None
            };

            let commentary = format!(
                "PUBG PC (PID {}) was active. Observed {} candidate external endpoint(s). Non-invasive ICMP measurements completed without injecting into or modifying the game.",
                proc.pid,
                candidate_endpoints.len()
            );

            GameTestSummary {
                game_title: "PUBG PC".to_string(),
                process_name: "TslGame.exe".to_string(),
                pid: Some(proc.pid),
                candidate_endpoints,
                candidate_baselines,
                candidate_traces,
                observed_latency_ms: mean_observed,
                user_reported_latency_ms: 200.0,
                commentary,
            }
        } else {
            println!("[NOTICE] PUBG PC (TslGame.exe) is not currently running on this machine.");
            println!();
            println!("============================================================");
            println!("  PUBG PC Baseline Test Procedure:");
            println!("  1. Start PUBG PC (via Steam).");
            println!("  2. Enter an active match or training map.");
            println!("  3. Once spawned in the game world, run:");
            println!("       rift-baseline game-test");
            println!("  4. The tool will non-invasively detect active connections.");
            println!("  5. It will characterize latency to candidate game endpoints.");
            println!("============================================================");

            GameTestSummary {
                game_title: "PUBG PC".to_string(),
                process_name: "TslGame.exe".to_string(),
                pid: None,
                candidate_endpoints: Vec::new(),
                candidate_baselines: Vec::new(),
                candidate_traces: Vec::new(),
                observed_latency_ms: None,
                user_reported_latency_ms: 200.0,
                commentary: "PUBG PC process (TslGame.exe) was not active at the time of sampling. Test procedure documented for user invocation.".to_string(),
            }
        }
    }
}
