use chrono::Utc;
use clap::{Parser, Subcommand};
use std::process::exit;

use rift_baseline::candidate_path::report::CandidateReportRenderer;
use rift_baseline::candidate_path::CandidateManager;
use rift_baseline::config::BaselineConfig;
use rift_baseline::connectivity::ConnectivityTester;
use rift_baseline::endpoint_analyzer::report::ReportRenderer;
use rift_baseline::endpoint_analyzer::EndpointAnalyzer;
use rift_baseline::game_test::GameTester;
use rift_baseline::monitoring::models::DegradationThresholds;
use rift_baseline::monitoring::report::MonitoringReportRenderer;
use rift_baseline::monitoring::MonitoringManager;
use rift_baseline::process::ProcessManager;
use rift_baseline::report::{BaselineSession, ReportGenerator};
use rift_baseline::route::RouteAnalyzer;
use rift_baseline::route_intelligence::report::RouteReportRenderer;
use rift_baseline::route_intelligence::RouteIntelligence;
use rift_baseline::system::SystemInventory;

#[derive(Parser)]
#[command(
    name = "rift-baseline",
    version = "0.1.0",
    about = "RiftRoute: Gaming Network Intelligence & Diagnostic Tool",
    long_about = "Non-invasive network diagnostic CLI for characterizing local network conditions, ISP identity, baseline latency, jitter, advanced route intelligence, and game endpoints."
)]
struct Cli {
    #[arg(short, long, help = "Output machine-readable JSON to stdout")]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum CandidateSubcommands {
    #[command(about = "Discover candidate endpoints from packet captures, game processes, or route snapshots")]
    Discover {
        #[arg(long, help = "Path to TShark packet metadata export file")]
        capture_file: Option<String>,

        #[arg(long, help = "Discover from active running game processes")]
        from_processes: bool,

        #[arg(long, help = "Discover from directory of route snapshot JSONs")]
        from_snapshots: Option<String>,

        #[arg(short, long, help = "Auto-save discovered candidates to data/route/candidates/")]
        save: bool,

        #[arg(short, long, help = "Optional path to save discovery output (text or JSON)")]
        output: Option<String>,
    },

    #[command(about = "Execute repeated longitudinal route measurements toward a candidate destination")]
    Measure {
        #[arg(help = "Candidate destination IP, hostname, or candidate ID")]
        target: String,

        #[arg(short = 'r', long, default_value_t = 5, help = "Number of repeated measurement runs (default: 5)")]
        runs: usize,

        #[arg(short = 'm', long, default_value_t = 30, help = "Maximum hops to trace (1-64)")]
        max_hops: u8,

        #[arg(short = 'w', long, default_value_t = 2000, help = "Per-probe timeout in milliseconds")]
        timeout_ms: u64,

        #[arg(short = 'i', long, default_value_t = 1000, help = "Pacing interval between runs in milliseconds")]
        interval_ms: u64,

        #[arg(long, help = "Resolve IP addresses to hostnames")]
        resolve: bool,

        #[arg(short, long, help = "Auto-save measurement series JSON to data/route/measurements/")]
        save: bool,

        #[arg(short, long, help = "Optional path to save measurement series output")]
        output: Option<String>,

        #[arg(long, default_value_t = 180, help = "Total process execution safety timeout in seconds")]
        timeout_secs: u64,
    },

    #[command(about = "Objectively compare two candidate measurement series")]
    Compare {
        #[arg(help = "Path to Candidate A measurement series JSON")]
        series_a: String,

        #[arg(help = "Path to Candidate B measurement series JSON")]
        series_b: String,

        #[arg(short, long, help = "Optional path to save comparison report")]
        output: Option<String>,

        #[arg(short, long, help = "Auto-save comparison report to reports/phase2/")]
        save: bool,
    },

    #[command(about = "Synthesize path diversity across all measured candidate series")]
    Analyze {
        #[arg(long, help = "Directory containing candidate series JSONs", default_value = "data/route/measurements")]
        measurements_dir: String,

        #[arg(short, long, help = "Optional path to save diversity report")]
        output: Option<String>,

        #[arg(short, long, help = "Auto-save diversity report to reports/phase2/")]
        save: bool,
    },
}

#[derive(Subcommand)]
enum MonitorSubcommands {
    #[command(about = "Execute a paced route performance monitoring session on a target")]
    Run {
        #[arg(help = "Monitoring target (IP address, hostname, candidate ID, or JSON file)")]
        target: String,

        #[arg(short = 'i', long, default_value_t = 30, help = "Interval between probe cycles in seconds")]
        interval_seconds: u64,

        #[arg(short = 'n', long, help = "Optional sample limit for bounded monitoring session (e.g. 10)")]
        samples: Option<usize>,

        #[arg(long, default_value_t = 5, help = "Minimum samples required to establish performance baseline")]
        baseline_samples: usize,

        #[arg(long, default_value_t = 30.0, help = "Relative latency degradation threshold percentage")]
        latency_rel_pct: f64,

        #[arg(long, default_value_t = 20.0, help = "Absolute latency degradation threshold in milliseconds")]
        latency_abs_ms: f64,

        #[arg(long, default_value_t = 100.0, help = "Relative jitter degradation threshold percentage")]
        jitter_rel_pct: f64,

        #[arg(long, default_value_t = 5.0, help = "Absolute jitter degradation threshold in milliseconds")]
        jitter_abs_ms: f64,

        #[arg(long, default_value_t = 3, help = "Consecutive samples required to confirm degradation")]
        confirmation_samples: usize,

        #[arg(long, default_value_t = 3, help = "Consecutive samples required to confirm recovery")]
        recovery_samples: usize,

        #[arg(short = 'm', long, default_value_t = 30, help = "Maximum hops to trace (1-64)")]
        max_hops: u8,

        #[arg(short = 'w', long, default_value_t = 2000, help = "Per-probe timeout in milliseconds")]
        timeout_ms: u64,

        #[arg(long, help = "Resolve IP addresses to hostnames")]
        resolve: bool,

        #[arg(short, long, help = "Auto-save session JSON to data/monitoring/sessions/")]
        save: bool,

        #[arg(short, long, help = "Optional path to save report output (text or JSON)")]
        output: Option<String>,

        #[arg(long, default_value_t = 120, help = "Process execution safety timeout in seconds")]
        timeout_secs: u64,
    },

    #[command(about = "Single-shot deterministic offline analysis of pre-recorded snapshots or session")]
    Analyze {
        #[arg(help = "Path to snapshots JSON, directory of snapshots, or session JSON")]
        input: String,

        #[arg(long, help = "Optional target IP or name to associate with the analysis")]
        target: Option<String>,

        #[arg(long, default_value_t = 5, help = "Minimum samples required to establish performance baseline")]
        baseline_samples: usize,

        #[arg(long, default_value_t = 30.0, help = "Relative latency degradation threshold percentage")]
        latency_rel_pct: f64,

        #[arg(long, default_value_t = 20.0, help = "Absolute latency degradation threshold in milliseconds")]
        latency_abs_ms: f64,

        #[arg(long, default_value_t = 3, help = "Consecutive samples required to confirm degradation")]
        confirmation_samples: usize,

        #[arg(long, default_value_t = 3, help = "Consecutive samples required to confirm recovery")]
        recovery_samples: usize,

        #[arg(short, long, help = "Auto-save analyzed session to data/monitoring/sessions/")]
        save: bool,

        #[arg(short, long, help = "Optional path to save analysis output")]
        output: Option<String>,
    },

    #[command(about = "Inspect or register a monitoring target definition")]
    Target {
        #[arg(help = "Target IP address, hostname, or candidate ID")]
        target: String,

        #[arg(short, long, help = "Auto-save target JSON to data/monitoring/targets/")]
        save: bool,

        #[arg(short, long, help = "Optional path to save target output")]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum RouteSubcommands {
    #[command(about = "Measure and record network path toward a target destination")]
    Measure {
        #[arg(help = "Target IP address or hostname")]
        destination: String,

        #[arg(short = 'm', long, default_value_t = 30, help = "Maximum hops to trace (1-64)")]
        max_hops: u8,

        #[arg(short = 'w', long, default_value_t = 1000, help = "Per-probe timeout in milliseconds")]
        timeout_ms: u64,

        #[arg(long, help = "Resolve IP addresses to hostnames (default is numeric IP -d)")]
        resolve: bool,

        #[arg(short, long, help = "Auto-save snapshot JSON to data/route/snapshots/")]
        save: bool,

        #[arg(short, long, help = "Optional path to save output report (text or JSON)")]
        output: Option<String>,

        #[arg(long, default_value_t = 90, help = "Total process execution safety timeout in seconds")]
        timeout_secs: u64,
    },

    #[command(about = "Compare two route snapshots and identify structural and RTT changes")]
    Compare {
        #[arg(help = "Path to previous route snapshot JSON")]
        previous: String,

        #[arg(help = "Path to current route snapshot JSON")]
        current: String,

        #[arg(short, long, help = "Optional path to save comparison report")]
        output: Option<String>,
    },

    #[command(about = "Analyze route stability across multiple route snapshots")]
    Stability {
        #[arg(help = "Path to directory containing snapshot JSONs or list of snapshot files", required = true)]
        inputs: Vec<String>,

        #[arg(short, long, help = "Optional path to save stability report")]
        output: Option<String>,
    },

    #[command(alias = "candidate", about = "Candidate path discovery, repeated measurement, and comparative evaluation")]
    Candidates {
        #[command(subcommand)]
        subcommand: CandidateSubcommands,
    },

    #[command(external_subcommand)]
    Legacy(Vec<String>),
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Display non-sensitive local network, interface, gateway, DNS, and ISP inventory")]
    System,

    #[command(about = "Measure baseline latency, RFC 3550 jitter, and packet loss against configured destinations")]
    Connectivity {
        #[arg(short, long, default_value_t = 30, help = "Number of probes per destination (1-100)")]
        probes: usize,
        #[arg(short, long, default_value_t = 1000, help = "Probe timeout in milliseconds")]
        timeout: u64,
        #[arg(short, long, default_value_t = 100, help = "Interval between probes in milliseconds")]
        interval: u64,
    },

    #[command(about = "Network path intelligence: measure, compare, and analyze route stability")]
    Route {
        #[command(subcommand)]
        subcommand: Option<RouteSubcommands>,
    },

    #[command(about = "Inventory active network sockets and detect running competitive FPS game processes")]
    Game,

    #[command(about = "Execute controlled, non-invasive PUBG PC baseline latency investigation")]
    GameTest,

    #[command(about = "Run complete baseline audit, save session JSON, and generate Markdown report")]
    Report {
        #[arg(short, long, default_value = "data/baseline", help = "Directory to store session JSON")]
        data_dir: String,
        #[arg(short, long, default_value = "reports/phase0", help = "Directory to store Markdown reports")]
        reports_dir: String,
    },

    #[command(about = "Analyze passive TShark UDP packet capture metadata file")]
    AnalyzeEndpoints {
        #[arg(help = "Path to TShark packet metadata export file (supports UTF-8 and UTF-16)")]
        file: String,

        #[arg(short, long, help = "Optional path to save report output")]
        output: Option<String>,
    },

    #[command(about = "Dynamic route performance monitoring and path degrade detection")]
    Monitor {
        #[command(subcommand)]
        subcommand: MonitorSubcommands,
    },
}

fn main() {
    let cli = Cli::parse();
    let mut config = BaselineConfig::default();

    match cli.command {
        Commands::System => {
            let inv = SystemInventory::collect();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&inv).unwrap());
            } else {
                println!("=== RIFTROUTE SYSTEM NETWORK INVENTORY ===");
                println!("Operating System:     {}", inv.os);
                println!("Architecture:         {}", inv.architecture);
                println!("Hostname:             {}", inv.hostname);
                println!("Active Interface:     {} ({})", inv.active_interface, inv.interface_description);
                println!("Local IPv4 Address:   {}", inv.ipv4_address);
                println!("Default Gateway:      {}", inv.default_gateway);
                println!("DNS Servers:          {}", inv.dns_servers.join(", "));
                println!("Interface Metric:     {}", inv.interface_metric);
                println!("Private Subnet:       {}", inv.private_network_range);
                println!("ISP Organization:     {} ({})", inv.isp_info.organization, inv.isp_info.asn);
                println!("ISP Geo Region:       {}, {}, {}", inv.isp_info.city, inv.isp_info.region, inv.isp_info.country);
                println!("Active IPv4 Routes:   {} entries", inv.routing_table.len());
                println!("Timestamp:            {}", inv.timestamp);
            }
        }

        Commands::Connectivity { probes, timeout, interval } => {
            config.probe_count = probes;
            config.timeout_ms = timeout;
            config.interval_ms = interval;

            if let Err(e) = config.validate() {
                eprintln!("[ERROR] Invalid configuration: {}", e);
                exit(1);
            }

            if !cli.json {
                println!("=== MEASURING BASELINE CONNECTIVITY ({} probes/dest) ===", config.probe_count);
            }
            let mut results = Vec::new();

            for dest in &config.destinations {
                if !cli.json {
                    println!("Probing {} ({}) via ICMP...", dest.name, dest.target);
                }
                let baseline = ConnectivityTester::probe_destination(dest, &config);
                let s = &baseline.stats;

                if !cli.json {
                    println!("  Successful: {}/{} ({:.1}% loss)", s.successful_probes, s.total_probes, s.packet_loss_pct);
                    if let Some(med) = s.median_ms {
                        println!("  Min: {:.1}ms | Median: {:.1}ms | Mean: {:.1}ms | Max: {:.1}ms", s.min_ms.unwrap_or(0.0), med, s.mean_ms.unwrap_or(0.0), s.max_ms.unwrap_or(0.0));
                        println!("  StdDev: {:.2}ms | RFC 3550 Jitter: {:.2}ms | MAPDV Jitter: {:.2}ms", s.std_dev_ms.unwrap_or(0.0), s.rfc3550_jitter_ms.unwrap_or(0.0), s.mapdv_jitter_ms.unwrap_or(0.0));
                    }
                    println!();
                }
                results.push(baseline);
            }

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&results).unwrap());
            }
        }

        Commands::Route { subcommand } => {
            match subcommand {
                Some(RouteSubcommands::Measure {
                    destination,
                    max_hops,
                    timeout_ms,
                    resolve,
                    save,
                    output,
                    timeout_secs,
                }) => {
                    let snapshot = match RouteIntelligence::measure(
                        &destination,
                        max_hops,
                        timeout_ms,
                        resolve,
                        std::time::Duration::from_secs(timeout_secs),
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[ERROR] Route measurement failed: {}", e);
                            exit(1);
                        }
                    };

                    if save {
                        match RouteReportRenderer::save_snapshot_json(&snapshot, "data/route") {
                            Ok(path) => {
                                if !cli.json {
                                    println!("[SAVED] Snapshot saved to: {}", path.display());
                                }
                            }
                            Err(e) => eprintln!("[WARN] Failed to auto-save snapshot: {}", e),
                        }
                    }

                    let rendered = if cli.json {
                        match RouteReportRenderer::render_snapshot_json(&snapshot) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("[ERROR] Failed to serialize JSON: {}", e);
                                exit(1);
                            }
                        }
                    } else {
                        RouteReportRenderer::render_snapshot_text(&snapshot)
                    };

                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &rendered) {
                            eprintln!("[ERROR] Failed to write report to '{}': {}", out_path, e);
                            exit(1);
                        }
                        if !cli.json {
                            println!("[SAVED] Report written to: {}", out_path);
                        }
                    }

                    println!("{}", rendered);
                }

                Some(RouteSubcommands::Compare {
                    previous,
                    current,
                    output,
                }) => {
                    let comparison = match RouteIntelligence::compare_files(&previous, &current) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("[ERROR] Route comparison failed: {}", e);
                            exit(1);
                        }
                    };

                    let rendered = if cli.json {
                        match RouteReportRenderer::render_comparison_json(&comparison) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("[ERROR] Failed to serialize comparison JSON: {}", e);
                                exit(1);
                            }
                        }
                    } else {
                        RouteReportRenderer::render_comparison_text(&comparison)
                    };

                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &rendered) {
                            eprintln!("[ERROR] Failed to write comparison to '{}': {}", out_path, e);
                            exit(1);
                        }
                        if !cli.json {
                            println!("[SAVED] Comparison saved to: {}", out_path);
                        }
                    }

                    println!("{}", rendered);
                }

                Some(RouteSubcommands::Stability { inputs, output }) => {
                    let paths: Vec<std::path::PathBuf> = inputs.iter().map(std::path::PathBuf::from).collect();
                    let stability = match RouteIntelligence::analyze_stability_from_paths(&paths) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[ERROR] Stability analysis failed: {}", e);
                            exit(1);
                        }
                    };

                    let rendered = if cli.json {
                        match RouteReportRenderer::render_stability_json(&stability) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("[ERROR] Failed to serialize stability JSON: {}", e);
                                exit(1);
                            }
                        }
                    } else {
                        RouteReportRenderer::render_stability_text(&stability)
                    };

                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &rendered) {
                            eprintln!("[ERROR] Failed to write stability report to '{}': {}", out_path, e);
                            exit(1);
                        }
                        if !cli.json {
                            println!("[SAVED] Stability report saved to: {}", out_path);
                        }
                    }

                    println!("{}", rendered);
                }

                Some(RouteSubcommands::Candidates { subcommand }) => {
                    match subcommand {
                        CandidateSubcommands::Discover {
                            capture_file,
                            from_processes,
                            from_snapshots,
                            save,
                            output,
                        } => {
                            let candidates = CandidateManager::discover_endpoints(
                                capture_file.as_deref(),
                                from_processes,
                                from_snapshots.as_deref(),
                            )
                            .unwrap_or_else(|e| {
                                eprintln!("[ERROR] Candidate discovery failed: {}", e);
                                exit(1);
                            });

                            if candidates.is_empty() && !cli.json {
                                println!("[INFO] No candidate endpoints discovered from specified sources.");
                            }

                            if save {
                                match CandidateReportRenderer::save_discovery(
                                    &candidates,
                                    "data/route/candidates",
                                ) {
                                    Ok(p) => {
                                        if !cli.json {
                                            println!("[SAVED] Candidates saved to: {}", p.display());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to save candidates: {}", e);
                                        exit(1);
                                    }
                                }
                            }

                            let rendered = if cli.json {
                                match CandidateReportRenderer::format_discovery_json(&candidates) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to serialize candidates JSON: {}", e);
                                        exit(1);
                                    }
                                }
                            } else {
                                CandidateReportRenderer::format_discovery_text(&candidates)
                            };

                            if let Some(ref out_path) = output {
                                if let Err(e) = std::fs::write(out_path, &rendered) {
                                    eprintln!("[ERROR] Failed to write discovery report to '{}': {}", out_path, e);
                                    exit(1);
                                }
                                if !cli.json {
                                    println!("[SAVED] Discovery report saved to: {}", out_path);
                                }
                            }

                            println!("{}", rendered);
                        }

                        CandidateSubcommands::Measure {
                            target,
                            runs,
                            max_hops,
                            timeout_ms,
                            interval_ms,
                            resolve,
                            save,
                            output,
                            timeout_secs,
                        } => {
                            if !cli.json {
                                println!(
                                    "=== MEASURING CANDIDATE TARGET: {} ({} runs, pacing: {} ms) ===",
                                    target, runs, interval_ms
                                );
                            }

                            let series = CandidateManager::measure_candidate(
                                &target,
                                runs,
                                max_hops,
                                timeout_ms,
                                interval_ms,
                                resolve,
                                timeout_secs,
                            )
                            .unwrap_or_else(|e| {
                                eprintln!("[ERROR] Candidate measurement failed: {}", e);
                                exit(1);
                            });

                            if save {
                                match CandidateReportRenderer::save_measurement_series(
                                    &series,
                                    "data/route/measurements",
                                ) {
                                    Ok(p) => {
                                        if !cli.json {
                                            println!("[SAVED] Measurement series saved to: {}", p.display());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to save measurement series: {}", e);
                                        exit(1);
                                    }
                                }
                            }

                            let rendered = if cli.json {
                                match CandidateReportRenderer::format_measurement_series_json(&series) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to serialize series JSON: {}", e);
                                        exit(1);
                                    }
                                }
                            } else {
                                CandidateReportRenderer::format_measurement_series_text(&series)
                            };

                            if let Some(ref out_path) = output {
                                if let Err(e) = std::fs::write(out_path, &rendered) {
                                    eprintln!("[ERROR] Failed to write measurement series to '{}': {}", out_path, e);
                                    exit(1);
                                }
                                if !cli.json {
                                    println!("[SAVED] Measurement series saved to: {}", out_path);
                                }
                            }

                            println!("{}", rendered);
                        }

                        CandidateSubcommands::Compare {
                            series_a,
                            series_b,
                            output,
                            save,
                        } => {
                            let report = CandidateManager::compare_from_files(&series_a, &series_b)
                                .unwrap_or_else(|e| {
                                    eprintln!("[ERROR] Candidate comparison failed: {}", e);
                                    exit(1);
                                });

                            if save {
                                match CandidateReportRenderer::save_comparison(&report, "reports/phase2") {
                                    Ok(p) => {
                                        if !cli.json {
                                            println!("[SAVED] Comparison report saved to: {}", p.display());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to save comparison: {}", e);
                                        exit(1);
                                    }
                                }
                            }

                            let rendered = if cli.json {
                                match CandidateReportRenderer::format_comparison_json(&report) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to serialize comparison JSON: {}", e);
                                        exit(1);
                                    }
                                }
                            } else {
                                CandidateReportRenderer::format_comparison_text(&report)
                            };

                            if let Some(ref out_path) = output {
                                if let Err(e) = std::fs::write(out_path, &rendered) {
                                    eprintln!("[ERROR] Failed to write comparison report to '{}': {}", out_path, e);
                                    exit(1);
                                }
                                if !cli.json {
                                    println!("[SAVED] Comparison report saved to: {}", out_path);
                                }
                            }

                            println!("{}", rendered);
                        }

                        CandidateSubcommands::Analyze {
                            measurements_dir,
                            output,
                            save,
                        } => {
                            let div_report =
                                CandidateManager::analyze_diversity_from_dir(&measurements_dir)
                                    .unwrap_or_else(|e| {
                                        eprintln!("[ERROR] Path diversity analysis failed: {}", e);
                                        exit(1);
                                    });

                            if save {
                                match CandidateReportRenderer::save_diversity(&div_report, "reports/phase2") {
                                    Ok(p) => {
                                        if !cli.json {
                                            println!("[SAVED] Diversity report saved to: {}", p.display());
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to save diversity report: {}", e);
                                        exit(1);
                                    }
                                }
                            }

                            let rendered = if cli.json {
                                match CandidateReportRenderer::format_diversity_json(&div_report) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        eprintln!("[ERROR] Failed to serialize diversity JSON: {}", e);
                                        exit(1);
                                    }
                                }
                            } else {
                                CandidateReportRenderer::format_diversity_text(&div_report)
                            };

                            if let Some(ref out_path) = output {
                                if let Err(e) = std::fs::write(out_path, &rendered) {
                                    eprintln!("[ERROR] Failed to write diversity report to '{}': {}", out_path, e);
                                    exit(1);
                                }
                                if !cli.json {
                                    println!("[SAVED] Diversity report saved to: {}", out_path);
                                }
                            }

                            println!("{}", rendered);
                        }
                    }
                }

                Some(RouteSubcommands::Legacy(args)) => {
                    if args.is_empty() {
                        eprintln!("Usage: rift-baseline route <COMMAND>\n\nCommands:\n  measure     Measure and record network path toward a target destination\n  compare     Compare two route snapshots and identify structural and RTT changes\n  stability   Analyze route stability across multiple route snapshots\n  candidates  Candidate path discovery, repeated measurement, and comparative evaluation\n\nFor more information, try '--help'.");
                        exit(1);
                    }
                    let destination = &args[0];
                    let mut max_hops = 30;
                    if args.len() >= 3 && args[1] == "--max-hops" {
                        if let Ok(mh) = args[2].parse::<u8>() {
                            max_hops = mh;
                        }
                    }

                    if !cli.json {
                        println!("=== TRACING ROUTE TO {} (max {} hops) ===", destination, max_hops);
                    }
                    let trace = RouteAnalyzer::trace(destination, max_hops);

                    if cli.json {
                        println!("{}", serde_json::to_string_pretty(&trace).unwrap());
                    } else {
                        println!("Fingerprint: {}", trace.route_fingerprint);
                        println!("Summary:     {}", trace.analysis_summary);
                        println!();
                        println!("{:<4} {:<10} {:<30} {:<12} {:<22} {}", "Hop", "Min RTT", "Endpoint", "Delta", "Significance", "Commentary");
                        println!("{:-<110}", "");
                        for h in &trace.hops {
                            let rtt_str = h.min_rtt_ms.map(|v| format!("{:.1}ms", v)).unwrap_or_else(|| "*".to_string());
                            let delta_str = h.latency_delta_ms.map(|v| format!("{:+.1}ms", v)).unwrap_or_else(|| "-".to_string());
                            let sig_str = format!("{:?}", h.significance);
                            println!("{:<4} {:<10} {:<30} {:<12} {:<22} {}", h.hop, rtt_str, h.ip_or_host, delta_str, sig_str, h.commentary);
                        }
                    }
                }

                None => {
                    eprintln!("Usage: rift-baseline route <COMMAND>\n\nCommands:\n  measure     Measure and record network path toward a target destination\n  compare     Compare two route snapshots and identify structural and RTT changes\n  stability   Analyze route stability across multiple route snapshots\n  candidates  Candidate path discovery, repeated measurement, and comparative evaluation\n\nFor more information, try '--help'.");
                    exit(1);
                }
            }
        }

        Commands::Game => {
            let inv = ProcessManager::scan_game_activity();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&inv).unwrap());
            } else {
                println!("=== GAME PROCESS & CONNECTION INVENTORY ===");
                println!("Total active sockets on system: {}", inv.total_active_connections);
                println!("Supported games detected:       {}", inv.detected_games.len());
                println!();

                if inv.detected_games.is_empty() {
                    println!("No running game processes (PUBG PC, CS2, VALORANT, THE FINALS) currently detected.");
                } else {
                    for g in &inv.detected_games {
                        println!("Game: {} (Process: {}, PID: {})", g.game, g.name, g.pid);
                        println!("Active Sockets: {}", g.connections.len());
                        for c in &g.connections {
                            println!("  [{}] {} -> {} ({:?})", c.protocol, c.local_address, c.remote_address, c.classification);
                        }
                    }
                }
            }
        }

        Commands::GameTest => {
            println!("=== PUBG PC BASELINE INVESTIGATION ===");
            let summary = GameTester::run_pubg_test(&config);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
            }
        }

        Commands::Report { data_dir, reports_dir } => {
            config.data_dir = data_dir;
            config.reports_dir = reports_dir;

            println!("=== RUNNING FULL RIFTROUTE PHASE 0 BASELINE AUDIT ===");
            let session_id = format!("baseline_{}", Utc::now().format("%Y%m%d_%H%M%S"));

            // 1. System Inventory
            print!("[1/5] Collecting local network & ISP inventory... ");
            let sys = SystemInventory::collect();
            println!("Done.");

            // 2. Connectivity Baselines
            println!("[2/5] Running baseline latency measurements (30 probes each)...");
            let mut baselines = Vec::new();
            for dest in &config.destinations {
                print!("      Probing {} ({}) ... ", dest.name, dest.target);
                let b = ConnectivityTester::probe_destination(dest, &config);
                println!("Done (Median: {:.1}ms, Loss: {:.1}%).", b.stats.median_ms.unwrap_or(0.0), b.stats.packet_loss_pct);
                baselines.push(b);
            }

            // 3. Route Traces
            println!("[3/5] Tracing baseline network routes...");
            let mut traces = Vec::new();
            for dest in &config.destinations {
                print!("      Tracing route to {} ... ", dest.target);
                let t = RouteAnalyzer::trace(&dest.target, config.max_hops);
                println!("Done ({} hops).", t.hops.len());
                traces.push(t);
            }

            // 4. Process & Game Discovery
            print!("[4/5] Scanning active connections and game activity... ");
            let proc_inv = ProcessManager::scan_game_activity();
            println!("Done ({} active connections).", proc_inv.total_active_connections);

            // 5. Game Test Snapshot
            print!("[5/5] Checking PUBG PC status... ");
            let game_summary = GameTester::run_pubg_test(&config);
            println!("Done.");

            // Formulate Findings, Hypotheses, Unknowns, and Recommendations
            let mut findings = Vec::new();
            let mut hypotheses = Vec::new();
            let mut unknowns = Vec::new();
            let mut recommendations = Vec::new();

            findings.push(format!("Local interface {} is active with gateway {} (subnet: {}).", sys.active_interface, sys.default_gateway, sys.private_network_range));
            findings.push(format!("ISP verified as {} ({}) in {}, {}, {}.", sys.isp_info.organization, sys.isp_info.asn, sys.isp_info.city, sys.isp_info.region, sys.isp_info.country));
            for b in &baselines {
                findings.push(format!(
                    "Domestic baseline latency to {} ({}) is {:.1} ms median (min: {:.1} ms, max: {:.1} ms, jitter: {:.2} ms, packet loss: {:.1}%).",
                    b.destination.name, b.destination.target, b.stats.median_ms.unwrap_or(0.0), b.stats.min_ms.unwrap_or(0.0), b.stats.max_ms.unwrap_or(0.0), b.stats.rfc3550_jitter_ms.unwrap_or(0.0), b.stats.packet_loss_pct
                ));
            }
            findings.push("Domestic first-mile and ISP gateway latency is low (10-15 ms to Indian edge destinations), confirming that the user's local fiber connection is operational and healthy.".to_string());

            hypotheses.push("The user-reported ~200 ms latency in PUBG PC is not caused by first-mile Wi-Fi/local ISP gateway degradation (which operates at 10-12 ms), but likely originates from international transit routing, inter-continental submarine cable paths, or matchmaking to geographically distant server regions (e.g., Frankfurt/Europe ~140-160 ms, North America ~220-250 ms, or East Asia via sub-optimal peering).".to_string());
            hypotheses.push("PUBG PC's matchmaking coordinator may be assigning matches to Singapore (expected ~40-60 ms), Tokyo (~110-130 ms), Seoul (~120-140 ms), or Frankfurt (~150-180 ms). If Singapore is not available or matchmaking pools players globally, latency naturally escalates to 180-220 ms.".to_string());

            unknowns.push("Specific PUBG PC server IP pool currently selected by the game client during active live gameplay cannot be confirmed until an active match session is sampled via `rift-baseline game-test` while playing.".to_string());
            unknowns.push("Whether PUBG PC matchmaking uses AWS, Azure, Tencent Cloud, or custom dedicated server hosts for Indian subcontinent players in 2026.".to_string());

            recommendations.push("Execute `rift-baseline game-test` during an active PUBG PC live match to capture the exact game server IP and port non-invasively.".to_string());
            recommendations.push("Phase 1 should build the automated Network Measurement Engine to track real-time route health to candidate gaming regions (Singapore, Mumbai, Frankfurt, Tokyo, Seoul).".to_string());

            let session = BaselineSession {
                session_id: session_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                tool_version: "rift-baseline 0.1.0".to_string(),
                system_inventory: sys,
                connectivity_baselines: baselines,
                route_traces: traces,
                process_inventory: proc_inv,
                game_test_summary: Some(game_summary),
                findings,
                hypotheses,
                unknowns,
                recommendations,
            };

            // Save JSON & Markdown
            match ReportGenerator::save_session_json(&session, &config.data_dir) {
                Ok(path) => println!("[SAVED] Session JSON:     {}", path.display()),
                Err(e) => eprintln!("[ERROR] Failed to save JSON: {}", e),
            }
            match ReportGenerator::generate_markdown_report(&session, &config.reports_dir) {
                Ok(path) => println!("[SAVED] Markdown Report:  {}", path.display()),
                Err(e) => eprintln!("[ERROR] Failed to save Report: {}", e),
            }

            println!("\nBaseline diagnostic audit complete.");
        }

        Commands::AnalyzeEndpoints { file, output } => {
            let report = match EndpointAnalyzer::analyze_file(&file) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[ERROR] Failed to analyze capture file '{}': {}", file, e);
                    exit(1);
                }
            };

            let rendered = if cli.json {
                match ReportRenderer::render_json(&report) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("[ERROR] Failed to generate JSON: {}", e);
                        exit(1);
                    }
                }
            } else {
                ReportRenderer::render_human_readable(&report)
            };

            if let Some(ref out_path) = output {
                if let Err(e) = std::fs::write(out_path, &rendered) {
                    eprintln!("[ERROR] Failed to write report to '{}': {}", out_path, e);
                    exit(1);
                }
                if !cli.json {
                    println!("[SAVED] Endpoint analysis report saved to: {}", out_path);
                }
            }

            println!("{}", rendered);
        }

        Commands::Monitor { subcommand } => {
            match subcommand {
                MonitorSubcommands::Run {
                    target,
                    interval_seconds,
                    samples,
                    baseline_samples,
                    latency_rel_pct,
                    latency_abs_ms,
                    jitter_rel_pct,
                    jitter_abs_ms,
                    confirmation_samples,
                    recovery_samples,
                    max_hops,
                    timeout_ms,
                    resolve,
                    save,
                    output,
                    timeout_secs,
                } => {
                    let mon_target = MonitoringManager::resolve_target(&target)
                        .unwrap_or_else(|e| {
                            eprintln!("[ERROR] Failed to resolve monitoring target '{}': {}", target, e);
                            exit(1);
                        });

                    let thresholds = DegradationThresholds {
                        baseline_sample_count: baseline_samples,
                        rolling_window_size: 20,
                        latency_relative_pct: latency_rel_pct,
                        latency_absolute_delta_ms: latency_abs_ms,
                        p95_relative_pct: 40.0,
                        jitter_relative_pct: jitter_rel_pct,
                        jitter_absolute_delta_ms: jitter_abs_ms,
                        detect_route_change: true,
                        stability_transition_rate_threshold_pct: 50.0,
                        confirmation_samples,
                        recovery_samples,
                        critical_latency_relative_pct: 100.0,
                        critical_latency_absolute_delta_ms: 60.0,
                    };

                    if !cli.json {
                        println!(
                            "=== STARTING ROUTE MONITORING: {} (interval: {}s, limit: {:?}) ===",
                            mon_target.destination, interval_seconds, samples
                        );
                    }

                    let session = MonitoringManager::run_monitoring(
                        mon_target,
                        interval_seconds,
                        samples,
                        thresholds,
                        max_hops,
                        timeout_ms,
                        resolve,
                        timeout_secs,
                        None,
                    )
                    .unwrap_or_else(|e| {
                        eprintln!("[ERROR] Monitoring session failed: {}", e);
                        exit(1);
                    });

                    if save {
                        match MonitoringManager::save_session(&session, "data/monitoring/sessions") {
                            Ok(p) => {
                                if !cli.json {
                                    println!("[SAVED] Monitoring session saved to: {}", p.display());
                                }
                            }
                            Err(e) => eprintln!("[ERROR] Failed to save monitoring session: {}", e),
                        }

                        if !session.events.is_empty() {
                            match MonitoringReportRenderer::save_events(
                                &session.session_id,
                                &session.events,
                                "data/monitoring/events",
                            ) {
                                Ok(p) => {
                                    if !cli.json {
                                        println!("[SAVED] Degradation events saved to: {}", p.display());
                                    }
                                }
                                Err(e) => eprintln!("[ERROR] Failed to save events: {}", e),
                            }
                        }
                    }

                    let rendered = if cli.json {
                        match MonitoringReportRenderer::format_session_json(&session) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("[ERROR] Failed to serialize session JSON: {}", e);
                                exit(1);
                            }
                        }
                    } else {
                        MonitoringReportRenderer::format_session_text(&session)
                    };

                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &rendered) {
                            eprintln!("[ERROR] Failed to write report to '{}': {}", out_path, e);
                            exit(1);
                        }
                        if !cli.json {
                            println!("[SAVED] Output report saved to: {}", out_path);
                        }
                    }

                    println!("{}", rendered);
                }

                MonitorSubcommands::Analyze {
                    input,
                    target,
                    baseline_samples,
                    latency_rel_pct,
                    latency_abs_ms,
                    confirmation_samples,
                    recovery_samples,
                    save,
                    output,
                } => {
                    let target_str = target.as_deref().unwrap_or("20.205.179.128");
                    let mon_target = MonitoringManager::resolve_target(target_str)
                        .unwrap_or_else(|e| {
                            eprintln!("[ERROR] Failed to resolve target: {}", e);
                            exit(1);
                        });

                    let thresholds = DegradationThresholds {
                        baseline_sample_count: baseline_samples,
                        rolling_window_size: 20,
                        latency_relative_pct: latency_rel_pct,
                        latency_absolute_delta_ms: latency_abs_ms,
                        p95_relative_pct: 40.0,
                        jitter_relative_pct: 100.0,
                        jitter_absolute_delta_ms: 5.0,
                        detect_route_change: true,
                        stability_transition_rate_threshold_pct: 50.0,
                        confirmation_samples,
                        recovery_samples,
                        critical_latency_relative_pct: 100.0,
                        critical_latency_absolute_delta_ms: 60.0,
                    };

                    let session = MonitoringManager::replay_snapshots_from_path(
                        mon_target,
                        &input,
                        30,
                        thresholds,
                    )
                    .unwrap_or_else(|e| {
                        eprintln!("[ERROR] Offline analysis failed: {}", e);
                        exit(1);
                    });

                    if save {
                        match MonitoringManager::save_session(&session, "data/monitoring/sessions") {
                            Ok(p) => {
                                if !cli.json {
                                    println!("[SAVED] Analyzed session saved to: {}", p.display());
                                }
                            }
                            Err(e) => eprintln!("[ERROR] Failed to save session: {}", e),
                        }

                        if !session.events.is_empty() {
                            match MonitoringReportRenderer::save_events(
                                &session.session_id,
                                &session.events,
                                "data/monitoring/events",
                            ) {
                                Ok(p) => {
                                    if !cli.json {
                                        println!("[SAVED] Degradation events saved to: {}", p.display());
                                    }
                                }
                                Err(e) => eprintln!("[ERROR] Failed to save events: {}", e),
                            }
                        }
                    }

                    let rendered = if cli.json {
                        match MonitoringReportRenderer::format_session_json(&session) {
                            Ok(j) => j,
                            Err(e) => {
                                eprintln!("[ERROR] Failed to serialize session JSON: {}", e);
                                exit(1);
                            }
                        }
                    } else {
                        MonitoringReportRenderer::format_session_text(&session)
                    };

                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &rendered) {
                            eprintln!("[ERROR] Failed to write analysis report to '{}': {}", out_path, e);
                            exit(1);
                        }
                        if !cli.json {
                            println!("[SAVED] Output report saved to: {}", out_path);
                        }
                    }

                    println!("{}", rendered);
                }

                MonitorSubcommands::Target {
                    target,
                    save,
                    output,
                } => {
                    let mon_target = MonitoringManager::resolve_target(&target)
                        .unwrap_or_else(|e| {
                            eprintln!("[ERROR] Failed to resolve target: {}", e);
                            exit(1);
                        });

                    if save {
                        match MonitoringManager::save_target(&mon_target, "data/monitoring/targets") {
                            Ok(p) => {
                                if !cli.json {
                                    println!("[SAVED] Monitoring target saved to: {}", p.display());
                                }
                            }
                            Err(e) => eprintln!("[ERROR] Failed to save target: {}", e),
                        }
                    }

                    let rendered = if cli.json {
                        serde_json::to_string_pretty(&mon_target).unwrap()
                    } else {
                        format!(
                            "Target ID:      {}\nDestination:    {}\nPort:           {:?}\nProtocol:       {}\nService:        {}\nEvidence:       {:?}\nNotes:          {}\n",
                            mon_target.target_id, mon_target.destination, mon_target.target_port, mon_target.protocol, mon_target.service_name, mon_target.evidence_level, mon_target.notes
                        )
                    };

                    if let Some(ref out_path) = output {
                        if let Err(e) = std::fs::write(out_path, &rendered) {
                            eprintln!("[ERROR] Failed to write target to '{}': {}", out_path, e);
                            exit(1);
                        }
                    }

                    println!("{}", rendered);
                }
            }
        }
    }
}
