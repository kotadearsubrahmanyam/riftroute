use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

use super::models::{DegradationEvent, MonitoringSession, MonitoringTarget};

/// Renderer for monitoring sessions, performance degradation events, and diagnostic summaries.
pub struct MonitoringReportRenderer;

impl MonitoringReportRenderer {
    pub fn format_session_text(session: &MonitoringSession) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                     RIFTROUTE ROUTE MONITORING REPORT                          \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Session ID:              {}\n", session.session_id));
        out.push_str(&format!("Target ID:               {}\n", session.target.target_id));
        let ep = match session.target.target_port {
            Some(p) => format!("{}:{}", session.target.destination, p),
            None => session.target.destination.clone(),
        };
        out.push_str(&format!("Endpoint:                {}\n", ep));
        out.push_str(&format!("Service:                 {}\n", session.target.service_name));
        out.push_str(&format!("Evidence Level:          {:?}\n", session.target.evidence_level));
        out.push_str(&format!("Sample Interval:         {}s\n", session.interval_seconds));
        out.push_str(&format!("Total Samples:           {}\n", session.total_samples_collected));
        out.push_str(&format!(
            "Session Window:          {} -> {}\n",
            session.start_time_utc,
            session.end_time_utc.as_deref().unwrap_or("Active (Running)")
        ));
        out.push_str(&format!("Current Health State:    {:?}\n\n", session.current_state));

        // Baseline Metrics Section
        out.push_str("ESTABLISHED PERFORMANCE BASELINE:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        if let Some(ref base) = session.baseline {
            out.push_str(&format!("Baseline ID:             {}\n", base.baseline_id));
            out.push_str(&format!("Method:                  {}\n", base.baseline_method));
            out.push_str(&format!("Samples in Baseline:     {}\n", base.sample_count));
            out.push_str(&format!("Median Probe RTT:        {:.2} ms\n", base.median_rtt_ms));
            out.push_str(&format!("p95 Probe RTT:           {:.2} ms\n", base.p95_rtt_ms));
            out.push_str(&format!("p99 Probe RTT:           {:.2} ms\n", base.p99_rtt_ms));
            out.push_str(&format!("Min / Max Probe RTT:     {:.2} ms / {:.2} ms\n", base.min_rtt_ms, base.max_rtt_ms));
            out.push_str(&format!("Std Deviation:           {:.2} ms\n", base.std_dev_ms));
            out.push_str(&format!("MAPDV Probe Jitter:      {:.2} ms\n", base.jitter_ms));
            out.push_str(&format!(
                "Dominant Fingerprint:    {} ({:.1}%)\n",
                base.dominant_fingerprint, base.dominant_fingerprint_pct
            ));
            out.push_str(&format!("Route Transition Rate:   {:.1}%\n", base.route_transition_rate_pct));
            out.push_str(&format!("Hop Count (Median):      {}\n", base.hop_count_median));
            out.push_str(&format!(
                "Contamination Shield:    {}\n\n",
                if base.is_frozen { "FROZEN (Protected against degradation)" } else { "ACTIVE (Rolling adaptation)" }
            ));
        } else {
            out.push_str(&format!(
                "Pending (gathering initial {} valid samples)...\n\n",
                session.thresholds.baseline_sample_count
            ));
        }

        // Latest Observed Metrics Section
        out.push_str("LATEST OBSERVED METRICS:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        if let Some(last) = session.samples.last() {
            let rtt_str = last.final_hop_rtt_ms.map(|v| format!("{:.2} ms", v)).unwrap_or_else(|| "N/A".to_string());
            let jit_str = last.jitter_ms.map(|v| format!("{:.2} ms", v)).unwrap_or_else(|| "N/A".to_string());
            out.push_str(&format!("Timestamp:               {}\n", last.timestamp_utc));
            out.push_str(&format!("Final Hop Probe RTT:     {}\n", rtt_str));
            out.push_str(&format!("Probe Jitter:            {}\n", jit_str));
            out.push_str(&format!("Route Fingerprint:       {}\n", last.route_fingerprint));
            out.push_str(&format!("Hop Count:               {} (Responding: {}, Drop: {})\n", last.hop_count, last.responding_hops, last.timeout_hops));

            if let Some(ref base) = session.baseline {
                if let Some(obs_rtt) = last.final_hop_rtt_ms {
                    let delta = obs_rtt - base.median_rtt_ms;
                    let pct = (delta / base.median_rtt_ms) * 100.0;
                    out.push_str(&format!("Deviation from Baseline: {:+.2} ms ({:+.1}%)\n", delta, pct));
                }
            }
            out.push_str("\n");
        } else {
            out.push_str("No samples recorded.\n\n");
        }

        // Degradation Events Log
        out.push_str("AUDITED DEGRADATION & LIFECYCLE EVENTS:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        if session.events.is_empty() {
            out.push_str("  No degradation events triggered. Network path operating within baseline parameters.\n");
        } else {
            for ev in &session.events {
                out.push_str(&format!(
                    "[{}] {:<22} | Severity: {:<8} | State: {:<10}\n",
                    ev.timestamp_utc,
                    format!("{:?}", ev.event_type),
                    format!("{:?}", ev.severity),
                    format!("{:?}", ev.state)
                ));
                out.push_str(&format!("  -> Evidence:    {}\n", ev.evidence_description));
                if let (Some(b_rtt), Some(o_rtt), Some(d), Some(pct)) = (
                    ev.baseline_median_rtt_ms,
                    ev.observed_median_rtt_ms,
                    ev.median_delta_ms,
                    ev.median_relative_change_pct,
                ) {
                    out.push_str(&format!(
                        "  -> RTT Metric:  Observed {:.2} ms vs Baseline {:.2} ms (Delta: {:+.2} ms, {:+.1}%)\n",
                        o_rtt, b_rtt, d, pct
                    ));
                }
                out.push_str(&format!("  -> Persistence: {} consecutive samples\n", ev.consecutive_count));
            }
        }
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str(&format!(
            "SUMMARY: Degradations Detected: {} | Recoveries: {} | Failures: {}\n\n",
            session.total_degradations_detected,
            session.total_recoveries_detected,
            session.total_failures_encountered
        ));

        out.push_str("SCIENTIFIC DISCLAIMER:\n");
        out.push_str(&session.scientific_disclaimer);
        out.push_str("\n================================================================================\n");
        out
    }

    pub fn format_session_json(session: &MonitoringSession) -> Result<String, String> {
        serde_json::to_string_pretty(session).map_err(|e| e.to_string())
    }

    pub fn format_event_json(event: &DegradationEvent) -> Result<String, String> {
        serde_json::to_string_pretty(event).map_err(|e| e.to_string())
    }

    pub fn format_events_json(events: &[DegradationEvent]) -> Result<String, String> {
        serde_json::to_string_pretty(events).map_err(|e| e.to_string())
    }

    pub fn save_session<P: AsRef<Path>>(
        session: &MonitoringSession,
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!("{}.json", session.session_id);
        let path = dir.join(filename);
        let json = Self::format_session_json(session)?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn save_target<P: AsRef<Path>>(
        target: &MonitoringTarget,
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!("{}.json", target.target_id);
        let path = dir.join(filename);
        let json = serde_json::to_string_pretty(target).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn save_events<P: AsRef<Path>>(
        session_id: &str,
        events: &[DegradationEvent],
        dir: P,
    ) -> Result<PathBuf, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let filename = format!("events_{}_{}.json", session_id, Utc::now().format("%Y%m%d%H%M%S"));
        let path = dir.join(filename);
        let json = Self::format_events_json(events)?;
        fs::write(&path, json).map_err(|e| e.to_string())?;
        Ok(path)
    }
}
