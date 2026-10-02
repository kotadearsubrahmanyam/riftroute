use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::models::{RouteComparison, RouteSnapshot, RouteStabilityReport};

/// Formatting and persistence engine for route intelligence artifacts.
pub struct RouteReportRenderer;

impl RouteReportRenderer {
    /// Render a single route snapshot as human-readable text.
    pub fn render_snapshot_text(snapshot: &RouteSnapshot) -> String {
        let mut out = String::new();

        out.push_str("================================================================================\n");
        out.push_str("                 RiftRoute Network Path Snapshot Report                         \n");
        out.push_str("================================================================================\n\n");

        out.push_str(&format!("Measurement ID:        {}\n", snapshot.measurement_id));
        out.push_str(&format!("Timestamp (UTC):       {}\n", snapshot.timestamp_utc));
        out.push_str(&format!("Target Destination:    {}\n", snapshot.destination));
        if let Some(ref ip) = snapshot.destination_ip {
            out.push_str(&format!("Resolved Target IP:    {}\n", ip));
        }
        out.push_str(&format!("Diagnostic Method:     {}\n", snapshot.probe_method));
        out.push_str(&format!("Active Interface:      {}\n", snapshot.active_interface.as_deref().unwrap_or("Unknown")));
        out.push_str(&format!("Source IPv4:           {}\n", snapshot.source_ipv4.as_deref().unwrap_or("Unknown")));
        out.push_str(&format!("Default Gateway:       {}\n", snapshot.default_gateway.as_deref().unwrap_or("Unknown")));
        out.push_str(&format!("Execution Duration:    {:.2} s\n", snapshot.measurement_duration_ms as f64 / 1000.0));
        out.push_str(&format!("Route Fingerprint:     {}\n", snapshot.fingerprint));
        out.push_str(&format!("Fingerprint SHA-256:   {}\n", snapshot.fingerprint_sha256));
        out.push_str(&format!("Canonical Path:        {}\n\n", snapshot.canonical_path));

        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("Observed Route Hop Progression\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("Hop   Address / Status              Min RTT   Median   Mean RTT   Max RTT   Jitter\n");
        out.push_str("----  ----------------------------  --------  -------  ---------  --------  ------\n");

        for h in &snapshot.hops {
            let addr_label = if h.responded {
                if let Some(ref host) = h.hostname {
                    format!("{} ({})", h.primary_address.as_deref().unwrap_or("?"), host)
                } else {
                    h.primary_address.clone().unwrap_or_else(|| "Unknown".to_string())
                }
            } else {
                format!("* (Timeout - {}/{} probes)", h.timeout_count, h.probe_count)
            };

            if let Some(ref stats) = h.rtt_stats {
                let jitter_str = stats
                    .jitter_ms
                    .map(|j| format!("{:.1} ms", j))
                    .unwrap_or_else(|| "-".to_string());

                out.push_str(&format!(
                    "{:<4}  {:<28}  {:>5.1} ms  {:>5.1} ms  {:>6.1} ms  {:>5.1} ms  {:>6}\n",
                    h.hop_number,
                    truncate_str(&addr_label, 28),
                    stats.min_ms,
                    stats.median_ms,
                    stats.mean_ms,
                    stats.max_ms,
                    jitter_str
                ));
            } else {
                out.push_str(&format!(
                    "{:<4}  {:<28}        -        -          -         -       -\n",
                    h.hop_number,
                    truncate_str(&addr_label, 28)
                ));
            }
        }

        out.push_str("\n--------------------------------------------------------------------------------\n");
        out.push_str("Path Metrics Summary:\n");
        out.push_str(&format!("  Total Hops Observed:    {}\n", snapshot.hop_count));
        out.push_str(&format!("  Responding Hops:        {}\n", snapshot.responding_hops));
        out.push_str(&format!("  Timeout Hops:           {}\n", snapshot.timeout_hops));
        out.push_str("================================================================================\n");
        out.push_str("SCIENTIFIC INTEGRITY DISCLAIMER:\n");
        out.push_str("1. Traceroute probe RTT reflects ICMP Time Exceeded generation latency from router\n");
        out.push_str("   control planes, NOT actual game client-server application latency.\n");
        out.push_str("2. Router timeouts ('*') indicate ICMP rate-limiting or filtering, NOT packet loss.\n");
        out.push_str("3. This measurement observes network topology; it does not alter routing behavior.\n");
        out.push_str("================================================================================\n");

        out
    }

    /// Render route snapshot as formatted JSON.
    pub fn render_snapshot_json(snapshot: &RouteSnapshot) -> Result<String, String> {
        serde_json::to_string_pretty(snapshot)
            .map_err(|e| format!("Failed to serialize route snapshot JSON: {}", e))
    }

    /// Render route comparison report as human-readable text.
    pub fn render_comparison_text(comp: &RouteComparison) -> String {
        let mut out = String::new();

        out.push_str("================================================================================\n");
        out.push_str("                 RiftRoute Network Path Comparison Report                       \n");
        out.push_str("================================================================================\n\n");

        out.push_str(&format!("Destination:           {}\n", comp.destination));
        out.push_str(&format!("Previous Snapshot:     {} ({})\n", comp.previous_id, comp.previous_timestamp));
        out.push_str(&format!("Current Snapshot:      {} ({})\n", comp.current_id, comp.current_timestamp));
        out.push_str(&format!("Previous Fingerprint:  {}\n", comp.previous_fingerprint));
        out.push_str(&format!("Current Fingerprint:   {}\n", comp.current_fingerprint));
        out.push_str(&format!(
            "Fingerprint Changed:   {}\n",
            if comp.fingerprint_identical { "NO (Path structurally identical)" } else { "YES (Path altered)" }
        ));
        out.push_str(&format!("Hop Count Delta:       {:+}\n\n", comp.hop_count_delta));

        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("Hop-Level Structural Differences:\n");
        out.push_str("--------------------------------------------------------------------------------\n");

        if comp.hop_differences.is_empty() {
            out.push_str("  No structural hop differences detected between the two snapshots.\n");
        } else {
            for diff in &comp.hop_differences {
                out.push_str(&format!("  [Hop {:>2}] {}\n", diff.hop_number, diff.description));
            }
        }

        out.push_str("\n--------------------------------------------------------------------------------\n");
        out.push_str("Hop Latency (Median RTT) Variations:\n");
        out.push_str("--------------------------------------------------------------------------------\n");

        if comp.rtt_changes.is_empty() {
            out.push_str("  No common responding hops available for RTT delta evaluation.\n");
        } else {
            out.push_str("Hop   Address                       Prev Median   Curr Median   RTT Delta\n");
            out.push_str("----  ----------------------------  ------------  ------------  ---------\n");
            for change in &comp.rtt_changes {
                let prev_str = change
                    .previous_median_ms
                    .map(|m| format!("{:.1} ms", m))
                    .unwrap_or_else(|| "-".to_string());
                let curr_str = change
                    .current_median_ms
                    .map(|m| format!("{:.1} ms", m))
                    .unwrap_or_else(|| "-".to_string());
                let delta_str = change
                    .delta_median_ms
                    .map(|d| format!("{:+.1} ms", d))
                    .unwrap_or_else(|| "-".to_string());

                out.push_str(&format!(
                    "{:<4}  {:<28}  {:>12}  {:>12}  {:>9}\n",
                    change.hop_number,
                    truncate_str(&change.address, 28),
                    prev_str,
                    curr_str,
                    delta_str
                ));
            }
        }

        out.push_str("\n================================================================================\n");
        out.push_str(&format!("SUMMARY: {}\n", comp.summary));
        out.push_str("================================================================================\n");

        out
    }

    /// Render route comparison as formatted JSON.
    pub fn render_comparison_json(comp: &RouteComparison) -> Result<String, String> {
        serde_json::to_string_pretty(comp)
            .map_err(|e| format!("Failed to serialize route comparison JSON: {}", e))
    }

    /// Render route stability report as human-readable text.
    pub fn render_stability_text(stab: &RouteStabilityReport) -> String {
        let mut out = String::new();

        out.push_str("================================================================================\n");
        out.push_str("                 RiftRoute Route Path Stability Report                          \n");
        out.push_str("================================================================================\n\n");

        out.push_str(&format!("Destination:           {}\n", stab.destination));
        out.push_str(&format!("Window Start:          {}\n", stab.analysis_window_start));
        out.push_str(&format!("Window End:            {}\n", stab.analysis_window_end));
        out.push_str(&format!("Total Snapshots:       {}\n", stab.total_snapshots));
        out.push_str(&format!("Unique Fingerprints:   {}\n", stab.unique_fingerprints_count));
        out.push_str(&format!("Dominant Fingerprint:  {} ({:.1}% of observations)\n", stab.dominant_fingerprint, stab.dominant_fingerprint_pct));
        out.push_str(&format!("Route Change Events:   {} ({:.1}% transition rate)\n\n", stab.route_change_count, stab.route_change_rate_pct));

        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("Fingerprint Distribution Breakdown:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("Fingerprint        Count   Percentage   Sample Snapshot ID\n");
        out.push_str("-----------------  -----   ----------   ----------------------------------------\n");

        for fp in &stab.fingerprint_frequencies {
            out.push_str(&format!(
                "{:<17}  {:>5}   {:>9.1}%   {}\n",
                fp.fingerprint, fp.count, fp.percentage, fp.sample_snapshot_id
            ));
        }

        out.push_str("\n--------------------------------------------------------------------------------\n");
        out.push_str("Hop-Position Variability Matrix:\n");
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("Hop   Stable?   Distinct IPs   Timeout Freq   Observed IP Address(es)\n");
        out.push_str("----  --------  -------------  ------------   ----------------------------------\n");

        for h in &stab.hop_variability {
            let stable_str = if h.is_stable { "YES" } else { "NO (Spurious)" };
            let addr_list = if h.unique_addresses.is_empty() {
                "ALL TIMEOUT".to_string()
            } else {
                h.unique_addresses.join(", ")
            };

            out.push_str(&format!(
                "{:<4}  {:<8}  {:>13}  {:>11.1}%   {}\n",
                h.hop_number,
                stable_str,
                h.unique_addresses.len(),
                h.timeout_frequency_pct,
                addr_list
            ));
        }

        out.push_str("\n================================================================================\n");
        out.push_str(&format!("ASSESSMENT: {}\n", stab.stability_summary));
        out.push_str("================================================================================\n");

        out
    }

    /// Render route stability as formatted JSON.
    pub fn render_stability_json(stab: &RouteStabilityReport) -> Result<String, String> {
        serde_json::to_string_pretty(stab)
            .map_err(|e| format!("Failed to serialize route stability JSON: {}", e))
    }

    /// Save snapshot JSON to disk in `data/route/snapshots/`.
    pub fn save_snapshot_json(snapshot: &RouteSnapshot, base_dir: &str) -> Result<PathBuf, String> {
        let snapshots_dir = Path::new(base_dir).join("snapshots");
        create_dir_all(&snapshots_dir)
            .map_err(|e| format!("Failed to create snapshots directory: {}", e))?;

        let filename = format!("{}.json", snapshot.measurement_id);
        let path = snapshots_dir.join(filename);

        let json_data = Self::render_snapshot_json(snapshot)?;
        let mut file = File::create(&path)
            .map_err(|e| format!("Failed to create snapshot file '{}': {}", path.display(), e))?;
        file.write_all(json_data.as_bytes())
            .map_err(|e| format!("Failed to write snapshot file '{}': {}", path.display(), e))?;

        Ok(path)
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}
