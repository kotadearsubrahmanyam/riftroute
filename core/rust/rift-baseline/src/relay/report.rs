use std::fs;
use std::path::{Path, PathBuf};

use crate::relay::models::{DirectVsRelayComparison, RelayHealth, RelayNode};
use crate::relay::registry::RelayRegistry;

pub struct RelayReportRenderer;

impl RelayReportRenderer {
    pub fn format_registry_text(registry: &RelayRegistry) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                      RIFTROUTE RELAY REGISTRY INVENTORY                        \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Total Known Nodes: {}\n\n", registry.relays.len()));
        out.push_str(&format!(
            "{:<18} {:<22} {:<10} {:<14} {:<10} {}\n",
            "Relay ID", "Endpoint", "Status", "Region", "Provider", "Provenance"
        ));
        out.push_str(&"-".repeat(88));
        out.push('\n');

        for r in &registry.relays {
            out.push_str(&format!(
                "{:<18} {:<22} {:<10} {:<14} {:<10} {:?}\n",
                r.relay_id,
                format!("{}:{}", r.public_address, r.control_port),
                format!("{:?}", r.status),
                format!("{}, {}", r.location.city, r.location.country),
                r.location.provider,
                r.location.provenance
            ));
        }
        out.push_str("================================================================================\n");
        out
    }

    pub fn format_health_text(health: &RelayHealth, relay: &RelayNode) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("                       RIFTROUTE RELAY HEALTH REPORT                            \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Relay ID:               {}\n", health.relay_id));
        out.push_str(&format!("Public Endpoint:        {}:{}\n", relay.public_address, relay.control_port));
        out.push_str(&format!("Status:                 {:?}\n", health.status));
        out.push_str(&format!("Alive:                  {}\n", health.is_alive));
        out.push_str(&format!("Uptime:                 {} seconds\n", health.uptime_seconds));
        out.push_str(&format!("Active Jobs:            {}\n", health.active_measurement_jobs));
        out.push_str(&format!("Total Measurements:     {}\n", health.total_measurements_completed));
        out.push_str(&format!("Memory Used:            {:.2} MB\n", health.memory_used_bytes as f64 / (1024.0 * 1024.0)));
        out.push_str(&format!(
            "Last Success:           {}\n",
            health.last_successful_measurement_utc.as_deref().unwrap_or("Never")
        ));
        out.push_str("================================================================================\n");
        out
    }

    pub fn format_comparison_text(comp: &DirectVsRelayComparison) -> String {
        let mut out = String::new();
        out.push_str("================================================================================\n");
        out.push_str("             RIFTROUTE DIRECT VS RELAY-ASSISTED PATH COMPARISON                 \n");
        out.push_str("================================================================================\n");
        out.push_str(&format!("Target Destination:      {}\n", comp.target_destination));
        out.push_str(&format!("Relay ID:                {}\n", comp.relay_id));
        out.push_str(&format!("Relay Endpoint:          {}\n", comp.relay_endpoint));
        out.push_str(&format!("Timestamp (UTC):         {}\n", comp.timestamp_utc));
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("EMPIRICAL PATH METRICS:\n");
        out.push_str(&format!("Direct Path Median RTT:  {:.2} ms (p95: {:.2} ms, Hops: {})\n", comp.direct_median_ms, comp.direct_p95_ms, comp.direct_hop_count));
        out.push_str(&format!("Direct Route Fingerprint: {}\n", comp.direct_fingerprint));
        out.push_str(&format!("Leg 1 (Client -> Relay): {:.2} ms\n", comp.client_to_relay_probe_rtt_ms));
        out.push_str(&format!("Leg 2 (Relay -> Dest):   {:.2} ms\n", comp.relay_to_destination_probe_rtt_ms));
        out.push_str(&format!("Composed Relay Estimate: {:.2} ms (Diagnostic Leg 1 + Leg 2)\n", comp.composed_relay_rtt_ms));
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("PATH DELTA & OVERHEAD BREAKDOWN:\n");
        out.push_str(&format!("RTT Delta (Relay - Direct): {:+.2} ms\n", comp.delta_median_ms));
        out.push_str(&format!("p95 Delta:                  {:+.2} ms\n", comp.delta_p95_ms));
        if let Some(dj) = comp.delta_jitter_ms {
            out.push_str(&format!("Jitter Delta:               {:+.2} ms\n", dj));
        }
        out.push_str(&format!("Network Path Overhead:      {:.2} ms\n", comp.network_overhead_ms));
        out.push_str(&format!("Control Channel Roundtrip:  {:.2} ms\n", comp.control_plane_roundtrip_ms));
        out.push_str(&format!("Path Divergence Summary:    {}\n", comp.path_difference_summary));
        out.push_str("--------------------------------------------------------------------------------\n");
        out.push_str("SCIENTIFIC DISCLAIMER:\n");
        out.push_str(&format!("{}\n", comp.scientific_disclaimer));
        out.push_str("================================================================================\n");
        out
    }

    pub fn save_json<T: serde::Serialize, P: AsRef<Path>>(data: &T, path: P) -> Result<PathBuf, String> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize JSON: {}", e))?;
        fs::write(p, json).map_err(|e| format!("Failed to write file {}: {}", p.display(), e))?;
        Ok(p.to_path_buf())
    }
}
