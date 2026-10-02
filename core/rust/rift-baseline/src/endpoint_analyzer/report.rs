use super::models::EndpointAnalysisReport;

pub struct ReportRenderer;

impl ReportRenderer {
    /// Format human-readable text report from the EndpointAnalysisReport.
    pub fn render_human_readable(report: &EndpointAnalysisReport) -> String {
        let mut out = String::new();

        out.push_str("================================================================================\n");
        out.push_str("                     RiftRoute Passive Endpoint Analysis                        \n");
        out.push_str("================================================================================\n\n");

        let c = &report.capture;
        out.push_str(&format!("Capture File:             {}\n", c.file_path));
        out.push_str(&format!("Total Lines Read:         {}\n", c.total_lines_read));
        out.push_str(&format!("Valid Packets Parsed:     {}\n", c.valid_packets));
        out.push_str(&format!("Malformed Records:        {}\n", c.malformed_lines));
        out.push_str(&format!("Capture Duration:         {:.4} seconds ({:.3}s - {:.3}s)\n", c.capture_duration_seconds, c.first_timestamp, c.last_timestamp));
        out.push_str(&format!("Total Frame Bytes:        {} bytes ({:.2} KB)\n", c.total_bytes, c.total_bytes as f64 / 1024.0));
        out.push_str(&format!("Endpoints Discovered:     {}\n\n", c.distinct_endpoints_count));

        for ep in &report.endpoints {
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!("Endpoint #{}: {} ({})\n", ep.rank, ep.classification, ep.protocol));
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str(&format!("Local Socket:             {}:{}\n", ep.local_ip, ep.local_port));
            out.push_str(&format!("Remote Socket:            {}:{}\n", ep.remote_ip, ep.remote_port));
            out.push_str(&format!("Protocol:                 {}\n", ep.protocol));
            out.push_str(&format!("Active Duration:          {:.4} s (first: {:.3}s, last: {:.3}s)\n\n", ep.flow_duration_seconds, ep.first_packet_ts, ep.last_packet_ts));

            // Packet counts & ratios
            out.push_str("Packets:\n");
            out.push_str(&format!("  TX (Outbound):          {} ({:.2}%)\n", ep.tx_packets, ep.direction_ratio.tx_packet_pct));
            out.push_str(&format!("  RX (Inbound):           {} ({:.2}%)\n", ep.rx_packets, ep.direction_ratio.rx_packet_pct));
            out.push_str(&format!("  Total:                  {}\n\n", ep.total_packets));

            // Byte counts & ratios
            out.push_str("Bytes:\n");
            out.push_str(&format!("  TX (Outbound):          {} bytes ({:.2}%)\n", ep.tx_bytes, ep.direction_ratio.tx_byte_pct));
            out.push_str(&format!("  RX (Inbound):           {} bytes ({:.2}%)\n", ep.rx_bytes, ep.direction_ratio.rx_byte_pct));
            out.push_str(&format!("  Total:                  {} bytes\n\n", ep.total_bytes));

            // Packet rates
            out.push_str("Packet Rates:\n");
            out.push_str(&format!("  Overall Rate:           {:.2} packets/sec\n", ep.packet_rate_total));
            out.push_str(&format!("  TX Rate:                {:.2} packets/sec\n", ep.packet_rate_tx));
            out.push_str(&format!("  RX Rate:                {:.2} packets/sec\n\n", ep.packet_rate_rx));

            // Packet size statistics
            out.push_str("Packet Size Statistics (bytes):\n");
            if let Some(ref s) = ep.tx_packet_size {
                out.push_str(&format!("  TX:  Min={} | Median={:.0} | Mean={:.1} | Max={} | StdDev={:.1} | p95={:.0} | p99={:.0}\n", s.min_bytes, s.median_bytes, s.mean_bytes, s.max_bytes, s.std_dev_bytes, s.p95_bytes, s.p99_bytes));
            } else {
                out.push_str("  TX:  No TX packets\n");
            }
            if let Some(ref s) = ep.rx_packet_size {
                out.push_str(&format!("  RX:  Min={} | Median={:.0} | Mean={:.1} | Max={} | StdDev={:.1} | p95={:.0} | p99={:.0}\n", s.min_bytes, s.median_bytes, s.mean_bytes, s.max_bytes, s.std_dev_bytes, s.p95_bytes, s.p99_bytes));
            } else {
                out.push_str("  RX:  No RX packets\n");
            }
            if let Some(ref s) = ep.overall_packet_size {
                out.push_str(&format!("  All: Min={} | Median={:.0} | Mean={:.1} | Max={} | StdDev={:.1} | p95={:.0} | p99={:.0}\n\n", s.min_bytes, s.median_bytes, s.mean_bytes, s.max_bytes, s.std_dev_bytes, s.p95_bytes, s.p99_bytes));
            }

            // Inter-arrival gaps
            out.push_str("Inter-Arrival Statistics (gap between consecutive packets in flow):\n");
            if let Some(ref ia) = ep.inter_arrival {
                out.push_str(&format!("  Min Gap:                {:.2} ms\n", ia.min_gap_ms));
                out.push_str(&format!("  Mean Gap:               {:.2} ms\n", ia.mean_gap_ms));
                out.push_str(&format!("  Median Gap:             {:.2} ms\n", ia.median_gap_ms));
                out.push_str(&format!("  p95 Gap:                {:.2} ms\n", ia.p95_gap_ms));
                out.push_str(&format!("  p99 Gap:                {:.2} ms\n", ia.p99_gap_ms));
                out.push_str(&format!("  Max Gap:                {:.2} ms\n", ia.max_gap_ms));
                out.push_str(&format!("  StdDev:                 {:.2} ms\n\n", ia.std_dev_ms));
            } else {
                out.push_str("  Single packet flow (no inter-arrival gaps)\n\n");
            }

            // Gap counts
            out.push_str("Inactivity Gap Distribution:\n");
            out.push_str(&format!("  Gaps > 10 ms:           {}\n", ep.gaps.gaps_over_10ms));
            out.push_str(&format!("  Gaps > 25 ms:           {}\n", ep.gaps.gaps_over_25ms));
            out.push_str(&format!("  Gaps > 50 ms:           {}\n", ep.gaps.gaps_over_50ms));
            out.push_str(&format!("  Gaps > 100 ms:          {}\n", ep.gaps.gaps_over_100ms));
            out.push_str(&format!("  Gaps > 250 ms:          {}\n", ep.gaps.gaps_over_250ms));
            out.push_str(&format!("  Gaps > 500 ms:          {}\n\n", ep.gaps.gaps_over_500ms));

            // Burst statistics
            let b = &ep.bursts;
            out.push_str("Burst Statistics:\n");
            out.push_str(&format!("  Rule:                   {}\n", b.burst_rule));
            out.push_str(&format!("  Total Bursts:           {}\n", b.burst_count));
            out.push_str(&format!("  Avg Packets / Burst:    {:.2}\n", b.avg_packets_per_burst));
            out.push_str(&format!("  Max Packets in Burst:   {}\n", b.max_packets_in_burst));
            out.push_str(&format!("  Avg Burst Duration:     {:.2} ms\n", b.avg_burst_duration_ms));
            out.push_str(&format!("  Max Burst Duration:     {:.2} ms\n\n", b.max_burst_duration_ms));

            // Stability
            let s = &ep.stability;
            out.push_str("Endpoint Stability:\n");
            out.push_str(&format!("  Continuously Active:    {}\n", if s.is_continuously_active { "YES" } else { "NO" }));
            out.push_str(&format!("  Active Duration Ratio:  {:.2}%\n", s.active_duration_ratio * 100.0));
            out.push_str(&format!("  Longest Inactivity Gap: {:.2} ms\n", s.longest_inactivity_gap_ms));
            out.push_str(&format!("  Gaps > 100 ms:          {}\n", s.gaps_over_100ms_count));
            out.push_str(&format!("  Gaps > 500 ms:          {}\n", s.gaps_over_500ms_count));
            out.push_str(&format!("  Gaps > 1.0 s:           {}\n", s.gaps_over_1s_count));
            out.push_str(&format!("  Assessment:             {}\n\n", s.criteria_commentary));

            // Critical Restrictions
            out.push_str("RTT:                      NOT MEASURED\n");
            out.push_str(&format!("  Note:                   {}\n", ep.rtt_note));
            out.push_str("Packet Loss:              NOT MEASURED\n");
            out.push_str(&format!("  Note:                   {}\n\n", ep.packet_loss_note));
        }

        out.push_str("================================================================================\n");
        out.push_str("Analysis completed in passive, read-only mode. No packets injected or altered.\n");
        out.push_str("================================================================================\n");

        out
    }

    /// Render machine-readable JSON string.
    pub fn render_json(report: &EndpointAnalysisReport) -> Result<String, String> {
        serde_json::to_string_pretty(report)
            .map_err(|e| format!("Failed to serialize report to JSON: {}", e))
    }
}
