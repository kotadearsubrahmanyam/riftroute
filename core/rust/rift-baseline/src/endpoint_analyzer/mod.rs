pub mod metrics;
pub mod models;
pub mod parser;
pub mod report;

use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;

use self::metrics::MetricsCalculator;
use self::models::{
    CaptureMetadata, EndpointAnalysisReport, EndpointKey, FlowPacket,
};
use self::parser::CaptureParser;

pub struct EndpointAnalyzer;

impl EndpointAnalyzer {
    /// Read, parse, group, and analyze a TShark packet metadata capture file.
    pub fn analyze_file<P: AsRef<Path>>(path: P) -> Result<EndpointAnalysisReport, String> {
        let path_ref = path.as_ref();
        let parse_result = CaptureParser::parse_file(path_ref)?;

        if parse_result.records.is_empty() {
            return Err(format!(
                "No valid packet records found in file '{}' (total lines read: {}, malformed: {})",
                path_ref.display(),
                parse_result.total_lines_read,
                parse_result.malformed_lines
            ));
        }

        // Group records into bidirectional endpoint flows
        let mut flows: HashMap<EndpointKey, Vec<FlowPacket>> = HashMap::new();
        let mut total_bytes = 0usize;
        let mut first_timestamp = f64::INFINITY;
        let mut last_timestamp = f64::NEG_INFINITY;

        for rec in &parse_result.records {
            total_bytes += rec.frame_length as usize;
            if rec.timestamp < first_timestamp {
                first_timestamp = rec.timestamp;
            }
            if rec.timestamp > last_timestamp {
                last_timestamp = rec.timestamp;
            }

            let (key, direction) = EndpointKey::normalize(
                &rec.src_ip,
                rec.src_port,
                &rec.dst_ip,
                rec.dst_port,
                "UDP",
            );

            flows.entry(key).or_default().push(FlowPacket {
                timestamp: rec.timestamp,
                direction,
                frame_length: rec.frame_length,
            });
        }

        let capture_duration_seconds = (last_timestamp - first_timestamp).max(0.0);

        // Sort flows by total packet count descending
        let mut sorted_flows: Vec<(EndpointKey, Vec<FlowPacket>)> = flows.into_iter().collect();
        // Ensure packets within each flow are strictly chronological
        for (_, pkts) in &mut sorted_flows {
            pkts.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap_or(std::cmp::Ordering::Equal));
        }
        sorted_flows.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        let distinct_endpoints_count = sorted_flows.len();

        let mut flow_reports = Vec::with_capacity(distinct_endpoints_count);
        for (idx, (key, pkts)) in sorted_flows.into_iter().enumerate() {
            let rank = idx + 1;
            let report = MetricsCalculator::analyze_flow(
                &key,
                &pkts,
                rank,
                capture_duration_seconds,
            );
            flow_reports.push(report);
        }

        let capture_metadata = CaptureMetadata {
            file_path: path_ref.to_string_lossy().to_string(),
            total_lines_read: parse_result.total_lines_read,
            valid_packets: parse_result.records.len(),
            malformed_lines: parse_result.malformed_lines,
            capture_duration_seconds,
            first_timestamp,
            last_timestamp,
            total_bytes,
            distinct_endpoints_count,
        };

        Ok(EndpointAnalysisReport {
            capture: capture_metadata,
            endpoints: flow_reports,
            analysis_timestamp: Utc::now().to_rfc3339(),
        })
    }
}
