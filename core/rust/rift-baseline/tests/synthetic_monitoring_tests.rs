use std::path::PathBuf;
use rift_baseline::candidate_path::models::EvidenceLevel;
use rift_baseline::monitoring::evaluator::DegradationEvaluator;
use rift_baseline::monitoring::models::{
    DegradationEventType, DegradationSeverity, DegradationThresholds,
    MonitoringSample, MonitoringSession, MonitoringState, MonitoringTarget,
};
use rift_baseline::monitoring::scheduler::MonitoringScheduler;
use rift_baseline::route_intelligence::models::{HopRttStats, RouteHop, RouteSnapshot};

fn test_target() -> MonitoringTarget {
    MonitoringTarget {
        target_id: "target_pubg_singapore".to_string(),
        candidate_id: Some("cand_20_205_179_128_27528".to_string()),
        destination: "20.205.179.128".to_string(),
        destination_ip: "20.205.179.128".to_string(),
        target_port: Some(27528),
        protocol: "UDP".to_string(),
        service_name: "PUBG PC".to_string(),
        evidence_level: EvidenceLevel::DirectlyObserved,
        enabled: true,
        created_at_utc: "2026-10-02T10:00:00Z".to_string(),
        notes: "Synthetic test target".to_string(),
    }
}

fn test_thresholds() -> DegradationThresholds {
    DegradationThresholds {
        baseline_sample_count: 5,
        rolling_window_size: 10,
        latency_relative_pct: 30.0,
        latency_absolute_delta_ms: 20.0,
        p95_relative_pct: 40.0,
        jitter_relative_pct: 100.0,
        jitter_absolute_delta_ms: 5.0,
        detect_route_change: true,
        stability_transition_rate_threshold_pct: 50.0,
        confirmation_samples: 3,
        recovery_samples: 3,
        critical_latency_relative_pct: 100.0,
        critical_latency_absolute_delta_ms: 60.0,
    }
}

fn make_synthetic_snapshot(
    idx: usize,
    final_rtt: f64,
    jitter: f64,
    fingerprint: &str,
    hops_count: u8,
) -> RouteSnapshot {
    let mut hops = Vec::new();
    // Gateway hop 1
    hops.push(RouteHop {
        hop_number: 1,
        addresses: vec!["192.168.1.1".to_string()],
        primary_address: Some("192.168.1.1".to_string()),
        hostname: None,
        rtt_samples_ms: vec![1.0, 1.2, 1.1],
        responded: true,
        timeout_count: 0,
        probe_count: 3,
        rtt_stats: Some(HopRttStats {
            sample_count: 3,
            min_ms: 1.0,
            median_ms: 1.1,
            mean_ms: 1.1,
            p95_ms: 1.2,
            p99_ms: 1.2,
            max_ms: 1.2,
            std_dev_ms: 0.1,
            jitter_ms: Some(0.1),
        }),
        is_timeout: false,
        raw_line: "".to_string(),
    });

    // Intermediate hops
    for h in 2..hops_count {
        hops.push(RouteHop {
            hop_number: h,
            addresses: vec![format!("10.0.{}.1", h)],
            primary_address: Some(format!("10.0.{}.1", h)),
            hostname: None,
            rtt_samples_ms: vec![20.0 + (h as f64 * 2.0)],
            responded: true,
            timeout_count: 0,
            probe_count: 3,
            rtt_stats: None,
            is_timeout: false,
            raw_line: "".to_string(),
        });
    }

    // Final hop
    let probe_a = final_rtt - jitter;
    let probe_b = final_rtt + jitter;
    let probe_c = final_rtt;

    hops.push(RouteHop {
        hop_number: hops_count,
        addresses: vec!["20.205.179.128".to_string()],
        primary_address: Some("20.205.179.128".to_string()),
        hostname: None,
        rtt_samples_ms: vec![probe_a, probe_b, probe_c],
        responded: true,
        timeout_count: 0,
        probe_count: 3,
        rtt_stats: Some(HopRttStats {
            sample_count: 3,
            min_ms: probe_a.min(probe_b).min(probe_c),
            median_ms: final_rtt,
            mean_ms: (probe_a + probe_b + probe_c) / 3.0,
            p95_ms: probe_a.max(probe_b).max(probe_c),
            p99_ms: probe_a.max(probe_b).max(probe_c),
            max_ms: probe_a.max(probe_b).max(probe_c),
            std_dev_ms: jitter,
            jitter_ms: Some(jitter),
        }),
        is_timeout: false,
        raw_line: "".to_string(),
    });

    let canonical = format!("1:192.168.1.1->...->{}:20.205.179.128", hops_count);

    RouteSnapshot {
        measurement_id: format!("meas_synthetic_{}_{:04}", fingerprint, idx),
        timestamp_utc: format!("2026-10-02T12:{:02}:00Z", idx % 60),
        destination: "20.205.179.128".to_string(),
        destination_ip: Some("20.205.179.128".to_string()),
        destination_port: Some(27528),
        probe_method: "tracert".to_string(),
        resolve_hostnames: false,
        active_interface: Some("Ethernet".to_string()),
        source_ipv4: Some("192.168.1.50".to_string()),
        default_gateway: Some("192.168.1.1".to_string()),
        hop_count: hops_count as usize,
        responding_hops: hops_count as usize,
        timeout_hops: 0,
        hops,
        fingerprint: fingerprint.to_string(),
        fingerprint_sha256: format!("{:0<64}", fingerprint),
        canonical_path: canonical,
        measurement_duration_ms: 450,
        scientific_disclaimer: "SYNTHETIC_TEST_DISCLAIMER".to_string(),
    }
}

fn save_synthetic_dataset(name: &str, snapshots: &[RouteSnapshot]) {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop(); // rift-baseline
    dir.pop(); // rust
    dir.pop(); // core
    dir.push("data");
    dir.push("monitoring");
    dir.push("synthetic");
    std::fs::create_dir_all(&dir).ok();

    let file_path = dir.join(format!("{}.json", name));
    let json = serde_json::to_string_pretty(snapshots).unwrap();
    std::fs::write(file_path, json).ok();
}

fn save_synthetic_samples(name: &str, samples: &[MonitoringSample]) {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop(); // rift-baseline
    dir.pop(); // rust
    dir.pop(); // core
    dir.push("data");
    dir.push("monitoring");
    dir.push("synthetic");
    std::fs::create_dir_all(&dir).ok();

    let file_path = dir.join(format!("{}.json", name));
    let json = serde_json::to_string_pretty(samples).unwrap();
    std::fs::write(file_path, json).ok();
}

#[test]
fn test_dataset_a_normal_stable_path() {
    // 8 samples, all with RTT 60ms, fingerprint FP_A
    let snapshots: Vec<RouteSnapshot> = (1..=8)
        .map(|i| make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10))
        .collect();

    save_synthetic_dataset("dataset_a_normal_stable_path", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 8);
    assert_eq!(session.current_state, MonitoringState::Normal);
    assert!(session.baseline.is_some());
    let b = session.baseline.unwrap();
    assert_eq!(b.median_rtt_ms, 60.0);
    assert_eq!(b.dominant_fingerprint, "FP_A");
    assert_eq!(session.events.len(), 0, "Normal stable path should trigger 0 events");
    assert_eq!(session.total_degradations_detected, 0);
}

#[test]
fn test_dataset_b_temporary_latency_spike() {
    // Samples 1-5: 60ms, Sample 6: spike to 110ms, Sample 7: 60ms
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10));
    }
    // Spike
    snapshots.push(make_synthetic_snapshot(6, 110.0, 1.0, "FP_A", 10));
    // Return to normal
    snapshots.push(make_synthetic_snapshot(7, 60.0, 1.0, "FP_A", 10));

    save_synthetic_dataset("dataset_b_temporary_latency_spike", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 7);
    assert_eq!(session.current_state, MonitoringState::Normal);
    assert_eq!(
        session.events.len(),
        0,
        "Temporary single spike should be absorbed by hysteresis confirmation (no Degraded event)"
    );
    assert_eq!(session.total_degradations_detected, 0);
}

#[test]
fn test_dataset_c_persistent_latency_degradation() {
    // Samples 1-5: 60ms, Samples 6-8: 120ms (3 consecutive > threshold)
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10));
    }
    for i in 6..=8 {
        snapshots.push(make_synthetic_snapshot(i, 120.0, 1.0, "FP_A", 10));
    }

    save_synthetic_dataset("dataset_c_persistent_latency_degradation", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 8);
    assert_eq!(session.current_state, MonitoringState::Degraded);
    assert_eq!(session.total_degradations_detected, 1);
    assert_eq!(session.events.len(), 1);
    assert_eq!(
        session.events[0].event_type,
        DegradationEventType::LatencyDegraded
    );
    assert!(session.events[0].severity == DegradationSeverity::Warning || session.events[0].severity == DegradationSeverity::Critical);
}

#[test]
fn test_dataset_d_route_change_normal_latency() {
    // Samples 1-5: 60ms, FP_ALPHA; Samples 6-8: 60ms, FP_BETA
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_ALPHA", 10));
    }
    for i in 6..=8 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_BETA", 10));
    }

    save_synthetic_dataset("dataset_d_route_change_normal_latency", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 8);
    // Route change alone MUST NOT trigger Degraded state! (ROUTE_CHANGED != ROUTE_DEGRADED)
    assert_eq!(session.current_state, MonitoringState::Normal);
    assert_eq!(session.total_degradations_detected, 0);

    let route_events: Vec<_> = session
        .events
        .iter()
        .filter(|e| e.event_type == DegradationEventType::RouteChanged)
        .collect();
    assert!(!route_events.is_empty(), "Must emit RouteChanged event");
    assert_eq!(route_events[0].severity, DegradationSeverity::Info);
}

#[test]
fn test_dataset_e_route_change_plus_latency_degradation() {
    // Samples 1-5: 60ms, FP_ALPHA; Samples 6-8: 130ms, FP_BETA
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_ALPHA", 10));
    }
    for i in 6..=8 {
        snapshots.push(make_synthetic_snapshot(i, 130.0, 1.0, "FP_BETA", 10));
    }

    save_synthetic_dataset("dataset_e_route_change_plus_latency_degradation", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 8);
    assert_eq!(session.current_state, MonitoringState::Degraded);
    assert_eq!(session.total_degradations_detected, 1);

    let has_route_changed = session
        .events
        .iter()
        .any(|e| e.event_type == DegradationEventType::RouteChanged);
    let has_latency_degraded = session
        .events
        .iter()
        .any(|e| e.event_type == DegradationEventType::LatencyDegraded);

    assert!(has_route_changed, "Must report route change event");
    assert!(has_latency_degraded, "Must report latency degradation event");
}

#[test]
fn test_dataset_f_jitter_degradation() {
    // Samples 1-5: 60ms, jitter 1.0ms; Samples 6-8: 60ms, jitter 15.0ms (jump > 5ms & > 100%)
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10));
    }
    for i in 6..=8 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 15.0, "FP_A", 10));
    }

    save_synthetic_dataset("dataset_f_jitter_degradation", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 8);
    assert_eq!(session.current_state, MonitoringState::Degraded);
    assert_eq!(session.total_degradations_detected, 1);
    assert_eq!(session.events.len(), 1);
    assert_eq!(
        session.events[0].event_type,
        DegradationEventType::JitterDegraded
    );
}

#[test]
fn test_dataset_g_measurement_failure() {
    let mut session = MonitoringSession::new(test_target(), 30, test_thresholds());
    // 5 normal samples
    for i in 1..=5 {
        let snap = make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10);
        let sample = MonitoringSample::from_snapshot(&session.target.target_id, &snap);
        DegradationEvaluator::evaluate_sample(&mut session, sample);
    }
    assert_eq!(session.current_state, MonitoringState::Normal);

    // Sample 6: Execution failure
    let mut fail_sample = MonitoringSample::from_snapshot(
        &session.target.target_id,
        &make_synthetic_snapshot(6, 60.0, 1.0, "FP_A", 10),
    );
    fail_sample.is_failure = true;
    fail_sample.failure_reason = Some("Tracert process timed out after 30000ms".to_string());
    fail_sample.final_hop_rtt_ms = None;

    let events = DegradationEvaluator::evaluate_sample(&mut session, fail_sample);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, DegradationEventType::MeasurementFailure);
    assert_eq!(events[0].severity, DegradationSeverity::Warning);
    assert_eq!(session.total_failures_encountered, 1);

    save_synthetic_samples("dataset_g_measurement_failure", &session.samples);
}

#[test]
fn test_dataset_h_recovery_after_degradation() {
    // Samples 1-5: 60ms; Samples 6-8: 120ms (Degraded); Samples 9-11: 60ms (Recovered)
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10));
    }
    for i in 6..=8 {
        snapshots.push(make_synthetic_snapshot(i, 120.0, 1.0, "FP_A", 10));
    }
    for i in 9..=11 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10));
    }

    save_synthetic_dataset("dataset_h_recovery_after_degradation", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 11);
    assert_eq!(session.current_state, MonitoringState::Normal);
    assert_eq!(session.total_degradations_detected, 1);
    assert_eq!(session.total_recoveries_detected, 1);

    let recovery_events: Vec<_> = session
        .events
        .iter()
        .filter(|e| e.event_type == DegradationEventType::Recovered)
        .collect();
    assert_eq!(recovery_events.len(), 1, "Must emit exactly 1 Recovered event");
}

#[test]
fn test_dataset_i_baseline_contamination_scenario() {
    // 5 baseline samples at 60ms (Baseline median = 60.0ms)
    // 10 consecutive degraded samples at 120ms
    // With baseline contamination protection, the baseline MUST remain frozen at 60.0ms!
    let mut snapshots = Vec::new();
    for i in 1..=5 {
        snapshots.push(make_synthetic_snapshot(i, 60.0, 1.0, "FP_A", 10));
    }
    for i in 6..=15 {
        snapshots.push(make_synthetic_snapshot(i, 120.0, 1.0, "FP_A", 10));
    }

    save_synthetic_dataset("dataset_i_baseline_contamination_scenario", &snapshots);

    let session = MonitoringScheduler::replay_snapshots(
        test_target(),
        &snapshots,
        30,
        test_thresholds(),
    );

    assert_eq!(session.total_samples_collected, 15);
    assert_eq!(session.current_state, MonitoringState::Degraded);
    assert!(session.baseline.is_some());
    let b = session.baseline.unwrap();

    assert!(
        b.is_frozen,
        "Baseline must be flagged as frozen during degraded state"
    );
    assert_eq!(
        b.median_rtt_ms, 60.0,
        "Baseline median MUST NOT drift to 120ms due to contamination protection"
    );
}
