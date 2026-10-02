use chrono::Utc;

use super::models::{
    DegradationEvent, DegradationEventType, DegradationSeverity,
    MonitoringBaseline, MonitoringSample, MonitoringSession, MonitoringState,
};

/// Engine for evaluating observed route samples against established baselines,
/// driving the lifecycle state machine, and generating audited degradation events.
pub struct DegradationEvaluator;

impl DegradationEvaluator {
    /// Evaluate a new monitoring sample within a monitoring session.
    /// Updates session state, counters, baseline, and appends any newly triggered events.
    pub fn evaluate_sample(
        session: &mut MonitoringSession,
        sample: MonitoringSample,
    ) -> Vec<DegradationEvent> {
        let mut new_events = Vec::new();
        session.total_samples_collected += 1;

        // 1. Check for immediate process or tool execution failures
        if sample.is_failure {
            session.total_failures_encountered += 1;
            let event = DegradationEvent {
                event_id: format!("evt_fail_{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
                target_id: session.target.target_id.clone(),
                timestamp_utc: sample.timestamp_utc.clone(),
                event_type: DegradationEventType::MeasurementFailure,
                state: session.current_state.clone(),
                severity: DegradationSeverity::Warning,
                evidence_description: format!(
                    "Measurement tool execution failed: {}",
                    sample.failure_reason.as_deref().unwrap_or("Unknown diagnostic error")
                ),
                baseline_median_rtt_ms: session.baseline.as_ref().map(|b| b.median_rtt_ms),
                observed_median_rtt_ms: None,
                median_delta_ms: None,
                median_relative_change_pct: None,
                baseline_jitter_ms: session.baseline.as_ref().map(|b| b.jitter_ms),
                observed_jitter_ms: None,
                baseline_fingerprint: session.baseline.as_ref().map(|b| b.dominant_fingerprint.clone()),
                observed_fingerprint: None,
                consecutive_count: 1,
                measurement_ids: vec![sample.measurement_id.clone()],
                resolved_at_utc: None,
                scientific_disclaimer: session.scientific_disclaimer.clone(),
            };
            new_events.push(event);
            session.samples.push(sample);
            return new_events;
        }

        // 2. Check for target unreachability (0 responding hops)
        if sample.target_unreachable && sample.responding_hops == 0 {
            let event = DegradationEvent {
                event_id: format!("evt_unreach_{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
                target_id: session.target.target_id.clone(),
                timestamp_utc: sample.timestamp_utc.clone(),
                event_type: DegradationEventType::TargetUnreachable,
                state: MonitoringState::Degraded,
                severity: DegradationSeverity::Critical,
                evidence_description: "Target endpoint elicited zero responses across all probe hops (100% path timeout)".to_string(),
                baseline_median_rtt_ms: session.baseline.as_ref().map(|b| b.median_rtt_ms),
                observed_median_rtt_ms: None,
                median_delta_ms: None,
                median_relative_change_pct: None,
                baseline_jitter_ms: session.baseline.as_ref().map(|b| b.jitter_ms),
                observed_jitter_ms: None,
                baseline_fingerprint: session.baseline.as_ref().map(|b| b.dominant_fingerprint.clone()),
                observed_fingerprint: Some(sample.route_fingerprint.clone()),
                consecutive_count: session.consecutive_anomalous_samples + 1,
                measurement_ids: vec![sample.measurement_id.clone()],
                resolved_at_utc: None,
                scientific_disclaimer: session.scientific_disclaimer.clone(),
            };
            session.current_state = MonitoringState::Degraded;
            session.total_degradations_detected += 1;
            new_events.push(event);
            session.samples.push(sample);
            return new_events;
        }

        // Store sample
        session.samples.push(sample.clone());

        // If baseline is not yet established, attempt to establish it
        if session.baseline.is_none() {
            if let Ok(base) = super::baseline::BaselineEngine::compute_baseline(
                &session.target.target_id,
                &session.samples,
                &session.thresholds,
            ) {
                session.baseline = Some(base);
            } else {
                // Not enough samples yet to establish baseline
                return new_events;
            }
        }

        let baseline = match session.baseline {
            Some(ref b) => b.clone(),
            None => return new_events,
        };

        // 3. Evaluate route change independently (Step 10: ROUTE_CHANGED != ROUTE_DEGRADED)
        if session.thresholds.detect_route_change
            && sample.route_fingerprint != "NONE"
            && sample.route_fingerprint != baseline.dominant_fingerprint
        {
            let route_event = DegradationEvent {
                event_id: format!("evt_route_{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
                target_id: session.target.target_id.clone(),
                timestamp_utc: sample.timestamp_utc.clone(),
                event_type: DegradationEventType::RouteChanged,
                state: session.current_state.clone(),
                severity: DegradationSeverity::Info,
                evidence_description: format!(
                    "Route path fingerprint changed from baseline '{}' to observed '{}'",
                    baseline.dominant_fingerprint, sample.route_fingerprint
                ),
                baseline_median_rtt_ms: Some(baseline.median_rtt_ms),
                observed_median_rtt_ms: sample.final_hop_rtt_ms,
                median_delta_ms: sample.final_hop_rtt_ms.map(|r| r - baseline.median_rtt_ms),
                median_relative_change_pct: sample.final_hop_rtt_ms.map(|r| {
                    ((r - baseline.median_rtt_ms) / baseline.median_rtt_ms) * 100.0
                }),
                baseline_jitter_ms: Some(baseline.jitter_ms),
                observed_jitter_ms: sample.jitter_ms,
                baseline_fingerprint: Some(baseline.dominant_fingerprint.clone()),
                observed_fingerprint: Some(sample.route_fingerprint.clone()),
                consecutive_count: 1,
                measurement_ids: vec![sample.measurement_id.clone()],
                resolved_at_utc: None,
                scientific_disclaimer: session.scientific_disclaimer.clone(),
            };
            new_events.push(route_event);
        }

        // 4. Evaluate latency and jitter degradation conditions
        let mut is_anomalous = false;
        let mut latency_degraded = false;
        let mut jitter_degraded = false;
        let mut severity = DegradationSeverity::Warning;
        let mut evidence_parts = Vec::new();

        let (delta_ms, rel_change_pct) = match sample.final_hop_rtt_ms {
            Some(obs_rtt) => {
                let delta = obs_rtt - baseline.median_rtt_ms;
                let pct = (delta / baseline.median_rtt_ms) * 100.0;

                if pct >= session.thresholds.latency_relative_pct
                    && delta >= session.thresholds.latency_absolute_delta_ms
                {
                    latency_degraded = true;
                    is_anomalous = true;

                    if pct >= session.thresholds.critical_latency_relative_pct
                        || delta >= session.thresholds.critical_latency_absolute_delta_ms
                    {
                        severity = DegradationSeverity::Critical;
                    }

                    evidence_parts.push(format!(
                        "Final-hop probe RTT increased by {:+.2} ms ({:+.1}%) over baseline {:.2} ms",
                        delta, pct, baseline.median_rtt_ms
                    ));
                }
                (Some(delta), Some(pct))
            }
            None => (None, None),
        };

        // Jitter check
        let (_jitter_delta, _jitter_rel_pct) = match (sample.jitter_ms, baseline.jitter_ms) {
            (Some(obs_j), base_j) if base_j > 0.0 => {
                let j_delta = obs_j - base_j;
                let j_pct = (j_delta / base_j) * 100.0;
                if j_pct >= session.thresholds.jitter_relative_pct
                    && j_delta >= session.thresholds.jitter_absolute_delta_ms
                {
                    jitter_degraded = true;
                    is_anomalous = true;
                    evidence_parts.push(format!(
                        "Probe jitter increased by {:+.2} ms ({:+.1}%) over baseline {:.2} ms",
                        j_delta, j_pct, base_j
                    ));
                }
                (Some(j_delta), Some(j_pct))
            }
            _ => (None, None),
        };

        // 5. Lifecycle State Machine Transitions (Step 14 & 15)
        match session.current_state {
            MonitoringState::Normal => {
                if is_anomalous {
                    session.current_state = MonitoringState::Suspected;
                    session.consecutive_anomalous_samples = 1;
                    session.consecutive_recovery_samples = 0;

                    // If confirmation_samples is 1, immediately escalate to Degraded
                    if session.consecutive_anomalous_samples >= session.thresholds.confirmation_samples {
                        session.current_state = MonitoringState::Degraded;
                        session.total_degradations_detected += 1;
                        let event = Self::create_degradation_event(
                            session,
                            &sample,
                            &baseline,
                            latency_degraded,
                            jitter_degraded,
                            severity,
                            evidence_parts.join("; "),
                            delta_ms,
                            rel_change_pct,
                            session.consecutive_anomalous_samples,
                        );
                        new_events.push(event);
                    }
                }
            }

            MonitoringState::Suspected => {
                if is_anomalous {
                    session.consecutive_anomalous_samples += 1;
                    if session.consecutive_anomalous_samples >= session.thresholds.confirmation_samples {
                        session.current_state = MonitoringState::Degraded;
                        session.total_degradations_detected += 1;
                        let event = Self::create_degradation_event(
                            session,
                            &sample,
                            &baseline,
                            latency_degraded,
                            jitter_degraded,
                            severity,
                            evidence_parts.join("; "),
                            delta_ms,
                            rel_change_pct,
                            session.consecutive_anomalous_samples,
                        );
                        new_events.push(event);
                    }
                } else {
                    // False alarm / transient noise -> restore to Normal
                    session.current_state = MonitoringState::Normal;
                    session.consecutive_anomalous_samples = 0;
                }
            }

            MonitoringState::Degraded => {
                if is_anomalous {
                    session.consecutive_anomalous_samples += 1;
                    session.consecutive_recovery_samples = 0;
                    // Event deduplication: only escalate severity if upgraded to Critical
                    if severity == DegradationSeverity::Critical {
                        let has_critical = session
                            .events
                            .iter()
                            .rev()
                            .take(3)
                            .any(|e| e.severity == DegradationSeverity::Critical);
                        if !has_critical {
                            let event = Self::create_degradation_event(
                                session,
                                &sample,
                                &baseline,
                                latency_degraded,
                                jitter_degraded,
                                DegradationSeverity::Critical,
                                format!("Critical escalation: {}", evidence_parts.join("; ")),
                                delta_ms,
                                rel_change_pct,
                                session.consecutive_anomalous_samples,
                            );
                            new_events.push(event);
                        }
                    }
                } else {
                    // Sample returned within normal criteria -> transition to Recovering
                    session.current_state = MonitoringState::Recovering;
                    session.consecutive_recovery_samples = 1;
                    session.consecutive_anomalous_samples = 0;

                    // If recovery_samples is 1, immediately recover
                    if session.consecutive_recovery_samples >= session.thresholds.recovery_samples {
                        session.current_state = MonitoringState::Normal;
                        session.total_recoveries_detected += 1;
                        new_events.push(Self::create_recovery_event(session, &sample, &baseline));
                    }
                }
            }

            MonitoringState::Recovering => {
                if !is_anomalous {
                    session.consecutive_recovery_samples += 1;
                    if session.consecutive_recovery_samples >= session.thresholds.recovery_samples {
                        session.current_state = MonitoringState::Normal;
                        session.total_recoveries_detected += 1;
                        new_events.push(Self::create_recovery_event(session, &sample, &baseline));
                    }
                } else {
                    // Relapse into Degraded
                    session.current_state = MonitoringState::Degraded;
                    session.consecutive_anomalous_samples += 1;
                    session.consecutive_recovery_samples = 0;
                }
            }
        }

        // 6. Update Rolling Baseline with Contamination Protection (Step 18)
        session.baseline = super::baseline::BaselineEngine::update_rolling_baseline(
            session.baseline.as_ref(),
            &session.target.target_id,
            &session.samples,
            &session.current_state,
            &session.thresholds,
        );

        // Append generated events to session history
        for ev in &new_events {
            session.events.push(ev.clone());
        }

        new_events
    }

    fn create_degradation_event(
        session: &MonitoringSession,
        sample: &MonitoringSample,
        baseline: &MonitoringBaseline,
        latency: bool,
        jitter: bool,
        severity: DegradationSeverity,
        evidence: String,
        delta_ms: Option<f64>,
        rel_change_pct: Option<f64>,
        consecutive: usize,
    ) -> DegradationEvent {
        let event_type = if latency {
            DegradationEventType::LatencyDegraded
        } else if jitter {
            DegradationEventType::JitterDegraded
        } else {
            DegradationEventType::PathStabilityDegraded
        };

        DegradationEvent {
            event_id: format!("evt_deg_{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
            target_id: session.target.target_id.clone(),
            timestamp_utc: sample.timestamp_utc.clone(),
            event_type,
            state: session.current_state.clone(),
            severity,
            evidence_description: evidence,
            baseline_median_rtt_ms: Some(baseline.median_rtt_ms),
            observed_median_rtt_ms: sample.final_hop_rtt_ms,
            median_delta_ms: delta_ms,
            median_relative_change_pct: rel_change_pct,
            baseline_jitter_ms: Some(baseline.jitter_ms),
            observed_jitter_ms: sample.jitter_ms,
            baseline_fingerprint: Some(baseline.dominant_fingerprint.clone()),
            observed_fingerprint: Some(sample.route_fingerprint.clone()),
            consecutive_count: consecutive,
            measurement_ids: vec![sample.measurement_id.clone()],
            resolved_at_utc: None,
            scientific_disclaimer: session.scientific_disclaimer.clone(),
        }
    }

    fn create_recovery_event(
        session: &MonitoringSession,
        sample: &MonitoringSample,
        baseline: &MonitoringBaseline,
    ) -> DegradationEvent {
        DegradationEvent {
            event_id: format!("evt_rec_{}", Utc::now().format("%Y%m%d%H%M%S%3f")),
            target_id: session.target.target_id.clone(),
            timestamp_utc: sample.timestamp_utc.clone(),
            event_type: DegradationEventType::Recovered,
            state: MonitoringState::Normal,
            severity: DegradationSeverity::Info,
            evidence_description: format!(
                "Network metrics returned within baseline tolerances for {} consecutive samples (observed RTT: {:.2} ms vs baseline: {:.2} ms)",
                session.thresholds.recovery_samples,
                sample.final_hop_rtt_ms.unwrap_or(0.0),
                baseline.median_rtt_ms
            ),
            baseline_median_rtt_ms: Some(baseline.median_rtt_ms),
            observed_median_rtt_ms: sample.final_hop_rtt_ms,
            median_delta_ms: sample.final_hop_rtt_ms.map(|r| r - baseline.median_rtt_ms),
            median_relative_change_pct: sample.final_hop_rtt_ms.map(|r| {
                ((r - baseline.median_rtt_ms) / baseline.median_rtt_ms) * 100.0
            }),
            baseline_jitter_ms: Some(baseline.jitter_ms),
            observed_jitter_ms: sample.jitter_ms,
            baseline_fingerprint: Some(baseline.dominant_fingerprint.clone()),
            observed_fingerprint: Some(sample.route_fingerprint.clone()),
            consecutive_count: session.thresholds.recovery_samples,
            measurement_ids: vec![sample.measurement_id.clone()],
            resolved_at_utc: Some(sample.timestamp_utc.clone()),
            scientific_disclaimer: session.scientific_disclaimer.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate_path::models::EvidenceLevel;
    use crate::monitoring::models::{DegradationThresholds, MonitoringTarget};

    fn make_test_session() -> MonitoringSession {
        let target = MonitoringTarget {
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
            notes: "Test target".to_string(),
        };

        let thresholds = DegradationThresholds {
            baseline_sample_count: 5,
            rolling_window_size: 10,
            latency_relative_pct: 30.0,
            latency_absolute_delta_ms: 20.0,
            confirmation_samples: 3,
            recovery_samples: 3,
            ..Default::default()
        };

        MonitoringSession::new(target, 30, thresholds)
    }

    fn make_sample(id: &str, rtt: f64, jitter: f64, fp: &str) -> MonitoringSample {
        MonitoringSample {
            sample_id: id.to_string(),
            target_id: "target_pubg_singapore".to_string(),
            timestamp_utc: "2026-10-02T10:00:00Z".to_string(),
            measurement_id: format!("meas_{}", id),
            route_fingerprint: fp.to_string(),
            canonical_path: "1:1.1.1.1".to_string(),
            final_hop_rtt_ms: Some(rtt),
            final_hop_p95_ms: Some(rtt + 2.0),
            final_hop_p99_ms: Some(rtt + 4.0),
            final_hop_min_ms: Some(rtt - 2.0),
            final_hop_max_ms: Some(rtt + 5.0),
            final_hop_std_dev_ms: Some(1.5),
            jitter_ms: Some(jitter),
            hop_count: 10,
            responding_hops: 10,
            timeout_hops: 0,
            measurement_duration_ms: 500,
            is_failure: false,
            failure_reason: None,
            target_unreachable: false,
        }
    }

    #[test]
    fn test_normal_baseline_establishment() {
        let mut session = make_test_session();
        for i in 1..=5 {
            let s = make_sample(&format!("s{}", i), 60.0, 1.5, "FP_SINGAPORE");
            let events = DegradationEvaluator::evaluate_sample(&mut session, s);
            assert!(events.is_empty());
        }

        assert!(session.baseline.is_some());
        let b = session.baseline.unwrap();
        assert_eq!(b.median_rtt_ms, 60.0);
        assert_eq!(session.current_state, MonitoringState::Normal);
    }

    #[test]
    fn test_hysteresis_and_degradation_confirmation() {
        let mut session = make_test_session();
        // 5 baseline samples (median = 60ms)
        for i in 1..=5 {
            let s = make_sample(&format!("s{}", i), 60.0, 1.5, "FP_SINGAPORE");
            DegradationEvaluator::evaluate_sample(&mut session, s);
        }

        // Sample 6: spike to 95ms (+35ms, > 30% and > 20ms)
        // confirmation_samples = 3, so sample 1 of 3 must transition to Suspected, NO event yet
        let s6 = make_sample("s6", 95.0, 1.5, "FP_SINGAPORE");
        let ev6 = DegradationEvaluator::evaluate_sample(&mut session, s6);
        assert_eq!(session.current_state, MonitoringState::Suspected);
        assert_eq!(session.consecutive_anomalous_samples, 1);
        assert!(ev6.is_empty(), "First anomaly should not trigger event immediately");

        // Sample 7: 95ms (2 of 3) -> still Suspected
        let s7 = make_sample("s7", 95.0, 1.5, "FP_SINGAPORE");
        let ev7 = DegradationEvaluator::evaluate_sample(&mut session, s7);
        assert_eq!(session.current_state, MonitoringState::Suspected);
        assert_eq!(session.consecutive_anomalous_samples, 2);
        assert!(ev7.is_empty());

        // Sample 8: 95ms (3 of 3) -> confirmed! Transitions to Degraded and emits event!
        let s8 = make_sample("s8", 95.0, 1.5, "FP_SINGAPORE");
        let ev8 = DegradationEvaluator::evaluate_sample(&mut session, s8);
        assert_eq!(session.current_state, MonitoringState::Degraded);
        assert_eq!(ev8.len(), 1);
        assert_eq!(ev8[0].event_type, DegradationEventType::LatencyDegraded);
        assert_eq!(ev8[0].severity, DegradationSeverity::Warning);
        assert_eq!(session.total_degradations_detected, 1);
    }

    #[test]
    fn test_transient_spike_does_not_degrade() {
        let mut session = make_test_session();
        for i in 1..=5 {
            let s = make_sample(&format!("s{}", i), 60.0, 1.5, "FP_SINGAPORE");
            DegradationEvaluator::evaluate_sample(&mut session, s);
        }

        // Single spike
        let s6 = make_sample("s6", 110.0, 1.5, "FP_SINGAPORE");
        let ev6 = DegradationEvaluator::evaluate_sample(&mut session, s6);
        assert_eq!(session.current_state, MonitoringState::Suspected);
        assert!(ev6.is_empty());

        // Next sample returns to normal
        let s7 = make_sample("s7", 60.0, 1.5, "FP_SINGAPORE");
        let ev7 = DegradationEvaluator::evaluate_sample(&mut session, s7);
        assert_eq!(session.current_state, MonitoringState::Normal);
        assert_eq!(session.consecutive_anomalous_samples, 0);
        assert!(ev7.is_empty());
    }

    #[test]
    fn test_recovery_lifecycle() {
        let mut session = make_test_session();
        for i in 1..=5 {
            let s = make_sample(&format!("s{}", i), 60.0, 1.5, "FP_SINGAPORE");
            DegradationEvaluator::evaluate_sample(&mut session, s);
        }

        // Push 3 degraded samples to reach Degraded state
        for i in 6..=8 {
            let s = make_sample(&format!("s{}", i), 95.0, 1.5, "FP_SINGAPORE");
            DegradationEvaluator::evaluate_sample(&mut session, s);
        }
        assert_eq!(session.current_state, MonitoringState::Degraded);

        // Recovery sample 1: returns to 60ms -> Recovering
        let s9 = make_sample("s9", 60.0, 1.5, "FP_SINGAPORE");
        let ev9 = DegradationEvaluator::evaluate_sample(&mut session, s9);
        assert_eq!(session.current_state, MonitoringState::Recovering);
        assert_eq!(session.consecutive_recovery_samples, 1);
        assert!(ev9.is_empty());

        // Recovery sample 2: 60ms -> still Recovering
        let s10 = make_sample("s10", 60.0, 1.5, "FP_SINGAPORE");
        let ev10 = DegradationEvaluator::evaluate_sample(&mut session, s10);
        assert_eq!(session.current_state, MonitoringState::Recovering);
        assert_eq!(session.consecutive_recovery_samples, 2);
        assert!(ev10.is_empty());

        // Recovery sample 3: 60ms (3 of 3) -> confirmed! Transitions to Normal and emits Recovered!
        let s11 = make_sample("s11", 60.0, 1.5, "FP_SINGAPORE");
        let ev11 = DegradationEvaluator::evaluate_sample(&mut session, s11);
        assert_eq!(session.current_state, MonitoringState::Normal);
        assert_eq!(ev11.len(), 1);
        assert_eq!(ev11[0].event_type, DegradationEventType::Recovered);
        assert_eq!(session.total_recoveries_detected, 1);
    }

    #[test]
    fn test_route_changed_is_independent_from_degradation() {
        let mut session = make_test_session();
        for i in 1..=5 {
            let s = make_sample(&format!("s{}", i), 60.0, 1.5, "FP_OLD");
            DegradationEvaluator::evaluate_sample(&mut session, s);
        }

        // Route changed, but latency is normal (60ms)
        let s6 = make_sample("s6", 60.0, 1.5, "FP_NEW");
        let ev6 = DegradationEvaluator::evaluate_sample(&mut session, s6);
        assert_eq!(ev6.len(), 1);
        assert_eq!(ev6[0].event_type, DegradationEventType::RouteChanged);
        assert_eq!(ev6[0].severity, DegradationSeverity::Info);
        // State remains Normal! Route changed does not imply degraded!
        assert_eq!(session.current_state, MonitoringState::Normal);
    }
}
