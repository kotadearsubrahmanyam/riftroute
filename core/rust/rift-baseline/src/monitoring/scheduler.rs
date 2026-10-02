use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::evaluator::DegradationEvaluator;
use super::models::{MonitoringSample, MonitoringSession, MonitoringTarget};
use crate::route_intelligence::models::RouteSnapshot;
use crate::route_intelligence::RouteIntelligence;

/// Safe, paced measurement scheduler for single-target and multi-target route monitoring.
pub struct MonitoringScheduler;

impl MonitoringScheduler {
    /// Execute a bounded or continuous monitoring session on a target.
    /// Respects pacing safety, process timeouts, and graceful termination flags.
    pub fn run_session(
        session: &mut MonitoringSession,
        max_samples: Option<usize>,
        max_hops: u8,
        probe_timeout_ms: u64,
        resolve_hostnames: bool,
        process_timeout_secs: u64,
        stop_signal: Option<Arc<AtomicBool>>,
    ) -> Result<(), String> {
        let interval_duration = Duration::from_secs(session.interval_seconds);
        let process_timeout = Duration::from_secs(process_timeout_secs);

        while session.is_active {
            if let Some(limit) = max_samples {
                if session.samples.len() >= limit {
                    break;
                }
            }

            if let Some(ref stop) = stop_signal {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }

            let start_time = Instant::now();

            // Execute safe Windows tracert probe non-invasively via Phase 1 RouteIntelligence
            let sample = match RouteIntelligence::measure(
                &session.target.destination_ip,
                max_hops,
                probe_timeout_ms,
                resolve_hostnames,
                process_timeout,
            ) {
                Ok(snapshot) => {
                    MonitoringSample::from_snapshot(&session.target.target_id, &snapshot)
                }
                Err(err) => {
                    MonitoringSample::failure(&session.target.target_id, &err)
                }
            };

            // Evaluate sample against baseline and state machine
            DegradationEvaluator::evaluate_sample(session, sample);

            // Check if termination condition reached
            if let Some(limit) = max_samples {
                if session.samples.len() >= limit {
                    break;
                }
            }

            if let Some(ref stop) = stop_signal {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }

            // Pacing Safety (Step 5): ensure sequential execution without overlap
            let elapsed = start_time.elapsed();
            if elapsed < interval_duration {
                std::thread::sleep(interval_duration - elapsed);
            }
            // If measurement duration exceeded interval, do not spawn overlapping measurement;
            // proceed immediately to the next sequential cycle.
        }

        session.is_active = false;
        session.end_time_utc = Some(Utc::now().to_rfc3339());
        Ok(())
    }

    /// Single-Shot Offline Replay Mode (Step 25):
    /// Ingests a pre-recorded sequence of RouteSnapshots and deterministically evaluates them.
    pub fn replay_snapshots(
        target: MonitoringTarget,
        snapshots: &[RouteSnapshot],
        interval_seconds: u64,
        thresholds: super::models::DegradationThresholds,
    ) -> MonitoringSession {
        let mut session = MonitoringSession::new(target, interval_seconds, thresholds);

        for snap in snapshots {
            let sample = MonitoringSample::from_snapshot(&session.target.target_id, snap);
            DegradationEvaluator::evaluate_sample(&mut session, sample);
        }

        session.is_active = false;
        session.end_time_utc = Some(Utc::now().to_rfc3339());
        session
    }

    /// Offline Replay Mode for pre-recorded MonitoringSamples.
    pub fn replay_samples(
        target: MonitoringTarget,
        samples: &[MonitoringSample],
        interval_seconds: u64,
        thresholds: super::models::DegradationThresholds,
    ) -> MonitoringSession {
        let mut session = MonitoringSession::new(target, interval_seconds, thresholds);

        for s in samples {
            DegradationEvaluator::evaluate_sample(&mut session, s.clone());
        }

        session.is_active = false;
        session.end_time_utc = Some(Utc::now().to_rfc3339());
        session
    }
}
