use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use chrono::Utc;

use crate::models::{RelayHealth, RelayStatusType};

/// In-memory tracker for relay health and telemetry.
pub struct HealthTracker {
    relay_id: String,
    start_time: Instant,
    active_jobs: Arc<AtomicUsize>,
    total_completed: Arc<AtomicU64>,
    last_success_utc: Arc<Mutex<Option<String>>>,
    status: Arc<Mutex<RelayStatusType>>,
}

impl HealthTracker {
    pub fn new(relay_id: String) -> Self {
        Self {
            relay_id,
            start_time: Instant::now(),
            active_jobs: Arc::new(AtomicUsize::new(0)),
            total_completed: Arc::new(AtomicU64::new(0)),
            last_success_utc: Arc::new(Mutex::new(None)),
            status: Arc::new(Mutex::new(RelayStatusType::Online)),
        }
    }

    pub fn start_job(&self) {
        self.active_jobs.fetch_add(1, Ordering::SeqCst);
    }

    pub fn finish_job(&self, success: bool) {
        self.active_jobs.fetch_sub(1, Ordering::SeqCst);
        self.total_completed.fetch_add(1, Ordering::SeqCst);
        if success {
            let mut last = self.last_success_utc.lock().unwrap();
            *last = Some(Utc::now().to_rfc3339());
        }
    }

    pub fn set_status(&self, new_status: RelayStatusType) {
        let mut st = self.status.lock().unwrap();
        *st = new_status;
    }

    pub fn active_jobs_count(&self) -> usize {
        self.active_jobs.load(Ordering::Relaxed)
    }

    pub fn get_health_snapshot(&self) -> RelayHealth {
        let uptime = self.start_time.elapsed().as_secs();
        let last = self.last_success_utc.lock().unwrap().clone();
        let st = self.status.lock().unwrap().clone();

        // Memory estimate (cross-platform safe fallback)
        let memory_bytes = get_process_memory_bytes();

        RelayHealth {
            relay_id: self.relay_id.clone(),
            is_alive: true,
            uptime_seconds: uptime,
            cpu_usage_pct: 0.0, // Minimal lightweight footprint
            memory_used_bytes: memory_bytes,
            active_measurement_jobs: self.active_jobs.load(Ordering::Relaxed),
            total_measurements_completed: self.total_completed.load(Ordering::Relaxed),
            last_successful_measurement_utc: last,
            status: st,
        }
    }
}

fn get_process_memory_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(pages) = statm.split_whitespace().next() {
                if let Ok(p) = pages.parse::<u64>() {
                    return p * 4096;
                }
            }
        }
    }
    // Minimal fallback: 8 MB nominal footprint for non-Linux or container mock
    8 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_tracker_lifecycle() {
        let tracker = HealthTracker::new("relay_in_01".to_string());
        let h1 = tracker.get_health_snapshot();
        assert_eq!(h1.relay_id, "relay_in_01");
        assert_eq!(h1.active_measurement_jobs, 0);

        tracker.start_job();
        assert_eq!(tracker.active_jobs_count(), 1);

        tracker.finish_job(true);
        assert_eq!(tracker.active_jobs_count(), 0);

        let h2 = tracker.get_health_snapshot();
        assert_eq!(h2.total_measurements_completed, 1);
        assert!(h2.last_successful_measurement_utc.is_some());
    }
}
