//! Supervised process polling worker with bounded retry backoff and cancellation.

use std::{
    fmt,
    sync::{mpsc::{self, Receiver, Sender}, Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{ProcessChange, ProcessSnapshot, ProcessTracker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollingConfig {
    pub interval: Duration,
    pub max_backoff: Duration,
}

impl PollingConfig {
    pub fn validate(self) -> Result<Self, PollingConfigError> {
        if self.interval.is_zero() || self.max_backoff < self.interval { return Err(PollingConfigError); }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollingConfigError;

impl fmt::Display for PollingConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("poll interval must be non-zero and max_backoff must be at least interval")
    }
}
impl std::error::Error for PollingConfigError {}

#[derive(Debug)]
pub enum PollingStartError { InvalidConfig(PollingConfigError), WorkerSpawn(std::io::Error) }
impl fmt::Display for PollingStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::InvalidConfig(error) => write!(f, "{error}"), Self::WorkerSpawn(error) => write!(f, "could not start process monitor worker: {error}") }
    }
}
impl std::error::Error for PollingStartError {}

#[derive(Debug)]
pub struct ProcessPollResult {
    pub processes: Vec<ProcessSnapshot>,
    pub inaccessible_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessMonitorMessage {
    Changes { changes: Vec<ProcessChange>, inaccessible_count: u32 },
    Healthy { inaccessible_count: u32 },
    Degraded { consecutive_failures: u32, error: String },
    Stopped,
}

/// Owns the polling thread. Stopping or dropping the service cancels and joins it.
pub struct ProcessMonitorService {
    stop: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl ProcessMonitorService {
    pub fn start<F, E>(config: PollingConfig, mut poll: F) -> Result<(Self, Receiver<ProcessMonitorMessage>), PollingStartError>
    where
        F: FnMut() -> Result<ProcessPollResult, E> + Send + 'static,
        E: fmt::Display + Send + 'static,
    {
        let config = config.validate().map_err(PollingStartError::InvalidConfig)?;
        let (sender, receiver) = mpsc::channel();
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("peacelocker-process-monitor".into())
            .spawn(move || run_worker(config, &mut poll, sender, worker_stop))
            .map_err(PollingStartError::WorkerSpawn)?;
        Ok((Self { stop, worker: Some(worker) }, receiver))
    }

    pub fn stop(&mut self) {
        let (lock, wake) = &*self.stop;
        if let Ok(mut stopped) = lock.lock() { *stopped = true; wake.notify_all(); }
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
impl Drop for ProcessMonitorService { fn drop(&mut self) { self.stop(); } }

fn run_worker<F, E>(config: PollingConfig, poll: &mut F, sender: Sender<ProcessMonitorMessage>, stop: Arc<(Mutex<bool>, Condvar)>)
where F: FnMut() -> Result<ProcessPollResult, E>, E: fmt::Display {
    let mut tracker = ProcessTracker::default();
    let mut failures = 0u32;
    loop {
        if is_stopped(&stop) { break; }
        match poll() {
            Ok(snapshot) => {
                failures = 0;
                let changes = tracker.update(snapshot.processes);
                let message = if changes.is_empty() {
                    ProcessMonitorMessage::Healthy { inaccessible_count: snapshot.inaccessible_count }
                } else {
                    ProcessMonitorMessage::Changes { changes, inaccessible_count: snapshot.inaccessible_count }
                };
                if sender.send(message).is_err() || !wait_or_stop(&stop, config.interval) { break; }
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                if sender.send(ProcessMonitorMessage::Degraded { consecutive_failures: failures, error: error.to_string() }).is_err() { break; }
                let delay = backoff(config.interval, config.max_backoff, failures);
                if !wait_or_stop(&stop, delay) { break; }
            }
        }
    }
    let _ = sender.send(ProcessMonitorMessage::Stopped);
}

fn backoff(base: Duration, maximum: Duration, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(31);
    base.saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX)).min(maximum)
}
fn is_stopped(stop: &Arc<(Mutex<bool>, Condvar)>) -> bool {
    stop.0.lock().map(|stopped| *stopped).unwrap_or(true)
}
fn wait_or_stop(stop: &Arc<(Mutex<bool>, Condvar)>, duration: Duration) -> bool {
    let (lock, wake) = &**stop;
    let Ok(stopped) = lock.lock() else { return false; };
    if *stopped { return false; }
    let Ok((stopped, _)) = wake.wait_timeout_while(stopped, duration, |stopped| !*stopped) else { return false; };
    !*stopped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sample() -> ProcessSnapshot {
        ProcessSnapshot { identity: crate::ProcessIdentity { pid: 44, creation_time_100ns: 1 }, name: "demo.exe".into(), executable_path: None }
    }

    #[test]
    fn worker_emits_changes_and_stops() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let (mut service, receiver) = ProcessMonitorService::start(
            PollingConfig { interval: Duration::from_millis(10), max_backoff: Duration::from_millis(40) },
            move || { count.fetch_add(1, Ordering::SeqCst); Ok::<_, &'static str>(ProcessPollResult { processes: vec![sample()], inaccessible_count: 0 }) },
        ).unwrap();
        assert!(matches!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), ProcessMonitorMessage::Changes { .. }));
        service.stop();
        assert!(matches!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), ProcessMonitorMessage::Stopped));
        assert!(calls.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn failures_are_reported_for_retry() {
        let (mut service, receiver) = ProcessMonitorService::start(
            PollingConfig { interval: Duration::from_millis(5), max_backoff: Duration::from_millis(20) },
            || Err::<ProcessPollResult, _>("snapshot failed"),
        ).unwrap();
        assert!(matches!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), ProcessMonitorMessage::Degraded { consecutive_failures: 1, .. }));
        service.stop();
    }

    #[test]
    fn invalid_intervals_are_rejected() {
        assert!(PollingConfig { interval: Duration::ZERO, max_backoff: Duration::from_secs(1) }.validate().is_err());
        assert!(PollingConfig { interval: Duration::from_secs(2), max_backoff: Duration::from_secs(1) }.validate().is_err());
    }

    #[test]
    fn retry_backoff_is_capped() {
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(5), 1), Duration::from_secs(1));
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(5), 3), Duration::from_secs(4));
        assert_eq!(backoff(Duration::from_secs(1), Duration::from_secs(5), 8), Duration::from_secs(5));
    }
}
