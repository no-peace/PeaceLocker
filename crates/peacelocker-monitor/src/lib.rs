//! Monitoring source contracts, process tracking, and supervised workers.

use peacelocker_core::{MonitorEvent, MonitorHealth, MonitorSource, MonitorStatus};
mod process;
mod service;
pub use process::{ProcessChange, ProcessChangeKind, ProcessIdentity, ProcessSnapshot, ProcessTracker};
pub use service::{PollingConfig, PollingConfigError, ProcessMonitorMessage, ProcessMonitorService, ProcessPollResult};

pub trait MonitorAdapter: Send {
    fn source(&self) -> MonitorSource;
    fn status(&self) -> MonitorStatus;
    fn drain_events(&mut self) -> Vec<MonitorEvent>;
}

#[derive(Debug)]
pub struct FakeMonitorAdapter { source: MonitorSource, status: MonitorStatus, events: Vec<MonitorEvent> }

impl FakeMonitorAdapter {
    pub fn new(source: MonitorSource) -> Self {
        Self { source, status: MonitorStatus { health: MonitorHealth::NotStarted, last_success_unix_ms: None, detail_code: None }, events: Vec::new() }
    }
    pub fn set_status(&mut self, status: MonitorStatus) { self.status = status; }
    pub fn push_event(&mut self, event: MonitorEvent) { self.events.push(event); }
}
impl MonitorAdapter for FakeMonitorAdapter {
    fn source(&self) -> MonitorSource { self.source }
    fn status(&self) -> MonitorStatus { self.status.clone() }
    fn drain_events(&mut self) -> Vec<MonitorEvent> { std::mem::take(&mut self.events) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peacelocker_core::{MonitorEventKind, ObservedTarget, RuleTargetKind};
    #[test]
    fn fake_adapter_reports_health_and_drains_events() {
        let mut adapter = FakeMonitorAdapter::new(MonitorSource::Process);
        assert_eq!(adapter.status().health, MonitorHealth::NotStarted);
        adapter.set_status(MonitorStatus { health: MonitorHealth::Healthy, last_success_unix_ms: Some(1_800_000_000_000), detail_code: None });
        adapter.push_event(MonitorEvent { id: 1, occurred_at_unix_ms: 1_800_000_000_000, source: MonitorSource::Process,
            kind: MonitorEventKind::ProcessStarted, correlation_id: Some(99),
            target: ObservedTarget::new(RuleTargetKind::ProcessName, "game.exe") });
        assert_eq!(adapter.source(), MonitorSource::Process);
        assert_eq!(adapter.status().health, MonitorHealth::Healthy);
        assert_eq!(adapter.drain_events().len(), 1);
        assert!(adapter.drain_events().is_empty());
    }
}
