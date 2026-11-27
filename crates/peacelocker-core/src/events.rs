//! Normalized monitor events and a bounded in-memory event queue.

use std::collections::VecDeque;
use serde::{Deserialize, Serialize};
use crate::rules::ObservedTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorSource { Process, Explorer, Browser }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorEventKind { Observed, ProcessStarted, ProcessExited, BrowserNavigated, ExplorerChanged }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorEvent {
    pub id: u128,
    pub occurred_at_unix_ms: u64,
    pub source: MonitorSource,
    pub kind: MonitorEventKind,
    pub correlation_id: Option<u128>,
    pub target: ObservedTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueInsert { Accepted, AcceptedAfterDroppingOldest, Duplicate }

pub struct EventQueue { capacity: usize, events: VecDeque<MonitorEvent>, dropped_count: u64 }

impl EventQueue {
    pub fn new(capacity: usize) -> Self {
        Self { capacity: capacity.max(1), events: VecDeque::new(), dropped_count: 0 }
    }
    pub fn push(&mut self, event: MonitorEvent) -> QueueInsert {
        if self.events.iter().any(|queued| queued.id == event.id) { return QueueInsert::Duplicate; }
        if self.events.len() == self.capacity {
            self.events.pop_front();
            self.dropped_count = self.dropped_count.saturating_add(1);
            self.events.push_back(event);
            QueueInsert::AcceptedAfterDroppingOldest
        } else {
            self.events.push_back(event);
            QueueInsert::Accepted
        }
    }
    pub fn pop(&mut self) -> Option<MonitorEvent> { self.events.pop_front() }
    pub fn len(&self) -> usize { self.events.len() }
    pub fn is_empty(&self) -> bool { self.events.is_empty() }
    pub fn dropped_count(&self) -> u64 { self.dropped_count }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleTargetKind;
    fn event(id: u128) -> MonitorEvent {
        MonitorEvent { id, occurred_at_unix_ms: 1_800_000_000_000, source: MonitorSource::Process,
            kind: MonitorEventKind::ProcessStarted, correlation_id: None,
            target: ObservedTarget::new(RuleTargetKind::ProcessName, "game.exe") }
    }
    #[test]
    fn queue_is_bounded_and_drops_oldest() {
        let mut queue = EventQueue::new(2);
        assert_eq!(queue.push(event(1)), QueueInsert::Accepted);
        assert_eq!(queue.push(event(2)), QueueInsert::Accepted);
        assert_eq!(queue.push(event(3)), QueueInsert::AcceptedAfterDroppingOldest);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_count(), 1);
        assert_eq!(queue.pop().unwrap().id, 2);
        assert_eq!(queue.pop().unwrap().id, 3);
    }
    #[test]
    fn duplicate_queued_event_ids_are_ignored() {
        let mut queue = EventQueue::new(2);
        assert_eq!(queue.push(event(7)), QueueInsert::Accepted);
        assert_eq!(queue.push(event(7)), QueueInsert::Duplicate);
        assert_eq!(queue.len(), 1);
    }
    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut queue = EventQueue::new(0);
        queue.push(event(1)); queue.push(event(2));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dropped_count(), 1);
    }
}
