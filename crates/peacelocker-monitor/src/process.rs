//! Process snapshot diffing with PID-reuse protection.
//!
//! This module is platform-independent. Windows adapters supply snapshots
//! using documented process-query APIs.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// FILETIME creation timestamp (100 ns intervals since 1601-01-01 UTC).
    pub creation_time_100ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub identity: ProcessIdentity,
    pub name: String,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessChangeKind {
    Started,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessChange {
    pub kind: ProcessChangeKind,
    pub process: ProcessSnapshot,
}

/// Diffs process snapshots by PID and creation time. A PID observed with a
/// different creation time is treated as an exit followed by a new start.
#[derive(Debug, Default)]
pub struct ProcessTracker {
    current: BTreeMap<u32, ProcessSnapshot>,
}

impl ProcessTracker {
    pub fn update<I>(&mut self, snapshots: I) -> Vec<ProcessChange>
    where
        I: IntoIterator<Item = ProcessSnapshot>,
    {
        let mut next = BTreeMap::new();
        for process in snapshots {
            // Duplicate PIDs in one snapshot are invalid; retain the first
            // observation to keep output deterministic.
            next.entry(process.identity.pid).or_insert(process);
        }

        let mut changes = Vec::new();

        for (pid, previous) in &self.current {
            match next.get(pid) {
                None => changes.push(ProcessChange {
                    kind: ProcessChangeKind::Exited,
                    process: previous.clone(),
                }),
                Some(current)
                    if current.identity.creation_time_100ns
                        != previous.identity.creation_time_100ns =>
                {
                    changes.push(ProcessChange {
                        kind: ProcessChangeKind::Exited,
                        process: previous.clone(),
                    });
                }
                _ => {}
            }
        }

        for (pid, current) in &next {
            let is_new_lifetime = self.current.get(pid).is_none_or(|previous| {
                previous.identity.creation_time_100ns
                    != current.identity.creation_time_100ns
            });
            if is_new_lifetime {
                changes.push(ProcessChange {
                    kind: ProcessChangeKind::Started,
                    process: current.clone(),
                });
            }
        }

        self.current = next;
        changes
    }

    pub fn current(&self) -> impl Iterator<Item = &ProcessSnapshot> {
        self.current.values()
    }

    pub fn clear(&mut self) -> Vec<ProcessChange> {
        let previous = std::mem::take(&mut self.current);
        previous
            .into_values()
            .map(|process| ProcessChange {
                kind: ProcessChangeKind::Exited,
                process,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, created: u64, name: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            identity: ProcessIdentity {
                pid,
                creation_time_100ns: created,
            },
            name: name.into(),
            executable_path: None,
        }
    }

    #[test]
    fn initial_snapshot_reports_all_processes_as_started() {
        let mut tracker = ProcessTracker::default();
        let changes = tracker.update([process(10, 100, "one.exe"), process(20, 200, "two.exe")]);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|change| change.kind == ProcessChangeKind::Started));
    }

    #[test]
    fn unchanged_snapshot_does_not_emit_duplicate_starts() {
        let mut tracker = ProcessTracker::default();
        tracker.update([process(10, 100, "one.exe")]);
        assert!(tracker.update([process(10, 100, "one.exe")]).is_empty());
    }

    #[test]
    fn removed_process_is_reported_as_exited() {
        let mut tracker = ProcessTracker::default();
        tracker.update([process(10, 100, "one.exe")]);
        let changes = tracker.update([]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ProcessChangeKind::Exited);
        assert_eq!(changes[0].process.identity.pid, 10);
    }

    #[test]
    fn pid_reuse_emits_exit_and_start() {
        let mut tracker = ProcessTracker::default();
        tracker.update([process(10, 100, "old.exe")]);
        let changes = tracker.update([process(10, 200, "new.exe")]);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].kind, ProcessChangeKind::Exited);
        assert_eq!(changes[1].kind, ProcessChangeKind::Started);
    }

    #[test]
    fn duplicate_pid_in_snapshot_is_deterministic() {
        let mut tracker = ProcessTracker::default();
        let changes = tracker.update([process(10, 100, "first.exe"), process(10, 200, "second.exe")]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].process.name, "first.exe");
    }
}
