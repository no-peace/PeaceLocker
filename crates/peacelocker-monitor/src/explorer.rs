//! Platform-independent Explorer window identity and folder-change tracking.
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExplorerWindowIdentity {
    pub hwnd: isize,
    pub process_id: u32,
    pub process_creation_time_100ns: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerObservation {
    pub identity: ExplorerWindowIdentity,
    /// Absolute local filesystem path; never a URL or window title.
    pub folder_path: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerChange {
    pub identity: ExplorerWindowIdentity,
    pub previous_path: Option<String>,
    pub folder_path: String,
}
#[derive(Debug, Default)]
pub struct ExplorerTracker {
    baseline_established: bool,
    current: BTreeMap<ExplorerWindowIdentity, String>,
}
impl ExplorerTracker {
    /// The first successful snapshot establishes a baseline. Later new or
    /// navigated windows emit changes. Duplicate identities keep first value.
    pub fn update(&mut self, observations: impl IntoIterator<Item = ExplorerObservation>) -> Vec<ExplorerChange> {
        let mut next = BTreeMap::new();
        for observation in observations {
            if is_absolute_local_path(&observation.folder_path) {
                next.entry(observation.identity).or_insert_with(|| normalize_path(&observation.folder_path));
            }
        }
        let mut changes = Vec::new();
        if self.baseline_established {
            for (identity, path) in &next {
                let previous = self.current.get(identity);
                if previous != Some(path) {
                    changes.push(ExplorerChange { identity: *identity, previous_path: previous.cloned(), folder_path: path.clone() });
                }
            }
        }
        self.current = next;
        self.baseline_established = true;
        changes
    }
    pub fn clear(&mut self) { self.current.clear(); self.baseline_established = false; }
    pub fn tracked_window_count(&self) -> usize { self.current.len() }
}
fn is_absolute_local_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/')) || path.starts_with(r"\\")
}
fn normalize_path(path: &str) -> String {
    let value = path.replace('/', "\\").to_ascii_lowercase();
    if value.len() == 3 && value.as_bytes()[1] == b':' && value.ends_with('\\') { value }
    else { value.trim_end_matches('\\').to_owned() }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn obs(hwnd: isize, path: &str) -> ExplorerObservation {
        ExplorerObservation { identity: ExplorerWindowIdentity { hwnd, process_id: 10, process_creation_time_100ns: 20 }, folder_path: path.into() }
    }
    #[test] fn first_snapshot_is_baseline() {
        let mut t = ExplorerTracker::default();
        assert!(t.update([obs(1, r"C:\Data")]).is_empty());
        assert_eq!(t.tracked_window_count(), 1);
    }
    #[test] fn folder_navigation_is_reported() {
        let mut t = ExplorerTracker::default();
        t.update([obs(1, r"C:\\Data")]);
        let c = t.update([obs(1, r"C:\Data\Private")]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].previous_path.as_deref(), Some(r"c:\data"));
    }
    #[test] fn reused_hwnd_with_new_process_identity_is_new_window() {
        let mut t = ExplorerTracker::default();
        t.update([obs(1, r"C:\\Data")]);
        let mut replacement = obs(1, r"C:\\Data");
        replacement.identity.process_creation_time_100ns += 1;
        assert_eq!(t.update([replacement]).len(), 1);
    }
    #[test] fn urls_and_relative_paths_are_rejected() {
        let mut t = ExplorerTracker::default();
        t.update([obs(1, "file:///C:/Data"), obs(2, "relative")]);
        assert_eq!(t.tracked_window_count(), 0);
    }
}
