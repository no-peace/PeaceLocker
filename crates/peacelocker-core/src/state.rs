use serde::{Deserialize, Serialize};

/// User-visible protection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProtectionStatus {
    #[default]
    NotConfigured,
    Locked,
    Unlocked,
}

/// Read-only state exposed to the presentation layer.
///
/// Secrets and raw credentials must never be added to this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AppSnapshot {
    pub protection: ProtectionStatus,
    pub monitoring_enabled: bool,
    pub healthy_monitor_count: u32,
    pub configured_rule_count: u32,
}

impl AppSnapshot {
    /// A concise status string for diagnostics and the initial UI.
    pub fn status_label(&self) -> &'static str {
        match self.protection {
            ProtectionStatus::NotConfigured => "not configured",
            ProtectionStatus::Locked => "locked",
            ProtectionStatus::Unlocked => "unlocked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppSnapshot, ProtectionStatus};

    #[test]
    fn default_snapshot_is_not_configured_and_monitoring_is_off() {
        let snapshot = AppSnapshot::default();

        assert_eq!(snapshot.protection, ProtectionStatus::NotConfigured);
        assert!(!snapshot.monitoring_enabled);
        assert_eq!(snapshot.healthy_monitor_count, 0);
    }

    #[test]
    fn status_label_matches_protection_state() {
        let snapshot = AppSnapshot {
            protection: ProtectionStatus::Unlocked,
            ..AppSnapshot::default()
        };

        assert_eq!(snapshot.status_label(), "unlocked");
    }
}
