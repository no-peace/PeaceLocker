//! Deterministic, UI-independent application command processor.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::{
    ProtectionStatus,
    rules::{Rule, RuleValidationError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorHealth {
    NotStarted,
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorStatus {
    pub health: MonitorHealth,
    pub last_success_unix_ms: Option<u64>,
    pub detail_code: Option<&'static str>,
}

impl Default for MonitorStatus {
    fn default() -> Self {
        Self {
            health: MonitorHealth::NotStarted,
            last_success_unix_ms: None,
            detail_code: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSnapshot {
    pub revision: u64,
    pub protection: ProtectionStatus,
    pub monitoring_enabled: bool,
    pub rules: Vec<Rule>,
    pub monitors: BTreeMap<String, MonitorStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    CompleteSetup,
    Unlock,
    Lock,
    SetMonitoringEnabled(bool),
    AddRule(Rule),
    RemoveRule(u64),
    SetMonitorStatus {
        source: String,
        status: MonitorStatus,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandResult {
    StateChanged { revision: u64 },
    NoChange { revision: u64 },
    RuleAdded { revision: u64 },
    RuleRemoved { revision: u64 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("protection has not been configured")]
    NotConfigured,
    #[error("protection is already configured")]
    AlreadyConfigured,
    #[error("application is not locked")]
    NotLocked,
    #[error("application is not unlocked")]
    NotUnlocked,
    #[error("rule ID already exists")]
    DuplicateRule,
    #[error("rule ID was not found")]
    RuleNotFound,
    #[error("monitor source identifier is invalid")]
    InvalidMonitorSource,
    #[error("rule validation failed: {0}")]
    InvalidRule(#[from] RuleValidationError),
    #[error("state revision counter is exhausted")]
    RevisionExhausted,
}

#[derive(Debug, Default)]
pub struct CoreEngine {
    protection: ProtectionStatus,
    monitoring_enabled: bool,
    rules: BTreeMap<u64, Rule>,
    monitors: BTreeMap<String, MonitorStatus>,
    revision: u64,
}

impl CoreEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> CoreSnapshot {
        CoreSnapshot {
            revision: self.revision,
            protection: self.protection,
            monitoring_enabled: self.monitoring_enabled,
            rules: self.rules.values().cloned().collect(),
            monitors: self.monitors.clone(),
        }
    }

    pub fn execute(&mut self, command: Command) -> Result<CommandResult, CommandError> {
        match command {
            Command::CompleteSetup => {
                if self.protection != ProtectionStatus::NotConfigured {
                    return Err(CommandError::AlreadyConfigured);
                }
                self.protection = ProtectionStatus::Unlocked;
                self.changed()
            }
            Command::Unlock => {
                if self.protection == ProtectionStatus::NotConfigured {
                    return Err(CommandError::NotConfigured);
                }
                if self.protection != ProtectionStatus::Locked {
                    return Err(CommandError::NotLocked);
                }
                self.protection = ProtectionStatus::Unlocked;
                self.changed()
            }
            Command::Lock => {
                if self.protection != ProtectionStatus::Unlocked {
                    return Err(if self.protection == ProtectionStatus::NotConfigured {
                        CommandError::NotConfigured
                    } else {
                        CommandError::NotUnlocked
                    });
                }
                self.protection = ProtectionStatus::Locked;
                self.changed()
            }
            Command::SetMonitoringEnabled(enabled) => {
                if self.monitoring_enabled == enabled {
                    return Ok(CommandResult::NoChange { revision: self.revision });
                }
                self.monitoring_enabled = enabled;
                self.changed()
            }
            Command::AddRule(rule) => {
                rule.validate()?;
                if self.rules.contains_key(&rule.id) {
                    return Err(CommandError::DuplicateRule);
                }
                self.rules.insert(rule.id, rule);
                let revision = self.bump_revision()?;
                Ok(CommandResult::RuleAdded { revision })
            }
            Command::RemoveRule(id) => {
                if self.rules.remove(&id).is_none() {
                    return Err(CommandError::RuleNotFound);
                }
                let revision = self.bump_revision()?;
                Ok(CommandResult::RuleRemoved { revision })
            }
            Command::SetMonitorStatus { source, status } => {
                if source.trim().is_empty() || source.len() > 64 {
                    return Err(CommandError::InvalidMonitorSource);
                }
                if self.monitors.get(&source) == Some(&status) {
                    return Ok(CommandResult::NoChange { revision: self.revision });
                }
                self.monitors.insert(source, status);
                self.changed()
            }
        }
    }

    fn changed(&mut self) -> Result<CommandResult, CommandError> {
        let revision = self.bump_revision()?;
        Ok(CommandResult::StateChanged { revision })
    }

    fn bump_revision(&mut self) -> Result<u64, CommandError> {
        self.revision = self.revision.checked_add(1).ok_or(CommandError::RevisionExhausted)?;
        Ok(self.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleAction, RuleTargetKind};

    fn rule(id: u64) -> Rule {
        Rule::new(
            id,
            "Game",
            RuleTargetKind::ProcessName,
            "game.exe",
            RuleAction::Block,
        )
        .unwrap()
    }

    #[test]
    fn setup_lock_and_unlock_follow_valid_transitions() {
        let mut engine = CoreEngine::new();
        assert_eq!(engine.snapshot().protection, ProtectionStatus::NotConfigured);
        engine.execute(Command::CompleteSetup).unwrap();
        assert_eq!(engine.snapshot().protection, ProtectionStatus::Unlocked);
        engine.execute(Command::Lock).unwrap();
        assert_eq!(engine.snapshot().protection, ProtectionStatus::Locked);
        engine.execute(Command::Unlock).unwrap();
        assert_eq!(engine.snapshot().protection, ProtectionStatus::Unlocked);
    }

    #[test]
    fn invalid_protection_transitions_are_rejected() {
        let mut engine = CoreEngine::new();
        assert_eq!(engine.execute(Command::Unlock), Err(CommandError::NotConfigured));
        assert_eq!(engine.execute(Command::Lock), Err(CommandError::NotConfigured));
        engine.execute(Command::CompleteSetup).unwrap();
        assert_eq!(engine.execute(Command::CompleteSetup), Err(CommandError::AlreadyConfigured));
        assert_eq!(engine.execute(Command::Unlock), Err(CommandError::NotLocked));
    }

    #[test]
    fn rule_commands_validate_and_update_snapshots() {
        let mut engine = CoreEngine::new();
        assert!(matches!(engine.execute(Command::AddRule(rule(1))), Ok(CommandResult::RuleAdded { revision: 1 })));
        assert_eq!(engine.snapshot().rules.len(), 1);
        assert_eq!(engine.execute(Command::AddRule(rule(1))), Err(CommandError::DuplicateRule));
        assert!(matches!(engine.execute(Command::RemoveRule(1)), Ok(CommandResult::RuleRemoved { revision: 2 })));
        assert!(engine.snapshot().rules.is_empty());
    }

    #[test]
    fn monitor_unavailability_is_not_reported_as_healthy() {
        let mut engine = CoreEngine::new();
        engine.execute(Command::SetMonitorStatus {
            source: "process".into(),
            status: MonitorStatus {
                health: MonitorHealth::Unavailable,
                last_success_unix_ms: None,
                detail_code: Some("permission_denied"),
            },
        }).unwrap();
        assert_eq!(engine.snapshot().monitors["process"].health, MonitorHealth::Unavailable);
    }

    #[test]
    fn unchanged_commands_do_not_increment_revision() {
        let mut engine = CoreEngine::new();
        assert_eq!(engine.execute(Command::SetMonitoringEnabled(false)).unwrap(), CommandResult::NoChange { revision: 0 });
    }
}
