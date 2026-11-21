//! Deterministic, UI-independent application command processor.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::{
    ProtectionStatus,
    events::MonitorSource,
    rules::{ObservedTarget, Rule, RuleValidationError},
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
    /// Stable diagnostic identifier; never place secrets or raw paths here.
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
    pub monitors: BTreeMap<MonitorSource, MonitorStatus>,
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
        source: MonitorSource,
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
    monitors: BTreeMap<MonitorSource, MonitorStatus>,
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

    /// Return matching enabled rules in stable ID order. This is a decision
    /// result only; callers must not treat it as an enforcement operation.
    pub fn matching_rules(&self, observed: &ObservedTarget) -> Vec<&Rule> {
        self.rules.values().filter(|rule| rule.matches(observed)).collect()
    }

    pub fn execute(&mut self, command: Command) -> Result<CommandResult, CommandError> {
        match command {
            Command::CompleteSetup => {
                if self.protection != ProtectionStatus::NotConfigured {
                    return Err(CommandError::AlreadyConfigured);
                }
                let revision = self.next_revision()?;
                self.protection = ProtectionStatus::Unlocked;
                self.revision = revision;
                Ok(CommandResult::StateChanged { revision })
            }
            Command::Unlock => {
                if self.protection == ProtectionStatus::NotConfigured {
                    return Err(CommandError::NotConfigured);
                }
                if self.protection != ProtectionStatus::Locked {
                    return Err(CommandError::NotLocked);
                }
                let revision = self.next_revision()?;
                self.protection = ProtectionStatus::Unlocked;
                self.revision = revision;
                Ok(CommandResult::StateChanged { revision })
            }
            Command::Lock => {
                if self.protection != ProtectionStatus::Unlocked {
                    return Err(if self.protection == ProtectionStatus::NotConfigured {
                        CommandError::NotConfigured
                    } else {
                        CommandError::NotUnlocked
                    });
                }
                let revision = self.next_revision()?;
                self.protection = ProtectionStatus::Locked;
                self.revision = revision;
                Ok(CommandResult::StateChanged { revision })
            }
            Command::SetMonitoringEnabled(enabled) => {
                if self.monitoring_enabled == enabled {
                    return Ok(CommandResult::NoChange { revision: self.revision });
                }
                let revision = self.next_revision()?;
                self.monitoring_enabled = enabled;
                self.revision = revision;
                Ok(CommandResult::StateChanged { revision })
            }
            Command::AddRule(rule) => {
                rule.validate()?;
                if self.rules.contains_key(&rule.id) {
                    return Err(CommandError::DuplicateRule);
                }
                let revision = self.next_revision()?;
                self.rules.insert(rule.id, rule);
                self.revision = revision;
                Ok(CommandResult::RuleAdded { revision })
            }
            Command::RemoveRule(id) => {
                if !self.rules.contains_key(&id) {
                    return Err(CommandError::RuleNotFound);
                }
                let revision = self.next_revision()?;
                self.rules.remove(&id);
                self.revision = revision;
                Ok(CommandResult::RuleRemoved { revision })
            }
            Command::SetMonitorStatus { source, status } => {
                if self.monitors.get(&source) == Some(&status) {
                    return Ok(CommandResult::NoChange { revision: self.revision });
                }
                let revision = self.next_revision()?;
                self.monitors.insert(source, status);
                self.revision = revision;
                Ok(CommandResult::StateChanged { revision })
            }
        }
    }

    fn next_revision(&self) -> Result<u64, CommandError> {
        self.revision.checked_add(1).ok_or(CommandError::RevisionExhausted)
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
    fn matching_rules_are_returned_in_id_order() {
        let mut engine = CoreEngine::new();
        engine.execute(Command::AddRule(rule(9))).unwrap();
        engine.execute(Command::AddRule(rule(2))).unwrap();
        let observed = ObservedTarget::new(RuleTargetKind::ProcessName, "GAME.EXE");
        let matches = engine.matching_rules(&observed);
        assert_eq!(matches.iter().map(|rule| rule.id).collect::<Vec<_>>(), vec![2, 9]);
    }

    #[test]
    fn monitor_unavailability_is_not_reported_as_healthy() {
        let mut engine = CoreEngine::new();
        engine.execute(Command::SetMonitorStatus {
            source: MonitorSource::Process,
            status: MonitorStatus {
                health: MonitorHealth::Unavailable,
                last_success_unix_ms: None,
                detail_code: Some("permission_denied"),
            },
        }).unwrap();
        assert_eq!(engine.snapshot().monitors[&MonitorSource::Process].health, MonitorHealth::Unavailable);
    }

    #[test]
    fn unchanged_commands_do_not_increment_revision() {
        let mut engine = CoreEngine::new();
        assert_eq!(engine.execute(Command::SetMonitoringEnabled(false)).unwrap(), CommandResult::NoChange { revision: 0 });
    }
}
