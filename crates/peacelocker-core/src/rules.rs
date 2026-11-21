//! Validated, deterministic rule definitions and matching.
//!
//! Matching produces decisions only. This module never performs enforcement.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_RULE_VALUE: usize = 4_096;
const MAX_RULE_LABEL: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTargetKind {
    ProcessName,
    ExecutablePath,
    BrowserHost,
    FolderPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Notify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: u64,
    pub label: String,
    pub target_kind: RuleTargetKind,
    pub target: String,
    pub action: RuleAction,
    pub enabled: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleValidationError {
    #[error("rule ID must be non-zero")]
    InvalidId,
    #[error("rule label is empty or too long")]
    InvalidLabel,
    #[error("rule target is empty, too long, or malformed")]
    InvalidTarget,
}

impl Rule {
    pub fn new(
        id: u64,
        label: impl Into<String>,
        target_kind: RuleTargetKind,
        target: impl Into<String>,
        action: RuleAction,
    ) -> Result<Self, RuleValidationError> {
        let rule = Self {
            id,
            label: label.into(),
            target_kind,
            target: target.into(),
            action,
            enabled: true,
        };
        rule.validate()?;
        Ok(rule)
    }

    pub fn validate(&self) -> Result<(), RuleValidationError> {
        if self.id == 0 {
            return Err(RuleValidationError::InvalidId);
        }
        if self.label.trim().is_empty() || self.label.len() > MAX_RULE_LABEL {
            return Err(RuleValidationError::InvalidLabel);
        }
        if self.target.trim().is_empty()
            || self.target.len() > MAX_RULE_VALUE
            || self.target.chars().any(char::is_control)
        {
            return Err(RuleValidationError::InvalidTarget);
        }

        match self.target_kind {
            RuleTargetKind::ProcessName => {
                if self.target.chars().any(|ch| matches!(ch, '/' | '\\')) {
                    return Err(RuleValidationError::InvalidTarget);
                }
            }
            RuleTargetKind::ExecutablePath | RuleTargetKind::FolderPath => {
                if !self.target.chars().any(|ch| matches!(ch, '/' | '\\')) {
                    return Err(RuleValidationError::InvalidTarget);
                }
            }
            RuleTargetKind::BrowserHost => {
                if !is_valid_hostname(&self.target) {
                    return Err(RuleValidationError::InvalidTarget);
                }
            }
        }
        Ok(())
    }

    pub fn matches(&self, observed: &ObservedTarget) -> bool {
        if !self.enabled || self.target_kind != observed.kind { return false; }
        let expected = normalize(self.target_kind, &self.target);
        let actual = normalize(observed.kind, &observed.value);
        if self.target_kind == RuleTargetKind::FolderPath {
            path_is_same_or_child(&expected, &actual)
        } else { expected == actual }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTarget {
    pub kind: RuleTargetKind,
    pub value: String,
}

impl ObservedTarget {
    pub fn new(kind: RuleTargetKind, value: impl Into<String>) -> Self {
        Self { kind, value: value.into() }
    }
}

fn path_is_same_or_child(rule: &str, observed: &str) -> bool {
    if rule == observed { return true; }
    if rule.ends_with('\\') { return observed.starts_with(rule); }
    observed.strip_prefix(rule).is_some_and(|suffix| suffix.starts_with('\\'))
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn normalize(kind: RuleTargetKind, value: &str) -> String {
    let value = value.trim();
    match kind {
        RuleTargetKind::ProcessName | RuleTargetKind::BrowserHost => value.to_ascii_lowercase(),
        RuleTargetKind::ExecutablePath | RuleTargetKind::FolderPath => {
            let normalized = value.replace('/', "\\").to_ascii_lowercase();
            if normalized.len() == 3 && normalized.as_bytes()[1] == b':' && normalized.ends_with('\\') {
                normalized
            } else {
                normalized.trim_end_matches('\\').to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: RuleTargetKind, target: &str) -> Rule {
        Rule::new(1, "test", kind, target, RuleAction::Block).unwrap()
    }

    #[test]
    fn process_name_matching_is_case_insensitive_and_exact() {
        let rule = rule(RuleTargetKind::ProcessName, "Game.exe");
        assert!(rule.matches(&ObservedTarget::new(RuleTargetKind::ProcessName, "game.EXE")));
        assert!(!rule.matches(&ObservedTarget::new(RuleTargetKind::ProcessName, "game.exe.extra")));
    }

    #[test]
    fn windows_paths_normalize_slashes_and_case() {
        let rule = rule(RuleTargetKind::ExecutablePath, "C:/Games/Example/game.exe");
        assert!(rule.matches(&ObservedTarget::new(
            RuleTargetKind::ExecutablePath,
            "c:\\games\\example\\game.exe",
        )));
    }

    #[test]
    fn folder_paths_use_directory_boundaries() {
        let r = rule(RuleTargetKind::FolderPath, r"C:\Data\Private");
        assert!(r.matches(&ObservedTarget::new(RuleTargetKind::FolderPath, r"c:/data/private")));
        assert!(r.matches(&ObservedTarget::new(RuleTargetKind::FolderPath, r"C:\Data\Private\Nested")));
        assert!(!r.matches(&ObservedTarget::new(RuleTargetKind::FolderPath, r"C:\Data\Private2")));
        assert!(!r.matches(&ObservedTarget::new(RuleTargetKind::FolderPath, r"C:\Data\Other")));
    }

    #[test]
    fn target_kinds_never_cross_match() {
        let rule = rule(RuleTargetKind::BrowserHost, "example.com");
        assert!(!rule.matches(&ObservedTarget::new(
            RuleTargetKind::ProcessName,
            "example.com",
        )));
    }

    #[test]
    fn malformed_rules_are_rejected() {
        assert_eq!(
            Rule::new(0, "x", RuleTargetKind::ProcessName, "x.exe", RuleAction::Block)
                .unwrap_err(),
            RuleValidationError::InvalidId,
        );
        assert!(Rule::new(1, "x", RuleTargetKind::BrowserHost, "https://example.com", RuleAction::Block).is_err());
    }

    #[test]
    fn malformed_hostnames_are_rejected() {
        for host in ["https://example.com", ".example.com", "example..com", "-bad.example", "bad-.example", "bad host"] {
            assert!(Rule::new(1, "host", RuleTargetKind::BrowserHost, host, RuleAction::Block).is_err(), "{host}");
        }
    }

    #[test]
    fn disabled_rules_do_not_match() {
        let mut rule = rule(RuleTargetKind::ProcessName, "game.exe");
        rule.enabled = false;
        assert!(!rule.matches(&ObservedTarget::new(RuleTargetKind::ProcessName, "game.exe")));
    }
}
