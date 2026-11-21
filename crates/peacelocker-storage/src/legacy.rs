//! Read-only importer for the legacy C++ key=value text configuration.
//!
//! Credential material is deliberately not migrated: legacy PIN verifiers,
//! peppers, recovery hashes, and the legacy HMAC are not compatible with the
//! Rust security model. The user must establish a new Rust PIN.

use super::{BlockedItem, ConfigDocument, MAX_BLOCKED_ITEMS, StoreError};

const MAX_LEGACY_BYTES: usize = 1024 * 1024;
const MAX_LINE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySettings {
    pub auto_start: bool,
    pub shell_integration: bool,
    pub activity_logging_enabled: bool,
    pub webhook_url: Option<String>,
    pub blocked_items: Vec<BlockedItem>,
}

impl Default for LegacySettings {
    fn default() -> Self {
        Self {
            auto_start: true,
            shell_integration: true,
            activity_logging_enabled: false,
            webhook_url: None,
            blocked_items: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyImportReport {
    pub settings: LegacySettings,
    pub credential_reset_required: bool,
    pub ignored_sensitive_fields: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyImportError {
    FileTooLarge,
    LineTooLarge,
    TooManyBlockedItems,
    InvalidBlockedEntry,
    InvalidSetting,
}

impl std::fmt::Display for LegacyImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::FileTooLarge => "legacy configuration exceeds 1 MiB",
            Self::LineTooLarge => "legacy configuration line exceeds 8 KiB",
            Self::TooManyBlockedItems => "legacy configuration contains too many blocked items",
            Self::InvalidBlockedEntry => "legacy blocked-item entry is malformed",
            Self::InvalidSetting => "legacy boolean setting is malformed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LegacyImportError {}

impl LegacyImportReport {
    /// Apply the reviewed, non-credential settings to a newly initialized Rust
    /// document. A fresh Rust PIN verifier must already be present.
    pub fn apply_to(&self, document: &mut ConfigDocument) -> Result<(), StoreError> {
        document.auto_start = self.settings.auto_start;
        document.shell_integration = self.settings.shell_integration;
        document.activity_logging_enabled = self.settings.activity_logging_enabled;
        document.webhook_url = self.settings.webhook_url.clone();
        document.blocked_items = self.settings.blocked_items.clone();
        document.validate()
    }
}

/// Parse only safe, non-credential settings from legacy plaintext key=value
/// data. Does not read files, decrypt legacy binary containers, or mutate input.
pub fn parse_legacy_text(input: &str) -> Result<LegacyImportReport, LegacyImportError> {
    if input.len() > MAX_LEGACY_BYTES {
        return Err(LegacyImportError::FileTooLarge);
    }

    let mut report = LegacyImportReport {
        settings: LegacySettings::default(),
        credential_reset_required: false,
        ignored_sensitive_fields: Vec::new(),
        warnings: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();

    for raw_line in input.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.len() > MAX_LINE_BYTES {
            return Err(LegacyImportError::LineTooLarge);
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key {
            "pin" | "pinsalt" | "piniter" | "pinv" | "pepper" | "pinfail"
            | "pinlock" | "recsalt" | "rechash" | "hmac" => {
                report.credential_reset_required = true;
                if key == "hmac" {
                    report.warnings.push(
                        "Legacy HMAC was not trusted because the old format used a hardcoded key."
                            .to_owned(),
                    );
                }
                if !report.ignored_sensitive_fields.iter().any(|field| field == key) {
                    report.ignored_sensitive_fields.push(key.to_owned());
                }
            }
            "auto" => {
                if !seen.insert(key) {
                    report.warnings.push("duplicate auto setting; last value used".into());
                }
                report.settings.auto_start = parse_bool(value)?;
            }
            "shell" => {
                if !seen.insert(key) {
                    report.warnings.push("duplicate shell setting; last value used".into());
                }
                report.settings.shell_integration = parse_bool(value)?;
            }
            "logall" => {
                if !seen.insert(key) {
                    report.warnings.push("duplicate logall setting; last value used".into());
                }
                report.settings.activity_logging_enabled = parse_bool(value)?;
            }
            "webhook" => {
                if value.is_empty() {
                    report.settings.webhook_url = None;
                } else if value.starts_with("https://") && value.len() <= 2_048 {
                    report.settings.webhook_url = Some(value.to_owned());
                } else {
                    report.settings.webhook_url = None;
                    report.warnings.push("webhook URL omitted because it is not a bounded HTTPS URL".into());
                }
            }
            "b" => {
                if report.settings.blocked_items.len() >= MAX_BLOCKED_ITEMS {
                    return Err(LegacyImportError::TooManyBlockedItems);
                }
                let mut parts = value.splitn(3, '|');
                let target_type = parts.next().unwrap_or_default();
                let item_value = parts.next().unwrap_or_default();
                let label = parts.next().unwrap_or_default();
                if target_type.is_empty()
                    || target_type.len() > 32
                    || item_value.is_empty()
                    || item_value.len() > 4_096
                    || label.len() > 256
                {
                    return Err(LegacyImportError::InvalidBlockedEntry);
                }
                report.settings.blocked_items.push(BlockedItem {
                    target_type: target_type.to_owned(),
                    value: item_value.to_owned(),
                    label: label.to_owned(),
                });
            }
            _ => {}
        }
    }

    Ok(report)
}

fn parse_bool(value: &str) -> Result<bool, LegacyImportError> {
    match value {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(LegacyImportError::InvalidSetting),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_only_supported_non_credential_settings() {
        let input = concat!(
            "pin=legacy-sha256-hash\n",
            "pepper=DPAPI:opaque\n",
            "auto=0\n",
            "shell=1\n",
            "logall=0\n",
            "webhook=https://discord.com/api/webhooks/example\n",
            "b=url|example.com|Example\n",
        );
        let report = parse_legacy_text(input).unwrap();
        assert!(report.credential_reset_required);
        assert!(report.ignored_sensitive_fields.contains(&"pin".to_owned()));
        assert!(!report.settings.auto_start);
        assert!(report.settings.shell_integration);
        assert!(!report.settings.activity_logging_enabled);
        assert_eq!(report.settings.blocked_items.len(), 1);
        assert_eq!(report.settings.webhook_url.as_deref(), Some("https://discord.com/api/webhooks/example"));
    }

    #[test]
    fn rejects_plaintext_http_webhook() {
        let report = parse_legacy_text("webhook=http://example.invalid/hook\n").unwrap();
        assert!(report.settings.webhook_url.is_none());
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn rejects_malformed_blocked_item() {
        assert_eq!(parse_legacy_text("b=only-type\n"), Err(LegacyImportError::InvalidBlockedEntry));
    }

    #[test]
    fn rejects_oversized_input() {
        let input = "x".repeat(MAX_LEGACY_BYTES + 1);
        assert_eq!(parse_legacy_text(&input), Err(LegacyImportError::FileTooLarge));
    }
}
