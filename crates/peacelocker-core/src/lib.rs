//! Platform-independent application types, commands, rules, and events.

mod engine;
mod events;
mod rules;
mod state;

pub use engine::{
    Command, CommandError, CommandResult, CoreEngine, CoreSnapshot, MonitorHealth, MonitorStatus,
};
pub use events::{EventQueue, MonitorEvent, MonitorSource, QueueInsert};
pub use rules::{
    ObservedTarget, Rule, RuleAction, RuleTargetKind, RuleValidationError,
};
pub use state::{AppSnapshot, ProtectionStatus};
