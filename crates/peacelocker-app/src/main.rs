#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use std::path::PathBuf;
use eframe::egui;
use peacelocker_core::{AppSnapshot, Command, CoreEngine, EventQueue, MonitorEvent, MonitorEventKind, MonitorSource, ObservedTarget, Rule, RuleAction, RuleTargetKind};

#[cfg(windows)]
use std::{sync::mpsc::Receiver, time::Duration};
#[cfg(windows)]
use peacelocker_monitor::{PollingConfig, ProcessMonitorMessage, ProcessMonitorService};
#[cfg(windows)]
use peacelocker_windows::{SecuritySession, UnlockResult};

#[cfg(windows)]
fn default_config_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|root| root.join("PeaceLocker").join("config.enc"))
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .with_target(false).init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("PeaceLocker")
            .with_inner_size([1120.0, 720.0]).with_min_inner_size([800.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native("PeaceLocker", options, Box::new(|_cc| Ok(Box::new(PeaceLockerApp::default()))))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppSection { Overview, Protection, Monitoring, Rules, Activity, Security, Notifications, Settings }

impl AppSection {
    const ALL: [(Self, &'static str); 8] = [
        (Self::Overview, "[01] OVERVIEW"), (Self::Protection, "[02] PROTECTION"),
        (Self::Monitoring, "[03] MONITORING"), (Self::Rules, "[04] RULES"),
        (Self::Activity, "[05] ACTIVITY"), (Self::Security, "[06] SECURITY"),
        (Self::Notifications, "[07] NOTIFICATIONS"), (Self::Settings, "[08] SETTINGS"),
    ];
}

struct PeaceLockerApp {
    active_section: AppSection,
    security_message: String,
    #[cfg(windows)] security_path: Option<PathBuf>,
    #[cfg(windows)] security_configured: bool,
    #[cfg(windows)] security_session: Option<SecuritySession>,
    #[cfg(windows)] pin_input: String,
    #[cfg(windows)] pin_confirmation: String,
    #[cfg(windows)] recovery_codes: Vec<String>,
    snapshot: AppSnapshot,
    core: CoreEngine,
    event_queue: EventQueue,
    next_event_id: u128,
    matched_rule_count: usize,
    last_event: String,
    monitor_error: Option<String>,
    #[cfg(windows)]
    process_monitor: Option<ProcessMonitorService>,
    #[cfg(windows)]
    process_receiver: Option<Receiver<ProcessMonitorMessage>>,
    #[cfg(windows)]
    process_monitor_status: String,
    #[cfg(windows)]
    inaccessible_count: u32,
    #[cfg(windows)]
    explorer_monitor: Option<peacelocker_windows::ExplorerMonitorService>,
    #[cfg(windows)]
    explorer_receiver: Option<Receiver<peacelocker_windows::ExplorerMonitorMessage>>,
    #[cfg(windows)]
    explorer_tracker: peacelocker_monitor::ExplorerTracker,
    #[cfg(windows)]
    explorer_status: String,
    #[cfg(windows)]
    explorer_window_count: usize,
    #[cfg(windows)]
    browser_monitor: Option<peacelocker_windows::BrowserMonitorService>,
    #[cfg(windows)]
    browser_receiver: Option<Receiver<peacelocker_windows::BrowserMonitorMessage>>,
    #[cfg(windows)]
    browser_tracker: peacelocker_monitor::BrowserTracker,
    #[cfg(windows)]
    browser_status: String,
    #[cfg(windows)]
    browser_last_host: String,
    rule_label: String,
    rule_target: String,
    rule_kind: RuleTargetKind,
    rule_action: peacelocker_core::RuleAction,
    editing_rule_id: Option<u64>,
    rule_error: Option<String>,
}
impl Default for PeaceLockerApp {
    fn default() -> Self {
        #[cfg(windows)]
        let security_path = default_config_path();
        #[cfg(windows)]
        let security_configured = security_path.as_ref().is_some_and(|path| SecuritySession::configuration_exists(path.clone()));
        Self {
            active_section: AppSection::Overview,
            security_message: "Security session is locked".into(),
            #[cfg(windows)] security_path,
            #[cfg(windows)] security_configured,
            #[cfg(windows)] security_session: None,
            #[cfg(windows)] pin_input: String::new(),
            #[cfg(windows)] pin_confirmation: String::new(),
            #[cfg(windows)] recovery_codes: Vec::new(),
            snapshot: AppSnapshot::default(), core: CoreEngine::new(), event_queue: EventQueue::new(1024),
            next_event_id: 1, matched_rule_count: 0, last_event: "No process events observed".into(),
            monitor_error: None,
            #[cfg(windows)] process_monitor: None,
            #[cfg(windows)] process_receiver: None,
            #[cfg(windows)] process_monitor_status: "Not started".into(),
            #[cfg(windows)] inaccessible_count: 0,
            #[cfg(windows)] explorer_monitor: None,
            #[cfg(windows)] explorer_receiver: None,
            #[cfg(windows)] explorer_tracker: peacelocker_monitor::ExplorerTracker::default(),
            #[cfg(windows)] explorer_status: "Not started".into(),
            #[cfg(windows)] explorer_window_count: 0,
            #[cfg(windows)] browser_monitor: None,
            #[cfg(windows)] browser_receiver: None,
            #[cfg(windows)] browser_tracker: peacelocker_monitor::BrowserTracker::default(),
            #[cfg(windows)] browser_status: "Not started".into(),
            #[cfg(windows)] browser_last_host: "No browser URL observed".into(),
            rule_label: String::new(), rule_target: String::new(),
            rule_kind: RuleTargetKind::ProcessName,
            rule_action: peacelocker_core::RuleAction::Block,
            editing_rule_id: None, rule_error: None,
        }
    }
}

impl PeaceLockerApp {
    fn save_rule(&mut self) {
        let id = match self.editing_rule_id {
            Some(id) => id,
            None => match self.core.snapshot().rules.iter().map(|rule| rule.id).max() {
                Some(max_id) => match max_id.checked_add(1) {
                    Some(id) => id,
                    None => { self.rule_error = Some("Rule ID space is exhausted.".into()); return; }
                },
                None => 1,
            },
        };

        let existing_rules = self.core.snapshot().rules;
        let mut rule = match Rule::new(id, self.rule_label.trim(), self.rule_kind,
            self.rule_target.trim(), self.rule_action) {
            Ok(rule) => rule,
            Err(error) => { self.rule_error = Some(error.to_string()); return; }
        };
        if let Some(existing) = existing_rules.iter().find(|item| item.id == id) {
            rule.enabled = existing.enabled;
        }

        let mut next_rules = existing_rules.clone();
        if let Some(existing) = next_rules.iter_mut().find(|item| item.id == id) {
            *existing = rule.clone();
        } else {
            next_rules.push(rule.clone());
        }

        #[cfg(windows)]
        if !self.persist_rules(next_rules) { return; }

        let command = if self.editing_rule_id.is_some() {
            Command::ReplaceRule(rule)
        } else {
            Command::AddRule(rule)
        };
        match self.core.execute(command) {
            Ok(_) => {
                self.rule_label.clear();
                self.rule_target.clear();
                self.editing_rule_id = None;
                self.rule_error = None;
            }
            Err(error) => self.rule_error = Some(error.to_string()),
        }
    }

    #[cfg(windows)]
    fn persist_rules(&mut self, rules: Vec<Rule>) -> bool {
        let Some(session) = self.security_session.as_mut() else {
            self.rule_error = Some("Unlock PeaceLocker before changing persistent rules.".into());
            return false;
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        match session.save_rules(rules, now) {
            Ok(()) => true,
            Err(error) => {
                self.rule_error = Some(format!("Could not save encrypted rules: {error}"));
                false
            }
        }
    }

    fn set_rule_enabled(&mut self, id: u64, enabled: bool) {
        let mut next_rules = self.core.snapshot().rules;
        let Some(rule) = next_rules.iter_mut().find(|rule| rule.id == id) else { return; };
        rule.enabled = enabled;
        #[cfg(windows)]
        if !self.persist_rules(next_rules) { return; }
        if let Err(error) = self.core.execute(Command::SetRuleEnabled { id, enabled }) {
            self.rule_error = Some(error.to_string());
        }
    }

    fn delete_rule(&mut self, id: u64) {
        let mut next_rules = self.core.snapshot().rules;
        next_rules.retain(|rule| rule.id != id);
        #[cfg(windows)]
        if !self.persist_rules(next_rules) { return; }
        if let Err(error) = self.core.execute(Command::RemoveRule(id)) {
            self.rule_error = Some(error.to_string());
            return;
        }
        if self.editing_rule_id == Some(id) {
            self.editing_rule_id = None;
            self.rule_label.clear();
            self.rule_target.clear();
        }
    }

    fn begin_edit_rule(&mut self, rule: &peacelocker_core::Rule) {
        self.editing_rule_id = Some(rule.id);
        self.rule_label = rule.label.clone();
        self.rule_target = rule.target.clone();
        self.rule_kind = rule.target_kind;
        self.rule_action = rule.action;
        self.rule_error = None;
    }

    #[cfg(windows)]
    fn activate_security_session(&mut self, session: SecuritySession) {
        let stored_rules = session.config().rules.clone();
        let mut core = CoreEngine::new();
        let _ = core.execute(Command::CompleteSetup);
        for rule in stored_rules {
            if let Err(error) = core.execute(Command::AddRule(rule)) {
                self.rule_error = Some(format!("A stored rule could not be loaded: {error}"));
            }
        }
        self.core = core;
        self.security_session = Some(session);
        self.security_configured = true;
        self.security_message = "UNLOCKED // encrypted configuration loaded".into();
    }

    #[cfg(windows)]
    fn setup_security(&mut self) {
        let Some(path) = self.security_path.clone() else {
            self.security_message = "LOCALAPPDATA is unavailable; cannot resolve a safe configuration location.".into();
            return;
        };
        let pin = self.pin_input.clone();
        if pin.as_bytes().len() < 6 || pin.as_bytes().len() > 128 {
            self.security_message = "Use a passphrase/PIN between 6 and 128 bytes.".into();
            return;
        }
        if pin != self.pin_confirmation {
            self.security_message = "PIN confirmation does not match.".into();
            return;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        match SecuritySession::setup(path, pin.as_bytes(), now) {
            Ok((session, setup)) => {
                self.recovery_codes = setup.recovery_codes;
                self.pin_input.clear();
                self.pin_confirmation.clear();
                self.activate_security_session(session);
                self.security_message = "SETUP COMPLETE // save the one-time recovery codes below".into();
            }
            Err(error) => self.security_message = format!("SETUP FAILED // {error}"),
        }
    }

    #[cfg(windows)]
    fn unlock_security(&mut self) {
        let Some(path) = self.security_path.clone() else {
            self.security_message = "LOCALAPPDATA is unavailable; cannot resolve the configuration location.".into();
            return;
        };
        let pin = self.pin_input.clone();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        match SecuritySession::unlock(path, pin.as_bytes(), now) {
            Ok(UnlockResult::Authenticated(session)) => {
                self.pin_input.clear();
                self.activate_security_session(session);
            }
            Ok(UnlockResult::Rejected { attempts_remaining }) => {
                self.pin_input.clear();
                self.security_message = format!("ACCESS DENIED // {attempts_remaining} attempts remaining");
            }
            Ok(UnlockResult::LockedOut { until_unix }) => {
                self.pin_input.clear();
                self.security_message = format!("LOCKED OUT // retry after Unix time {until_unix}");
            }
            Err(error) => {
                self.pin_input.clear();
                self.security_message = format!("UNLOCK FAILED // {error}");
            }
        }
    }

    #[cfg(windows)]
    fn lock_security(&mut self) {
        self.security_session = None;
        self.core = CoreEngine::new();
        self.rule_label.clear();
        self.rule_target.clear();
        self.editing_rule_id = None;
        self.recovery_codes.clear();
        self.security_message = "LOCKED // in-memory rules cleared".into();
    }

    #[cfg(windows)]
    fn acknowledge_recovery_codes(&mut self) {
        self.recovery_codes.clear();
        self.security_message = "RECOVERY CODES ACKNOWLEDGED // keep them offline".into();
    }

    fn handle_process_change(&mut self, change: peacelocker_monitor::ProcessChange) {
        let kind = match change.kind {
            peacelocker_monitor::ProcessChangeKind::Started => MonitorEventKind::ProcessStarted,
            peacelocker_monitor::ProcessChangeKind::Exited => MonitorEventKind::ProcessExited,
        };
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64;
        let correlation_id = Some(((change.process.identity.pid as u128) << 64) | change.process.identity.creation_time_100ns as u128);
        let mut targets = vec![ObservedTarget::new(RuleTargetKind::ProcessName, change.process.name.clone())];
        if let Some(path) = change.process.executable_path.as_ref() {
            targets.push(ObservedTarget::new(RuleTargetKind::ExecutablePath, path.clone()));
        }
        for target in targets {
            let event = MonitorEvent { id: self.next_event_id, occurred_at_unix_ms: timestamp, source: MonitorSource::Process,
                kind, correlation_id, target };
            self.next_event_id = self.next_event_id.saturating_add(1);
            let _ = self.event_queue.push(event.clone());
            self.last_event = format!("{:?}: {}", event.kind, event.target.value);
        }
        while let Some(queued_event) = self.event_queue.pop() {
            self.matched_rule_count = self.matched_rule_count.saturating_add(self.core.evaluate_event(&queued_event).len());
        }
    }

    #[cfg(windows)]
    fn start_process_monitor(&mut self) {
        if self.process_monitor.is_some() { return; }
        let result = ProcessMonitorService::start(
            PollingConfig { interval: Duration::from_secs(2), max_backoff: Duration::from_secs(60) },
            || peacelocker_windows::enumerate_processes()
                .map(|snapshot| peacelocker_monitor::ProcessPollResult {
                    processes: snapshot.processes, inaccessible_count: snapshot.inaccessible_count,
                }),
        );
        match result {
            Ok((service, receiver)) => {
                self.process_monitor = Some(service);
                self.process_receiver = Some(receiver);
                self.process_monitor_status = "Starting".into();
                self.monitor_error = None;
            }
            Err(error) => self.monitor_error = Some(error.to_string()),
        }
    }

    #[cfg(windows)]
    fn stop_process_monitor(&mut self) {
        if let Some(mut service) = self.process_monitor.take() { service.stop(); }
        self.process_receiver = None;
        self.process_monitor_status = "Stopped".into();
    }


    #[cfg(windows)]
    fn start_explorer_monitor(&mut self) {
        if self.explorer_monitor.is_some() { return; }
        match peacelocker_windows::ExplorerMonitorService::start(Duration::from_secs(2)) {
            Ok((service, receiver)) => {
                self.explorer_monitor = Some(service);
                self.explorer_receiver = Some(receiver);
                self.explorer_status = "Starting".into();
                self.explorer_tracker.clear();
                self.monitor_error = None;
            }
            Err(error) => self.monitor_error = Some(error.to_string()),
        }
    }

    #[cfg(windows)]
    fn stop_explorer_monitor(&mut self) {
        if let Some(mut service) = self.explorer_monitor.take() { service.stop(); }
        self.explorer_receiver = None;
        self.explorer_tracker.clear();
        self.explorer_window_count = 0;
        self.explorer_status = "Stopped".into();
    }

    #[cfg(windows)]
    fn handle_explorer_change(&mut self, change: peacelocker_monitor::ExplorerChange) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
            .as_millis().min(u64::MAX as u128) as u64;
        let correlation_id = Some(((change.identity.process_id as u128) << 64)
            | change.identity.process_creation_time_100ns as u128);
        let event = MonitorEvent {
            id: self.next_event_id,
            occurred_at_unix_ms: timestamp,
            source: MonitorSource::Explorer,
            kind: MonitorEventKind::ExplorerChanged,
            correlation_id,
            target: ObservedTarget::new(RuleTargetKind::FolderPath, change.folder_path),
        };
        self.next_event_id = self.next_event_id.saturating_add(1);
        let _ = self.event_queue.push(event.clone());
        self.last_event = format!("Explorer folder: {}", event.target.value);
        while let Some(queued_event) = self.event_queue.pop() {
            self.matched_rule_count = self.matched_rule_count.saturating_add(
                self.core.evaluate_event(&queued_event).len()
            );
        }
    }

    #[cfg(windows)]
    fn drain_explorer_messages(&mut self) {
        let messages: Vec<_> = self.explorer_receiver.as_ref()
            .map(|receiver| receiver.try_iter().collect()).unwrap_or_default();
        for message in messages {
            match message {
                peacelocker_windows::ExplorerMonitorMessage::Snapshot(observations) => {
                    self.explorer_window_count = observations.len();
                    self.explorer_status = "Healthy".into();
                    let changes = self.explorer_tracker.update(observations);
                    for change in changes { self.handle_explorer_change(change); }
                }
                peacelocker_windows::ExplorerMonitorMessage::Degraded(error) => {
                    self.explorer_status = "Degraded".into();
                    self.monitor_error = Some(error);
                }
                peacelocker_windows::ExplorerMonitorMessage::Stopped => {
                    self.explorer_status = "Stopped".into();
                }
            }
        }
    }


    #[cfg(windows)]
    fn start_browser_monitor(&mut self) {
        if self.browser_monitor.is_some() { return; }
        match peacelocker_windows::BrowserMonitorService::start(Duration::from_secs(2)) {
            Ok((service, receiver)) => {
                self.browser_monitor = Some(service);
                self.browser_receiver = Some(receiver);
                self.browser_tracker.clear();
                self.browser_status = "Starting".into();
                self.monitor_error = None;
            }
            Err(error) => self.monitor_error = Some(error.to_string()),
        }
    }

    #[cfg(windows)]
    fn stop_browser_monitor(&mut self) {
        if let Some(mut service) = self.browser_monitor.take() { service.stop(); }
        self.browser_receiver = None;
        self.browser_tracker.clear();
        self.browser_status = "Stopped".into();
    }

    #[cfg(windows)]
    fn handle_browser_change(&mut self, change: peacelocker_monitor::BrowserChange) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()
            .as_millis().min(u64::MAX as u128) as u64;
        let correlation_id = Some(((change.identity.process_id as u128) << 64)
            | change.identity.process_creation_time_100ns as u128);
        let event = MonitorEvent {
            id: self.next_event_id,
            occurred_at_unix_ms: timestamp,
            source: MonitorSource::Browser,
            kind: MonitorEventKind::BrowserNavigated,
            correlation_id,
            target: ObservedTarget::new(RuleTargetKind::BrowserHost, change.hostname.clone()),
        };
        self.next_event_id = self.next_event_id.saturating_add(1);
        let _ = self.event_queue.push(event.clone());
        self.browser_last_host = format!("{} · {}", change.browser, change.hostname);
        self.last_event = format!("Browser host: {}", change.hostname);
        while let Some(queued_event) = self.event_queue.pop() {
            self.matched_rule_count = self.matched_rule_count.saturating_add(
                self.core.evaluate_event(&queued_event).len()
            );
        }
    }

    #[cfg(windows)]
    fn drain_browser_messages(&mut self) {
        let messages: Vec<_> = self.browser_receiver.as_ref()
            .map(|receiver| receiver.try_iter().collect()).unwrap_or_default();
        for message in messages {
            match message {
                peacelocker_windows::BrowserMonitorMessage::Snapshot(observation) => {
                    self.browser_status = "Healthy".into();
                    self.browser_last_host = format!("{} · {}", observation.browser, observation.hostname);
                    let change = self.browser_tracker.update(Some(observation));
                    if let Some(change) = change { self.handle_browser_change(change); }
                }
                peacelocker_windows::BrowserMonitorMessage::NoSupportedBrowser => {
                    self.browser_status = "Waiting for supported browser".into();
                }
                peacelocker_windows::BrowserMonitorMessage::Degraded(error) => {
                    self.browser_status = "Degraded".into();
                    self.monitor_error = Some(error);
                }
                peacelocker_windows::BrowserMonitorMessage::Stopped => self.browser_status = "Stopped".into(),
            }
        }
    }

    #[cfg(windows)]
    fn drain_process_messages(&mut self) {
        let messages: Vec<_> = self.process_receiver.as_ref()
            .map(|receiver| receiver.try_iter().collect()).unwrap_or_default();
        for message in messages {
            match message {
                ProcessMonitorMessage::Changes { changes, inaccessible_count } => {
                    self.inaccessible_count = inaccessible_count;
                    self.process_monitor_status = "Healthy".into();
                    for change in changes { self.handle_process_change(change); }
                }
                ProcessMonitorMessage::Healthy { inaccessible_count } => {
                    self.inaccessible_count = inaccessible_count;
                    self.process_monitor_status = "Healthy".into();
                }
                ProcessMonitorMessage::Degraded { consecutive_failures, .. } => {
                    self.process_monitor_status = format!("Degraded ({consecutive_failures} failures)");
                }
                ProcessMonitorMessage::Stopped => self.process_monitor_status = "Stopped".into(),
            }
        }
    }
}

impl PeaceLockerApp {
    fn show_overview(&mut self, ui: &mut egui::Ui) {
        terminal_panel(ui, "SYSTEM OVERVIEW", |ui| {
            ui.monospace(" [ STATUS ]");
            ui.monospace(format!(" application ........ ONLINE"));
            #[cfg(windows)]
            ui.monospace(format!(" security ........... {}", if self.security_session.is_some() { "UNLOCKED" } else if self.security_configured { "LOCKED" } else { "NOT CONFIGURED" }));
            #[cfg(not(windows))]
            ui.monospace(" security ........... WINDOWS ONLY");
            ui.monospace(format!(" policy rules ....... {}", self.core.snapshot().rules.len()));
            ui.monospace(format!(" policy matches .... {}", self.matched_rule_count));
            ui.monospace(format!(" event queue drops .. {}", self.event_queue.dropped_count()));
            ui.separator();
            ui.monospace(" [ MONITORS ]");
            #[cfg(windows)]
            {
                ui.monospace(format!(" process ............ {}", self.process_monitor_status));
                ui.monospace(format!(" explorer ........... {}", self.explorer_status));
                ui.monospace(format!(" browser ............ {}", self.browser_status));
            }
            #[cfg(not(windows))]
            ui.monospace(" Windows monitoring is unavailable on this platform.");
            ui.separator();
            ui.monospace(format!(" last event: {}", self.last_event));
            ui.monospace(" NOTE: observations and rule matches are informational only.");
        });
        ui.add_space(8.0);
        terminal_panel(ui, "QUICK ACTIONS", |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button(egui::RichText::new("[ OPEN RULES ]").monospace()).clicked() {
                    self.active_section = AppSection::Rules;
                }
                if ui.button(egui::RichText::new("[ SECURITY ]").monospace()).clicked() {
                    self.active_section = AppSection::Protection;
                }
                if ui.button(egui::RichText::new("[ MONITORS ]").monospace()).clicked() {
                    self.active_section = AppSection::Monitoring;
                }
            });
        });
    }

    fn show_protection(&mut self, ui: &mut egui::Ui) {
        #[cfg(windows)]
        terminal_panel(ui, "PIN AUTHENTICATION", |ui| {
            if self.security_session.is_some() {
                ui.monospace(" [ SESSION: UNLOCKED ]");
                ui.monospace(" Your encrypted configuration is open in this process.");
                if ui.button(egui::RichText::new("[ LOCK PEACELOCKER ]").monospace()).clicked() {
                    self.lock_security();
                }
            } else if self.security_configured {
                ui.monospace(" [ SESSION: LOCKED ]");
                ui.label("Enter your PIN or passphrase to unlock the encrypted configuration.");
                ui.add(egui::TextEdit::singleline(&mut self.pin_input).password(true)
                    .hint_text("PIN / passphrase").desired_width(280.0));
                if ui.button(egui::RichText::new("[ UNLOCK ]").monospace()).clicked() {
                    self.unlock_security();
                }
            } else {
                ui.monospace(" [ FIRST-RUN SETUP ]");
                ui.label("Create a passphrase of 6–128 bytes. A longer passphrase is recommended.");
                ui.add(egui::TextEdit::singleline(&mut self.pin_input).password(true)
                    .hint_text("New PIN / passphrase").desired_width(280.0));
                ui.add(egui::TextEdit::singleline(&mut self.pin_confirmation).password(true)
                    .hint_text("Confirm PIN / passphrase").desired_width(280.0));
                if ui.button(egui::RichText::new("[ CREATE SECURE STORE ]").monospace()).clicked() {
                    self.setup_security();
                }
            }
            ui.separator();
            ui.monospace(format!(" STATUS: {}", self.security_message));
            if !self.recovery_codes.is_empty() {
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(255, 210, 100),
                    "IMPORTANT: These recovery codes are shown once. Save them somewhere offline.");
                for pair in self.recovery_codes.chunks(2) {
                    ui.horizontal(|ui| {
                        for code in pair {
                            ui.monospace(code);
                        }
                    });
                }
                if ui.button(egui::RichText::new("[ I SAVED MY RECOVERY CODES ]").monospace()).clicked() {
                    self.acknowledge_recovery_codes();
                }
            }
        });
        #[cfg(not(windows))]
        terminal_panel(ui, "PIN AUTHENTICATION", |ui| {
            ui.monospace(" PIN setup and DPAPI storage are available only on Windows.");
        });
    }

    fn show_monitoring(&mut self, ui: &mut egui::Ui) {
        terminal_panel(ui, "PROCESS MONITOR", |ui| {
            #[cfg(windows)]
            {
                ui.monospace(format!(" STATE: {}", self.process_monitor_status));
                ui.monospace(format!(" INACCESSIBLE PROCESSES: {}", self.inaccessible_count));
                ui.horizontal(|ui| {
                    if self.process_monitor.is_none()
                        && ui.button(egui::RichText::new("[ START ]").monospace()).clicked() {
                        self.start_process_monitor();
                    }
                    if self.process_monitor.is_some()
                        && ui.button(egui::RichText::new("[ STOP ]").monospace()).clicked() {
                        self.stop_process_monitor();
                    }
                });
            }
            #[cfg(not(windows))]
            ui.monospace(" Windows process enumeration is unavailable.");
        });
        ui.add_space(8.0);
        terminal_panel(ui, "EXPLORER MONITOR", |ui| {
            #[cfg(windows)]
            {
                ui.monospace(format!(" STATE: {}", self.explorer_status));
                ui.monospace(format!(" TRACKED WINDOWS: {}", self.explorer_window_count));
                ui.horizontal(|ui| {
                    if self.explorer_monitor.is_none()
                        && ui.button(egui::RichText::new("[ START ]").monospace()).clicked() {
                        self.start_explorer_monitor();
                    }
                    if self.explorer_monitor.is_some()
                        && ui.button(egui::RichText::new("[ STOP ]").monospace()).clicked() {
                        self.stop_explorer_monitor();
                    }
                });
            }
            #[cfg(not(windows))]
            ui.monospace(" Explorer COM monitoring is unavailable.");
        });
        ui.add_space(8.0);
        terminal_panel(ui, "BROWSER HOST MONITOR", |ui| {
            #[cfg(windows)]
            {
                ui.monospace(format!(" STATE: {}", self.browser_status));
                ui.monospace(format!(" LAST HOST: {}", self.browser_last_host));
                ui.horizontal(|ui| {
                    if self.browser_monitor.is_none()
                        && ui.button(egui::RichText::new("[ START ]").monospace()).clicked() {
                        self.start_browser_monitor();
                    }
                    if self.browser_monitor.is_some()
                        && ui.button(egui::RichText::new("[ STOP ]").monospace()).clicked() {
                        self.stop_browser_monitor();
                    }
                });
            }
            #[cfg(not(windows))]
            ui.monospace(" Browser UI Automation is unavailable.");
        });
        if let Some(error) = &self.monitor_error {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("MONITOR ERROR: {error}"));
        }
        ui.add_space(8.0);
        ui.monospace(" All observers are opt-in and read-only. No blocking or enforcement occurs.");
    }

    fn show_rules(&mut self, ui: &mut egui::Ui) {
        #[cfg(windows)]
        let can_edit = self.security_session.is_some();
        #[cfg(not(windows))]
        let can_edit = true;

        terminal_panel(ui, "RULE EDITOR", |ui| {
            #[cfg(windows)]
            if !can_edit {
                ui.colored_label(egui::Color32::from_rgb(255, 190, 90),
                    "LOCKED: unlock PeaceLocker in the Protection panel before editing persistent rules.");
            }
            ui.add_enabled_ui(can_edit, |ui| {
                egui::Grid::new("ascii_rule_editor").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.monospace("NAME"); ui.add(egui::TextEdit::singleline(&mut self.rule_label)
                        .hint_text("Rule label").desired_width(300.0)); ui.end_row();
                    ui.monospace("TYPE");
                    egui::ComboBox::from_id_salt("ascii_rule_kind")
                        .selected_text(match self.rule_kind {
                            RuleTargetKind::ProcessName => "Process name",
                            RuleTargetKind::ExecutablePath => "Executable path",
                            RuleTargetKind::FolderPath => "Folder path",
                            RuleTargetKind::BrowserHost => "Browser hostname",
                        }).show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.rule_kind, RuleTargetKind::ProcessName, "Process name");
                            ui.selectable_value(&mut self.rule_kind, RuleTargetKind::ExecutablePath, "Executable path");
                            ui.selectable_value(&mut self.rule_kind, RuleTargetKind::FolderPath, "Folder path");
                            ui.selectable_value(&mut self.rule_kind, RuleTargetKind::BrowserHost, "Browser hostname");
                        });
                    ui.end_row();
                    ui.monospace("TARGET");
                    ui.add(egui::TextEdit::singleline(&mut self.rule_target)
                        .hint_text(match self.rule_kind {
                            RuleTargetKind::ProcessName => "game.exe",
                            RuleTargetKind::ExecutablePath => r"C:\Games\game.exe",
                            RuleTargetKind::FolderPath => r"C:\Private",
                            RuleTargetKind::BrowserHost => "example.com",
                        }).desired_width(300.0));
                    ui.end_row();
                    ui.monospace("ACTION");
                    egui::ComboBox::from_id_salt("ascii_rule_action")
                        .selected_text(match self.rule_action {
                            RuleAction::Block => "Block (not enforced)",
                            RuleAction::Notify => "Notify",
                        }).show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.rule_action, RuleAction::Block, "Block (not enforced)");
                            ui.selectable_value(&mut self.rule_action, RuleAction::Notify, "Notify");
                        });
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.button(egui::RichText::new(if self.editing_rule_id.is_some() {
                        "[ SAVE CHANGES ]"
                    } else {
                        "[ ADD RULE ]"
                    }).monospace()).clicked() {
                        self.save_rule();
                    }
                    if self.editing_rule_id.is_some()
                        && ui.button(egui::RichText::new("[ CANCEL ]").monospace()).clicked() {
                        self.editing_rule_id = None;
                        self.rule_label.clear();
                        self.rule_target.clear();
                        self.rule_error = None;
                    }
                });
            });
            if let Some(error) = &self.rule_error {
                ui.colored_label(egui::Color32::LIGHT_RED, format!("ERROR: {error}"));
            }
        });
        ui.add_space(8.0);
        terminal_panel(ui, "SAVED RULES", |ui| {
            let rules = self.core.snapshot().rules;
            if rules.is_empty() {
                ui.monospace(" [ EMPTY ] no rules configured");
            }
            for rule in rules {
                ui.horizontal_wrapped(|ui| {
                    let mut enabled = rule.enabled;
                    let response = ui.add_enabled(can_edit,
                        egui::Checkbox::new(&mut enabled, egui::RichText::new(if rule.enabled { "[ON]" } else { "[OFF]" }).monospace()));
                    if response.changed() {
                        self.set_rule_enabled(rule.id, enabled);
                    }
                    ui.monospace(format!("{} :: {:?} :: {} :: {:?}", rule.label, rule.target_kind, rule.target, rule.action));
                    if ui.add_enabled(can_edit, egui::Button::new(egui::RichText::new("[EDIT]").monospace())).clicked() {
                        self.begin_edit_rule(&rule);
                    }
                    if ui.add_enabled(can_edit, egui::Button::new(egui::RichText::new("[DEL]").monospace())).clicked() {
                        self.delete_rule(rule.id);
                    }
                });
            }
        });
        ui.add_space(6.0);
        ui.monospace(" RULE ACTIONS ARE POLICY LABELS ONLY. NO PROCESS, FOLDER OR WEBSITE IS BLOCKED.");
    }

    fn show_activity(&mut self, ui: &mut egui::Ui) {
        terminal_panel(ui, "LIVE ACTIVITY", |ui| {
            ui.monospace(format!(" LAST EVENT: {}", self.last_event));
            ui.monospace(format!(" POLICY MATCHES: {}", self.matched_rule_count));
            ui.monospace(format!(" QUEUE DEPTH: {}", self.event_queue.len()));
            ui.monospace(format!(" DROPPED EVENTS: {}", self.event_queue.dropped_count()));
            ui.separator();
            ui.monospace(" This is live in-memory telemetry only.");
            ui.monospace(" Durable event history has not been implemented.");
        });
    }

    fn show_security(&mut self, ui: &mut egui::Ui) {
        terminal_panel(ui, "SECURITY MODEL", |ui| {
            ui.monospace(" ENCRYPTION : AES-256-GCM");
            ui.monospace(" KEY WRAP   : Windows DPAPI / current user");
            ui.monospace(" PIN HASH   : Argon2id");
            ui.monospace(" LOCKOUT    : 3 failed attempts / 6 hours");
            ui.monospace(" RECOVERY   : 8 one-time 128-bit codes");
            ui.separator();
            ui.monospace(" The PIN gates the app session; it is not used to derive the encryption key.");
            ui.monospace(" DPAPI protects the data key for the current Windows user.");
            ui.monospace(" Local administrators and malware in the same user session are outside the protection guarantee.");
            if ui.button(egui::RichText::new("[ OPEN PIN / RECOVERY ]").monospace()).clicked() {
                self.active_section = AppSection::Protection;
            }
        });
    }

    fn show_notifications(&mut self, ui: &mut egui::Ui) {
        terminal_panel(ui, "NOTIFICATION OUTPUT", |ui| {
            ui.monospace(" [ DISABLED ] notification delivery is not implemented yet.");
            ui.monospace(" No webhook requests or background network activity are performed.");
        });
    }

    fn show_settings(&mut self, ui: &mut egui::Ui) {
        terminal_panel(ui, "APPLICATION SETTINGS", |ui| {
            ui.monospace(" INTERFACE ........ ASCII / MONOSPACE TERMINAL");
            ui.monospace(" MONITORING ....... MANUAL OPT-IN");
            ui.monospace(" ACTIVITY HISTORY . IN-MEMORY ONLY");
            ui.monospace(" AUTO START ....... NOT CONNECTED");
            ui.monospace(" SHELL INTEGRATION  NOT CONNECTED");
            ui.separator();
            ui.monospace(" Settings are not exposed as editable controls until persistence is wired.");
        });
    }
}

impl eframe::App for PeaceLockerApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = egui::Color32::from_rgb(7, 14, 10);
        visuals.window_fill = egui::Color32::from_rgb(9, 18, 13);
        visuals.extreme_bg_color = egui::Color32::from_rgb(3, 8, 5);
        visuals.override_text_color = Some(egui::Color32::from_rgb(150, 235, 170));
        visuals.selection.bg_fill = egui::Color32::from_rgb(24, 76, 43);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(13, 32, 20);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(23, 65, 37);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(35, 92, 52);
        context.set_visuals(visuals);

        #[cfg(windows)]
        self.drain_process_messages();
        #[cfg(windows)]
        self.drain_explorer_messages();
        #[cfg(windows)]
        self.drain_browser_messages();

        egui::TopBottomPanel::top("ascii_header").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.monospace(r"  ____  _____    _    ____ _____ _     ___   ____ _  _______ ____  ");
                    ui.monospace(r" |  _ \| ____|  / \  / ___| ____| |   / _ \ / ___| |/ / ____|  _ \ ");
                    ui.monospace(r" | |_) |  _|   / _ \| |   |  _| | |  | | | | |   | ' /|  _| | |_) |");
                    ui.monospace(r" |  __/| |___ / ___ \ |___| |___| |__| |_| | |___| . \| |___|  _ < ");
                    ui.monospace(r" |_|   |_____/_/   \_\____|_____|_____\___/ \____|_|\_\_____|_| \_\");
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.monospace(" [ SYSTEM CONSOLE ]");
                    ui.monospace(" BUILD: RUST V2");
                    #[cfg(windows)]
                    ui.monospace(format!(" AUTH: {}", if self.security_session.is_some() { "UNLOCKED" } else { "LOCKED" }));
                    #[cfg(not(windows))]
                    ui.monospace(" AUTH: WINDOWS ONLY");
                });
            });
        });

        egui::SidePanel::left("ascii_navigation").resizable(false).default_width(190.0).show(context, |ui| {
            ui.add_space(8.0);
            ui.monospace("+--[ NAVIGATION ]--+");
            ui.separator();
            for (section, label) in AppSection::ALL {
                if ui.add_sized([ui.available_width(), 30.0],
                    egui::SelectableLabel::new(self.active_section == section,
                        egui::RichText::new(label).monospace())).clicked() {
                    self.active_section = section;
                }
            }
            ui.separator();
            ui.monospace("+--[ SYSTEM ]--+");
            ui.monospace(" APP ........ ONLINE");
            ui.monospace(format!(" RULES ...... {}", self.core.snapshot().rules.len()));
            ui.monospace(format!(" MATCHES .... {}", self.matched_rule_count));
            ui.add_space(12.0);
            if ui.button(egui::RichText::new("[ EXIT VIEW ]").monospace()).clicked() {
                self.active_section = AppSection::Overview;
            }
        });

        egui::CentralPanel::default().show(context, |ui| {
            ui.add_space(8.0);
            ui.monospace(format!("ROOT / PEACELOCKER / {:?}", self.active_section));
            ui.separator();
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                match self.active_section {
                    AppSection::Overview => self.show_overview(ui),
                    AppSection::Protection => self.show_protection(ui),
                    AppSection::Monitoring => self.show_monitoring(ui),
                    AppSection::Rules => self.show_rules(ui),
                    AppSection::Activity => self.show_activity(ui),
                    AppSection::Security => self.show_security(ui),
                    AppSection::Notifications => self.show_notifications(ui),
                    AppSection::Settings => self.show_settings(ui),
                }
            });
        });

        egui::TopBottomPanel::bottom("ascii_footer").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.monospace(" PEACELOCKER // TERMINAL INTERFACE");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.monospace(" [ESC] NAVIGATION VIA LEFT PANEL");
                });
            });
        });

        #[cfg(windows)]
        if self.process_monitor.is_some() || self.explorer_monitor.is_some() || self.browser_monitor.is_some() {
            context.request_repaint_after(Duration::from_millis(200));
        }
    }
}

fn terminal_panel(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui.group(|ui| {
        ui.monospace(format!("+--[ {title} ]"));
        ui.separator();
        add_contents(ui);
        ui.separator();
        ui.monospace("+--------------------------------------------------------------+");
    });
}
