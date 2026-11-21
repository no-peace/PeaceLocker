#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::{SystemTime, UNIX_EPOCH};
use eframe::egui;
use peacelocker_core::{AppSnapshot, CoreEngine, EventQueue, MonitorEvent, MonitorEventKind, MonitorSource, ObservedTarget, RuleTargetKind};

#[cfg(windows)]
use std::{sync::mpsc::Receiver, time::Duration};
#[cfg(windows)]
use peacelocker_monitor::{PollingConfig, ProcessMonitorMessage, ProcessMonitorService};

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

struct PeaceLockerApp {
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
        Self {
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
        let label = self.rule_label.trim();
        let target = self.rule_target.trim();
        let id = match self.editing_rule_id {
            Some(id) => id,
            None => match self.core.snapshot().rules.iter().map(|r| r.id).max() {
                Some(max_id) => match max_id.checked_add(1) { Some(id) => id, None => { self.rule_error = Some("Rule ID space is exhausted.".into()); return; } },
                None => 1,
            },
        };
        match peacelocker_core::Rule::new(id, label, self.rule_kind, target, self.rule_action) {
            Ok(mut rule) => {
                if let Some(existing) = self.editing_rule_id.and_then(|id| self.core.snapshot().rules.into_iter().find(|item| item.id == id)) {
                    rule.enabled = existing.enabled;
                }
                let command = if self.editing_rule_id.is_some() { peacelocker_core::Command::ReplaceRule(rule) } else { peacelocker_core::Command::AddRule(rule) };
                match self.core.execute(command) {
                    Ok(_) => { self.rule_label.clear(); self.rule_target.clear(); self.editing_rule_id = None; self.rule_error = None; }
                    Err(error) => self.rule_error = Some(error.to_string()),
                }
            }
            Err(error) => self.rule_error = Some(error.to_string()),
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

impl eframe::App for PeaceLockerApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(windows)]
        self.drain_process_messages();
        #[cfg(windows)]
        self.drain_explorer_messages();
        #[cfg(windows)]
        self.drain_browser_messages();

        egui::TopBottomPanel::top("top_bar").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading("PeaceLocker");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("RUST V2 · PHASE 5").small().color(egui::Color32::from_rgb(117, 190, 140)));
                });
            });
        });
        egui::SidePanel::left("navigation").resizable(false).default_width(190.0).show(context, |ui| {
            ui.add_space(12.0); ui.heading("Workspace"); ui.separator();
            for section in ["Overview", "Protection", "Monitoring", "Activity", "Security", "Notifications", "Settings"] {
                ui.add_sized([ui.available_width(), 34.0], egui::Button::new(section));
            }
        });
        egui::CentralPanel::default().show(context, |ui| {
            ui.add_space(12.0); ui.heading("Overview"); ui.label("The Rust rewrite is being initialized."); ui.add_space(18.0);
            ui.horizontal_wrapped(|ui| {
                status_card(ui, "Application", "Running", "Desktop shell initialized");
                status_card(ui, "Protection", "Not configured", "PIN and encrypted storage are not connected to this UI");
                #[cfg(windows)]
                status_card(ui, "Process monitor", &self.process_monitor_status, "Read-only process metadata polling");
                status_card(ui, "Explorer monitor", &self.explorer_status, "Read-only folder observation");
                status_card(ui, "Browser monitor", &self.browser_status, "Foreground hostname only");
                #[cfg(not(windows))]
                status_card(ui, "Monitoring", "Unavailable", "Windows process monitoring is Windows-only");
            });
            ui.add_space(20.0);
            ui.group(|ui| {
                ui.heading("Monitoring controls");
                #[cfg(windows)]
                {
                    ui.horizontal(|ui| {
                        if self.process_monitor.is_none() && ui.button("Start process monitor").clicked() { self.start_process_monitor(); }
                        if self.process_monitor.is_some() && ui.button("Stop monitor").clicked() { self.stop_process_monitor(); }
                    });
                    ui.label(format!("Processes inaccessible to query: {}", self.inaccessible_count));
                    ui.separator();
                    ui.label(format!("Explorer monitor: {}", self.explorer_status));
                    ui.label(format!("Explorer filesystem windows: {}", self.explorer_window_count));
                    ui.separator();
                    ui.label(format!("Browser monitor: {}", self.browser_status));
                    ui.label(format!("Last browser host: {}", self.browser_last_host));
                    ui.horizontal(|ui| {
                        if self.browser_monitor.is_none() && ui.button("Start browser monitor").clicked() { self.start_browser_monitor(); }
                        if self.browser_monitor.is_some() && ui.button("Stop browser monitor").clicked() { self.stop_browser_monitor(); }
                    });
                    ui.horizontal(|ui| {
                        if self.explorer_monitor.is_none() && ui.button("Start Explorer monitor").clicked() { self.start_explorer_monitor(); }
                        if self.explorer_monitor.is_some() && ui.button("Stop Explorer monitor").clicked() { self.stop_explorer_monitor(); }
                    });
                }
                ui.label(format!("Last event: {}", self.last_event));
                ui.label(format!("Policy matches: {}", self.matched_rule_count));
                if let Some(error) = &self.monitor_error { ui.colored_label(egui::Color32::LIGHT_RED, error); }
                ui.label("Monitoring observes process metadata and Explorer folder locations. Policy matches are decisions only; nothing is suspended, terminated, or blocked.");
            });
            ui.add_space(16.0);
            ui.group(|ui| {
                ui.heading("Rule management");
                ui.label("Create and maintain policy rules. Matches are currently informational only; no blocking or enforcement is performed.");
                egui::Grid::new("rule_editor_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label("Rule name"); ui.text_edit_singleline(&mut self.rule_label); ui.end_row();
                    ui.label("Target type");
                    egui::ComboBox::from_id_salt("rule_target_kind").selected_text(match self.rule_kind {
                        RuleTargetKind::ProcessName => "Process name", RuleTargetKind::ExecutablePath => "Executable path",
                        RuleTargetKind::FolderPath => "Folder path", RuleTargetKind::BrowserHost => "Browser hostname",
                    }).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.rule_kind, RuleTargetKind::ProcessName, "Process name");
                        ui.selectable_value(&mut self.rule_kind, RuleTargetKind::ExecutablePath, "Executable path");
                        ui.selectable_value(&mut self.rule_kind, RuleTargetKind::FolderPath, "Folder path");
                        ui.selectable_value(&mut self.rule_kind, RuleTargetKind::BrowserHost, "Browser hostname");
                    }); ui.end_row();
                    ui.label("Target");
                    ui.add(egui::TextEdit::singleline(&mut self.rule_target).hint_text(match self.rule_kind {
                        RuleTargetKind::ProcessName => "game.exe", RuleTargetKind::ExecutablePath => r"C:\\Games\\game.exe",
                        RuleTargetKind::FolderPath => r"C:\\Private", RuleTargetKind::BrowserHost => "example.com",
                    }).desired_width(360.0)); ui.end_row();
                    ui.label("Action");
                    egui::ComboBox::from_id_salt("rule_action").selected_text(match self.rule_action {
                        peacelocker_core::RuleAction::Block => "Block (not enforced yet)", peacelocker_core::RuleAction::Notify => "Notify",
                    }).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.rule_action, peacelocker_core::RuleAction::Block, "Block (not enforced yet)");
                        ui.selectable_value(&mut self.rule_action, peacelocker_core::RuleAction::Notify, "Notify");
                    }); ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.button(if self.editing_rule_id.is_some() { "Save changes" } else { "Add rule" }).clicked() { self.save_rule(); }
                    if self.editing_rule_id.is_some() && ui.button("Cancel edit").clicked() {
                        self.editing_rule_id = None; self.rule_label.clear(); self.rule_target.clear(); self.rule_error = None;
                    }
                });
                if let Some(error) = &self.rule_error { ui.colored_label(egui::Color32::LIGHT_RED, error); }
                ui.separator();
                let rules = self.core.snapshot().rules;
                if rules.is_empty() { ui.label("No rules configured."); }
                for rule in rules {
                    ui.horizontal_wrapped(|ui| {
                        let mut enabled = rule.enabled;
                        if ui.checkbox(&mut enabled, "").changed() {
                            if let Err(error) = self.core.execute(peacelocker_core::Command::SetRuleEnabled { id: rule.id, enabled }) { self.rule_error = Some(error.to_string()); }
                        }
                        ui.label(egui::RichText::new(&rule.label).strong());
                        ui.label(format!("{:?} · {} · {:?}", rule.target_kind, rule.target, rule.action));
                        if ui.small_button("Edit").clicked() { self.begin_edit_rule(&rule); }
                        if ui.small_button("Delete").clicked() {
                            if let Err(error) = self.core.execute(peacelocker_core::Command::RemoveRule(rule.id)) { self.rule_error = Some(error.to_string()); }
                            if self.editing_rule_id == Some(rule.id) { self.editing_rule_id = None; self.rule_label.clear(); self.rule_target.clear(); }
                        }
                    });
                }
            });
            ui.add_space(16.0);
            ui.group(|ui| {
                ui.heading("Implementation status");
                ui.label("Windows process, Explorer and active-browser observations feed supervised workers. Lifecycle, folder and hostname changes are normalized and evaluated against core rules.");
                ui.label("Rules can be managed in memory. Encrypted-store integration and durable event history remain incomplete.");
                ui.label(format!("Runtime state: {}", self.snapshot.status_label()));
            });
        });
        #[cfg(windows)]
        if self.process_monitor.is_some() || self.explorer_monitor.is_some() || self.browser_monitor.is_some() { context.request_repaint_after(Duration::from_millis(200)); }
    }
}

fn status_card(ui: &mut egui::Ui, title: &str, value: &str, detail: &str) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(190.0); ui.set_min_height(104.0);
        ui.label(egui::RichText::new(title).small().weak()); ui.add_space(6.0);
        ui.heading(value); ui.label(egui::RichText::new(detail).small().weak());
    });
}
