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
        }
    }
}

impl PeaceLockerApp {
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
        self.drain_explorer_messages();

        egui::TopBottomPanel::top("top_bar").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading("PeaceLocker");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("RUST V2 · PHASE 4").small().color(egui::Color32::from_rgb(117, 190, 140)));
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
                #[cfg(not(windows))]
                status_card(ui, "Monitoring", "Unavailable", "Windows process monitoring is Windows-only");
            });
            ui.add_space(20.0);
            ui.group(|ui| {
                ui.heading("Process monitoring");
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
                    ui.horizontal(|ui| {
                        if self.explorer_monitor.is_none() && ui.button("Start Explorer monitor").clicked() { self.start_explorer_monitor(); }
                        if self.explorer_monitor.is_some() && ui.button("Stop Explorer monitor").clicked() { self.stop_explorer_monitor(); }
                    });
                }
                ui.label(format!("Last event: {}", self.last_event));
                ui.label(format!("Policy matches: {}", self.matched_rule_count));
                if let Some(error) = &self.monitor_error { ui.colored_label(egui::Color32::LIGHT_RED, error); }
                ui.label("Monitoring only observes process metadata. Policy matches are reported as decisions; no process is suspended, terminated, or blocked.");
            });
            ui.add_space(16.0);
            ui.group(|ui| {
                ui.heading("Implementation status");
                ui.label("The Windows process enumerator now feeds the supervised worker. Process lifecycle changes are normalized and evaluated against core rules.");
                ui.label("Browser URL monitoring, rule-management UI, and encrypted-store integration remain incomplete.");
                ui.label(format!("Runtime state: {}", self.snapshot.status_label()));
            });
        });
        #[cfg(windows)]
        if self.process_monitor.is_some() || self.explorer_monitor.is_some() { context.request_repaint_after(Duration::from_millis(200)); }
    }
}

fn status_card(ui: &mut egui::Ui, title: &str, value: &str, detail: &str) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(190.0); ui.set_min_height(104.0);
        ui.label(egui::RichText::new(title).small().weak()); ui.add_space(6.0);
        ui.heading(value); ui.label(egui::RichText::new(detail).small().weak());
    });
}
