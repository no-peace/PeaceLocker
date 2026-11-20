#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use peacelocker_core::AppSnapshot;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PeaceLocker")
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([800.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "PeaceLocker",
        options,
        Box::new(|_creation_context| Ok(Box::new(PeaceLockerApp::default()))),
    )
}

#[derive(Default)]
struct PeaceLockerApp {
    snapshot: AppSnapshot,
}

impl eframe::App for PeaceLockerApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_bar").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading("PeaceLocker");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new("RUST V2 · FOUNDATION")
                            .small()
                            .color(egui::Color32::from_rgb(117, 190, 140)),
                    );
                });
            });
        });

        egui::SidePanel::left("navigation")
            .resizable(false)
            .default_width(190.0)
            .show(context, |ui| {
                ui.add_space(12.0);
                ui.heading("Workspace");
                ui.separator();
                for section in [
                    "Overview",
                    "Protection",
                    "Monitoring",
                    "Activity",
                    "Security",
                    "Notifications",
                    "Settings",
                ] {
                    ui.add_sized([ui.available_width(), 34.0], egui::Button::new(section));
                }
            });

        egui::CentralPanel::default().show(context, |ui| {
            ui.add_space(12.0);
            ui.heading("Overview");
            ui.label("The Rust rewrite is being initialized.");
            ui.add_space(18.0);

            ui.horizontal_wrapped(|ui| {
                status_card(ui, "Application", "Running", "Desktop shell initialized");
                status_card(
                    ui,
                    "Protection",
                    "Not configured",
                    "Authentication is not implemented yet",
                );
                status_card(
                    ui,
                    "Monitoring",
                    "Inactive",
                    "No monitor sources are running",
                );
            });

            ui.add_space(24.0);
            ui.group(|ui| {
                ui.heading("Foundation status");
                ui.label("This build is the Phase 0 application skeleton.");
                ui.label(
                    "No monitoring, webcam capture, network reporting, or enforcement is active.",
                );
                ui.label(format!("Runtime state: {}", self.snapshot.status_label()));
            });
        });
    }
}

fn status_card(ui: &mut egui::Ui, title: &str, value: &str, detail: &str) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(190.0);
        ui.set_min_height(104.0);
        ui.label(egui::RichText::new(title).small().weak());
        ui.add_space(6.0);
        ui.heading(value);
        ui.label(egui::RichText::new(detail).small().weak());
    });
}
