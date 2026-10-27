//! The setup wizard: GPG key, companion, seal folder and theme, step by step. Nothing is written before Finish.

use std::path::PathBuf;

use egui::RichText;

use super::companion_dialogs::CompanionSettingsDialog;
use super::dialogs::{DialogResult, error_line, folder_field, gpg_help_text, key_list, primary_button, title};
use super::theme::{self, MONO_SIZE, SMALL_SIZE, THEMES};
use crate::companion::Settings;
use crate::pystr::strip;
use crate::signer::{GnupgSigner, GpgKey, Signer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Welcome,
    Gpg,
    Companion,
    SealFolder,
    Appearance,
    Summary,
}

const STEPS: [(Step, &str); 6] = [
    (Step::Welcome, "Welcome"),
    (Step::Gpg, "Signing key"),
    (Step::Companion, "Companion"),
    (Step::SealFolder, "Seal folder"),
    (Step::Appearance, "Appearance"),
    (Step::Summary, "Summary"),
];

/// What a seal is, for the wizard and the seal folder dialog: a term of factum's own.
pub const SEAL_EXPLAINED: &str = "A seal is a signed fingerprint of the case log at one moment. factum makes one \
                                  whenever a case is archived or exported, and on Seal Now; each is also copied into \
                                  this folder and kept.";
pub const SEAL_FOLDER_EXPLAINED: &str = "Kept on another medium (USB stick, network share), these copies later prove \
                                         that no entry was removed, even if the database itself was changed.";

/// What Finish applies; None (or false) leaves that setting as it is.
pub struct WizardChoices {
    pub key: Option<String>,
    /// saves these settings, enabled
    pub companion: Option<Box<CompanionSettingsDialog>>,
    /// the companion was declined while one is configured: it is disabled
    pub companion_off: bool,
    /// empty: back to the folder next to the database
    pub seal_folder: Option<String>,
    pub theme: Option<String>,
}

pub struct Wizard {
    pub step: Step,
    gpg_home: Option<PathBuf>,
    gpg_available: bool,
    keys: Vec<GpgKey>,
    key: Option<String>,
    current_key: Option<String>,
    pub use_companion: bool,
    companion_configured: bool,
    companion: Box<CompanionSettingsDialog>,
    /// the field, starting with the folder seals go to now
    pub(super) seal_folder: String,
    /// the setting: empty while the seals go to the default folder
    current_seal_folder: String,
    /// the seals folder next to the database
    default_seal_folder: String,
    seal_env: Option<PathBuf>,
    theme: String,
    previous_theme: String,
    skipped: Vec<Step>,
    /// whether signing and seals are set up: without, the wizard leaves out the key and the seal folder
    pub integrity: bool,
    error: Option<String>,
}

/// What the wizard starts from: the current settings.
pub struct WizardStart {
    pub gpg_home: Option<PathBuf>,
    pub current_key: Option<String>,
    pub companion: Settings,
    pub db_path: PathBuf,
    pub seal_folder: String,
    pub default_seal_folder: String,
    pub seal_env: Option<PathBuf>,
    pub theme: String,
}

fn theme_label(theme: &str) -> &'static str {
    match theme {
        "light" => "Light",
        "dark" => "Dark",
        _ => "Follow System",
    }
}

impl Wizard {
    pub fn new(start: WizardStart) -> Self {
        let mut companion = CompanionSettingsDialog::new(&start.companion, start.db_path);
        // the wizard turns the companion on or off with its own choice
        companion.draft.enabled = true;
        let mut wizard = Self {
            step: Step::Welcome,
            gpg_home: start.gpg_home,
            gpg_available: false,
            keys: Vec::new(),
            key: start.current_key.clone(),
            current_key: start.current_key,
            use_companion: start.companion.is_configured(),
            companion_configured: start.companion.is_configured(),
            companion: Box::new(companion),
            seal_folder: if start.seal_folder.is_empty() {
                start.default_seal_folder.clone()
            } else {
                start.seal_folder.clone()
            },
            current_seal_folder: start.seal_folder,
            default_seal_folder: start.default_seal_folder,
            seal_env: start.seal_env,
            previous_theme: start.theme.clone(),
            theme: start.theme,
            skipped: Vec::new(),
            integrity: true,
            error: None,
        };
        wizard.check_gpg();
        wizard
    }

    fn check_gpg(&mut self) {
        let signer = GnupgSigner::without_key(self.gpg_home.clone());
        self.gpg_available = signer.available();
        self.keys = if self.gpg_available {
            signer.list_keys()
        } else {
            Vec::new()
        };
    }

    /// The steps this run goes through.
    fn steps(&self) -> Vec<(Step, &'static str)> {
        STEPS
            .into_iter()
            .filter(|(step, _)| self.integrity || !matches!(step, Step::Gpg | Step::SealFolder))
            .collect()
    }

    fn index(&self) -> usize {
        self.steps()
            .iter()
            .position(|(step, _)| *step == self.step)
            .unwrap_or(0)
    }

    fn go(&mut self, delta: isize) {
        let steps = self.steps();
        let index = (self.index() as isize + delta).clamp(0, steps.len() as isize - 1) as usize;
        self.step = steps[index].0;
        self.error = None;
    }

    /// Skipped, or left out with signing and seals: the step changes nothing.
    fn skipped(&self, step: Step) -> bool {
        self.skipped.contains(&step) || !self.steps().iter().any(|(s, _)| *s == step)
    }

    /// The step's input is acceptable for Next; otherwise the error to show.
    fn check_step(&self) -> Result<(), String> {
        match self.step {
            Step::Companion
                if self.use_companion
                    && (self.companion.draft.endpoint_url.trim().is_empty()
                        || self.companion.draft.model.trim().is_empty()) =>
            {
                Err("Set the endpoint URL and the model, or don't use the companion.".into())
            }
            Step::SealFolder if self.seal_env.is_none() => {
                // the default folder is created with the first seal; another one has to exist
                let folder = self.chosen_seal_folder();
                if folder.is_empty() || std::path::Path::new(&folder).is_dir() {
                    Ok(())
                } else {
                    Err("The folder does not exist.".into())
                }
            }
            _ => Ok(()),
        }
    }

    /// The folder in the field as the setting stores it: empty for the default folder (or an emptied field).
    fn chosen_seal_folder(&self) -> String {
        let folder = strip(&self.seal_folder);
        if folder == self.default_seal_folder.as_str() {
            String::new()
        } else {
            folder.to_string()
        }
    }

    /// The result of Cancel (or closing the window): the theme shown before the wizard comes back.
    pub fn cancelled(&self) -> DialogResult {
        DialogResult::WizardCancelled {
            theme: self.previous_theme.clone(),
        }
    }

    fn choices(&mut self) -> WizardChoices {
        let key = (!self.skipped(Step::Gpg))
            .then(|| self.key.clone())
            .flatten()
            .filter(|key| Some(key) != self.current_key.as_ref());
        let companion_step = !self.skipped(Step::Companion);
        let companion = (companion_step && self.use_companion).then(|| {
            let placeholder = CompanionSettingsDialog::new(&Settings::default(), PathBuf::new());
            std::mem::replace(&mut self.companion, Box::new(placeholder))
        });
        // the default folder (or an emptied field) is stored as no setting, so it follows the database
        let seal_folder = (!self.skipped(Step::SealFolder) && self.seal_env.is_none())
            .then(|| self.chosen_seal_folder())
            .filter(|folder| *folder != self.current_seal_folder);
        let theme = (!self.skipped(Step::Appearance))
            .then(|| self.theme.clone())
            .filter(|theme| *theme != self.previous_theme);
        WizardChoices {
            key,
            companion,
            companion_off: companion_step && !self.use_companion && self.companion_configured,
            seal_folder,
            theme,
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> Option<DialogResult> {
        let p = *theme::current(ctx);
        let small = |text: &str| RichText::new(text).size(SMALL_SIZE).color(p.muted);
        title(ui, "Setup");
        // where the wizard is, as one line: the current step in the accent colour, skipped ones struck through
        let mut steps = egui::text::LayoutJob::default();
        let style = ui.style().clone();
        for (index, (step, name)) in self.steps().iter().enumerate() {
            if index > 0 {
                small("  ›  ").append_to(&mut steps, &style, egui::FontSelection::Default, egui::Align::Center);
            }
            let current = index == self.index();
            let color = if current {
                p.accent
            } else if index < self.index() {
                p.secondary
            } else {
                p.muted
            };
            let mut text = RichText::new(*name).size(SMALL_SIZE).color(color);
            if current {
                text = text.family(theme::bold());
            }
            if self.skipped(*step) && !current {
                text = text.strikethrough();
            }
            text.append_to(&mut steps, &style, egui::FontSelection::Default, egui::Align::Center);
        }
        ui.add(egui::Label::new(steps).wrap());
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("wizard")
            .max_height((ctx.content_rect().height() - 160.0).max(200.0))
            .show(ui, |ui| self.body(ui, ctx));
        error_line(ui, &self.error);
        ui.separator();

        let mut result = None;
        ui.horizontal(|ui| {
            if ui.button("Cancel").clicked() {
                result = Some(self.cancelled());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let last = self.step == Step::Summary;
                if primary_button(ui, if last { "Finish" } else { "Next" }, true, false) {
                    if last {
                        result = Some(DialogResult::WizardFinished(Box::new(self.choices())));
                    } else {
                        match self.check_step() {
                            Ok(()) => {
                                self.skipped.retain(|step| *step != self.step);
                                self.go(1);
                            }
                            Err(e) => self.error = Some(e),
                        }
                    }
                }
                if !matches!(self.step, Step::Welcome | Step::Summary) && ui.button("Skip").clicked() {
                    if self.step == Step::Appearance {
                        theme::apply(ctx, &self.previous_theme);
                    }
                    if !self.skipped.contains(&self.step) {
                        self.skipped.push(self.step);
                    }
                    self.go(1);
                }
                if self.step != Step::Welcome && ui.button("Back").clicked() {
                    self.go(-1);
                }
            });
        });
        result
    }

    fn body(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let small = |text: &str| RichText::new(text).size(SMALL_SIZE).color(p.muted);
        match self.step {
            Step::Welcome => {
                ui.label("Every note goes into a tamper-evident log: each entry is chained to the ones before it.");
                ui.add_space(6.0);
                ui.label("Do you need to prove who wrote the notes, and that none was changed or removed?");
                ui.radio_value(&mut self.integrity, true, "Yes: set up signing and seals");
                ui.radio_value(&mut self.integrity, false, "Not now: skip signing and seals");
                ui.label(small("Each step can be skipped and changed later under Settings."));
            }
            Step::Gpg => {
                ui.label("The GPG key that signs notes and seals:");
                if !self.gpg_available {
                    ui.label(RichText::new("GPG is not installed or not on the PATH.").color(p.warn));
                    ui.label(RichText::new(gpg_help_text()).font(egui::FontId::monospace(MONO_SIZE)));
                    if ui.button("Check again").clicked() {
                        self.check_gpg();
                    }
                } else if self.keys.is_empty() {
                    ui.label(RichText::new("⚠ No signing key found. Create one, then check again:").color(p.warn));
                    ui.label(
                        RichText::new("gpg --quick-gen-key \"Your Name <you@example.org>\" default sign")
                            .font(egui::FontId::monospace(MONO_SIZE)),
                    );
                    if ui.button("Check again").clicked() {
                        self.check_gpg();
                    }
                } else {
                    key_list(ui, &self.keys, &mut self.key);
                }
                ui.label(small("Without one, notes stay unsigned until signed later."));
            }
            Step::Companion => {
                ui.label("Optional: a language model you choose reads the log and asks open questions.");
                ui.label(small("It never writes into the log."));
                ui.radio_value(&mut self.use_companion, false, "Don't use the AI companion");
                ui.radio_value(&mut self.use_companion, true, "Use the AI companion");
                if self.use_companion {
                    self.companion.connection_fields(ui, ctx);
                    self.companion.endpoint_note(ui, ctx);
                    self.companion.preset_fields(ui, ctx);
                }
            }
            Step::SealFolder => {
                ui.label(SEAL_EXPLAINED);
                ui.label(small(SEAL_FOLDER_EXPLAINED));
                ui.label(small(
                    "Optional: keep the default for now and change it any time under Settings → Seal Folder…",
                ));
                ui.add_space(4.0);
                if let Some(dir) = &self.seal_env {
                    ui.label(format!(
                        "FACTUM_SEAL_DIR is set to {}; it overrides this setting.",
                        dir.display()
                    ));
                } else {
                    let label = ui.label("Seal folder");
                    folder_field(ui, &mut self.seal_folder, Some(label.id));
                }
            }
            Step::Appearance => {
                ui.label("Theme");
                for option in THEMES {
                    if ui
                        .radio_value(&mut self.theme, option.to_string(), theme_label(option))
                        .changed()
                    {
                        theme::apply(ctx, option);
                    }
                }
            }
            Step::Summary => {
                let unchanged = "unchanged";
                let key = if self.skipped(Step::Gpg) {
                    unchanged.to_string()
                } else {
                    self.key.clone().unwrap_or_else(|| "not set".into())
                };
                let companion = if self.skipped(Step::Companion) {
                    unchanged.to_string()
                } else if self.use_companion {
                    format!(
                        "on, {} with the {} preset",
                        self.companion.draft.model.trim(),
                        self.companion.draft.preset.label()
                    )
                } else {
                    "off".into()
                };
                let seal_folder = if self.seal_env.is_some() {
                    "set by FACTUM_SEAL_DIR".to_string()
                } else if self.skipped(Step::SealFolder) {
                    unchanged.to_string()
                } else if self.chosen_seal_folder().is_empty() {
                    format!("{} (next to the database)", self.default_seal_folder)
                } else {
                    self.chosen_seal_folder()
                };
                let theme = if self.skipped(Step::Appearance) {
                    unchanged
                } else {
                    theme_label(&self.theme)
                };
                egui::Grid::new("wizard-summary")
                    .num_columns(2)
                    .spacing([16.0, 6.0])
                    .show(ui, |ui| {
                        for (name, value) in [
                            ("Signing key", key.as_str()),
                            ("Companion", companion.as_str()),
                            ("Seal folder", seal_folder.as_str()),
                            ("Theme", theme),
                        ] {
                            ui.label(RichText::new(name).color(p.muted));
                            let color = if value == unchanged { p.muted } else { p.text };
                            ui.label(RichText::new(value).color(color));
                            ui.end_row();
                        }
                    });
                ui.add_space(4.0);
                ui.label(small("Finish saves these settings."));
            }
        }
    }
}
