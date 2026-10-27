//! The setup wizard: GPG key, companion, seal folder and theme, step by step. Nothing is written before Finish.

use std::path::PathBuf;

use egui::{RichText, TextEdit};

use super::companion_dialogs::CompanionSettingsDialog;
use super::dialogs::{DialogResult, error_line, gpg_help_text, key_list, title};
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
    pub(super) seal_folder: String,
    current_seal_folder: String,
    seal_env: Option<PathBuf>,
    theme: String,
    previous_theme: String,
    skipped: Vec<Step>,
    error: Option<String>,
}

/// What the wizard starts from: the current settings.
pub struct WizardStart {
    pub gpg_home: Option<PathBuf>,
    pub current_key: Option<String>,
    pub companion: Settings,
    pub db_path: PathBuf,
    pub seal_folder: String,
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
            seal_folder: start.seal_folder.clone(),
            current_seal_folder: start.seal_folder,
            seal_env: start.seal_env,
            previous_theme: start.theme.clone(),
            theme: start.theme,
            skipped: Vec::new(),
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

    fn index(&self) -> usize {
        STEPS.iter().position(|(step, _)| *step == self.step).unwrap_or(0)
    }

    fn go(&mut self, delta: isize) {
        let index = (self.index() as isize + delta).clamp(0, STEPS.len() as isize - 1) as usize;
        self.step = STEPS[index].0;
        self.error = None;
    }

    fn skipped(&self, step: Step) -> bool {
        self.skipped.contains(&step)
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
                let folder = strip(&self.seal_folder);
                if folder.is_empty() || std::path::Path::new(folder).is_dir() {
                    Ok(())
                } else {
                    Err("The folder does not exist.".into())
                }
            }
            _ => Ok(()),
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
        // an emptied field goes back to the folder next to the database
        let seal_folder = (!self.skipped(Step::SealFolder) && self.seal_env.is_none())
            .then(|| strip(&self.seal_folder).to_string())
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
        ui.label(small(&format!(
            "Step {} of {} · {}",
            self.index() + 1,
            STEPS.len(),
            STEPS[self.index()].1
        )));
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
                if ui.button(if last { "Finish" } else { "Next" }).clicked() {
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
                ui.label(
                    "factum keeps a tamper-evident case log: every note is chained into a Merkle tree, signed with \
                     your GPG key and sealed from time to time.",
                );
                ui.label(
                    "This wizard sets up the signing key, the optional AI companion, a folder for seal copies and \
                     the theme. Every step can be skipped, and everything can be changed later in the Settings and \
                     Companion menus.",
                );
            }
            Step::Gpg => {
                ui.label("Notes and seals are signed with a GPG key, so that changes can be detected and attributed.");
                if !self.gpg_available {
                    ui.label(RichText::new("GPG is not installed or not on the PATH.").color(p.warn));
                    ui.label(RichText::new(gpg_help_text()).font(egui::FontId::monospace(MONO_SIZE)));
                    if ui.button("Check again").clicked() {
                        self.check_gpg();
                    }
                } else if self.keys.is_empty() {
                    ui.label(RichText::new("No secret keys with signing capability found.").color(p.warn));
                    ui.label("Create one in a terminal, then check again:");
                    ui.label(
                        RichText::new("gpg --quick-gen-key \"Your Name <you@example.org>\" default sign")
                            .font(egui::FontId::monospace(MONO_SIZE)),
                    );
                    if ui.button("Check again").clicked() {
                        self.check_gpg();
                    }
                } else {
                    ui.label("Choose the key to sign with (only keys with signing capability [S]):");
                    key_list(ui, &self.keys, &mut self.key);
                }
                ui.label(small(
                    "Without a key, notes are stored unsigned and can be signed later.",
                ));
            }
            Step::Companion => {
                ui.label(
                    "The companion reads the case log through a language model you choose and keeps a short list of \
                     open questions. It never writes into the log. Case content is sent to the endpoint you set.",
                );
                ui.radio_value(&mut self.use_companion, false, "Don't use the AI companion");
                ui.radio_value(&mut self.use_companion, true, "Use the AI companion");
                if self.use_companion {
                    ui.separator();
                    self.companion.connection_fields(ui, ctx);
                    ui.separator();
                    self.companion.preset_fields(ui, ctx);
                    self.companion.endpoint_note(ui, ctx);
                }
            }
            Step::SealFolder => {
                ui.label(
                    "A seal only protects against removed entries if a copy exists outside the database. Choose a \
                     folder on another medium (USB stick, network share); it must already exist. Leave it empty to \
                     keep the seals next to the database.",
                );
                if let Some(dir) = &self.seal_env {
                    ui.label(format!(
                        "FACTUM_SEAL_DIR is set to {}; it overrides this setting.",
                        dir.display()
                    ));
                } else {
                    let label = ui.label("Seal folder");
                    ui.horizontal(|ui| {
                        let browse = ui.button("Browse…");
                        ui.add(TextEdit::singleline(&mut self.seal_folder).desired_width(f32::INFINITY))
                            .labelled_by(label.id);
                        if browse.clicked()
                            && let Some(picked) = rfd::FileDialog::new()
                                .set_directory(self.seal_folder.as_str())
                                .pick_folder()
                        {
                            self.seal_folder = picked.to_string_lossy().into_owned();
                        }
                    });
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
                } else if strip(&self.seal_folder).is_empty() {
                    "next to the database".into()
                } else {
                    strip(&self.seal_folder).to_string()
                };
                let theme = if self.skipped(Step::Appearance) {
                    unchanged
                } else {
                    theme_label(&self.theme)
                };
                egui::Grid::new("wizard-summary")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        for (name, value) in [
                            ("Signing key", key.as_str()),
                            ("Companion", companion.as_str()),
                            ("Seal folder", seal_folder.as_str()),
                            ("Theme", theme),
                        ] {
                            ui.label(name);
                            ui.label(value);
                            ui.end_row();
                        }
                    });
                ui.label(small("Finish saves these settings."));
            }
        }
    }
}
