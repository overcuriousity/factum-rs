//! The companion settings dialog: a draft of the settings, the model list loaded from the draft's endpoint
//! (debounced, on a worker) and the "Test connection" probe.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::{Align, Layout, RichText, TextEdit};

use super::dialogs::{DialogResult, buttons, error_line, title};
use super::theme::{self, SMALL_SIZE};
use super::workers::Worker;
use crate::companion::llm::{self, LlmError, ModelInfo};
use crate::companion::{CompanionDb, Preset, Protocol, Settings};

/// Names a built-in preset's guideline, which is shown read-only.
pub const BUILTIN_GUIDELINE: &str = "Built in. Choose Custom to write your own.";

/// The model list is loaded this long after the last edit of URL, key, protocol or headers.
const DEBOUNCE: Duration = Duration::from_millis(600);
const POLL: Duration = Duration::from_millis(100);

pub struct CompanionSettingsDialog {
    /// what the fields edit; `api_key` is the typed key, empty while a stored key is kept
    pub draft: Settings,
    pub models: Vec<ModelInfo>,
    pub models_status: String,
    pub models_worker: Option<Worker<Result<Vec<ModelInfo>, String>>>,
    pub last_edit: Option<Instant>,
    /// hash of the url, key, protocol and headers the model list was last loaded for
    pub listed_for: Option<u64>,
    /// Ok(model count) or Err("Unreachable: <reason>")
    pub probe: Option<Result<usize, String>>,
    pub probe_worker: Option<Worker<Result<Vec<ModelInfo>, String>>>,
    /// a key is stored and the field is empty: the stored key is kept
    pub key_stored: bool,
    stored_key: String,
    /// the stored key goes only to the endpoint it was saved for
    saved_url: String,
    saved_protocol: Protocol,
    saved_model: String,
    context_window: String,
    /// the case database; "Test connection" saves through its companion database
    db_path: PathBuf,
    error: Option<String>,
}

/// The proxy variable the HTTP client follows, if one is set.
fn proxy_variable() -> Option<&'static str> {
    [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ]
    .into_iter()
    .find(|name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty()))
}

/// The listing's failure reason, without the "Unreachable: " the error's own text starts with.
fn reason(e: LlmError) -> String {
    match e {
        LlmError::Unreachable(reason) => reason,
        other => other.to_string(),
    }
}

impl CompanionSettingsDialog {
    pub fn new(settings: &Settings, db_path: PathBuf) -> Self {
        let key_stored = !settings.api_key_from_env && !settings.api_key.is_empty();
        let mut draft = settings.clone();
        if key_stored {
            draft.api_key.clear();
        }
        Self {
            draft,
            models: Vec::new(),
            models_status: String::new(),
            models_worker: None,
            last_edit: None,
            listed_for: None,
            probe: None,
            probe_worker: None,
            key_stored,
            stored_key: if key_stored {
                settings.api_key.clone()
            } else {
                String::new()
            },
            saved_url: settings.endpoint_url.trim().to_string(),
            saved_protocol: settings.protocol,
            saved_model: settings.model.clone(),
            context_window: settings.context_window.map(|n| n.to_string()).unwrap_or_default(),
            db_path,
            error: None,
        }
    }

    /// The draft as it would be saved: the stored key when the field is empty, every string trimmed.
    fn settings(&self) -> Settings {
        let mut s = self.draft.clone();
        if self.key_stored && s.api_key.is_empty() {
            s.api_key = self.stored_key.clone();
        }
        for field in [
            &mut s.endpoint_url,
            &mut s.api_key,
            &mut s.user_agent,
            &mut s.extra_headers,
            &mut s.model,
            &mut s.global_guideline,
        ] {
            *field = field.trim().to_string();
        }
        s.context_window = self.context_window.trim().parse().ok();
        s
    }

    /// The draft as the listing and the probe send it: without the stored key (or the one from the environment)
    /// once URL or protocol differ from the saved ones, so a key never reaches an endpoint it was not saved for
    /// before it is saved; a typed key goes to the URL it is typed for.
    fn connection_settings(&self) -> Settings {
        let mut s = self.settings();
        let typed = !self.draft.api_key_from_env && !self.draft.api_key.trim().is_empty();
        if !typed && (s.endpoint_url != self.saved_url || s.protocol != self.saved_protocol) {
            s.api_key.clear();
        }
        s
    }

    fn connection_hash(s: &Settings) -> u64 {
        let mut hasher = DefaultHasher::new();
        (&s.endpoint_url, &s.api_key, s.protocol.as_str(), &s.extra_headers).hash(&mut hasher);
        hasher.finish()
    }

    fn spawn_listing(ctx: &egui::Context, settings: Settings) -> Worker<Result<Vec<ModelInfo>, String>> {
        Worker::spawn(ctx, move || llm::list_models(&settings).map_err(reason))
    }

    /// Takes a finished listing: failures read as an empty list, never as an error.
    fn take_models(&mut self, result: Result<Vec<ModelInfo>, String>) {
        if let Err(e) = &result {
            log::info!("Listing the companion models failed: {e}");
        }
        // the listing fills the dropdown, never the field: the first id may be any model
        self.models = result.unwrap_or_default();
        self.models_status = if self.models.is_empty() {
            "The endpoint listed no models. Enter the name by hand.".into()
        } else {
            format!("{} models from the endpoint.", self.models.len())
        };
    }

    /// Polls the workers and starts a listing once the connection fields have been left alone for a moment.
    fn update_models(&mut self, ctx: &egui::Context) {
        if let Some(result) = self.models_worker.as_mut().and_then(Worker::poll) {
            self.models_worker = None;
            self.take_models(result);
        }
        if let Some(result) = self.probe_worker.as_mut().and_then(Worker::poll) {
            self.probe_worker = None;
            self.probe = Some(match &result {
                Ok(models) => Ok(models.len()),
                Err(reason) => Err(format!("Unreachable: {reason}")),
            });
            self.take_models(result);
        }
        let settings = self.connection_settings();
        if settings.endpoint_url.is_empty() {
            self.models_worker = None;
            self.listed_for = None;
            self.models.clear();
            self.models_status = "Set the endpoint URL to load the model list.".into();
        } else {
            let hash = Self::connection_hash(&settings);
            if self.listed_for != Some(hash) {
                let waited = self.last_edit.map_or(DEBOUNCE, |t| t.elapsed());
                if waited >= DEBOUNCE {
                    self.listed_for = Some(hash);
                    self.models_status = "Loading models from the endpoint…".into();
                    self.models_worker = Some(Self::spawn_listing(ctx, settings));
                } else {
                    ctx.request_repaint_after(DEBOUNCE - waited);
                }
            }
        }
        if self.models_worker.is_some() || self.probe_worker.is_some() {
            ctx.request_repaint_after(POLL);
        }
    }

    /// Checks the draft and saves it, creating the companion database on first use; the error is shown in the
    /// dialog, which stays open with the draft.
    /// Why the last save failed.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn save(&mut self) -> Option<Settings> {
        if !self.context_window.trim().is_empty() && self.context_window.trim().parse::<u32>().is_err() {
            self.error = Some("The context window is a number of tokens.".into());
            return None;
        }
        let settings = self.settings();
        if let Err(e) = CompanionDb::open_for(&self.db_path).and_then(|cdb| settings.save(&cdb)) {
            self.error = Some(format!("The settings could not be saved: {e}"));
            return None;
        }
        self.error = None;
        // what is saved now is what the stored key belongs to
        self.saved_url = settings.endpoint_url.clone();
        self.saved_protocol = settings.protocol;
        self.saved_model = settings.model.clone();
        if !settings.api_key_from_env {
            self.key_stored = !settings.api_key.is_empty();
            self.stored_key = settings.api_key.clone();
        }
        Some(settings)
    }

    /// "Test connection": saves the draft, then lists the models whatever the debounce says.
    fn test_connection(&mut self, ctx: &egui::Context) {
        if self.save().is_none() {
            return;
        }
        self.probe = None;
        self.models_worker = None;
        self.models_status = "Loading models from the endpoint…".into();
        let settings = self.connection_settings();
        self.listed_for = Some(Self::connection_hash(&settings));
        self.probe_worker = Some(Worker::spawn(ctx, move || llm::probe(&settings).map_err(reason)));
    }

    /// A field under its label; the label names the field for screen readers.
    fn labelled(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui) -> egui::Response) -> egui::Response {
        let label = ui.label(label);
        add(ui).labelled_by(label.id)
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> Option<DialogResult> {
        ui.horizontal(|ui| {
            title(ui, "Companion");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.checkbox(&mut self.draft.enabled, "Enabled");
            });
        });
        // OK and Cancel stay on screen in a small window
        egui::ScrollArea::vertical()
            .id_salt("companion-settings")
            .max_height((ctx.content_rect().height() - 120.0).max(200.0))
            .show(ui, |ui| self.fields(ui, ctx));
        error_line(ui, &self.error);
        let (ok, cancel) = buttons(ui, "OK", true);
        if ok {
            return self.save().map(DialogResult::CompanionSettings);
        }
        cancel.then_some(DialogResult::Cancel)
    }

    fn fields(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.connection_fields(ui, ctx);
        let p = *theme::current(ctx);
        ui.horizontal(|ui| {
            let testing = self.probe_worker.is_some();
            if ui.add_enabled(!testing, egui::Button::new("Test connection")).clicked() {
                self.test_connection(ctx);
            }
            if testing {
                ui.spinner();
            }
            match &self.probe {
                Some(Ok(_)) => {
                    ui.label(RichText::new("✓ Reachable").color(p.ok));
                }
                Some(Err(line)) => {
                    ui.add(egui::Label::new(RichText::new(format!("✗ {line}")).color(p.fail)).wrap());
                }
                None => {}
            }
        });
        self.endpoint_note(ui, ctx);
        self.preset_fields(ui, ctx);
    }

    /// Endpoint, protocol, key and model with the model list, the context window, and under Advanced the
    /// User-Agent and extra headers.
    pub fn connection_fields(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let small = |text: &str| RichText::new(text).size(SMALL_SIZE).color(p.muted);
        let mut connection_edited = false;
        section(ui, "Connection");

        let url = Self::labelled(ui, "Endpoint URL", |ui| {
            ui.add(
                TextEdit::singleline(&mut self.draft.endpoint_url)
                    .hint_text("e.g. http://10.0.0.5:8000/v1")
                    .desired_width(f32::INFINITY),
            )
        });
        connection_edited |= url.changed();

        ui.label("Protocol");
        ui.horizontal(|ui| {
            for (protocol, text) in [(Protocol::OpenAi, "OpenAI"), (Protocol::Anthropic, "Anthropic")] {
                connection_edited |= ui.radio_value(&mut self.draft.protocol, protocol, text).changed();
            }
        });

        if self.draft.api_key_from_env {
            ui.label("API key");
            ui.label(small("(from environment)"));
        } else {
            let hint = if self.key_stored { "(stored)" } else { "" };
            let key = Self::labelled(ui, "API key", |ui| {
                ui.add(
                    TextEdit::singleline(&mut self.draft.api_key)
                        .password(true)
                        .hint_text(hint)
                        .desired_width(f32::INFINITY),
                )
            });
            connection_edited |= key.changed();
            if self.key_stored && ui.small_button("Clear stored key").clicked() {
                // saving now writes an empty key, unless one is typed
                self.key_stored = false;
                self.stored_key.clear();
                connection_edited = true;
            }
            ui.label(small(
                "Stored as entered in the companion database: keep its folder private.",
            ));
        }

        let mut headers_edited = false;
        egui::CollapsingHeader::new(RichText::new("Advanced").size(SMALL_SIZE).color(p.secondary))
            .id_salt("companion-advanced")
            .default_open(!self.draft.user_agent.trim().is_empty() || !self.draft.extra_headers.trim().is_empty())
            .show(ui, |ui| {
                Self::labelled(ui, "User-Agent", |ui| {
                    ui.add(TextEdit::singleline(&mut self.draft.user_agent).desired_width(f32::INFINITY))
                });
                let headers = Self::labelled(ui, "Extra headers", |ui| {
                    ui.add(
                        TextEdit::multiline(&mut self.draft.extra_headers)
                            .code_editor()
                            .hint_text(r#"{"X-Header": "value"}"#)
                            .desired_rows(2)
                            .desired_width(f32::INFINITY),
                    )
                });
                headers_edited = headers.changed();
            });
        connection_edited |= headers_edited;

        if connection_edited {
            self.last_edit = Some(Instant::now());
        }
        self.update_models(ctx);

        section(ui, "Model");
        let model_label = ui.label("Model");
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let mut ids: Vec<&str> = self.models.iter().map(|m| m.id.as_str()).collect();
                if !self.saved_model.is_empty() && !ids.contains(&self.saved_model.as_str()) {
                    ids.push(&self.saved_model);
                }
                let mut chosen = None;
                let combo = egui::ComboBox::from_id_salt("companion-model")
                    .selected_text("")
                    .width(20.0)
                    .show_ui(ui, |ui| {
                        for id in ids {
                            if ui.selectable_label(self.draft.model == id, id).clicked() {
                                chosen = Some(id.to_string());
                            }
                        }
                    });
                combo
                    .response
                    .widget_info(|| egui::WidgetInfo::labeled(egui::Role::ComboBox, true, "Models from the endpoint"));
                if let Some(id) = chosen {
                    self.draft.model = id;
                }
                // the field takes the width the list button leaves
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    ui.add(TextEdit::singleline(&mut self.draft.model).desired_width(f32::INFINITY))
                        .labelled_by(model_label.id);
                });
            });
        });
        ui.label(small(&self.models_status));

        Self::labelled(ui, "Context window", |ui| {
            ui.add(
                TextEdit::singleline(&mut self.context_window)
                    .hint_text("tokens (empty: unknown)")
                    .desired_width(f32::INFINITY),
            )
        });
    }

    /// The preset choice, what the chosen one is for, and its guideline: a built-in one read-only behind a closed
    /// heading, a custom one open for editing.
    pub fn preset_fields(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let small = |text: &str| RichText::new(text).size(SMALL_SIZE).color(p.muted);
        section(ui, "Preset");
        ui.horizontal_wrapped(|ui| {
            for preset in Preset::ALL {
                let before = self.draft.preset;
                if ui.radio_value(&mut self.draft.preset, preset, preset.label()).changed()
                    && preset == Preset::Custom
                    && self.draft.global_guideline.trim().is_empty()
                {
                    // a custom text starts from the guideline chosen before
                    self.draft.global_guideline = before.builtin_guideline().unwrap_or_default().to_string();
                }
            }
        });
        ui.add(egui::Label::new(small(self.draft.preset.blurb())).wrap());
        // the dialog itself scrolls: a scroll area of its own here would catch the mouse wheel
        match self.draft.preset.builtin_guideline() {
            Some(text) => {
                egui::CollapsingHeader::new("Guideline")
                    .id_salt("companion-guideline")
                    .default_open(false)
                    .show(ui, |ui| {
                        let note = ui.label(small(BUILTIN_GUIDELINE));
                        ui.add(
                            TextEdit::multiline(&mut { text })
                                .desired_rows(6)
                                .desired_width(f32::INFINITY),
                        )
                        .labelled_by(note.id);
                    });
            }
            None => {
                let label = ui.label("Guideline");
                ui.add(
                    TextEdit::multiline(&mut self.draft.global_guideline)
                        .desired_rows(6)
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label.id);
            }
        }
    }

    /// Where case content goes, and through which proxy.
    pub fn endpoint_note(&self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let small = |text: &str| RichText::new(text).size(SMALL_SIZE).color(p.muted);
        let url = self.draft.endpoint_url.trim();
        if !url.is_empty() {
            ui.label(small(&format!("Case content is sent to {url}.")));
            if let Some(variable) = proxy_variable() {
                ui.label(small(&format!(
                    "{variable} is set: the requests go through that proxy unless NO_PROXY names the host."
                )));
            }
        }
    }
}

/// A group heading inside the settings, in the style of the panel headings.
fn section(ui: &mut egui::Ui, text: &str) {
    let p = theme::current(ui.ctx());
    ui.add_space(10.0);
    ui.label(
        RichText::new(text.to_uppercase())
            .size(SMALL_SIZE)
            .family(theme::bold())
            .color(p.muted)
            .extra_letter_spacing(1.2),
    );
    ui.add_space(2.0);
}
