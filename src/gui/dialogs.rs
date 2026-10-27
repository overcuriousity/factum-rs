//! Dialogs: each one is a state that is drawn every frame until it returns a result.

use egui::{Align, Id, Layout, RichText, TextEdit};

use super::companion_dialogs::CompanionSettingsDialog;
use super::icons;
use super::theme::{self, MONO_SIZE, SMALL_SIZE};
use super::widgets::{IconButton, actions_shown, remember_shown, visible_ui};
use super::wizard::{SEAL_EXPLAINED, SEAL_FOLDER_EXPLAINED, Wizard, WizardChoices};
use crate::companion::Settings;
use crate::pystr::{head, splitlines, strip};
use crate::signer::GpgKey;
use crate::verifier::{CaseReport, EntryResult, Finding, Level, SealSource, SignatureCheck};

/// An action that is carried out once the user has confirmed it.
#[derive(Debug, Clone, PartialEq)]
pub enum Pending {
    Archive(i64),
    DeleteEvidence(i64),
    Seal(i64),
    Export {
        case_id: i64,
        formats: Vec<String>,
        folder: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoGpgChoice {
    Configure,
    Continue,
    Cancel,
}

pub const EXPORT_FORMATS: [(&str, &str); 4] = [
    ("html", "HTML report"),
    ("pdf", "PDF report"),
    ("md", "Markdown report"),
    ("bundle", "Verification bundle (ZIP, includes all three reports)"),
];

pub enum Dialog {
    NewCase {
        file: String,
        name: String,
        description: String,
        error: Option<String>,
    },
    NewEvidence {
        case_id: i64,
        name: String,
        hash: String,
        details: String,
        error: Option<String>,
    },
    EditCase {
        case_id: i64,
        file: String,
        name: String,
        description: String,
        error: Option<String>,
    },
    EditEvidence {
        evidence_id: i64,
        name: String,
        hash: String,
        details: String,
    },
    AddLabel {
        entry_id: i64,
        label: String,
        /// the tags and labels in use, with their counts, minus the note's own
        known: Vec<(String, usize)>,
        /// the suggestion chosen with the arrow keys
        highlight: Option<usize>,
    },
    Confirm {
        message: String,
        then: Pending,
    },
    TypedConfirm {
        case_id: i64,
        message: String,
        expected: String,
        typed: String,
    },
    Correct {
        entry_id: i64,
        original: String,
        text: String,
    },
    Export {
        case_id: i64,
        formats: [bool; 4],
        folder: String,
        error: Option<String>,
    },
    GpgKeys {
        keys: Vec<GpgKey>,
        selected: Option<String>,
    },
    NoGpgKey {
        then: Pending,
    },
    GpgHelp,
    SealFolder {
        folder: String,
    },
    Shortcuts {
        rows: Vec<(String, String)>,
    },
    VerifyEntry {
        result: Box<EntryResult>,
    },
    Message {
        title: String,
        text: String,
    },
    CompanionSettings(Box<CompanionSettingsDialog>),
    Wizard(Box<Wizard>),
    CaseGoal {
        case_id: i64,
        goal: String,
    },
}

pub enum DialogResult {
    Cancel,
    NewCase {
        file: String,
        name: String,
        description: String,
    },
    NewEvidence {
        case_id: i64,
        name: String,
        hash: String,
        details: String,
    },
    EditCase {
        case_id: i64,
        file: String,
        name: String,
        description: String,
    },
    EditEvidence {
        evidence_id: i64,
        details: String,
    },
    AddLabel {
        entry_id: i64,
        label: String,
    },
    Confirmed(Pending),
    TypedConfirmed {
        case_id: i64,
        typed: String,
    },
    Correct {
        entry_id: i64,
        text: String,
    },
    Export {
        case_id: i64,
        formats: Vec<String>,
        folder: String,
    },
    KeySelected(String),
    NoGpg(NoGpgChoice, Pending),
    SealFolder(String),
    CompanionSettings(Settings),
    WizardFinished(Box<WizardChoices>),
    WizardCancelled {
        theme: String,
    },
    CaseGoal {
        case_id: i64,
        goal: String,
    },
}

pub(super) fn title(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let heading = ui.label(RichText::new(text).heading());
    ui.add_space(4.0);
    heading
}

pub(super) fn error_line(ui: &mut egui::Ui, error: &Option<String>) {
    if let Some(error) = error {
        ui.label(RichText::new(error).color(theme::current(ui.ctx()).fail));
    }
}

/// A right-aligned row of buttons, one button high. A plain right-to-left layout would take all the
/// height left in the dialog and centre the buttons in it, so the dialog could never shrink.
pub(super) fn button_row<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.add_space(6.0);
    let size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
    ui.allocate_ui_with_layout(size, Layout::right_to_left(Align::Center), add)
        .inner
}

/// The dialog's main action, filled in the accent colour (in the failure colour when it destroys something).
pub(super) fn primary_button(ui: &mut egui::Ui, text: &str, enabled: bool, destructive: bool) -> bool {
    let p = theme::current(ui.ctx());
    let fill = if destructive { p.fail } else { p.accent };
    let button = egui::Button::new(RichText::new(text).color(p.on_accent).family(theme::bold()))
        .fill(fill)
        .min_size(egui::vec2(72.0, 0.0));
    ui.add_enabled(enabled, button).clicked()
}

/// The main action on the right, Cancel left of it; returns (ok, cancel).
pub(super) fn buttons(ui: &mut egui::Ui, ok: &str, ok_enabled: bool) -> (bool, bool) {
    button_row(ui, |ui| {
        let ok = primary_button(ui, ok, ok_enabled, false);
        let cancel = ui.button("Cancel").clicked();
        (ok, cancel)
    })
}

fn close_button(ui: &mut egui::Ui, text: &str) -> bool {
    button_row(ui, |ui| primary_button(ui, text, true, false))
}

/// A folder path with a button that opens the system's folder picker.
pub(super) fn folder_field(ui: &mut egui::Ui, folder: &mut String, label: Option<egui::Id>) {
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let browse = IconButton::new(icons::FOLDER, "Choose folder").show(ui);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                let field = ui.add(TextEdit::singleline(folder).desired_width(f32::INFINITY));
                if let Some(label) = label {
                    field.labelled_by(label);
                }
            });
            if browse.clicked()
                && let Some(picked) = rfd::FileDialog::new().set_directory(folder.as_str()).pick_folder()
            {
                *folder = picked.to_string_lossy().into_owned();
            }
        });
    });
}

/// The suggestions under a text field, like a dropdown attached to it: the typed part of each name in bold, how
/// many entries carry it on the right. Returns the clicked one.
fn suggestion_list(
    ui: &mut egui::Ui,
    typed: &str,
    suggestions: &[(&str, usize, crate::tags::Match)],
    highlighted: Option<usize>,
) -> Option<String> {
    use crate::tags::Match;
    if suggestions.is_empty() || (suggestions.len() == 1 && suggestions[0].2 == Match::Exact) {
        return None;
    }
    let p = *theme::current(ui.ctx());
    let typed_len = typed.trim_start_matches('#').chars().count();
    let mut picked = None;
    egui::Frame::new()
        .fill(p.surface)
        .stroke(egui::Stroke::new(1.0, p.border))
        .corner_radius(2)
        .inner_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (index, (name, count, matched)) in suggestions.iter().enumerate() {
                let start = match matched {
                    Match::Exact | Match::Prefix => Some(0),
                    Match::Substring(at) => Some(*at),
                    Match::Typo(_) => None,
                };
                let mut job = egui::text::LayoutJob::default();
                let chars: Vec<char> = name.chars().collect();
                let plain = egui::TextFormat::simple(egui::FontId::proportional(theme::BODY_SIZE), p.text);
                let bold = egui::TextFormat::simple(egui::FontId::new(theme::BODY_SIZE, theme::bold()), p.accent);
                match start {
                    Some(at) if typed_len > 0 => {
                        let end = (at + typed_len).min(chars.len());
                        job.append(&chars[..at].iter().collect::<String>(), 0.0, plain.clone());
                        job.append(&chars[at..end].iter().collect::<String>(), 0.0, bold);
                        job.append(&chars[end..].iter().collect::<String>(), 0.0, plain);
                    }
                    _ => job.append(name, 0.0, plain),
                }
                let background = ui.painter().add(egui::Shape::Noop);
                let row = ui.scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
                    egui::Frame::new()
                        .inner_margin(egui::Margin::symmetric(8, 4))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.add(egui::Label::new(job).selectable(false));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    let uses = format!("{count}");
                                    ui.add(
                                        egui::Label::new(RichText::new(uses).size(SMALL_SIZE).color(p.muted))
                                            .selectable(false),
                                    );
                                    if matches!(matched, Match::Typo(_)) {
                                        ui.add(
                                            egui::Label::new(RichText::new("≈").size(SMALL_SIZE).color(p.muted))
                                                .selectable(false),
                                        )
                                        .on_hover_text("Close to what you typed");
                                    }
                                });
                            });
                        });
                });
                let response = row.response;
                let fill = if highlighted == Some(index) {
                    p.accent_soft
                } else if response.hovered() {
                    p.panel
                } else {
                    egui::Color32::TRANSPARENT
                };
                ui.painter()
                    .set(background, egui::Shape::rect_filled(response.rect, 2.0, fill));
                if response.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                let label = name.to_string();
                response.widget_info(|| {
                    egui::WidgetInfo::selected(egui::Role::ListBoxOption, true, highlighted == Some(index), &label)
                });
                if response
                    .on_hover_text(format!("On {count} entr{}", if *count == 1 { "y" } else { "ies" }))
                    .clicked()
                {
                    picked = Some(name.to_string());
                }
            }
        });
    picked
}

/// A note under a dialog's title or a field, in the small muted style.
pub(super) fn note(ui: &mut egui::Ui, text: &str) {
    let p = theme::current(ui.ctx());
    ui.add(egui::Label::new(RichText::new(text).size(SMALL_SIZE).color(p.muted)).wrap());
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str, focus: bool) -> egui::Response {
    let label = ui.label(label);
    let response = ui
        .add(TextEdit::singleline(value).hint_text(hint).desired_width(f32::INFINITY))
        .labelled_by(label.id);
    if focus {
        focus_once(ui, &response);
    }
    response
}

/// Gives the field the keyboard while nothing has it, but not in the frame Enter ended its input: taking it back
/// then would keep the dialog from ever seeing Enter.
fn focus_once(ui: &egui::Ui, field: &egui::Response) {
    if ui.memory(|m| m.focused().is_none()) && !ui.input(|i| i.key_pressed(egui::Key::Enter)) {
        field.request_focus();
    }
}

/// The signing keys to choose from, one row each, clickable as a whole; the list scrolls once it is taller than
/// about four keys.
pub fn key_list(ui: &mut egui::Ui, keys: &[GpgKey], selected: &mut Option<String>) {
    let p = *theme::current(ui.ctx());
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0, p.border))
        .corner_radius(2)
        .inner_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("gpg-keys")
                .max_height(236.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for key in keys {
                        let chosen = selected.as_deref() == Some(key.keyid.as_str());
                        if key_row(ui, key, chosen).clicked() {
                            *selected = Some(key.keyid.clone());
                        }
                    }
                });
        });
}

/// 40 hex digits in groups of four, the halves set apart, as gpg prints them.
fn grouped_fingerprint(fingerprint: &str) -> String {
    let groups: Vec<&str> = fingerprint
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect();
    let half = groups.len().div_ceil(2);
    format!("{}  {}", groups[..half].join(" "), groups[half..].join(" "))
}

/// A key: its radio mark, the first user ID, and below it key ID, algorithm and dates.
fn key_row(ui: &mut egui::Ui, key: &GpgKey, chosen: bool) -> egui::Response {
    let p = *theme::current(ui.ctx());
    let uid = key.uids.first().map(String::as_str).unwrap_or("(no user ID)");
    let mut details = vec![key.keyid.clone(), key.algorithm.clone()];
    if !key.created.is_empty() {
        details.push(format!("since {}", key.created));
    }
    if !key.expires.is_empty() && !key.expired() {
        details.push(format!("until {}", key.expires));
    }
    let warning = if key.revoked() {
        Some(("✗ revoked".to_string(), p.fail))
    } else if key.expired() {
        Some((format!("⚠ expired {}", key.expires).trim().to_string(), p.warn))
    } else {
        None
    };
    // the background goes under the row once its size and the pointer are known
    let background = ui.painter().add(egui::Shape::Noop);
    let row = ui.scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
        egui::Frame::new()
            .inner_margin(egui::Margin {
                left: 30,
                right: 8,
                top: 6,
                bottom: 6,
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add(
                    egui::Label::new(RichText::new(uid).color(p.text))
                        .truncate()
                        .selectable(false),
                );
                // one line of details, the warning after it in its colour
                let mut line = egui::text::LayoutJob::default();
                let style = ui.style().clone();
                RichText::new(details.join(" · "))
                    .size(SMALL_SIZE)
                    .monospace()
                    .color(p.muted)
                    .append_to(&mut line, &style, egui::FontSelection::Default, Align::Center);
                if let Some((text, color)) = warning {
                    RichText::new(format!("  {text}"))
                        .size(SMALL_SIZE)
                        .color(color)
                        .append_to(&mut line, &style, egui::FontSelection::Default, Align::Center);
                }
                ui.add(egui::Label::new(line).truncate().selectable(false));
            });
    });
    let response = row.response;
    let rect = response.rect;
    let fill = if chosen {
        p.accent_soft
    } else if response.hovered() {
        p.panel
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().set(background, egui::Shape::rect_filled(rect, 2.0, fill));
    // a radio mark: the row reads as one choice among several
    let center = egui::pos2(
        rect.left() + 15.0,
        rect.top() + 6.0 + ui.text_style_height(&egui::TextStyle::Body) / 2.0,
    );
    let ring = if chosen || response.hovered() {
        p.accent
    } else {
        p.muted
    };
    ui.painter().circle_stroke(center, 6.0, egui::Stroke::new(1.5, ring));
    if chosen {
        ui.painter().circle_filled(center, 3.0, p.accent);
    }
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::RadioButton, true, chosen, uid));
    let mut tip = grouped_fingerprint(&key.fingerprint);
    for uid in &key.uids {
        tip += &format!("\n{uid}");
    }
    response.on_hover_text(tip)
}

/// A multiline "Description" under its label.
fn description_field(ui: &mut egui::Ui, value: &mut String, hint: &str) {
    let label = ui.label("Description");
    ui.add(
        TextEdit::multiline(value)
            .hint_text(hint)
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(label.id);
}

fn enter_pressed(ui: &egui::Ui) -> bool {
    ui.input(|i| i.key_pressed(egui::Key::Enter) && !i.modifiers.shift)
}

pub fn signature_text(check: &SignatureCheck) -> String {
    if !check.present {
        return "not signed".into();
    }
    if !check.valid {
        return format!("INVALID ({})", check.status);
    }
    if !check.covers_payload {
        return "valid, but made over different data".into();
    }
    let late = if check.late {
        format!(
            ", signed later on {}",
            check.late_signed_utc.clone().unwrap_or_default()
        )
    } else {
        String::new()
    };
    format!(
        "valid{late} · {}",
        check.trust.clone().unwrap_or_else(|| "trust unknown".into())
    )
}

fn first_line(text: &str) -> String {
    splitlines(text)
        .first()
        .map(|line| head(line, 80).to_string())
        .unwrap_or_default()
}

fn verdict_color(ui: &egui::Ui, level: Level) -> egui::Color32 {
    let p = theme::current(ui.ctx());
    match level {
        Level::Ok => p.ok,
        Level::Warn => p.warn,
        Level::Fail => p.fail,
    }
}

/// ✓, ⚠ or ✗: a status is never told by its colour alone.
fn verdict_mark(level: Level) -> &'static str {
    match level {
        Level::Ok => "✓",
        Level::Warn => "⚠",
        Level::Fail => "✗",
    }
}

const GPG_HELP_LINUX: &str = "GPG signing failed because pinentry cannot display a dialog.\n\nFix: install a graphical \
    pinentry (e.g. pinentry-qt or pinentry-gnome3) and set it in ~/.gnupg/gpg-agent.conf:\n\n    pinentry-program \
    /usr/bin/pinentry-qt\n\nThen restart the agent:\n\n    gpgconf --reload gpg-agent";
const GPG_HELP_MACOS: &str = "GPG signing failed because pinentry cannot display a dialog.\n\nInstall pinentry-mac and \
    set it in ~/.gnupg/gpg-agent.conf:\n\n    pinentry-program /opt/homebrew/bin/pinentry-mac\n\nThen restart the \
    agent:\n\n    gpgconf --reload gpg-agent";
const GPG_HELP_WINDOWS: &str = "GPG signing failed because Gpg4win's pinentry could not prompt for a passphrase.\n\n\
    Ensure Gpg4win is installed and gpg-agent is running.\nYou can restart it from Kleopatra or by running:\n\n    \
    gpgconf --reload gpg-agent";

pub fn gpg_help_text() -> &'static str {
    if cfg!(target_os = "macos") {
        GPG_HELP_MACOS
    } else if cfg!(windows) {
        GPG_HELP_WINDOWS
    } else {
        GPG_HELP_LINUX
    }
}

impl Dialog {
    /// Draws the dialog; Some(result) closes it.
    pub fn show(&mut self, ctx: &egui::Context) -> Option<DialogResult> {
        // one id per kind of dialog: a modal keeps its last size under its id
        let modal = egui::Modal::new(Id::unique(("factum-dialog", std::mem::discriminant(self))))
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.set_width(match self {
                    Dialog::VerifyEntry { .. } => 820.0,
                    Dialog::GpgKeys { .. }
                    | Dialog::Correct { .. }
                    | Dialog::Shortcuts { .. }
                    | Dialog::CompanionSettings(_)
                    | Dialog::Wizard(_) => 560.0,
                    _ => 460.0,
                });
                self.contents(ui, ctx)
            });
        match modal.inner {
            Some(result) => Some(result),
            None if modal.should_close() => Some(match self {
                Dialog::Wizard(wizard) => wizard.cancelled(),
                _ => DialogResult::Cancel,
            }),
            None => None,
        }
    }

    fn contents(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> Option<DialogResult> {
        let p = *theme::current(ui.ctx());
        match self {
            Dialog::CompanionSettings(dialog) => dialog.show(ui, ctx),
            Dialog::Wizard(wizard) => wizard.show(ui, ctx),
            Dialog::CaseGoal { case_id, goal } => {
                let heading = title(ui, "Case goal");
                note(
                    ui,
                    "What this case has to establish; the companion asks its questions toward it.",
                );
                ui.add(TextEdit::multiline(goal).desired_rows(4).desired_width(f32::INFINITY))
                    .labelled_by(heading.id);
                let (ok, cancel) = buttons(ui, "OK", true);
                if ok {
                    return Some(DialogResult::CaseGoal {
                        case_id: *case_id,
                        goal: strip(goal).to_string(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::NewCase {
                file,
                name,
                description,
                error,
            } => {
                title(ui, "New Case");
                let first = field(ui, "File number", file, "Case file number", true);
                error_line(ui, error);
                field(ui, "Name", name, "Case name (defaults to the file number)", false);
                ui.label("Description");
                ui.add(
                    TextEdit::multiline(description)
                        .hint_text("Case description (optional)")
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                let (ok, cancel) = buttons(ui, "Create", true);
                if ok || (enter_pressed(ui) && first.lost_focus()) {
                    if strip(file).is_empty() {
                        *error = Some("Case file number is required.".into());
                        first.request_focus();
                        return None;
                    }
                    return Some(DialogResult::NewCase {
                        file: file.clone(),
                        name: name.clone(),
                        description: description.clone(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::NewEvidence {
                case_id,
                name,
                hash,
                details,
                error,
            } => {
                title(ui, "New Evidence");
                let first = field(ui, "Name", name, "Evidence name", true);
                error_line(ui, error);
                let second = field(ui, "Hash", hash, "Evidence hash (optional)", false);
                description_field(ui, details, "Description (optional)");
                let (ok, cancel) = buttons(ui, "Create", true);
                if ok || (enter_pressed(ui) && (first.lost_focus() || second.lost_focus())) {
                    if strip(name).is_empty() {
                        *error = Some("Evidence name is required.".into());
                        first.request_focus();
                        return None;
                    }
                    return Some(DialogResult::NewEvidence {
                        case_id: *case_id,
                        name: strip(name).to_string(),
                        hash: strip(hash).to_string(),
                        details: details.clone(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::EditEvidence {
                evidence_id,
                name,
                hash,
                details,
            } => {
                title(ui, "Edit Evidence");
                note(
                    ui,
                    "The change is a signed entry in the case log; the earlier description stays in it.",
                );
                ui.add_space(4.0);
                egui::Grid::new("evidence-fixed")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Name").color(p.muted));
                        ui.label(name.as_str());
                        ui.end_row();
                        ui.label(RichText::new("Hash").color(p.muted));
                        ui.label(RichText::new(if hash.is_empty() { "—" } else { hash.as_str() }).monospace());
                        ui.end_row();
                    });
                description_field(ui, details, "");
                let (ok, cancel) = buttons(ui, "Save", true);
                if ok {
                    return Some(DialogResult::EditEvidence {
                        evidence_id: *evidence_id,
                        details: details.clone(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::EditCase {
                case_id,
                file,
                name,
                description,
                error,
            } => {
                title(ui, "Edit Case");
                note(
                    ui,
                    "The change is a signed entry in the case log; the earlier details stay in it.",
                );
                let first = field(ui, "File number", file, "Case file number", true);
                error_line(ui, error);
                field(ui, "Name", name, "Case name (defaults to the file number)", false);
                ui.label("Description");
                ui.add(
                    TextEdit::multiline(description)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                let (ok, cancel) = buttons(ui, "Save", true);
                if ok {
                    if strip(file).is_empty() {
                        *error = Some("Case file number is required.".into());
                        first.request_focus();
                        return None;
                    }
                    return Some(DialogResult::EditCase {
                        case_id: *case_id,
                        file: file.clone(),
                        name: name.clone(),
                        description: description.clone(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::AddLabel {
                entry_id,
                label,
                known,
                highlight,
            } => {
                title(ui, &format!("Label Note #{entry_id}"));
                note(ui, "Labels are not signed.");
                let suggestions = crate::tags::suggest(label, known, 6);
                let field_id = Id::unique(("label-field", *entry_id));
                // while typing, ↑ and ↓ move through the suggestions and Tab takes one into the field
                if ui.memory(|m| m.has_focus(field_id)) && !suggestions.is_empty() {
                    let pressed = |key| ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, key));
                    if pressed(egui::Key::ArrowDown) {
                        *highlight = Some(highlight.map_or(0, |h| (h + 1).min(suggestions.len() - 1)));
                    }
                    if pressed(egui::Key::ArrowUp) {
                        *highlight = highlight.and_then(|h| h.checked_sub(1));
                    }
                    if let Some(h) = *highlight
                        && h < suggestions.len()
                        && pressed(egui::Key::Tab)
                    {
                        *label = suggestions[h].0.to_string();
                        *highlight = None;
                    }
                }
                let highlighted = highlight.filter(|h| *h < suggestions.len());
                let name = ui.label("Label");
                let input = ui
                    .add(
                        TextEdit::singleline(label)
                            .id(field_id)
                            .hint_text("Type to search the tags and labels in use")
                            .desired_width(f32::INFINITY),
                    )
                    .labelled_by(name.id)
                    .on_hover_text("↑ ↓ choose · Tab complete · Enter add");
                focus_once(ui, &input);
                if input.changed() {
                    *highlight = None;
                }
                let typed = strip(label).to_string();
                let picked = suggestion_list(ui, &typed, &suggestions, highlighted);
                let enter = enter_pressed(ui) && input.lost_focus();
                let (ok, cancel) = buttons(ui, "Add", !typed.is_empty());
                // a click on a suggestion adds it; Enter adds the highlighted one, or what was typed
                let chosen = if picked.is_some() {
                    picked
                } else if enter {
                    Some(highlighted.map_or(typed.clone(), |h| suggestions[h].0.to_string()))
                } else {
                    ok.then(|| typed.clone())
                };
                if let Some(chosen) = chosen.filter(|c| !strip(c).is_empty()) {
                    return Some(DialogResult::AddLabel {
                        entry_id: *entry_id,
                        label: strip(&chosen).to_string(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::Confirm { message, then } => {
                let (heading, verb) = match then {
                    Pending::Archive(_) => ("Archive Case?", "Archive"),
                    Pending::DeleteEvidence(_) => ("Delete Evidence?", "Delete"),
                    Pending::Seal(_) => ("Seal Case?", "Seal"),
                    Pending::Export { .. } => ("Export Case?", "Export"),
                };
                title(ui, heading);
                // user-entered names are shown as plain text
                ui.add(egui::Label::new(message.as_str()).wrap());
                let mut result = None;
                button_row(ui, |ui| {
                    let destructive = matches!(then, Pending::DeleteEvidence(_));
                    if primary_button(ui, verb, true, destructive) {
                        result = Some(DialogResult::Confirmed(then.clone()));
                    }
                    if ui.button("Cancel").clicked() {
                        result = Some(DialogResult::Cancel);
                    }
                });
                result
            }
            Dialog::TypedConfirm {
                case_id,
                message,
                expected,
                typed,
            } => {
                title(ui, "Delete Case Permanently?");
                ui.add(egui::Label::new(message.as_str()).wrap());
                ui.add(
                    TextEdit::singleline(typed)
                        .hint_text(expected.as_str())
                        .desired_width(f32::INFINITY),
                );
                // the button only becomes available once the expected text is typed exactly
                let (ok, cancel) = button_row(ui, |ui| {
                    let ok = primary_button(ui, "Delete permanently", typed == expected, true);
                    (ok, ui.button("Cancel").clicked())
                });
                if ok && typed == expected {
                    return Some(DialogResult::TypedConfirmed {
                        case_id: *case_id,
                        typed: typed.clone(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::Correct {
                entry_id,
                original,
                text,
            } => {
                let heading = title(ui, &format!("Correct Note #{entry_id}"));
                note(
                    ui,
                    "The original stays in the log; the corrected text is added as a new, signed version.",
                );
                ui.add(
                    TextEdit::multiline(text)
                        .font(egui::FontId::proportional(theme::NOTE_SIZE))
                        .desired_rows(8)
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(heading.id);
                let changed = !strip(text).is_empty() && strip(text) != strip(original);
                let (ok, cancel) = buttons(ui, "Add corrected version", changed);
                if ok && changed {
                    return Some(DialogResult::Correct {
                        entry_id: *entry_id,
                        text: strip(text).to_string(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::Export {
                case_id,
                formats,
                folder,
                error,
            } => {
                title(ui, "Export Case");
                ui.label("Formats");
                for (index, (_, label)) in EXPORT_FORMATS.iter().enumerate() {
                    ui.checkbox(&mut formats[index], *label);
                }
                ui.add_space(4.0);
                let label = ui.label("Folder");
                folder_field(ui, folder, Some(label.id));
                note(ui, "Exporting seals the current state of the case.");
                error_line(ui, error);
                let (ok, cancel) = buttons(ui, "Export", true);
                if ok {
                    let chosen: Vec<String> = EXPORT_FORMATS
                        .iter()
                        .zip(formats.iter())
                        .filter(|(_, on)| **on)
                        .map(|((key, _), _)| key.to_string())
                        .collect();
                    if chosen.is_empty() {
                        *error = Some("Choose at least one format.".into());
                        return None;
                    }
                    if strip(folder).is_empty() {
                        *error = Some("Choose a folder.".into());
                        return None;
                    }
                    return Some(DialogResult::Export {
                        case_id: *case_id,
                        formats: chosen,
                        folder: strip(folder).to_string(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::GpgKeys { keys, selected } => {
                title(ui, "Signing Key");
                note(ui, "Your secret keys that can sign [S].");
                if keys.is_empty() {
                    ui.label(RichText::new("⚠ No secret keys with signing capability found.").color(p.warn));
                }
                key_list(ui, keys, selected);
                let (ok, cancel) = buttons(ui, "Use this key", selected.is_some());
                if ok {
                    return selected.clone().map(DialogResult::KeySelected);
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::NoGpgKey { then } => {
                title(ui, "No Signing Key");
                ui.add(
                    egui::Label::new("The seal will be stored unsigned; it can be signed later. Choose a key now?")
                        .wrap(),
                );
                let mut result = None;
                button_row(ui, |ui| {
                    if primary_button(ui, "Choose key…", true, false) {
                        result = Some(DialogResult::NoGpg(NoGpgChoice::Configure, then.clone()));
                    }
                    if ui.button("Continue unsigned").clicked() {
                        result = Some(DialogResult::NoGpg(NoGpgChoice::Continue, then.clone()));
                    }
                    if ui.button("Cancel").clicked() {
                        result = Some(DialogResult::NoGpg(NoGpgChoice::Cancel, then.clone()));
                    }
                });
                result
            }
            Dialog::GpgHelp => {
                title(ui, "GPG Signing Failed");
                ui.label(RichText::new(gpg_help_text()).font(egui::FontId::monospace(MONO_SIZE)));
                close_button(ui, "OK").then_some(DialogResult::Cancel)
            }
            Dialog::SealFolder { folder } => {
                title(ui, "Seal Folder");
                ui.add(egui::Label::new(SEAL_EXPLAINED).wrap());
                note(ui, SEAL_FOLDER_EXPLAINED);
                ui.add_space(4.0);
                folder_field(ui, folder, None);
                let (ok, cancel) = buttons(ui, "Use this folder", !strip(folder).is_empty());
                if ok {
                    return Some(DialogResult::SealFolder(strip(folder).to_string()));
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::Shortcuts { rows } => {
                title(ui, "Keyboard Shortcuts");
                egui::Grid::new("shortcuts")
                    .striped(true)
                    .num_columns(2)
                    .spacing([24.0, 6.0])
                    .show(ui, |ui| {
                        for (keys, action) in rows.iter() {
                            ui.label(RichText::new(keys).monospace());
                            ui.label(action);
                            ui.end_row();
                        }
                    });
                close_button(ui, "Close").then_some(DialogResult::Cancel)
            }
            Dialog::VerifyEntry { result } => {
                let (entry, check) = (&result.entry, &result.signature);
                title(ui, &format!("Verify Entry #{}", entry.id));
                let status = result.status();
                let verdict = if status == Level::Ok {
                    "✓ The entry matches its leaf hash, its tree head is consistent with every earlier entry, and the signature is valid.".to_string()
                } else {
                    format!(
                        "{} {}",
                        verdict_mark(status),
                        result
                            .findings
                            .iter()
                            .map(|f| f.message.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                };
                ui.add(
                    egui::Label::new(
                        RichText::new(verdict)
                            .color(verdict_color(ui, status))
                            .family(theme::bold()),
                    )
                    .wrap(),
                );
                let signed_at = check
                    .signature_timestamp
                    .as_deref()
                    .and_then(|t| t.parse::<i64>().ok())
                    .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                let dash =
                    |value: &Option<String>| value.clone().filter(|v| !v.is_empty()).unwrap_or_else(|| "-".into());
                let lines = [
                    format!("Created:           {}", entry.created_utc),
                    format!("Leaf index:        {}", entry.leaf_index),
                    format!("Stored leaf hash:  {}", entry.leaf_hash),
                    format!("Recomputed:        {}", result.recomputed_leaf_hash),
                    format!("Stored tree head:  size {}, root {}", entry.tree_size, entry.root_hash),
                    format!(
                        "Recomputed head:   size {}, root {}",
                        result.recomputed_tree_size, result.recomputed_root_hash
                    ),
                    format!("Signature:         {}", signature_text(check)),
                    format!("Signer:            {}", dash(&check.username)),
                    format!("Key ID:            {}", dash(&check.key_id)),
                    format!("Fingerprint:       {}", dash(&check.fingerprint)),
                    format!("Signed at:         {}", dash(&signed_at)),
                ];
                let mut details = lines.join("\n");
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    ui.add(
                        TextEdit::multiline(&mut details)
                            .font(egui::FontId::monospace(MONO_SIZE))
                            .desired_width(f32::INFINITY)
                            .interactive(true),
                    );
                });
                close_button(ui, "OK").then_some(DialogResult::Cancel)
            }
            Dialog::Message { title: heading, text } => {
                title(ui, heading);
                ui.add(egui::Label::new(text.as_str()).wrap());
                close_button(ui, "OK").then_some(DialogResult::Cancel)
            }
        }
    }
}

/// The verification report of a case; not modal, so entries can be looked at while it stays open.
pub struct VerifyWindow {
    pub id: u64,
    pub report: CaseReport,
    pub open: bool,
}

pub enum VerifyAction {
    ShowEntry(i64),
    SignSeal(i64),
}

fn finding_item(finding: &Finding) -> String {
    match (finding.entry_id, finding.tree_head_id) {
        (Some(id), _) => format!("#{id}"),
        (None, Some(id)) => format!("seal #{id}"),
        _ => "case".into(),
    }
}

/// A window that stays open beside the main window (reports, Ask, History): framed like a dialog, about centred when
/// it opens (moved by `offset`, so a second one does not hide the first), with its title and a close button on top.
pub(super) fn report_window(
    ctx: &egui::Context,
    id: Id,
    heading: &str,
    open: &mut bool,
    size: [f32; 2],
    offset: f32,
    add: impl FnOnce(&mut egui::Ui),
) {
    if !*open {
        return;
    }
    egui::Window::new(heading)
        .id(id)
        .title_bar(false)
        .frame(theme::dialog_frame(ctx))
        .default_size(size)
        .resizable(true)
        // placed by its top left corner: centred for its default size, it grows downwards instead of moving
        .default_pos(ctx.content_rect().center() - egui::vec2(size[0], size[1]) / 2.0 + egui::vec2(offset, offset))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(heading).heading());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if IconButton::new(icons::CLOSE, "Close").show(ui).clicked() {
                        *open = false;
                    }
                });
            });
            ui.add_space(4.0);
            add(ui);
        });
}

fn plural(count: usize, word: &str) -> String {
    format!("{count} {word}{}", if count == 1 { "" } else { "s" })
}

impl VerifyWindow {
    pub fn show(&mut self, ctx: &egui::Context, actions: &mut Vec<VerifyAction>) {
        let report = &self.report;
        let unsigned_heads: Vec<i64> = report
            .tree_heads
            .iter()
            .filter(|h| h.source == SealSource::Database && !h.signature.present)
            .filter_map(|h| h.tree_head_id)
            .collect();
        let heading = format!("Verify Case {}", report.case.case_file);
        let offset = 24.0 * (self.id % 5) as f32;
        report_window(
            ctx,
            Id::unique(("verify-window", self.id)),
            &heading,
            &mut self.open,
            [760.0, 520.0],
            offset,
            |ui| {
                let p = *theme::current(ui.ctx());
                let overall = report.overall();
                let fails: Vec<&Finding> = report.findings.iter().filter(|f| f.level == Level::Fail).collect();
                let warnings: Vec<&Finding> = report.findings.iter().filter(|f| f.level == Level::Warn).collect();
                let ok_entries: Vec<&EntryResult> = report.entries.iter().filter(|r| r.status() == Level::Ok).collect();
                // the verdict counts findings, like the sections below; the line under it counts entries
                let verdict = match overall {
                    Level::Ok => format!("All {} entries verified", report.entries.len()),
                    Level::Warn => plural(warnings.len(), "warning"),
                    Level::Fail if warnings.is_empty() => plural(fails.len(), "failure"),
                    Level::Fail => format!(
                        "{}, {}",
                        plural(fails.len(), "failure"),
                        plural(warnings.len(), "warning")
                    ),
                };
                ui.label(
                    RichText::new(format!("{} {verdict}", verdict_mark(overall)))
                        .size(theme::NOTE_SIZE)
                        .family(theme::bold())
                        .color(verdict_color(ui, overall)),
                );
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let small = |text: String| RichText::new(text).size(SMALL_SIZE).color(p.muted);
                    ui.label(small(format!(
                        "{} of {} entries OK · tree size {} · root",
                        ok_entries.len(),
                        report.entries.len(),
                        report.tree_size
                    )));
                    ui.label(
                        RichText::new(format!("{}…", head(&report.root_hash, 16)))
                            .monospace()
                            .color(p.secondary),
                    )
                    .on_hover_text(&report.root_hash);
                    if IconButton::new(icons::COPY, "Copy root hash").show(ui).clicked() {
                        ui.ctx().copy_text(report.root_hash.clone());
                    }
                });
                ui.separator();
                let bottom = 64.0;
                egui::ScrollArea::vertical()
                    .auto_shrink([false, true])
                    .max_height((ui.available_height() - bottom).max(120.0))
                    .show(ui, |ui| {
                        let row = |ui: &mut egui::Ui,
                                   status: Level,
                                   item: String,
                                   details: String,
                                   entry_id: Option<i64>,
                                   head_id: Option<i64>,
                                   actions: &mut Vec<VerifyAction>| {
                            let id = ui.scope_id().with(("verify-row", &item, &details));
                            let shown = actions_shown(ui, id);
                            let can_sign = head_id.is_some_and(|id| unsigned_heads.contains(&id));
                            let response = ui.horizontal(|ui| {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.spacing_mut().item_spacing.x = 2.0;
                                    visible_ui(ui, shown, |ui| {
                                        if let Some(id) = entry_id
                                            && IconButton::new(icons::SHOW, "Show entry").show(ui).clicked()
                                        {
                                            actions.push(VerifyAction::ShowEntry(id));
                                        }
                                        if let Some(id) = head_id.filter(|_| can_sign)
                                            && IconButton::new(icons::SIGN, "Sign seal").show(ui).clicked()
                                        {
                                            actions.push(VerifyAction::SignSeal(id));
                                        }
                                    });
                                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                        ui.label(RichText::new(verdict_mark(status)).color(verdict_color(ui, status)));
                                        ui.label(RichText::new(format!("{item:<10}")).monospace().color(p.secondary));
                                        ui.add(egui::Label::new(details.as_str()).wrap().sense(egui::Sense::click()))
                                    })
                                    .inner
                                })
                                .inner
                            });
                            remember_shown(ui, id, response.response.contains_pointer());
                            let label = response.inner;
                            if label.double_clicked()
                                && let Some(id) = entry_id
                            {
                                actions.push(VerifyAction::ShowEntry(id));
                            }
                            if entry_id.is_some() || can_sign {
                                label.context_menu(|ui| {
                                    if let Some(id) = entry_id
                                        && ui.button("Show Entry").clicked()
                                    {
                                        actions.push(VerifyAction::ShowEntry(id));
                                    }
                                    if let Some(id) = head_id.filter(|_| can_sign)
                                        && ui.button("Sign Now").clicked()
                                    {
                                        actions.push(VerifyAction::SignSeal(id));
                                    }
                                });
                            }
                        };
                        egui::CollapsingHeader::new(format!("Failures {}", fails.len()))
                            .default_open(true)
                            .show(ui, |ui| {
                                for f in &fails {
                                    row(
                                        ui,
                                        f.level,
                                        finding_item(f),
                                        f.message.clone(),
                                        f.entry_id,
                                        f.tree_head_id,
                                        actions,
                                    );
                                }
                            });
                        egui::CollapsingHeader::new(format!("Warnings {}", warnings.len()))
                            .default_open(fails.is_empty())
                            .show(ui, |ui| {
                                for f in &warnings {
                                    row(
                                        ui,
                                        f.level,
                                        finding_item(f),
                                        f.message.clone(),
                                        f.entry_id,
                                        f.tree_head_id,
                                        actions,
                                    );
                                }
                            });
                        egui::CollapsingHeader::new(format!("Entries OK {}", ok_entries.len()))
                            .default_open(false)
                            .show(ui, |ui| {
                                for r in &ok_entries {
                                    let item = format!("#{} leaf {}", r.entry.id, r.entry.leaf_index);
                                    row(
                                        ui,
                                        Level::Ok,
                                        item,
                                        first_line(&r.entry.text),
                                        Some(r.entry.id),
                                        None,
                                        actions,
                                    );
                                }
                            });
                        egui::CollapsingHeader::new(format!("Seals {}", report.tree_heads.len()))
                            .default_open(false)
                            .show(ui, |ui| {
                                for h in &report.tree_heads {
                                    row(
                                        ui,
                                        h.status(),
                                        h.label.clone(),
                                        signature_text(&h.signature),
                                        None,
                                        h.tree_head_id,
                                        actions,
                                    );
                                }
                            });
                    });
                ui.separator();
                let signers = report
                    .signers
                    .iter()
                    .map(|(fingerprint, name)| {
                        format!("{fingerprint} {}", name.clone().unwrap_or_default())
                            .trim()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let newest = report
                    .newest_seal_size
                    .map(|s| format!("size {s}"))
                    .unwrap_or_else(|| "none".into());
                egui::Grid::new("verify-facts")
                    .num_columns(2)
                    .spacing([16.0, 2.0])
                    .show(ui, |ui| {
                        for (name, value) in [
                            ("Signers", if signers.is_empty() { "none" } else { signers.as_str() }),
                            ("Newest valid seal", newest.as_str()),
                        ] {
                            ui.label(RichText::new(name).size(SMALL_SIZE).color(p.muted));
                            ui.label(RichText::new(value).size(SMALL_SIZE).color(p.secondary));
                            ui.end_row();
                        }
                    });
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_texts() {
        assert_eq!(signature_text(&SignatureCheck::default()), "not signed");
        let good = SignatureCheck {
            present: true,
            valid: true,
            covers_payload: true,
            trust: Some("TRUST_ULTIMATE".into()),
            ..Default::default()
        };
        assert_eq!(signature_text(&good), "valid · TRUST_ULTIMATE");
        let late = SignatureCheck {
            late: true,
            late_signed_utc: Some("2026".into()),
            ..good.clone()
        };
        assert_eq!(signature_text(&late), "valid, signed later on 2026 · TRUST_ULTIMATE");
        assert_eq!(
            signature_text(&SignatureCheck {
                covers_payload: false,
                ..good
            }),
            "valid, but made over different data"
        );
    }
}
