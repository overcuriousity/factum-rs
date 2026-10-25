//! Dialogs: each one is a state that is drawn every frame until it returns a result.

use egui::{Align, Id, Layout, RichText, TextEdit};

use super::theme::{self, MONO_SIZE, SMALL_SIZE};
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
        description: String,
        hash: String,
        error: Option<String>,
    },
    EditCase {
        case_id: i64,
        file: String,
        name: String,
        description: String,
        error: Option<String>,
    },
    AddLabel {
        entry_id: i64,
        label: String,
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
        description: String,
        hash: String,
    },
    EditCase {
        case_id: i64,
        file: String,
        name: String,
        description: String,
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
}

fn title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).heading());
    ui.add_space(4.0);
}

fn error_line(ui: &mut egui::Ui, error: &Option<String>) {
    if let Some(error) = error {
        ui.label(RichText::new(error).color(theme::current(ui.ctx()).fail));
    }
}

/// OK / Cancel buttons, right-aligned; returns (ok, cancel).
fn buttons(ui: &mut egui::Ui, ok: &str, ok_enabled: bool) -> (bool, bool) {
    let mut result = (false, false);
    ui.add_space(6.0);
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        result.1 = ui.button("Cancel").clicked();
        result.0 = ui.add_enabled(ok_enabled, egui::Button::new(ok)).clicked();
    });
    result
}

fn close_button(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add_space(6.0);
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.button(text).clicked())
        .inner
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str, focus: bool) -> egui::Response {
    ui.label(label);
    let response = ui.add(TextEdit::singleline(value).hint_text(hint).desired_width(f32::INFINITY));
    if focus && ui.memory(|m| m.focused().is_none()) {
        response.request_focus();
    }
    response
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
        let modal = egui::Modal::new(Id::unique("factum-dialog")).show(ctx, |ui| {
            ui.set_width(match self {
                Dialog::VerifyEntry { .. } => 820.0,
                Dialog::Correct { .. } | Dialog::Shortcuts { .. } => 560.0,
                _ => 460.0,
            });
            self.contents(ui)
        });
        match modal.inner {
            Some(result) => Some(result),
            None if modal.should_close() => Some(DialogResult::Cancel),
            None => None,
        }
    }

    fn contents(&mut self, ui: &mut egui::Ui) -> Option<DialogResult> {
        let p = *theme::current(ui.ctx());
        match self {
            Dialog::NewCase {
                file,
                name,
                description,
                error,
            } => {
                title(ui, "Create New Case");
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
                description,
                hash,
                error,
            } => {
                title(ui, "Create New Evidence");
                let first = field(ui, "Description", description, "Evidence description", true);
                error_line(ui, error);
                let second = field(ui, "Hash", hash, "Evidence hash (optional)", false);
                let (ok, cancel) = buttons(ui, "Create", true);
                if ok || (enter_pressed(ui) && (first.lost_focus() || second.lost_focus())) {
                    if strip(description).is_empty() {
                        *error = Some("Evidence description is required.".into());
                        first.request_focus();
                        return None;
                    }
                    return Some(DialogResult::NewEvidence {
                        case_id: *case_id,
                        description: strip(description).to_string(),
                        hash: strip(hash).to_string(),
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
                title(ui, "Edit Case Details");
                ui.label(
                    RichText::new("The change is recorded as a signed entry in the case log; the earlier details stay in the log.")
                        .size(SMALL_SIZE)
                        .color(p.muted),
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
            Dialog::AddLabel { entry_id, label } => {
                title(ui, &format!("Add a label to note #{entry_id}"));
                ui.label(RichText::new("Labels are not signed.").size(SMALL_SIZE).color(p.muted));
                let input = field(ui, "Label", label, "e.g. review", true);
                let (ok, cancel) = buttons(ui, "Add", !strip(label).is_empty());
                if (ok || (enter_pressed(ui) && input.lost_focus())) && !strip(label).is_empty() {
                    return Some(DialogResult::AddLabel {
                        entry_id: *entry_id,
                        label: strip(label).to_string(),
                    });
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::Confirm { message, then } => {
                title(ui, "Confirm Action");
                // user-entered names are shown as plain text
                ui.label(message.as_str());
                let mut result = None;
                ui.add_space(6.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("No").clicked() {
                        result = Some(DialogResult::Cancel);
                    }
                    if ui.button("Yes").clicked() {
                        result = Some(DialogResult::Confirmed(then.clone()));
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
                title(ui, "Confirm Permanent Deletion");
                ui.label(message.as_str());
                ui.add(
                    TextEdit::singleline(typed)
                        .hint_text(expected.as_str())
                        .desired_width(f32::INFINITY),
                );
                // OK only becomes available once the expected text is typed exactly
                let (ok, cancel) = buttons(ui, "Delete permanently", typed == expected);
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
                title(ui, &format!("Correct Note #{entry_id}"));
                ui.label("The original stays in the log. The corrected text is added as a new, signed version.");
                ui.add(
                    TextEdit::multiline(text)
                        .font(egui::FontId::proportional(theme::NOTE_SIZE))
                        .desired_rows(8)
                        .desired_width(f32::INFINITY),
                );
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
                ui.label("Formats:");
                for (index, (_, label)) in EXPORT_FORMATS.iter().enumerate() {
                    ui.checkbox(&mut formats[index], *label);
                }
                ui.label("Folder:");
                ui.horizontal(|ui| {
                    let browse = ui.button("Browse…");
                    ui.add(TextEdit::singleline(folder).desired_width(f32::INFINITY));
                    if browse.clicked()
                        && let Some(picked) = rfd::FileDialog::new().set_directory(folder.as_str()).pick_folder()
                    {
                        *folder = picked.to_string_lossy().into_owned();
                    }
                });
                ui.label(
                    RichText::new("Exporting creates a seal of the current state of the case.")
                        .size(SMALL_SIZE)
                        .color(p.muted),
                );
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
                title(ui, "Select GPG Signing Key");
                ui.label("Only keys with signing capability [S] are shown:");
                if keys.is_empty() {
                    ui.label(RichText::new("No secret keys with signing capability found.").color(p.warn));
                }
                egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    egui::Grid::new("gpg-keys").striped(true).num_columns(2).show(ui, |ui| {
                        for key in keys.iter() {
                            let uid = key.uids.first().map(String::as_str).unwrap_or("(no UID)");
                            let chosen = selected.as_deref() == Some(key.keyid.as_str());
                            if ui
                                .selectable_label(chosen, RichText::new(&key.keyid).monospace())
                                .clicked()
                            {
                                *selected = Some(key.keyid.clone());
                            }
                            ui.label(uid);
                            ui.end_row();
                        }
                    });
                });
                let (ok, cancel) = buttons(ui, "Use this key", selected.is_some());
                if ok {
                    return selected.clone().map(DialogResult::KeySelected);
                }
                cancel.then_some(DialogResult::Cancel)
            }
            Dialog::NoGpgKey { then } => {
                title(ui, "No GPG key configured");
                ui.label("No GPG signing key is configured. The seal will be stored unsigned; it can be signed later.\n\nConfigure a key now?");
                let mut result = None;
                ui.add_space(6.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Cancel").clicked() {
                        result = Some(DialogResult::NoGpg(NoGpgChoice::Cancel, then.clone()));
                    }
                    if ui.button("Continue unsigned").clicked() {
                        result = Some(DialogResult::NoGpg(NoGpgChoice::Continue, then.clone()));
                    }
                    if ui.button("Configure…").clicked() {
                        result = Some(DialogResult::NoGpg(NoGpgChoice::Configure, then.clone()));
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
                title(ui, "Folder for external seal copies");
                ui.label("Put it on another medium (USB stick, network share): a seal only protects against removed entries if a copy exists outside the database. The folder must already exist.");
                ui.horizontal(|ui| {
                    let browse = ui.button("Browse…");
                    ui.add(TextEdit::singleline(folder).desired_width(f32::INFINITY));
                    if browse.clicked()
                        && let Some(picked) = rfd::FileDialog::new().set_directory(folder.as_str()).pick_folder()
                    {
                        *folder = picked.to_string_lossy().into_owned();
                    }
                });
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
                    "OK: the entry matches its leaf hash, its tree head is consistent with every earlier entry, and the signature is valid.".to_string()
                } else {
                    format!(
                        "{status}: {}",
                        result
                            .findings
                            .iter()
                            .map(|f| f.message.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                };
                ui.label(
                    RichText::new(verdict)
                        .color(verdict_color(ui, status))
                        .family(theme::bold()),
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
                ui.label(text.as_str());
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

impl VerifyWindow {
    pub fn show(&mut self, ctx: &egui::Context, actions: &mut Vec<VerifyAction>) {
        let report = &self.report;
        let unsigned_heads: Vec<i64> = report
            .tree_heads
            .iter()
            .filter(|h| h.source == SealSource::Database && !h.signature.present)
            .filter_map(|h| h.tree_head_id)
            .collect();
        egui::Window::new(format!("Verify Case {}", report.case.case_file))
            .id(Id::unique(("verify-window", self.id)))
            .open(&mut self.open)
            .default_size([940.0, 580.0])
            .resizable(true)
            .show(ctx, |ui| {
                let overall = report.overall();
                ui.label(
                    RichText::new(format!(
                        "{overall}: {} entries — {} OK, {} WARN, {} FAIL · tree size {} · root {}…",
                        report.entries.len(),
                        report.count(Level::Ok),
                        report.count(Level::Warn),
                        report.count(Level::Fail),
                        report.tree_size,
                        head(&report.root_hash, 16)
                    ))
                    .family(theme::bold())
                    .color(verdict_color(ui, overall)),
                );
                let fails: Vec<&Finding> = report.findings.iter().filter(|f| f.level == Level::Fail).collect();
                let warnings: Vec<&Finding> = report.findings.iter().filter(|f| f.level == Level::Warn).collect();
                let ok_entries: Vec<&EntryResult> = report.entries.iter().filter(|r| r.status() == Level::Ok).collect();
                let bottom = 84.0;
                egui::ScrollArea::vertical().max_height((ui.available_height() - bottom).max(120.0)).show(ui, |ui| {
                    let row = |ui: &mut egui::Ui, status: Level, item: String, details: String, entry_id: Option<i64>, head_id: Option<i64>, actions: &mut Vec<VerifyAction>| {
                        let response = ui
                            .horizontal(|ui| {
                                ui.label(RichText::new(format!("{:4}", status.as_str())).monospace().color(verdict_color(ui, status)));
                                ui.label(RichText::new(format!("{item:<10}")).monospace());
                                ui.add(egui::Label::new(details.as_str()).wrap().sense(egui::Sense::click()))
                            })
                            .inner;
                        if response.double_clicked()
                            && let Some(id) = entry_id {
                                actions.push(VerifyAction::ShowEntry(id));
                            }
                        let can_sign = head_id.is_some_and(|id| unsigned_heads.contains(&id));
                        if entry_id.is_some() || can_sign {
                            response.context_menu(|ui| {
                                if let Some(id) = entry_id
                                    && ui.button("Show Entry").clicked() {
                                        actions.push(VerifyAction::ShowEntry(id));
                                    }
                                if let Some(id) = head_id.filter(|_| can_sign)
                                    && ui.button("Sign Now").clicked() {
                                        actions.push(VerifyAction::SignSeal(id));
                                    }
                            });
                        }
                    };
                    egui::CollapsingHeader::new(format!("Failures ({})", fails.len())).default_open(true).show(ui, |ui| {
                        for f in &fails {
                            row(ui, f.level, finding_item(f), f.message.clone(), f.entry_id, f.tree_head_id, actions);
                        }
                    });
                    egui::CollapsingHeader::new(format!("Warnings ({})", warnings.len())).default_open(fails.is_empty()).show(ui, |ui| {
                        for f in &warnings {
                            row(ui, f.level, finding_item(f), f.message.clone(), f.entry_id, f.tree_head_id, actions);
                        }
                    });
                    egui::CollapsingHeader::new(format!("Entries OK ({})", ok_entries.len())).default_open(false).show(ui, |ui| {
                        for r in &ok_entries {
                            let item = format!("#{} leaf {}", r.entry.id, r.entry.leaf_index);
                            row(ui, Level::Ok, item, first_line(&r.entry.text), Some(r.entry.id), None, actions);
                        }
                    });
                    egui::CollapsingHeader::new(format!("Seals ({})", report.tree_heads.len())).default_open(false).show(ui, |ui| {
                        for h in &report.tree_heads {
                            row(ui, h.status(), h.label.clone(), signature_text(&h.signature), None, h.tree_head_id, actions);
                        }
                    });
                });
                ui.separator();
                let signers = report
                    .signers
                    .iter()
                    .map(|(fingerprint, name)| format!("{fingerprint} {}", name.clone().unwrap_or_default()).trim().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let newest = report.newest_seal_size.map(|s| format!("size {s}")).unwrap_or_else(|| "none".into());
                ui.label(format!(
                    "Signers: {}\nNewest valid seal: {newest}\nDouble-click an entry to show it. Right-click an unsigned seal to sign it.",
                    if signers.is_empty() { "none" } else { &signers }
                ));
            });
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
