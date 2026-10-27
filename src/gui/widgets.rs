//! Note cards, system entry rows and the small helpers they share.

use chrono::{DateTime, Utc};
use egui::{Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Sense, Stroke, UiBuilder};

use super::icons;
use super::theme::{self, ICON_SIZE, MAX_CARD_WIDTH, NOTE_SIZE, Palette, SMALL_SIZE};
use crate::notes::Entry;
use crate::verifier::SignatureCheck;

/// 2026-10-05T14:03:22.417Z -> 2026-10-05 14:03:22.417 UTC
pub fn display_time(utc: &str) -> String {
    format!("{} UTC", utc.replace('T', " ").trim_end_matches('Z'))
}

/// A rough age for orientation; the UTC timestamp next to it stays the authoritative one.
pub fn relative_time(utc: &str, now: DateTime<Utc>) -> String {
    let Ok(then) = DateTime::parse_from_rfc3339(utc) else {
        return String::new();
    };
    let seconds = (now - then.with_timezone(&Utc)).num_seconds();
    if seconds < 60 {
        return "just now".into();
    }
    for (unit, size) in [("day", 86_400), ("h", 3_600), ("min", 60)] {
        if seconds >= size {
            let count = seconds / size;
            let plural = if unit == "day" && count > 1 { "s" } else { "" };
            return format!("{count} {unit}{plural} ago");
        }
    }
    unreachable!("seconds >= 60 always matches a unit")
}

pub const ENTRY_NUMBER_TIP: &str = "Entry number in the case log (system entries are numbered too)";

/// A small icon button, framed only under the pointer. `name` is its tooltip, with the shortcut if it has one, and
/// what screen readers read.
pub struct IconButton<'a> {
    icon: &'a str,
    name: &'a str,
    shortcut: Option<String>,
    color: Option<Color32>,
    selected: bool,
}

impl<'a> IconButton<'a> {
    pub fn new(icon: &'a str, name: &'a str) -> Self {
        Self {
            icon,
            name,
            shortcut: None,
            color: None,
            selected: false,
        }
    }

    pub fn shortcut(mut self, shortcut: impl Into<String>) -> Self {
        self.shortcut = Some(shortcut.into());
        self
    }

    pub fn color(mut self, color: Color32) -> Self {
        self.color = Some(color);
        self
    }

    /// A toggle that is on: drawn filled in the accent colour.
    pub fn selected(mut self, selected: bool) -> Self {
        self.selected = selected;
        self
    }

    pub fn show(self, ui: &mut egui::Ui) -> egui::Response {
        let p = *theme::current(ui.ctx());
        let color = self.color.unwrap_or(if self.selected { p.accent } else { p.secondary });
        let mut button = egui::Button::new(RichText::new(self.icon).size(ICON_SIZE).color(color))
            .min_size(egui::vec2(24.0, 22.0))
            .frame_when_inactive(self.selected);
        if self.selected {
            button = button.fill(p.accent_soft).stroke(Stroke::NONE);
        }
        let response = ui.add(button);
        let enabled = ui.is_enabled();
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, self.name));
        let tip = match &self.shortcut {
            Some(shortcut) => format!("{} ({shortcut})", self.name),
            None => self.name.to_string(),
        };
        response.on_hover_text(tip)
    }

    /// The button opening a menu below it; true while the menu is open.
    pub fn menu(self, ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) -> bool {
        let response = self.show(ui);
        egui::Popup::menu(&response).show(add_contents).is_some()
    }
}

/// What is known about the signature of an entry on screen.
#[derive(Debug, Clone, Copy)]
pub enum CheckView<'a> {
    /// the background check has not finished yet
    Pending,
    /// gpg is not available: a stored signature cannot be checked
    Unchecked,
    Done(&'a SignatureCheck),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Plain,
    Ok,
    Warn,
    Bad,
}

impl Tone {
    pub fn color(self, p: &Palette) -> Color32 {
        match self {
            Tone::Plain => p.muted,
            Tone::Ok => p.ok,
            Tone::Warn => p.warn,
            Tone::Bad => p.fail,
        }
    }
}

/// Text, tone and details of an entry's signature state. A ✓ only follows a successful check; until then a
/// stored signature shows as being checked.
pub fn signature_display(entry: &Entry, check: CheckView) -> (String, Tone, String) {
    if !entry.is_signed() {
        return ("○ Not signed".into(), Tone::Plain, String::new());
    }
    let check = match check {
        CheckView::Pending => return ("… Checking".into(), Tone::Plain, String::new()),
        CheckView::Unchecked => return ("? Not checked".into(), Tone::Plain, "GPG is not installed".into()),
        CheckView::Done(check) => check,
    };
    let none = |value: &Option<String>| value.clone().unwrap_or_else(|| "none".into());
    if !check.valid {
        if check.status.contains("no public key") {
            return (
                "⚠ Key missing".into(),
                Tone::Warn,
                format!("{} is not in the keyring", none(&check.key_id)),
            );
        }
        return ("✗ Invalid".into(), Tone::Bad, check.status.clone());
    }
    if !check.covers_payload {
        return (
            "✗ Wrong data".into(),
            Tone::Bad,
            "Signed over different data: the entry or the log before it changed".into(),
        );
    }
    if !check.trusted {
        return (
            "⚠ Untrusted key".into(),
            Tone::Warn,
            format!("{} · trust {}", none(&check.fingerprint), none(&check.trust)),
        );
    }
    let who = check.username.clone().or(check.fingerprint.clone()).unwrap_or_default();
    if check.late {
        let signed = entry
            .late_signature
            .as_ref()
            .map(|late| display_time(&late.signed_utc))
            .unwrap_or_default();
        return ("✓ Signed later".into(), Tone::Ok, format!("on {signed} · {who}"));
    }
    ("✓ Verified".into(), Tone::Ok, who)
}

/// Only the mark is shown; the tooltip says the rest.
pub fn compact_signature(text: &str, details: &str) -> (String, String) {
    let mut chars = text.chars();
    let mark = chars.next().map(String::from).unwrap_or_default();
    let rest: String = chars.skip(1).collect();
    if details.is_empty() {
        (mark, rest)
    } else {
        (mark, format!("{rest}\n{details}"))
    }
}

/// A note as shown on screen.
#[derive(Debug, Clone)]
pub struct Card {
    pub entry: Entry,
    pub tags: Vec<(String, String)>,
    /// earlier versions, oldest first
    pub history: Vec<Entry>,
    /// the evidence, when the view does not already show it
    pub evidence: Option<String>,
    pub archived: bool,
}

impl Card {
    pub fn labels(&self) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|(_, source)| source == "label")
            .map(|(tag, _)| tag.as_str())
            .collect()
    }
}

/// Something the user asked for on a card or row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardAction {
    TogglePin(i64),
    AddLabel(i64),
    RemoveLabel(i64, String),
    Correct(i64),
    CopySignature(i64),
    Sign(i64),
    Verify(i64),
    Focus(i64),
    ToggleHistory(i64),
}

fn mono(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text).font(FontId::monospace(size)).color(color)
}

fn chip(ui: &mut egui::Ui, text: &str, fg: Color32, fill: Color32, stroke: Stroke) -> egui::Response {
    Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(2))
        .inner_margin(Margin::symmetric(6, 1))
        .show(ui, |ui| ui.label(RichText::new(text).size(SMALL_SIZE).color(fg)))
        .inner
}

/// The signature mark, always on screen; the tooltip names the state.
fn signature_mark(ui: &mut egui::Ui, entry: &Entry, check: CheckView) {
    let p = theme::current(ui.ctx());
    let (text, tone, details) = signature_display(entry, check);
    let (mark, tooltip) = compact_signature(&text, &details);
    let response = ui
        .add(egui::Label::new(RichText::new(mark).size(NOTE_SIZE).color(tone.color(p))).selectable(false))
        .on_hover_text(tooltip);
    let name = text.chars().skip(2).collect::<String>();
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, &name));
}

fn card_menu(ui: &mut egui::Ui, card: &Card, actions: &mut Vec<CardAction>) {
    let id = card.entry.id;
    if !card.archived {
        let pin = if card.entry.is_pinned { "Unpin Note" } else { "Pin Note" };
        if ui.add(egui::Button::new(pin).shortcut_text("P")).clicked() {
            actions.push(CardAction::TogglePin(id));
        }
        if ui.button("Correct Note…").clicked() {
            actions.push(CardAction::Correct(id));
        }
        if ui.button("Add Label…").clicked() {
            actions.push(CardAction::AddLabel(id));
        }
        let labels = card.labels();
        ui.add_enabled_ui(!labels.is_empty(), |ui| {
            ui.menu_button("Remove Label", |ui| {
                for label in labels {
                    if ui.button(label).clicked() {
                        actions.push(CardAction::RemoveLabel(id, label.to_string()));
                    }
                }
            })
            .response
            .on_disabled_hover_text("No labels (tags in the text stay)");
        });
        ui.separator();
    }
    signature_menu(ui, &card.entry, actions);
    if ui.button("Verify Note").clicked() {
        actions.push(CardAction::Verify(id));
    }
}

fn signature_menu(ui: &mut egui::Ui, entry: &Entry, actions: &mut Vec<CardAction>) {
    if entry.is_signed() {
        if ui.button("Copy GPG Signature").clicked() {
            actions.push(CardAction::CopySignature(entry.id));
        }
    } else if ui.button("Sign Now").clicked() {
        actions.push(CardAction::Sign(entry.id));
    }
}

/// Options of [`note_card`].
pub struct CardView<'a> {
    pub check: CheckView<'a>,
    /// the narrow pinned panel: the pin only under the pointer
    pub compact: bool,
    pub focused: bool,
    pub history_open: bool,
    pub now: DateTime<Utc>,
}

/// Inner margin of log rows: notes and system entries start their timestamps at the same x.
const ROW_MARGIN: Margin = Margin {
    left: 12,
    right: 6,
    top: 8,
    bottom: 8,
};

/// The hairline under each log row, and a bar on the left edge of the focused note.
fn row_rules(ui: &egui::Ui, rect: egui::Rect, bar: Option<Color32>) {
    let p = theme::current(ui.ctx());
    ui.painter()
        .hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, p.border));
    if let Some(color) = bar {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
            0.0,
            color,
        );
    }
}

/// A header line: `right` from the right edge (signature mark, actions), then `left` in the width that is left,
/// wrapping onto a second line rather than running under the right side.
fn header_line<R>(ui: &mut egui::Ui, right: impl FnOnce(&mut egui::Ui), left: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            right(ui);
            ui.add_space(6.0);
            ui.with_layout(Layout::left_to_right(Align::Center).with_main_wrap(true), |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                left(ui)
            })
            .inner
        })
        .inner
    })
    .inner
}

/// Draws `add` in place; while hidden it keeps its space and takes no input.
pub(super) fn visible_ui(ui: &mut egui::Ui, visible: bool, add: impl FnOnce(&mut egui::Ui)) {
    let builder = if visible {
        UiBuilder::new()
    } else {
        UiBuilder::new().invisible()
    };
    ui.scope_builder(builder, add);
}

/// The full timestamp of a row in two parts, date and time: in a narrow column the time goes onto the next line
/// instead of running under the row's actions. Returns the time's response.
fn timestamp(ui: &mut egui::Ui, utc: &str, color: Color32) -> egui::Response {
    let shown = display_time(utc);
    let (date, time) = shown.split_once(' ').unwrap_or((shown.as_str(), ""));
    // the gap after a widget is the spacing set when it is added: none after the date, the usual after the time
    let spacing = std::mem::replace(&mut ui.spacing_mut().item_spacing.x, 0.0);
    ui.add(egui::Label::new(mono(format!("{date} "), SMALL_SIZE, color)).extend());
    ui.spacing_mut().item_spacing.x = spacing;
    ui.add(egui::Label::new(mono(time, SMALL_SIZE, color)).extend())
}

/// Whether a row's actions show: under the pointer (last frame), focused, or while its menu is open.
pub(super) fn actions_shown(ui: &egui::Ui, id: egui::Id) -> bool {
    ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false)
}

/// Remembers for the next frame whether the row's actions show; repaints when that changes.
pub(super) fn remember_shown(ui: &egui::Ui, id: egui::Id, shown: bool) {
    if shown != actions_shown(ui, id) {
        ui.data_mut(|d| d.insert_temp(id, shown));
        ui.ctx().request_repaint();
    }
}

/// Draws a note as a row of the log; returns the response of the row itself (for scrolling to it).
pub fn note_card(ui: &mut egui::Ui, card: &Card, view: &CardView, actions: &mut Vec<CardAction>) -> egui::Response {
    let p = *theme::current(ui.ctx());
    let entry = &card.entry;
    let id = ui.scope_id().with(("card", entry.id, view.compact));
    let shown = actions_shown(ui, id) || view.focused;
    let mut menu_open = false;
    let width = ui.available_width().min(MAX_CARD_WIDTH);
    let response = ui
        .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
            ui.set_max_width(width);
            let frame = Frame::new()
                .fill(if view.focused { p.surface } else { Color32::TRANSPARENT })
                .inner_margin(ROW_MARGIN)
                .show(ui, |ui| {
                    ui.set_width(width - ROW_MARGIN.sum().x);
                    let toggle_history = header_line(
                        ui,
                        |ui| {
                            signature_mark(ui, entry, view.check);
                            visible_ui(ui, shown, |ui| {
                                menu_open =
                                    IconButton::new(icons::MORE, "More").menu(ui, |ui| card_menu(ui, card, actions));
                            });
                            if card.archived {
                                return;
                            }
                            // the narrow pinned panel has Correct in the menu only
                            if !view.compact {
                                visible_ui(ui, shown, |ui| {
                                    if IconButton::new(icons::CORRECT, "Correct").show(ui).clicked() {
                                        actions.push(CardAction::Correct(entry.id));
                                    }
                                });
                            }
                            // a pinned note in the log keeps its pin in sight
                            let pin_shown = shown || (entry.is_pinned && !view.compact);
                            visible_ui(ui, pin_shown, |ui| {
                                let (name, color) = if entry.is_pinned {
                                    ("Unpin", p.accent)
                                } else {
                                    ("Pin", p.secondary)
                                };
                                if IconButton::new(icons::PIN, name)
                                    .shortcut("P")
                                    .color(color)
                                    .show(ui)
                                    .clicked()
                                {
                                    actions.push(CardAction::TogglePin(entry.id));
                                }
                            });
                        },
                        |ui| {
                            timestamp(ui, &entry.created_utc, p.secondary)
                                .on_hover_text(relative_time(&entry.created_utc, view.now));
                            ui.label(mono(format!("#{}", entry.id), SMALL_SIZE, p.muted))
                                .on_hover_text(ENTRY_NUMBER_TIP);
                            // the evidence, only where the view does not already say it
                            if let Some(evidence) = &card.evidence {
                                ui.add(
                                    egui::Label::new(RichText::new(evidence).size(SMALL_SIZE).color(p.secondary))
                                        .truncate(),
                                )
                                .on_hover_text(format!("Evidence: {evidence}"));
                            }
                            !card.history.is_empty() && versions_chip(ui, card, view.history_open)
                        },
                    );
                    if toggle_history {
                        actions.push(CardAction::ToggleHistory(entry.id));
                    }
                    // notes are evidence: shown as plain text, never interpreted
                    let text = ui.add(
                        egui::Label::new(RichText::new(&entry.text).size(NOTE_SIZE).color(p.text))
                            .selectable(true)
                            .wrap(),
                    );
                    text.context_menu(|ui| card_menu(ui, card, actions));
                    if text.clicked() {
                        actions.push(CardAction::Focus(entry.id));
                    }
                    // tags are signed with the note; labels look different because they are not
                    if !card.tags.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;
                            for (tag, source) in &card.tags {
                                if source == "text" {
                                    chip(ui, &format!("#{tag}"), p.tag, p.tag_soft, Stroke::NONE);
                                } else {
                                    chip(ui, tag, p.secondary, p.surface, Stroke::new(1.0, p.border))
                                        .on_hover_text("Label (not signed)");
                                }
                            }
                        });
                    }
                    if view.history_open {
                        earlier_versions(ui, card);
                    }
                });
            row_rules(ui, frame.response.rect, view.focused.then_some(p.accent));
        })
        .response;
    remember_shown(ui, id, response.contains_pointer() || menu_open);
    if response.clicked() {
        actions.push(CardAction::Focus(entry.id));
    }
    response.context_menu(|ui| card_menu(ui, card, actions));
    response
}

/// `v2` for a corrected note; true when clicked, which shows or hides the earlier versions.
fn versions_chip(ui: &mut egui::Ui, card: &Card, open: bool) -> bool {
    let p = *theme::current(ui.ctx());
    let count = card.history.len();
    let name = if open {
        "Hide earlier versions".to_string()
    } else {
        format!("Show {count} earlier version{}", if count > 1 { "s" } else { "" })
    };
    let text = RichText::new(format!("{}  v{}", icons::HISTORY, count + 1))
        .size(SMALL_SIZE)
        .color(p.secondary);
    let button = egui::Button::new(text)
        .small()
        .fill(if open { p.accent_soft } else { p.panel })
        .stroke(Stroke::NONE);
    let response = ui.add(button);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &name));
    response
        .on_hover_text(format!("Corrected · {}", name.to_lowercase()))
        .clicked()
}

/// The earlier versions of a corrected note, oldest first, set off by a rule on the left.
fn earlier_versions(ui: &mut egui::Ui, card: &Card) {
    let p = *theme::current(ui.ctx());
    ui.add_space(2.0);
    let block = Frame::new()
        .inner_margin(Margin {
            left: 10,
            top: 2,
            bottom: 2,
            ..Margin::ZERO
        })
        .show(ui, |ui| {
            for old in &card.history {
                ui.label(mono(
                    format!("{} · #{}", display_time(&old.created_utc), old.id),
                    SMALL_SIZE,
                    p.muted,
                ));
                ui.add(
                    egui::Label::new(RichText::new(&old.text).color(p.secondary))
                        .selectable(true)
                        .wrap(),
                );
            }
        });
    let rect = block.response.rect;
    ui.painter()
        .vline(rect.left() + 1.0, rect.y_range(), Stroke::new(2.0, p.border));
}

/// A quiet row for system entries (case created, evidence deleted, archived, ...), its timestamp in line with the
/// notes' timestamps.
pub fn system_row(ui: &mut egui::Ui, entry: &Entry, check: CheckView, actions: &mut Vec<CardAction>) -> egui::Response {
    let p = *theme::current(ui.ctx());
    let id = ui.scope_id().with(("system", entry.id));
    let shown = actions_shown(ui, id);
    let mut menu_open = false;
    let width = ui.available_width().min(MAX_CARD_WIDTH);
    let menu = |ui: &mut egui::Ui, actions: &mut Vec<CardAction>| {
        if ui.button("Verify Entry").clicked() {
            actions.push(CardAction::Verify(entry.id));
        }
        signature_menu(ui, entry, actions);
    };
    let response = ui
        .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
            ui.set_max_width(width);
            let margin = Margin {
                top: 4,
                bottom: 4,
                ..ROW_MARGIN
            };
            let frame = Frame::new().inner_margin(margin).show(ui, |ui| {
                ui.set_width(width - margin.sum().x);
                let text = header_line(
                    ui,
                    |ui| {
                        signature_mark(ui, entry, check);
                        visible_ui(ui, shown, |ui| {
                            menu_open = IconButton::new(icons::MORE, "More").menu(ui, |ui| menu(ui, actions));
                        });
                    },
                    |ui| {
                        timestamp(ui, &entry.created_utc, p.muted);
                        ui.label(mono(format!("#{}", entry.id), SMALL_SIZE, p.muted))
                            .on_hover_text(ENTRY_NUMBER_TIP);
                        ui.add(
                            egui::Label::new(RichText::new(&entry.text).size(SMALL_SIZE).color(p.muted))
                                .selectable(true)
                                .wrap(),
                        )
                    },
                );
                text.context_menu(|ui| menu(ui, actions));
            });
            row_rules(ui, frame.response.rect, None);
        })
        .response;
    remember_shown(ui, id, response.contains_pointer() || menu_open);
    response.context_menu(|ui| menu(ui, actions));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_time_keeps_milliseconds() {
        assert_eq!(display_time("2026-10-05T14:03:22.417Z"), "2026-10-05 14:03:22.417 UTC");
    }

    #[test]
    fn relative_times() {
        let now = DateTime::parse_from_rfc3339("2026-10-05T12:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(relative_time("2026-10-05T11:59:30.000Z", now), "just now");
        assert_eq!(relative_time("2026-10-05T11:55:00.000Z", now), "5 min ago");
        assert_eq!(relative_time("2026-10-05T09:00:00.000Z", now), "3 h ago");
        assert_eq!(relative_time("2026-10-04T11:00:00.000Z", now), "1 day ago");
        assert_eq!(relative_time("2026-10-03T12:00:00.000Z", now), "2 days ago");
        assert_eq!(relative_time("2026-10-05T12:00:05.000Z", now), "just now"); // clock skew
    }

    fn entry(signed: bool) -> Entry {
        Entry {
            id: 1,
            case_id: 1,
            leaf_index: 0,
            kind: "note".into(),
            evidence_id: None,
            text: "x".into(),
            payload_json: None,
            corrects_id: None,
            created_utc: "2026-10-05T12:00:00.000Z".into(),
            leaf_hash: String::new(),
            tree_size: 1,
            root_hash: String::new(),
            signature: signed.then(|| "SIG".to_string()),
            is_pinned: false,
            format: 1,
            late_signature: None,
        }
    }

    #[test]
    fn a_tick_only_after_a_successful_check() {
        assert_eq!(signature_display(&entry(false), CheckView::Pending).0, "○ Not signed");
        assert_eq!(signature_display(&entry(true), CheckView::Pending).0, "… Checking");
        assert_eq!(signature_display(&entry(true), CheckView::Unchecked).0, "? Not checked");
        let good = SignatureCheck {
            present: true,
            valid: true,
            covers_payload: true,
            trusted: true,
            ..Default::default()
        };
        let cases = [
            (good.clone(), "✓ Verified", Tone::Ok),
            (
                SignatureCheck {
                    late: true,
                    ..good.clone()
                },
                "✓ Signed later",
                Tone::Ok,
            ),
            (
                SignatureCheck {
                    trusted: false,
                    ..good.clone()
                },
                "⚠ Untrusted key",
                Tone::Warn,
            ),
            (
                SignatureCheck {
                    covers_payload: false,
                    ..good.clone()
                },
                "✗ Wrong data",
                Tone::Bad,
            ),
            (
                SignatureCheck {
                    valid: false,
                    status: "no public key".into(),
                    ..good.clone()
                },
                "⚠ Key missing",
                Tone::Warn,
            ),
            (
                SignatureCheck {
                    valid: false,
                    status: "signature bad".into(),
                    ..good
                },
                "✗ Invalid",
                Tone::Bad,
            ),
        ];
        for (check, text, tone) in cases {
            let (shown, shown_tone, _) = signature_display(&entry(true), CheckView::Done(&check));
            assert_eq!((shown.as_str(), shown_tone), (text, tone));
        }
        let (mark, tooltip) = compact_signature("✓ Verified", "GPG signature verified");
        assert_eq!(mark, "✓");
        assert!(tooltip.starts_with("Verified"));
    }
}
