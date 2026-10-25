//! Note cards, system entry rows and the small helpers they share.

use chrono::{DateTime, Utc};
use egui::{Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Sense, Stroke, UiBuilder};

use super::theme::{self, MAX_CARD_WIDTH, NOTE_SIZE, Palette, SMALL_SIZE};
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

pub const ENTRY_NUMBER_TIP: &str = "Entry number in the case log. System entries (case created, evidence added, ...) are \
                                    numbered too, so the numbers of the notes shown here can have gaps.";

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

/// Text, tone and tooltip of an entry's signature state. A ✓ only follows a successful check; until then a
/// stored signature shows as being checked.
pub fn signature_display(entry: &Entry, check: CheckView) -> (String, Tone, String) {
    if !entry.is_signed() {
        return (
            "○ Not signed".into(),
            Tone::Plain,
            "No GPG signature yet. Right-click → Sign Now, or select a key under Settings → GPG.".into(),
        );
    }
    let check = match check {
        CheckView::Pending => {
            return (
                "… Checking".into(),
                Tone::Plain,
                "The GPG signature is being checked.".into(),
            );
        }
        CheckView::Unchecked => {
            return (
                "? Not checked".into(),
                Tone::Plain,
                "GPG is not available, so the stored signature cannot be checked.".into(),
            );
        }
        CheckView::Done(check) => check,
    };
    let details = "\nRight-click → Verify for details.";
    let none = |value: &Option<String>| value.clone().unwrap_or_else(|| "None".into());
    if !check.valid {
        if check.status.contains("no public key") {
            return (
                "⚠ Key missing".into(),
                Tone::Warn,
                format!(
                    "The signing key {} is not in your keyring, so the signature cannot be checked.{details}",
                    none(&check.key_id)
                ),
            );
        }
        return (
            "✗ Invalid".into(),
            Tone::Bad,
            format!("The GPG signature is invalid ({}).{details}", check.status),
        );
    }
    if !check.covers_payload {
        return (
            "✗ Wrong data".into(),
            Tone::Bad,
            format!(
                "The signature is valid but was made over different data: the entry or the log before it was changed.{details}"
            ),
        );
    }
    if !check.trusted {
        return (
            "⚠ Untrusted key".into(),
            Tone::Warn,
            format!(
                "Valid signature by {}, but the key is not trusted ({}).{details}",
                none(&check.fingerprint),
                none(&check.trust)
            ),
        );
    }
    let who = format!(
        "\nSigned by {}.",
        check.username.clone().or(check.fingerprint.clone()).unwrap_or_default()
    );
    if check.late {
        let signed = entry
            .late_signature
            .as_ref()
            .map(|late| display_time(&late.signed_utc))
            .unwrap_or_default();
        return (
            "✓ Signed later".into(),
            Tone::Ok,
            format!(
                "GPG signature verified. It was made later, on {signed}, not when the entry was written (no signing key \
                 was active then).\nThe entry's own timestamp is protected by the case log's hash chain.{who}"
            ),
        );
    }
    (
        "✓ Verified".into(),
        Tone::Ok,
        format!("GPG signature verified: made when the entry was written.{who}"),
    )
}

/// Only the mark fits in the narrow pinned panel; the tooltip has the rest.
pub fn compact_signature(text: &str, tooltip: &str) -> (String, String) {
    let mut chars = text.chars();
    let mark = chars.next().map(String::from).unwrap_or_default();
    let rest: String = chars.skip(1).collect();
    (mark, format!("{rest}\n{tooltip}"))
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

fn signature_label(ui: &mut egui::Ui, entry: &Entry, check: CheckView, compact: bool) {
    let p = theme::current(ui.ctx());
    let (mut text, tone, mut tooltip) = signature_display(entry, check);
    if compact {
        (text, tooltip) = compact_signature(&text, &tooltip);
    }
    ui.label(RichText::new(text).size(SMALL_SIZE).color(tone.color(p)))
        .on_hover_text(tooltip);
}

fn card_menu(ui: &mut egui::Ui, card: &Card, actions: &mut Vec<CardAction>) {
    let id = card.entry.id;
    if !card.archived {
        let pin = if card.entry.is_pinned { "Unpin Note" } else { "Pin Note" };
        if ui.button(pin).clicked() {
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
            .on_disabled_hover_text("This note has no labels. Tags written in the note text cannot be removed.");
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
    /// the narrow pinned panel: only the signature mark, the pin only on hover
    pub compact: bool,
    pub focused: bool,
    pub history_open: bool,
    pub now: DateTime<Utc>,
}

/// Inner margin of log rows: notes and system entries start their text at the same x.
const ROW_MARGIN: Margin = Margin {
    left: 12,
    right: 10,
    top: 8,
    bottom: 8,
};

/// The hairline under each log row, and a bar on the left edge for the focused or pinned note.
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

/// Draws a note as a row of the log; returns the response of the row itself (for scrolling to it).
pub fn note_card(ui: &mut egui::Ui, card: &Card, view: &CardView, actions: &mut Vec<CardAction>) -> egui::Response {
    let p = *theme::current(ui.ctx());
    let entry = &card.entry;
    let id = ui.scope_id().with(("card", entry.id, view.compact));
    let hovered_before = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let bar = if view.focused {
        Some(p.accent)
    } else if entry.is_pinned && !view.compact {
        Some(p.warn)
    } else {
        None
    };
    let width = ui.available_width().min(MAX_CARD_WIDTH);
    let response = ui
        .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
            ui.set_max_width(width);
            let frame = Frame::new()
                .fill(if view.focused { p.surface } else { Color32::TRANSPARENT })
                .inner_margin(ROW_MARGIN)
                .show(ui, |ui| {
                    ui.set_width(width - ROW_MARGIN.sum().x);
                    // header: timestamp, entry id, age, version; signature and pin on the right
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.label(mono(display_time(&entry.created_utc), SMALL_SIZE, p.secondary));
                        ui.label(mono(format!("#{}", entry.id), SMALL_SIZE, p.muted))
                            .on_hover_text(ENTRY_NUMBER_TIP);
                        if !view.compact {
                            ui.label(
                                RichText::new(format!("· {}", relative_time(&entry.created_utc, view.now)))
                                    .size(SMALL_SIZE)
                                    .color(p.muted),
                            );
                        }
                        if !card.history.is_empty() {
                            chip(
                                ui,
                                &format!("corrected · v{}", card.history.len() + 1),
                                p.warn,
                                p.warn_soft,
                                Stroke::NONE,
                            );
                        }
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            signature_label(ui, entry, view.check, view.compact);
                            if !card.archived {
                                let show = hovered_before || view.focused || (entry.is_pinned && !view.compact);
                                let text = if entry.is_pinned { "Pinned" } else { "Pin" };
                                let button =
                                    egui::Button::new(RichText::new(text).size(SMALL_SIZE).color(if entry.is_pinned {
                                        p.warn
                                    } else {
                                        p.secondary
                                    }))
                                    .small();
                                let tip = if entry.is_pinned {
                                    "Unpin (P)"
                                } else {
                                    "Pin to the side panel (P)"
                                };
                                if (view.compact && !show) || (!view.compact && !show) {
                                    if !view.compact {
                                        ui.add_visible(false, button); // the header keeps its height and layout
                                    }
                                } else if ui.add(button).on_hover_text(tip).clicked() {
                                    actions.push(CardAction::TogglePin(entry.id));
                                }
                            }
                        });
                    });
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
                    if !card.history.is_empty() {
                        let count = card.history.len();
                        let label = if view.history_open {
                            "Hide history".to_string()
                        } else {
                            format!(
                                "Show history ({count} earlier version{})",
                                if count > 1 { "s" } else { "" }
                            )
                        };
                        if ui.link(RichText::new(label).size(SMALL_SIZE).color(p.accent)).clicked() {
                            actions.push(CardAction::ToggleHistory(entry.id));
                        }
                        if view.history_open {
                            Frame::new()
                                .inner_margin(Margin {
                                    left: 8,
                                    ..Margin::ZERO
                                })
                                .stroke(Stroke::NONE)
                                .show(ui, |ui| {
                                    for old in &card.history {
                                        ui.label(mono(
                                            format!("#{} · {}", old.id, display_time(&old.created_utc)),
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
                        }
                    }
                    // the evidence, only where the view does not already say it
                    if let Some(evidence) = &card.evidence {
                        ui.add(egui::Label::new(RichText::new(evidence).size(SMALL_SIZE).color(p.muted)).truncate())
                            .on_hover_text(evidence);
                    }
                });
            row_rules(ui, frame.response.rect, bar);
        })
        .response;
    let hovered = response.contains_pointer();
    ui.data_mut(|d| d.insert_temp(id, hovered));
    if hovered != hovered_before {
        ui.ctx().request_repaint();
    }
    if response.clicked() {
        actions.push(CardAction::Focus(entry.id));
    }
    response.context_menu(|ui| card_menu(ui, card, actions));
    response
}

/// A compact, greyed-out row for system entries (case created, evidence deleted, archived, ...).
pub fn system_row(ui: &mut egui::Ui, entry: &Entry, check: CheckView, actions: &mut Vec<CardAction>) -> egui::Response {
    let p = *theme::current(ui.ctx());
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
                ui.horizontal(|ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        signature_label(ui, entry, check, false);
                        let text = format!(
                            "◇ #{} · {} · {}",
                            entry.id,
                            display_time(&entry.created_utc),
                            entry.text
                        );
                        let label = ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(text).size(SMALL_SIZE).color(p.muted))
                                    .selectable(true)
                                    .wrap(),
                            )
                        });
                        label.inner.context_menu(|ui| menu(ui, actions));
                    });
                });
            });
            row_rules(ui, frame.response.rect, None);
        })
        .response;
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
