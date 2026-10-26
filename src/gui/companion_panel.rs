//! The companion's section of the side panel: the open questions of the selected case, rated with + and −.

use std::collections::HashMap;

use egui::{Align, Id, Layout, Margin, RichText};

use super::theme::{self, SMALL_SIZE};
use super::widgets::{display_time, relative_time};
use crate::companion::thread::{State, Status};
use crate::companion::{CompanionDb, Question, Rating};
use crate::error::Result;
use crate::services::Factum;

pub const GOAL_ROW: &str = "No goal set for this case. Set it…";

/// The scrolled height of the question rows in the last frame, for the side panel's height split.
const CONTENT_HEIGHT: &str = "companion-questions-height";

/// What the Questions section shows, read from the companion database on rebuild.
pub struct CompanionView {
    pub case_id: i64,
    /// open questions by position
    pub questions: Vec<Question>,
    pub goal_set: bool,
    pub enabled_for_case: bool,
    /// when the last successful pass of the case finished
    pub last_pass: Option<String>,
    /// each `rests_on` id to the newest version of its entry
    pub latest_entry: HashMap<i64, i64>,
}

impl CompanionView {
    pub fn read(factum: &Factum, cdb: &CompanionDb, case_id: i64) -> Result<Self> {
        let case = cdb.case_settings(case_id)?;
        let enabled_for_case = case.as_ref().is_none_or(|c| c.enabled);
        let questions = if enabled_for_case {
            cdb.open_questions(case_id)?
        } else {
            Vec::new()
        };
        let mut latest_entry = HashMap::new();
        for id in questions.iter().flat_map(|q| &q.rests_on) {
            latest_entry.insert(*id, factum.latest_version_id(*id)?);
        }
        let last_pass = cdb.last_ok_pass(case_id)?;
        Ok(Self {
            case_id,
            questions,
            goal_set: case.is_some_and(|c| !c.goal.trim().is_empty()),
            enabled_for_case,
            last_pass,
            latest_entry,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PanelAction {
    Jump(i64),
    Rate(i64, Rating),
    SetGoal,
    OpenHistory,
    OpenAsk,
    Rethink,
    OpenSettings,
}

/// The height the question rows took in the last frame.
pub fn content_height(ctx: &egui::Context) -> f32 {
    ctx.data(|d| d.get_temp(Id::unique(CONTENT_HEIGHT))).unwrap_or(0.0)
}

/// The header's right side: what the companion does for this case, or when it last reflected on it.
fn header_status(view: &CompanionView, status: &Status) -> String {
    match &status.state {
        State::Reflecting(case_id) if *case_id == view.case_id => return "reflecting…".into(),
        State::Unreachable => return "endpoint unreachable".into(),
        _ => {}
    }
    match status.last_pass_utc.get(&view.case_id).or(view.last_pass.as_ref()) {
        Some(utc) => format!("reflected {}", relative_time(utc, chrono::Utc::now())),
        None => status.line().trim_start_matches("companion: ").to_string(),
    }
}

/// `QUESTIONS n` with its menu, the goal row while no goal is set, and one row per open question; the rows
/// scroll within the height the caller's `ui` leaves.
pub fn questions_section(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    view: &CompanionView,
    status: &Status,
    actions: &mut Vec<PanelAction>,
) {
    let p = *theme::current(ctx);
    let section = egui::Frame::new()
        .inner_margin(Margin {
            left: 10,
            ..Margin::ZERO
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // like PINNED and IOCS: no count when there is nothing
                let heading = match view.questions.len() {
                    0 => "QUESTIONS".to_string(),
                    n => format!("QUESTIONS {n}"),
                };
                ui.label(
                    RichText::new(heading)
                        .size(SMALL_SIZE)
                        .family(theme::bold())
                        .color(p.muted)
                        .extra_letter_spacing(1.2),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.menu_button("▾", |ui| {
                        for (label, action) in [
                            ("History…", PanelAction::OpenHistory),
                            ("Ask…", PanelAction::OpenAsk),
                            ("Case goal…", PanelAction::SetGoal),
                            ("Re-think now", PanelAction::Rethink),
                            ("Settings…", PanelAction::OpenSettings),
                        ] {
                            if ui.button(label).clicked() {
                                actions.push(action);
                            }
                        }
                    })
                    .response
                    .on_hover_text("Companion");
                    ui.label(
                        RichText::new(header_status(view, status))
                            .size(SMALL_SIZE)
                            .color(p.muted),
                    );
                });
            });
            let rows = egui::ScrollArea::vertical()
                .id_salt("questions")
                .auto_shrink([false, true])
                .max_height(ui.available_height())
                .show(ui, |ui| {
                    if !view.goal_set {
                        let goal = ui.add(egui::Link::new(RichText::new(GOAL_ROW).color(p.secondary)));
                        if goal.on_hover_text("What this case has to establish").clicked() {
                            actions.push(PanelAction::SetGoal);
                        }
                        ui.add_space(6.0);
                    }
                    if view.questions.is_empty() {
                        ui.label(RichText::new("No open questions.").size(SMALL_SIZE).color(p.muted));
                    }
                    for question in &view.questions {
                        question_row(ui, view, question, actions);
                    }
                });
            let height = rows.content_size.y;
            if (height - content_height(ctx)).abs() > 0.5 {
                ctx.data_mut(|d| d.insert_temp(Id::unique(CONTENT_HEIGHT), height));
                ctx.request_repaint(); // the side panel splits its height by it
            }
        });
    let rect = section.response.rect;
    let bar = egui::Rect::from_min_size(rect.min, egui::vec2(2.0, rect.height()));
    ui.painter().rect_filled(bar, 0.0, p.accent);
}

/// A quiet, frameless rating button; a given rating is shown filled in the accent colour.
fn rate_button(ui: &mut egui::Ui, text: &str, rated: bool) -> egui::Response {
    let p = *theme::current(ui.ctx());
    let color = if rated { p.accent } else { p.muted };
    let button = egui::Button::new(RichText::new(text).size(SMALL_SIZE).color(color)).min_size(egui::vec2(16.0, 16.0));
    // fill and stroke turn the frame on: an unrated button shows one only under the pointer
    let button = if rated {
        button.fill(p.accent_soft).stroke(egui::Stroke::NONE)
    } else {
        button.frame_when_inactive(false)
    };
    let response = ui.add(button);
    if response.hovered() && !rated {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    response
}

/// The text, the entries it rests on as `#id` links, and `+` / `−` on the right.
fn question_row(ui: &mut egui::Ui, view: &CompanionView, question: &Question, actions: &mut Vec<PanelAction>) {
    let p = *theme::current(ui.ctx());
    ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
        let minus = rate_button(ui, "−", false).on_hover_text("Not useful: remove it, and ask less like it");
        if minus.clicked() {
            actions.push(PanelAction::Rate(question.id, Rating::Minus));
        }
        let rated = question.rating == Rating::Plus;
        let tip = if rated {
            "Rated useful: it is kept, and the companion asks more like it"
        } else {
            "Useful: keep it, and ask more like it"
        };
        let plus = rate_button(ui, "+", rated).on_hover_text(tip);
        if plus.clicked() && !rated {
            actions.push(PanelAction::Rate(question.id, Rating::Plus));
        }
        ui.with_layout(Layout::top_down(Align::Min), |ui| {
            ui.add(egui::Label::new(RichText::new(&question.text).color(p.text)).wrap())
                .on_hover_text(format!(
                    "{} · asked {}",
                    question.archetype.as_str(),
                    display_time(&question.created_utc)
                ));
            ui.horizontal_wrapped(|ui| {
                for id in &question.rests_on {
                    let link = ui.add(egui::Link::new(
                        RichText::new(format!("#{id}")).size(SMALL_SIZE).color(p.muted),
                    ));
                    if link.on_hover_text("Show the entry").clicked() {
                        actions.push(PanelAction::Jump(view.latest_entry.get(id).copied().unwrap_or(*id)));
                    }
                }
            });
        });
    });
    ui.add_space(6.0);
}
