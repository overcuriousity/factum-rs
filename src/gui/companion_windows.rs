//! The companion's windows: the history of a case's resolved questions, and Ask. Both are read-only views; what
//! they change goes back to the app as a [`WindowAction`].

use egui::{Id, Key, RichText, TextEdit};

use super::theme::{self, SMALL_SIZE};
use super::widgets::display_time;
use crate::companion::ask::Answer;
use crate::companion::{Question, QuestionState, Rating};

pub enum CompanionWindow {
    History {
        case_id: i64,
        /// the case's non-open questions, newest first
        rows: Vec<Question>,
        open: bool,
    },
    Ask {
        case_id: i64,
        question: String,
        answer: Option<Answer>,
        error: Option<String>,
        running: bool,
        open: bool,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum WindowAction {
    Jump(i64),
    Unlink(i64),
    Restore(i64),
    Ask { case_id: i64, question: String },
    CopyAnswer(String),
}

impl CompanionWindow {
    pub fn is_open(&self) -> bool {
        match self {
            CompanionWindow::History { open, .. } | CompanionWindow::Ask { open, .. } => *open,
        }
    }

    pub fn show(&mut self, ctx: &egui::Context, actions: &mut Vec<WindowAction>) {
        match self {
            CompanionWindow::History { case_id, rows, open } => history(ctx, *case_id, rows, open, actions),
            CompanionWindow::Ask {
                case_id,
                question,
                answer,
                error,
                running,
                open,
            } => {
                egui::Window::new("Ask the companion")
                    .id(Id::unique(("companion-ask", *case_id)))
                    .open(open)
                    .default_size([560.0, 360.0])
                    .resizable(true)
                    .show(ctx, |ui| {
                        ask_body(
                            ui,
                            *case_id,
                            question,
                            answer.as_ref(),
                            error.as_deref(),
                            *running,
                            actions,
                        )
                    });
            }
        }
    }
}

fn history(ctx: &egui::Context, case_id: i64, rows: &[Question], open: &mut bool, actions: &mut Vec<WindowAction>) {
    let p = *theme::current(ctx);
    egui::Window::new("Companion history")
        .id(Id::unique(("companion-history", case_id)))
        .open(open)
        .default_size([560.0, 420.0])
        .resizable(true)
        .show(ctx, |ui| {
            if rows.is_empty() {
                ui.label(RichText::new("No resolved questions.").color(p.muted));
            }
            egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
                for question in rows {
                    ui.add(egui::Label::new(RichText::new(&question.text).color(p.text)).wrap());
                    ui.horizontal_wrapped(|ui| {
                        let rating = match question.rating {
                            Rating::None => "unrated",
                            Rating::Plus => "rated +",
                            Rating::Minus => "rated −",
                        };
                        let when = question.resolved_utc.as_deref().map(display_time).unwrap_or_default();
                        ui.label(
                            RichText::new(format!("{} · {rating} · {when}", question.state.as_str()))
                                .size(SMALL_SIZE)
                                .color(p.muted),
                        );
                        match question.state {
                            QuestionState::Answered => {
                                if let Some(entry_id) = question.resolved_entry_id {
                                    let link = ui.add(egui::Link::new(
                                        RichText::new(format!("#{entry_id}")).size(SMALL_SIZE).color(p.muted),
                                    ));
                                    if link.on_hover_text("Show the answering entry").clicked() {
                                        actions.push(WindowAction::Jump(entry_id));
                                    }
                                }
                                let unlink = ui.small_button("Unlink").on_hover_text("Not answered: open it again");
                                if unlink.clicked() {
                                    actions.push(WindowAction::Unlink(question.id));
                                }
                            }
                            QuestionState::Withdrawn | QuestionState::Rejected => {
                                if ui.small_button("Restore").on_hover_text("Open it again").clicked() {
                                    actions.push(WindowAction::Restore(question.id));
                                }
                            }
                            QuestionState::Open => {}
                        }
                    });
                    ui.add_space(6.0);
                }
            });
        });
}

/// The question field and Ask button, then the answer with its references as entry links.
fn ask_body(
    ui: &mut egui::Ui,
    case_id: i64,
    question: &mut String,
    answer: Option<&Answer>,
    error: Option<&str>,
    running: bool,
    actions: &mut Vec<WindowAction>,
) {
    let p = *theme::current(ui.ctx());
    let label = ui.label("Question");
    let field = ui
        .add(
            TextEdit::singleline(question)
                .hint_text("Ask about this case's log")
                .desired_width(f32::INFINITY),
        )
        .labelled_by(label.id);
    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
    let ready = !running && !question.trim().is_empty();
    let button = ui.add_enabled(ready, egui::Button::new(if running { "asking…" } else { "Ask" }));
    if ready && (button.clicked() || enter) {
        actions.push(WindowAction::Ask {
            case_id,
            question: question.trim().to_string(),
        });
    }
    if let Some(error) = error {
        ui.add_space(8.0);
        ui.add(egui::Label::new(RichText::new(error).color(p.fail)).wrap());
    }
    let Some(answer) = answer else { return };
    ui.add_space(8.0);
    ui.separator();
    egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
        ui.add(
            egui::Label::new(RichText::new(&answer.text).color(p.text))
                .wrap()
                .selectable(true),
        );
        if !answer.references.is_empty() {
            ui.horizontal_wrapped(|ui| {
                for (n, entry_id) in &answer.references {
                    let link = ui.add(egui::Link::new(
                        RichText::new(format!("[{n}] #{entry_id}"))
                            .size(SMALL_SIZE)
                            .color(p.secondary),
                    ));
                    if link.on_hover_text("Show the entry").clicked() {
                        actions.push(WindowAction::Jump(*entry_id));
                    }
                }
            });
        }
        if !answer.unsupported.is_empty() {
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "not found in the cited entries: {}",
                        answer.unsupported.join(", ")
                    ))
                    .size(SMALL_SIZE)
                    .color(p.muted),
                )
                .wrap(),
            );
        }
        ui.add_space(6.0);
        if ui.button("Copy").clicked() {
            actions.push(WindowAction::CopyAnswer(answer.text.clone()));
        }
    });
}
