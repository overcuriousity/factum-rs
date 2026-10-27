//! Completing a #tag in the note field from the tags and labels in use: a short list above the line, ↑ ↓ to
//! choose, Tab or a click to take one, Escape to close it until the typed part changes.

use egui::text::{CCursor, CCursorRange, CharIndex};
use egui::{Event, EventFilter, Id, Key, LayerId, Order, SurrenderFocusOn, TextEdit, Ui};

use super::dialogs::{suggestion_list, suggestions_shown};
use crate::db::Db;

const LIMIT: usize = 6;
const LIST_WIDTH: f32 = 260.0;

#[derive(Default)]
pub struct TagCompletion {
    /// the tags and labels in use that can be written as a #tag; loaded when a #tag is begun
    known: Option<Vec<(String, usize)>>,
    /// the list was shown in the last frame, so it takes the keys in this one
    open: bool,
    selected: usize,
    /// the typed part the selection belongs to; typing on starts from the top again
    selected_for: String,
    /// the typed part the list was closed for (Escape, or just completed); it stays closed until that changes
    dismissed: Option<String>,
}

/// Keys pressed while the list is open, taken before the note field sees them.
#[derive(Default)]
struct Keys {
    down: usize,
    up: usize,
    accept: bool,
    dismiss: bool,
}

/// Takes the presses of `key` without modifiers (Shift+↓ still selects text), returns how many there were.
fn take_key(ui: &Ui, key: Key) -> usize {
    ui.input_mut(|input| {
        let before = input.events.len();
        input.events.retain(|event| {
            !matches!(event, Event::Key { key: pressed, pressed: true, modifiers, .. }
                if *pressed == key && modifiers.is_none())
        });
        before - input.events.len()
    })
}

impl TagCompletion {
    /// Shows `field` (the note field, with id `id`) and the list for the #tag before the cursor.
    pub fn show(&mut self, ui: &mut Ui, db: &Db, field: TextEdit<'_>, id: Id) -> egui::Response {
        let mut keys = Keys::default();
        if self.open && ui.memory(|m| m.has_focus(id)) {
            keys.down = take_key(ui, Key::ArrowDown);
            keys.up = take_key(ui, Key::ArrowUp);
            keys.accept = take_key(ui, Key::Tab) > 0;
            keys.dismiss = take_key(ui, Key::Escape) > 0;
        }
        // a click on the list must not take the focus from the field
        let list_id = id.with("tag-list");
        let on_list = self.open
            && ui
                .ctx()
                .pointer_interact_pos()
                .and_then(|pos| ui.ctx().layer_id_at(pos))
                == Some(LayerId::new(Order::Foreground, list_id));
        let surrender = ui.ctx().options(|o| o.input_options.surrender_focus_on);
        if on_list {
            ui.ctx()
                .options_mut(|o| o.input_options.surrender_focus_on = SurrenderFocusOn::Never);
        }
        let (output, text) = field.id(id).show_returning_text(ui);
        if on_list {
            ui.ctx().options_mut(|o| o.input_options.surrender_focus_on = surrender);
        }
        let response = output.response.response.clone();

        let cursor = output.cursor_range.map(|range| range.primary.index.0);
        let typed_range = cursor
            .filter(|_| response.has_focus())
            .and_then(|cursor| crate::tags::tag_before(text.as_str(), cursor));
        let Some(range) = typed_range else {
            self.known = None;
            self.open = false;
            self.dismissed = None;
            return response;
        };
        let typed: String = text.as_str().chars().skip(range.start).take(range.len()).collect();
        if keys.dismiss {
            self.dismissed = Some(typed.clone());
        }
        if self.dismissed.as_ref().is_some_and(|d| *d != typed) {
            self.dismissed = None;
        }
        if self.selected_for != typed {
            self.selected = 0;
            self.selected_for = typed.clone();
        }
        let known = self.known.get_or_insert_with(|| {
            crate::tags::tag_counts(&db.conn)
                .inspect_err(|e| log::error!("Failed to load the tags in use: {e}"))
                .unwrap_or_default()
                .into_iter()
                .filter(|(name, _)| crate::tags::is_tag_name(name))
                .collect()
        });
        let suggestions = crate::tags::suggest(&typed, known, LIMIT);
        self.open = self.dismissed.is_none() && suggestions_shown(&suggestions);
        if !self.open {
            return response;
        }
        self.selected = (self.selected + keys.down)
            .saturating_sub(keys.up)
            .min(suggestions.len() - 1);
        let mut chosen = keys.accept.then(|| suggestions[self.selected].0.to_string());
        if chosen.is_none() {
            // above the line, starting at the #
            let hash = output.galley.pos_from_cursor(CCursor::new(CharIndex(range.start - 1)));
            let anchor = output.galley_pos + hash.min.to_vec2();
            chosen = egui::Area::new(list_id)
                .order(Order::Foreground)
                .fixed_pos(anchor)
                .pivot(egui::Align2::LEFT_BOTTOM)
                .show(ui.ctx(), |ui| {
                    ui.set_width(LIST_WIDTH);
                    suggestion_list(ui, &typed, &suggestions, Some(self.selected))
                })
                .inner;
        }
        if let Some(name) = chosen {
            let mut completed = text.as_str().to_string();
            let cursor = crate::tags::complete_tag(&mut completed, range, &name);
            text.replace_with(&completed);
            let mut state = egui::TextEdit::load_state(ui.ctx(), id).unwrap_or_default();
            state
                .cursor
                .set_char_range(Some(CCursorRange::one(CCursor::new(CharIndex(cursor)))));
            state.store(ui.ctx(), id);
            self.dismissed = Some(name);
            self.open = false;
            response.request_focus();
        }
        // while the list is open, Tab and Escape stay in the field (from the next frame on)
        if self.open {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    id,
                    EventFilter {
                        tab: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: true,
                    },
                )
            });
        }
        response
    }
}
