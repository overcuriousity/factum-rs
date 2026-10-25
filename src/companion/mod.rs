//! The analytical companion: derived data and model-assisted questions, kept in a database of its own.

pub mod prompts;
pub mod questions;
pub mod retrieval;
pub mod store;
pub mod tokens;

use std::path::{Path, PathBuf};

pub use questions::{Archetype, NewQuestion, PassKind, Question, QuestionEvent, QuestionState, RatedExample, Rating};
pub use store::{CaseSettings, CompanionDb, Protocol, Settings};

/// The companion database lives next to the case database: `/x/y.db` becomes `/x/y.companion.db`.
pub fn companion_db_path(case_db: &Path) -> PathBuf {
    let text = case_db.as_os_str().to_string_lossy();
    match text.strip_suffix(".db") {
        Some(stem) => PathBuf::from(format!("{stem}.companion.db")),
        None => PathBuf::from(format!("{text}.companion.db")),
    }
}
