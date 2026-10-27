//! The analytical companion: derived data and model-assisted questions, kept in a database of its own.

#[cfg(feature = "gui")]
pub mod ask;
#[cfg(feature = "gui")]
pub mod enrich;
/// A fake endpoint for tests; the integration tests include the same file (`tests/common`), so it is not built into
/// the library.
#[cfg(test)]
pub mod fake_llm;
#[cfg(feature = "gui")]
pub mod llm;
pub mod presets;
pub mod prompts;
pub mod questions;
#[cfg(feature = "gui")]
pub mod reflect;
pub mod retrieval;
pub mod schedule;
pub mod store;
#[cfg(feature = "gui")]
pub mod thread;
pub mod tokens;
pub mod validate;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::db::Db;
use crate::error::Result;

pub use presets::Preset;
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

/// The newest entry id of every case in the case database that has entries.
pub fn newest_entry_by_case(db: &Db) -> Result<HashMap<i64, i64>> {
    let mut stmt = db
        .conn
        .prepare("SELECT case_id, MAX(id) FROM entries GROUP BY case_id")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The case database for the companion's own connections, read-only: the companion never writes to it.
pub fn open_case_db(path: &Path) -> Result<Db> {
    let db = Db::open(path)?;
    db.conn.execute_batch("PRAGMA query_only = ON")?;
    Ok(db)
}
