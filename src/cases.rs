use rusqlite::{OptionalExtension, Row, params};
use serde_json::{Value, json};

use crate::canonical::utc_now;
use crate::error::{FactumError, Result};
use crate::log_service::{Append, KIND_SYSTEM};
use crate::pystr::strip;
use crate::services::Factum;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub id: i64,
    pub case_file: String,
    pub case_name: String,
    pub description: String,
    pub created_utc: String,
    pub is_active: bool,
    pub archived_utc: Option<String>,
}

impl Case {
    pub fn is_archived(&self) -> bool {
        self.archived_utc.is_some()
    }

    const COLUMNS: &'static str =
        "id, case_file, case_name, description, created_utc, is_active, archived_utc";

    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            case_file: row.get(1)?,
            case_name: row.get(2)?,
            description: row.get(3)?,
            created_utc: row.get(4)?,
            is_active: row.get::<_, i64>(5)? != 0,
            archived_utc: row.get(6)?,
        })
    }
}

/// The case fields a system entry vouches for; verification compares the cases row against the newest one.
pub fn case_payload(event: &str, case: &Case) -> Value {
    json!({"event": event, "case_id": case.id, "case_file": case.case_file, "case_name": case.case_name,
           "description": case.description, "created_utc": case.created_utc})
}

impl Factum<'_> {
    pub fn create_case(&self, case_file: &str, case_name: &str, description: &str) -> Result<i64> {
        let case_file = strip(case_file);
        if case_file.is_empty() {
            return Err(FactumError::general("A case file number is required."));
        }
        let case_name = Some(strip(case_name))
            .filter(|name| !name.is_empty())
            .unwrap_or(case_file);
        let case_id = self.db.transaction(|conn| {
            conn.execute(
                "INSERT INTO cases (case_file, case_name, description, created_utc) VALUES (?, ?, ?, ?)",
                params![case_file, case_name, description, utc_now()],
            )?;
            Ok(conn.last_insert_rowid())
        })?;
        let case = self.require_case(case_id)?;
        let appended = self.append(
            case_id,
            KIND_SYSTEM,
            &format!("Case created: {case_file} — {case_name}"),
            Append {
                payload: Some(case_payload("case_created", &case)),
                ..Default::default()
            },
        );
        if let Err(e) = appended {
            // the row has no entries yet, so removing it leaves no trace in any log
            self.db.transaction(|conn| {
                Ok(conn.execute("DELETE FROM cases WHERE id = ?", [case_id])?)
            })?;
            return Err(e);
        }
        log::debug!("Case created with ID: {case_id}");
        Ok(case_id)
    }

    pub fn get_case(&self, case_id: i64) -> Result<Option<Case>> {
        Ok(self
            .db
            .conn
            .query_row(
                &format!("SELECT {} FROM cases WHERE id = ?", Case::COLUMNS),
                [case_id],
                Case::from_row,
            )
            .optional()?)
    }

    pub fn require_case(&self, case_id: i64) -> Result<Case> {
        self.get_case(case_id)?
            .ok_or_else(|| FactumError::case_not_found(format!("Case #{case_id} does not exist.")))
    }

    pub fn list_cases(&self, include_archived: bool) -> Result<Vec<i64>> {
        let filter = if include_archived {
            ""
        } else {
            " WHERE archived_utc IS NULL"
        };
        let mut statement = self
            .db
            .conn
            .prepare(&format!("SELECT id FROM cases{filter} ORDER BY id"))?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn get_active_case_id(&self) -> Result<Option<i64>> {
        Ok(self
            .db
            .conn
            .query_row("SELECT id FROM cases WHERE is_active = 1", [], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn set_active_case(&self, case_id: i64) -> Result<bool> {
        let Some(case) = self.get_case(case_id)? else {
            log::warn!("Cannot set active case with ID {case_id} because it does not exist.");
            return Ok(false);
        };
        if case.is_archived() {
            return Err(FactumError::case_archived(format!(
                "Case #{case_id} is archived and cannot be made active."
            )));
        }
        self.db.transaction(|conn| {
            conn.execute("UPDATE cases SET is_active = (id = ?)", [case_id])?;
            // notes go to the case itself from now on; an active evidence item of any case would redirect them
            conn.execute("UPDATE evidence SET is_active = 0", [])?;
            Ok(())
        })?;
        Ok(true)
    }

    pub fn update_case(
        &self,
        case_id: i64,
        case_file: &str,
        case_name: &str,
        description: &str,
    ) -> Result<()> {
        let case = self.require_case(case_id)?;
        let case_file = strip(case_file);
        if case_file.is_empty() {
            return Err(FactumError::general("A case file number is required."));
        }
        let name = strip(case_name);
        let updated = Case {
            case_file: case_file.to_string(),
            case_name: if name.is_empty() { case_file } else { name }.to_string(),
            description: description.to_string(),
            ..case
        };
        let apply = |conn: &rusqlite::Connection, _entry_id: i64| -> Result<()> {
            conn.execute(
                "UPDATE cases SET case_file = ?, case_name = ?, description = ? WHERE id = ?",
                params![
                    updated.case_file,
                    updated.case_name,
                    updated.description,
                    case_id
                ],
            )?;
            Ok(())
        };
        self.append(
            case_id,
            KIND_SYSTEM,
            &format!(
                "Case details edited: {} — {}",
                updated.case_file, updated.case_name
            ),
            Append {
                payload: Some(case_payload("case_edited", &updated)),
                on_commit: Some(&apply),
                ..Default::default()
            },
        )?;
        Ok(())
    }

    /// Archives the case and seals it; returns the seal id.
    pub fn archive_case(&self, case_id: i64) -> Result<i64> {
        let case = self.require_case(case_id)?;
        if case.is_archived() {
            return Err(FactumError::case_archived(format!(
                "Case #{case_id} is already archived."
            )));
        }
        let archived_utc = utc_now();
        let apply = |conn: &rusqlite::Connection, _entry_id: i64| -> Result<()> {
            conn.execute(
                "UPDATE cases SET archived_utc = ?, is_active = 0 WHERE id = ?",
                params![archived_utc, case_id],
            )?;
            conn.execute(
                "UPDATE evidence SET is_active = 0 WHERE case_id = ?",
                [case_id],
            )?;
            Ok(())
        };
        self.append(
            case_id,
            KIND_SYSTEM,
            "Case archived",
            Append {
                payload: Some(json!({"event": "case_archived", "case_id": case_id, "archived_utc": archived_utc})),
                on_commit: Some(&apply),
                ..Default::default()
            },
        )?;
        self.seal(case_id, crate::seals::REASON_ARCHIVE).map_err(|e| {
            FactumError::general(format!(
                "Case archived, but the seal could not be created: {e} Use 'Seal now' once this is fixed."
            ))
        })
    }

    pub fn reopen_case(&self, case_id: i64) -> Result<()> {
        if !self.require_case(case_id)?.is_archived() {
            return Err(FactumError::general(format!(
                "Case #{case_id} is not archived."
            )));
        }
        let apply = |conn: &rusqlite::Connection, _entry_id: i64| -> Result<()> {
            conn.execute(
                "UPDATE cases SET archived_utc = NULL WHERE id = ?",
                [case_id],
            )?;
            Ok(())
        };
        self.append(
            case_id,
            KIND_SYSTEM,
            "Case reopened",
            Append {
                payload: Some(json!({"event": "case_reopened", "case_id": case_id})),
                allow_archived: true,
                on_commit: Some(&apply),
                ..Default::default()
            },
        )?;
        Ok(())
    }

    pub fn delete_case_permanently(&self, case_id: i64, typed_case_file: &str) -> Result<()> {
        let case = self.require_case(case_id)?;
        if !case.is_archived() {
            return Err(FactumError::general(
                "Only archived cases can be deleted permanently. Archive the case first.",
            ));
        }
        if typed_case_file != case.case_file {
            return Err(FactumError::confirmation(
                "The typed case file number does not match — nothing was deleted.",
            ));
        }
        let entries = "SELECT id FROM entries WHERE case_id = ?";
        self.db.transaction(|conn| {
            conn.execute(&format!("DELETE FROM entry_tag_map WHERE entry_id IN ({entries})"), [case_id])?;
            conn.execute(&format!("DELETE FROM entry_ioc_map WHERE entry_id IN ({entries})"), [case_id])?;
            conn.execute(
                &format!("DELETE FROM late_signatures WHERE target = 'entry' AND target_id IN ({entries})"),
                [case_id],
            )?;
            conn.execute(
                "DELETE FROM late_signatures WHERE target = 'tree_head' AND target_id IN \
                 (SELECT id FROM tree_heads WHERE case_id = ?)",
                [case_id],
            )?;
            conn.execute("DELETE FROM tree_heads WHERE case_id = ?", [case_id])?;
            conn.execute("DELETE FROM entries WHERE case_id = ?", [case_id])?;
            conn.execute("DELETE FROM evidence WHERE case_id = ?", [case_id])?;
            conn.execute("DELETE FROM cases WHERE id = ?", [case_id])?;
            crate::tags::remove_orphaned_tags(conn)?;
            crate::iocs::remove_orphaned_iocs(conn)?;
            Ok(())
        })?;
        log::info!("Case #{case_id} ({}) deleted permanently.", case.case_file);
        Ok(())
    }
}
