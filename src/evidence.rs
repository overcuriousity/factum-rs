use rusqlite::{OptionalExtension, Row, params};
use serde_json::json;

use crate::canonical::utc_now;
use crate::db::ensure_case_open;
use crate::error::{FactumError, Result};
use crate::log_service::{Append, KIND_SYSTEM};
use crate::pystr::strip;
use crate::services::Factum;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: i64,
    pub case_id: i64,
    /// the evidence name (the column keeps its historical name)
    pub description: String,
    pub evidence_hash: String,
    pub created_utc: String,
    pub is_active: bool,
    pub deleted_utc: Option<String>,
    /// the free-text description, editable through a logged entry
    pub details: String,
}

impl Evidence {
    pub fn is_deleted(&self) -> bool {
        self.deleted_utc.is_some()
    }

    pub const COLUMNS: &'static str =
        "id, case_id, description, evidence_hash, created_utc, is_active, deleted_utc, details";

    pub fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            case_id: row.get(1)?,
            description: row.get(2)?,
            evidence_hash: row.get(3)?,
            created_utc: row.get(4)?,
            is_active: row.get::<_, i64>(5)? != 0,
            deleted_utc: row.get(6)?,
            details: row.get(7)?,
        })
    }
}

// intentionally no update_evidence method, as evidence should be immutable after creation
impl Factum<'_> {
    pub fn create_evidence(&self, case_id: i64, description: &str, evidence_hash: &str) -> Result<i64> {
        let (description, evidence_hash) = (strip(description), strip(evidence_hash));
        if description.is_empty() {
            return Err(FactumError::general("An evidence description is required."));
        }
        ensure_case_open(&self.db.conn, case_id)?;
        let created_utc = utc_now();
        let evidence_id = self.db.transaction(|conn| {
            conn.execute(
                "INSERT INTO evidence (case_id, description, evidence_hash, created_utc) VALUES (?, ?, ?, ?)",
                params![case_id, description, evidence_hash, created_utc],
            )?;
            Ok(conn.last_insert_rowid())
        })?;
        let payload = json!({"event": "evidence_created", "evidence_id": evidence_id, "case_id": case_id,
                             "description": description, "evidence_hash": evidence_hash, "created_utc": created_utc});
        let mut text = format!("Evidence #{evidence_id} created: {description}");
        if !evidence_hash.is_empty() {
            text += &format!(" · {evidence_hash}");
        }
        if let Err(e) = self.append(
            case_id,
            KIND_SYSTEM,
            &text,
            Append {
                payload: Some(payload),
                ..Default::default()
            },
        ) {
            self.db
                .transaction(|conn| Ok(conn.execute("DELETE FROM evidence WHERE id = ?", [evidence_id])?))?;
            return Err(e);
        }
        Ok(evidence_id)
    }

    pub fn get_evidence(&self, evidence_id: i64) -> Result<Option<Evidence>> {
        Ok(self
            .db
            .conn
            .query_row(
                &format!("SELECT {} FROM evidence WHERE id = ?", Evidence::COLUMNS),
                [evidence_id],
                Evidence::from_row,
            )
            .optional()?)
    }

    pub fn get_active_evidence_id(&self) -> Result<Option<i64>> {
        Ok(self
            .db
            .conn
            .query_row("SELECT id FROM evidence WHERE is_active = 1", [], |row| row.get(0))
            .optional()?)
    }

    /// Makes evidence (and its case) the CLI target; None clears the active evidence.
    pub fn set_active_evidence(&self, evidence_id: Option<i64>) -> Result<bool> {
        let mut evidence = None;
        if let Some(id) = evidence_id {
            // check before touching anything, so a failed call keeps the current active evidence
            match self.get_evidence(id)? {
                Some(found) if !found.is_deleted() => {
                    ensure_case_open(&self.db.conn, found.case_id)?;
                    evidence = Some(found);
                }
                _ => {
                    log::warn!("Cannot set active evidence with ID {id}: it does not exist.");
                    return Ok(false);
                }
            }
        }
        self.db.transaction(|conn| {
            conn.execute("UPDATE evidence SET is_active = 0", [])?;
            if let Some(evidence) = &evidence {
                conn.execute("UPDATE evidence SET is_active = 1 WHERE id = ?", [evidence.id])?;
                // the active case must always be the parent of the active evidence
                conn.execute("UPDATE cases SET is_active = (id = ?)", [evidence.case_id])?;
            }
            Ok(())
        })?;
        Ok(true)
    }

    pub fn list_evidence_for_case(&self, case_id: i64, include_deleted: bool) -> Result<Vec<i64>> {
        let filter = if include_deleted {
            ""
        } else {
            " AND deleted_utc IS NULL"
        };
        let mut statement = self.db.conn.prepare(&format!(
            "SELECT id FROM evidence WHERE case_id = ?{filter} ORDER BY id"
        ))?;
        let rows = statement.query_map([case_id], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn has_entries(&self, evidence_id: i64) -> Result<bool> {
        Ok(self
            .db
            .conn
            .query_row(
                "SELECT 1 FROM entries WHERE evidence_id = ? LIMIT 1",
                [evidence_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    pub fn delete_evidence(&self, evidence_id: i64) -> Result<()> {
        let evidence = match self.get_evidence(evidence_id)? {
            Some(evidence) if !evidence.is_deleted() => evidence,
            _ => {
                return Err(FactumError::general(format!("Evidence #{evidence_id} does not exist.")));
            }
        };
        let not_empty =
            || FactumError::evidence_not_empty(format!("Evidence #{evidence_id} has notes and cannot be deleted."));
        if self.has_entries(evidence_id)? {
            return Err(not_empty());
        }
        let deleted_utc = utc_now();
        let apply = |conn: &rusqlite::Connection, _entry_id: i64| -> Result<()> {
            // checked again inside the transaction: a note may have been added meanwhile
            let used: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM entries WHERE evidence_id = ? LIMIT 1",
                    [evidence_id],
                    |row| row.get(0),
                )
                .optional()?;
            if used.is_some() {
                return Err(not_empty());
            }
            conn.execute(
                "UPDATE evidence SET deleted_utc = ?, is_active = 0 WHERE id = ?",
                params![deleted_utc, evidence_id],
            )?;
            Ok(())
        };
        self.append(
            evidence.case_id,
            KIND_SYSTEM,
            &format!("Evidence #{evidence_id} deleted: {}", evidence.description),
            Append {
                payload: Some(
                    json!({"event": "evidence_deleted", "evidence_id": evidence_id, "deleted_utc": deleted_utc}),
                ),
                on_commit: Some(&apply),
                ..Default::default()
            },
        )?;
        Ok(())
    }
}
