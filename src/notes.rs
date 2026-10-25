use rusqlite::{OptionalExtension, Row, ToSql, params};
use serde_json::Value;

use crate::db::ensure_entry_case_open;
use crate::error::{FactumError, Result};
use crate::log_service::{Append, KIND_NOTE};
use crate::pystr::strip;
use crate::services::Factum;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateSignature {
    pub signature: String,
    pub signed_utc: String,
}

/// One row of the case log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: i64,
    pub case_id: i64,
    pub leaf_index: i64,
    pub kind: String,
    pub evidence_id: Option<i64>,
    pub text: String,
    /// the payload_json column as stored
    pub payload_json: Option<String>,
    pub corrects_id: Option<i64>,
    pub created_utc: String,
    pub leaf_hash: String,
    pub tree_size: i64,
    pub root_hash: String,
    pub signature: Option<String>,
    pub is_pinned: bool,
    pub format: i64,
    pub late_signature: Option<LateSignature>,
}

impl Entry {
    pub const COLUMNS: &'static str = "id, case_id, leaf_index, kind, evidence_id, text, payload_json, corrects_id, \
        created_utc, leaf_hash, tree_size, root_hash, signature, is_pinned, format";

    pub fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            case_id: row.get(1)?,
            leaf_index: row.get(2)?,
            kind: row.get(3)?,
            evidence_id: row.get(4)?,
            text: row.get(5)?,
            payload_json: row.get(6)?,
            corrects_id: row.get(7)?,
            created_utc: row.get(8)?,
            leaf_hash: row.get(9)?,
            tree_size: row.get(10)?,
            root_hash: row.get(11)?,
            signature: row.get(12)?,
            is_pinned: row.get::<_, i64>(13)? != 0,
            format: row.get(14)?,
            late_signature: None,
        })
    }

    /// The parsed payload; an edited row whose JSON does not parse is kept as a string, so verification
    /// hashes it as it is and reports it.
    pub fn payload(&self) -> Value {
        parse_payload(self.payload_json.as_deref())
    }

    pub fn is_note(&self) -> bool {
        self.kind == KIND_NOTE
    }

    /// Signed at creation or later.
    pub fn is_signed(&self) -> bool {
        self.signature.as_deref().is_some_and(|s| !s.is_empty()) || self.late_signature.is_some()
    }

    /// The clearsigned block that signs this entry.
    pub fn any_signature(&self) -> Option<&str> {
        self.signature.as_deref().filter(|s| !s.is_empty()).or(self
            .late_signature
            .as_ref()
            .map(|late| late.signature.as_str()))
    }
}

/// Python's json.loads with a fallback to the raw text; an empty column is no payload.
pub fn parse_payload(payload_json: Option<&str>) -> Value {
    match payload_json {
        None | Some("") => Value::Null,
        Some(text) => {
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
        }
    }
}

/// match text literally anywhere, % and _ in the filter are not wildcards
pub fn like_substring(text: &str) -> String {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// Filters of [`Factum::list_entries`].
#[derive(Debug, Clone)]
pub struct EntryFilter<'a> {
    pub evidence_id: Option<i64>,
    pub tag: Option<&'a str>,
    /// false hides system entries
    pub include_system: bool,
    pub pinned_only: bool,
    pub search: Option<&'a str>,
}

impl Default for EntryFilter<'_> {
    /// Every entry of the case, system entries included (like the Python defaults).
    fn default() -> Self {
        Self {
            evidence_id: None,
            tag: None,
            include_system: true,
            pinned_only: false,
            search: None,
        }
    }
}

impl EntryFilter<'_> {
    /// Notes only, no system entries.
    pub fn notes() -> Self {
        Self {
            include_system: false,
            ..Default::default()
        }
    }
}

impl Factum<'_> {
    pub fn create_note(
        &self,
        note_text: &str,
        evidence_id: Option<i64>,
        case_id: i64,
    ) -> Result<i64> {
        if strip(note_text).is_empty() {
            return Err(FactumError::general("The note is empty."));
        }
        if let Some(evidence_id) = evidence_id {
            let row: Option<(i64, Option<String>)> = self
                .db
                .conn
                .query_row(
                    "SELECT case_id, deleted_utc FROM evidence WHERE id = ?",
                    [evidence_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            match row {
                Some((owner, _)) if owner != case_id => {
                    return Err(FactumError::general(format!(
                        "Evidence #{evidence_id} does not belong to case #{case_id}."
                    )));
                }
                None => {
                    return Err(FactumError::general(format!(
                        "Evidence #{evidence_id} does not belong to case #{case_id}."
                    )));
                }
                Some((_, Some(_))) => {
                    return Err(FactumError::general(format!(
                        "Evidence #{evidence_id} was deleted."
                    )));
                }
                Some((_, None)) => {}
            }
        }
        self.append(
            case_id,
            KIND_NOTE,
            note_text,
            Append {
                evidence_id,
                ..Default::default()
            },
        )
    }

    pub fn correct_note(&self, note_id: i64, new_text: &str) -> Result<i64> {
        if strip(new_text).is_empty() {
            return Err(FactumError::general("The corrected note is empty."));
        }
        let entry = match self.get_entry(note_id)? {
            Some(entry) if entry.is_note() => entry,
            _ => {
                return Err(FactumError::invalid_correction(format!(
                    "#{note_id} is not a note and cannot be corrected."
                )));
            }
        };
        // versions never branch: a correction always attaches to the newest version of the line
        let newest = self.latest_version_id(note_id)?;
        let move_pin = |conn: &rusqlite::Connection, new_id: i64| -> Result<()> {
            let pinned: i64 = conn.query_row(
                "SELECT is_pinned FROM entries WHERE id = ?",
                [newest],
                |row| row.get(0),
            )?;
            if pinned != 0 {
                conn.execute("UPDATE entries SET is_pinned = 0 WHERE id = ?", [newest])?;
                conn.execute("UPDATE entries SET is_pinned = 1 WHERE id = ?", [new_id])?;
            }
            Ok(())
        };
        self.append(
            entry.case_id,
            KIND_NOTE,
            new_text,
            Append {
                evidence_id: entry.evidence_id,
                corrects_id: Some(newest),
                on_commit: Some(&move_pin),
                ..Default::default()
            },
        )
    }

    pub fn get_entry(&self, entry_id: i64) -> Result<Option<Entry>> {
        let conn = &self.db.conn;
        let entry = conn
            .query_row(
                &format!("SELECT {} FROM entries WHERE id = ?", Entry::COLUMNS),
                [entry_id],
                Entry::from_row,
            )
            .optional()?;
        let Some(mut entry) = entry else {
            return Ok(None);
        };
        entry.late_signature = conn
            .query_row(
                "SELECT signature, signed_utc FROM late_signatures WHERE target = 'entry' AND target_id = ?",
                [entry_id],
                |row| Ok(LateSignature { signature: row.get(0)?, signed_utc: row.get(1)? }),
            )
            .optional()?;
        Ok(Some(entry))
    }

    pub fn successor_id(&self, entry_id: i64) -> Result<Option<i64>> {
        Ok(self
            .db
            .conn
            .query_row(
                "SELECT id FROM entries WHERE corrects_id = ? ORDER BY leaf_index DESC LIMIT 1",
                [entry_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn latest_version_id(&self, entry_id: i64) -> Result<i64> {
        let mut current = entry_id;
        while let Some(successor) = self.successor_id(current)? {
            current = successor;
        }
        Ok(current)
    }

    /// All versions of the entry's line, oldest first.
    pub fn history(&self, entry_id: i64) -> Result<Vec<i64>> {
        let mut first = entry_id;
        loop {
            let corrects: Option<Option<i64>> = self
                .db
                .conn
                .query_row(
                    "SELECT corrects_id FROM entries WHERE id = ?",
                    [first],
                    |row| row.get(0),
                )
                .optional()?;
            match corrects {
                Some(Some(previous)) => first = previous,
                _ => break,
            }
        }
        let mut versions = vec![first];
        while let Some(successor) = self.successor_id(*versions.last().unwrap())? {
            versions.push(successor);
        }
        Ok(versions)
    }

    /// Newest version of every line, ordered by the leaf index of the line's first version.
    ///
    /// search matches the entry text or one of its tags/labels anywhere, case-insensitively for ASCII.
    pub fn list_entries(&self, case_id: i64, filter: &EntryFilter<'_>) -> Result<Vec<i64>> {
        let mut conditions =
            vec!["NOT EXISTS (SELECT 1 FROM entries s WHERE s.corrects_id = e.id)".to_string()];
        let mut values: Vec<Box<dyn ToSql>> = vec![Box::new(case_id)];
        if let Some(evidence_id) = filter.evidence_id {
            conditions.push("e.evidence_id = ?".into());
            values.push(Box::new(evidence_id));
        }
        let tag = filter.tag.filter(|t| !t.is_empty());
        let search = filter.search.filter(|s| !s.is_empty());
        if !filter.include_system || tag.is_some() || filter.pinned_only {
            conditions.push("e.kind = 'note'".into());
        }
        if filter.pinned_only {
            conditions.push("e.is_pinned = 1".into());
        }
        if let Some(tag) = tag {
            conditions.push(
                "EXISTS (SELECT 1 FROM entry_tag_map m JOIN tags t ON t.id = m.tag_id \
                 WHERE m.entry_id = e.id AND t.tag_text LIKE ? ESCAPE '\\')"
                    .into(),
            );
            values.push(Box::new(like_substring(tag)));
        }
        if let Some(search) = search {
            conditions.push(
                "(e.text LIKE ? ESCAPE '\\' OR EXISTS (SELECT 1 FROM entry_tag_map m \
                 JOIN tags t ON t.id = m.tag_id WHERE m.entry_id = e.id AND t.tag_text LIKE ? ESCAPE '\\'))"
                    .into(),
            );
            values.push(Box::new(like_substring(search)));
            values.push(Box::new(like_substring(search)));
        }
        let sql = format!(
            "WITH RECURSIVE line(id, origin) AS (
                SELECT id, id FROM entries WHERE case_id = ? AND corrects_id IS NULL
                UNION ALL
                SELECT e.id, line.origin FROM entries e JOIN line ON e.corrects_id = line.id
            )
            SELECT e.id FROM entries e
            JOIN line ON line.id = e.id
            JOIN entries o ON o.id = line.origin
            WHERE {}
            ORDER BY o.leaf_index",
            conditions.join(" AND ")
        );
        let mut statement = self.db.conn.prepare(&sql)?;
        let refs: Vec<&dyn ToSql> = values.iter().map(|v| v.as_ref()).collect();
        let rows = statement.query_map(refs.as_slice(), |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn set_pinned(&self, entry_id: i64, pinned: bool) -> Result<()> {
        self.db.transaction(|conn| {
            ensure_entry_case_open(conn, entry_id)?;
            conn.execute(
                "UPDATE entries SET is_pinned = ? WHERE id = ? AND kind = 'note'",
                params![pinned as i64, entry_id],
            )?;
            Ok(())
        })
    }

    pub fn pin_note(&self, entry_id: i64) -> Result<()> {
        self.set_pinned(entry_id, true)
    }

    pub fn unpin_note(&self, entry_id: i64) -> Result<()> {
        self.set_pinned(entry_id, false)
    }
}
