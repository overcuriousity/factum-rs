//! The only writer of the entries table: appends a leaf to a case's Merkle tree and signs the new tree head.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::canonical::{canonical_json, utc_now};
use crate::db::ensure_case_open;
use crate::error::{FactumError, Result};
use crate::merkle;
use crate::services::Factum;

/// version of the leaf and signature formats; part of every hash, so the format can change later without guessing
pub const FORMAT: i64 = 1;
pub const MAX_ATTEMPTS: usize = 3;

pub const KIND_NOTE: &str = "note";
pub const KIND_SYSTEM: &str = "system";

/// Canonical JSON of everything a leaf hash covers; verify.py builds the same object.
#[allow(clippy::too_many_arguments)]
pub fn leaf_data(
    case_id: i64,
    leaf_index: i64,
    kind: &str,
    evidence_id: Option<i64>,
    text: &str,
    payload: &Value,
    corrects_id: Option<i64>,
    created_utc: &str,
    format: i64,
) -> String {
    canonical_json(&json!({
        "case_id": case_id, "corrects_id": corrects_id, "created_utc": created_utc, "evidence_id": evidence_id,
        "format": format, "kind": kind, "leaf_index": leaf_index, "payload": payload, "text": text,
    }))
}

/// What an entry's signature covers: its leaf and the tree head right after it was appended.
pub fn entry_signed_payload(leaf_hash: &str, tree_size: i64, root_hash: &str) -> String {
    canonical_json(
        &json!({"format": FORMAT, "leaf_hash": leaf_hash, "root_hash": root_hash, "tree_size": tree_size}),
    )
}

/// Something to do inside the append transaction, after the entry row was inserted (gets the new entry id).
pub type OnCommit<'f> = &'f dyn Fn(&Connection, i64) -> Result<()>;

/// What to append; the defaults are a note without evidence, payload or correction.
#[derive(Default)]
pub struct Append<'f> {
    pub evidence_id: Option<i64>,
    pub payload: Option<Value>,
    pub corrects_id: Option<i64>,
    pub allow_archived: bool,
    pub on_commit: Option<OnCommit<'f>>,
}

impl Factum<'_> {
    pub fn leaf_hashes(&self, case_id: i64) -> Result<Vec<String>> {
        let mut statement = self.db.conn.prepare_cached(
            "SELECT leaf_hash FROM entries WHERE case_id = ? ORDER BY leaf_index",
        )?;
        let rows = statement.query_map([case_id], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Signs a payload with the active key; None without a key, an error when a key is active but signing fails.
    pub fn sign_or_fail(&self, payload: &str, failure: &str) -> Result<Option<String>> {
        let signature = self.signer.sign_text(payload);
        if self.signer.active_key().is_some() && signature.is_none() {
            return Err(FactumError::signing(failure));
        }
        Ok(signature)
    }

    pub fn append(&self, case_id: i64, kind: &str, text: &str, options: Append<'_>) -> Result<i64> {
        let conn = &self.db.conn;
        let payload = options.payload.clone().unwrap_or(Value::Null);
        for attempt in 1..=MAX_ATTEMPTS {
            if !options.allow_archived {
                ensure_case_open(conn, case_id)?;
            }
            let hashes = self.leaf_hashes(case_id)?;
            let leaf_index = hashes.len() as i64;
            let created_utc = utc_now();
            let data = leaf_data(
                case_id,
                leaf_index,
                kind,
                options.evidence_id,
                text,
                &payload,
                options.corrects_id,
                &created_utc,
                FORMAT,
            );
            let leaf = merkle::leaf_hash(data.as_bytes());
            let mut parsed: Vec<merkle::Hash> =
                hashes.iter().map(|h| merkle::from_hex(h)).collect();
            parsed.push(leaf);
            let leaf = hex::encode(leaf);
            let root = hex::encode(merkle::root(&parsed));
            // signing may open a pinentry dialog, so it happens before the write lock is taken
            let signature = self.sign_or_fail(
                &entry_signed_payload(&leaf, leaf_index + 1, &root),
                "GPG signing failed — nothing was saved.",
            )?;
            if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
                return Err(FactumError::general(format!(
                    "The database is locked by another factum process ({e}) — nothing was saved. Try again."
                )));
            }
            let result = (|| -> Result<Option<i64>> {
                let size: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM entries WHERE case_id = ?",
                    [case_id],
                    |row| row.get(0),
                )?;
                if size != leaf_index {
                    // another process appended while we were signing: our tree head is stale
                    log::info!(
                        "Case #{case_id} log changed while signing (attempt {attempt}), retrying."
                    );
                    return Ok(None);
                }
                if !options.allow_archived {
                    ensure_case_open(conn, case_id)?;
                }
                if let Some(corrects_id) = options.corrects_id {
                    let corrected: Option<i64> = conn
                        .query_row(
                            "SELECT 1 FROM entries WHERE corrects_id = ?",
                            [corrects_id],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if corrected.is_some() {
                        return Err(FactumError::invalid_correction(format!(
                            "Entry #{corrects_id} was corrected in the meantime. Reload and try again."
                        )));
                    }
                }
                conn.execute(
                    "INSERT INTO entries (case_id, leaf_index, kind, evidence_id, text, payload_json, corrects_id, \
                     created_utc, leaf_hash, tree_size, root_hash, signature, format) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        case_id,
                        leaf_index,
                        kind,
                        options.evidence_id,
                        text,
                        options.payload.as_ref().map(canonical_json),
                        options.corrects_id,
                        created_utc,
                        leaf,
                        leaf_index + 1,
                        root,
                        signature,
                        FORMAT
                    ],
                )?;
                let entry_id = conn.last_insert_rowid();
                if kind == KIND_NOTE {
                    crate::tags::parse_tags_from_note(conn, entry_id, text)?;
                    crate::iocs::parse_ioc_from_note(conn, entry_id, text)?;
                }
                if let Some(on_commit) = options.on_commit {
                    on_commit(conn, entry_id)?;
                }
                Ok(Some(entry_id))
            })();
            match result {
                Ok(Some(entry_id)) => {
                    if let Err(e) = conn.execute_batch("COMMIT") {
                        let _ = conn.execute_batch("ROLLBACK");
                        return Err(e.into());
                    }
                    log::debug!(
                        "Entry #{entry_id} appended to case #{case_id} at leaf {leaf_index}."
                    );
                    return Ok(entry_id);
                }
                Ok(None) => {
                    conn.execute_batch("ROLLBACK")?;
                }
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            }
        }
        Err(FactumError::log_changed(
            "The case log changed while signing, nothing was saved — try again.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_data_is_pinned() {
        assert_eq!(
            leaf_data(
                1,
                0,
                "note",
                None,
                "hi",
                &Value::Null,
                None,
                "2026-01-01T00:00:00.000Z",
                1
            ),
            r#"{"case_id":1,"corrects_id":null,"created_utc":"2026-01-01T00:00:00.000Z","evidence_id":null,"format":1,"kind":"note","leaf_index":0,"payload":null,"text":"hi"}"#
        );
    }

    #[test]
    fn entry_signed_payload_is_pinned() {
        assert_eq!(
            entry_signed_payload("aa", 2, "bb"),
            r#"{"format":1,"leaf_hash":"aa","root_hash":"bb","tree_size":2}"#
        );
    }
}
