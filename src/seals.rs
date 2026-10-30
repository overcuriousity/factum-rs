//! Signed tree heads: stored in tree_heads and, as the copy that matters, written to the seal folder.

use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, Row, params};
use serde_json::{Map, Value, json};

use crate::canonical::{canonical_json, compact_utc, extract_clearsigned_text, utc_now};
use crate::config::{file_seal_dir, set_seal_dir};
use crate::db::{Cells, Db};
use crate::error::{FactumError, Result};
use crate::files::{parent_of, safe_filename_capped, write_atomically};
use crate::merkle;
use crate::notes::parse_payload;
use crate::services::Factum;

/// where the GUI kept the seal folder up to 2.7.1; read once to move it to the user config, and by the verifier
/// only to mention a folder left there (seal_dir_unused), never to use it
pub const SEAL_DIR_SETTING: &str = "seal_dir";
/// the case file number's share of a seal file name; the rest (`_<id>_size<n>_<time>.asc`) stays under 70 bytes,
/// together well below the 255 bytes most file systems allow
const SEAL_NAME_MAX_BYTES: usize = 100;
pub const REASON_CHECKPOINT: &str = "checkpoint";
pub const REASON_ARCHIVE: &str = "archive";
pub const REASON_EXPORT: &str = "export";
pub const REASONS: [&str; 3] = [REASON_CHECKPOINT, REASON_ARCHIVE, REASON_EXPORT];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    pub id: i64,
    pub case_id: i64,
    /// as signed: the case file number can be edited later
    pub case_file: String,
    pub tree_size: i64,
    pub root_hash: String,
    pub created_utc: String,
    pub reason: String,
    pub signature: Option<String>,
    pub file_path: Option<String>,
}

impl TreeHead {
    const COLUMNS: &'static str =
        "id, case_id, case_file, tree_size, root_hash, created_utc, reason, signature, file_path";

    fn read(cells: &mut Cells) -> Self {
        Self {
            id: cells.int(0),
            case_id: cells.int(1),
            case_file: cells.text(2),
            tree_size: cells.int(3),
            root_hash: cells.text(4),
            created_utc: cells.text(5),
            reason: cells.text(6),
            signature: cells.optional_text(7),
            file_path: cells.optional_text(8),
        }
    }

    fn from_row(row: &Row) -> rusqlite::Result<Self> {
        Cells::strict(row, Self::read)
    }
}

/// A seal file found in the seal folder.
#[derive(Debug, Clone)]
pub struct SealFile {
    pub path: PathBuf,
    pub payload: Map<String, Value>,
    pub payload_text: String,
    pub signature: Option<String>,
}

impl SealFile {
    pub fn tree_size(&self) -> i64 {
        self.payload["tree_size"].as_i64().unwrap_or_default()
    }

    pub fn root_hash(&self) -> &str {
        self.payload["root_hash"].as_str().unwrap_or_default()
    }

    pub fn text_field(&self, key: &str) -> Option<String> {
        self.payload.get(key).and_then(Value::as_str).map(str::to_string)
    }
}

/// What a seal's signature covers; verify.py builds the same object.
pub fn seal_payload(
    case_id: i64,
    case_file: &str,
    tree_size: i64,
    root_hash: &str,
    created_utc: &str,
    reason: &str,
) -> String {
    canonical_json(
        &json!({"case_file": case_file, "case_id": case_id, "created_utc": created_utc, "format": 1,
                           "reason": reason, "root_hash": root_hash, "tree_size": tree_size}),
    )
}

/// Next to the user config `.env`: written on the first start of a factum that keeps the seal folder there.
pub fn seal_dir_migration_marker(env_file: &Path) -> PathBuf {
    parent_of(env_file).join("seal-dir-migrated")
}

/// On the first start of a factum that keeps the seal folder in the user config `.env`, moves the folder the GUI
/// stored up to 2.7.1 in the database opened then, unless the `.env` names one already. The marker in the user
/// config records that first start, moved or not: after it no database is consulted again, so a tampered one
/// cannot plant a folder. Returns the folder that was moved.
pub fn migrate_seal_dir_setting(db: &Db, env_file: &Path) -> Result<Option<String>> {
    let marker = seal_dir_migration_marker(env_file);
    if marker.exists() {
        return Ok(None);
    }
    let failed = |e: std::io::Error| {
        FactumError::general(format!(
            "The seal folder setting could not be moved to {}: {e}",
            env_file.display()
        ))
    };
    let stored = db.get_setting(SEAL_DIR_SETTING)?;
    let moved = !stored.is_empty() && file_seal_dir(env_file).is_none();
    if moved {
        set_seal_dir(env_file, Some(&stored)).map_err(failed)?;
        log::warn!(
            "The seal folder {stored} was taken from the database {} and is now set in {}.",
            db.path.display(),
            env_file.display()
        );
    } else if !stored.is_empty() {
        log::info!(
            "The seal folder {stored} of this database is ignored: {} sets one already.",
            env_file.display()
        );
    }
    std::fs::create_dir_all(parent_of(&marker))
        .and_then(|_| {
            write_atomically(
                &marker,
                b"factum keeps the seal folder in .env (FACTUM_SEAL_DIR); seal folders in databases are not read.\n",
            )
        })
        .map_err(failed)?;
    Ok(moved.then_some(stored))
}

/// Python's Path.resolve(): absolute, with the symlinks of the existing part resolved.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut existing = absolute.clone();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.file_name().map(|n| n.to_os_string()), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent.to_path_buf();
            }
            _ => return absolute,
        }
    }
    let mut resolved = std::fs::canonicalize(&existing).unwrap_or(existing);
    for name in rest.into_iter().rev() {
        resolved.push(name);
    }
    resolved
}

/// True for integer JSON numbers (Python's isinstance(value, int)).
pub fn is_int(value: Option<&Value>) -> bool {
    value.is_some_and(|v| v.is_i64() || v.is_u64())
}

impl Factum<'_> {
    pub fn default_seal_dir(&self) -> PathBuf {
        parent_of(&self.db.path).join("seals")
    }

    /// precedence: explicit setting of this Factum, FACTUM_SEAL_DIR (environment, then user config), next to the
    /// database; never a setting stored in the database, which could point the check at an empty folder
    pub fn seal_dir(&self) -> PathBuf {
        self.seal_dir_override
            .clone()
            .or_else(|| self.env_seal_dir.clone())
            .unwrap_or_else(|| self.default_seal_dir())
    }

    pub fn seal_dir_is_default(&self) -> bool {
        resolve(&self.seal_dir()) == resolve(&self.default_seal_dir())
    }

    pub fn case_file(&self, case_id: i64) -> Result<String> {
        self.db
            .conn
            .query_row("SELECT case_file FROM cases WHERE id = ?", [case_id], |row| row.get(0))
            .optional()?
            .ok_or_else(|| FactumError::case_not_found(format!("Case #{case_id} does not exist.")))
    }

    /// Every case file number this case has had: the current one and those recorded in its log.
    pub fn known_case_files(&self, case_id: i64) -> Result<Vec<Value>> {
        // read tolerantly: the verifier gets here with whatever is in the row, and reports it
        let current = self
            .db
            .conn
            .query_row("SELECT case_file FROM cases WHERE id = ?", [case_id], |row| {
                Ok(Cells::tolerant(row, |cells| cells.text(0)).0)
            })
            .optional()?
            .ok_or_else(|| FactumError::case_not_found(format!("Case #{case_id} does not exist.")))?;
        let mut known = vec![Value::String(current)];
        let mut statement = self
            .db
            .conn
            .prepare("SELECT payload_json FROM entries WHERE case_id = ? AND kind = 'system'")?;
        // a cell that cannot be read names no case file number; the verifier reports it
        let rows = statement.query_map([case_id], |row| Ok(row.get::<_, Option<String>>(0).ok().flatten()))?;
        for row in rows {
            let payload_json = row?;
            // json.loads(payload_json or "null"); unparsable rows are skipped
            let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(payload_json.as_deref().unwrap_or("null"))
            else {
                continue;
            };
            if matches!(
                payload.get("event").and_then(Value::as_str),
                Some("case_created" | "case_edited")
            ) {
                let value = payload.get("case_file").cloned().unwrap_or(Value::Null);
                if !known.contains(&value) {
                    known.push(value);
                }
            }
        }
        Ok(known)
    }

    /// (size, root hash) of the case log as it is now.
    pub fn current_head(&self, case_id: i64) -> Result<(i64, String)> {
        let hashes: Vec<merkle::Hash> = self.leaf_hashes(case_id)?.iter().map(|h| merkle::from_hex(h)).collect();
        Ok((hashes.len() as i64, hex::encode(merkle::root(&hashes))))
    }

    pub fn seal(&self, case_id: i64, reason: &str) -> Result<i64> {
        assert!(REASONS.contains(&reason), "Unknown seal reason {reason}");
        let case_file = self.case_file(case_id)?;
        let (tree_size, root_hash) = self.current_head(case_id)?;
        let created_utc = utc_now();
        let payload = seal_payload(case_id, &case_file, tree_size, &root_hash, &created_utc, reason);
        let signature = self.sign_or_fail(&payload, "GPG signing failed — the seal was not created.")?;
        let name = format!(
            "{}_{case_id}_size{tree_size}_{}",
            safe_filename_capped(&case_file, SEAL_NAME_MAX_BYTES),
            compact_utc(&created_utc)
        );
        let folder = self.seal_dir();
        let path = folder.join(format!("{name}{}", if signature.is_some() { ".asc" } else { ".json" }));
        if !folder.is_dir() && !self.seal_dir_is_default() {
            // never create an external folder: on an unmounted medium it would end up on the local disk
            return Err(FactumError::general(format!(
                "The seal could not be written: the seal folder {} does not exist. Connect the external medium or create the folder.",
                folder.display()
            )));
        }
        let parent = parent_of(&path);
        // written byte for byte: gpg on Windows already writes CRLF
        let content = signature.clone().unwrap_or_else(|| format!("{payload}\n"));
        std::fs::create_dir_all(&parent)
            .and_then(|_| write_atomically(&path, content.as_bytes()))
            .map_err(|e| FactumError::general(format!("The seal could not be written to {}: {e}", parent.display())))?;
        let id = self.db.transaction(|conn| {
            conn.execute(
                "INSERT INTO tree_heads (case_id, case_file, tree_size, root_hash, created_utc, reason, signature, file_path) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![case_id, case_file, tree_size, root_hash, created_utc, reason, signature, path.to_string_lossy()],
            )?;
            Ok(conn.last_insert_rowid())
        })?;
        log::info!(
            "Case #{case_id} sealed at tree size {tree_size} ({reason}): {}",
            path.display()
        );
        Ok(id)
    }

    pub fn get_tree_head(&self, tree_head_id: i64) -> Result<Option<TreeHead>> {
        Ok(self
            .db
            .conn
            .query_row(
                &format!("SELECT {} FROM tree_heads WHERE id = ?", TreeHead::COLUMNS),
                [tree_head_id],
                TreeHead::from_row,
            )
            .optional()?)
    }

    pub fn list_tree_heads(&self, case_id: i64) -> Result<Vec<TreeHead>> {
        let mut statement = self.db.conn.prepare(&format!(
            "SELECT {} FROM tree_heads WHERE case_id = ? ORDER BY tree_size, id",
            TreeHead::COLUMNS
        ))?;
        let rows = statement.query_map([case_id], TreeHead::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// [`Self::list_tree_heads`] for the verifier: each seal with what could not be read of its row.
    pub(crate) fn list_tree_heads_tolerant(&self, case_id: i64) -> Result<Vec<(TreeHead, Vec<String>)>> {
        let mut statement = self.db.conn.prepare(&format!(
            "SELECT {} FROM tree_heads WHERE case_id = ? ORDER BY tree_size, id",
            TreeHead::COLUMNS
        ))?;
        let rows = statement.query_map([case_id], |row| Ok(Cells::tolerant(row, TreeHead::read)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Seal files of this case in the seal folder, matched on case id and any case file number the case has had,
    /// and the files that could not be read as a seal.
    pub fn read_seal_files(&self, case_id: i64) -> Result<SealFiles> {
        let folder = self.seal_dir();
        let case_files = self.known_case_files(case_id)?;
        let mut result = SealFiles::default();
        if !folder.is_dir() {
            return Ok(result);
        }
        let mut signed = Vec::new();
        let mut unsigned = Vec::new();
        for item in std::fs::read_dir(&folder)?.flatten() {
            let path = item.path();
            if !path.is_file() {
                continue;
            }
            match path.extension().and_then(|e| e.to_str()) {
                Some("asc") => signed.push(path),
                Some("json") => unsigned.push(path),
                _ => {}
            }
        }
        signed.sort();
        unsigned.sort();
        // an unsigned seal that was signed later has a .asc with the same name; the .json is then superseded,
        // but only by a .asc that is a valid seal of this case
        let mut superseding = Vec::new();
        let unsigned: Vec<_> = unsigned.into_iter().map(|path| (path, false)).collect();
        for (path, is_signed) in signed.into_iter().map(|path| (path, true)).chain(unsigned) {
            let stem = path.file_stem().map(|s| s.to_os_string());
            if !is_signed && superseding.contains(&stem) {
                continue;
            }
            let (text, payload_text, payload) = match parse_seal_file(&path, is_signed) {
                Ok(parsed) => parsed,
                Err(problem) => {
                    result.unreadable.push((path, problem));
                    continue;
                }
            };
            if payload.get("case_id").and_then(Value::as_i64) != Some(case_id)
                || !case_files.contains(payload.get("case_file").unwrap_or(&Value::Null))
            {
                continue;
            }
            if !is_int(payload.get("tree_size")) || !payload.get("root_hash").is_some_and(Value::is_string) {
                result
                    .unreadable
                    .push((path, "has no valid tree size or root hash".into()));
                continue;
            }
            if is_signed {
                superseding.push(stem);
            }
            result.found.push(SealFile {
                path,
                payload,
                payload_text,
                signature: is_signed.then_some(text),
            });
        }
        Ok(result)
    }
}

/// What read_seal_files found in the seal folder.
#[derive(Debug, Default)]
pub struct SealFiles {
    pub found: Vec<SealFile>,
    /// seal files that could not be read or parsed, with what is wrong ("cannot be read (…)")
    pub unreadable: Vec<(PathBuf, String)>,
}

/// (file text, signed payload text, payload) of a seal file, or what keeps it from being read as one.
fn parse_seal_file(path: &Path, is_signed: bool) -> std::result::Result<(String, String, Map<String, Value>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot be read ({e})"))?;
    let payload_text = if is_signed {
        extract_clearsigned_text(&text).ok_or("is not a clearsigned text")?
    } else {
        crate::pystr::strip(&text).to_string()
    };
    match serde_json::from_str::<Value>(&payload_text) {
        Ok(Value::Object(payload)) => Ok((text, payload_text, payload)),
        _ => Err("does not contain a seal".into()),
    }
}

/// The parsed payloads of a case's system entries, in log order (unparsable ones as strings).
pub fn system_payloads<'e>(entries: impl IntoIterator<Item = &'e crate::notes::Entry>) -> Vec<Value> {
    entries
        .into_iter()
        .filter(|e| e.kind == "system")
        .map(|e| parse_payload(e.payload_json.as_deref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_payload_is_pinned() {
        assert_eq!(
            seal_payload(1, "C-1", 2, "ab", "2026-01-01T00:00:00.000Z", "checkpoint"),
            r#"{"case_file":"C-1","case_id":1,"created_utc":"2026-01-01T00:00:00.000Z","format":1,"reason":"checkpoint","root_hash":"ab","tree_size":2}"#
        );
    }
}
