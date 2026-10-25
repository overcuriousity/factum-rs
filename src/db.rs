use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{FactumError, Result};

pub const SCHEMA_VERSION: i64 = 3;

pub const SCHEMA: &str = r#"
CREATE TABLE cases(
    id INTEGER PRIMARY KEY,
    case_file TEXT NOT NULL,
    case_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_utc TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    archived_utc TEXT
);
CREATE TABLE evidence(
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    description TEXT NOT NULL,
    evidence_hash TEXT NOT NULL DEFAULT '',
    created_utc TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    deleted_utc TEXT
);
-- AUTOINCREMENT: entry ids are referenced in reports and must never be reused
CREATE TABLE entries(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    leaf_index INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('note', 'system')),
    evidence_id INTEGER REFERENCES evidence(id),
    text TEXT NOT NULL,
    payload_json TEXT,
    corrects_id INTEGER REFERENCES entries(id),
    created_utc TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    tree_size INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    signature TEXT,
    is_pinned INTEGER NOT NULL DEFAULT 0,
    format INTEGER NOT NULL DEFAULT 1,
    UNIQUE(case_id, leaf_index)
);
CREATE INDEX entries_corrects ON entries(corrects_id);
CREATE TABLE tree_heads(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES cases(id),
    case_file TEXT NOT NULL,  -- as signed: the case file number can be edited later
    tree_size INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN ('checkpoint', 'archive', 'export')),
    signature TEXT,
    file_path TEXT
);
CREATE TABLE late_signatures(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL CHECK(target IN ('entry', 'tree_head')),
    target_id INTEGER NOT NULL,
    signature TEXT NOT NULL,
    signed_utc TEXT NOT NULL,
    UNIQUE(target, target_id)
);
CREATE TABLE tags(
    id INTEGER PRIMARY KEY,
    tag_text TEXT NOT NULL UNIQUE
);
CREATE TABLE entry_tag_map(
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK(source IN ('text', 'label')),
    PRIMARY KEY(entry_id, tag_id)
);
CREATE TABLE ioc(
    id INTEGER PRIMARY KEY,
    ioc_type TEXT CHECK(ioc_type IN ('ip', 'domain', 'url', 'hash', 'email')),
    ioc_value TEXT,
    UNIQUE(ioc_type, ioc_value)
);
CREATE TABLE entry_ioc_map(
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    ioc_id INTEGER NOT NULL REFERENCES ioc(id) ON DELETE CASCADE,
    PRIMARY KEY(entry_id, ioc_id)
);
CREATE TABLE settings(
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE,
    value TEXT
);
"#;

/// The database connection. Schema-compatible with factum-notes (Python), so both can share a database.
pub struct Db {
    pub conn: Connection,
    pub path: PathBuf,
}

impl Db {
    /// Opens the database configured by FACTUM_DB or the per-user default.
    pub fn open_default() -> Result<Self> {
        Self::open(&crate::config::settings().db_path)
    }

    pub fn open(path: &Path) -> Result<Self> {
        log::debug!("Trying to connect to database at {}", path.display());
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(|e| {
            log::error!("Database connection failed: {e}");
            FactumError::from(e)
        })?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // this is needed to allow simultaneous having the gui open and doing cli operations
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        let db = Self {
            conn,
            path: path.to_path_buf(),
        };
        db.initialize_schema()?;
        db.conn.execute_batch("PRAGMA foreign_keys = ON")?;
        log::debug!("Database connection established.");
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<()> {
        let version: i64 = self.conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        let tables: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'", [], |row| {
                    row.get(0)
                })?;
        if version == 0 && tables == 0 {
            self.conn.execute_batch(&format!(
                "BEGIN;{SCHEMA}PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
            ))?;
            log::debug!("Database schema created.");
            return Ok(());
        }
        // no migrations: databases of earlier versions are not carried forward
        Err(FactumError::unsupported_database(format!(
            "This database was created by an older factum version and is not supported. Set FACTUM_DB to a new file. ({})",
            self.path.display()
        )))
    }

    /// Changes only when another connection commits, so the GUI can ignore its own writes.
    pub fn data_version(&self) -> Result<i64> {
        Ok(self.conn.query_row("PRAGMA data_version", [], |row| row.get(0))?)
    }

    /// Runs f in a transaction (like Python's `with conn:`): committed on Ok, rolled back on Err.
    pub fn transaction<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.conn.execute_batch("BEGIN")?;
        match f(&self.conn) {
            Ok(value) => {
                if let Err(e) = self.conn.execute_batch("COMMIT") {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e.into());
                }
                Ok(value)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn get_setting(&self, key: &str) -> Result<String> {
        let value: Option<Option<String>> = self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?", [key], |row| row.get(0))
            .optional()
            .inspect_err(|e| log::error!("Failed to retrieve setting for key '{key}': {e}"))?;
        match value {
            Some(value) => {
                log::debug!("Retrieved setting for key: {key}");
                Ok(value.unwrap_or_default())
            }
            None => {
                log::debug!("Setting for key '{key}' not found.");
                Ok(String::new())
            }
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.transaction(|conn| {
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .inspect_err(|e| log::error!("Failed to set setting for key '{key}': {e}"))?;
            log::debug!("Setting updated for key: {key}");
            Ok(())
        })
    }

    pub fn delete_setting(&self, key: &str) -> Result<()> {
        self.transaction(|conn| {
            conn.execute("DELETE FROM settings WHERE key = ?", [key])
                .inspect_err(|e| log::error!("Failed to delete setting for key '{key}': {e}"))?;
            log::debug!("Setting deleted for key: {key}");
            Ok(())
        })
    }
}

pub fn ensure_case_open(conn: &Connection, case_id: i64) -> Result<()> {
    let row: Option<Option<String>> = conn
        .query_row("SELECT archived_utc FROM cases WHERE id = ?", [case_id], |row| {
            row.get(0)
        })
        .optional()?;
    match row {
        None => Err(FactumError::case_not_found(format!("Case #{case_id} does not exist."))),
        Some(Some(_)) => Err(FactumError::case_archived(format!(
            "Case #{case_id} is archived. Reopen it to make changes."
        ))),
        Some(None) => Ok(()),
    }
}

pub fn ensure_entry_case_open(conn: &Connection, entry_id: i64) -> Result<i64> {
    let case_id: Option<i64> = conn
        .query_row("SELECT case_id FROM entries WHERE id = ?", [entry_id], |row| row.get(0))
        .optional()?;
    let case_id = case_id.ok_or_else(|| FactumError::general(format!("Entry #{entry_id} does not exist.")))?;
    ensure_case_open(conn, case_id)?;
    Ok(case_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    const TABLES: [&str; 10] = [
        "cases",
        "evidence",
        "entries",
        "tree_heads",
        "late_signatures",
        "tags",
        "entry_tag_map",
        "ioc",
        "entry_ioc_map",
        "settings",
    ];

    #[test]
    fn new_database_gets_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("f.db")).unwrap();
        let version: i64 = db.conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, 3);
        for table in TABLES {
            let count: i64 = db
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{table}");
        }
    }

    #[test]
    fn existing_current_database_opens_again() {
        let dir = tempfile::tempdir().unwrap();
        drop(Db::open(&dir.path().join("f.db")).unwrap());
        drop(Db::open(&dir.path().join("f.db")).unwrap());
    }

    #[test]
    fn older_versioned_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE notes(id INTEGER); PRAGMA user_version = 2;")
            .unwrap();
        drop(conn);
        let error = Db::open(&path).err().unwrap();
        assert!(error.is(ErrorKind::UnsupportedDatabase));
        assert!(error.message.contains("created by an older factum version"));
    }

    #[test]
    fn factum_1_0_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v1.db");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE notes(id INTEGER)")
            .unwrap();
        assert!(
            Db::open(&path)
                .err()
                .unwrap()
                .message
                .contains("Set FACTUM_DB to a new file")
        );
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("f.db")).unwrap();
        let on: i64 = db.conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
        assert_eq!(on, 1);
    }

    #[test]
    fn settings_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("f.db")).unwrap();
        assert_eq!(db.get_setting("x").unwrap(), "");
        db.set_setting("x", "1").unwrap();
        db.set_setting("x", "2").unwrap();
        assert_eq!(db.get_setting("x").unwrap(), "2");
        db.delete_setting("x").unwrap();
        assert_eq!(db.get_setting("x").unwrap(), "");
    }
}
