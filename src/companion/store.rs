use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{FactumError, Result};

pub const SCHEMA_VERSION: i64 = 1;

/// Case ids are the case database's ids; there are no foreign keys across the two files. The `embedding` columns are
/// reserved and never written.
pub const SCHEMA: &str = r#"
CREATE TABLE settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE case_settings(
    case_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    goal TEXT NOT NULL DEFAULT '',
    last_seen_entry_id INTEGER NOT NULL DEFAULT 0,
    last_pass_id INTEGER
);
CREATE TABLE enrichment(
    case_id INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    keywords TEXT NOT NULL DEFAULT '',
    context TEXT NOT NULL DEFAULT '',
    importance INTEGER NOT NULL DEFAULT 0,
    embedding BLOB NULL,
    created_utc TEXT NOT NULL,
    PRIMARY KEY(case_id, entry_id)
);
CREATE VIRTUAL TABLE entry_fts USING fts5(
    entry_id UNINDEXED,
    case_id UNINDEXED,
    body,
    tokenize = "unicode61 tokenchars '-_./:\'"
);
CREATE TABLE questions(
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    archetype TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open', 'answered', 'withdrawn', 'rejected')),
    rating TEXT NOT NULL DEFAULT 'none' CHECK(rating IN ('none', 'plus', 'minus')),
    created_pass_id INTEGER,
    resolved_pass_id INTEGER,
    resolved_entry_id INTEGER,
    position INTEGER NOT NULL,
    embedding BLOB NULL,
    created_utc TEXT NOT NULL,
    resolved_utc TEXT,
    UNIQUE(case_id, position)
);
CREATE TABLE question_entries(
    question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    entry_id INTEGER NOT NULL,
    PRIMARY KEY(question_id, entry_id)
);
CREATE TABLE question_events(
    id INTEGER PRIMARY KEY,
    question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('created', 'linked', 'unlinked', 'withdrawn', 'plus', 'minus', 'restored')),
    pass_id INTEGER,
    entry_id INTEGER,
    created_utc TEXT NOT NULL
);
CREATE TABLE passes(
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('diff', 'full')),
    started_utc TEXT NOT NULL,
    finished_utc TEXT,
    model TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT NOT NULL DEFAULT '',
    entries_from INTEGER NOT NULL DEFAULT 0,
    entries_to INTEGER NOT NULL DEFAULT 0,
    prompt_chars INTEGER NOT NULL DEFAULT 0,
    output_chars INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE rated_examples(
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,
    rating TEXT NOT NULL CHECK(rating IN ('plus', 'minus')),
    archetype TEXT NOT NULL DEFAULT '',
    embedding BLOB NULL,
    source_case_id INTEGER,
    source_question_id INTEGER,
    created_utc TEXT NOT NULL
);
CREATE VIRTUAL TABLE rated_fts USING fts5(example_id UNINDEXED, body);
CREATE TABLE archetype_weights(
    archetype TEXT PRIMARY KEY,
    plus_count INTEGER NOT NULL DEFAULT 0,
    minus_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX questions_case ON questions(case_id, position);
CREATE INDEX question_events_question ON question_events(question_id);
CREATE INDEX passes_case ON passes(case_id, id);
"#;

const ENV_API_KEY: &str = "FACTUM_COMPANION_API_KEY";

/// The wire protocol of the model endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    OpenAi,
    Anthropic,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::OpenAi => "openai",
            Protocol::Anthropic => "anthropic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "openai" => Some(Protocol::OpenAi),
            "anthropic" => Some(Protocol::Anthropic),
            _ => None,
        }
    }
}

/// App-level companion configuration, stored in the `settings` table.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub endpoint_url: String,
    pub protocol: Protocol,
    pub api_key: String,
    /// the key comes from FACTUM_COMPANION_API_KEY: it overrides the stored one and is never saved
    pub api_key_from_env: bool,
    pub user_agent: String,
    /// a JSON object
    pub extra_headers: String,
    pub model: String,
    /// tokens
    pub context_window: Option<u32>,
    pub global_guideline: String,
    pub enabled: bool,
}

impl Settings {
    pub fn load(db: &CompanionDb) -> Result<Self> {
        Self::load_with_env(db, std::env::var(ENV_API_KEY).ok())
    }

    fn load_with_env(db: &CompanionDb, env_key: Option<String>) -> Result<Self> {
        let env_key = env_key.map(|key| key.trim().to_string()).filter(|key| !key.is_empty());
        let enabled = db.get_setting("enabled")?;
        Ok(Self {
            endpoint_url: db.get_setting("endpoint_url")?,
            protocol: Protocol::parse(&db.get_setting("protocol")?).unwrap_or(Protocol::OpenAi),
            api_key_from_env: env_key.is_some(),
            api_key: match env_key {
                Some(key) => key,
                None => db.get_setting("api_key")?,
            },
            user_agent: db.get_setting("user_agent")?,
            extra_headers: db.get_setting("extra_headers")?,
            model: db.get_setting("model")?,
            context_window: db.get_setting("context_window")?.trim().parse().ok(),
            // Task 4 supplies prompts::DEFAULT_GUIDELINE as the default for an empty stored value
            global_guideline: db.get_setting("global_guideline")?,
            enabled: enabled.is_empty() || enabled == "1",
        })
    }

    /// Trims every string field; the key is not written while it comes from the environment.
    pub fn save(&self, db: &CompanionDb) -> Result<()> {
        db.transaction(|conn| {
            let put = |key: &str, value: &str| -> Result<()> {
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    params![key, value.trim()],
                )?;
                Ok(())
            };
            put("endpoint_url", &self.endpoint_url)?;
            put("protocol", self.protocol.as_str())?;
            if !self.api_key_from_env {
                put("api_key", &self.api_key)?;
            }
            put("user_agent", &self.user_agent)?;
            put("extra_headers", &self.extra_headers)?;
            put("model", &self.model)?;
            put("context_window", &self.context_window.map(|n| n.to_string()).unwrap_or_default())?;
            put("global_guideline", &self.global_guideline)?;
            put("enabled", if self.enabled { "1" } else { "0" })?;
            Ok(())
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.endpoint_url.trim().is_empty() && !self.model.trim().is_empty() && self.enabled
    }
}

/// Per-case companion state, stored in the `case_settings` table.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseSettings {
    pub case_id: i64,
    pub enabled: bool,
    pub goal: String,
    pub last_seen_entry_id: i64,
    pub last_pass_id: Option<i64>,
}

/// The companion database: derived data next to the case database. Deleting it loses ratings and settings, no evidence.
pub struct CompanionDb {
    pub conn: Connection,
    pub path: PathBuf,
}

impl CompanionDb {
    /// Opens the companion database that belongs to the case database at `case_db`.
    pub fn open_for(case_db: &Path) -> Result<Self> {
        Self::open(&super::companion_db_path(case_db))
    }

    pub fn open(path: &Path) -> Result<Self> {
        log::debug!("Opening companion database at {}", path.display());
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(|e| {
            log::error!("Companion database connection failed: {e}");
            FactumError::from(e)
        })?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // the GUI and the companion thread use separate connections
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        let db = Self {
            conn,
            path: path.to_path_buf(),
        };
        db.initialize_schema()?;
        db.conn.execute_batch("PRAGMA foreign_keys = ON")?;
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
            return Ok(());
        }
        // derived data: no migrations, the file can be deleted and is rebuilt from the log
        Err(FactumError::unsupported_database(format!(
            "This companion database was created by another factum version and is not supported. Delete it to start over. ({})",
            self.path.display()
        )))
    }

    /// Runs f in a transaction: committed on Ok, rolled back on Err.
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

    /// The stored value, or an empty string when the key is missing.
    pub fn get_setting(&self, key: &str) -> Result<String> {
        let value: Option<String> = self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?", [key], |row| row.get(0))
            .optional()?;
        Ok(value.unwrap_or_default())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.transaction(|conn| {
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )?;
            Ok(())
        })
    }

    pub fn case_settings(&self, case_id: i64) -> Result<Option<CaseSettings>> {
        Ok(self
            .conn
            .query_row(
                "SELECT case_id, enabled, goal, last_seen_entry_id, last_pass_id FROM case_settings WHERE case_id = ?",
                [case_id],
                |row| {
                    Ok(CaseSettings {
                        case_id: row.get(0)?,
                        enabled: row.get::<_, i64>(1)? != 0,
                        goal: row.get(2)?,
                        last_seen_entry_id: row.get(3)?,
                        last_pass_id: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// The case's settings; a case without a row gets the defaults (enabled, no goal) inserted.
    pub fn ensure_case(&self, case_id: i64) -> Result<CaseSettings> {
        self.conn
            .execute("INSERT OR IGNORE INTO case_settings (case_id) VALUES (?)", [case_id])?;
        Ok(self.case_settings(case_id)?.expect("the row was just inserted"))
    }

    pub fn set_case_enabled(&self, case_id: i64, enabled: bool) -> Result<()> {
        self.ensure_case(case_id)?;
        self.conn.execute(
            "UPDATE case_settings SET enabled = ? WHERE case_id = ?",
            params![enabled, case_id],
        )?;
        Ok(())
    }

    pub fn set_case_goal(&self, case_id: i64, goal: &str) -> Result<()> {
        self.ensure_case(case_id)?;
        self.conn.execute(
            "UPDATE case_settings SET goal = ? WHERE case_id = ?",
            params![goal.trim(), case_id],
        )?;
        Ok(())
    }

    /// Records how far a finished pass has read the log.
    pub fn set_last_seen(&self, case_id: i64, entry_id: i64, pass_id: i64) -> Result<()> {
        self.ensure_case(case_id)?;
        self.conn.execute(
            "UPDATE case_settings SET last_seen_entry_id = ?, last_pass_id = ? WHERE case_id = ?",
            params![entry_id, pass_id, case_id],
        )?;
        Ok(())
    }

    /// Removes every companion row of the case (permanent deletion of the case).
    pub fn delete_case(&self, case_id: i64) -> Result<()> {
        self.transaction(|conn| {
            for sql in [
                "DELETE FROM question_events WHERE question_id IN (SELECT id FROM questions WHERE case_id = ?1)",
                "DELETE FROM question_entries WHERE question_id IN (SELECT id FROM questions WHERE case_id = ?1)",
                "DELETE FROM questions WHERE case_id = ?1",
                "DELETE FROM passes WHERE case_id = ?1",
                "DELETE FROM enrichment WHERE case_id = ?1",
                "DELETE FROM entry_fts WHERE case_id = ?1",
                "DELETE FROM case_settings WHERE case_id = ?1",
            ] {
                conn.execute(sql, [case_id])?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::companion::companion_db_path;

    fn temp_db() -> (tempfile::TempDir, CompanionDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = CompanionDb::open(&dir.path().join("f.companion.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn path_is_next_to_case_db() {
        assert_eq!(
            companion_db_path(Path::new("/x/y.db")),
            PathBuf::from("/x/y.companion.db")
        );
        assert_eq!(
            companion_db_path(Path::new("/x/cases")),
            PathBuf::from("/x/cases.companion.db")
        );
    }

    #[test]
    fn new_database_has_schema_and_fts() {
        let (_dir, db) = temp_db();
        let v: i64 = db.conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        db.conn
            .execute(
                "INSERT INTO entry_fts(entry_id, case_id, body) VALUES (1, 1, 'a/b/c.php md5 d41d8cd9')",
                [],
            )
            .unwrap();
        let n: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM entry_fts WHERE entry_fts MATCH '\"a/b/c.php\"'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "paths are single tokens");
    }

    #[test]
    fn settings_round_trip_trims_and_defaults() {
        let (_dir, db) = temp_db();
        let s = Settings::load(&db).unwrap();
        assert_eq!(s.protocol, Protocol::OpenAi);
        assert!(s.enabled);
        assert!(!s.is_configured());
        let mut s2 = s.clone();
        s2.endpoint_url = " http://h:8080/v1 \n".into();
        s2.model = "m".into();
        s2.api_key = "k\n".into();
        s2.save(&db).unwrap();
        let back = Settings::load(&db).unwrap();
        assert_eq!(back.endpoint_url, "http://h:8080/v1");
        assert_eq!(back.api_key, "k");
        assert!(back.is_configured());
    }

    #[test]
    fn env_key_overrides_stored_key() {
        let (_dir, db) = temp_db();
        let mut s = Settings::load(&db).unwrap();
        s.api_key = "stored".into();
        s.save(&db).unwrap();
        // load_with_env takes the variable's value, so no test has to touch the process environment
        let from_env = Settings::load_with_env(&db, Some("from-env\n".into())).unwrap();
        assert!(from_env.api_key_from_env);
        assert_eq!(from_env.api_key, "from-env");
        from_env.save(&db).unwrap();
        let back = Settings::load_with_env(&db, None).unwrap();
        assert!(!back.api_key_from_env);
        assert_eq!(back.api_key, "stored");
    }

    #[test]
    fn case_settings_lifecycle() {
        let (_dir, db) = temp_db();
        assert_eq!(db.case_settings(7).unwrap(), None);
        let c = db.ensure_case(7).unwrap();
        assert!(c.enabled && c.goal.is_empty() && c.last_seen_entry_id == 0);
        db.set_case_goal(7, "find the shell").unwrap();
        db.set_case_enabled(7, false).unwrap();
        assert_eq!(db.case_settings(7).unwrap().unwrap().goal, "find the shell");
        db.delete_case(7).unwrap();
        assert_eq!(db.case_settings(7).unwrap(), None);
    }

    #[test]
    fn busy_timeout_is_set() {
        let (_dir, db) = temp_db();
        let ms: i64 = db.conn.query_row("PRAGMA busy_timeout", [], |r| r.get(0)).unwrap();
        assert_eq!(ms, 5000);
    }
}
