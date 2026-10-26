#![allow(dead_code)]

/// The fake model endpoint of the library's unit tests, shared without building it into the library.
#[path = "../../src/companion/fake_llm.rs"]
pub mod fake_llm;

use std::path::{Path, PathBuf};
use std::process::Command;

use factum::signer::FakeSigner;
use factum::{Db, Factum};
use serde_json::Value;

/// A temporary database, a fake signer and an external seal folder (deliberately not <db dir>/seals).
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub db: Db,
    pub signer: FakeSigner,
    pub seal_dir: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_signer(FakeSigner::new(true))
    }

    pub fn with_signer(signer: FakeSigner) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("factum.db")).unwrap();
        let seal_dir = dir.path().join("external-seals");
        std::fs::create_dir(&seal_dir).unwrap();
        Self {
            dir,
            db,
            signer,
            seal_dir,
        }
    }

    /// The services wired together like the GUI does it, with the external seal folder.
    pub fn factum(&self) -> Factum<'_> {
        Factum::with_seal_dir(&self.db, &self.signer, Some(self.seal_dir.clone()))
    }

    /// With the default seal folder next to the database.
    pub fn factum_default_seals(&self) -> Factum<'_> {
        Factum::with_seal_dir(&self.db, &self.signer, None)
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn exec(&self, sql: &str) {
        self.db.conn.execute_batch(sql).unwrap();
    }

    pub fn count(&self, sql: &str) -> i64 {
        self.db.conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }
}

pub fn add_case_row(db: &Db, case_file: &str, archived: bool) -> i64 {
    db.conn
        .execute(
            "INSERT INTO cases (case_file, case_name, description, created_utc, archived_utc) VALUES (?, ?, '', ?, ?)",
            rusqlite::params![
                case_file,
                case_file,
                "2026-01-01T00:00:00.000Z",
                archived.then_some("2026-01-02T00:00:00.000Z")
            ],
        )
        .unwrap();
    db.conn.last_insert_rowid()
}

pub fn add_raw_entry(db: &Db, case_id: i64, text: &str, corrects_id: Option<i64>) -> i64 {
    let index: i64 = db
        .conn
        .query_row("SELECT COUNT(*) FROM entries WHERE case_id = ?", [case_id], |r| {
            r.get(0)
        })
        .unwrap();
    db.conn
        .execute(
            "INSERT INTO entries (case_id, leaf_index, kind, evidence_id, text, corrects_id, created_utc, leaf_hash, \
             tree_size, root_hash) VALUES (?, ?, 'note', NULL, ?, ?, '2026-01-01T00:00:00.000Z', '', ?, '')",
            rusqlite::params![case_id, index, text, corrects_id, index + 1],
        )
        .unwrap();
    db.conn.last_insert_rowid()
}

pub fn system_events(db: &Db, case_id: i64) -> Vec<Value> {
    let mut statement = db
        .conn
        .prepare("SELECT payload_json FROM entries WHERE case_id = ? AND kind = 'system' ORDER BY leaf_index")
        .unwrap();
    statement
        .query_map([case_id], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|text| serde_json::from_str(&text.unwrap()).unwrap())
        .collect()
}

/// A throwaway gpg home with an ed25519 signing key; None when gpg is not installed.
pub struct GpgHome {
    pub dir: tempfile::TempDir,
}

impl GpgHome {
    pub fn new(user_id: &str) -> Option<Self> {
        which::which("gpg").ok()?;
        // short path: gpg-agent puts its socket here and socket paths are limited to ~107 characters
        let dir = tempfile::Builder::new()
            .prefix("fg-")
            .tempdir_in("/tmp")
            .or_else(|_| tempfile::tempdir())
            .ok()?;
        let status = Command::new("gpg")
            .arg("--homedir")
            .arg(dir.path())
            .args([
                "--batch",
                "--passphrase",
                "",
                "--quick-gen-key",
                user_id,
                "ed25519",
                "sign",
                "never",
            ])
            .output()
            .ok()?;
        if !status.status.success() {
            eprintln!(
                "cannot create a gpg test key: {}",
                String::from_utf8_lossy(&status.stderr)
            );
            return None;
        }
        Some(Self { dir })
    }

    pub fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.dir.path())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

#[macro_export]
macro_rules! require_gpg {
    ($user_id:expr) => {
        match common::GpgHome::new($user_id) {
            Some(home) => home,
            None => {
                eprintln!("skipped: gpg is not installed");
                return;
            }
        }
    };
}
