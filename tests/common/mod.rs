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
        Self::with_key(user_id, "sign", "never")
    }

    /// With a key of these capabilities and this expiry.
    pub fn with_key(user_id: &str, usage: &str, expiry: &str) -> Option<Self> {
        Self::at_time(None, user_id, usage, expiry)
    }

    /// `with_key` on a clock set to `time` (YYYYMMDDTHHMMSS) for everything in this home, until `set_clock`.
    pub fn at_time(time: Option<&str>, user_id: &str, usage: &str, expiry: &str) -> Option<Self> {
        which::which("gpg").ok()?;
        // short path: gpg-agent puts its socket here and socket paths are limited to ~107 characters
        let dir = tempfile::Builder::new()
            .prefix("fg-")
            .tempdir_in("/tmp")
            .or_else(|_| tempfile::tempdir())
            .ok()?;
        let home = Self { dir };
        home.set_clock(time);
        let output = home.gpg(&[
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            user_id,
            "ed25519",
            usage,
            expiry,
        ]);
        if !output.status.success() {
            eprintln!(
                "cannot create a gpg test key: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }
        Some(home)
    }

    pub fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    /// Sets the clock of every gpg run in this home; None is the real time.
    pub fn set_clock(&self, time: Option<&str>) {
        let config = self.dir.path().join("gpg.conf");
        match time {
            Some(time) => std::fs::write(config, format!("faked-system-time {time}\n")).unwrap(),
            None => drop(std::fs::remove_file(config)),
        }
    }

    pub fn gpg(&self, args: &[&str]) -> std::process::Output {
        Command::new("gpg")
            .arg("--homedir")
            .arg(self.dir.path())
            .args(args)
            .output()
            .unwrap()
    }

    /// Adds a key or subkey, or whatever else `args` say, and insists that it worked.
    pub fn gpg_ok(&self, args: &[&str]) -> std::process::Output {
        let output = self.gpg(args);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        output
    }

    /// The fingerprints of the key of this user ID: the primary key's first, then its subkeys'.
    pub fn fingerprints(&self, user_id: &str) -> Vec<String> {
        let listing = self.gpg_ok(&["--list-keys", "--with-colons", "--fixed-list-mode", user_id]);
        String::from_utf8_lossy(&listing.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("fpr:::::::::"))
            .map(|line| line.trim_end_matches(':').to_string())
            .collect()
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

/// A throwaway gpgsm home with a root CA (made with openssl) and a signing certificate under it; None when gpgsm
/// or openssl is missing. The root is not trusted until `trusted()`.
pub struct GpgsmHome {
    pub dir: tempfile::TempDir,
    /// root.pem, root.key, leaf.pem live here
    pub files: tempfile::TempDir,
    pub leaf_fingerprint: String,
    pub root_fingerprint: String,
}

impl GpgsmHome {
    pub fn new() -> Option<Self> {
        Self::build(false)
    }

    /// With a leaf that expired yesterday, under a root that was valid before it; `sign_while_valid` signs with it.
    /// None also where openssl has no `-not_before` (before 3.4).
    pub fn with_expired_leaf() -> Option<Self> {
        Self::build(true)
    }

    /// A detached signature over `data` made while the expired leaf was still valid: at a faked time, the day before.
    pub fn sign_while_valid(&self, data: &[u8]) -> String {
        let at = chrono::Utc::now() - chrono::Duration::hours(36);
        let at = at.format("%Y%m%dT%H%M%S").to_string();
        let (data_file, signature) = (self.file("to-sign"), self.file("signature.pem"));
        std::fs::write(&data_file, data).unwrap();
        let output = self
            .gpgsm(
                &[
                    "--faked-system-time",
                    &at,
                    "--disable-crl-checks",
                    "--disable-ocsp",
                    "--detach-sign",
                    "--armor",
                    "--include-certs",
                    "-1",
                    "--local-user",
                    &self.leaf_fingerprint,
                    "--output",
                    signature.to_str().unwrap(),
                ],
                &[&data_file],
            )
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        std::fs::read_to_string(signature).unwrap()
    }

    fn build(expired_leaf: bool) -> Option<Self> {
        which::which("gpgsm").ok()?;
        which::which("openssl").ok()?;
        let dir = tempfile::Builder::new()
            .prefix("fx-")
            .tempdir_in("/tmp")
            .or_else(|_| tempfile::tempdir())
            .ok()?;
        let files = tempfile::tempdir().ok()?;
        std::fs::write(
            dir.path().join("gpg-agent.conf"),
            "allow-loopback-pinentry\nno-allow-mark-trusted\n",
        )
        .ok()?;
        let f = |name: &str| files.path().join(name);
        let openssl = |args: &[&str]| -> Option<()> {
            let output = Command::new("openssl")
                .args(args)
                .current_dir(files.path())
                .output()
                .ok()?;
            if !output.status.success() {
                eprintln!("openssl {args:?}: {}", String::from_utf8_lossy(&output.stderr));
                return None;
            }
            Some(())
        };
        let stamp = |days: i64| (chrono::Utc::now() + chrono::Duration::days(days)).format("%Y%m%d%H%M%SZ");
        let (not_before, not_after) = (stamp(-2).to_string(), stamp(-1).to_string());
        let (root_before, root_after) = (stamp(-10).to_string(), stamp(3000).to_string());
        let root_validity: &[&str] = if expired_leaf {
            &["-not_before", &root_before, "-not_after", &root_after]
        } else {
            &["-days", "3650"]
        };
        let leaf_validity: &[&str] = if expired_leaf {
            &["-not_before", &not_before, "-not_after", &not_after]
        } else {
            &["-days", "365"]
        };
        openssl(
            &[
                &[
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem",
                ][..],
                root_validity,
                &[
                    "-subj",
                    "/CN=Factum Test Root",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ][..],
            ]
            .concat(),
        )?;
        openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=Examiner One/O=Lab",
        ])?;
        std::fs::write(
            f("ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n",
        )
        .ok()?;
        openssl(
            &[
                &[
                    "x509",
                    "-req",
                    "-in",
                    "leaf.csr",
                    "-CA",
                    "root.pem",
                    "-CAkey",
                    "root.key",
                    "-CAcreateserial",
                    "-out",
                    "leaf.pem",
                    "-extfile",
                    "ext",
                ][..],
                leaf_validity,
            ]
            .concat(),
        )?;
        openssl(&[
            "pkcs12",
            "-export",
            "-inkey",
            "leaf.key",
            "-in",
            "leaf.pem",
            "-certfile",
            "root.pem",
            "-out",
            "leaf.p12",
            "-passout",
            "pass:",
        ])?;
        let mut home = Self {
            dir,
            files,
            leaf_fingerprint: String::new(),
            root_fingerprint: String::new(),
        };
        let output = home.gpgsm(
            &["--pinentry-mode", "loopback", "--passphrase", "", "--import"],
            &[&home.file("leaf.p12")],
        )?;
        if !output.status.success() {
            eprintln!(
                "cannot import the test certificate: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }
        let listing = home.gpgsm(&["--with-colons", "--list-keys"], &[])?;
        let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
        // fpr records: field 10 the certificate's fingerprint, field 13 its issuer's
        let fprs: Vec<(String, String)> = listing
            .lines()
            .filter(|l| l.starts_with("fpr:"))
            .map(|l| {
                let fields: Vec<&str> = l.split(':').collect();
                (fields[9].to_string(), fields.get(12).unwrap_or(&"").to_string())
            })
            .collect();
        let root = fprs.iter().find(|(fpr, issuer)| fpr == issuer)?.0.clone();
        let leaf = fprs.iter().find(|(fpr, _)| *fpr != root)?.0.clone();
        home.leaf_fingerprint = leaf;
        home.root_fingerprint = root;
        Some(home)
    }

    pub fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.files.path().join(name)
    }

    pub fn gpgsm(&self, args: &[&str], paths: &[&Path]) -> Option<std::process::Output> {
        Command::new("gpgsm")
            .arg("--homedir")
            .arg(self.dir.path())
            .arg("--batch")
            .args(args)
            .args(paths)
            .output()
            .ok()
    }

    /// Marks the root trusted, as an examiner does in trustlist.txt.
    pub fn trusted(&self) {
        let colons: Vec<String> = self
            .root_fingerprint
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).into_owned())
            .collect();
        std::fs::write(
            self.dir.path().join("trustlist.txt"),
            format!("{} S relax\n", colons.join(":")),
        )
        .unwrap();
        self.reload_agent();
    }

    pub fn untrusted(&self) {
        let _ = std::fs::remove_file(self.dir.path().join("trustlist.txt"));
        self.reload_agent();
    }

    fn reload_agent(&self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.dir.path())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

impl Drop for GpgsmHome {
    fn drop(&mut self) {
        self.reload_agent();
    }
}
