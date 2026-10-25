//! Signing and verification. [`GnupgSigner`] drives the system's `gpg` (like python-gnupg did), so keyrings,
//! trust and pinentry work exactly as before; [`FakeSigner`] is a deterministic stand-in for tests.

use std::cell::{Cell, OnceCell, RefCell};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::db::Db;

pub const ACTIVE_KEY_SETTING: &str = "active_gpg_key_id";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GpgKey {
    pub keyid: String,
    pub fingerprint: String,
    pub uids: Vec<String>,
    pub cap: String,
}

/// The outcome of checking one clearsigned block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyResult {
    pub valid: bool,
    pub status: String,
    pub signed_text: Option<String>,
    pub key_id: Option<String>,
    pub fingerprint: Option<String>,
    pub username: Option<String>,
    pub signature_timestamp: Option<String>,
    pub trust: Option<String>,
}

pub trait Signer {
    /// false when gpg is not installed: notes can still be written, unsigned
    fn available(&self) -> bool;
    fn active_key(&self) -> Option<String>;
    /// Only secret keys that have signing capability.
    fn list_keys(&self) -> Vec<GpgKey>;
    /// Selects a signing key and remembers it in the database (shared by CLI and GUI).
    fn set_active_key(&self, db: &Db, key_id: &str) -> bool;
    fn clear_active_key(&self, db: &Db);
    /// Clearsign text with the active key. None when no key is active or signing failed (see last_sign_failed).
    fn sign_text(&self, text: &str) -> Option<String>;
    /// Armored detached signature over data, used for the bundle manifest.
    fn sign_detached(&self, data: &[u8]) -> Option<String>;
    fn export_public_keys(&self, fingerprints: &[String]) -> String;
    fn verify_signature(&self, clearsigned: &str) -> VerifyResult;
    fn last_sign_failed(&self) -> bool;
    fn gpg_home(&self) -> Option<PathBuf>;
}

/// gpg's own messages, without the machine-readable [GNUPG:] status lines
pub fn gpg_error(stderr: &str) -> String {
    crate::pystr::splitlines(stderr)
        .into_iter()
        .map(crate::pystr::strip)
        .filter(|line| !line.is_empty() && !line.starts_with("[GNUPG:]"))
        .collect::<Vec<_>>()
        .join("; ")
}

struct GpgOutput {
    stdout: Vec<u8>,
    stderr: String,
    status: Vec<(String, Vec<String>)>,
}

impl GpgOutput {
    fn has(&self, keyword: &str) -> bool {
        self.status.iter().any(|(key, _)| key == keyword)
    }
}

fn run_gpg(binary: &Path, home: Option<&Path>, args: &[&str], input: &[u8]) -> std::io::Result<GpgOutput> {
    let mut command = Command::new(binary);
    // gpg writes user IDs in its messages in the locale's charset unless told otherwise; status lines on stderr
    command.args([
        "--status-fd",
        "2",
        "--no-tty",
        "--no-verbose",
        "--display-charset",
        "utf-8",
    ]);
    if let Some(home) = home {
        command.arg("--homedir").arg(home);
    }
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000; // no console window flashing up behind the GUI
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let data = input.to_vec();
    // written from a thread, so a large input cannot deadlock against gpg's full output pipes
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let output = child.wait_with_output()?;
    let _ = writer.join();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let status = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] "))
        .map(|line| {
            let mut parts = line.trim_end_matches('\r').split(' ').map(str::to_string);
            let key = parts.next().unwrap_or_default();
            (key, parts.collect())
        })
        .collect();
    Ok(GpgOutput {
        stdout: output.stdout,
        stderr,
        status,
    })
}

/// Unescapes the \xHH sequences gpg uses in --with-colons output.
fn unescape_colons(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && bytes.get(index + 1) == Some(&b'x')
            && let Some(hex) = field
                .get(index + 2..index + 4)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(hex);
            index += 4;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_key_listing(listing: &str) -> Vec<GpgKey> {
    let mut keys: Vec<GpgKey> = Vec::new();
    let mut in_primary = false;
    for line in listing.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let field = |index: usize| fields.get(index).copied().unwrap_or("");
        match field(0) {
            "sec" | "pub" => {
                keys.push(GpgKey {
                    keyid: field(4).into(),
                    cap: field(11).into(),
                    ..Default::default()
                });
                in_primary = true;
            }
            "fpr" if in_primary => {
                if let Some(key) = keys.last_mut() {
                    key.fingerprint = field(9).into();
                }
                in_primary = false; // later fpr lines belong to subkeys
            }
            "uid" => {
                if let Some(key) = keys.last_mut() {
                    key.uids.push(unescape_colons(field(9)));
                }
            }
            "ssb" | "sub" => in_primary = false,
            _ => {}
        }
    }
    keys
}

/// Reads gpg's status lines into a verification result, like python-gnupg's Verify.
fn verify_result(output: &GpgOutput) -> VerifyResult {
    let mut result = VerifyResult::default();
    let mut status: Option<&str> = None;
    for (key, values) in &output.status {
        let first = values.first().cloned();
        let rest = || values.get(1..).map(|v| v.join(" ")).filter(|s| !s.is_empty());
        match key.as_str() {
            "GOODSIG" => {
                result.valid = true;
                status = Some("signature good");
                result.key_id = first;
                result.username = rest();
            }
            "BADSIG" => {
                result.valid = false;
                status = Some("signature bad");
                result.key_id = first;
                result.username = rest();
            }
            "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" => {
                result.valid = false;
                status = Some(match key.as_str() {
                    "EXPSIG" => "signature expired",
                    "EXPKEYSIG" => "signing key has expired",
                    _ => "signing key was revoked",
                });
                result.key_id = first;
                result.username = rest();
            }
            "ERRSIG" => {
                result.valid = false;
                result.key_id = first;
                status = Some(if values.get(5).map(String::as_str) == Some("9") {
                    "no public key"
                } else {
                    "signature error"
                });
            }
            "NO_PUBKEY" => {
                result.valid = false;
                result.key_id = first;
                status = Some("no public key");
            }
            "VALIDSIG" => {
                result.fingerprint = first;
                result.signature_timestamp = values.get(2).cloned();
                status = Some("signature valid");
            }
            key if key.starts_with("TRUST_") => result.trust = Some(key.to_string()),
            _ => {}
        }
    }
    result.signed_text = if output.stdout.is_empty() {
        None
    } else {
        Some(crate::pystr::strip(&String::from_utf8_lossy(&output.stdout)).to_string())
    };
    // without a status gpg did not get as far as checking the signature: its error says why
    result.status = match status {
        Some(status) => status.to_string(),
        None => Some(gpg_error(&output.stderr))
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| "gpg gave no result".into()),
    };
    result
}

pub struct GnupgSigner {
    binary: Option<PathBuf>,
    home: Option<PathBuf>,
    active_key_id: RefCell<Option<String>>,
    last_sign_failed: Cell<bool>,
}

impl GnupgSigner {
    /// Looks for gpg and loads the remembered signing key from the database.
    pub fn new(db: &Db, home: Option<PathBuf>) -> Self {
        let signer = Self::without_key(home);
        signer.load_active_key_from_settings(db);
        signer
    }

    /// A signer with no key loaded (worker threads only verify).
    pub fn without_key(home: Option<PathBuf>) -> Self {
        let binary = which::which("gpg").ok();
        if binary.is_none() {
            // gpg is not installed (common on Windows without Gpg4win): notes can still be written, unsigned
            log::warn!("GPG is not available, nothing will be signed: gpg is not installed or not on the PATH");
        }
        Self {
            binary,
            home,
            active_key_id: RefCell::new(None),
            last_sign_failed: Cell::new(false),
        }
    }

    /// For tests: behaves as if gpg were not installed.
    pub fn unavailable(home: Option<PathBuf>) -> Self {
        Self {
            binary: None,
            home,
            active_key_id: RefCell::new(None),
            last_sign_failed: Cell::new(false),
        }
    }

    fn load_active_key_from_settings(&self, db: &Db) {
        let key_id = db.get_setting(ACTIVE_KEY_SETTING).unwrap_or_default();
        if key_id.is_empty() {
            log::debug!("No active GPG key ID found in settings.");
        } else if self.set_active_key(db, &key_id) {
            log::debug!("Loaded active GPG key from settings: {key_id}");
        } else {
            log::warn!("Failed to set active GPG key from settings: {key_id}");
        }
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Option<std::io::Result<GpgOutput>> {
        let binary = self.binary.as_ref()?;
        Some(run_gpg(binary, self.home.as_deref(), args, input))
    }

    fn sign_with(&self, args: &[&str], data: &[u8], what: &str) -> Option<String> {
        let key = self.active_key_id.borrow().clone()?;
        if self.binary.is_none() {
            log::debug!("No active GPG key set, nothing is signed.");
            return None;
        }
        self.last_sign_failed.set(false); // reset before attempting to sign
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--local-user", &key]);
        match self.run(&full, data) {
            Some(Ok(output)) if output.has("SIG_CREATED") && !output.stdout.is_empty() => {
                return Some(String::from_utf8_lossy(&output.stdout).into_owned());
            }
            Some(Ok(output)) => log::error!("GPG {what} failed for key {key}: {}", gpg_error(&output.stderr)),
            Some(Err(e)) => log::error!("Error signing: {e}"),
            None => {}
        }
        self.last_sign_failed.set(true);
        None
    }
}

impl Signer for GnupgSigner {
    fn available(&self) -> bool {
        self.binary.is_some()
    }

    fn active_key(&self) -> Option<String> {
        self.active_key_id.borrow().clone().filter(|key| !key.is_empty())
    }

    fn list_keys(&self) -> Vec<GpgKey> {
        let args = [
            "--list-secret-keys",
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
        ];
        match self.run(&args, b"") {
            Some(Ok(output)) => parse_key_listing(&String::from_utf8_lossy(&output.stdout))
                .into_iter()
                .filter(|key| key.cap.contains('s'))
                .collect(),
            Some(Err(e)) => {
                log::warn!("Could not list GPG keys: {e}");
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    fn set_active_key(&self, db: &Db, key_id: &str) -> bool {
        if self.list_keys().iter().any(|key| key.keyid == key_id) {
            *self.active_key_id.borrow_mut() = Some(key_id.to_string());
            log::debug!("Active GPG key set to: {key_id}");
            if let Err(e) = db.set_setting(ACTIVE_KEY_SETTING, key_id) {
                log::error!("{e}");
            }
            return true;
        }
        log::warn!("GPG key ID {key_id} not found or lacks signing capability.");
        false
    }

    fn clear_active_key(&self, db: &Db) {
        *self.active_key_id.borrow_mut() = None;
        if let Err(e) = db.delete_setting(ACTIVE_KEY_SETTING) {
            log::error!("{e}");
        }
        log::debug!("Active GPG key cleared.");
    }

    fn sign_text(&self, text: &str) -> Option<String> {
        if self.active_key().is_none() {
            log::debug!("No active GPG key set, nothing is signed.");
            return None;
        }
        self.sign_with(&["--clearsign"], text.as_bytes(), "signing")
    }

    fn sign_detached(&self, data: &[u8]) -> Option<String> {
        self.active_key()?;
        self.sign_with(&["--armor", "--detach-sign"], data, "detached signing")
    }

    fn export_public_keys(&self, fingerprints: &[String]) -> String {
        if fingerprints.is_empty() {
            return String::new();
        }
        let mut args = vec!["--armor", "--export"];
        args.extend(fingerprints.iter().map(String::as_str));
        match self.run(&args, b"") {
            Some(Ok(output)) => String::from_utf8_lossy(&output.stdout).into_owned(),
            _ => String::new(),
        }
    }

    fn verify_signature(&self, clearsigned: &str) -> VerifyResult {
        // decrypting a clearsigned message returns the signed text and verifies the signature in one step
        let error = |message: String| {
            log::error!("Error verifying signature: {message}");
            VerifyResult {
                status: format!("error: {message}"),
                ..Default::default()
            }
        };
        match self.run(&["--decrypt"], clearsigned.as_bytes()) {
            None => error("gpg is not installed or not on the PATH".into()),
            Some(Err(e)) => error(e.to_string()),
            Some(Ok(output)) => verify_result(&output),
        }
    }

    fn last_sign_failed(&self) -> bool {
        self.last_sign_failed.get()
    }

    fn gpg_home(&self) -> Option<PathBuf> {
        self.home.clone()
    }
}

/// Creates the GnuPG signer on first use, so read-only commands work without gpg installed.
pub struct LazySigner<'a> {
    db: &'a Db,
    inner: OnceCell<GnupgSigner>,
}

impl<'a> LazySigner<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self {
            db,
            inner: OnceCell::new(),
        }
    }

    fn get(&self) -> &GnupgSigner {
        self.inner.get_or_init(|| GnupgSigner::new(self.db, None))
    }
}

impl Signer for LazySigner<'_> {
    fn available(&self) -> bool {
        self.get().available()
    }
    fn active_key(&self) -> Option<String> {
        self.get().active_key()
    }
    fn list_keys(&self) -> Vec<GpgKey> {
        self.get().list_keys()
    }
    fn set_active_key(&self, db: &Db, key_id: &str) -> bool {
        self.get().set_active_key(db, key_id)
    }
    fn clear_active_key(&self, db: &Db) {
        self.get().clear_active_key(db)
    }
    fn sign_text(&self, text: &str) -> Option<String> {
        self.get().sign_text(text)
    }
    fn sign_detached(&self, data: &[u8]) -> Option<String> {
        self.get().sign_detached(data)
    }
    fn export_public_keys(&self, fingerprints: &[String]) -> String {
        self.get().export_public_keys(fingerprints)
    }
    fn verify_signature(&self, clearsigned: &str) -> VerifyResult {
        self.get().verify_signature(clearsigned)
    }
    fn last_sign_failed(&self) -> bool {
        self.inner.get().is_some_and(|signer| signer.last_sign_failed())
    }
    fn gpg_home(&self) -> Option<PathBuf> {
        None
    }
}

/// Stand-in for GnupgSigner: deterministic, clearsign-shaped signatures, no gpg needed.
pub struct FakeSigner {
    pub active_key_id: RefCell<Option<String>>,
    pub trust: RefCell<String>,
    pub fail_next: Cell<bool>,
    pub last_failed: Cell<bool>,
    /// armor as gpg writes it on Windows
    pub crlf: Cell<bool>,
    /// called before every signature, e.g. to simulate another process appending meanwhile
    #[allow(clippy::type_complexity)]
    pub before_sign: RefCell<Option<Box<dyn FnMut()>>>,
}

impl FakeSigner {
    pub const PREFIX: &'static str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: FAKE\n\n";
    pub const SUFFIX: &'static str = "\n-----BEGIN PGP SIGNATURE-----\nFAKE\n-----END PGP SIGNATURE-----\n";

    pub fn new(active: bool) -> Self {
        Self::with_trust(active, "TRUST_ULTIMATE")
    }

    pub fn with_trust(active: bool, trust: &str) -> Self {
        Self {
            active_key_id: RefCell::new(active.then(|| "FAKEKEY1".to_string())),
            trust: RefCell::new(trust.to_string()),
            fail_next: Cell::new(false),
            last_failed: Cell::new(false),
            crlf: Cell::new(false),
            before_sign: RefCell::new(None),
        }
    }

    pub fn set_active(&self, active: bool) {
        *self.active_key_id.borrow_mut() = active.then(|| "FAKEKEY1".to_string());
    }

    pub fn fake_signature(text: &str) -> String {
        format!("{}{}{}", Self::PREFIX, text, Self::SUFFIX)
    }
}

impl Signer for FakeSigner {
    fn available(&self) -> bool {
        true
    }
    fn active_key(&self) -> Option<String> {
        self.active_key_id.borrow().clone()
    }
    fn list_keys(&self) -> Vec<GpgKey> {
        Vec::new()
    }
    fn set_active_key(&self, _db: &Db, _key_id: &str) -> bool {
        false
    }
    fn clear_active_key(&self, _db: &Db) {
        *self.active_key_id.borrow_mut() = None;
    }
    fn sign_text(&self, text: &str) -> Option<String> {
        if let Some(hook) = self.before_sign.borrow_mut().as_mut() {
            hook();
        }
        self.active_key_id.borrow().as_ref()?;
        if self.fail_next.replace(false) {
            self.last_failed.set(true);
            return None;
        }
        let signature = Self::fake_signature(text);
        Some(if self.crlf.get() {
            signature.replace('\n', "\r\n")
        } else {
            signature
        })
    }
    fn sign_detached(&self, data: &[u8]) -> Option<String> {
        use sha2::Digest;
        self.active_key_id.borrow().as_ref()?;
        Some(format!("FAKE DETACHED {}", hex::encode(sha2::Sha256::digest(data))))
    }
    fn export_public_keys(&self, _fingerprints: &[String]) -> String {
        String::new()
    }
    fn verify_signature(&self, signature: &str) -> VerifyResult {
        let signature = signature.replace("\r\n", "\n");
        let ok = signature.starts_with(Self::PREFIX) && signature.ends_with(Self::SUFFIX);
        VerifyResult {
            valid: ok,
            status: if ok { "signature valid" } else { "bad signature" }.into(),
            signed_text: ok.then(|| signature[Self::PREFIX.len()..signature.len() - Self::SUFFIX.len()].to_string()),
            key_id: Some("FAKEKEY1".into()),
            fingerprint: Some("FAKEFINGERPRINT1".into()),
            username: Some("Fake Signer".into()),
            signature_timestamp: None,
            trust: Some(self.trust.borrow().clone()),
        }
    }
    fn last_sign_failed(&self) -> bool {
        self.last_failed.get()
    }
    fn gpg_home(&self) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_listing_is_parsed() {
        let listing = "sec:u:255:22:AAAABBBBCCCCDDDD:1700000000:::u:::scESC:::+:::ed25519:::0:\n\
                       fpr:::::::::0123456789ABCDEF0123456789ABCDEFAAAABBBB:\n\
                       grp:::::::::XYZ:\n\
                       uid:u::::1700000000::HASH::J\\xc3\\xbcrgen \\x3a <j@x.invalid>::::::::::0:\n\
                       ssb:u:255:18:1111222233334444:1700000000::::::e:::+:::cv25519::\n\
                       fpr:::::::::FFFF:\n";
        let keys = parse_key_listing(listing);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].keyid, "AAAABBBBCCCCDDDD");
        assert_eq!(keys[0].fingerprint, "0123456789ABCDEF0123456789ABCDEFAAAABBBB");
        assert_eq!(keys[0].uids, vec!["Jürgen : <j@x.invalid>"]);
        assert!(keys[0].cap.contains('s'));
    }

    #[test]
    fn gpg_error_drops_status_lines() {
        assert_eq!(
            gpg_error("[GNUPG:] NEWSIG\ngpg: can't connect to the keyboxd: IPC connect call failed\n"),
            "gpg: can't connect to the keyboxd: IPC connect call failed"
        );
    }

    #[test]
    fn invalid_signature_without_status_reports_gpg_error() {
        let output = GpgOutput {
            stdout: Vec::new(),
            stderr: "[GNUPG:] NEWSIG\ngpg: can't connect to the keyboxd: IPC connect call failed\n".into(),
            status: vec![("NEWSIG".into(), vec![])],
        };
        let result = verify_result(&output);
        assert!(!result.valid);
        assert_eq!(
            result.status,
            "gpg: can't connect to the keyboxd: IPC connect call failed"
        );
    }

    #[test]
    fn missing_gpg_leaves_signing_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("f.db")).unwrap();
        db.set_setting(ACTIVE_KEY_SETTING, "ABCD1234").unwrap();
        let service = GnupgSigner::unavailable(None);
        assert!(!service.available() && service.list_keys().is_empty());
        assert!(!service.set_active_key(&db, "ABCD1234"));
        assert_eq!(service.sign_text("x"), None);
        assert_eq!(service.sign_detached(b"x"), None);
        assert_eq!(service.export_public_keys(&["F".into()]), "");
        assert!(!service.verify_signature("-----BEGIN PGP SIGNED MESSAGE-----").valid);
    }
}
