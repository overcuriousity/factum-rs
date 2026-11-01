//! Signing and verification. [`GnupgSigner`] drives the system's `gpg` (like python-gnupg did), so keyrings,
//! trust and pinentry work exactly as before; [`FakeSigner`] is a deterministic stand-in for tests.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::db::Db;

pub const ACTIVE_KEY_SETTING: &str = "active_gpg_key_id";

/// gpg must not ask for anything while it checks a signature: what is checked comes from the database or a seal file
/// and may hold a symmetric-encrypted message instead of a signature. Never for signing, which may need pinentry.
const VERIFY_ARGS: [&str; 3] = ["--batch", "--pinentry-mode", "error"];
/// what gpg's verdict on a signature depends on, besides the clock; under the gpg home folder
const KEYRING_FILES: [&str; 8] = [
    "pubring.kbx",
    "pubring.gpg",
    "public-keys.d/pubring.db",
    "public-keys.d/pubring.db-wal",
    "trustdb.gpg",
    "tofu.db",
    "gpg.conf",
    "common.conf",
];
/// a good result can go stale without a file changing, when a key or signature expires; this bounds for how long
const VERIFIED_LIFETIME: Duration = Duration::from_secs(600);
/// a good result takes well under a kilobyte; old keyring states are dropped this way too
const VERIFIED_MAX: usize = 100_000;

/// Good verification results of this process, by [`GnupgSigner::verified_key`]; workers each have their own signer,
/// so this is shared. Never on disk.
static VERIFIED: LazyLock<Mutex<VerifiedResults>> = LazyLock::new(Default::default);
type VerifiedResults = HashMap<[u8; 32], (Instant, VerifyResult)>;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GpgKey {
    pub keyid: String,
    pub fingerprint: String,
    pub uids: Vec<String>,
    pub cap: String,
    /// e.g. ed25519 or rsa4096
    pub algorithm: String,
    /// YYYY-MM-DD; empty when gpg does not say
    pub created: String,
    /// YYYY-MM-DD; empty for a key that does not expire
    pub expires: String,
    /// gpg's validity: e expired, r revoked, ...
    pub validity: String,
    /// gpg's owner trust: u ultimate, f full, ...
    pub ownertrust: String,
}

impl GpgKey {
    pub fn expired(&self) -> bool {
        self.validity == "e"
    }

    pub fn revoked(&self) -> bool {
        self.validity == "r"
    }

    /// Uppercase capabilities are what the whole key can do now: a certify-only primary key with a signing subkey has
    /// them, an expired or revoked key does not.
    pub fn can_sign(&self) -> bool {
        self.cap.contains('S')
    }

    /// Why a key that cannot sign cannot.
    fn unusable_reason(&self) -> &'static str {
        if self.revoked() {
            "was revoked"
        } else if self.expired() {
            "has expired"
        } else {
            "has no usable signing key"
        }
    }
}

/// A Unix time from a --with-colons field as YYYY-MM-DD.
fn colon_date(field: &str) -> String {
    field
        .parse::<i64>()
        .ok()
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The key's algorithm from the public key algorithm (field 4), key length (field 3) and curve name (field 17).
fn colon_algorithm(algorithm: &str, length: &str, curve: &str) -> String {
    if !curve.is_empty() {
        return curve.to_string();
    }
    match algorithm {
        "1" | "2" | "3" => format!("rsa{length}"),
        "17" => format!("dsa{length}"),
        "16" | "20" => format!("elgamal{length}"),
        other => format!("algorithm {other}"),
    }
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
    /// gpg found the signing key expired; with `valid`, the signature was made before that
    pub key_expired: bool,
    /// the subkey that signed, when it is not the primary key in `fingerprint`
    pub signing_subkey: Option<String>,
}

pub trait Signer {
    /// false when gpg is not installed: notes can still be written, unsigned
    fn available(&self) -> bool;
    fn active_key(&self) -> Option<String>;
    /// Only secret keys that have signing capability, and the active key whatever its state: it stays active after
    /// expiring, and the list shows why it no longer signs.
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
    /// Checks an armored detached signature over data; `signed_text` stays None.
    fn verify_detached(&self, signature: &str, data: &[u8]) -> VerifyResult;
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

pub(crate) struct GpgOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) status: Vec<(String, Vec<String>)>,
    /// the exit code was 0
    pub(crate) success: bool,
}

impl GpgOutput {
    pub(crate) fn has(&self, keyword: &str) -> bool {
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
    command.args(args);
    run_program(command, input)
}

/// Runs a GnuPG program with `input` on stdin; its status lines are read from stderr (`--status-fd 2`).
pub(crate) fn run_program(mut command: Command, input: &[u8]) -> std::io::Result<GpgOutput> {
    command
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
        success: output.status.success(),
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
                    algorithm: colon_algorithm(field(3), field(2), field(16)),
                    created: colon_date(field(5)),
                    expires: colon_date(field(6)),
                    validity: field(1).into(),
                    ownertrust: field(8).into(),
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

/// Reads gpg's status lines into a verification result, like python-gnupg's Verify but stricter: valid means exactly
/// one good signature, no bad one, and an exit code that agrees.
fn verify_result(output: &GpgOutput) -> VerifyResult {
    let mut result = VerifyResult::default();
    // why the signature does not count
    let mut rejected: Option<&str> = None;
    let (mut good, mut validsig) = (0, 0);
    let (mut last_expiry, mut key_expiry) = (None, None);
    for (key, values) in &output.status {
        let first = values.first().cloned();
        let rest = || values.get(1..).map(|v| v.join(" ")).filter(|s| !s.is_empty());
        match key.as_str() {
            "GOODSIG" | "EXPKEYSIG" => {
                good += 1;
                if key == "EXPKEYSIG" {
                    result.key_expired = true;
                    key_expiry = last_expiry;
                }
                result.key_id = first;
                result.username = rest();
            }
            "BADSIG" | "EXPSIG" | "REVKEYSIG" => {
                rejected = Some(match key.as_str() {
                    "BADSIG" => "signature bad",
                    "EXPSIG" => "signature expired",
                    _ => "signing key was revoked",
                });
                result.key_id = first;
                result.username = rest();
            }
            "ERRSIG" => {
                result.key_id = first;
                rejected = Some(if values.get(5).map(String::as_str) == Some("9") {
                    "no public key"
                } else {
                    "signature error"
                });
            }
            "NO_PUBKEY" => {
                result.key_id = first;
                rejected = Some("no public key");
            }
            // gpg also says this of other expired subkeys; the last one before EXPKEYSIG is the signing key's
            "KEYEXPIRED" => last_expiry = first.and_then(|time| time.parse::<i64>().ok()),
            "VALIDSIG" => {
                validsig += 1;
                let primary = values.get(9).filter(|f| !f.is_empty()).or(values.first()).cloned();
                result.signing_subkey = first.filter(|signing| Some(signing) != primary.as_ref());
                result.fingerprint = primary;
                result.signature_timestamp = values.get(2).cloned();
            }
            key if key.starts_with("TRUST_") => result.trust = Some(key.to_string()),
            _ => {}
        }
    }
    let made = result
        .signature_timestamp
        .as_deref()
        .and_then(|t| t.parse::<i64>().ok());
    if result.key_expired && made.zip(key_expiry).is_some_and(|(made, expiry)| made > expiry) {
        rejected = Some("signature made after the signing key expired");
    }
    result.valid = rejected.is_none() && good == 1 && validsig == 1 && output.success && !output.has("FAILURE");
    result.signed_text = if output.stdout.is_empty() {
        None
    } else {
        Some(crate::pystr::strip(&String::from_utf8_lossy(&output.stdout)).to_string())
    };
    result.status = if result.valid {
        "signature valid".to_string()
    } else if let Some(rejected) = rejected {
        rejected.to_string()
    } else if good > 1 || validsig > 1 {
        "more than one signature".to_string()
    } else if good > 0 || validsig > 0 {
        // gpg's own words would be a "Good signature" in a failure, in the user's locale
        "bad signature".to_string()
    } else {
        // gpg did not get as far as checking the signature: its error says why
        Some(gpg_error(&output.stderr))
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| "gpg gave no result".into())
    };
    result
}

pub struct GnupgSigner {
    binary: Option<PathBuf>,
    home: Option<PathBuf>,
    active_key_id: RefCell<Option<String>>,
    last_sign_failed: Cell<bool>,
    /// the folder gpg uses; None when that cannot be told
    resolved_home: OnceCell<Option<PathBuf>>,
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
            resolved_home: OnceCell::new(),
        }
    }

    /// For tests: behaves as if gpg were not installed.
    pub fn unavailable(home: Option<PathBuf>) -> Self {
        Self {
            binary: None,
            home,
            active_key_id: RefCell::new(None),
            last_sign_failed: Cell::new(false),
            resolved_home: OnceCell::new(),
        }
    }

    /// For tests: runs `binary` as gpg.
    pub fn with_binary(binary: PathBuf, home: Option<PathBuf>) -> Self {
        Self {
            binary: Some(binary),
            ..Self::unavailable(home)
        }
    }

    /// Reads the remembered signing key again: another process may have changed or removed it.
    pub fn reload_active_key(&self, db: &Db) {
        *self.active_key_id.borrow_mut() = None;
        self.load_active_key_from_settings(db);
    }

    fn load_active_key_from_settings(&self, db: &Db) {
        let key_id = db.get_setting(ACTIVE_KEY_SETTING).unwrap_or_default();
        if key_id.is_empty() {
            log::debug!("No active GPG key ID found in settings.");
            return;
        }
        let Some(key) = self.secret_keys().into_iter().find(|key| key.keyid == key_id) else {
            log::warn!("Failed to set active GPG key from settings: {key_id}");
            return;
        };
        // a key that no longer signs stays active: signing then fails, instead of notes going unsigned
        if key.can_sign() {
            log::debug!("Loaded active GPG key from settings: {key_id}");
        } else {
            log::warn!(
                "The active GPG key {key_id} {}: signing fails until another key is selected.",
                key.unusable_reason()
            );
        }
        *self.active_key_id.borrow_mut() = Some(key_id);
    }

    /// Every secret key, whether or not it can sign.
    fn secret_keys(&self) -> Vec<GpgKey> {
        let args = [
            "--list-secret-keys",
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
        ];
        match self.run(&args, b"") {
            Some(Ok(output)) => parse_key_listing(&String::from_utf8_lossy(&output.stdout)),
            Some(Err(e)) => {
                log::warn!("Could not list GPG keys: {e}");
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Option<std::io::Result<GpgOutput>> {
        let binary = self.binary.as_ref()?;
        Some(run_gpg(binary, self.home.as_deref(), args, input))
    }

    fn run_verify(&self, args: &[&str], input: &[u8]) -> Option<std::io::Result<GpgOutput>> {
        let mut full = VERIFY_ARGS.to_vec();
        full.extend(args);
        self.run(&full, input)
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

    /// The gpg home folder: as set, else gpg's own answer (GNUPGHOME, the Windows registry, ...).
    fn resolved_home(&self) -> Option<&Path> {
        self.resolved_home
            .get_or_init(|| {
                self.home.clone().or_else(|| {
                    let mut command = Command::new(which::which("gpgconf").ok()?);
                    command.args(["--list-dirs", "homedir"]);
                    let output = run_program(command, b"").ok().filter(|output| output.success)?;
                    let home = String::from_utf8_lossy(&output.stdout);
                    Some(PathBuf::from(home.trim_end())).filter(|home| !home.as_os_str().is_empty())
                })
            })
            .as_deref()
    }

    /// Identifies a check: the signature, the data (None: it is inside a clearsigned signature) and the state of the
    /// keyring. The size and time of its files change with every key or trust change. None when gpg's home is unknown.
    fn verified_key(&self, signature: &str, data: Option<&[u8]>) -> Option<[u8; 32]> {
        self.binary.as_ref()?;
        let home = self.resolved_home()?;
        let mut hash = Sha256::new();
        let mut field = |bytes: &[u8]| {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        };
        field(signature.as_bytes());
        field(if data.is_some() { b"detached" } else { b"clearsigned" });
        field(data.unwrap_or_default());
        field(home.to_string_lossy().as_bytes());
        for file in KEYRING_FILES {
            let metadata = std::fs::metadata(home.join(file)).ok();
            let size = metadata.as_ref().map_or(0, |m| m.len());
            let modified = metadata
                .and_then(|m| m.modified().ok())
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |time| time.as_nanos());
            field(file.as_bytes());
            field(&size.to_le_bytes());
            field(&modified.to_le_bytes());
        }
        Some(hash.finalize().into())
    }

    /// The result of `check`, from the cache if nothing it depends on has changed. Only good results are kept: a
    /// failure may be passing (gpg-agent not reachable), and the next run decides it anyway.
    fn verify_cached(
        &self,
        signature: &str,
        data: Option<&[u8]>,
        check: impl FnOnce() -> VerifyResult,
    ) -> VerifyResult {
        let Some(key) = self.verified_key(signature, data) else {
            return check();
        };
        if let Ok(verified) = VERIFIED.lock()
            && let Some((at, result)) = verified.get(&key)
            && at.elapsed() < VERIFIED_LIFETIME
        {
            return result.clone();
        }
        let result = check();
        if result.valid
            && let Ok(mut verified) = VERIFIED.lock()
        {
            if verified.len() >= VERIFIED_MAX {
                verified.clear();
            }
            verified.insert(key, (Instant::now(), result.clone()));
        }
        result
    }

    /// gpg gives no trust level for a signature by an expired key, but the key listing still says what it can: the
    /// validity of a live primary key whose signing subkey expired, and owner trust. Owner trust `u` makes a key valid
    /// by itself, `f` does not. An expired primary key that was valid through certification cannot be told apart.
    fn trust_expired_key(&self, result: &mut VerifyResult) {
        if !(result.valid && result.key_expired && result.trust.is_none()) {
            return;
        }
        let Some(fingerprint) = result.fingerprint.as_deref() else {
            return;
        };
        let args = ["--list-keys", "--with-colons", "--fixed-list-mode", fingerprint];
        let Some(Ok(output)) = self.run_verify(&args, b"") else {
            return;
        };
        let listing = parse_key_listing(&String::from_utf8_lossy(&output.stdout));
        result.trust = listing.first().and_then(|key| match key.validity.as_str() {
            "u" => Some("TRUST_ULTIMATE".to_string()),
            "f" => Some("TRUST_FULLY".to_string()),
            _ => (key.ownertrust == "u").then(|| "TRUST_ULTIMATE".to_string()),
        });
    }

    fn verified(&self, output: &GpgOutput) -> VerifyResult {
        let mut result = verify_result(output);
        self.trust_expired_key(&mut result);
        result
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
        let active = self.active_key();
        self.secret_keys()
            .into_iter()
            .filter(|key| key.can_sign() || active.as_ref() == Some(&key.keyid))
            .collect()
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
        self.verify_cached(clearsigned, None, || {
            match self.run_verify(&["--decrypt"], clearsigned.as_bytes()) {
                None => error("gpg is not installed or not on the PATH".into()),
                Some(Err(e)) => error(e.to_string()),
                Some(Ok(output)) => self.verified(&output),
            }
        })
    }

    fn verify_detached(&self, signature: &str, data: &[u8]) -> VerifyResult {
        let error = |message: String| {
            log::error!("Error verifying a detached signature: {message}");
            VerifyResult {
                status: format!("error: {message}"),
                ..Default::default()
            }
        };
        self.verify_cached(signature, Some(data), || {
            // the signature goes through a file, the data through stdin
            let file =
                match tempfile::NamedTempFile::new().and_then(|mut f| f.write_all(signature.as_bytes()).map(|_| f)) {
                    Ok(file) => file,
                    Err(e) => return error(e.to_string()),
                };
            let path = file.path().display().to_string();
            match self.run_verify(&["--verify", &path, "-"], data) {
                None => error("gpg is not installed or not on the PATH".into()),
                Some(Err(e)) => error(e.to_string()),
                Some(Ok(output)) => {
                    let mut result = self.verified(&output);
                    result.signed_text = None;
                    result
                }
            }
        })
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
    fn verify_detached(&self, signature: &str, data: &[u8]) -> VerifyResult {
        self.get().verify_detached(signature, data)
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
    /// detached signatures still made before one fails (once)
    pub fail_detached_after: Cell<Option<u32>>,
    /// text signatures still made before one fails (once)
    pub fail_text_after: Cell<Option<u32>>,
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
            fail_detached_after: Cell::new(None),
            fail_text_after: Cell::new(None),
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
        match self.fail_text_after.get() {
            Some(0) => {
                self.fail_text_after.set(None);
                self.fail_next.set(true);
            }
            Some(n) => self.fail_text_after.set(Some(n - 1)),
            None => {}
        }
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
        self.active_key_id.borrow().as_ref()?;
        match self.fail_detached_after.get() {
            Some(0) => {
                self.fail_detached_after.set(None);
                return None;
            }
            Some(n) => self.fail_detached_after.set(Some(n - 1)),
            None => {}
        }
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
            ..Default::default()
        }
    }
    fn verify_detached(&self, signature: &str, data: &[u8]) -> VerifyResult {
        let ok = signature == format!("FAKE DETACHED {}", hex::encode(sha2::Sha256::digest(data)));
        VerifyResult {
            valid: ok,
            status: if ok { "signature valid" } else { "bad signature" }.into(),
            signed_text: None,
            key_id: Some("FAKEKEY1".into()),
            fingerprint: Some("FAKEFINGERPRINT1".into()),
            username: Some("Fake Signer".into()),
            signature_timestamp: None,
            trust: Some(self.trust.borrow().clone()),
            ..Default::default()
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
        let listing = "sec:u:255:22:AAAABBBBCCCCDDDD:1700000000:1900000000::u:::scESC:::+::ed25519:::0:\n\
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
        assert_eq!(
            (
                keys[0].algorithm.as_str(),
                keys[0].created.as_str(),
                keys[0].expires.as_str()
            ),
            ("ed25519", "2023-11-14", "2030-03-17")
        );
        assert!(!keys[0].expired() && !keys[0].revoked());
        let rsa = parse_key_listing("sec:e:4096:1:AAAABBBBCCCCDDDD:1700000000:::u:::scSC:::+:::::0:\n");
        assert_eq!((rsa[0].algorithm.as_str(), rsa[0].expires.as_str()), ("rsa4096", ""));
        assert!(rsa[0].expired());
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
            success: false,
        };
        let result = verify_result(&output);
        assert!(!result.valid);
        assert_eq!(
            result.status,
            "gpg: can't connect to the keyboxd: IPC connect call failed"
        );
    }

    /// gpg's output from status lines, without the `[GNUPG:] ` prefix.
    fn output(lines: &[&str], success: bool) -> GpgOutput {
        let status = lines
            .iter()
            .map(|line| {
                let mut parts = line.split(' ').map(str::to_string);
                (parts.next().unwrap(), parts.collect())
            })
            .collect();
        GpgOutput {
            stdout: b"text\n".to_vec(),
            stderr: String::new(),
            status,
            success,
        }
    }

    const PRIMARY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SUBKEY: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn validsig(signing: &str, made: i64, primary: &str) -> String {
        format!("VALIDSIG {signing} 2020-01-15 {made} 0 4 0 22 10 01 {primary}")
    }

    #[test]
    fn expired_key_counts_for_signatures_made_before_its_expiry() {
        let valid = validsig(PRIMARY, 1000, PRIMARY);
        let result = verify_result(&output(&["KEYEXPIRED 2000", "EXPKEYSIG 1234 Name", &valid], true));
        assert!(result.valid && result.key_expired);
        assert_eq!(result.status, "signature valid");
        assert_eq!(result.username.as_deref(), Some("Name"));
    }

    #[test]
    fn expired_key_does_not_count_for_signatures_made_after_its_expiry() {
        let valid = validsig(PRIMARY, 3000, PRIMARY);
        let result = verify_result(&output(&["KEYEXPIRED 2000", "EXPKEYSIG 1234 Name", &valid], true));
        assert!(!result.valid);
        assert_eq!(result.status, "signature made after the signing key expired");
    }

    #[test]
    fn expired_key_without_a_known_expiry_counts() {
        let valid = validsig(PRIMARY, 3000, PRIMARY);
        assert!(verify_result(&output(&["EXPKEYSIG 1234 Name", &valid], true)).valid);
    }

    #[test]
    fn expiry_of_the_signing_key_is_the_line_before_expkeysig() {
        // lines about other subkeys come before and after
        let valid = validsig(SUBKEY, 1500, PRIMARY);
        let lines = [
            "KEYEXPIRED 1000",
            "KEYEXPIRED 2000",
            "EXPKEYSIG 1234 Name",
            &valid,
            "KEYEXPIRED 1000",
        ];
        assert!(verify_result(&output(&lines, true)).valid);
        let lines = ["KEYEXPIRED 2000", "KEYEXPIRED 1000", "EXPKEYSIG 1234 Name", &valid];
        assert!(!verify_result(&output(&lines, true)).valid);
    }

    #[test]
    fn an_expired_subkey_next_to_a_good_signature_is_no_expired_key() {
        let valid = validsig(PRIMARY, 3000, PRIMARY);
        let result = verify_result(&output(&["KEYEXPIRED 2000", "GOODSIG 1234 Name", &valid], true));
        assert!(result.valid && !result.key_expired);
    }

    #[test]
    fn revoked_key_and_expired_signature_stay_invalid_and_say_why() {
        let valid = validsig(PRIMARY, 1000, PRIMARY);
        for (line, status) in [
            ("REVKEYSIG 1234 Name", "signing key was revoked"),
            ("EXPSIG 1234 Name", "signature expired"),
        ] {
            let result = verify_result(&output(&[line, &valid, "TRUST_ULTIMATE 0 pgp"], true));
            assert!(!result.valid);
            assert_eq!(result.status, status);
        }
    }

    #[test]
    fn fingerprint_is_the_primary_key_with_the_subkey_beside_it() {
        let valid = validsig(SUBKEY, 1000, PRIMARY);
        let result = verify_result(&output(&["GOODSIG 1234 Name", &valid], true));
        assert_eq!(result.fingerprint.as_deref(), Some(PRIMARY));
        assert_eq!(result.signing_subkey.as_deref(), Some(SUBKEY));
    }

    #[test]
    fn fingerprint_of_a_primary_key_signature_is_unchanged() {
        let valid = validsig(PRIMARY, 1000, PRIMARY);
        let result = verify_result(&output(&["GOODSIG 1234 Name", &valid], true));
        assert_eq!(result.fingerprint.as_deref(), Some(PRIMARY));
        assert_eq!(result.signing_subkey, None);
    }

    #[test]
    fn fingerprint_falls_back_to_the_signing_key() {
        let result = verify_result(&output(
            &["GOODSIG 1234 Name", &format!("VALIDSIG {PRIMARY} 2020-01-15 1000")],
            true,
        ));
        assert_eq!(result.fingerprint.as_deref(), Some(PRIMARY));
        assert_eq!(result.signing_subkey, None);
    }

    #[test]
    fn only_exactly_one_good_signature_counts() {
        let valid = validsig(PRIMARY, 1000, PRIMARY);
        let other = validsig(SUBKEY, 1000, SUBKEY);
        let two = ["GOODSIG 1 A", &valid, "GOODSIG 2 B", &other];
        let result = verify_result(&output(&two, true));
        assert!(!result.valid);
        assert_eq!(result.status, "more than one signature");
        assert!(!verify_result(&output(&["GOODSIG 1 A", "BADSIG 2 B", &valid], false)).valid);
        assert!(!verify_result(&output(&["GOODSIG 1 A", "ERRSIG 2 22 10 01 1000 9", &valid], true)).valid);
        assert!(!verify_result(&output(&["GOODSIG 1 A"], true)).valid);
        assert!(!verify_result(&output(&[&valid], true)).valid);
    }

    #[test]
    fn a_good_signature_counts_only_if_gpg_exits_cleanly() {
        let valid = validsig(PRIMARY, 1000, PRIMARY);
        assert!(!verify_result(&output(&["GOODSIG 1 A", &valid], false)).valid);
        let failure = ["GOODSIG 1 A", &valid, "FAILURE gpg-exit 33554433"];
        assert!(!verify_result(&output(&failure, true)).valid);
        let mut failed = output(&["GOODSIG 1 A", &valid], false);
        failed.stderr = "[GNUPG:] GOODSIG 1 A\ngpg: Korrekte Signatur von \"A\"\n".into();
        assert_eq!(verify_result(&failed).status, "bad signature");
    }

    #[test]
    fn a_certify_only_primary_key_with_a_signing_subkey_can_sign() {
        let listing = "sec:u:255:22:AAAABBBBCCCCDDDD:1700000000:::u:::cSC:::+::ed25519:::0:\n\
                       fpr:::::::::0123456789ABCDEF0123456789ABCDEFAAAABBBB:\n\
                       ssb:u:255:22:1111222233334444:1700000000::::::s:::+::ed25519::\n\
                       fpr:::::::::FFFF:\n";
        let keys = parse_key_listing(listing);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].can_sign());
        assert_eq!(keys[0].fingerprint, "0123456789ABCDEF0123456789ABCDEFAAAABBBB");
        assert_eq!(keys[0].ownertrust, "u");
    }

    #[test]
    fn expired_revoked_and_encrypt_only_keys_cannot_sign() {
        for cap in ["sc", "c", "eE", "scE"] {
            let listing = format!("sec:e:255:22:AAAABBBBCCCCDDDD:1700000000:::u:::{cap}:::+::ed25519:::0:\n");
            assert!(!parse_key_listing(&listing)[0].can_sign(), "{cap}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_remembered_key_is_read_again() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("f.db")).unwrap();
        let gpg = dir.path().join("gpg");
        let listing = "sec:u:255:22:AAAABBBBCCCCDDDD:1700000000:::u:::scESC:::+::ed25519:::0:";
        std::fs::write(&gpg, format!("#!/bin/sh\necho '{listing}'\n")).unwrap();
        std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o755)).unwrap();
        let service = GnupgSigner::with_binary(gpg, None);
        assert_eq!(service.active_key(), None);
        db.set_setting(ACTIVE_KEY_SETTING, "AAAABBBBCCCCDDDD").unwrap();
        service.reload_active_key(&db);
        assert_eq!(service.active_key().as_deref(), Some("AAAABBBBCCCCDDDD"));
        db.delete_setting(ACTIVE_KEY_SETTING).unwrap();
        service.reload_active_key(&db);
        assert_eq!(service.active_key(), None);
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
