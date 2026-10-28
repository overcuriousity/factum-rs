//! X.509 signatures through gpgsm (GnuPG's S/MIME tool): the signing certificate, its chain, detached CMS
//! signatures and their verification. Nothing here changes the examiner's keybox or trust list.
//!
//! gpgsm validates a chain whenever it signs or lists with validation, and in batch mode it then marks an
//! untrusted root as trusted on its own. So factum only signs when the root is already trusted (checked in the
//! trust list), and builds chains and verifies in a temporary home holding a copy of the trust list.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::signer::{GpgOutput, gpg_error, run_program};

/// gpgsm fingerprint of the certificate that signs containers
pub const X509_CERT_SETTING: &str = "x509_certificate";
/// PEM files with intermediate and root certificates, one path per line
pub const X509_CHAIN_SETTING: &str = "x509_chain_files";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct X509Cert {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    /// empty when gpgsm does not have the issuer's certificate
    pub issuer_fingerprint: String,
    pub not_before: String,
    pub not_after: String,
    pub can_sign: bool,
    /// gpgsm holds its private key
    pub has_secret: bool,
}

impl X509Cert {
    pub fn is_self_signed(&self) -> bool {
        !self.fingerprint.is_empty() && self.fingerprint == self.issuer_fingerprint
    }
}

/// The outcome of checking one X.509 signature.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct X509Check {
    /// the signature matches the data
    pub valid: bool,
    /// the chain ends at a root this machine's gpgsm trusts
    pub trusted: bool,
    pub signer_subject: Option<String>,
    pub root_subject: Option<String>,
    pub root_fingerprint: Option<String>,
    pub signed_utc: Option<String>,
    /// the signing certificate was valid when the signature was made
    pub valid_at_signing: bool,
    pub status: String,
}

/// 20261027T211004 (or a Unix time) as 2026-10-27T21:10:04Z.
fn colon_time(field: &str) -> String {
    if let Ok(time) = chrono::NaiveDateTime::parse_from_str(field, "%Y%m%dT%H%M%S") {
        return time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    }
    field
        .parse::<i64>()
        .ok()
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// Certificates from `gpgsm --with-colons --list-keys` / `--list-secret-keys`.
pub fn parse_cert_listing(listing: &str) -> Vec<X509Cert> {
    let mut certs: Vec<X509Cert> = Vec::new();
    let mut fingerprint_seen = false;
    let mut subject_seen = false;
    for line in listing.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let field = |index: usize| fields.get(index).copied().unwrap_or("");
        match field(0) {
            "crt" | "crs" => {
                certs.push(X509Cert {
                    issuer: field(9).to_string(),
                    not_before: colon_time(field(5)),
                    not_after: colon_time(field(6)),
                    can_sign: field(11).contains('s'),
                    has_secret: field(0) == "crs",
                    ..Default::default()
                });
                fingerprint_seen = false;
                subject_seen = false;
            }
            "fpr" if !fingerprint_seen => {
                if let Some(cert) = certs.last_mut() {
                    cert.fingerprint = field(9).to_string();
                    cert.issuer_fingerprint = field(12).to_string();
                    fingerprint_seen = true;
                }
            }
            "uid" if !subject_seen => {
                if let Some(cert) = certs.last_mut() {
                    cert.subject = field(9).to_string();
                    subject_seen = true;
                }
            }
            _ => {}
        }
    }
    certs
}

/// Whether a gpg-agent trust list marks the root as trusted (a `!` in front marks it as not trusted).
pub fn trusted_in(list: &str, fingerprint: &str) -> bool {
    list.lines().map(str::trim).any(|line| {
        !line.is_empty()
            && !line.starts_with('#')
            && !line.starts_with('!')
            && line
                .split_whitespace()
                .next()
                .is_some_and(|f| f.replace(':', "").eq_ignore_ascii_case(fingerprint))
    })
}

/// The PEM certificate blocks of an export, without gpgsm's informational header lines.
pub fn pem_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----")
            && let Some(block) = current.take()
        {
            blocks.push(block);
        }
    }
    blocks
}

/// %XX escapes as gpgconf writes them.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(byte) = text.get(at + 1..at + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A gpgsm home that lives as long as this value: no marking of roots, optionally a copy of a trust list.
struct TempHome {
    dir: tempfile::TempDir,
}

impl TempHome {
    fn new(trust_list: &str) -> Result<Self, String> {
        // short path: gpg-agent puts its socket here, and socket paths are limited to about 107 characters
        let builder = {
            let mut builder = tempfile::Builder::new();
            builder.prefix("fx-");
            builder
        };
        let dir = if cfg!(unix) && Path::new("/tmp").is_dir() {
            builder.tempdir_in("/tmp")
        } else {
            builder.tempdir()
        }
        .map_err(|e| format!("cannot create a temporary gpgsm home: {e}"))?;
        std::fs::write(dir.path().join("gpg-agent.conf"), "no-allow-mark-trusted\n")
            .and_then(|_| std::fs::write(dir.path().join("trustlist.txt"), trust_list))
            .map_err(|e| format!("cannot prepare a temporary gpgsm home: {e}"))?;
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.dir.path())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

pub struct Gpgsm {
    binary: Option<PathBuf>,
    home: Option<PathBuf>,
}

impl Gpgsm {
    /// `home`: the GnuPG home (None: gpgsm's default).
    pub fn new(home: Option<PathBuf>) -> Self {
        Self {
            binary: which::which("gpgsm").ok(),
            home,
        }
    }

    /// For tests: behaves as if gpgsm were not installed.
    pub fn unavailable() -> Self {
        Self {
            binary: None,
            home: None,
        }
    }

    pub fn available(&self) -> bool {
        self.binary.is_some()
    }

    fn run(&self, home: Option<&Path>, args: &[&str], input: &[u8]) -> Result<GpgOutput, String> {
        let binary = self
            .binary
            .as_ref()
            .ok_or("gpgsm is not installed or not on the PATH")?;
        let mut command = Command::new(binary);
        command.args(["--batch", "--no-tty", "--status-fd", "2"]);
        if let Some(home) = home.or(self.home.as_deref()) {
            command.arg("--homedir").arg(home);
        }
        command.args(args);
        run_program(command, input).map_err(|e| format!("gpgsm could not be run: {e}"))
    }

    /// The examiner's GnuPG home, where the trust list is.
    fn home_dir(&self) -> Option<PathBuf> {
        if let Some(home) = &self.home {
            return Some(home.clone());
        }
        let output = Command::new("gpgconf").args(["--list-dirs", "homedir"]).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        Some(PathBuf::from(percent_decode(text.trim())))
    }

    /// The trust lists gpg-agent reads: the examiner's and the system's.
    fn trust_list(&self) -> String {
        let mut list = String::new();
        let mut files: Vec<PathBuf> = self.home_dir().into_iter().map(|h| h.join("trustlist.txt")).collect();
        if self.home.is_none() {
            files.push(PathBuf::from("/etc/gnupg/trustlist.txt"));
        }
        for file in files {
            if let Ok(text) = std::fs::read_to_string(file) {
                list.push_str(&text);
                list.push('\n');
            }
        }
        list
    }

    fn certs(&self, home: Option<&Path>, args: &[&str]) -> Vec<X509Cert> {
        match self.run(home, args, b"") {
            Ok(output) => parse_cert_listing(&String::from_utf8_lossy(&output.stdout)),
            Err(e) => {
                log::warn!("Could not list X.509 certificates: {e}");
                Vec::new()
            }
        }
    }

    fn cert(&self, home: Option<&Path>, fingerprint: &str) -> Option<X509Cert> {
        self.certs(home, &["--with-colons", "--list-keys", fingerprint])
            .into_iter()
            .find(|c| c.fingerprint.eq_ignore_ascii_case(fingerprint))
    }

    fn export(&self, home: Option<&Path>, fingerprint: &str) -> Result<String, String> {
        let output = self.run(home, &["--armor", "--export", fingerprint], b"")?;
        pem_blocks(&String::from_utf8_lossy(&output.stdout))
            .into_iter()
            .next()
            .ok_or_else(|| format!("certificate {fingerprint} could not be exported"))
    }

    /// Certificates with a private key that can sign: the choices for signing containers.
    pub fn list_secret_certs(&self) -> Vec<X509Cert> {
        if !self.available() {
            return Vec::new();
        }
        self.certs(None, &["--with-colons", "--list-secret-keys"])
            .into_iter()
            .filter(|c| c.can_sign && c.has_secret)
            .collect()
    }

    /// From a certificate up to its root, following the issuer fingerprints in `home`; stops where one is missing.
    fn follow(&self, home: Option<&Path>, fingerprint: &str) -> Vec<X509Cert> {
        let mut chain: Vec<X509Cert> = Vec::new();
        let mut current = fingerprint.to_string();
        while chain.len() < 16 {
            let Some(cert) = self.cert(home, &current) else { break };
            let next = cert.issuer_fingerprint.clone();
            let done = cert.is_self_signed() || next.is_empty();
            chain.push(cert);
            if done || chain.iter().any(|c| c.fingerprint == next) {
                break;
            }
            current = next;
        }
        chain
    }

    /// Builds the chain in a temporary home from the examiner's keybox and `extra_pem`: (PEM of the signing
    /// certificate, its intermediates and the self-signed root, in that order; the root).
    fn build_chain(&self, fingerprint: &str, extra_pem: &[PathBuf]) -> Result<(String, X509Cert), String> {
        let mut pems = String::new();
        let known = self.follow(None, fingerprint);
        if known.is_empty() {
            return Err(format!("gpgsm has no certificate {fingerprint}."));
        }
        for cert in &known {
            pems.push_str(&self.export(None, &cert.fingerprint)?);
        }
        for file in extra_pem {
            let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
            pems.push_str(&text);
            pems.push('\n');
        }
        let temp = TempHome::new("")?;
        self.run(Some(temp.path()), &["--import"], pems.as_bytes())?;
        let chain = self.follow(Some(temp.path()), fingerprint);
        let last = chain
            .last()
            .cloned()
            .ok_or("the signing certificate could not be read")?;
        if !last.is_self_signed() {
            return Err(format!(
                "The certificate chain of {} is incomplete: the issuer {} is missing. Add its certificate as a \
                 chain file.",
                last.subject, last.issuer
            ));
        }
        let mut out = String::new();
        for cert in &chain {
            out.push_str(&self.export(Some(temp.path()), &cert.fingerprint)?);
        }
        Ok((out, last))
    }

    /// The certificate chain as PEM: the signing certificate, its intermediates and the self-signed root.
    pub fn chain(&self, fingerprint: &str, extra_pem: &[PathBuf]) -> Result<String, String> {
        self.build_chain(fingerprint, extra_pem).map(|(pem, _)| pem)
    }

    /// A detached CMS signature (PEM) over `data`, and the chain. Refused when the chain does not end at a root
    /// the examiner's gpgsm already trusts.
    pub fn sign_with_chain(
        &self,
        fingerprint: &str,
        data: &[u8],
        extra_pem: &[PathBuf],
    ) -> Result<(String, String), String> {
        if !self.available() {
            return Err("gpgsm is not installed or not on the PATH".into());
        }
        let (chain, root) = self.build_chain(fingerprint, extra_pem)?;
        if !trusted_in(&self.trust_list(), &root.fingerprint) {
            return Err(format!(
                "The root certificate {} ({}) is not trusted in gpgsm. Mark it trusted (trustlist.txt) after \
                 checking its fingerprint.",
                root.subject, root.fingerprint
            ));
        }
        // gpgsm checks the chain from its own keybox when it signs: certificates given only as chain files are
        // added to it (certificates only; whether a root is trusted stays with the trust list)
        if !extra_pem.is_empty() {
            let imported = self.run(None, &["--import"], chain.as_bytes())?;
            if self
                .follow(None, fingerprint)
                .last()
                .is_none_or(|c| !c.is_self_signed())
            {
                return Err(format!(
                    "The chain files could not be added to gpgsm: {}",
                    gpg_error(&imported.stderr)
                ));
            }
        }
        let output = self.run(
            None,
            &[
                "--disable-crl-checks",
                "--disable-ocsp",
                "--detach-sign",
                "--armor",
                "--include-certs",
                "-1",
                "--local-user",
                fingerprint,
            ],
            data,
        )?;
        if !output.has("SIG_CREATED") || output.stdout.is_empty() {
            return Err(format!("X.509 signing failed: {}", gpg_error(&output.stderr)));
        }
        Ok((String::from_utf8_lossy(&output.stdout).into_owned(), chain))
    }

    pub fn sign_detached(&self, fingerprint: &str, data: &[u8]) -> Result<String, String> {
        self.sign_with_chain(fingerprint, data, &[])
            .map(|(signature, _)| signature)
    }

    /// Checks a detached CMS signature over `data` against the examiner's trust list, offline (revocation is not
    /// checked), in a temporary home: the certificates the signature carries are not imported anywhere.
    pub fn verify_detached(&self, signature: &str, data: &[u8]) -> X509Check {
        let failed = |status: String| X509Check {
            status,
            ..Default::default()
        };
        if !self.available() {
            return failed("not checked: gpgsm is not installed".into());
        }
        let temp = match TempHome::new(&self.trust_list()) {
            Ok(temp) => temp,
            Err(e) => return failed(e),
        };
        let (signature_file, data_file) = (temp.path().join("signature.pem"), temp.path().join("data"));
        if let Err(e) = std::fs::write(&signature_file, signature).and_then(|_| std::fs::write(&data_file, data)) {
            return failed(format!("not checked: {e}"));
        }
        let (signature_arg, data_arg) = (signature_file.display().to_string(), data_file.display().to_string());
        let output = match self.run(
            Some(temp.path()),
            &[
                "--disable-crl-checks",
                "--disable-ocsp",
                "--verify",
                &signature_arg,
                &data_arg,
            ],
            b"",
        ) {
            Ok(output) => output,
            Err(e) => return failed(e),
        };
        let status = |key: &str| output.status.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        let mut check = X509Check {
            valid: output.has("GOODSIG") && !output.has("BADSIG") && !output.has("ERRSIG"),
            trusted: output.has("TRUST_FULLY") || output.has("TRUST_ULTIMATE"),
            signer_subject: status("GOODSIG").or(status("BADSIG")).map(|v| v[1..].join(" ")),
            ..Default::default()
        };
        if let Some(valid) = status("VALIDSIG") {
            check.signed_utc = valid.get(2).map(|t| colon_time(t)).filter(|t| !t.is_empty());
            let chain = self.follow(Some(temp.path()), &valid[0]);
            if let (Some(leaf), Some(signed)) = (chain.first(), &check.signed_utc) {
                check.valid_at_signing =
                    leaf.not_before <= *signed && (leaf.not_after.is_empty() || *signed <= leaf.not_after);
            }
            if let Some(root) = chain.last().filter(|c| c.is_self_signed()) {
                check.root_subject = Some(root.subject.clone());
                check.root_fingerprint = Some(root.fingerprint.clone());
            }
        }
        let root = check.root_subject.clone().unwrap_or_else(|| "unknown".into());
        check.status = if !check.valid {
            let reason = gpg_error(&output.stderr);
            format!(
                "bad signature{}",
                if reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({reason})")
                }
            )
        } else if !check.trusted {
            format!("good signature, but the root {root} is not trusted")
        } else {
            format!("good signature, root {root} trusted")
        } + "; revocation not checked (offline)";
        check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "/tmp/fx/pubring.kbx\n-------------------------\n\
crs::2048:1:08A9DF55298DF768:20261027T211004:20271027T211004:547C06::CN=Factum Test Root::sS::::::23:\n\
fpr:::::::::71290BCFA16D2AA7A03CDA3208A9DF55298DF768:::F70913322D949474B56BFD813E2F4F409F4A4646:\n\
grp:::::::::3E8E54C1468D0C8AED6377515B3BBB3A9E5CCBC8:\n\
uid:::::::::O=Lab,CN=Examiner One:::\n\
crt:u:2048:1:3E2F4F409F4A4646:20261027T211004:20361024T211004:1BD731::CN=Factum Test Root::cC::::::23:\n\
fpr:::::::::F70913322D949474B56BFD813E2F4F409F4A4646:::F70913322D949474B56BFD813E2F4F409F4A4646:\n\
uid:u::::::::CN=Factum Test Root:::\n";

    #[test]
    fn cert_listing_is_parsed() {
        let certs = parse_cert_listing(LISTING);
        assert_eq!(certs.len(), 2);
        assert_eq!(
            certs[0],
            X509Cert {
                fingerprint: "71290BCFA16D2AA7A03CDA3208A9DF55298DF768".into(),
                subject: "O=Lab,CN=Examiner One".into(),
                issuer: "CN=Factum Test Root".into(),
                issuer_fingerprint: "F70913322D949474B56BFD813E2F4F409F4A4646".into(),
                not_before: "2026-10-27T21:10:04Z".into(),
                not_after: "2027-10-27T21:10:04Z".into(),
                can_sign: true,
                has_secret: true,
            }
        );
        assert!(certs[1].is_self_signed() && !certs[1].has_secret && !certs[1].can_sign);
    }

    #[test]
    fn trust_list_lines() {
        let list = "# comment\n!AA:BB S\nF7:09:13:32 S relax\n  \n01020304 P\n";
        assert!(trusted_in(list, "F7091332"));
        assert!(trusted_in(list, "01020304"));
        assert!(!trusted_in(list, "AABB"));
        assert!(!trusted_in(list, "CCDD"));
    }

    #[test]
    fn pem_blocks_drop_export_headers() {
        let export =
            "Issuer ...: /CN=x\nSerial ...: 01\n\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(
            pem_blocks(export),
            vec!["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"]
        );
    }

    #[test]
    fn missing_gpgsm_signs_and_verifies_nothing() {
        let gpgsm = Gpgsm::unavailable();
        assert!(!gpgsm.available() && gpgsm.list_secret_certs().is_empty());
        assert!(gpgsm.sign_detached("F", b"x").is_err());
        assert!(!gpgsm.verify_detached("sig", b"x").valid);
    }
}
