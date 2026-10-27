//! Verification of a container file, read-only: every stored stream against its hashes, each state's
//! information.turtle against its hashes file, its signatures (GPG and X.509) and every closed state kept under
//! factum/history/<n>/. Never writes or truncates the file.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::Digest;

use super::AFF4_NS;
use super::stream;
use super::turtle::{self, Graph, Term};
use super::volume::{
    CER_X509, FileRecord, HASHES, KEY_GPG, SIG_GPG, SIG_X509, TURTLE, content_reader, file_records, history_member,
};
use super::x509::{Gpgsm, X509Check};
use super::zip64::{Archive, find_last_end, member_reader, read_archive};
use crate::error::{FactumError, Result};
use crate::services::Factum;
use crate::signer::Signer;
use crate::verifier::{Finding, Level, Ref, SignatureCheck, TRUSTED, worst};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFormat {
    /// AFF4-L v1.0, written by factum
    Factum,
    /// AFF4-L v1.0, written by another tool
    Aff4l,
    /// AFF4 before AFF4-L v1.0: not supported
    Legacy,
    NotAff4,
}

/// One state of the container: a closed one kept under factum/history/<n>/, or the current open one.
#[derive(Debug, Clone)]
pub struct StateResult {
    /// "close 1", "close 2 (current)", "current (open)"
    pub label: String,
    /// n for a closed state
    pub close: Option<u32>,
    /// true for the state the file is in now
    pub current: bool,
    pub turtle_sha256: String,
    pub files: usize,
    pub gpg: Option<SignatureCheck>,
    pub x509: Option<X509Check>,
    pub findings: Vec<Finding>,
}

/// How a container file relates to the case log of the open database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogMatch {
    pub container_id: i64,
    /// the close whose state the file is in; None for an open state
    pub matches_close: Option<u32>,
    /// what the log recorded for this container after that state
    pub recorded_after: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ContainerReport {
    pub path: PathBuf,
    pub uuid: Option<String>,
    pub format: ContainerFormat,
    pub states: Vec<StateResult>,
    /// every finding, those of the states included
    pub findings: Vec<Finding>,
    pub log: Option<LogMatch>,
    /// bytes after the last complete state (an interrupted addition)
    pub discarded_tail: u64,
    /// files whose content was checked
    pub checked_files: usize,
    /// the current state's metadata, for the log checks
    #[doc(hidden)]
    pub graph: Option<Graph>,
}

impl ContainerReport {
    pub fn overall(&self) -> Level {
        worst(&self.findings)
    }

    fn finding(&mut self, level: Level, code: &'static str, message: impl Into<String>) {
        self.findings.push(Finding::new(level, code, message, Ref::default()));
    }
}

fn read_member(file: &mut File, archive: &Archive, name: &str) -> Option<io::Result<Vec<u8>>> {
    let entry = archive.get(name)?;
    let mut data = Vec::new();
    Some(
        member_reader(file, entry)
            .and_then(|mut r| r.read_to_end(&mut data))
            .map(|_| data),
    )
}

fn hash_value(graph: &Graph, subject: &str, algorithm: &str) -> Option<String> {
    graph
        .objects(subject, &format!("{AFF4_NS}hash"))
        .find(|t| {
            t.datatype()
                .is_some_and(|d| d.rsplit(['#', '/']).next() == Some(algorithm))
        })
        .and_then(Term::value)
        .map(str::to_lowercase)
}

/// information.turtle against its hashes file (AFF4-L v1.0, 10.1); the hashes file is mandatory.
fn check_turtle_hashes(turtle: &[u8], hashes: Option<&[u8]>, label: &str) -> Vec<Finding> {
    let fail = |message: String| vec![Finding::new(Level::Fail, "turtle_hash", message, Ref::default())];
    let Some(hashes) = hashes else {
        return fail(format!("{label}: information.turtle.hashes is missing."));
    };
    let graph = match turtle::parse(&String::from_utf8_lossy(hashes)) {
        Ok(graph) => graph,
        Err(e) => return fail(format!("{label}: information.turtle.hashes cannot be read ({e}).")),
    };
    let mut findings = Vec::new();
    let mut checked = 0;
    for triple in graph.triples() {
        let Some(algorithm) = triple.object.datatype().and_then(|d| d.rsplit(['#', '/']).next()) else {
            continue;
        };
        let actual = match algorithm {
            "SHA256" => hex::encode(sha2::Sha256::digest(turtle)),
            "SHA512" => hex::encode(sha2::Sha512::digest(turtle)),
            _ => continue,
        };
        checked += 1;
        if triple.object.value().map(str::to_lowercase).as_deref() != Some(actual.as_str()) {
            findings.extend(fail(format!(
                "{label}: information.turtle does not match its {algorithm} in information.turtle.hashes."
            )));
        }
    }
    if checked == 0 {
        findings.extend(fail(format!(
            "{label}: information.turtle.hashes has no SHA-256 or SHA-512."
        )));
    }
    findings
}

fn gpg_check(signer: &dyn Signer, signature: &str, turtle: &[u8]) -> SignatureCheck {
    let result = signer.verify_detached(signature, turtle);
    SignatureCheck {
        present: true,
        late: false,
        late_signed_utc: None,
        valid: result.valid,
        covers_payload: result.valid,
        trusted: result.trust.as_deref().is_some_and(|t| TRUSTED.contains(&t)),
        status: result.status,
        key_id: result.key_id,
        fingerprint: result.fingerprint,
        username: result.username,
        trust: result.trust,
        signature_timestamp: result.signature_timestamp,
    }
}

fn x509_findings(check: &X509Check, label: &str) -> Vec<Finding> {
    let finding = |level, code, message: String| vec![Finding::new(level, code, message, Ref::default())];
    if check.status.starts_with("not checked") {
        return finding(
            Level::Warn,
            "not_checked",
            format!("{label}: X.509 signature {}.", check.status),
        );
    }
    if !check.valid {
        return finding(
            Level::Fail,
            "x509_invalid",
            format!("{label}: the X.509 signature is invalid ({}).", check.status),
        );
    }
    if !check.trusted {
        return finding(
            Level::Fail,
            "x509_untrusted",
            format!(
                "{label}: the X.509 signature is good, but its root {} ({}) is not trusted in gpgsm. Check the \
                 fingerprint and mark it trusted (trustlist.txt) if it is right.",
                check.root_subject.as_deref().unwrap_or("unknown"),
                check.root_fingerprint.as_deref().unwrap_or("unknown")
            ),
        );
    }
    if !check.valid_at_signing {
        return finding(
            Level::Fail,
            "x509_invalid",
            format!("{label}: the signing certificate was not valid when the signature was made."),
        );
    }
    Vec::new()
}

/// The signature members of a state: (gpg signature, x509 signature).
fn signature_names(close: Option<u32>) -> (String, String) {
    match close {
        Some(n) => (history_member(n, SIG_GPG), history_member(n, SIG_X509)),
        None => (SIG_GPG.to_string(), SIG_X509.to_string()),
    }
}

struct Parsed {
    close: Option<u32>,
    current: bool,
    turtle: Vec<u8>,
    hashes: Option<Vec<u8>>,
    graph: Graph,
}

/// Checks a container file. `progress` gets (bytes checked, bytes to check).
pub fn verify_file(
    path: &Path,
    signer: &dyn Signer,
    gpgsm: &Gpgsm,
    progress: &dyn Fn(u64, u64),
    cancel: &AtomicBool,
) -> Result<ContainerReport> {
    let mut report = ContainerReport {
        path: path.to_path_buf(),
        uuid: None,
        format: ContainerFormat::NotAff4,
        states: Vec::new(),
        findings: Vec::new(),
        log: None,
        discarded_tail: 0,
        checked_files: 0,
        graph: None,
    };
    let mut file =
        File::open(path).map_err(|e| FactumError::general(format!("{} cannot be read: {e}", path.display())))?;
    let len = file.seek(SeekFrom::End(0))?;
    let end = match find_last_end(&mut file, None) {
        Ok(Some(end)) => end,
        _ => {
            report.finding(
                Level::Fail,
                "not_aff4",
                format!("{} is not a ZIP (AFF4) container.", path.display()),
            );
            return Ok(report);
        }
    };
    if end < len {
        report.discarded_tail = len - end;
        report.finding(
            Level::Warn,
            "trailing_data",
            format!(
                "{} bytes after the last complete state (an interrupted addition); the last complete state was checked.",
                len - end
            ),
        );
    }
    let archive = read_archive(&mut file, end)?;
    let version = read_member(&mut file, &archive, "version.txt").and_then(|r| r.ok());
    let Some(version) = version.map(|v| String::from_utf8_lossy(&v).into_owned()) else {
        report.format = ContainerFormat::Legacy;
        report.finding(
            Level::Warn,
            "unsupported",
            "No version.txt: an AFF4 container from before AFF4-L v1.0. This format is not supported; nothing was checked.",
        );
        return Ok(report);
    };
    let property = |key: &str| {
        version
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim().to_string())
    };
    let (major, minor) = (
        property("major").unwrap_or_default(),
        property("minor").unwrap_or_default(),
    );
    if (major.as_str(), minor.as_str()) != ("2", "1") {
        report.format = ContainerFormat::Legacy;
        report.finding(
            Level::Warn,
            "unsupported",
            format!("AFF4 version {major}.{minor}: only AFF4-L v1.0 (2.1) is supported; nothing was checked."),
        );
        return Ok(report);
    }
    report.format = if property("tool").is_some_and(|t| t.starts_with("factum")) {
        ContainerFormat::Factum
    } else {
        ContainerFormat::Aff4l
    };
    report.uuid = read_member(&mut file, &archive, "container.description")
        .and_then(|r| r.ok())
        .map(|d| {
            String::from_utf8_lossy(&d)
                .trim()
                .trim_start_matches("aff4://")
                .to_string()
        });

    // the states: every closed one, and the current one when it is not the newest close
    let Some(Ok(current_turtle)) = read_member(&mut file, &archive, TURTLE) else {
        report.finding(
            Level::Fail,
            "turtle_hash",
            "information.turtle is missing or unreadable.",
        );
        return Ok(report);
    };
    let count = (1..)
        .take_while(|n| archive.get(&history_member(*n, TURTLE)).is_some())
        .last()
        .unwrap_or(0);
    let mut parsed = Vec::new();
    for n in 1..=count {
        let turtle = read_member(&mut file, &archive, &history_member(n, TURTLE))
            .transpose()?
            .unwrap_or_default();
        let hashes = read_member(&mut file, &archive, &history_member(n, HASHES)).transpose()?;
        parsed.push((Some(n), n == count && turtle == current_turtle, turtle, hashes));
    }
    if count == 0 || parsed.last().is_some_and(|p| !p.1) {
        let hashes = read_member(&mut file, &archive, HASHES).transpose()?;
        parsed.push((None, true, current_turtle.clone(), hashes));
    }
    let mut states = Vec::new();
    for (close, current, turtle, hashes) in parsed {
        match turtle::parse(&String::from_utf8_lossy(&turtle)) {
            Ok(graph) => states.push(Parsed {
                close,
                current,
                turtle,
                hashes,
                graph,
            }),
            Err(e) => report.finding(
                Level::Warn,
                "not_checked",
                format!("The metadata of a state cannot be read ({e}); its files were not checked."),
            ),
        }
    }

    // the signatures and hashes of each state
    for state in &states {
        let label = match (state.close, state.current) {
            (Some(n), true) => format!("close {n} (current)"),
            (Some(n), false) => format!("close {n}"),
            (None, _) => "current (open)".to_string(),
        };
        let mut result = StateResult {
            label: label.clone(),
            close: state.close,
            current: state.current,
            turtle_sha256: hex::encode(sha2::Sha256::digest(&state.turtle)),
            files: file_records(&state.graph).len(),
            gpg: None,
            x509: None,
            findings: check_turtle_hashes(&state.turtle, state.hashes.as_deref(), &label),
        };
        let (gpg_name, x509_name) = signature_names(state.close);
        if let Some(signature) = read_member(&mut file, &archive, &gpg_name).transpose()? {
            let check = gpg_check(signer, &String::from_utf8_lossy(&signature), &state.turtle);
            result.findings.extend(Factum::signature_findings(
                &check,
                &format!("Container state '{label}'"),
                Ref::default(),
            ));
            result.gpg = Some(check);
        }
        if let Some(signature) = read_member(&mut file, &archive, &x509_name).transpose()? {
            let check = gpgsm.verify_detached(&String::from_utf8_lossy(&signature), &state.turtle);
            result
                .findings
                .extend(x509_findings(&check, &format!("Container state '{label}'")));
            result.x509 = Some(check);
        }
        if state.close.is_some()
            && result.gpg.is_none()
            && result.x509.is_none()
            && report.format == ContainerFormat::Factum
        {
            result.findings.push(Finding::new(
                Level::Fail,
                "unsigned",
                format!("Container state '{label}' is not signed."),
                Ref::default(),
            ));
        }
        // the root signatures of a closed current state are that close's
        if let (Some(n), true) = (state.close, state.current) {
            for name in [SIG_GPG, KEY_GPG, SIG_X509, CER_X509] {
                let root = read_member(&mut file, &archive, name).transpose()?;
                let kept = read_member(&mut file, &archive, &history_member(n, name)).transpose()?;
                if root.is_some() && root != kept {
                    result.findings.push(Finding::new(
                        Level::Fail,
                        "history",
                        format!("{name} differs from the one kept for close {n}."),
                        Ref::default(),
                    ));
                }
            }
        }
        report.findings.extend(result.findings.clone());
        report.states.push(result);
    }

    // a closed state's files are the same files, byte for byte, in every later state
    let newest = states.last().map(|s| file_records(&s.graph)).unwrap_or_default();
    let newest: HashMap<&str, &FileRecord> = newest.iter().map(|r| (r.arn.as_str(), r)).collect();
    for state in &states {
        let Some(n) = state.close else { continue };
        for record in file_records(&state.graph) {
            match newest.get(record.arn.as_str()) {
                None => report.finding(
                    Level::Fail,
                    "history",
                    format!("{} (close {n}) is no longer listed in the newest state.", record.path),
                ),
                Some(now) if **now != record => report.finding(
                    Level::Fail,
                    "history",
                    format!(
                        "{}: its metadata in close {n} differs from the newest state.",
                        record.path
                    ),
                ),
                Some(_) => {}
            }
        }
    }

    // every stored stream, once, against the hashes its newest state gives
    if let Some(state) = states.last() {
        let graph = &state.graph;
        let stored: Vec<FileRecord> = file_records(graph);
        let total: u64 = stored
            .iter()
            .filter(|r| !r.metadata_only && r.link.is_none())
            .map(|r| r.size)
            .sum();
        let mut done = 0u64;
        progress(0, total);
        for record in &stored {
            if cancel.load(Ordering::Relaxed) {
                return Err(FactumError::general("Verification cancelled."));
            }
            let reader = match content_reader(&mut file, &archive, graph, &record.arn) {
                Ok(Some(reader)) => reader,
                Ok(None) => continue,
                Err(e) => {
                    report.finding(
                        Level::Fail,
                        "stream_hash",
                        format!("{}: its content cannot be read ({e}).", record.path),
                    );
                    continue;
                }
            };
            let mut reader = reader;
            let report_progress = |read: u64| progress(done + read, total);
            match stream::hash_only(&mut reader, &report_progress, cancel) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    return Err(FactumError::general("Verification cancelled."));
                }
                Err(e) => report.finding(
                    Level::Fail,
                    "stream_hash",
                    format!("{}: its content cannot be read ({e}).", record.path),
                ),
                Ok((size, digests)) => {
                    report.checked_files += 1;
                    let mut compared = 0;
                    for (algorithm, actual) in digests.typed() {
                        if let Some(expected) = hash_value(graph, &record.arn, algorithm) {
                            compared += 1;
                            if expected != actual {
                                report.finding(
                                    Level::Fail,
                                    "stream_hash",
                                    format!("{}: the content does not match its {algorithm}.", record.path),
                                );
                            }
                        }
                    }
                    if size != record.size {
                        report.finding(
                            Level::Fail,
                            "stream_hash",
                            format!("{}: {size} bytes stored, {} listed.", record.path, record.size),
                        );
                    }
                    if compared == 0 {
                        report.finding(
                            Level::Warn,
                            "not_checked",
                            format!(
                                "{}: no MD5, SHA-1 or SHA-256 to check its content against.",
                                record.path
                            ),
                        );
                    }
                }
            }
            done += record.size;
        }
        progress(total, total);
        report.graph = Some(state.graph.clone());
    }
    Ok(report)
}
