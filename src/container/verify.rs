//! Verification of a container file, read-only: every stored stream against its hashes, each state's
//! information.turtle against its hashes file, its signatures (GPG and X.509) and every closed state kept under
//! factum/history/<n>/. Never writes or truncates the file.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::Digest;

use super::stream;
use super::turtle::{self, Graph, Term};
use super::volume::{
    CER_X509, FileRecord, HASHES, KEY_GPG, SIG_GPG, SIG_X509, TURTLE, content_reader, file_records, history_member,
};
use super::x509::{Gpgsm, X509Check};
use super::zip64::{Archive, find_last_end, member_bytes, read_archive};
use super::{AFF4_NS, AFF4L_NS, FACTUM_NS};
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
    Some(member_bytes(file, archive.get(name)?))
}

/// A member's content; one that is listed but cannot be read is a failure (with `code`), not an error.
fn read_checked(
    file: &mut File,
    archive: &Archive,
    name: &str,
    code: &'static str,
    findings: &mut Vec<Finding>,
) -> Option<Vec<u8>> {
    match read_member(file, archive, name)? {
        Ok(data) => Some(data),
        Err(e) => {
            findings.push(Finding::new(
                Level::Fail,
                code,
                format!("{name} cannot be read ({e})."),
                Ref::default(),
            ));
            None
        }
    }
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

/// What a file's content came to.
enum Content {
    /// nothing stored (metadata only, a link, a folder)
    None,
    Hashed(u64, stream::Digests),
    /// stored in a way factum does not read (another codec, special map targets)
    NotChecked(String),
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact).ok()
}

fn number(graph: &Graph, subject: &str, local: &str) -> Option<u64> {
    graph.first_value(subject, &format!("{AFF4_NS}{local}"))?.parse().ok()
}

fn hash_reader(reader: &mut dyn Read, progress: &dyn Fn(u64), cancel: &AtomicBool) -> io::Result<Content> {
    let (size, digests) = stream::hash_only(reader, progress, cancel)?;
    Ok(Content::Hashed(size, digests))
}

/// The content of `arn`: a ZipSegment, an ImageStream, data in the metadata (`aff4:dataStream`, also as the
/// standard's example spells it, `dataSteam`), a stream it names with `dataStream`, or a Map.
fn hash_content(
    file: &mut File,
    archive: &Archive,
    graph: &Graph,
    arn: &str,
    progress: &dyn Fn(u64),
    cancel: &AtomicBool,
) -> io::Result<Content> {
    let unsupported = |e: &io::Error| e.kind() == io::ErrorKind::Unsupported;
    match content_reader(file, archive, graph, arn) {
        Ok(Some(mut reader)) => return hash_reader(&mut reader, progress, cancel),
        Ok(None) => {}
        Err(e) if unsupported(&e) => return Ok(Content::NotChecked(e.to_string())),
        Err(e) => return Err(e),
    }
    for property in ["dataStream", "dataSteam"] {
        for object in graph.objects(arn, &format!("{AFF4_NS}{property}")) {
            match object {
                Term::Literal { value, .. } => {
                    let data = base64_decode(value)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "its data is not Base64"))?;
                    return hash_reader(&mut data.as_slice(), progress, cancel);
                }
                Term::Iri(target) if target != arn => {
                    if graph.has_type(target, &format!("{AFF4_NS}Map")) {
                        return hash_map(file, archive, graph, target, progress, cancel);
                    }
                    return match content_reader(file, archive, graph, target) {
                        Ok(Some(mut reader)) => hash_reader(&mut reader, progress, cancel),
                        Ok(None) => Ok(Content::NotChecked(format!("its stream {target} is not stored here"))),
                        Err(e) if unsupported(&e) => Ok(Content::NotChecked(e.to_string())),
                        Err(e) => Err(e),
                    };
                }
                Term::Iri(_) => {}
            }
        }
    }
    if graph.has_type(arn, &format!("{AFF4_NS}Map")) {
        return hash_map(file, archive, graph, arn, progress, cancel);
    }
    Ok(Content::None)
}

/// Maps claiming more are not hashed (1 PiB: hashing that many zeros alone would take days).
const MAX_MAP_SIZE: u64 = 1 << 50;

/// A Map (AFF4 Standard v1.0): `<map>/map` entries (u64 mapped offset, u64 length, u64 target offset, u32 target)
/// over the targets in `<map>/idx`; what no entry covers reads as zeros.
fn hash_map(
    file: &mut File,
    archive: &Archive,
    graph: &Graph,
    map: &str,
    progress: &dyn Fn(u64),
    cancel: &AtomicBool,
) -> io::Result<Content> {
    let missing = |what: &str| io::Error::new(io::ErrorKind::NotFound, format!("{map}: {what} is missing"));
    let read_arn = |file: &mut File, arn: String| archive.get_arn(&arn).map(|entry| member_bytes(file, entry));
    let entries = read_arn(file, format!("{map}/map")).ok_or_else(|| missing("its map"))??;
    let index = read_arn(file, format!("{map}/idx")).ok_or_else(|| missing("its idx"))??;
    let targets: Vec<String> = String::from_utf8_lossy(&index)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let mut ranges: Vec<(u64, u64, u64, u32)> = entries
        .as_chunks::<28>()
        .0
        .iter()
        .map(|e| {
            (
                u64::from_le_bytes(e[0..8].try_into().unwrap()),
                u64::from_le_bytes(e[8..16].try_into().unwrap()),
                u64::from_le_bytes(e[16..24].try_into().unwrap()),
                u32::from_le_bytes(e[24..28].try_into().unwrap()),
            )
        })
        .collect();
    ranges.sort();
    let damaged = |why: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{map}: damaged map ({why})"));
    let mut end_of_ranges = 0u64;
    for (mapped, length, _, _) in &ranges {
        end_of_ranges = end_of_ranges.max(mapped.checked_add(*length).ok_or_else(|| damaged("offsets overflow"))?);
    }
    let size = number(graph, map, "size").unwrap_or(end_of_ranges);
    if end_of_ranges > size {
        return Err(damaged("ranges beyond its size"));
    }
    if size > MAX_MAP_SIZE {
        return Ok(Content::NotChecked(format!("its map claims {size} bytes")));
    }
    let mut hasher = stream::Hasher::new();
    let mut position = 0u64;
    let zeros = vec![0u8; 1 << 16];
    // what no range covers is hashed too, so its progress shows and it can be cancelled like stored content
    let fill = |hasher: &mut stream::Hasher, at: u64, count: u64, byte: u8| -> io::Result<()> {
        let block = if byte == 0 {
            zeros.clone()
        } else {
            vec![byte; zeros.len()]
        };
        let mut done = 0u64;
        while done < count {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            let take = (count - done).min(block.len() as u64) as usize;
            hasher.update(&block[..take]);
            done += take as u64;
            if done.is_multiple_of(1 << 24) {
                progress(at + done);
            }
        }
        Ok(())
    };
    for (mapped, length, target_offset, target) in ranges {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if mapped > position {
            fill(&mut hasher, position, mapped - position, 0)?;
        }
        let target = targets.get(target as usize).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{map}: target {target} is not in its idx"),
            )
        })?;
        if target == &format!("{AFF4_NS}Zero") {
            fill(&mut hasher, mapped, length, 0)?;
        } else if let Some(byte) = target
            .strip_prefix(&format!("{AFF4_NS}SymbolicStream"))
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            fill(&mut hasher, mapped, length, byte)?;
        } else if target.starts_with(AFF4_NS) {
            return Ok(Content::NotChecked(format!("its map uses {target}")));
        } else if graph.has_type(target, &format!("{AFF4_NS}ImageStream")) {
            let compression = graph
                .objects(target, &format!("{AFF4_NS}compressionMethod"))
                .find_map(|t| t.iri().or(t.value()))
                .unwrap_or(stream::ZLIB)
                .to_string();
            let mut reader = match stream::open_image_stream(
                file,
                archive,
                target,
                number(graph, target, "size").unwrap_or(u64::MAX),
                number(graph, target, "chunkSize").unwrap_or(stream::CHUNK_SIZE),
                number(graph, target, "chunksInSegment").unwrap_or(stream::CHUNKS_PER_SEGMENT),
                &compression,
            ) {
                Ok(reader) => reader,
                Err(e) if e.kind() == io::ErrorKind::Unsupported => return Ok(Content::NotChecked(e.to_string())),
                Err(e) => return Err(e),
            };
            reader.seek(SeekFrom::Start(target_offset))?;
            let read = std::io::copy(&mut (&mut reader).take(length), &mut HashWriter(&mut hasher))?;
            if read != length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{target} ends early"),
                ));
            }
        } else {
            return Ok(Content::NotChecked(format!(
                "its map target {target} is not an ImageStream"
            )));
        }
        position = mapped + length;
        progress(position);
    }
    if size > position {
        fill(&mut hasher, position, size - position, 0)?;
    }
    Ok(Content::Hashed(size.max(position), hasher.finish()))
}

struct HashWriter<'h>(&'h mut stream::Hasher);

impl io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Joins the secondary information stores (`aff4l:imports`, AFF4-L v1.0 section 9) into the graph, each checked
/// against the hash the primary store gives for it (section 10.2).
fn resolve_imports(file: &mut File, archive: &Archive, graph: &mut Graph, uuid: &str, label: &str) -> Vec<Finding> {
    let volume = format!("aff4://{uuid}");
    let fail = |message: String| Finding::new(Level::Fail, "turtle_hash", message, Ref::default());
    let mut findings = Vec::new();
    let mut done = std::collections::HashSet::new();
    for _ in 0..16 {
        let imports: Vec<String> = graph
            .objects(&volume, &format!("{AFF4L_NS}imports"))
            .filter_map(Term::iri)
            .filter(|i| !done.contains(*i))
            .map(str::to_string)
            .collect();
        if imports.is_empty() {
            break;
        }
        for store in imports {
            done.insert(store.clone());
            let name = super::member_name(&store, &volume);
            let Some(Ok(data)) = read_member(file, archive, &name) else {
                findings.push(fail(format!("{label}: the secondary store {name} is missing.")));
                continue;
            };
            let expected: Vec<(&str, String)> = [("SHA512", "SHA512"), ("SHA256", "SHA256")]
                .into_iter()
                .filter_map(|(algorithm, _)| hash_value(graph, &store, algorithm).map(|v| (algorithm, v)))
                .collect();
            if expected.is_empty() {
                findings.push(fail(format!("{label}: the primary store gives no hash for {name}.")));
            }
            for (algorithm, value) in expected {
                let actual = match algorithm {
                    "SHA512" => hex::encode(sha2::Sha512::digest(&data)),
                    _ => hex::encode(sha2::Sha256::digest(&data)),
                };
                if actual != value {
                    findings.push(fail(format!("{label}: {name} does not match its {algorithm}.")));
                }
            }
            match turtle::parse(&String::from_utf8_lossy(&data)) {
                Ok(secondary) => graph.extend(secondary),
                Err(e) => findings.push(Finding::new(
                    Level::Warn,
                    "not_checked",
                    format!("{label}: {name} cannot be read ({e}); its files were not checked."),
                    Ref::default(),
                )),
            }
        }
    }
    findings
}

fn plural_files(count: usize) -> String {
    format!("{count} file{}", if count == 1 { "" } else { "s" })
}

struct Parsed {
    close: Option<u32>,
    current: bool,
    turtle: Vec<u8>,
    hashes: Option<Vec<u8>>,
    /// None when information.turtle cannot be parsed: its hashes and signatures are still checked
    graph: Option<Graph>,
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
    for name in archive.duplicates() {
        report.finding(
            Level::Fail,
            "duplicate_member",
            format!("{name} is listed more than once; ZIP tools may read a different one than this check did."),
        );
    }
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
    if archive.get("information.hdt").is_some() {
        report.finding(
            Level::Warn,
            "not_checked",
            "information.hdt (an AFF4/HDT store) was not read; the Turtle metadata was checked.",
        );
    }
    let mut next_part = path.as_os_str().to_owned();
    next_part.push(".1");
    if Path::new(&next_part).exists() {
        report.finding(
            Level::Warn,
            "not_checked",
            format!(
                "This is one part of a multi-part container ({} exists); only this part was checked.",
                Path::new(&next_part).display()
            ),
        );
    }
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
    // every closed state kept, numbered from 1 without gaps: a gap is a closed state that was removed
    let closes: std::collections::BTreeSet<u32> = archive
        .entries
        .iter()
        .filter_map(|e| {
            let name = std::str::from_utf8(&e.name).ok()?;
            name.strip_prefix("factum/history/")?
                .strip_suffix(&format!("/{TURTLE}"))?
                .parse()
                .ok()
        })
        .collect();
    let count = closes.last().copied().unwrap_or(0);
    for missing in (1..count).filter(|n| !closes.contains(n)) {
        report.finding(
            Level::Fail,
            "history",
            format!("The closed state of close {missing} is missing from the container."),
        );
    }
    let mut parsed = Vec::new();
    for n in closes.iter().copied() {
        let turtle = read_checked(
            &mut file,
            &archive,
            &history_member(n, TURTLE),
            "history",
            &mut report.findings,
        )
        .unwrap_or_default();
        let hashes = read_checked(
            &mut file,
            &archive,
            &history_member(n, HASHES),
            "turtle_hash",
            &mut report.findings,
        );
        parsed.push((Some(n), n == count && turtle == current_turtle, turtle, hashes));
    }
    if count == 0 || parsed.last().is_some_and(|p| !p.1) {
        let hashes = read_checked(&mut file, &archive, HASHES, "turtle_hash", &mut report.findings);
        parsed.push((None, true, current_turtle.clone(), hashes));
    }
    let mut states = Vec::new();
    for (close, current, turtle, hashes) in parsed {
        let label = close.map_or("current".to_string(), |n| format!("close {n}"));
        // metadata that cannot be parsed is a failure; the state's hashes and signatures are still checked below
        let graph = match turtle::parse(&String::from_utf8_lossy(&turtle)) {
            Ok(mut graph) => {
                let uuid = report.uuid.clone().unwrap_or_default();
                let findings = resolve_imports(&mut file, &archive, &mut graph, &uuid, &label);
                report.findings.extend(findings);
                Some(graph)
            }
            Err(e) => {
                report.finding(
                    Level::Fail,
                    "turtle_hash",
                    format!("{label}: information.turtle cannot be read ({e}); its files were not checked."),
                );
                None
            }
        };
        states.push(Parsed {
            close,
            current,
            turtle,
            hashes,
            graph,
        });
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
            files: state.graph.as_ref().map_or(0, |g| file_records(g).len()),
            gpg: None,
            x509: None,
            findings: check_turtle_hashes(&state.turtle, state.hashes.as_deref(), &label),
        };
        let (gpg_name, x509_name) = signature_names(state.close);
        if let Some(signature) = read_checked(
            &mut file,
            &archive,
            &gpg_name,
            "signature_invalid",
            &mut result.findings,
        ) {
            let check = gpg_check(signer, &String::from_utf8_lossy(&signature), &state.turtle);
            result.findings.extend(Factum::signature_findings(
                &check,
                &format!("Container state '{label}'"),
                Ref::default(),
            ));
            result.gpg = Some(check);
        }
        if let Some(signature) = read_checked(&mut file, &archive, &x509_name, "x509_invalid", &mut result.findings) {
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
                let root = read_checked(&mut file, &archive, name, "history", &mut result.findings);
                let kept = read_checked(
                    &mut file,
                    &archive,
                    &history_member(n, name),
                    "history",
                    &mut result.findings,
                );
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

    // the states whose metadata could be read; the others failed above
    let newest_readable = states.last().is_some_and(|s| s.graph.is_some());
    let states: Vec<(&Parsed, &Graph)> = states.iter().filter_map(|s| s.graph.as_ref().map(|g| (s, g))).collect();
    // a closed state's files are the same files, described alike (storage included), in every later state
    if let Some(&(newest, newest_graph)) = states.last() {
        let listed: HashMap<String, FileRecord> = file_records(newest_graph)
            .into_iter()
            .map(|r| (r.arn.clone(), r))
            .collect();
        for &(state, graph) in &states[..states.len() - 1] {
            let Some(n) = state.close else { continue };
            for record in file_records(graph) {
                if !listed.contains_key(&record.arn) {
                    report.finding(
                        Level::Fail,
                        "history",
                        format!("{} (close {n}) is no longer listed in the newest state.", record.path),
                    );
                } else if graph.about(&record.arn) != newest_graph.about(&record.arn) {
                    report.finding(
                        Level::Fail,
                        "history",
                        format!(
                            "{}: its metadata in close {n} differs from the newest state.",
                            record.path
                        ),
                    );
                }
            }
        }
        // what was added after the last close is not signed yet; a container never closed is not signed at all
        if report.format == ContainerFormat::Factum && newest.close.is_none() {
            let closed = states
                .iter()
                .rev()
                .find(|(s, _)| s.close.is_some())
                .map(|(_, g)| file_records(g).len());
            let open = file_records(newest_graph).len();
            let message = match closed {
                Some(closed) => {
                    let added = open.saturating_sub(closed);
                    format!(
                        "{} added after the last close {} not signed yet; closing the container signs {}.",
                        plural_files(added),
                        if added == 1 { "is" } else { "are" },
                        if added == 1 { "it" } else { "them" }
                    )
                }
                None => format!(
                    "The container was never closed: none of its {} is signed.",
                    plural_files(open)
                ),
            };
            report.finding(Level::Warn, "not_signed", message);
        }
    }

    // every stored stream, once, against the hashes its newest state gives
    if let Some(&(_, graph)) = states.last() {
        let stored: Vec<FileRecord> = file_records(graph);
        // metadata-only files and links have no content to read: they count for neither total nor progress
        let counted = |r: &FileRecord| !r.metadata_only && r.link.is_none();
        let total: u64 = stored.iter().filter(|r| counted(r)).map(|r| r.size).sum();
        let mut done = 0u64;
        progress(0, total);
        for record in &stored {
            if cancel.load(Ordering::Relaxed) {
                return Err(FactumError::general("Verification cancelled."));
            }
            let name = if record.path.is_empty() {
                record.arn.clone()
            } else {
                record.path.clone()
            };
            let findings_before = report.findings.len();
            // content longer than its listed size (a damaged or crafted container) never shows more than all of it
            let report_progress = |read: u64| progress((done + read).min(total), total);
            match hash_content(&mut file, &archive, graph, &record.arn, &report_progress, cancel) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    return Err(FactumError::general("Verification cancelled."));
                }
                Err(e) => report.finding(
                    Level::Fail,
                    "stream_hash",
                    format!("{name}: its content cannot be read ({e})."),
                ),
                Ok(Content::None)
                    if report.format == ContainerFormat::Factum && !record.metadata_only && record.link.is_none() =>
                {
                    report.finding(
                        Level::Fail,
                        "stream_hash",
                        format!("{name}: no stored content, though it is neither metadata only nor a link."),
                    );
                }
                Ok(Content::None) => {}
                Ok(Content::NotChecked(why)) => {
                    report.finding(Level::Warn, "not_checked", format!("{name}: not checked ({why})."));
                }
                Ok(Content::Hashed(size, digests)) => {
                    report.checked_files += 1;
                    let mut compared = 0;
                    for (algorithm, actual) in digests.typed() {
                        if let Some(expected) = hash_value(graph, &record.arn, algorithm) {
                            compared += 1;
                            if expected != actual {
                                report.finding(
                                    Level::Fail,
                                    "stream_hash",
                                    format!("{name}: the content does not match its {algorithm}."),
                                );
                            }
                        }
                    }
                    if number(graph, &record.arn, "size").is_some_and(|listed| listed != size) {
                        report.finding(
                            Level::Fail,
                            "stream_hash",
                            format!("{name}: {size} bytes stored, {} listed.", record.size),
                        );
                    }
                    let block_hashes = graph
                        .objects(&record.arn, &format!("{AFF4_NS}hash"))
                        .any(|t| t.datatype().is_some_and(|d| d.contains("blockMapHash")))
                        || graph
                            .objects(&record.arn, &format!("{AFF4_NS}blockMapHash"))
                            .next()
                            .is_some();
                    if block_hashes {
                        report.finding(
                            Level::Warn,
                            "not_checked",
                            format!("{name}: block map hashes are not checked; its linear hash was."),
                        );
                    }
                    if compared == 0 {
                        report.finding(
                            Level::Warn,
                            "not_checked",
                            format!("{name}: no MD5, SHA-1 or SHA-256 to check its content against."),
                        );
                    }
                }
            }
            // a damaged copy that was added again (Add Again) is a known, logged fact: a warning, not a failure
            let replacement = graph
                .objects(&record.arn, &format!("{FACTUM_NS}replacedBy"))
                .find_map(|t| match t {
                    Term::Iri(arn) => Some(arn.clone()),
                    Term::Literal { .. } => None,
                });
            if let Some(replacement) = replacement {
                let failed = report.findings[findings_before..]
                    .iter()
                    .any(|f| f.code == "stream_hash");
                if failed {
                    let tail = report.findings.split_off(findings_before);
                    report
                        .findings
                        .extend(tail.into_iter().filter(|f| f.code != "stream_hash"));
                    let by = graph
                        .first_value(&replacement, &format!("{AFF4L_NS}originalPathName"))
                        .unwrap_or(&replacement)
                        .to_string();
                    report.finding(
                        Level::Warn,
                        "replaced_copy",
                        format!(
                            "{name}: the content does not match its hashes; replaced by a copy added again ({by})."
                        ),
                    );
                }
            }
            if counted(record) {
                done += record.size;
            }
        }
        progress(total, total);
        if newest_readable {
            report.graph = Some(graph.clone());
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests_support {
    use super::*;
    use crate::container::stream::{CHUNK_SIZE, CHUNKS_PER_SEGMENT};
    use crate::container::volume::hashes_bytes;
    use crate::container::zip64::Appender;
    use crate::container::{AFF4L_NS, RDF_NS, XSD_NS};
    use crate::signer::FakeSigner;

    pub const VOLUME: &str = "7cbb47d0-b04c-42bc-8c04-87b7782739ad";

    pub fn aff4(local: &str) -> String {
        format!("{AFF4_NS}{local}")
    }

    pub fn typed(value: impl ToString, datatype: &str) -> Term {
        Term::Literal {
            value: value.to_string(),
            datatype: Some(datatype.to_string()),
        }
    }

    pub fn a(graph: &mut Graph, subject: &str, class: &str) {
        graph.add(subject, &format!("{RDF_NS}type"), Term::Iri(class.to_string()));
    }

    /// A container another tool could have written: version 2.1, `tool=other`, the graph and extra members.
    pub fn foreign(
        dir: &tempfile::TempDir,
        graph: &Graph,
        extra: &mut dyn FnMut(&mut Appender),
        version: Option<&str>,
    ) -> PathBuf {
        let path = dir.path().join("c.aff4l");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut app = Appender::new(file, 0, Vec::new()).unwrap();
        if let Some(version) = version {
            app.add_bytes("version.txt", 0, version.as_bytes()).unwrap();
        }
        app.add_bytes("container.description", 0, format!("aff4://{VOLUME}").as_bytes())
            .unwrap();
        let turtle = turtle::write(graph, &[("aff4", AFF4_NS), ("aff4l", AFF4L_NS), ("xsd", XSD_NS)]);
        app.add_bytes(TURTLE, 8, turtle.as_bytes()).unwrap();
        app.add_bytes(HASHES, 0, &hashes_bytes(VOLUME, turtle.as_bytes()))
            .unwrap();
        extra(&mut app);
        app.finish(&[], format!("aff4://{VOLUME}").as_bytes()).unwrap();
        path
    }

    pub fn check(path: &Path) -> ContainerReport {
        verify_file(
            path,
            &FakeSigner::new(false),
            &Gpgsm::unavailable(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap()
    }

    pub fn codes(report: &ContainerReport, level: Level) -> Vec<&'static str> {
        report
            .findings
            .iter()
            .filter(|f| f.level == level)
            .map(|f| f.code)
            .collect()
    }

    pub const V21: Option<&str> = Some("major=2\nminor=1\ntool=other 1.0\n");

    pub fn image_stream(graph: &mut Graph, arn: &str, size: usize, compression: &str) {
        a(graph, arn, &aff4("ImageStream"));
        graph.add(arn, &aff4("size"), typed(size, &format!("{XSD_NS}long")));
        graph.add(arn, &aff4("chunkSize"), typed(CHUNK_SIZE, &format!("{XSD_NS}int")));
        graph.add(
            arn,
            &aff4("chunksInSegment"),
            typed(CHUNKS_PER_SEGMENT, &format!("{XSD_NS}int")),
        );
        graph.add(arn, &aff4("compressionMethod"), Term::Iri(compression.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use crate::container::stream::{CHUNKS_PER_SEGMENT, ZLIB, store_image_stream};
    use crate::container::{AFF4L_NS, XSD_NS};
    use base64::Engine;

    fn in_metadata(graph: &mut Graph, arn: &str, property: &str, content: &[u8], sha1: &str) {
        a(graph, arn, &aff4("FileImage"));
        graph.add(arn, &aff4("size"), typed(content.len(), &format!("{XSD_NS}long")));
        let encoded = base64::engine::general_purpose::STANDARD.encode(content);
        graph.add(arn, &aff4(property), typed(encoded, &format!("{XSD_NS}base64Binary")));
        graph.add(arn, &aff4("hash"), typed(sha1, &aff4("SHA1")));
    }

    #[test]
    fn in_metadata_stream_verified() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        let sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"; // "hello world"
        in_metadata(&mut graph, "aff4://a", "dataStream", b"hello world", sha1);
        in_metadata(&mut graph, "aff4://b", "dataSteam", b"hello world", sha1); // the standard's spelling
        let report = check(&foreign(&dir, &graph, &mut |_| {}, V21));
        assert_eq!(report.format, ContainerFormat::Aff4l);
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        assert_eq!(report.checked_files, 2);

        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        in_metadata(&mut graph, "aff4://a", "dataStream", b"hello world!", sha1);
        let report = check(&foreign(&dir, &graph, &mut |_| {}, V21));
        assert_eq!(codes(&report, Level::Fail), vec!["stream_hash"]);
    }

    #[test]
    fn zip_segments_are_found_by_the_standard_member_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        let sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"; // "hello world"
        let relative = format!("aff4://{VOLUME}/docs/a.txt");
        for arn in [relative.as_str(), "aff4://0b4c6f2e-1a2b-4c3d-8e9f-001122334455"] {
            a(&mut graph, arn, &aff4("FileImage"));
            a(&mut graph, arn, &aff4("ZipSegment"));
            graph.add(arn, &aff4("size"), typed(11, &format!("{XSD_NS}long")));
            graph.add(arn, &aff4("hash"), typed(sha1, &aff4("SHA1")));
        }
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes("docs/a.txt", 8, b"hello world").unwrap();
                app.add_bytes("aff4%3A%2F%2F0b4c6f2e-1a2b-4c3d-8e9f-001122334455", 8, b"hello world")
                    .unwrap();
            },
            V21,
        );
        let report = check(&path);
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        assert_eq!(report.checked_files, 2);
    }

    #[test]
    fn map_over_image_stream_verified() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        // mapped: data[0..50000], a gap of zeros, then data[50000..90000]
        let mut expected = data[..50_000].to_vec();
        expected.extend(vec![0u8; 10_000]);
        expected.extend(&data[50_000..90_000]);
        let mut graph = Graph::default();
        image_stream(&mut graph, "aff4://stream", data.len(), ZLIB);
        let file = "aff4://file";
        a(&mut graph, file, &aff4("FileImage"));
        a(&mut graph, file, &aff4("Map"));
        graph.add(file, &aff4("dependentStream"), Term::Iri("aff4://stream".into()));
        graph.add(file, &aff4("size"), typed(expected.len(), &format!("{XSD_NS}long")));
        graph.add(
            file,
            &aff4("hash"),
            typed(hex::encode(sha2::Sha256::digest(&expected)), &aff4("SHA256")),
        );
        graph.add(file, &aff4("hash"), typed("00", &aff4("blockMapHashSHA512")));
        let mut map = Vec::new();
        for (mapped, length, target) in [(0u64, 50_000u64, 0u64), (60_000, 40_000, 50_000)] {
            map.extend(mapped.to_le_bytes());
            map.extend(length.to_le_bytes());
            map.extend(target.to_le_bytes());
            map.extend(0u32.to_le_bytes());
        }
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                store_image_stream(
                    app,
                    "aff4%3A%2F%2Fstream",
                    &mut data.as_slice(),
                    CHUNKS_PER_SEGMENT,
                    &|_| {},
                    &AtomicBool::new(false),
                )
                .unwrap();
                app.add_bytes("aff4%3A%2F%2Ffile/map", 0, &map).unwrap();
                app.add_bytes("aff4%3A%2F%2Ffile/idx", 0, b"aff4://stream\n").unwrap();
            },
            V21,
        );
        let report = check(&path);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
        assert_eq!(
            codes(&report, Level::Warn),
            vec!["not_checked"],
            "{:?}",
            report.findings
        );
        assert_eq!(report.checked_files, 1);
    }

    #[test]
    fn snappy_stream_not_checked() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        image_stream(&mut graph, "aff4://s", 10, "http://code.google.com/p/snappy/");
        a(&mut graph, "aff4://s", &aff4("FileImage"));
        graph.add("aff4://s", &aff4("hash"), typed("00", &aff4("SHA1")));
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes("aff4%3A%2F%2Fs/00000000", 0, b"compressed").unwrap();
                app.add_bytes("aff4%3A%2F%2Fs/00000000.index", 0, &[0; 12]).unwrap();
            },
            V21,
        );
        let report = check(&path);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
        assert_eq!(codes(&report, Level::Warn), vec!["not_checked"]);
    }

    fn with_import(dir: &tempfile::TempDir, hash_of_secondary: Option<String>) -> PathBuf {
        let mut secondary = Graph::default();
        in_metadata(
            &mut secondary,
            "aff4://a",
            "dataStream",
            b"hello world",
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        );
        let secondary = turtle::write(&secondary, &[("aff4", AFF4_NS), ("xsd", XSD_NS)]);
        let store = format!("aff4://{VOLUME}/information.turtle.2");
        let mut graph = Graph::default();
        a(&mut graph, &format!("aff4://{VOLUME}"), &aff4("ZipVolume"));
        graph.add(
            &format!("aff4://{VOLUME}"),
            &format!("{AFF4L_NS}imports"),
            Term::Iri(store.clone()),
        );
        let hash = hash_of_secondary.unwrap_or_else(|| hex::encode(sha2::Sha512::digest(secondary.as_bytes())));
        graph.add(&store, &aff4("hash"), typed(hash, &aff4("SHA512")));
        foreign(
            dir,
            &graph,
            &mut |app| {
                app.add_bytes("information.turtle.2", 8, secondary.as_bytes()).unwrap();
            },
            V21,
        )
    }

    #[test]
    fn imports_are_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let report = check(&with_import(&dir, None));
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        assert_eq!(report.checked_files, 1); // the imported store's file joined the graph
        let dir = tempfile::tempdir().unwrap();
        let report = check(&with_import(&dir, Some("00".repeat(64))));
        assert_eq!(codes(&report, Level::Fail), vec!["turtle_hash"]);
    }

    #[test]
    fn legacy_container_is_unsupported() {
        for version in [None, Some("major=1\nminor=0\ntool=pyaff4\n")] {
            let dir = tempfile::tempdir().unwrap();
            let report = check(&foreign(&dir, &Graph::default(), &mut |_| {}, version));
            assert_eq!(report.format, ContainerFormat::Legacy);
            assert_eq!(codes(&report, Level::Warn), vec!["unsupported"]);
            assert!(codes(&report, Level::Fail).is_empty());
        }
    }

    #[test]
    fn hdt_and_multipart_not_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = foreign(
            &dir,
            &Graph::default(),
            &mut |app| {
                app.add_bytes("information.hdt", 0, b"HDT").unwrap();
            },
            V21,
        );
        let report = check(&path);
        assert_eq!(codes(&report, Level::Warn), vec!["not_checked"]);
        std::fs::write(dir.path().join("c.aff4l.1"), b"part two").unwrap();
        let report = check(&path);
        assert_eq!(codes(&report, Level::Warn), vec!["not_checked", "not_checked"]);
    }

    #[test]
    fn not_a_zip_is_not_aff4() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.aff4l");
        std::fs::write(&path, vec![0u8; 5000]).unwrap();
        let report = check(&path);
        assert_eq!(
            (report.format, codes(&report, Level::Fail)),
            (ContainerFormat::NotAff4, vec!["not_aff4"])
        );
    }
}

#[cfg(test)]
mod crafted {
    //! Containers built to break a reader: Verify must report them, not crash or run out of memory.
    use super::tests_support::*;
    use super::*;
    use crate::container::XSD_NS;
    use crate::container::stream::ZLIB;
    use std::io::Write;

    #[test]
    fn implausible_chunk_size_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        image_stream(&mut graph, "aff4://s", 10, ZLIB);
        graph.add(
            "aff4://s",
            &aff4("chunkSize"),
            typed("99999999999999", &format!("{XSD_NS}int")),
        );
        a(&mut graph, "aff4://s", &aff4("FileImage"));
        graph.add("aff4://s", &aff4("hash"), typed("00", &aff4("SHA1")));
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes("aff4%3A%2F%2Fs/00000000", 0, b"x").unwrap();
                app.add_bytes("aff4%3A%2F%2Fs/00000000.index", 0, &[0; 12]).unwrap();
            },
            V21,
        );
        let report = check(&path);
        assert!(!codes(&report, Level::Fail).is_empty() || !codes(&report, Level::Warn).is_empty());
    }

    #[test]
    fn a_chunk_that_inflates_beyond_its_size_is_damaged() {
        let dir = tempfile::tempdir().unwrap();
        let mut bomb = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        bomb.write_all(&vec![0u8; 8 << 20]).unwrap();
        let bomb = bomb.finish().unwrap();
        let mut index = 0u64.to_le_bytes().to_vec();
        index.extend((bomb.len() as u32).to_le_bytes());
        let mut graph = Graph::default();
        image_stream(&mut graph, "aff4://s", 1000, ZLIB);
        a(&mut graph, "aff4://s", &aff4("FileImage"));
        graph.add("aff4://s", &aff4("hash"), typed("00", &aff4("SHA1")));
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes("aff4%3A%2F%2Fs/00000000", 0, &bomb).unwrap();
                app.add_bytes("aff4%3A%2F%2Fs/00000000.index", 0, &index).unwrap();
            },
            V21,
        );
        let report = check(&path);
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "stream_hash")
            .expect("a failure");
        assert!(fail.message.contains("damaged"), "{}", fail.message);
    }

    #[test]
    fn map_offsets_that_overflow_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        let file = "aff4://file";
        a(&mut graph, file, &aff4("FileImage"));
        a(&mut graph, file, &aff4("Map"));
        graph.add(file, &aff4("size"), typed(100, &format!("{XSD_NS}long")));
        graph.add(file, &aff4("hash"), typed("00", &aff4("SHA1")));
        let mut map = Vec::new();
        map.extend((u64::MAX - 5).to_le_bytes());
        map.extend(10u64.to_le_bytes());
        map.extend(0u64.to_le_bytes());
        map.extend(0u32.to_le_bytes());
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes("aff4%3A%2F%2Ffile/map", 0, &map).unwrap();
                app.add_bytes("aff4%3A%2F%2Ffile/idx", 0, format!("{AFF4_NS}Zero\n").as_bytes())
                    .unwrap();
            },
            V21,
        );
        let report = check(&path);
        assert!(
            codes(&report, Level::Fail).contains(&"stream_hash"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn a_map_of_implausible_size_is_not_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        let file = "aff4://file";
        a(&mut graph, file, &aff4("FileImage"));
        a(&mut graph, file, &aff4("Map"));
        graph.add(file, &aff4("size"), typed(1u64 << 62, &format!("{XSD_NS}long")));
        graph.add(file, &aff4("hash"), typed("00", &aff4("SHA1")));
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes("aff4%3A%2F%2Ffile/map", 0, b"").unwrap();
                app.add_bytes("aff4%3A%2F%2Ffile/idx", 0, b"").unwrap();
            },
            V21,
        );
        let started = std::time::Instant::now();
        let report = check(&path);
        assert!(started.elapsed().as_secs() < 10);
        let warning = report
            .findings
            .iter()
            .find(|f| f.code == "not_checked")
            .expect("not checked");
        assert!(warning.message.contains("claims"), "{}", warning.message);
    }
}
