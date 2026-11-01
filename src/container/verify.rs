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
    CER_X509, FileRecord, HASHES, KEY_GPG, SIG_GPG, SIG_X509, SIGNATURE_MEMBERS, TURTLE, content_reader, file_records,
    history_member,
};
use super::x509::{Gpgsm, X509Check, first_fingerprint};
use super::zip64::{
    Archive, MAX_IN_MEMORY, MAX_METADATA_BUDGET, MAX_SIGNATURE_MEMBER, METADATA_BUDGET_PER_STORED_BYTE,
    MIN_METADATA_BUDGET, find_last_end, find_newest_end, member_bytes_and_crc, member_bytes_up_to, read_archive,
    search_gave_up,
};
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

    /// Whether the check stopped because a container's metadata did not fit: nothing past that point was judged.
    pub(crate) fn stopped_on_budget(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.code == "too_large" && f.level == Level::Fail)
    }

    pub(crate) fn finding(&mut self, level: Level, code: &'static str, message: impl Into<String>) {
        self.findings.push(Finding::new(level, code, message, Ref::default()));
    }
}

const HISTORY: &[u8] = b"factum/history/";
const GIB: f64 = (1u64 << 30) as f64;

/// Whether the check reads a member of this name as a state's metadata: the root's, or that of a close.
fn is_read_metadata(name: &[u8]) -> bool {
    let leaf = |name: &[u8]| name == TURTLE.as_bytes() || name == HASHES.as_bytes();
    if leaf(name) {
        return true;
    }
    let Some(rest) = name.strip_prefix(HISTORY) else {
        return false;
    };
    let mut parts = rest.splitn(2, |byte| *byte == b'/');
    let number = parts.next().and_then(|n| std::str::from_utf8(n).ok());
    number
        .and_then(|text| text.parse::<u32>().ok().filter(|n| *n > 0 && n.to_string() == text))
        .is_some()
        && parts.next().is_some_and(leaf)
}

/// Whether factum wrote this container, by what only its files hold. The tool named in version.txt says nothing: that
/// file is not signed, and what it would decide is whether a missing signature counts.
fn factum_layout(archive: &Archive) -> bool {
    ["factum/README.txt", "verify_container.py"]
        .iter()
        .chain(&SIGNATURE_MEMBERS)
        .any(|name| archive.get(name).is_some())
        || archive.entries.iter().any(|e| e.name.starts_with(HISTORY))
}

/// How many members under factum/history/ belong to none of `closes`, and the first of them.
fn outside_closes(archive: &Archive, closes: &std::collections::BTreeSet<u32>) -> (usize, Option<String>) {
    let inside = |name: &[u8]| {
        let rest = &name[HISTORY.len()..];
        let number = rest.split(|byte| *byte == b'/').next().unwrap_or_default();
        rest.len() > number.len()
            && std::str::from_utf8(number)
                .ok()
                .and_then(|text| text.parse().ok().filter(|n: &u32| n.to_string() == text))
                .is_some_and(|n| closes.contains(&n))
    };
    let mut outside = archive
        .entries
        .iter()
        .filter(|e| e.name.starts_with(HISTORY) && !inside(&e.name))
        .map(|e| e.name_lossy());
    let first = outside.next();
    (outside.count() + usize::from(first.is_some()), first)
}

/// What one check may hold of a container's metadata, all its states and their graphs together. It grows with what the
/// file stores of it, so a real large container fits, and a few MiB that inflate to many members do not.
struct Budget {
    left: u64,
    limit: u64,
    /// spent: the check stopped there, which says nothing about the container
    exhausted: bool,
}

impl Budget {
    fn new(limit: u64) -> Self {
        Self {
            left: limit,
            limit,
            exhausted: false,
        }
    }

    /// For a file of `len` bytes: a directory can claim any compressed size, the file cannot hold more than it holds.
    /// What counts is what the check reads, so stored bytes that nothing reads buy nothing.
    fn for_archive(archive: &Archive, len: u64) -> Self {
        let stored = archive
            .entries
            .iter()
            .filter(|e| is_read_metadata(&e.name))
            .fold(0u64, |sum, e| sum.saturating_add(e.compressed_size))
            .min(len);
        Self::new(
            stored
                .saturating_mul(METADATA_BUDGET_PER_STORED_BYTE)
                .clamp(MIN_METADATA_BUDGET, MAX_METADATA_BUDGET),
        )
    }

    fn stop(&mut self) -> FactumError {
        self.exhausted = true;
        FactumError::general("the metadata does not fit its budget")
    }

    fn take(&mut self, count: u64) -> Result<()> {
        match self.left.checked_sub(count) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => Err(self.stop()),
        }
    }

    /// The graph of a member's bytes, or why it is none; an error only when the budget is spent. Bytes that are not
    /// UTF-8 are not refused here: the hashes and signatures say what they are worth. Each may become three.
    fn parse(&mut self, bytes: &[u8]) -> Result<std::result::Result<Graph, String>> {
        if std::str::from_utf8(bytes).is_err() {
            self.take(bytes.len() as u64 * 3)?;
        }
        match turtle::parse_within(&String::from_utf8_lossy(bytes), &mut self.left) {
            Err(e) if e == turtle::TOO_MUCH => Err(self.stop()),
            parsed => Ok(parsed),
        }
    }

    /// The one finding of a check that stopped here.
    fn finding(&self) -> String {
        format!(
            "The metadata of this container needs more memory than this check sets aside ({:.1} GiB in all, {:.1} GiB \
             for one member), so the check stopped here and did not finish. That alone does not mean the container was \
             altered.",
            self.limit as f64 / GIB,
            MAX_IN_MEMORY as f64 / GIB
        )
    }
}

#[cfg(test)]
thread_local! {
    /// A test seam: the budget of the next check.
    static BUDGET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// A member's content; one that is listed but cannot be read is a failure (with `code`), not an error. So is a CRC-32
/// that differs, and the content then still counts: what is wrong may be the field, and the checks say the rest.
fn read_limited(
    file: &mut File,
    archive: &Archive,
    name: &str,
    code: &'static str,
    findings: &mut Vec<Finding>,
    limit: u64,
) -> Option<Vec<u8>> {
    match member_bytes_up_to(file, archive.get(name)?, limit) {
        Ok((data, crc_matches)) => {
            let message = format!("{name}: CRC-32 differs from the central directory.");
            if !crc_matches && !findings.iter().any(|f| f.message == message) {
                findings.push(Finding::new(Level::Fail, code, message, Ref::default()));
            }
            Some(data)
        }
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

/// `read_limited` for what is held for the rest of the check, so it comes out of `budget`.
fn read_checked(
    file: &mut File,
    archive: &Archive,
    name: &str,
    code: &'static str,
    findings: &mut Vec<Finding>,
    budget: &mut Budget,
) -> Result<Option<Vec<u8>>> {
    if archive.get(name).is_some_and(|entry| entry.size > MAX_IN_MEMORY) {
        return Err(budget.stop());
    }
    let data = read_limited(file, archive, name, code, findings, MAX_IN_MEMORY);
    if let Some(data) = &data {
        budget.take(data.len() as u64)?;
    }
    Ok(data)
}

/// A signature member: looked at once and let go, so the budget has no part in it, and there is no reason for one to be
/// large. A public key can be, with its certifications.
fn read_signature(
    file: &mut File,
    archive: &Archive,
    name: &str,
    code: &'static str,
    findings: &mut Vec<Finding>,
) -> Option<Vec<u8>> {
    let limit = if name.ends_with(KEY_GPG) {
        MAX_IN_MEMORY
    } else {
        MAX_SIGNATURE_MEMBER
    };
    read_limited(file, archive, name, code, findings, limit)
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
fn check_turtle_hashes(turtle: &[u8], hashes: Option<&[u8]>, label: &str, budget: &mut Budget) -> Result<Vec<Finding>> {
    let fail = |message: String| vec![Finding::new(Level::Fail, "turtle_hash", message, Ref::default())];
    let Some(hashes) = hashes else {
        return Ok(fail(format!("{label}: information.turtle.hashes is missing.")));
    };
    let graph = match budget.parse(hashes)? {
        Ok(graph) => graph,
        Err(e) => {
            return Ok(fail(format!(
                "{label}: information.turtle.hashes cannot be read ({e})."
            )));
        }
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
    Ok(findings)
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
        key_expired: result.key_expired,
        signing_subkey: result.signing_subkey,
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
            format!(
                "{label}: the signing certificate or one in its chain was not valid at the time the signature states."
            ),
        );
    }
    if check.expired {
        return finding(
            Level::Warn,
            "x509_expired",
            format!(
                "{label}: the X.509 signature is good, but its certificate or one in its chain has expired since. \
                 That they were valid at signing rests on the signing time the signer stated; nothing confirms it."
            ),
        );
    }
    Vec::new()
}

/// The certificate that made a signature against the first of the chain stored beside it: any certificate below a
/// trusted root makes a good signature, so a signature alone does not say it is the examiner's.
fn stored_certificate_findings(check: &X509Check, chain: &[u8], label: &str) -> Vec<Finding> {
    let Some(signer) = &check.fingerprint else {
        return Vec::new();
    };
    let stored = first_fingerprint(&String::from_utf8_lossy(chain));
    if stored
        .as_ref()
        .is_some_and(|stored| stored.eq_ignore_ascii_case(signer))
    {
        return Vec::new();
    }
    vec![Finding::new(
        Level::Fail,
        "x509_mismatch",
        format!(
            "{label}: the X.509 signature was made by certificate {signer}, not by the one stored in the container \
             ({}).",
            stored.as_deref().unwrap_or("none readable")
        ),
        Ref::default(),
    )]
}

/// The signature members of a state: (gpg signature, x509 signature, x509 certificate chain).
fn signature_names(close: Option<u32>) -> (String, String, String) {
    match close {
        Some(n) => (
            history_member(n, SIG_GPG),
            history_member(n, SIG_X509),
            history_member(n, CER_X509),
        ),
        None => (SIG_GPG.to_string(), SIG_X509.to_string(), CER_X509.to_string()),
    }
}

/// What a file's content came to.
enum Content {
    /// nothing stored (metadata only, a link, a folder)
    None,
    /// size, digests and the members that differ from the directory's CRC-32
    Hashed(u64, stream::Digests, Vec<String>),
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
    let (size, digests, crc) = stream::hash_stored(reader, progress, cancel)?;
    Ok(Content::Hashed(size, digests, crc.into_iter().collect()))
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
    let mut crc = Vec::new();
    let mut read_arn = |file: &mut File, arn: String| {
        archive.get_arn(&arn).map(|entry| {
            let (data, crc_matches) = member_bytes_and_crc(file, entry)?;
            if !crc_matches {
                crc.push(entry.name_lossy());
            }
            Ok::<_, io::Error>(data)
        })
    };
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
            crc.extend(reader.crc_mismatch().map(str::to_string));
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
    crc.sort();
    crc.dedup();
    Ok(Content::Hashed(size.max(position), hasher.finish(), crc))
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
fn resolve_imports(
    file: &mut File,
    archive: &Archive,
    graph: &mut Graph,
    uuid: &str,
    label: &str,
    layout: bool,
    budget: &mut Budget,
) -> Result<Vec<Finding>> {
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
            if archive.get(&name).is_none() {
                findings.push(fail(format!("{label}: the secondary store {name} is missing.")));
                continue;
            }
            let Some(data) = read_checked(file, archive, &name, "turtle_hash", &mut findings, budget)? else {
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
            match budget.parse(&data)? {
                Ok(secondary) => graph.extend(secondary),
                // what another tool wrote may just be beyond this reader; factum writes nothing it cannot read
                Err(e) if layout => findings.push(fail(format!("{label}: {name} cannot be read ({e})."))),
                Err(e) => findings.push(Finding::new(
                    Level::Warn,
                    "not_checked",
                    format!("{label}: {name} cannot be read ({e}); its files were not checked."),
                    Ref::default(),
                )),
            }
        }
    }
    Ok(findings)
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
    let mut budget = Budget::new(MIN_METADATA_BUDGET);
    match check_file(&mut report, &mut budget, path, signer, gpgsm, progress, cancel) {
        // what is left unread stays unjudged: no rule may read anything into it
        Err(_) if budget.exhausted => {
            let level = if report.format == ContainerFormat::Factum {
                Level::Fail
            } else {
                Level::Warn
            };
            report.finding(level, "too_large", budget.finding());
            Ok(report)
        }
        Err(e) => Err(e),
        Ok(()) => Ok(report),
    }
}

fn check_file(
    report: &mut ContainerReport,
    budget: &mut Budget,
    path: &Path,
    signer: &dyn Signer,
    gpgsm: &Gpgsm,
    progress: &dyn Fn(u64, u64),
    cancel: &AtomicBool,
) -> Result<()> {
    let mut file =
        File::open(path).map_err(|e| FactumError::general(format!("{} cannot be read: {e}", path.display())))?;
    let len = file.seek(SeekFrom::End(0))?;
    let end = match find_last_end(&mut file, None) {
        Ok(Some(end)) => end,
        Ok(None) => {
            let message = if search_gave_up(&mut file)? {
                format!(
                    "No complete state was found in {}: the search through its end records stopped at its limit, so \
                     this does not say what the file is.",
                    path.display()
                )
            } else {
                format!("{} is not a ZIP (AFF4) container.", path.display())
            };
            report.finding(Level::Fail, "not_aff4", message);
            return Ok(());
        }
        Err(e) => return Err(FactumError::general(format!("{} cannot be read: {e}", path.display()))),
    };
    if end < len {
        report.discarded_tail = len - end;
        match find_newest_end(&mut file, Some(end)) {
            Ok(_) => report.finding(
                Level::Warn,
                "trailing_data",
                format!(
                    "{} bytes after the last complete state (an interrupted addition); the last complete state was \
                     checked.",
                    len - end
                ),
            ),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => report.finding(
                Level::Fail,
                "trailing_data",
                format!(
                    "{} bytes after the last complete state may be more than an interrupted addition ({e}); the last \
                     complete state was checked.",
                    len - end
                ),
            ),
            Err(e) => return Err(FactumError::general(format!("{} cannot be read: {e}", path.display()))),
        }
    }
    let archive = read_archive(&mut file, end)?;
    *budget = Budget::for_archive(&archive, len);
    #[cfg(test)]
    if let Some(limit) = BUDGET.with(std::cell::Cell::take) {
        *budget = Budget::new(limit);
    }
    for name in archive.duplicates() {
        report.finding(
            Level::Fail,
            "duplicate_member",
            format!("{name} is listed more than once; ZIP tools may read a different one than this check did."),
        );
    }
    let layout = factum_layout(&archive);
    if layout {
        report.format = ContainerFormat::Factum;
    }
    // before anything can end the check: it is what ties the file to its case log
    let description = read_checked(
        &mut file,
        &archive,
        "container.description",
        "history",
        &mut report.findings,
        budget,
    )?;
    let volume = description.map_or_else(|| archive.volume(), |d| String::from_utf8_lossy(&d).trim().to_string());
    report.uuid = Some(volume.trim_start_matches("aff4://").to_string()).filter(|uuid| !uuid.is_empty());
    if layout && archive.get("container.description").is_none() {
        report.finding(
            Level::Fail,
            "history",
            "container.description is missing, which ties this container to its case log.",
        );
    } else if layout && volume != archive.volume() {
        report.finding(
            Level::Fail,
            "history",
            format!(
                "container.description names {volume}, the ZIP comment {}.",
                archive.volume()
            ),
        );
    }
    let version = read_checked(
        &mut file,
        &archive,
        "version.txt",
        "history",
        &mut report.findings,
        budget,
    )?;
    let version = version.map(|v| String::from_utf8_lossy(&v).into_owned());
    let property = |key: &str| {
        version
            .as_deref()
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim().to_string())
    };
    let (major, minor) = (
        property("major").unwrap_or_default(),
        property("minor").unwrap_or_default(),
    );
    if (major.as_str(), minor.as_str()) != ("2", "1") {
        let found = match version {
            Some(_) => format!("AFF4 version {major}.{minor}"),
            None => "No version.txt".to_string(),
        };
        if !layout {
            report.format = ContainerFormat::Legacy;
            report.finding(
                Level::Warn,
                "unsupported",
                format!("{found}: only AFF4-L v1.0 (2.1) is supported; nothing was checked."),
            );
            return Ok(());
        }
        report.finding(
            Level::Fail,
            "unsupported",
            format!("{found}, though factum wrote this container; it was checked all the same."),
        );
    }
    report.format = if layout {
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

    // the states: every closed one, and the current one when it is not the newest close
    let current_turtle = read_checked(&mut file, &archive, TURTLE, "turtle_hash", &mut report.findings, budget)?;
    let Some(current_turtle) = current_turtle else {
        if archive.get(TURTLE).is_none() {
            report.finding(Level::Fail, "turtle_hash", "information.turtle is missing.");
        }
        return Ok(());
    };
    // every closed state kept, numbered from 1 without gaps: a gap is a closed state that was removed
    let mut closes: std::collections::BTreeSet<u32> = archive
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
    if closes.remove(&0) {
        report.finding(
            Level::Fail,
            "history",
            "A closed state numbered 0: closes are numbered from 1; it was not checked.",
        );
    }
    let count = closes.last().copied().unwrap_or(0);
    // from one kept state to the next: a crafted number must not make this count up to it
    let mut next = 1;
    for &n in &closes {
        match n - next {
            0 => {}
            1 => report.finding(
                Level::Fail,
                "history",
                format!("The closed state of close {next} is missing from the container."),
            ),
            _ => report.finding(
                Level::Fail,
                "history",
                format!(
                    "The closed states of closes {next} to {} are missing from the container.",
                    n - 1
                ),
            ),
        }
        next = n.saturating_add(1);
    }
    // a close that cannot be read is no close: what it held must not pass for something else, or for nothing
    if let (count @ 1.., Some(first)) = outside_closes(&archive, &closes) {
        report.finding(
            Level::Fail,
            "history",
            format!("{count} member(s) under factum/history/ belong to no closed state ({first})."),
        );
    }
    let mut parsed = Vec::new();
    let mut close_unread = false;
    for n in closes.iter().copied() {
        let turtle = read_checked(
            &mut file,
            &archive,
            &history_member(n, TURTLE),
            "history",
            &mut report.findings,
            budget,
        )?;
        close_unread |= turtle.is_none();
        let turtle = turtle.unwrap_or_default();
        let hashes = read_checked(
            &mut file,
            &archive,
            &history_member(n, HASHES),
            "turtle_hash",
            &mut report.findings,
            budget,
        )?;
        parsed.push((Some(n), n == count && turtle == current_turtle, turtle, hashes));
    }
    if count == 0 || parsed.last().is_some_and(|p| !p.1) {
        let hashes = read_checked(&mut file, &archive, HASHES, "turtle_hash", &mut report.findings, budget)?;
        budget.take(current_turtle.len() as u64)?;
        parsed.push((None, true, current_turtle.clone(), hashes));
    }
    let mut states = Vec::new();
    for (close, current, turtle, hashes) in parsed {
        let label = close.map_or("current".to_string(), |n| format!("close {n}"));
        // metadata that cannot be parsed is a failure; the state's hashes and signatures are still checked below
        let graph = match budget.parse(&turtle)? {
            Ok(mut graph) => {
                let uuid = report.uuid.clone().unwrap_or_default();
                let findings = resolve_imports(&mut file, &archive, &mut graph, &uuid, &label, layout, budget)?;
                report.findings.extend(findings);
                // the signed metadata says which volume it describes
                if layout && !graph.has_type(&volume, &format!("{AFF4_NS}ZipVolume")) {
                    report.finding(
                        Level::Fail,
                        "history",
                        format!("{label}: information.turtle does not describe the volume {volume}."),
                    );
                }
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
            findings: check_turtle_hashes(&state.turtle, state.hashes.as_deref(), &label, budget)?,
        };
        let (gpg_name, x509_name, chain_name) = signature_names(state.close);
        if let Some(signature) = read_signature(
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
        if let Some(signature) = read_signature(&mut file, &archive, &x509_name, "x509_invalid", &mut result.findings) {
            let check = gpgsm.verify_detached(&String::from_utf8_lossy(&signature), &state.turtle);
            let what = format!("Container state '{label}'");
            result.findings.extend(x509_findings(&check, &what));
            if let Some(chain) = read_signature(&mut file, &archive, &chain_name, "x509_invalid", &mut result.findings)
            {
                result
                    .findings
                    .extend(stored_certificate_findings(&check, &chain, &what));
            } else if archive.get(&chain_name).is_none() {
                result.findings.push(Finding::new(
                    Level::Warn,
                    "x509_no_certificate",
                    format!("{what}: an X.509 signature without the certificate chain stored beside it."),
                    Ref::default(),
                ));
            }
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
                let root = read_signature(&mut file, &archive, name, "history", &mut result.findings);
                let kept = read_signature(
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
            // what readers of the standard go by; the close's copy above is another member
            let root = read_checked(&mut file, &archive, HASHES, "turtle_hash", &mut result.findings, budget)?;
            if root.is_some() || archive.get(HASHES).is_none() {
                let at_root = format!("{label}, at the root");
                let findings = check_turtle_hashes(&state.turtle, root.as_deref(), &at_root, budget)?;
                result.findings.extend(findings);
            }
        }
        // every state factum writes takes the root signatures away, so an open state has none: one that does is a
        // close that was taken out of the directory
        if state.close.is_none()
            && !close_unread
            && let Some(name) = SIGNATURE_MEMBERS.iter().find(|name| archive.get(name).is_some())
        {
            result.findings.push(Finding::new(
                Level::Fail,
                "history",
                format!("{name} is at the root of a state that was never closed."),
                Ref::default(),
            ));
        }
        report.findings.extend(result.findings.clone());
        report.states.push(result);
    }

    // the states whose metadata could be read; the others failed above
    let mut parsed = states;
    let states: Vec<(&Parsed, &Graph)> = parsed.iter().filter_map(|s| s.graph.as_ref().map(|g| (s, g))).collect();
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
        if newest.close.is_none() {
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
            let mut crc_differs = Vec::new();
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
                // factum stores files in one way, so another is no format it cannot read: the hashes must not be
                // skipped by naming one
                Ok(Content::NotChecked(why)) if report.format == ContainerFormat::Factum => {
                    report.finding(Level::Fail, "stream_hash", format!("{name}: not checked ({why})."));
                }
                Ok(Content::NotChecked(why)) => {
                    report.finding(Level::Warn, "not_checked", format!("{name}: not checked ({why})."));
                }
                Ok(Content::Hashed(size, digests, crc)) => {
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
                    crc_differs = crc;
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
            let mut damage_replaced = false;
            if let Some(replacement) = replacement {
                let failed = report.findings[findings_before..]
                    .iter()
                    .any(|f| f.code == "stream_hash");
                damage_replaced = failed;
                if failed {
                    let tail = report.findings.split_off(findings_before);
                    report
                        .findings
                        .extend(tail.into_iter().filter(|f| f.code != "stream_hash"));
                    let by = graph
                        .first_value(&replacement, &format!("{AFF4L_NS}originalPathName"))
                        .unwrap_or(&replacement)
                        .to_string();
                    // a replacement counts only when it is a file of this state with the same hashes and size
                    let same = stored.iter().find(|r| r.arn == replacement).is_some_and(|new| {
                        (&new.md5, &new.sha1, &new.sha256, new.size)
                            == (&record.md5, &record.sha1, &record.sha256, record.size)
                    });
                    if same {
                        report.finding(
                            Level::Warn,
                            "replaced_copy",
                            format!(
                                "{name}: the content does not match its hashes; replaced by a copy added again ({by})."
                            ),
                        );
                    } else {
                        report.finding(
                            Level::Fail,
                            "stream_hash",
                            format!(
                                "{name}: the content does not match its hashes; replaced by a copy with different \
                                 content ({by})."
                            ),
                        );
                    }
                }
            }
            // content that was replaced for its damage explains its CRC-32; otherwise it is a fault of its own
            if !damage_replaced {
                for member in crc_differs {
                    report.finding(
                        Level::Fail,
                        "stream_hash",
                        format!("{name}: CRC-32 differs from the central directory ({member})."),
                    );
                }
            }
            if counted(record) {
                done += record.size;
            }
        }
        progress(total, total);
    }
    // the newest state's metadata goes on to the log checks; a clone of it would be the peak of the whole check
    report.graph = parsed.pop().and_then(|state| state.graph);
    Ok(())
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

    /// A container with what makes it factum's, and `graph`.
    pub fn factum_laid_out(dir: &tempfile::TempDir, graph: &Graph, extra: &mut dyn FnMut(&mut Appender)) -> PathBuf {
        let volume = format!("aff4://{VOLUME}");
        let mut graph = graph.clone();
        a(&mut graph, &volume, &aff4("ZipVolume"));
        foreign(
            dir,
            &graph,
            &mut |app| {
                app.add_bytes("factum/README.txt", 0, b"readme").unwrap();
                extra(app);
            },
            V21,
        )
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
        // everything checks out, and still nothing signs it
        assert_eq!(codes(&report, Level::Warn), vec!["not_signed"], "{:?}", report.findings);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
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
        assert_eq!(codes(&report, Level::Warn), vec!["not_signed"], "{:?}", report.findings);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
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
            vec!["not_signed", "not_checked"],
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
        assert_eq!(codes(&report, Level::Warn), vec!["not_signed", "not_checked"]);
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
        assert_eq!(codes(&report, Level::Warn), vec!["not_signed"], "{:?}", report.findings);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
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
        assert_eq!(codes(&report, Level::Warn), vec!["not_checked", "not_signed"]);
        std::fs::write(dir.path().join("c.aff4l.1"), b"part two").unwrap();
        let report = check(&path);
        assert_eq!(
            codes(&report, Level::Warn),
            vec!["not_checked", "not_checked", "not_signed"]
        );
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
    use crate::container::zip64::Appender;
    use std::io::Write;

    #[test]
    fn a_secondary_store_that_cannot_be_read_fails_in_factums_layout_and_warns_in_others() {
        let store = format!("aff4://{VOLUME}/information.turtle.2");
        let text = b"x> .";
        let graph = |graph: &mut Graph| {
            graph.add(
                &format!("aff4://{VOLUME}"),
                &format!("{AFF4L_NS}imports"),
                Term::Iri(store.clone()),
            );
            graph.add(
                &store,
                &aff4("hash"),
                typed(hex::encode(sha2::Sha256::digest(text)), &aff4("SHA256")),
            );
        };
        let mut imports = Graph::default();
        graph(&mut imports);
        let add = |app: &mut Appender| {
            app.add_bytes("information.turtle.2", 8, text).unwrap();
        };
        let dir = tempfile::tempdir().unwrap();
        let report = check(&factum_laid_out(&dir, &imports, &mut { add }));
        assert!(
            codes(&report, Level::Fail).contains(&"turtle_hash"),
            "{:?}",
            report.findings
        );
        let dir = tempfile::tempdir().unwrap();
        let report = check(&foreign(&dir, &imports, &mut { add }, V21));
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
        assert!(
            codes(&report, Level::Warn).contains(&"not_checked"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn a_budget_grows_with_what_is_stored_and_not_with_what_a_directory_claims() {
        let entry = |name: &str, compressed_size: u64| crate::container::zip64::CdEntry {
            name: name.as_bytes().to_vec(),
            compressed_size,
            ..Default::default()
        };
        let archive = |entries| Archive::new(entries, Vec::new(), 0);
        // a few MiB of it, however far they inflate: the floor
        let small = archive(vec![entry(TURTLE, 3 << 20)]);
        assert_eq!(Budget::for_archive(&small, 3 << 20).limit, MIN_METADATA_BUDGET);
        // a real large one: every copy it reads counts, what is no metadata does not
        let large = archive(vec![
            entry(TURTLE, 40 << 20),
            entry("factum/history/1/information.turtle", 40 << 20),
            entry("factum/history/1/information.turtle.hashes", 1 << 10),
            entry("evidence", 1 << 40),
        ]);
        assert_eq!(
            Budget::for_archive(&large, 2 << 40).limit,
            ((80 << 20) + (1 << 10)) * METADATA_BUDGET_PER_STORED_BYTE
        );
        // stored bytes that nothing reads buy nothing, whatever they are called
        for pad in [
            "evidence/information.turtle.pad",
            "information.turtle.2",
            "factum/history/x/information.turtle",
            "factum/history/01/information.turtle",
            "factum/history/0/information.turtle",
            "factum/history/1/x/information.turtle",
            "factum/history/1/information.turtle.asc",
        ] {
            let padded = archive(vec![entry(TURTLE, 3 << 20), entry(pad, 1 << 30)]);
            assert_eq!(
                Budget::for_archive(&padded, 2 << 30).limit,
                MIN_METADATA_BUDGET,
                "{pad}"
            );
        }
        // however much is stored, a ceiling
        let huge = archive(vec![entry(TURTLE, 1 << 40)]);
        assert_eq!(Budget::for_archive(&huge, 2 << 40).limit, MAX_METADATA_BUDGET);
        // a directory that claims it: the file holds no more than it holds
        let claimed = archive(vec![entry(TURTLE, 1 << 50)]);
        assert_eq!(Budget::for_archive(&claimed, 1 << 20).limit, MIN_METADATA_BUDGET);
    }

    /// A genuine container that hits the limit, on the only path factum verifies by: the log has nothing to add.
    #[test]
    fn a_stop_at_the_limit_is_no_finding_of_the_log() {
        use crate::db::Db;
        use crate::services::Factum;
        use crate::signer::FakeSigner;
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("f.db")).unwrap();
        let signer = FakeSigner::new(true);
        let factum = Factum::with_seal_dir(&db, &signer, Some(dir.path().to_path_buf()));
        let case_id = factum.create_case("C-1", "Case", "").unwrap();
        let evidence = factum.create_evidence(case_id, "disk", "", "").unwrap();
        let path = dir.path().join("c.aff4l");
        let id = factum.create_container(case_id, "C", evidence, &path, "/mnt").unwrap();
        factum.close_container(id).unwrap();
        let verify = |expected, budget| {
            BUDGET.with(|cell| cell.set(budget));
            factum
                .verify_expected_container(
                    &path,
                    expected,
                    &Gpgsm::unavailable(),
                    &|_, _| {},
                    &AtomicBool::new(false),
                )
                .unwrap()
        };
        let report = verify(None, None);
        assert!(report.log.is_some(), "{:?}", report.findings);
        for expected in [Some(id), None] {
            let report = verify(expected, Some(1_000));
            assert_eq!(codes(&report, Level::Fail), vec!["too_large"], "{:?}", report.findings);
            assert!(report.log.is_none());
        }
    }

    /// The same stop on a file that shows no sign of factum is no failure of its own, so the log still has its say.
    #[test]
    fn a_stop_at_the_limit_keeps_a_stripped_file_from_the_log_no_longer_than_it_stops() {
        let graph = Graph::default();
        let dir = tempfile::tempdir().unwrap();
        let path = foreign(&dir, &graph, &mut |_| {}, V21);
        BUDGET.with(|budget| budget.set(Some(10)));
        let report = check(&path);
        assert!(!report.stopped_on_budget(), "{:?}", report.findings);
    }

    /// Two closes, each with its signature, and the last one out of reach of a budget that fits the first.
    fn two_closes(dir: &tempfile::TempDir) -> (PathBuf, u64) {
        let mut graph = Graph::default();
        a(&mut graph, "aff4://file", &aff4("FileImage"));
        let turtle = turtle::write(&graph, &[("aff4", AFF4_NS)]);
        let padded = format!("{turtle}{}", "\n".repeat(4000));
        let path = factum_laid_out(dir, &graph, &mut |app| {
            for n in 1..=2 {
                app.add_bytes(&history_member(n, TURTLE), 8, padded.as_bytes()).unwrap();
                app.add_bytes(&history_member(n, SIG_GPG), 0, b"signature").unwrap();
            }
        });
        (path, padded.len() as u64)
    }

    #[test]
    fn a_check_that_runs_out_says_that_once_and_reads_nothing_into_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (path, padded) = two_closes(&dir);
        BUDGET.with(|budget| budget.set(Some(padded + 3000)));
        let report = check(&path);
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].level, Level::Fail);
        assert_eq!(report.findings[0].code, "too_large");
        assert!(report.findings[0].message.contains("does not mean"));
        // what is no container of factum's warns, as it is nothing to fail
        let dir = tempfile::tempdir().unwrap();
        let graph = Graph::default();
        let path = foreign(&dir, &graph, &mut |_| {}, V21);
        BUDGET.with(|budget| budget.set(Some(10)));
        let report = check(&path);
        assert_eq!(codes(&report, Level::Warn), vec!["too_large"], "{:?}", report.findings);
    }

    #[test]
    fn a_budget_stops_once_and_keeps_what_is_left() {
        let mut budget = Budget::new(10);
        budget.take(4).unwrap();
        assert_eq!(budget.left, 6);
        assert!(budget.take(7).is_err() && budget.exhausted);
        let mut budget = Budget::new(5);
        assert!(budget.parse(b"<a> <b> <c> .").is_err() && budget.exhausted);
        let mut budget = Budget::new(1 << 20);
        assert!(budget.parse(b"x> .").unwrap().is_err() && !budget.exhausted);
        let finding = Budget::new((14 << 30) / 3).finding();
        assert!(
            finding.contains("does not mean") && finding.contains("4.7 GiB in all"),
            "{finding}"
        );
    }

    #[test]
    fn bytes_that_are_not_utf8_count_for_what_they_become() {
        let text = [b"<a> <b> \"".as_slice(), &[0xFF; 1 << 12], b"\" .\n"].concat();
        // the text itself would fit, what it is read as does not
        let mut budget = Budget::new(2 << 12);
        assert!(budget.parse(&text).is_err() && budget.exhausted);
        let mut budget = Budget::new(16 << 12);
        assert!(budget.parse(&text).unwrap().is_ok());
    }

    #[test]
    fn an_unreadable_secondary_store_is_one_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut graph = Graph::default();
        let store = "aff4://secondary";
        graph.add(
            &format!("aff4://{VOLUME}"),
            &format!("{AFF4L_NS}imports"),
            Term::Iri(store.to_string()),
        );
        let name = crate::container::member_name(store, &format!("aff4://{VOLUME}"));
        let path = foreign(
            &dir,
            &graph,
            &mut |app| {
                app.add_bytes(&name, 0, b"secondary").unwrap();
            },
            V21,
        );
        // its local header differs from the directory
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.windows(name.len()).position(|w| w == name.as_bytes()).unwrap();
        bytes[at] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let report = check(&path);
        let store: Vec<_> = report.findings.iter().filter(|f| f.message.contains(&name)).collect();
        assert_eq!(store.len(), 1, "{store:?}");
        assert!(store[0].message.contains("cannot be read"), "{}", store[0].message);
    }

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
