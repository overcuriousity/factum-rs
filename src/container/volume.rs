//! One container file: created, filled by Add operations, closed (signed state kept under factum/history/<n>/),
//! reopened, and recovered after an interrupted Add.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::Digest;

use super::mounts::Mount;
use super::source::{
    self, SourceKind, SourceMeta, encode_name, exact_path, is_same_file, open_source, os_bytes, raw_path, read_meta,
    stored_path,
};
use super::stream::{self, Storage, ZLIB};
use super::turtle::{self, Graph, Term};
use super::zip64::{
    Appender, Archive, CdEntry, crc_mismatch, find_last_end, find_newest_end, member_bytes, member_bytes_and_crc,
    member_reader, member_text, read_archive,
};
use super::{AFF4_NS, AFF4L_NS, FACTUM_NS, RDF_NS, XSD_NS, ZIP_SEGMENT_LIMIT, member_name};
use crate::error::{FactumError, Result};

pub const TURTLE: &str = "information.turtle";
pub const HASHES: &str = "information.turtle.hashes";
pub const SIG_GPG: &str = "information.turtle.asc";
pub const KEY_GPG: &str = "information.turtle.pubkey.asc";
pub const SIG_X509: &str = "information.turtle.factum.sig";
pub const CER_X509: &str = "information.turtle.factum.cer";
pub const SIGNATURE_MEMBERS: [&str; 4] = [SIG_GPG, KEY_GPG, SIG_X509, CER_X509];
const README: &str = include_str!("README.txt");
pub const VERIFY_CONTAINER_PY: &[u8] = include_bytes!("verify_container.py");

/// The README a container carries: what it is, how to verify it, and which verifier it carries (spec 5.3).
pub fn readme_text() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let hash = hex::encode(sha2::Sha256::digest(VERIFY_CONTAINER_PY));
    format!(
        "{README}\nWritten by factum {version}. verify_container.py in this container:\n  SHA-256 {hash}\n\
         The same script is published at\n  \
         https://github.com/overcuriousity/factum-rs/blob/v{version}/src/container/verify_container.py\n\
         Compare the hash with that copy (sha256sum verify_container.py) before running it.\n"
    )
}

/// The name of a closed state's copy of a member.
pub fn history_member(n: u32, name: &str) -> String {
    format!("factum/history/{n}/{name}")
}

/// What the volume says about where it comes from.
#[derive(Debug, Clone, Default)]
pub struct VolumeInfo {
    pub name: String,
    pub case_file: String,
    pub case_id: i64,
    /// id, name, description
    pub evidence: Option<(i64, String, String)>,
    pub created_utc: String,
}

/// The choices of one Add operation (spec 4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddOptions {
    /// removed from the sources' paths; empty: the full paths are kept
    pub base: PathBuf,
    pub keep_path: bool,
    pub metadata_only: bool,
    /// from (inclusive) and to (exclusive) byte offset, for a single file
    pub excerpt: Option<(u64, u64)>,
    /// (source path, ARN): copies this operation adds again, replacing the ARN's damaged copy
    pub replaces: Vec<(PathBuf, String)>,
}

/// One file as the log records it (`container_files_added`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub arn: String,
    pub path: String,
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub metadata_only: bool,
    pub excerpt: Option<(u64, u64)>,
    pub link: Option<String>,
    /// the absolute path it was read from (not recorded before 2.7)
    pub source: Option<String>,
    /// Base64 of that path's bytes, when `source` cannot hold them
    pub source_raw: Option<String>,
}

impl FileRecord {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "arn": self.arn, "path": self.path, "size": self.size, "md5": self.md5, "sha1": self.sha1,
            "sha256": self.sha256, "metadata_only": self.metadata_only,
            "excerpt": self.excerpt.map(|(from, to)| json!([from, to])), "link": self.link,
            "source": self.source,
        });
        if let Some(raw) = &self.source_raw {
            value["source_raw"] = json!(raw);
        }
        value
    }

    /// The exact path it was read from.
    pub fn source_path(&self) -> Option<PathBuf> {
        let source = self.source.as_deref()?;
        Some(exact_path(source, self.source_raw.as_deref()))
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        let excerpt = match value.get("excerpt") {
            Some(Value::Array(pair)) if pair.len() == 2 => Some((pair[0].as_u64()?, pair[1].as_u64()?)),
            Some(Value::Null) | None => None,
            Some(_) => return None,
        };
        Some(Self {
            arn: text("arn")?,
            path: text("path")?,
            size: value.get("size")?.as_u64()?,
            md5: text("md5")?,
            sha1: text("sha1")?,
            sha256: text("sha256")?,
            metadata_only: value.get("metadata_only")?.as_bool()?,
            excerpt,
            link: text("link"),
            source: text("source"),
            source_raw: text("source_raw"),
        })
    }
}

/// One folder as the log records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderRecord {
    pub arn: String,
    pub path: String,
}

impl FolderRecord {
    pub fn to_json(&self) -> Value {
        json!({"arn": self.arn, "path": self.path})
    }

    pub fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            arn: value.get("arn")?.as_str()?.to_string(),
            path: value.get("path")?.as_str()?.to_string(),
        })
    }
}

/// The folders a graph lists, in order.
pub fn folder_records(graph: &Graph) -> Vec<FolderRecord> {
    graph
        .subjects_of_type(&aff4l("Folder"))
        .map(|arn| FolderRecord {
            arn: arn.to_string(),
            path: graph
                .first_value(arn, &aff4l("originalPathName"))
                .unwrap_or_default()
                .to_string(),
        })
        .collect()
}

/// How far an Add operation got; read by the GUI while it runs.
#[derive(Debug, Default)]
pub struct AddProgress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    pub total_files: AtomicU64,
    pub total_bytes: AtomicU64,
}

/// An Add operation whose content is written but not yet listed: `finalize_add` lists it, `discard` drops it.
#[derive(Debug, Clone)]
pub struct Staged {
    /// the end of the state before the operation
    pub start: u64,
    pub records: Vec<FileRecord>,
    pub folders: Vec<FolderRecord>,
    /// (path, reason): special files
    pub skipped: Vec<(String, String)>,
    /// (path, reason): files that could not be read or changed while they were read
    pub errors: Vec<(String, String)>,
    /// the mounts the sources lie on
    pub mounts: Vec<Mount>,
    /// (ARN, ARN of its copy added again by this operation)
    pub replaced: Vec<(String, String)>,
    graph: Graph,
    task_arn: String,
    base: PathBuf,
    pub keep_path: bool,
    mark: Mark,
}

impl Staged {
    /// The volume as it was before this operation: rolling back to it removes the operation.
    pub fn mark(&self) -> Mark {
        self.mark
    }

    pub fn bytes(&self) -> u64 {
        self.records.iter().filter(|r| !r.metadata_only).map(|r| r.size).sum()
    }

    /// The base path the sources' paths were stored below; empty: full paths.
    pub fn base(&self) -> &Path {
        &self.base
    }
}

/// Where a state ends and where the next write goes; equal unless a state was set aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pub base_end: u64,
    pub write_pos: u64,
}

/// The signatures of one close: (armored GPG signature, public key) and (PEM CMS signature, PEM chain).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signatures {
    pub gpg: Option<(String, String)>,
    pub x509: Option<(String, String)>,
}

impl Signatures {
    fn members(&self) -> Vec<(&'static str, &str)> {
        let mut members = Vec::new();
        if let Some((signature, key)) = &self.gpg {
            members.extend([(SIG_GPG, signature.as_str()), (KEY_GPG, key.as_str())]);
        }
        if let Some((signature, chain)) = &self.x509 {
            members.extend([(SIG_X509, signature.as_str()), (CER_X509, chain.as_str())]);
        }
        members
    }
}

fn rdf_type() -> String {
    format!("{RDF_NS}type")
}

fn aff4(local: &str) -> String {
    format!("{AFF4_NS}{local}")
}

fn aff4l(local: &str) -> String {
    format!("{AFF4L_NS}{local}")
}

fn factum(local: &str) -> String {
    format!("{FACTUM_NS}{local}")
}

fn plain(value: impl Into<String>) -> Term {
    Term::Literal {
        value: value.into(),
        datatype: None,
    }
}

fn typed(value: impl ToString, xsd: &str) -> Term {
    Term::Literal {
        value: value.to_string(),
        datatype: Some(format!("{XSD_NS}{xsd}")),
    }
}

pub fn new_arn() -> String {
    format!("aff4://{}", uuid::Uuid::new_v4())
}

fn io_error(path: &Path, e: io::Error) -> FactumError {
    FactumError::general(format!("The container {} could not be written: {e}", path.display()))
}

/// A read that failed for a reason other than what the file holds: it says nothing about the file.
fn read_refused(path: &Path, e: io::Error) -> FactumError {
    FactumError::general(format!(
        "The container {} was not opened, nothing in it was changed: it could not be read ({e}).",
        path.display()
    ))
}

/// A failed read while opening: a differing CRC-32 (`crc_mismatch`, a kind of its own that says so), a read error, or
/// what `other` makes of the file's content.
fn open_error(path: &Path, e: io::Error, other: impl Fn(String) -> FactumError) -> FactumError {
    use io::ErrorKind::{InvalidData, UnexpectedEof, Unsupported};
    match crc_mismatch(&e) {
        Some(member) => FactumError::container_crc(format!(
            "The container {} was not opened, nothing in it was changed: {member} differs from the CRC-32 of the \
             directory. Verify Container shows whether the content is intact; it can only be closed as damaged.",
            path.display()
        )),
        None if matches!(e.kind(), InvalidData | UnexpectedEof | Unsupported) => other(e.to_string()),
        None => read_refused(path, e),
    }
}

/// What a re-check read back from the container file (spec 5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recheck {
    pub files: u64,
    pub bytes: u64,
    /// the operating system's cache was bypassed, so the bytes came from the disk
    pub uncached: bool,
    /// files whose stored content cannot be read or does not match their hashes
    pub mismatches: Vec<FileRecord>,
    /// faults of the directory, not of the content: a metadata member, or `path (member)` of a file that matched its
    /// hashes, that differs from the directory's CRC-32, or a directory that cannot be read. Such a state is not
    /// signed; it can only be closed as damaged.
    pub directory_faults: Vec<String>,
    /// where the log's state ended when the re-check started
    pub logged_end: Option<u64>,
    /// the files it read back, in the order of the input
    pub arns: Vec<String>,
    /// the end of the state it read
    pub volume_end: u64,
}

impl Recheck {
    /// Whether this re-check read what the log and the locked volume hold now: `mark` is the volume's, its write
    /// position the end of a state that was set aside, which a re-check before that read.
    pub fn is_of(&self, logged_end: Option<u64>, records: &[FileRecord], mark: Mark) -> bool {
        self.logged_end == logged_end
            && self.arns.iter().eq(records.iter().map(|r| &r.arn))
            && (self.volume_end == mark.base_end || self.volume_end == mark.write_pos)
    }
}

/// Drops the file's cached pages, so the next reads come from the disk; true when that was possible.
fn drop_cache(file: &File) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: a valid descriptor for the call; the advice changes no data
        unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        false
    }
}

/// Errors that say a device or share went away, in the numbers of the platform.
#[cfg(target_os = "linux")]
const MEDIUM_GONE: [i32; 4] = [libc::ENODEV, libc::ENXIO, libc::ENOMEDIUM, libc::EHOSTDOWN];
#[cfg(all(unix, not(target_os = "linux")))]
const MEDIUM_GONE: [i32; 3] = [libc::ENODEV, libc::ENXIO, libc::EHOSTDOWN];
// ERROR_NOT_READY, _DEV_NOT_EXIST, _NETNAME_DELETED, _MEDIA_CHANGED, _NO_MEDIA_IN_DRIVE, _DEVICE_NOT_CONNECTED
#[cfg(windows)]
const MEDIUM_GONE: [i32; 6] = [21, 55, 64, 1110, 1112, 1167];

/// Whether a read error during a re-check means the stored content is damaged (missing, corrupt, cut short).
fn is_damage(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::NotFound
            | io::ErrorKind::UnexpectedEof
    )
}

/// Whether a read error only says that the container could not be read right now (permissions, a lock, an
/// interrupted call, a removed medium, a lost share): retried by the user, never logged as damage.
fn is_transient(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        PermissionDenied
            | Interrupted
            | WouldBlock
            | TimedOut
            | ResourceBusy
            | OutOfMemory
            | NotConnected
            | ConnectionReset
            | ConnectionAborted
            | HostUnreachable
            | NetworkUnreachable
            | NetworkDown
            | StaleNetworkFileHandle
    ) || e.raw_os_error().is_some_and(|code| MEDIUM_GONE.contains(&code))
}

/// Whether a read error that stayed on a second attempt counts as damage. Any error but a transient one does (EIO
/// above all, which a bad sector gives), unless `rest_reads` fails too: a removed drive gives EIO for the whole file.
fn counts_as_damage(e: &io::Error, rest_reads: impl FnOnce() -> bool) -> bool {
    is_damage(e.kind()) || (!is_transient(e) && rest_reads())
}

/// Whether the medium is still there: the start or the end of the file can be read from the disk. A dead sector
/// takes one of them at most, and a re-check reads the metadata at both ends first; a removed drive fails both.
fn medium_reads(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    drop_cache(&file);
    let mut buffer = [0; 4096];
    let head = file.read(&mut buffer).is_ok_and(|read| read > 0);
    let tail = file
        .seek(SeekFrom::End(-4096))
        .or_else(|_| file.rewind().map(|_| 0))
        .is_ok()
        && file.read(&mut buffer).is_ok_and(|read| read > 0);
    #[cfg(test)]
    let (head, tail) = tests::probed(head, tail);
    head || tail
}

/// A state as a re-check finds it.
struct RecheckState {
    end: u64,
    archive: Archive,
    turtle: Vec<u8>,
    /// the metadata members that differ from the directory's CRC-32
    crc: Vec<String>,
}

/// Reads the directory of the state at `end` (the newest when None) and its metadata; None without a complete one.
fn read_recheck_state(file: &mut File, end: Option<u64>) -> io::Result<Option<RecheckState>> {
    #[cfg(test)]
    if let Some(e) = tests::failed_metadata() {
        return Err(e);
    }
    let Some(end) = find_last_end(file, end)? else {
        return Ok(None);
    };
    let archive = read_archive(file, end)?;
    let mut crc = Vec::new();
    let mut turtle = Vec::new();
    for name in ["version.txt", "container.description", HASHES, TURTLE] {
        let Some(entry) = archive.get(name) else { continue };
        let (data, matches) = member_bytes_and_crc(file, entry)?;
        if !matches {
            crc.push(name.to_string());
        }
        if name == TURTLE {
            turtle = data;
        }
    }
    if archive.get(TURTLE).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "information.turtle is missing",
        ));
    }
    Ok(Some(RecheckState {
        end,
        archive,
        turtle,
        crc,
    }))
}

fn open_for_recheck(path: &Path) -> io::Result<File> {
    #[cfg(test)]
    if let Some(e) = tests::failed_open() {
        return Err(e);
    }
    File::open(path)
}

/// Reads the stored content of `records` back from the state that ends at `end` (the newest when None) and
/// compares it with their hashes. A read error that stays on a second attempt counts as damage when the file can
/// otherwise be read (`counts_as_damage`); until then it is an error and nothing is decided.
pub fn recheck(
    path: &Path,
    end: Option<u64>,
    records: &[FileRecord],
    progress: &AddProgress,
    cancel: &AtomicBool,
) -> Result<Recheck> {
    let unreadable = |e: String| FactumError::general(format!("The container {} cannot be read: {e}", path.display()));
    let mut result = Recheck {
        logged_end: end,
        arns: records.iter().map(|r| r.arn.clone()).collect(),
        ..Default::default()
    };
    let mut file = match open_for_recheck(path).or_else(|_| open_for_recheck(path)) {
        Ok(file) => file,
        // it is there, but what it stands on cannot be read: no state to go through
        Err(e) if !is_damage(e.kind()) && !is_transient(&e) && std::fs::metadata(path).is_ok() => {
            result.directory_faults.push(format!("the file cannot be opened ({e})"));
            return Ok(result);
        }
        Err(e) => return Err(unreadable(e.to_string())),
    };
    result.uncached = drop_cache(&file);
    let state = match read_recheck_state(&mut file, end) {
        Err(e) if !is_damage(e.kind()) && !is_transient(&e) => read_recheck_state(&mut file, end),
        state => state,
    };
    let state = match state {
        Ok(state) => state.ok_or_else(|| unreadable("no complete ZIP directory".into()))?,
        // the directory itself is what cannot be read: nothing to go through, and nothing to sign
        Err(e) if !is_damage(e.kind()) && counts_as_damage(&e, || medium_reads(path)) => {
            result
                .directory_faults
                .push(format!("the directory cannot be read ({e})"));
            return Ok(result);
        }
        Err(e) => return Err(unreadable(e.to_string())),
    };
    result.volume_end = state.end;
    result.directory_faults = state.crc;
    let archive = state.archive;
    let parsed = String::from_utf8(state.turtle)
        .map_err(|_| "information.turtle is not UTF-8 text".to_string())
        .and_then(|text| turtle::parse(&text));
    let graph = match parsed {
        Ok(graph) => graph,
        // it differs from its CRC-32 and cannot be read: the listed files cannot be found, whatever they hold
        Err(_) if result.directory_faults.iter().any(|name| name == TURTLE) => return Ok(result),
        Err(e) => return Err(unreadable(e)),
    };
    progress.total_files.store(records.len() as u64, Ordering::Relaxed);
    progress
        .total_bytes
        .store(records.iter().map(|r| r.size).sum(), Ordering::Relaxed);
    progress.files.store(0, Ordering::Relaxed);
    progress.bytes.store(0, Ordering::Relaxed);
    let cancelled = || FactumError::general("Re-check cancelled — the container was not closed.");
    for record in records {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        let done = result.bytes;
        let report = |read: u64| progress.bytes.store(done + read, Ordering::Relaxed);
        let hash = |file: &mut File| {
            #[cfg(test)]
            if let Some(e) = tests::failed_read() {
                return Err(e);
            }
            match content_reader(file, &archive, &graph, &record.arn) {
                Ok(Some(mut reader)) => stream::hash_stored(&mut reader, &report, cancel).map(Some),
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        };
        let hashed = match hash(&mut file) {
            Err(e) if !is_damage(e.kind()) && !is_transient(&e) => hash(&mut file),
            hashed => hashed,
        };
        let (matches, crc) = match hashed {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Err(cancelled()),
            // not damage: the check stops, the container stays open and nothing is logged
            Err(e) if !counts_as_damage(&e, || medium_reads(path)) => return Err(unreadable(e.to_string())),
            Ok(Some((size, digests, crc))) => (
                size == record.size
                    && digests.md5 == record.md5
                    && digests.sha1 == record.sha1
                    && digests.sha256 == record.sha256,
                crc,
            ),
            Ok(None) | Err(_) => (false, None),
        };
        if !matches {
            result.mismatches.push(record.clone());
        } else if let Some(member) = crc {
            // the hashes matched, so the fault is the directory's; damaged content explains its CRC-32 itself
            result.directory_faults.push(format!("{} ({member})", record.path));
        }
        result.files += 1;
        result.bytes += record.size;
        progress.files.store(result.files, Ordering::Relaxed);
        progress.bytes.store(result.bytes, Ordering::Relaxed);
    }
    Ok(result)
}

/// The metadata of a container file's newest complete state, read without changing the file. `end`, where the
/// logged state ends, spares the search for it while an addition is being written after it.
pub fn read_graph(path: &Path, end: Option<u64>) -> Result<Graph> {
    let not_container = |why: String| FactumError::general(format!("{} cannot be read: {why}", path.display()));
    let mut file = File::open(path).map_err(|e| not_container(e.to_string()))?;
    let end = find_last_end(&mut file, end)
        .map_err(|e| not_container(e.to_string()))?
        .ok_or_else(|| not_container("no complete ZIP directory".into()))?;
    let archive = read_archive(&mut file, end).map_err(|e| not_container(e.to_string()))?;
    let entry = archive
        .get(TURTLE)
        .ok_or_else(|| not_container("information.turtle is missing".into()))?;
    let text = member_text(&mut file, entry).map_err(|e| not_container(e.to_string()))?;
    turtle::parse(&text).map_err(not_container)
}

/// When each file of a graph was last written, by ARN.
pub fn modified_times(graph: &Graph) -> std::collections::HashMap<String, String> {
    graph
        .subjects_of_type(&aff4("FileImage"))
        .filter_map(|arn| {
            Some((
                arn.to_string(),
                graph.first_value(arn, &aff4l("lastWritten"))?.to_string(),
            ))
        })
        .collect()
}

/// The files a graph lists, in order, as the log records them.
pub fn file_records(graph: &Graph) -> Vec<FileRecord> {
    graph
        .subjects_of_type(&aff4("FileImage"))
        .map(|arn| {
            let value = |p: String| graph.first_value(arn, &p).map(str::to_string);
            let number = |p: String| value(p).and_then(|v| v.parse::<u64>().ok());
            let hash = |name: &str| {
                graph
                    .objects(arn, &aff4("hash"))
                    .find(|t| t.datatype().is_some_and(|d| d.ends_with(&format!("#{name}"))))
                    .and_then(Term::value)
                    .unwrap_or_default()
                    .to_string()
            };
            let excerpt = number(factum("excerptStart")).zip(number(factum("excerptEnd")));
            FileRecord {
                arn: arn.to_string(),
                path: value(aff4l("originalPathName")).unwrap_or_default(),
                size: number(aff4("size")).unwrap_or(0),
                md5: hash("MD5"),
                sha1: hash("SHA1"),
                sha256: hash("SHA256"),
                metadata_only: value(factum("metadataOnly")).as_deref() == Some("true"),
                excerpt,
                link: value(factum("symlinkTarget")),
                source: value(factum("sourcePath")),
                source_raw: value(factum("sourcePathRaw")),
            }
        })
        .collect()
}

/// The (ARN, ARN of its copy added again) pairs a graph lists; what verification takes a replacement from.
pub fn replaced_pairs(graph: &Graph) -> Vec<(String, String)> {
    let predicate = factum("replacedBy");
    graph
        .subjects_of_type(&aff4("FileImage"))
        .flat_map(|arn| {
            graph
                .objects(arn, &predicate)
                .map(move |t| (arn, t))
                .collect::<Vec<_>>()
        })
        .filter_map(|(arn, t)| Some((arn.to_string(), t.iri()?.to_string())))
        .collect()
}

/// The log entries of the Add operations a graph lists, in order.
pub fn task_entries(graph: &Graph) -> Vec<i64> {
    graph
        .subjects_of_type(&aff4l("LogicalAcquisitionTask"))
        .filter_map(|task| graph.first_value(task, &factum("logEntry"))?.parse().ok())
        .collect()
}

/// The stored content of a FileImage (ZipSegment or ImageStream); None when it has none (metadata only, link).
pub fn content_reader<'f>(
    file: &'f mut File,
    archive: &Archive,
    graph: &Graph,
    arn: &str,
) -> io::Result<Option<Box<dyn Read + 'f>>> {
    let number = |p: &str| graph.first_value(arn, p).and_then(|v| v.parse::<u64>().ok());
    let missing = |what: &str| io::Error::new(io::ErrorKind::NotFound, format!("{arn}: {what} is missing"));
    if graph.has_type(arn, &aff4("ZipSegment")) {
        let entry = archive.get_arn(arn).ok_or_else(|| missing("its ZIP member"))?;
        return member_reader(file, entry).map(Some);
    }
    if graph.has_type(arn, &aff4("ImageStream")) {
        let compression = graph
            .objects(arn, &aff4("compressionMethod"))
            .find_map(|t| t.iri().or(t.value()))
            .unwrap_or(ZLIB)
            .to_string();
        return stream::image_stream_reader(
            file,
            archive,
            arn,
            number(&aff4("size")).ok_or_else(|| missing("aff4:size"))?,
            number(&aff4("chunkSize")).unwrap_or(stream::CHUNK_SIZE),
            number(&aff4("chunksInSegment")).unwrap_or(stream::CHUNKS_PER_SEGMENT),
            &compression,
        )
        .map(Some);
    }
    Ok(None)
}

fn volume_graph(uuid: &str, info: &VolumeInfo) -> Graph {
    let arn = format!("aff4://{uuid}");
    let mut graph = Graph::default();
    graph.add(&arn, &rdf_type(), Term::Iri(aff4("ZipVolume")));
    graph.add(&arn, &aff4("creationTime"), typed(&info.created_utc, "dateTime"));
    graph.add(&arn, &factum("containerName"), plain(&info.name));
    graph.add(&arn, &factum("caseFile"), plain(&info.case_file));
    graph.add(&arn, &factum("caseId"), typed(info.case_id, "long"));
    if let Some((id, name, description)) = &info.evidence {
        graph.add(&arn, &factum("evidenceId"), typed(id, "long"));
        graph.add(&arn, &factum("evidenceName"), plain(name));
        graph.add(&arn, &factum("evidenceDescription"), plain(description));
    }
    graph
}

/// fileName, originalPathName (with their Raw forms when needed), timestamps and mode of a file or folder.
fn name_and_meta(graph: &mut Graph, arn: &str, name: &[u8], stored: &[u8], meta: &SourceMeta) {
    for (property, bytes) in [("fileName", name), ("originalPathName", stored)] {
        let encoded = encode_name(bytes);
        graph.add(arn, &aff4l(property), plain(encoded.text));
        if let Some(raw) = encoded.raw_b64 {
            graph.add(arn, &aff4l(&format!("{property}Raw")), typed(raw, "base64Binary"));
        }
    }
    for (property, time) in [
        ("lastWritten", &meta.modified),
        ("lastAccessed", &meta.accessed),
        ("recordChanged", &meta.changed),
        ("birthTime", &meta.birth),
    ] {
        if let Some(time) = time {
            graph.add(arn, &aff4l(property), typed(time, "dateTime"));
        }
    }
    if let Some(mode) = meta.mode {
        graph.add(arn, &aff4l("fileMode"), typed(mode, "long"));
    }
}

/// A path as a factum property, and its bytes as `<property>Raw` when the text cannot hold them.
fn path_triples(graph: &mut Graph, arn: &str, property: &str, path: &Path) {
    graph.add(arn, &factum(property), plain(path.display().to_string()));
    if let Some(raw) = raw_path(path) {
        graph.add(arn, &factum(&format!("{property}Raw")), typed(raw, "base64Binary"));
    }
}

/// A mount as its own subject `arn`, and the FUSE mount behind it as another.
fn mount_triples(graph: &mut Graph, arn: &str, mount: &Mount) {
    graph.add(arn, &rdf_type(), Term::Iri(factum("Mount")));
    if mount.is_unknown() {
        graph.add(arn, &factum("unknown"), typed("true", "boolean"));
    }
    if !mount.mount_point.is_empty() {
        graph.add(arn, &factum("mountPoint"), plain(&mount.mount_point));
    }
    if let Some(raw) = &mount.mount_point_raw {
        graph.add(arn, &factum("mountPointRaw"), typed(raw, "base64Binary"));
    }
    for (property, value) in [
        ("device", &mount.device),
        ("fileSystem", &mount.fs_type),
        ("mountOptions", &mount.options),
        ("superOptions", &mount.super_options),
        ("image", &mount.image),
        ("volumeSerial", &mount.volume_serial),
        ("volumeLabel", &mount.volume_label),
        ("volumeGuid", &mount.volume_guid),
    ] {
        if let Some(value) = value {
            graph.add(arn, &factum(property), plain(value));
        }
    }
    if let Some(read_only) = mount.read_only {
        graph.add(arn, &factum("readOnly"), typed(read_only, "boolean"));
    }
    if let Some(backing) = &mount.backing {
        let backing_arn = new_arn();
        graph.add(arn, &factum("backingMount"), Term::Iri(backing_arn.clone()));
        mount_triples(graph, &backing_arn, backing);
    }
}

fn hash_triples(graph: &mut Graph, arn: &str, digests: &stream::Digests) {
    for (name, value) in digests.typed() {
        graph.add(
            arn,
            &aff4("hash"),
            Term::Literal {
                value: value.to_string(),
                datatype: Some(aff4(name)),
            },
        );
    }
}

/// The content of one file: stored, or only hashed.
enum Content {
    Stored(stream::Stored),
    Hashed(u64, stream::Digests),
}

/// The bytes of `information.turtle.hashes` for a turtle (AFF4-L v1.0, 10.1).
pub(crate) fn hashes_bytes(uuid: &str, turtle: &[u8]) -> Vec<u8> {
    let mut graph = Graph::default();
    let subject = format!("aff4://{uuid}/{TURTLE}");
    for (name, value) in [
        ("SHA256", hex::encode(sha2::Sha256::digest(turtle))),
        ("SHA512", hex::encode(sha2::Sha512::digest(turtle))),
    ] {
        graph.add(
            &subject,
            &aff4("hash"),
            Term::Literal {
                value,
                datatype: Some(aff4(name)),
            },
        );
    }
    turtle::write(&graph, &[("aff4", AFF4_NS)]).into_bytes()
}

/// Takes the writer's lock without blocking. On Windows a lock is mandatory: locking the file's bytes would stop
/// every other handle, the verifier's and the view's included, from reading them. So one byte far beyond any
/// content is locked there instead; it excludes another writer all the same.
#[cfg(windows)]
fn try_lock(file: &File) -> std::result::Result<(), std::fs::TryLockError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    const LOCK_BYTE: u64 = i64::MAX as u64 - 1;
    // SAFETY: OVERLAPPED is plain data, valid when zeroed; the handle stays open for the call
    let locked = unsafe {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        overlapped.Anonymous.Anonymous.Offset = LOCK_BYTE as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (LOCK_BYTE >> 32) as u32;
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if locked != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Err(std::fs::TryLockError::WouldBlock)
    } else {
        Err(std::fs::TryLockError::Error(error))
    }
}

#[cfg(not(windows))]
fn try_lock(file: &File) -> std::result::Result<(), std::fs::TryLockError> {
    file.try_lock()
}

/// Locks the file, waiting briefly for a lock held for a moment (a child process between fork and exec still shares
/// the open file). The last error is what stayed: `WouldBlock`, another process holds the lock.
fn wait_for_lock(file: &File) -> std::result::Result<(), std::fs::TryLockError> {
    for _ in 0..19 {
        match try_lock(file) {
            Err(std::fs::TryLockError::WouldBlock) => std::thread::sleep(std::time::Duration::from_millis(50)),
            result => return result,
        }
    }
    try_lock(file)
}

fn in_use() -> FactumError {
    FactumError::general("The container is in use by another factum process.")
}

/// Locks the file for this process.
fn lock(file: &File) -> Result<()> {
    match wait_for_lock(file) {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(in_use()),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(FactumError::general(format!("The container cannot be locked: {e}")))
        }
    }
}

/// Holds the writer's lock of a container file while the log alone changes (the returned handle keeps it). Only
/// another writer refuses: a file that cannot be opened or locked (missing, a dead mount, no permission) has none
/// that could be waited for, and these steps are the way out then. Nothing is written through the handle.
pub fn lock_file(path: &Path) -> Result<Option<File>> {
    let opened = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .or_else(|_| File::open(path));
    let Ok(file) = opened else {
        return Ok(None);
    };
    match wait_for_lock(&file) {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(in_use()),
        Err(std::fs::TryLockError::Error(e)) => {
            log::warn!("{} could not be locked: {e}", path.display());
            Ok(None)
        }
    }
}

/// The writer of a volume; gone only after a failed rollback left the file in an unknown state.
fn writer<'a>(app: &'a mut Option<Appender>, path: &Path) -> Result<&'a mut Appender> {
    app.as_mut().ok_or_else(|| {
        FactumError::general(format!(
            "The container {} could not be restored after a failed write; open it again.",
            path.display()
        ))
    })
}

/// An open container file, locked for writing as long as this value lives.
pub struct Volume {
    path: PathBuf,
    uuid: String,
    app: Option<Appender>,
    archive: Archive,
    graph: Graph,
    /// content up to this size is a ZipSegment (lowered in tests)
    pub segment_limit: u64,
    /// test seam: the next `finalize_add` fails
    #[doc(hidden)]
    pub fail_next_finalize: bool,
}

impl Volume {
    /// Creates a new container file; fails if the file exists.
    pub fn create(path: &Path, uuid: &str, info: &VolumeInfo) -> Result<Volume> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| FactumError::general(format!("The container {} cannot be created: {e}", path.display())))?;
        // the file is new: one that could not be written whole is removed, so the name can be used again
        Self::fill_new(file, path, uuid, info).inspect_err(|_| {
            if let Err(e) = std::fs::remove_file(path) {
                log::error!("{} could not be removed after a failed create: {e}", path.display());
            }
        })
    }

    /// The first state of a new container; the file is closed again when it fails.
    fn fill_new(file: File, path: &Path, uuid: &str, info: &VolumeInfo) -> Result<Volume> {
        lock(&file)?;
        let arn = format!("aff4://{uuid}");
        let mut app = Appender::new(file, 0, Vec::new()).map_err(|e| io_error(path, e))?;
        let version = format!("major=2\nminor=1\ntool=factum {}\n", crate::VERSION);
        let write = |app: &mut Appender| -> io::Result<()> {
            #[cfg(test)]
            if tests::FAIL_CREATE.with(|fail| fail.replace(false)) {
                return Err(io::Error::other("no space left on device (test)"));
            }
            app.add_bytes("version.txt", 0, version.as_bytes())?;
            app.add_bytes("container.description", 0, arn.as_bytes())?;
            app.add_bytes("verify_container.py", 8, VERIFY_CONTAINER_PY)?;
            app.add_bytes("factum/README.txt", 8, readme_text().as_bytes())?;
            Ok(())
        };
        write(&mut app).map_err(|e| io_error(path, e))?;
        let mut volume = Volume {
            path: path.to_path_buf(),
            uuid: uuid.to_string(),
            archive: Archive::new(Vec::new(), arn.clone().into_bytes(), 0),
            app: Some(app),
            graph: Graph::default(),
            segment_limit: ZIP_SEGMENT_LIMIT,
            fail_next_finalize: false,
        };
        volume.commit(volume_graph(uuid, info), &[], &SIGNATURE_MEMBERS)?;
        Ok(volume)
    }

    /// Opens a container for writing. An interrupted Add left bytes after the last complete state: they are cut
    /// off (never a complete state); the second value says how many. `known` is where a complete state ends (the
    /// case log's), from which the newest one is found quickly. A read error, or bytes after that state that could
    /// be more than an interrupted Add, refuse the open and leave the file as it is.
    pub fn open(path: &Path, known: Option<u64>) -> Result<(Volume, u64)> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| FactumError::general(format!("The container {} cannot be opened: {e}", path.display())))?;
        lock(&file)?;
        let not_container =
            |why: String| FactumError::general(format!("{} is not a factum container: {why}", path.display()));
        let len = file.seek(SeekFrom::End(0)).map_err(|e| io_error(path, e))?;
        let refused = |e: io::Error| {
            if e.kind() != io::ErrorKind::InvalidData {
                return read_refused(path, e);
            }
            FactumError::general(format!(
                "The container {} was not opened, nothing in it was changed: it may hold more than an interrupted \
                 addition ({e}).",
                path.display()
            ))
        };
        let end = find_newest_end(&mut file, known)
            .map_err(refused)?
            .ok_or_else(|| not_container("no complete ZIP directory".into()))?;
        let archive = read_archive(&mut file, end).map_err(|e| open_error(path, e, not_container))?;
        let read = |file: &mut File, name: &str| -> Result<Vec<u8>> {
            let entry = archive
                .get(name)
                .ok_or_else(|| not_container(format!("{name} is missing")))?;
            member_bytes(file, entry).map_err(|e| open_error(path, e, not_container))
        };
        let version = String::from_utf8_lossy(&read(&mut file, "version.txt")?).into_owned();
        if !(version.contains("major=2") && version.contains("minor=1")) {
            return Err(not_container("not an AFF4-L v1.0 container".into()));
        }
        let description = String::from_utf8_lossy(&read(&mut file, "container.description")?)
            .trim()
            .to_string();
        let uuid = description
            .strip_prefix("aff4://")
            .ok_or_else(|| not_container("container.description is not a volume ARN".into()))?
            .to_string();
        let turtle = read(&mut file, TURTLE)?;
        let graph = turtle::parse(&String::from_utf8_lossy(&turtle)).map_err(not_container)?;
        let app = Appender::new(file, end, archive.entries.clone()).map_err(|e| io_error(path, e))?;
        if len > end {
            log::warn!(
                "{}: {} bytes of an interrupted addition were discarded.",
                path.display(),
                len - end
            );
        }
        Ok((
            Volume {
                path: path.to_path_buf(),
                uuid,
                app: Some(app),
                archive,
                graph,
                segment_limit: ZIP_SEGMENT_LIMIT,
                fail_next_finalize: false,
            },
            len - end,
        ))
    }

    /// The volume UUID of a container file, without changing it.
    pub fn uuid_of(path: &Path) -> Result<String> {
        let not_container =
            |why: String| FactumError::general(format!("{} is not a factum container: {why}", path.display()));
        let mut file = File::open(path).map_err(|e| not_container(e.to_string()))?;
        let end = find_last_end(&mut file, None)
            .map_err(|e| open_error(path, e, not_container))?
            .ok_or_else(|| not_container("no complete ZIP directory".into()))?;
        let archive = read_archive(&mut file, end).map_err(|e| open_error(path, e, not_container))?;
        let entry = archive
            .get("container.description")
            .ok_or_else(|| not_container("container.description is missing".into()))?;
        let description = member_text(&mut file, entry).map_err(|e| open_error(path, e, not_container))?;
        let description = description.trim();
        if description.as_bytes() != archive.comment.as_slice() {
            return Err(not_container("its description and its ZIP comment differ".into()));
        }
        description
            .strip_prefix("aff4://")
            .map(str::to_string)
            .ok_or_else(|| not_container("container.description is not a volume ARN".into()))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn arn(&self) -> String {
        format!("aff4://{}", self.uuid)
    }

    pub fn archive(&self) -> &Archive {
        &self.archive
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    pub fn end(&self) -> u64 {
        self.archive.end
    }

    fn app(&mut self) -> Result<&mut Appender> {
        writer(&mut self.app, &self.path)
    }

    /// How many times the container was closed.
    pub fn history_count(&self) -> u32 {
        self.archive
            .entries
            .iter()
            .filter_map(|e| {
                let name = std::str::from_utf8(&e.name).ok()?;
                name.strip_prefix("factum/history/")?
                    .strip_suffix(&format!("/{TURTLE}"))?
                    .parse()
                    .ok()
            })
            .max()
            .unwrap_or(0)
    }

    /// A member's content (small members: metadata, signatures).
    pub fn member(&mut self, name: &str) -> Result<Vec<u8>> {
        let entry = self
            .archive
            .get(name)
            .cloned()
            .ok_or_else(|| FactumError::general(format!("{name} is not in the container.")))?;
        let path = self.path.clone();
        let file = self.app()?.file_mut().map_err(|e| io_error(&path, e))?;
        member_bytes(file, &entry).map_err(|e| io_error(&path, e))
    }

    /// The stored content of a file.
    pub fn read_file(&mut self, arn: &str) -> Result<Box<dyn Read + '_>> {
        let path = self.path.clone();
        let file = writer(&mut self.app, &path)?
            .file_mut()
            .map_err(|e| io_error(&path, e))?;
        content_reader(file, &self.archive, &self.graph, arn)
            .map_err(|e| io_error(&path, e))?
            .ok_or_else(|| FactumError::general(format!("{arn} has no stored content.")))
    }

    /// Writes `graph` as the new information.turtle (and its hashes), then `extra` members, then the directory
    /// without `omit`. The volume takes the new state only when all of it was written.
    fn commit(&mut self, graph: Graph, extra: &[(String, Vec<u8>, u16)], omit: &[&str]) -> Result<u64> {
        let turtle = turtle::write(&graph, &turtle::factum_prefixes()).into_bytes();
        let hashes = hashes_bytes(&self.uuid, &turtle);
        let comment = self.archive.comment.clone();
        let path = self.path.clone();
        let app = self.app()?;
        let mut write = || -> io::Result<u64> {
            app.add_bytes(TURTLE, 8, &turtle)?;
            app.add_bytes(HASHES, 0, &hashes)?;
            for (name, data, method) in extra {
                app.add_bytes(name, *method, data)?;
            }
            app.finish(omit, &comment)
        };
        let end = write().map_err(|e| io_error(&path, e))?;
        self.archive = Archive::new(self.app()?.entries(), comment, end);
        self.graph = graph;
        Ok(end)
    }

    /// Writes only new members (no new information.turtle).
    fn commit_members(&mut self, members: &[(String, Vec<u8>)]) -> Result<u64> {
        let comment = self.archive.comment.clone();
        let path = self.path.clone();
        let app = self.app()?;
        let mut write = || -> io::Result<u64> {
            for (name, data) in members {
                app.add_bytes(name, 0, data)?;
            }
            app.finish(&[], &comment)
        };
        let end = write().map_err(|e| io_error(&path, e))?;
        self.archive = Archive::new(self.app()?.entries(), comment, end);
        Ok(end)
    }

    pub fn stage_add(
        &mut self,
        sources: &[PathBuf],
        options: &AddOptions,
        progress: &AddProgress,
        cancel: &AtomicBool,
    ) -> Result<Staged> {
        self.stage_add_with(sources, options, progress, cancel, &|_| {})
    }

    /// Copies and hashes the sources into the file, after the current state, without listing them yet.
    /// `after_read` is called after each file was read (a test seam).
    pub fn stage_add_with(
        &mut self,
        sources: &[PathBuf],
        options: &AddOptions,
        progress: &AddProgress,
        cancel: &AtomicBool,
        after_read: &dyn Fn(&Path),
    ) -> Result<Staged> {
        if options.metadata_only && options.excerpt.is_some() {
            return Err(FactumError::general(
                "An excerpt stores content; it cannot be metadata only.",
            ));
        }
        let mut errors = Vec::new();
        let mut skipped = Vec::new();
        let mut items = Vec::new();
        // a container inside the folder being added never adds itself; a symbolic link to it is recorded like any link
        let own = std::fs::canonicalize(&self.path)
            .ok()
            .and_then(|real| Some((read_meta(&real).ok()?, real)));
        let is_own = |path: &Path, meta: &SourceMeta| {
            own.as_ref()
                .is_some_and(|(own, real)| is_same_file(own, real, path, meta))
        };
        for walked in source::walk(sources) {
            match walked {
                Ok((path, meta)) if is_own(&path, &meta) => {
                    // the same file under another name (a hard link): left out, and the log says so
                    if own.as_ref().map(|(_, real)| real) != std::fs::canonicalize(&path).ok().as_ref() {
                        skipped.push((
                            path.display().to_string(),
                            "the container itself; not added".to_string(),
                        ));
                    }
                }
                Ok(item) => items.push(item),
                Err((path, e)) => errors.push((path.display().to_string(), e.to_string())),
            }
        }
        // everything is checked before anything is written
        let mut stored_paths = Vec::with_capacity(items.len());
        for (path, _) in &items {
            stored_paths.push(stored_path(path, &options.base, options.keep_path).map_err(FactumError::general)?);
        }
        if let Some((from, to)) = options.excerpt {
            let single_file = items.len() == 1 && items[0].1.kind == SourceKind::File;
            if !single_file {
                return Err(FactumError::general("An excerpt can only be taken from a single file."));
            }
            let size = items[0].1.size;
            if from >= to || to > size {
                return Err(FactumError::general(format!(
                    "The excerpt {from}–{to} is outside the file (0–{size}); the end must be after the start."
                )));
            }
        }
        let files = items
            .iter()
            .filter(|(_, m)| matches!(m.kind, SourceKind::File | SourceKind::Link(_)))
            .count();
        let bytes: u64 = match options.excerpt {
            Some((from, to)) => to - from,
            None => items
                .iter()
                .filter(|(_, m)| m.kind == SourceKind::File)
                .map(|(_, m)| m.size)
                .sum(),
        };
        progress.total_files.store(files as u64, Ordering::Relaxed);
        progress.total_bytes.store(bytes, Ordering::Relaxed);
        progress.files.store(0, Ordering::Relaxed);
        progress.bytes.store(0, Ordering::Relaxed);

        let walked: Vec<PathBuf> = items.iter().map(|(path, _)| path.clone()).collect();
        let mounts = crate::container::mounts::mounts_for(sources, &walked);
        let mark = self.mark();
        let start = mark.write_pos;
        let volume_arn = self.arn();
        let limit = self.segment_limit;
        let path_of_container = self.path.clone();
        let task_arn = new_arn();
        let mut graph = Graph::default();
        let mut records = Vec::new();
        let mut folders = Vec::new();
        let mut done_bytes = 0u64;
        let app = self.app()?;
        let cancelled = |app: &mut Appender| -> Result<Staged> {
            app.rewind_to(start).map_err(|e| io_error(&path_of_container, e))?;
            Err(FactumError::general("Cancelled — nothing was added."))
        };
        for ((path, meta), stored) in items.iter().zip(&stored_paths) {
            if cancel.load(Ordering::Relaxed) {
                return cancelled(app);
            }
            let display = path.display().to_string();
            let name = path.file_name().map(os_bytes).unwrap_or_default();
            match &meta.kind {
                SourceKind::Folder => {
                    if options.keep_path && !stored.is_empty() {
                        let arn = new_arn();
                        graph.add(&arn, &rdf_type(), Term::Iri(aff4l("Folder")));
                        name_and_meta(&mut graph, &arn, &name, stored, meta);
                        graph.add(&arn, &factum("task"), Term::Iri(task_arn.clone()));
                        folders.push(FolderRecord {
                            arn,
                            path: encode_name(stored).text,
                        });
                    }
                }
                SourceKind::Special => {
                    skipped.push((display, "special file (device, socket or FIFO), not added".to_string()));
                }
                SourceKind::Link(target) => {
                    let arn = new_arn();
                    graph.add(&arn, &rdf_type(), Term::Iri(aff4("FileImage")));
                    name_and_meta(&mut graph, &arn, &name, stored, meta);
                    graph.add(&arn, &aff4("size"), typed(0, "long"));
                    path_triples(&mut graph, &arn, "symlinkTarget", target);
                    path_triples(&mut graph, &arn, "sourcePath", path);
                    graph.add(&arn, &factum("task"), Term::Iri(task_arn.clone()));
                    records.push(FileRecord {
                        arn,
                        path: encode_name(stored).text,
                        size: 0,
                        md5: String::new(),
                        sha1: String::new(),
                        sha256: String::new(),
                        metadata_only: false,
                        excerpt: None,
                        link: Some(target.display().to_string()),
                        source: Some(display.clone()),
                        source_raw: raw_path(path),
                    });
                    progress.files.fetch_add(1, Ordering::Relaxed);
                }
                SourceKind::File => {
                    let arn = new_arn();
                    let member = member_name(&arn, &volume_arn);
                    let file_start = app.position();
                    let report = |read: u64| progress.bytes.store(done_bytes + read, Ordering::Relaxed);
                    let result = (|| -> io::Result<Content> {
                        let mut src = open_source(path, meta)?;
                        if let Some((from, to)) = options.excerpt {
                            src.seek(SeekFrom::Start(from))?;
                            let mut part = src.take(to - from);
                            return stream::store(app, &member, &mut part, to - from, limit, &report, cancel)
                                .map(Content::Stored);
                        }
                        // one byte more than listed is enough to know it changed
                        let mut src = src.take(meta.size.saturating_add(1));
                        if options.metadata_only {
                            let (size, digests) = stream::hash_only(&mut src, &report, cancel)?;
                            return Ok(Content::Hashed(size, digests));
                        }
                        stream::store(app, &member, &mut src, meta.size, limit, &report, cancel).map(Content::Stored)
                    })();
                    after_read(path);
                    let content = match result {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => return cancelled(app),
                        Err(e) => {
                            app.rewind_to(file_start).map_err(|e| io_error(&path_of_container, e))?;
                            errors.push((display, e.to_string()));
                            continue;
                        }
                        Ok(content) => content,
                    };
                    let read_size = match &content {
                        Content::Stored(stored) => stored.size,
                        Content::Hashed(size, _) => *size,
                    };
                    let expected = options.excerpt.map_or(meta.size, |(from, to)| to - from);
                    let after = read_meta(path).ok();
                    let changed = read_size != expected
                        || after.is_none_or(|after| after.size != meta.size || after.modified != meta.modified);
                    if changed {
                        app.rewind_to(file_start).map_err(|e| io_error(&path_of_container, e))?;
                        errors.push((display, "changed while it was read; not added".to_string()));
                        continue;
                    }
                    graph.add(&arn, &rdf_type(), Term::Iri(aff4("FileImage")));
                    graph.add(&arn, &rdf_type(), Term::Iri(aff4("Image")));
                    let digests = match &content {
                        Content::Stored(stored) => {
                            match stored.storage {
                                Storage::ZipSegment => {
                                    graph.add(&arn, &rdf_type(), Term::Iri(aff4("ZipSegment")));
                                }
                                Storage::ImageStream { .. } => {
                                    graph.add(&arn, &rdf_type(), Term::Iri(aff4("ImageStream")));
                                    graph.add(&arn, &aff4("chunkSize"), typed(stream::CHUNK_SIZE, "int"));
                                    graph.add(&arn, &aff4("chunksInSegment"), typed(stream::CHUNKS_PER_SEGMENT, "int"));
                                    graph.add(&arn, &aff4("compressionMethod"), Term::Iri(ZLIB.into()));
                                }
                            }
                            graph.add(&arn, &aff4("stored"), Term::Iri(volume_arn.clone()));
                            stored.digests.clone()
                        }
                        Content::Hashed(_, digests) => digests.clone(),
                    };
                    name_and_meta(&mut graph, &arn, &name, stored, meta);
                    graph.add(&arn, &aff4("size"), typed(read_size, "long"));
                    hash_triples(&mut graph, &arn, &digests);
                    if options.metadata_only {
                        graph.add(&arn, &factum("metadataOnly"), typed("true", "boolean"));
                    }
                    if let Some((from, to)) = options.excerpt {
                        graph.add(&arn, &factum("excerptStart"), typed(from, "long"));
                        graph.add(&arn, &factum("excerptEnd"), typed(to, "long"));
                        graph.add(&arn, &factum("originalSize"), typed(meta.size, "long"));
                    }
                    path_triples(&mut graph, &arn, "sourcePath", path);
                    graph.add(&arn, &factum("task"), Term::Iri(task_arn.clone()));
                    done_bytes += read_size;
                    progress.bytes.store(done_bytes, Ordering::Relaxed);
                    progress.files.fetch_add(1, Ordering::Relaxed);
                    records.push(FileRecord {
                        arn,
                        path: encode_name(stored).text,
                        size: read_size,
                        md5: digests.md5,
                        sha1: digests.sha1,
                        sha256: digests.sha256,
                        metadata_only: options.metadata_only,
                        excerpt: options.excerpt,
                        link: None,
                        source: Some(display.clone()),
                        source_raw: raw_path(path),
                    });
                }
            }
        }
        // a copy replaces a damaged one only when it is the same content: a source that changed since is new evidence
        let earlier: HashMap<String, FileRecord> = file_records(&self.graph)
            .into_iter()
            .map(|r| (r.arn.clone(), r))
            .collect();
        let mut by_source: HashMap<PathBuf, &FileRecord> = HashMap::new();
        for record in &records {
            if let Some(source) = record.source_path() {
                by_source.entry(source).or_insert(record);
            }
        }
        let replaced = options
            .replaces
            .iter()
            .filter_map(|(source, old)| {
                let new = *by_source.get(source)?;
                let old_record = earlier.get(old)?;
                let same = (&new.md5, &new.sha1, &new.sha256, new.size)
                    == (&old_record.md5, &old_record.sha1, &old_record.sha256, old_record.size);
                same.then(|| (old.clone(), new.arn.clone()))
            })
            .collect();
        Ok(Staged {
            start,
            records,
            folders,
            replaced,
            skipped,
            errors,
            graph,
            mounts,
            task_arn,
            base: options.base.clone(),
            keep_path: options.keep_path,
            mark,
        })
    }

    /// Lists a staged Add operation: one LogicalAcquisitionTask naming the log entry, a new information.turtle,
    /// and a directory without the signatures of the previous close (they no longer match).
    pub fn finalize_add(&mut self, staged: &Staged, entry_id: i64) -> Result<u64> {
        if std::mem::take(&mut self.fail_next_finalize) {
            return Err(FactumError::general("The container could not be written (test)."));
        }
        let mut graph = self.graph.clone();
        graph.extend(staged.graph.clone());
        let task = &staged.task_arn;
        graph.add(task, &rdf_type(), Term::Iri(aff4l("LogicalAcquisitionTask")));
        // without a base path the full paths are stored: below / on Unix, with the drive on Windows
        let root = if staged.base.as_os_str().is_empty() {
            if cfg!(windows) { String::new() } else { "/".to_string() }
        } else {
            encode_name(&os_bytes(staged.base.as_os_str())).text
        };
        graph.add(task, &aff4l("filesystemRoot"), plain(root));
        graph.add(task, &aff4l("pathSeparator"), plain(std::path::MAIN_SEPARATOR_STR));
        graph.add(task, &factum("logEntry"), typed(entry_id, "long"));
        for (old, new) in &staged.replaced {
            graph.add(old, &factum("replacedBy"), Term::Iri(new.clone()));
        }
        let mount_arns: Vec<String> = staged.mounts.iter().map(|_| new_arn()).collect();
        // the task's triples first: the file lists them by subject, in the order subjects first appear
        for arn in &mount_arns {
            graph.add(task, &factum("mount"), Term::Iri(arn.clone()));
        }
        for (arn, mount) in mount_arns.iter().zip(&staged.mounts) {
            mount_triples(&mut graph, arn, mount);
        }
        self.commit(graph, &[], &SIGNATURE_MEMBERS)
    }

    /// Drops a staged (or finalized but not logged) Add operation: the file is cut back to the state before it.
    pub fn discard(&mut self, staged: Staged) -> Result<()> {
        self.rollback_to(staged.mark)
    }

    pub fn mark(&self) -> Mark {
        Mark {
            base_end: self.archive.end,
            write_pos: self.app.as_ref().map_or(self.archive.end, Appender::position),
        }
    }

    /// Continues from the earlier complete state that ends at `end`; what was written after it stays in the file,
    /// unreferenced (a state the case log never recorded).
    pub fn set_aside_after(&mut self, end: u64) -> Result<()> {
        let write_pos = self.mark().write_pos;
        self.rollback_to(Mark {
            base_end: end,
            write_pos,
        })
    }

    /// Cuts the file back to `mark.write_pos` and reloads the state that ends at `mark.base_end`.
    /// The state is read first: when it cannot be, nothing changes and the volume stays as it was.
    pub fn rollback_to(&mut self, mark: Mark) -> Result<()> {
        let path = self.path.clone();
        let file = self.app()?.file_mut().map_err(|e| io_error(&path, e))?;
        let archive = read_archive(file, mark.base_end).map_err(|e| io_error(&path, e))?;
        let entry = archive
            .get(TURTLE)
            .ok_or_else(|| FactumError::general("information.turtle is missing."))?;
        let turtle = member_text(file, entry).map_err(|e| io_error(&path, e))?;
        let graph = turtle::parse(&turtle).map_err(FactumError::general)?;
        let file = self.app.take().expect("checked above").into_file();
        // only a failed truncation leaves the volume without a writer; app() then says so
        self.app = Some(Appender::new(file, mark.write_pos, archive.entries.clone()).map_err(|e| io_error(&path, e))?);
        self.graph = graph;
        self.archive = archive;
        Ok(())
    }

    /// Closes the current state: its signatures at the root, and a copy of the signed state under
    /// factum/history/<n>/, byte for byte the root `information.turtle`. Returns n.
    pub fn close(&mut self, signatures: &Signatures) -> Result<u32> {
        let n = self.history_count().checked_add(1).ok_or_else(|| {
            FactumError::general("The container lists a closed state with the highest number; it cannot be closed.")
        })?;
        let turtle = self.member(TURTLE)?;
        let hashes = hashes_bytes(&self.uuid, &turtle);
        let mut members: Vec<(String, Vec<u8>)> =
            vec![(history_member(n, TURTLE), turtle), (history_member(n, HASHES), hashes)];
        for (name, data) in signatures.members() {
            members.push((name.to_string(), data.as_bytes().to_vec()));
            members.push((history_member(n, name), data.as_bytes().to_vec()));
        }
        // the root signatures always belong to the newest close
        let provided: Vec<&str> = signatures.members().iter().map(|(name, _)| *name).collect();
        let omit: Vec<&str> = SIGNATURE_MEMBERS
            .into_iter()
            .filter(|n| !provided.contains(n))
            .collect();
        let comment = self.archive.comment.clone();
        let path = self.path.clone();
        let app = self.app()?;
        let mut write = || -> io::Result<u64> {
            for (name, data) in &members {
                app.add_bytes(name, if name.ends_with(TURTLE) { 8 } else { 0 }, data)?;
            }
            app.finish(&omit, &comment)
        };
        let end = write().map_err(|e| io_error(&path, e))?;
        self.archive = Archive::new(self.app()?.entries(), comment, end);
        Ok(n)
    }

    /// Adds signatures made later to close n: under its history entry where they are missing, and at the root
    /// while the current state is still that close's. Existing members are never replaced.
    pub fn add_late_signatures(&mut self, n: u32, signatures: &Signatures) -> Result<()> {
        let signed = self.member(&history_member(n, TURTLE))?;
        let current = n == self.history_count() && signed == self.member(TURTLE)?;
        let mut members = Vec::new();
        for (name, data) in signatures.members() {
            let history = history_member(n, name);
            if self.archive.get(&history).is_none() {
                members.push((history, data.as_bytes().to_vec()));
            }
            if current && self.archive.get(name).is_none() {
                members.push((name.to_string(), data.as_bytes().to_vec()));
            }
        }
        if !members.is_empty() {
            self.commit_members(&members)?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn _assert_send() {
    fn send<T: Send>() {}
    send::<Volume>();
    send::<CdEntry>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::zip64::{find_last_end, read_archive};
    use std::sync::atomic::AtomicBool;

    thread_local! {
        /// the next create fails while writing its first members
        pub static FAIL_CREATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[test]
    fn a_failed_create_leaves_no_file() {
        let setup = Setup::new();
        FAIL_CREATE.with(|fail| fail.set(true));
        let error = Volume::create(&setup.path(), "x", &VolumeInfo::default())
            .err()
            .unwrap();
        assert!(error.to_string().contains("no space left"), "{error}");
        assert!(!setup.path().exists());
        // the name can be used again
        setup.create();
    }

    thread_local! {
        /// what the next reads of stored content fail with, as (OS error, how many times)
        pub static FAIL_READ: std::cell::Cell<(i32, u32)> = const { std::cell::Cell::new((0, 0)) };
    }

    thread_local! {
        /// what the next read of the metadata and the next opens fail with, as for FAIL_READ
        pub static FAIL_METADATA: std::cell::Cell<(i32, u32)> = const { std::cell::Cell::new((0, 0)) };
        pub static FAIL_OPEN: std::cell::Cell<(i32, u32)> = const { std::cell::Cell::new((0, 0)) };
        /// (head, tail) that a probe of the medium does not get
        pub static DEAD: std::cell::Cell<(bool, bool)> = const { std::cell::Cell::new((false, false)) };
    }

    fn next_failure(failure: &'static std::thread::LocalKey<std::cell::Cell<(i32, u32)>>) -> Option<io::Error> {
        let (code, times) = failure.get();
        (times > 0).then(|| {
            failure.set((code, times - 1));
            io::Error::from_raw_os_error(code)
        })
    }

    pub fn failed_metadata() -> Option<io::Error> {
        next_failure(&FAIL_METADATA)
    }

    pub fn failed_open() -> Option<io::Error> {
        next_failure(&FAIL_OPEN)
    }

    pub fn probed(head: bool, tail: bool) -> (bool, bool) {
        let (dead_head, dead_tail) = DEAD.get();
        (head && !dead_head, tail && !dead_tail)
    }

    pub fn failed_read() -> Option<io::Error> {
        next_failure(&FAIL_READ)
    }

    fn eio() -> io::Error {
        io::Error::from_raw_os_error(libc::EIO)
    }

    #[test]
    #[cfg(unix)]
    fn read_errors_are_sorted_into_damage_and_transient() {
        let fine = || true;
        let gone = || false;
        // what the content itself gives away counts at once
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NotFound,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(counts_as_damage(&kind.into(), gone));
        }
        // a read that fails while the file still reads
        assert!(counts_as_damage(&eio(), fine));
        assert!(counts_as_damage(&io::Error::other("anything else"), fine));
        assert!(counts_as_damage(&io::ErrorKind::Unsupported.into(), fine));
        // a removed drive gives EIO for all of the file
        assert!(!counts_as_damage(&eio(), gone));
        // these say nothing about the content, however often they come
        for code in [
            libc::EACCES,
            libc::EPERM,
            libc::EINTR,
            libc::ENODEV,
            libc::ENXIO,
            libc::ETIMEDOUT,
            libc::ESTALE,
        ] {
            assert!(!counts_as_damage(&io::Error::from_raw_os_error(code), fine), "{code}");
        }
    }

    /// The result, the files, and how many of the failures were not used up.
    fn recheck_with_failing_reads(code: i32, times: u32) -> (Result<Recheck>, Vec<FileRecord>, u32) {
        let setup = Setup::new();
        let mut volume = setup.create();
        let records = add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1).records;
        drop(volume);
        FAIL_READ.set((code, times));
        let result = recheck(
            &setup.path(),
            None,
            &records,
            &AddProgress::default(),
            &AtomicBool::new(false),
        );
        (result, records, FAIL_READ.replace((0, 0)).1)
    }

    #[test]
    #[cfg(unix)]
    fn a_read_error_that_repeats_is_damage() {
        let (result, records, _) = recheck_with_failing_reads(libc::EIO, 2);
        let result = result.unwrap();
        assert_eq!(paths(&result.mismatches), [records[0].path.as_str()]);
        assert_eq!(result.files as usize, records.len());
    }

    #[test]
    #[cfg(unix)]
    fn a_read_error_that_goes_away_is_nothing() {
        let (result, ..) = recheck_with_failing_reads(libc::EIO, 1);
        assert!(result.unwrap().mismatches.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn a_transient_read_error_stops_the_recheck_and_decides_nothing() {
        for code in [libc::EACCES, libc::ENODEV, libc::ENXIO] {
            let (result, _, left) = recheck_with_failing_reads(code, 2);
            let error = result.unwrap_err();
            assert!(error.to_string().contains("cannot be read"), "{error}");
            assert_eq!(left, 1, "retried: {code}");
        }
    }

    /// A re-check with a failing setup, one small file listed.
    fn recheck_set_up(fail: impl FnOnce()) -> Result<Recheck> {
        let setup = Setup::new();
        let mut volume = setup.create();
        let records = add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1).records;
        drop(volume);
        fail();
        let result = recheck(
            &setup.path(),
            None,
            &records,
            &AddProgress::default(),
            &AtomicBool::new(false),
        );
        FAIL_METADATA.set((0, 0));
        FAIL_OPEN.set((0, 0));
        DEAD.set((false, false));
        result
    }

    #[test]
    #[cfg(unix)]
    fn a_dead_sector_at_the_start_is_not_a_removed_drive() {
        let dead = |head, tail| {
            recheck_set_up(|| {
                FAIL_METADATA.set((libc::EIO, 2));
                DEAD.set((head, tail));
            })
        };
        for (head, tail) in [(true, false), (false, true), (false, false)] {
            let result = dead(head, tail).unwrap();
            assert_eq!(result.directory_faults.len(), 1, "{head} {tail}");
            assert!(
                result.directory_faults[0].contains("directory"),
                "{:?}",
                result.directory_faults
            );
            assert_eq!(result.files, 0);
        }
        // a removed drive
        let error = dead(true, true).unwrap_err();
        assert!(error.to_string().contains("cannot be read"), "{error}");
    }

    #[test]
    #[cfg(unix)]
    fn an_open_that_fails_is_a_fault_only_while_the_file_is_there() {
        let result = recheck_set_up(|| FAIL_OPEN.set((libc::EIO, 2))).unwrap();
        assert!(
            result.directory_faults[0].contains("cannot be opened"),
            "{:?}",
            result.directory_faults
        );
        assert_eq!((result.files, result.arns.is_empty()), (0, false));
        // once is nothing, and a transient error stays one
        assert!(
            recheck_set_up(|| FAIL_OPEN.set((libc::EIO, 1)))
                .unwrap()
                .directory_faults
                .is_empty()
        );
        assert!(recheck_set_up(|| FAIL_OPEN.set((libc::EACCES, 2))).is_err());
        // gone altogether: the stat fails as well
        let missing = recheck(
            &PathBuf::from("/nonexistent/c.aff4l"),
            None,
            &[],
            &AddProgress::default(),
            &AtomicBool::new(false),
        );
        assert!(missing.is_err());
    }

    #[test]
    fn the_last_close_number_is_refused() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let comment = volume.archive.comment.clone();
        let app = volume.app().unwrap();
        app.add_bytes(&history_member(u32::MAX, TURTLE), 8, b"# nothing")
            .unwrap();
        let end = app.finish(&[], &comment).unwrap();
        volume.archive = Archive::new(app.entries(), comment, end);
        let error = volume.close(&Signatures::default()).unwrap_err();
        assert!(error.to_string().contains("cannot be closed"), "{error}");
    }

    #[test]
    fn a_close_copies_the_stored_turtle_byte_for_byte() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let stored = format!(
            "# by another version\n{}",
            String::from_utf8(volume.member(TURTLE).unwrap()).unwrap()
        );
        let comment = volume.archive.comment.clone();
        let app = volume.app().unwrap();
        app.add_bytes(TURTLE, 8, stored.as_bytes()).unwrap();
        let end = app.finish(&[], &comment).unwrap();
        volume.archive = Archive::new(app.entries(), comment, end);
        volume.close(&Signatures::default()).unwrap();
        assert_eq!(volume.member(&history_member(1, TURTLE)).unwrap(), stored.as_bytes());
    }

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    struct Setup {
        dir: tempfile::TempDir,
        source: PathBuf,
    }

    impl Setup {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("mnt");
            std::fs::create_dir_all(source.join("Users/x")).unwrap();
            std::fs::write(source.join("Users/x/evil.exe"), b"MZ evil").unwrap();
            std::fs::write(source.join("Users/x/notes.txt"), b"notes").unwrap();
            Self { dir, source }
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("c.aff4l")
        }

        fn create(&self) -> Volume {
            let info = VolumeInfo {
                name: "FS01 preserved".into(),
                case_file: "C-1".into(),
                case_id: 1,
                evidence: Some((3, "disk".into(), "seized at desk 4".into())),
                created_utc: "2026-10-27T10:00:00.000Z".into(),
            };
            Volume::create(&self.path(), "0b4c6f2e-1a2b-4c3d-8e9f-001122334455", &info).unwrap()
        }

        fn options(&self) -> AddOptions {
            AddOptions {
                base: self.source.clone(),
                keep_path: true,
                metadata_only: false,
                excerpt: None,
                replaces: Vec::new(),
            }
        }
    }

    fn add(volume: &mut Volume, sources: &[PathBuf], options: &AddOptions, entry_id: i64) -> Staged {
        let staged = volume
            .stage_add(sources, options, &AddProgress::default(), &AtomicBool::new(false))
            .unwrap();
        volume.finalize_add(&staged, entry_id).unwrap();
        staged
    }

    fn paths(records: &[FileRecord]) -> Vec<&str> {
        records.iter().map(|r| r.path.as_str()).collect()
    }

    fn sep(path: &str) -> String {
        path.replace('/', std::path::MAIN_SEPARATOR_STR)
    }

    #[test]
    fn create_writes_the_standard_members() {
        let setup = Setup::new();
        let mut volume = setup.create();
        for name in [
            "version.txt",
            "container.description",
            "verify_container.py",
            "factum/README.txt",
            "information.turtle",
            "information.turtle.hashes",
        ] {
            assert!(volume.archive().get(name).is_some(), "{name}");
        }
        assert_eq!(
            volume.member("version.txt").unwrap(),
            format!("major=2\nminor=1\ntool=factum {}\n", crate::VERSION).into_bytes()
        );
        let arn = "aff4://0b4c6f2e-1a2b-4c3d-8e9f-001122334455";
        assert_eq!(volume.member("container.description").unwrap(), arn.as_bytes());
        assert_eq!(volume.archive().comment, arn.as_bytes());
        let graph = volume.graph();
        assert!(graph.has_type(arn, &format!("{AFF4_NS}ZipVolume")));
        assert_eq!(
            graph.first_value(arn, &format!("{FACTUM_NS}evidenceDescription")),
            Some("seized at desk 4")
        );
        let hashes = String::from_utf8(volume.member("information.turtle.hashes").unwrap()).unwrap();
        let turtle = volume.member("information.turtle").unwrap();
        assert!(hashes.contains(&hex::encode(sha2::Sha256::digest(&turtle))));
        assert!(hashes.contains(&hex::encode(sha2::Sha512::digest(&turtle))));
        assert_eq!(
            Volume::uuid_of(&setup.path()).unwrap(),
            "0b4c6f2e-1a2b-4c3d-8e9f-001122334455"
        );
        assert!(Volume::create(&setup.path(), "x", &VolumeInfo::default()).is_err());
    }

    #[test]
    fn create_add_close_reopen_add_close_keeps_history() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let first = add(
            &mut volume,
            &[setup.source.join("Users/x/evil.exe")],
            &setup.options(),
            11,
        );
        assert_eq!(paths(&first.records), vec![sep("Users/x/evil.exe")]);
        let n = volume.close(&Signatures::default()).unwrap();
        assert_eq!(n, 1);
        let history1 = volume.member("factum/history/1/information.turtle").unwrap();
        assert_eq!(history1, volume.member(TURTLE).unwrap());
        let listed1: Vec<CdEntry> = volume.archive().entries.clone();
        // reopen (nothing in the file changes) and add more
        let second = add(
            &mut volume,
            &[setup.source.join("Users/x/notes.txt")],
            &setup.options(),
            12,
        );
        assert_eq!(paths(&second.records), vec![sep("Users/x/notes.txt")]);
        assert_eq!(volume.close(&Signatures::default()).unwrap(), 2);
        assert_eq!(volume.history_count(), 2);
        assert!(volume.archive().get("factum/history/2/information.turtle").is_some());
        let records = file_records(volume.graph());
        assert_eq!(records.len(), 2);
        let old = turtle::parse(std::str::from_utf8(&history1).unwrap()).unwrap();
        assert_eq!(paths(&file_records(&old)), vec![sep("Users/x/evil.exe")]);
        assert_eq!(task_entries(volume.graph()), vec![11, 12]);
        // every member of the first closed state is still there, byte for byte
        let mut file = File::open(setup.path()).unwrap();
        let now = read_archive(&mut file, volume.end()).unwrap();
        for entry in &listed1 {
            let name = entry.name_lossy();
            if name == "information.turtle" || name == "information.turtle.hashes" {
                continue; // replaced by the newer state; the old ones are under history/1/
            }
            assert_eq!(now.get(&name), Some(entry), "{name}");
        }
    }

    #[test]
    fn history_metadata_is_compressed() {
        let setup = Setup::new();
        let mut volume = setup.create();
        add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        volume.close(&Signatures::default()).unwrap();
        for name in [TURTLE, &history_member(1, TURTLE)] {
            assert_eq!(volume.archive().get(name).unwrap().method, 8, "{name}");
        }
    }

    #[test]
    fn earlier_copy_is_prefix() {
        let setup = Setup::new();
        let mut volume = setup.create();
        add(&mut volume, &[setup.source.join("Users")], &setup.options(), 11);
        volume.close(&Signatures::default()).unwrap();
        let copy = std::fs::read(setup.path()).unwrap();
        add(
            &mut volume,
            &[setup.source.join("Users/x/notes.txt")],
            &setup.options(),
            12,
        );
        volume.close(&Signatures::default()).unwrap();
        let all = std::fs::read(setup.path()).unwrap();
        assert!(all.len() > copy.len() && all.starts_with(&copy));
    }

    #[test]
    fn interrupted_add_is_discarded_on_open() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let before = volume.archive().clone();
        volume
            .stage_add(
                std::slice::from_ref(&setup.source),
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        drop(volume); // the process died before finalize
        let (volume, discarded) = Volume::open(&setup.path(), None).unwrap();
        assert!(discarded > 0);
        assert_eq!(volume.archive(), &before);
        assert_eq!(std::fs::metadata(setup.path()).unwrap().len(), before.end);
    }

    #[test]
    fn read_graph_at_the_logged_end_skips_an_addition_being_written() {
        let setup = Setup::new();
        let mut volume = setup.create();
        add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        let (end, graph) = (volume.end(), volume.graph().clone());
        drop(volume);
        // an addition in progress: bytes after the logged state, no directory yet
        let mut file = OpenOptions::new().append(true).open(setup.path()).unwrap();
        std::io::Write::write_all(&mut file, &vec![0x50; 3 << 20]).unwrap();
        assert_eq!(read_graph(&setup.path(), Some(end)).unwrap(), graph);
        assert_eq!(read_graph(&setup.path(), None).unwrap(), graph);
    }

    #[test]
    fn a_failed_set_aside_leaves_the_volume_usable() {
        let setup = Setup::new();
        let mut volume = setup.create();
        add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        let before = volume.archive().clone();
        let mark = volume.mark();
        // not the end of a state: the set-aside fails, and the volume is unchanged
        assert!(volume.set_aside_after(volume.end() - 7).is_err());
        assert_eq!(volume.archive(), &before);
        volume.rollback_to(mark).unwrap();
        assert_eq!(volume.archive(), &before);
        add(
            &mut volume,
            &[setup.source.join("Users/x/notes.txt")],
            &setup.options(),
            2,
        );
        assert_eq!(file_records(volume.graph()).len(), 3);
    }

    #[test]
    fn changed_file_is_reported_not_added() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let b = setup.source.join("Users/x/notes.txt");
        let staged = volume
            .stage_add_with(
                &[setup.source.join("Users/x/evil.exe"), b.clone()],
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
                &|path| {
                    if path.ends_with("notes.txt") {
                        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
                        std::io::Write::write_all(&mut file, b" grown").unwrap();
                    }
                },
            )
            .unwrap();
        assert_eq!(paths(&staged.records), vec![sep("Users/x/evil.exe")]);
        assert_eq!(staged.errors.len(), 1);
        assert!(staged.errors[0].0.ends_with("notes.txt"));
        assert!(
            staged.errors[0].1.contains("changed while it was read"),
            "{}",
            staged.errors[0].1
        );
        volume.finalize_add(&staged, 1).unwrap();
        assert_eq!(file_records(volume.graph()).len(), 1);
    }

    #[test]
    fn overlapping_sources_store_each_file_once() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let staged = add(
            &mut volume,
            &[setup.source.join("Users"), setup.source.join("Users/x/evil.exe")],
            &setup.options(),
            1,
        );
        assert_eq!(
            paths(&staged.records),
            vec![sep("Users/x/evil.exe"), sep("Users/x/notes.txt")]
        );
        let folders: Vec<&str> = volume.graph().subjects_of_type(&format!("{AFF4L_NS}Folder")).collect();
        assert_eq!(folders.len(), 2); // Users, Users/x
    }

    #[test]
    fn empty_file_and_empty_folder_round_trip() {
        let setup = Setup::new();
        std::fs::write(setup.source.join("empty"), b"").unwrap();
        std::fs::create_dir(setup.source.join("void")).unwrap();
        let mut volume = setup.create();
        let staged = add(
            &mut volume,
            &[setup.source.join("empty"), setup.source.join("void")],
            &setup.options(),
            1,
        );
        assert_eq!(staged.records.len(), 1);
        assert_eq!(
            (staged.records[0].size, staged.records[0].sha256.as_str()),
            (0, EMPTY_SHA256)
        );
        let graph = volume.graph();
        let folder = graph.subjects_of_type(&format!("{AFF4L_NS}Folder")).next().unwrap();
        assert_eq!(
            graph.first_value(folder, &format!("{AFF4L_NS}originalPathName")),
            Some("void")
        );
        let mut content = Vec::new();
        volume
            .read_file(&staged.records[0].arn)
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn excerpt_out_of_range_is_refused() {
        let setup = Setup::new();
        std::fs::write(setup.source.join("six"), b"abcdef").unwrap();
        let mut volume = setup.create();
        let end = volume.end();
        for excerpt in [(5, 5), (0, 7), (4, 2)] {
            let options = AddOptions {
                excerpt: Some(excerpt),
                ..setup.options()
            };
            let result = volume.stage_add(
                &[setup.source.join("six")],
                &options,
                &AddProgress::default(),
                &AtomicBool::new(false),
            );
            assert!(result.is_err(), "{excerpt:?}");
            assert_eq!(std::fs::metadata(setup.path()).unwrap().len(), end);
        }
        let options = AddOptions {
            excerpt: Some((2, 4)),
            ..setup.options()
        };
        let staged = add(&mut volume, &[setup.source.join("six")], &options, 1);
        let record = &staged.records[0];
        assert_eq!((record.size, record.excerpt), (2, Some((2, 4))));
        let mut content = Vec::new();
        volume
            .read_file(&record.arn)
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, b"cd");
        assert_eq!(
            volume
                .graph()
                .first_value(&record.arn, &format!("{FACTUM_NS}originalSize")),
            Some("6")
        );
        // an excerpt is for a single file
        let options = AddOptions {
            excerpt: Some((0, 1)),
            ..setup.options()
        };
        assert!(
            volume
                .stage_add(
                    &[setup.source.join("Users")],
                    &options,
                    &AddProgress::default(),
                    &AtomicBool::new(false)
                )
                .is_err()
        );
    }

    #[test]
    fn metadata_only_hashes_original_and_stores_nothing() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let options = AddOptions {
            metadata_only: true,
            ..setup.options()
        };
        let staged = add(&mut volume, &[setup.source.join("Users/x/evil.exe")], &options, 1);
        let record = &staged.records[0];
        assert!(record.metadata_only);
        assert_eq!(record.size, 7);
        assert_eq!(record.sha256, hex::encode(sha2::Sha256::digest(b"MZ evil")));
        assert!(volume.archive().get(&record.arn).is_none());
        assert_eq!(
            volume
                .graph()
                .first_value(&record.arn, &format!("{FACTUM_NS}metadataOnly")),
            Some("true")
        );
        assert!(!volume.graph().has_type(&record.arn, &format!("{AFF4_NS}ZipSegment")));
    }

    #[cfg(unix)]
    #[test]
    fn special_files_are_skipped_and_links_recorded() {
        let setup = Setup::new();
        std::os::unix::fs::symlink("Users/x/evil.exe", setup.source.join("link")).unwrap();
        let fifo = std::process::Command::new("mkfifo")
            .arg(setup.source.join("pipe"))
            .status()
            .is_ok_and(|s| s.success());
        let mut volume = setup.create();
        let staged = add(
            &mut volume,
            &[setup.source.join("link"), setup.source.join("pipe")],
            &setup.options(),
            1,
        );
        if fifo {
            assert_eq!(staged.skipped.len(), 1);
            assert!(staged.skipped[0].0.ends_with("pipe"));
        }
        assert_eq!(staged.records.len(), 1);
        assert_eq!(staged.records[0].link.as_deref(), Some("Users/x/evil.exe"));
        assert_eq!((staged.records[0].size, staged.records[0].sha256.as_str()), (0, ""));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_folder_is_an_error_with_its_path() {
        use std::os::unix::fs::PermissionsExt;
        let setup = Setup::new();
        let locked = setup.source.join("a: locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            return; // running as root: nothing is unreadable
        }
        let mut volume = setup.create();
        let staged = volume
            .stage_add(
                &[locked.clone(), setup.source.join("Users/x/notes.txt")],
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(staged.errors.len(), 1, "{:?}", staged.errors);
        assert_eq!(staged.errors[0].0, locked.display().to_string());
        assert!(!staged.errors[0].1.contains("locked"), "{}", staged.errors[0].1);
        assert_eq!(staged.records.len(), 1);
    }

    #[test]
    fn cancel_adds_nothing() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let end = volume.end();
        let result = volume.stage_add(
            std::slice::from_ref(&setup.source),
            &setup.options(),
            &AddProgress::default(),
            &AtomicBool::new(true),
        );
        assert!(result.unwrap_err().to_string().contains("nothing was added"));
        assert_eq!(std::fs::metadata(setup.path()).unwrap().len(), end);
        assert_eq!(volume.end(), end);
    }

    #[test]
    fn source_outside_base_adds_nothing() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let end = volume.end();
        let outside = setup.dir.path().join("elsewhere");
        std::fs::write(&outside, b"x").unwrap();
        let error = volume
            .stage_add(
                &[setup.source.join("Users/x/evil.exe"), outside.clone()],
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(error.to_string().contains(&outside.display().to_string()));
        assert_eq!(std::fs::metadata(setup.path()).unwrap().len(), end);
    }

    /// A state after the created one, and an interrupted Add after it; the end of each state and the file's length.
    fn two_states_and_a_tail(setup: &Setup) -> (u64, u64, u64) {
        let mut volume = setup.create();
        let first = volume.end();
        add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        let second = volume.end();
        volume
            .stage_add(
                std::slice::from_ref(&setup.source),
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        drop(volume);
        let len = std::fs::metadata(setup.path()).unwrap().len();
        assert!(len > second);
        (first, second, len)
    }

    #[test]
    fn a_read_error_while_opening_cuts_nothing() {
        let setup = Setup::new();
        let (first, second, len) = two_states_and_a_tail(&setup);
        // each read in turn fails once
        for n in 1.. {
            crate::container::zip64::FAIL_READ.with(|fail| fail.set(n));
            let opened = Volume::open(&setup.path(), Some(first));
            if crate::container::zip64::FAIL_READ.with(|fail| fail.replace(0)) != 0 {
                let (volume, discarded) = opened.unwrap();
                assert_eq!((volume.end(), discarded), (second, len - second));
                break;
            }
            assert_read_refused(&opened.err().unwrap());
            assert_eq!(std::fs::metadata(setup.path()).unwrap().len(), len, "{n}");
        }
    }

    fn assert_read_refused(error: &FactumError) {
        let text = error.to_string();
        assert!(text.contains("was not opened, nothing in it was changed"), "{text}");
        assert!(text.contains("could not be read") && text.contains("error 5"), "{text}");
        assert!(!text.contains("not a factum container"), "{text}");
        assert!(!error.is(crate::error::ErrorKind::ContainerCrc), "{text}");
    }

    #[test]
    fn a_read_error_on_a_member_says_so() {
        let setup = Setup::new();
        drop(setup.create());
        // every read in turn fails once, those of version.txt, the description and the metadata among them
        let refused = |read: &dyn Fn() -> Result<()>| {
            for n in 1.. {
                crate::container::zip64::FAIL_READ.with(|fail| fail.set(n));
                let result = read();
                if crate::container::zip64::FAIL_READ.with(|fail| fail.replace(0)) != 0 {
                    result.unwrap();
                    return n - 1;
                }
                assert_read_refused(&result.err().unwrap());
            }
            unreachable!()
        };
        let opens = refused(&|| Volume::open(&setup.path(), None).map(|_| ()));
        let descriptions = refused(&|| Volume::uuid_of(&setup.path()).map(|_| ()));
        assert!(opens > descriptions && descriptions > 0, "{opens} {descriptions}");
    }

    #[test]
    fn a_state_that_cannot_be_read_is_not_cut_off() {
        let setup = Setup::new();
        let (first, second, _) = two_states_and_a_tail(&setup);
        // the classic end record of the newest state, damaged: bytes that end no directory, a state all the same
        let mut bytes = std::fs::read(setup.path()).unwrap();
        let locator = bytes[..second as usize]
            .windows(4)
            .rposition(|w| w == b"PK\x06\x07")
            .unwrap();
        bytes[locator + 20] ^= 1;
        std::fs::write(setup.path(), &bytes).unwrap();
        for known in [Some(first), None] {
            let error = Volume::open(&setup.path(), known).err().unwrap();
            assert!(
                error.to_string().contains("more than an interrupted addition"),
                "{error}"
            );
            assert_eq!(std::fs::read(setup.path()).unwrap(), bytes);
        }
    }

    #[test]
    fn a_logged_state_is_not_cut_off_whatever_replaced_it() {
        let setup = Setup::new();
        let (first, second, _) = two_states_and_a_tail(&setup);
        let directory = bytes_before_directory(&setup, second);
        // the newest directory and all that follows it, zeroed
        let mut bytes = std::fs::read(setup.path()).unwrap();
        bytes[directory..].fill(0);
        std::fs::write(setup.path(), &bytes).unwrap();
        for known in [Some(second), Some(first), None] {
            let error = Volume::open(&setup.path(), known).err().unwrap();
            assert!(error.to_string().contains("nothing in it was changed"), "{error}");
            assert_eq!(std::fs::read(setup.path()).unwrap(), bytes);
        }
    }

    /// Where the directory of the state ending at `end` starts.
    fn bytes_before_directory(setup: &Setup, end: u64) -> usize {
        let bytes = std::fs::read(setup.path()).unwrap();
        let record = bytes[..end as usize]
            .windows(4)
            .rposition(|w| w == b"PK\x06\x06")
            .unwrap();
        u64::from_le_bytes(bytes[record + 48..record + 56].try_into().unwrap()) as usize
    }

    #[test]
    fn second_open_is_refused_while_locked() {
        let setup = Setup::new();
        let volume = setup.create();
        let error = Volume::open(&setup.path(), None).err().unwrap();
        assert!(
            error.to_string().contains("in use by another factum process"),
            "{error}"
        );
        drop(volume);
        Volume::open(&setup.path(), None).unwrap();
    }

    #[test]
    fn discard_restores_the_previous_state() {
        let setup = Setup::new();
        let mut volume = setup.create();
        volume
            .close(&Signatures {
                gpg: Some(("SIG".into(), "KEY".into())),
                x509: None,
            })
            .unwrap();
        let before = volume.archive().clone();
        let staged = volume
            .stage_add(
                std::slice::from_ref(&setup.source),
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        volume.finalize_add(&staged, 1).unwrap();
        // the log append failed after the container was written: back to the state before
        volume.discard(staged).unwrap();
        assert_eq!(volume.archive(), &before);
        assert!(volume.archive().get(SIG_GPG).is_some());
        assert_eq!(file_records(volume.graph()).len(), 0);
    }

    #[test]
    fn failing_finalize_seam() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let staged = volume
            .stage_add(
                std::slice::from_ref(&setup.source),
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        volume.fail_next_finalize = true;
        assert!(volume.finalize_add(&staged, 1).is_err());
        volume.discard(staged).unwrap();
        assert_eq!(file_records(volume.graph()).len(), 0);
    }

    #[test]
    fn signatures_go_to_root_and_history_and_late_ones_are_added() {
        let setup = Setup::new();
        let mut volume = setup.create();
        add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        assert_eq!(volume.close(&Signatures::default()).unwrap(), 1);
        assert!(volume.archive().get(SIG_GPG).is_none());
        let late = Signatures {
            gpg: Some(("ARMORED".into(), "PUBKEY".into())),
            x509: Some(("PEM".into(), "CHAIN".into())),
        };
        volume.add_late_signatures(1, &late).unwrap();
        for name in [SIG_GPG, KEY_GPG, SIG_X509, CER_X509] {
            assert!(volume.archive().get(name).is_some(), "{name}");
            assert!(
                volume.archive().get(&format!("factum/history/1/{name}")).is_some(),
                "{name}"
            );
        }
        assert_eq!(
            volume.member("factum/history/1/information.turtle.asc").unwrap(),
            b"ARMORED"
        );
        // existing members are never replaced
        volume
            .add_late_signatures(
                1,
                &Signatures {
                    gpg: Some(("OTHER".into(), "K".into())),
                    x509: None,
                },
            )
            .unwrap();
        assert_eq!(
            volume.member("factum/history/1/information.turtle.asc").unwrap(),
            b"ARMORED"
        );
        // after more content, a signature of close 1 only goes to its history entry
        add(
            &mut volume,
            &[setup.source.join("Users/x/notes.txt")],
            &setup.options(),
            2,
        );
        assert!(volume.archive().get(SIG_GPG).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_name_round_trips() {
        use base64::Engine;
        use std::os::unix::ffi::OsStrExt;
        let setup = Setup::new();
        let raw = b"caf\xe9\x01.txt";
        let path = setup.source.join(std::ffi::OsStr::from_bytes(raw));
        std::fs::write(&path, b"x").unwrap();
        let mut volume = setup.create();
        let staged = add(&mut volume, &[path], &setup.options(), 1);
        let arn = &staged.records[0].arn;
        let graph = volume.graph();
        assert_eq!(
            graph.first_value(arn, &format!("{AFF4L_NS}fileName")),
            Some("caf%E9%01.txt")
        );
        assert_eq!(staged.records[0].path, "caf%E9%01.txt");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(graph.first_value(arn, &format!("{AFF4L_NS}fileNameRaw")).unwrap())
            .unwrap();
        assert_eq!(decoded, raw);
        assert!(
            graph
                .first_value(arn, &format!("{AFF4L_NS}originalPathNameRaw"))
                .is_some()
        );
    }

    #[test]
    fn thousands_of_small_files() {
        let setup = Setup::new();
        let root = setup.source.join("many");
        for folder in 0..50 {
            let dir = root.join(format!("d{folder:02}"));
            std::fs::create_dir_all(&dir).unwrap();
            for file in 0..100 {
                std::fs::write(dir.join(format!("f{file:03}")), b"0123456789").unwrap();
            }
        }
        let mut volume = setup.create();
        let started = std::time::Instant::now();
        let progress = AddProgress::default();
        let staged = volume
            .stage_add(&[root], &setup.options(), &progress, &AtomicBool::new(false))
            .unwrap();
        volume.finalize_add(&staged, 1).unwrap();
        assert_eq!(staged.records.len(), 5000);
        assert_eq!(progress.files.load(std::sync::atomic::Ordering::Relaxed), 5000);
        assert_eq!(progress.total_bytes.load(std::sync::atomic::Ordering::Relaxed), 50_000);
        drop(volume);
        let (volume, discarded) = Volume::open(&setup.path(), None).unwrap();
        assert_eq!((discarded, file_records(volume.graph()).len()), (0, 5000));
        // adding, reopening and listing stay well below a second per thousand files, even in a debug build
        assert!(started.elapsed().as_secs() < 10, "{:?}", started.elapsed());
    }

    #[test]
    fn image_stream_files_round_trip() {
        let setup = Setup::new();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(setup.source.join("big"), &data).unwrap();
        let mut volume = setup.create();
        volume.segment_limit = 1000;
        let staged = add(&mut volume, &[setup.source.join("big")], &setup.options(), 1);
        let arn = staged.records[0].arn.clone();
        assert!(volume.graph().has_type(&arn, &format!("{AFF4_NS}ImageStream")));
        let mut back = Vec::new();
        volume.read_file(&arn).unwrap().read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn a_crash_in_the_first_bevy_of_a_large_zip_recovers_by_itself() {
        let setup = Setup::new();
        // as a large ZIP starts: a header and data that does not compress, stored raw in the first chunk
        let mut x = 0x1234_5678u32;
        let noise: Vec<u8> = (0..40_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let zip = setup.dir.path().join("evidence.zip");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&zip)
            .unwrap();
        let mut app = Appender::new(file, 0, Vec::new()).unwrap();
        app.add_bytes("inner", 0, &noise).unwrap();
        app.add_bytes("second", 0, b"second").unwrap();
        app.finish(&[], b"").unwrap();
        drop(app);
        std::fs::copy(&zip, setup.source.join("large.zip")).unwrap();

        let mut volume = setup.create();
        let first = volume.end();
        add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        let second = volume.end();
        volume.segment_limit = 1000;
        let staged = volume
            .stage_add(
                &[setup.source.join("large.zip")],
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        let bevy = member_name(&format!("{}/00000000", staged.records[0].arn), &volume.arn());
        drop(volume);

        // the bevy being written: its placeholders, and part of its content
        let mut bytes = std::fs::read(setup.path()).unwrap();
        let header = bytes.windows(bevy.len()).position(|w| w == bevy.as_bytes()).unwrap() - 30;
        let data = header + 30 + bevy.len() + 20;
        assert_eq!(bytes[data..data + 4], *b"PK\x03\x04");
        bytes[header + 14..header + 18].fill(0);
        bytes[header + 30 + bevy.len() + 4..data].fill(0);
        bytes.truncate(data + 45_000);
        std::fs::write(setup.path(), &bytes).unwrap();

        for known in [Some(second), Some(first), None] {
            std::fs::write(setup.path(), &bytes).unwrap();
            let (volume, discarded) = Volume::open(&setup.path(), known).unwrap();
            assert_eq!((volume.end(), discarded), (second, bytes.len() as u64 - second));
        }
    }

    /// Flips a bit in the CRC-32 of a central entry of the newest directory: the content stays as it is.
    fn flip_crc_field(path: &Path, name: &str) {
        let mut bytes = std::fs::read(path).unwrap();
        let name = [name.as_bytes(), &[1, 0, 24, 0]].concat();
        let at = bytes.windows(name.len()).rposition(|w| w == name).unwrap();
        assert_eq!(bytes[at - 46..at - 42], *b"PK\x01\x02");
        bytes[at - 46 + 16] ^= 1;
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn a_crc_field_alone_is_a_finding_of_its_own_and_no_damage_to_the_content() {
        let setup = Setup::new();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(setup.source.join("big"), &data).unwrap();
        let mut volume = setup.create();
        let small = add(
            &mut volume,
            &[setup.source.join("Users/x/notes.txt")],
            &setup.options(),
            1,
        );
        volume.segment_limit = 1000;
        let big = add(&mut volume, &[setup.source.join("big")], &setup.options(), 2);
        let records = [small.records[0].clone(), big.records[0].clone()];
        let segment = volume.archive().get_arn(&records[0].arn).unwrap().name_lossy();
        let bevy = member_name(&format!("{}/00000000", records[1].arn), &volume.arn());
        drop(volume);
        let (progress, cancel) = (AddProgress::default(), AtomicBool::new(false));

        // the content matches: the re-check says so, Verify says that and the CRC, a plain read fails
        for (name, record) in [(&segment, &records[0]), (&bevy, &records[1])] {
            flip_crc_field(&setup.path(), name);
            let recheck = recheck(&setup.path(), None, &records, &progress, &cancel).unwrap();
            assert_eq!(recheck.mismatches, Vec::new(), "{name}");

            let report = crate::container::verify::verify_file(
                &setup.path(),
                &crate::signer::FakeSigner::new(false),
                &crate::container::x509::Gpgsm::unavailable(),
                &|_, _| {},
                &cancel,
            )
            .unwrap();
            assert_eq!(report.checked_files, 2);
            let fails: Vec<_> = report
                .findings
                .iter()
                .filter(|f| f.level == crate::verifier::Level::Fail)
                .collect();
            assert_eq!(fails.len(), 1, "{fails:?}");
            assert_eq!(fails[0].code, "stream_hash");
            assert!(fails[0].message.contains("CRC-32 differs"), "{}", fails[0].message);
            assert!(fails[0].message.contains(name.as_str()), "{}", fails[0].message);

            let (mut volume, _) = Volume::open(&setup.path(), None).unwrap();
            let error = volume.read_file(&record.arn).unwrap().read_to_end(&mut Vec::new());
            assert!(error.unwrap_err().to_string().contains("CRC-32"));
            drop(volume);
            flip_crc_field(&setup.path(), name);
        }
    }

    #[test]
    fn a_crc_field_refuses_the_open_and_says_what_to_do() {
        let setup = Setup::new();
        drop(setup.create());
        let good = std::fs::read(setup.path()).unwrap();
        for name in ["version.txt", "container.description", TURTLE] {
            std::fs::write(setup.path(), &good).unwrap();
            flip_crc_field(&setup.path(), name);
            let flipped = std::fs::read(setup.path()).unwrap();
            let mut errors = vec![Volume::open(&setup.path(), None).err().unwrap()];
            if name == "container.description" {
                errors.push(Volume::uuid_of(&setup.path()).unwrap_err());
            }
            for error in errors {
                assert!(error.is(crate::error::ErrorKind::ContainerCrc), "{error}");
                let text = error.to_string();
                assert!(text.contains("was not opened, nothing in it was changed"), "{text}");
                assert!(text.contains(&format!("{name} differs from the CRC-32")), "{text}");
                assert!(text.contains("Verify Container"), "{text}");
                assert!(!text.contains("not a factum container"), "{text}");
            }
            assert_eq!(std::fs::read(setup.path()).unwrap(), flipped);
        }
        // other failures stay what they were
        std::fs::write(setup.path(), &good).unwrap();
        rewrite_local_name(&setup.path(), "version.txt");
        let error = Volume::open(&setup.path(), None).err().unwrap();
        assert!(!error.is(crate::error::ErrorKind::ContainerCrc), "{error}");
        assert!(error.to_string().contains("not a factum container"), "{error}");
    }

    /// Changes the name in a member's local header.
    fn rewrite_local_name(path: &Path, name: &str) {
        let mut bytes = std::fs::read(path).unwrap();
        let at = bytes.windows(name.len()).position(|w| w == name.as_bytes()).unwrap();
        bytes[at] ^= 1;
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn recheck_tells_damage_from_read_errors() {
        use io::ErrorKind::*;
        for kind in [InvalidData, InvalidInput, NotFound, UnexpectedEof] {
            assert!(is_damage(kind), "{kind:?}");
        }
        for kind in [PermissionDenied, Other, TimedOut, WouldBlock] {
            assert!(!is_damage(kind), "{kind:?}");
        }
    }

    #[test]
    fn readme_names_the_script_hash() {
        let setup = Setup::new();
        let mut volume = setup.create();
        let readme = String::from_utf8(volume.member("factum/README.txt").unwrap()).unwrap();
        let script = volume.member("verify_container.py").unwrap();
        let hash = hex::encode(sha2::Sha256::digest(&script));
        assert_eq!(script, VERIFY_CONTAINER_PY);
        assert!(readme.contains(&hash), "{readme}");
        assert!(readme.contains(&format!(
            "blob/v{}/src/container/verify_container.py",
            env!("CARGO_PKG_VERSION")
        )));
    }

    #[test]
    fn records_survive_json() {
        let record = FileRecord {
            arn: "aff4://a".into(),
            path: "x".into(),
            size: 2,
            md5: "m".into(),
            sha1: "s".into(),
            sha256: "t".into(),
            metadata_only: false,
            excerpt: Some((1, 3)),
            link: None,
            source: Some("/mnt/x".into()),
            source_raw: None,
        };
        let json = record.to_json();
        assert_eq!(json["excerpt"], serde_json::json!([1, 3]));
        assert_eq!(json["link"], serde_json::Value::Null);
        // the payload of a plain path is what it always was
        assert!(json.get("source_raw").is_none());
        assert_eq!(FileRecord::from_json(&json), Some(record.clone()));
        let record = FileRecord {
            source_raw: Some("L21udC94".into()),
            ..record
        };
        assert_eq!(FileRecord::from_json(&record.to_json()), Some(record));
    }

    /// The source tree of `Setup` with two more files; the second comes after the first when walked.
    #[cfg(unix)]
    fn a_and_b(setup: &Setup) -> (PathBuf, PathBuf) {
        let (a, b) = (setup.source.join("a"), setup.source.join("b"));
        std::fs::write(&a, b"first").unwrap();
        std::fs::write(&b, b"second").unwrap();
        (a, b)
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_swapped_in_after_the_walk_is_an_error_of_that_file() {
        let setup = Setup::new();
        let (a, b) = a_and_b(&setup);
        let mut volume = setup.create();
        // the walk is over when the first file has been read
        let staged = volume
            .stage_add_with(
                &[a, b.clone()],
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
                &|path| {
                    if path.ends_with("a") {
                        std::fs::remove_file(&b).unwrap();
                        let made = std::process::Command::new("mkfifo").arg(&b).status();
                        assert!(made.is_ok_and(|s| s.success()));
                    }
                },
            )
            .unwrap();
        assert_eq!(paths(&staged.records), vec!["a"]);
        assert_eq!(staged.errors.len(), 1);
        assert!(staged.errors[0].0.ends_with("b"));
        assert!(
            staged.errors[0].1.contains("changed after it was listed"),
            "{}",
            staged.errors[0].1
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_swapped_in_after_the_walk_is_not_followed() {
        let setup = Setup::new();
        let (a, b) = a_and_b(&setup);
        let secret = setup.dir.path().join("secret");
        std::fs::write(&secret, b"SECOND").unwrap();
        let mut volume = setup.create();
        let staged = volume
            .stage_add_with(
                &[a, b.clone()],
                &setup.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
                &|path| {
                    if path.ends_with("a") {
                        std::fs::remove_file(&b).unwrap();
                        std::os::unix::fs::symlink(&secret, &b).unwrap();
                    }
                },
            )
            .unwrap();
        assert_eq!(paths(&staged.records), vec!["a"]);
        assert!(staged.errors[0].1.contains("changed after it was listed"));
    }

    /// A regular file of size 0 by its metadata that has content: reading stops one byte after the listed size.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_longer_than_listed_is_not_read_to_its_end() {
        let status = PathBuf::from("/proc/self/status");
        if !status.exists() {
            return;
        }
        let setup = Setup::new();
        let mut volume = setup.create();
        for metadata_only in [true, false] {
            let options = AddOptions {
                base: PathBuf::new(),
                keep_path: false,
                metadata_only,
                ..Default::default()
            };
            let progress = AddProgress::default();
            let staged = volume
                .stage_add(
                    std::slice::from_ref(&status),
                    &options,
                    &progress,
                    &AtomicBool::new(false),
                )
                .unwrap();
            assert!(staged.records.is_empty());
            assert!(
                staged.errors[0].1.contains("changed while it was read"),
                "{:?}",
                staged.errors
            );
            assert_eq!(progress.bytes.load(Ordering::Relaxed), 1);
            volume.discard(staged).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_the_container_is_recorded_and_the_container_left_out() {
        let setup = Setup::new();
        let inside = setup.source.join("c.aff4l");
        let mut volume =
            Volume::create(&inside, "33333333-3333-3333-3333-333333333333", &VolumeInfo::default()).unwrap();
        std::os::unix::fs::symlink(&inside, setup.source.join("link")).unwrap();
        let staged = add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        assert!(!paths(&staged.records).contains(&"c.aff4l"));
        let link = staged.records.iter().find(|r| r.path == "link").unwrap();
        assert_eq!(link.link.as_deref(), Some(inside.display().to_string().as_str()));
    }

    #[test]
    fn a_hard_link_to_the_container_is_left_out_with_a_trace() {
        let setup = Setup::new();
        let inside = setup.source.join("c.aff4l");
        let mut volume =
            Volume::create(&inside, "33333333-3333-3333-3333-333333333333", &VolumeInfo::default()).unwrap();
        let hard = setup.source.join("hard");
        std::fs::hard_link(&inside, &hard).unwrap();
        let staged = add(&mut volume, std::slice::from_ref(&setup.source), &setup.options(), 1);
        assert!(staged.records.iter().all(|r| r.path != "hard" && r.path != "c.aff4l"));
        // the container under its own name needs no mention
        assert_eq!(
            staged.skipped,
            vec![(
                hard.display().to_string(),
                "the container itself; not added".to_string()
            )]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn paths_that_are_not_unicode_keep_their_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let setup = Setup::new();
        let file = setup.source.join(OsStr::from_bytes(b"caf\xe9.txt"));
        let target = PathBuf::from(OsStr::from_bytes(b"target\xff"));
        std::fs::write(&file, b"x").unwrap();
        let link = setup.source.join(OsStr::from_bytes(b"link\xe9"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut volume = setup.create();
        let staged = add(&mut volume, &[file.clone(), link.clone()], &setup.options(), 1);
        // the file as written and read back, with the display text as it always was
        let graph = read_graph(&setup.path(), None).unwrap();
        let records = file_records(&graph);
        assert_eq!(records, staged.records);
        assert_eq!(records[0].source.as_deref(), Some(file.display().to_string().as_str()));
        assert_eq!(records[0].source_path(), Some(file));
        assert_eq!(records[1].source_path(), Some(link));
        let raw = graph.first_value(&records[1].arn, &factum("symlinkTargetRaw")).unwrap();
        assert_eq!(exact_path("", Some(raw)), target);
        // plain paths have no raw form
        let plain_path = setup.source.join("Users/x/evil.exe");
        let staged = add(&mut volume, std::slice::from_ref(&plain_path), &setup.options(), 2);
        assert_eq!(staged.records[0].source_raw, None);
        assert_eq!(staged.records[0].source_path(), Some(plain_path));
    }

    #[test]
    fn last_end_hint_matches_volume_end() {
        let setup = Setup::new();
        let volume = setup.create();
        let end = volume.end();
        drop(volume);
        let mut file = File::open(setup.path()).unwrap();
        assert_eq!(find_last_end(&mut file, None).unwrap(), Some(end));
    }
}
