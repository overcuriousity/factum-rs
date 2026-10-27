//! One container file: created, filled by Add operations, closed (signed state kept under factum/history/<n>/),
//! reopened, and recovered after an interrupted Add.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::Digest;

use super::source::{self, SourceKind, SourceMeta, encode_name, open_source, os_bytes, read_meta, stored_path};
use super::stream::{self, Storage, ZLIB};
use super::turtle::{self, Graph, Term};
use super::zip64::{Appender, Archive, CdEntry, find_last_end, member_reader, read_archive};
use super::{AFF4_NS, AFF4L_NS, FACTUM_NS, RDF_NS, XSD_NS, ZIP_SEGMENT_LIMIT};
use crate::error::{FactumError, Result};

pub const TURTLE: &str = "information.turtle";
pub const HASHES: &str = "information.turtle.hashes";
pub const SIG_GPG: &str = "information.turtle.asc";
pub const KEY_GPG: &str = "information.turtle.pubkey.asc";
pub const SIG_X509: &str = "information.turtle.factum.sig";
pub const CER_X509: &str = "information.turtle.factum.cer";
pub const SIGNATURE_MEMBERS: [&str; 4] = [SIG_GPG, KEY_GPG, SIG_X509, CER_X509];
const README: &[u8] = include_bytes!("README.txt");
pub const VERIFY_CONTAINER_PY: &[u8] = include_bytes!("verify_container.py");

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOptions {
    pub base: PathBuf,
    pub keep_path: bool,
    pub metadata_only: bool,
    /// from (inclusive) and to (exclusive) byte offset, for a single file
    pub excerpt: Option<(u64, u64)>,
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
}

impl FileRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "arn": self.arn, "path": self.path, "size": self.size, "md5": self.md5, "sha1": self.sha1,
            "sha256": self.sha256, "metadata_only": self.metadata_only,
            "excerpt": self.excerpt.map(|(from, to)| json!([from, to])), "link": self.link,
        })
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
        })
    }
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
    /// (path, reason): special files
    pub skipped: Vec<(String, String)>,
    /// (path, reason): files that could not be read or changed while they were read
    pub errors: Vec<(String, String)>,
    graph: Graph,
    task_arn: String,
    base: PathBuf,
}

impl Staged {
    pub fn bytes(&self) -> u64 {
        self.records.iter().filter(|r| !r.metadata_only).map(|r| r.size).sum()
    }
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
            }
        })
        .collect()
}

/// The log entries of the Add operations a graph lists, in order.
pub fn task_entries(graph: &Graph) -> Vec<i64> {
    graph
        .subjects_of_type(&aff4l("LogicalAcquisitionTask"))
        .filter_map(|task| graph.first_value(task, &factum("logEntry"))?.parse().ok())
        .collect()
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
fn hashes_bytes(uuid: &str, turtle: &[u8]) -> Vec<u8> {
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

/// Locks the file for this process. A lock held for a moment (a child process between fork and exec still shares
/// the open file) is waited for, briefly.
fn lock(file: &File) -> Result<()> {
    for attempt in 0..20 {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if attempt < 19 => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => break,
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(FactumError::general(format!("The container cannot be locked: {e}")));
            }
        }
    }
    Err(FactumError::general(
        "The container is in use by another factum process.",
    ))
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
        lock(&file)?;
        let arn = format!("aff4://{uuid}");
        let mut app = Appender::new(file, 0, Vec::new()).map_err(|e| io_error(path, e))?;
        let version = format!("major=2\nminor=1\ntool=factum {}\n", crate::VERSION);
        let write = |app: &mut Appender| -> io::Result<()> {
            app.add_bytes("version.txt", 0, version.as_bytes())?;
            app.add_bytes("container.description", 0, arn.as_bytes())?;
            app.add_bytes("verify_container.py", 8, VERIFY_CONTAINER_PY)?;
            app.add_bytes("factum/README.txt", 8, README)?;
            Ok(())
        };
        write(&mut app).map_err(|e| io_error(path, e))?;
        let mut volume = Volume {
            path: path.to_path_buf(),
            uuid: uuid.to_string(),
            archive: Archive {
                entries: Vec::new(),
                comment: arn.clone().into_bytes(),
                end: 0,
            },
            app: Some(app),
            graph: Graph::default(),
            segment_limit: ZIP_SEGMENT_LIMIT,
            fail_next_finalize: false,
        };
        volume.commit(volume_graph(uuid, info), &[], &SIGNATURE_MEMBERS)?;
        Ok(volume)
    }

    /// Opens a container for writing. An interrupted Add left bytes after the last complete state: they are cut
    /// off; the second value says how many. `end_hint` is where the last write ended, if known.
    pub fn open(path: &Path, end_hint: Option<u64>) -> Result<(Volume, u64)> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| FactumError::general(format!("The container {} cannot be opened: {e}", path.display())))?;
        lock(&file)?;
        let not_container =
            |why: String| FactumError::general(format!("{} is not a factum container: {why}", path.display()));
        let len = file.seek(SeekFrom::End(0)).map_err(|e| io_error(path, e))?;
        let end = find_last_end(&mut file, end_hint)
            .map_err(|e| not_container(e.to_string()))?
            .ok_or_else(|| not_container("no complete ZIP directory".into()))?;
        let archive = read_archive(&mut file, end).map_err(|e| not_container(e.to_string()))?;
        let read = |file: &mut File, name: &str| -> Result<Vec<u8>> {
            let entry = archive
                .get(name)
                .ok_or_else(|| not_container(format!("{name} is missing")))?;
            let mut data = Vec::new();
            member_reader(file, entry)
                .and_then(|mut r| r.read_to_end(&mut data))
                .map_err(|e| not_container(e.to_string()))?;
            Ok(data)
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
            .map_err(|e| not_container(e.to_string()))?
            .ok_or_else(|| not_container("no complete ZIP directory".into()))?;
        let archive = read_archive(&mut file, end).map_err(|e| not_container(e.to_string()))?;
        let entry = archive
            .get("container.description")
            .ok_or_else(|| not_container("container.description is missing".into()))?;
        let mut description = String::new();
        member_reader(&mut file, entry)
            .and_then(|mut r| r.read_to_string(&mut description))
            .map_err(|e| not_container(e.to_string()))?;
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

    fn app(&mut self) -> &mut Appender {
        self.app.as_mut().expect("the volume is open")
    }

    /// The bytes `information.turtle` has in the current state; what a close signs.
    pub fn turtle_bytes(&self) -> Vec<u8> {
        turtle::write(&self.graph, &turtle::factum_prefixes()).into_bytes()
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
        let file = self.app().file_mut().map_err(|e| io_error(&path, e))?;
        let mut data = Vec::new();
        member_reader(file, &entry)
            .and_then(|mut r| r.read_to_end(&mut data))
            .map_err(|e| io_error(&path, e))?;
        Ok(data)
    }

    /// The stored content of a file.
    pub fn read_file(&mut self, arn: &str) -> Result<Box<dyn Read + '_>> {
        let graph = &self.graph;
        let number = |p: &str| graph.first_value(arn, p).and_then(|v| v.parse::<u64>().ok());
        let missing = || FactumError::general(format!("{arn} has no stored content."));
        let file = self
            .app
            .as_mut()
            .expect("the volume is open")
            .file_mut()
            .map_err(|e| io_error(&self.path, e))?;
        if graph.has_type(arn, &aff4("ZipSegment")) {
            let entry = self.archive.get(arn).ok_or_else(missing)?;
            return member_reader(file, entry).map_err(|e| io_error(&self.path, e));
        }
        if graph.has_type(arn, &aff4("ImageStream")) {
            let compression = graph
                .objects(arn, &aff4("compressionMethod"))
                .find_map(|t| t.iri().or(t.value()))
                .unwrap_or(ZLIB)
                .to_string();
            return stream::image_stream_reader(
                file,
                &self.archive,
                arn,
                number(&aff4("size")).ok_or_else(missing)?,
                number(&aff4("chunkSize")).ok_or_else(missing)?,
                number(&aff4("chunksInSegment")).ok_or_else(missing)?,
                &compression,
            )
            .map_err(|e| io_error(&self.path, e));
        }
        Err(missing())
    }

    /// Writes `graph` as the new information.turtle (and its hashes), then `extra` members, then the directory
    /// without `omit`. The volume takes the new state only when all of it was written.
    fn commit(&mut self, graph: Graph, extra: &[(String, Vec<u8>, u16)], omit: &[&str]) -> Result<u64> {
        let turtle = turtle::write(&graph, &turtle::factum_prefixes()).into_bytes();
        let hashes = hashes_bytes(&self.uuid, &turtle);
        let comment = self.archive.comment.clone();
        let path = self.path.clone();
        let app = self.app();
        let mut write = || -> io::Result<u64> {
            app.add_bytes(TURTLE, 8, &turtle)?;
            app.add_bytes(HASHES, 0, &hashes)?;
            for (name, data, method) in extra {
                app.add_bytes(name, *method, data)?;
            }
            app.finish(omit, &comment)
        };
        let end = write().map_err(|e| io_error(&path, e))?;
        self.archive = Archive {
            entries: self.app().entries(),
            comment,
            end,
        };
        self.graph = graph;
        Ok(end)
    }

    /// Writes only new members (no new information.turtle).
    fn commit_members(&mut self, members: &[(String, Vec<u8>)]) -> Result<u64> {
        let comment = self.archive.comment.clone();
        let path = self.path.clone();
        let app = self.app();
        let mut write = || -> io::Result<u64> {
            for (name, data) in members {
                app.add_bytes(name, 0, data)?;
            }
            app.finish(&[], &comment)
        };
        let end = write().map_err(|e| io_error(&path, e))?;
        self.archive = Archive {
            entries: self.app().entries(),
            comment,
            end,
        };
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
        let mut items = Vec::new();
        for walked in source::walk(sources) {
            match walked {
                Ok(item) => items.push(item),
                Err(e) => {
                    let message = e.to_string();
                    let (path, reason) = message.rsplit_once(": ").unwrap_or(("", &message));
                    errors.push((path.to_string(), reason.to_string()));
                }
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

        let start = self.end();
        let volume_arn = self.arn();
        let limit = self.segment_limit;
        let path_of_container = self.path.clone();
        let task_arn = new_arn();
        let mut graph = Graph::default();
        let mut records = Vec::new();
        let mut skipped = Vec::new();
        let mut done_bytes = 0u64;
        let app = self.app.as_mut().expect("the volume is open");
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
                    }
                }
                SourceKind::Special => {
                    skipped.push((display, "special file (device, socket or FIFO), not added".to_string()));
                }
                SourceKind::Link(target) => {
                    let arn = new_arn();
                    let target = target.display().to_string();
                    graph.add(&arn, &rdf_type(), Term::Iri(aff4("FileImage")));
                    name_and_meta(&mut graph, &arn, &name, stored, meta);
                    graph.add(&arn, &aff4("size"), typed(0, "long"));
                    graph.add(&arn, &factum("symlinkTarget"), plain(&target));
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
                        link: Some(target),
                    });
                    progress.files.fetch_add(1, Ordering::Relaxed);
                }
                SourceKind::File => {
                    let arn = new_arn();
                    let file_start = app.position();
                    let report = |read: u64| progress.bytes.store(done_bytes + read, Ordering::Relaxed);
                    let result = (|| -> io::Result<Content> {
                        let mut src = open_source(path)?;
                        if options.metadata_only {
                            let (size, digests) = stream::hash_only(&mut src, &report, cancel)?;
                            return Ok(Content::Hashed(size, digests));
                        }
                        if let Some((from, to)) = options.excerpt {
                            src.seek(SeekFrom::Start(from))?;
                            let mut part = src.take(to - from);
                            return stream::store(app, &arn, &mut part, to - from, limit, &report, cancel)
                                .map(Content::Stored);
                        }
                        stream::store(app, &arn, &mut src, meta.size, limit, &report, cancel).map(Content::Stored)
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
                    });
                }
            }
        }
        Ok(Staged {
            start,
            records,
            skipped,
            errors,
            graph,
            task_arn,
            base: options.base.clone(),
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
        let root = encode_name(&os_bytes(staged.base.as_os_str()));
        graph.add(task, &aff4l("filesystemRoot"), plain(root.text));
        graph.add(task, &aff4l("pathSeparator"), plain(std::path::MAIN_SEPARATOR_STR));
        graph.add(task, &factum("logEntry"), typed(entry_id, "long"));
        self.commit(graph, &[], &SIGNATURE_MEMBERS)
    }

    /// Drops a staged (or finalized but not logged) Add operation: the file is cut back to the state before it.
    pub fn discard(&mut self, staged: Staged) -> Result<()> {
        self.rollback_to(staged.start)
    }

    /// Cuts the file back to an earlier state that ended at `end` and reloads it.
    pub fn rollback_to(&mut self, end: u64) -> Result<()> {
        let path = self.path.clone();
        let app = self.app.take().expect("the volume is open");
        let mut file = app.into_file();
        file.set_len(end).map_err(|e| io_error(&path, e))?;
        let archive = read_archive(&mut file, end).map_err(|e| io_error(&path, e))?;
        let entry = archive
            .get(TURTLE)
            .ok_or_else(|| FactumError::general("information.turtle is missing."))?;
        let mut turtle = String::new();
        member_reader(&mut file, entry)
            .and_then(|mut r| r.read_to_string(&mut turtle))
            .map_err(|e| io_error(&path, e))?;
        self.graph = turtle::parse(&turtle).map_err(FactumError::general)?;
        self.app = Some(Appender::new(file, end, archive.entries.clone()).map_err(|e| io_error(&path, e))?);
        self.archive = archive;
        Ok(())
    }

    /// Closes the current state: its signatures at the root, and a copy of the signed state under
    /// factum/history/<n>/. Returns n.
    pub fn close(&mut self, signatures: &Signatures) -> Result<u32> {
        let n = self.history_count() + 1;
        let turtle = self.turtle_bytes();
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
        let app = self.app();
        let mut write = || -> io::Result<u64> {
            for (name, data) in &members {
                app.add_bytes(name, 0, data)?;
            }
            app.finish(&omit, &comment)
        };
        let end = write().map_err(|e| io_error(&path, e))?;
        self.archive = Archive {
            entries: self.app().entries(),
            comment,
            end,
        };
        Ok(n)
    }

    /// Adds signatures made later to close n: under its history entry where they are missing, and at the root
    /// while the current state is still that close's. Existing members are never replaced.
    pub fn add_late_signatures(&mut self, n: u32, signatures: &Signatures) -> Result<()> {
        let signed = self.member(&history_member(n, TURTLE))?;
        let current = n == self.history_count() && signed == self.turtle_bytes();
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
        assert_eq!(history1, volume.turtle_bytes());
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
        };
        let json = record.to_json();
        assert_eq!(json["excerpt"], serde_json::json!([1, 3]));
        assert_eq!(json["link"], serde_json::Value::Null);
        assert_eq!(FileRecord::from_json(&json), Some(record));
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
