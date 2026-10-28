//! Evidence containers in the case log: every creation, addition, close, reopen and late signature is a system
//! entry, and the container's state is read back from those entries (no tables of its own). The entry is written
//! first; the container file is written inside the append transaction, so a failure leaves neither.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use rusqlite::OptionalExtension;
use serde_json::{Map, Value, json};
use sha2::Digest;

use crate::canonical::utc_now;
use crate::container::volume::{
    FileRecord, FolderRecord, Signatures, Staged, TURTLE, Volume, VolumeInfo, file_records, history_member,
    task_entries,
};
use crate::container::x509::{Gpgsm, X509_CERT_SETTING, X509_CHAIN_SETTING};
use crate::db::ensure_case_open;
use crate::error::{FactumError, Result};
use crate::log_service::{Append, KIND_SYSTEM};
use crate::pystr::strip;
use crate::services::Factum;
use crate::verifier::{Finding, Level, Ref};

pub fn path_setting(uuid: &str) -> String {
    format!("container_path:{uuid}")
}

pub fn end_setting(uuid: &str) -> String {
    format!("container_end:{uuid}")
}

/// A byte count in decimal units with one decimal: 512 B, 4.1 MB.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// A container as the case tree shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSummary {
    /// the entry id of its `container_created` entry: the container's number
    pub id: i64,
    pub case_id: i64,
    pub uuid: String,
    pub name: String,
    pub open: bool,
    pub file_count: u64,
    pub path: Option<PathBuf>,
    /// no file at the remembered path
    pub missing: bool,
    /// the evidence item it belongs to (containers from before 2.8 may have none)
    pub evidence_id: Option<i64>,
    /// the newest close is signed, when it was made or later
    pub signed: bool,
    /// the newest close was a close as damaged
    pub damaged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddEvent {
    pub entry_id: i64,
    pub utc: String,
    pub files: Vec<FileRecord>,
    pub folders: Vec<FolderRecord>,
    /// the mounts the sources were read from (not recorded before 2.8)
    pub mounts: Vec<crate::container::mounts::Mount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseEvent {
    pub entry_id: i64,
    pub utc: String,
    pub turtle_sha256: String,
    pub file_count: u64,
    /// fingerprint of the GPG key that signed this close
    pub gpg: Option<String>,
    /// fingerprint of the X.509 certificate that signed this close
    pub x509: Option<String>,
    /// why an X.509 signature was configured but not made
    pub x509_refused: Option<String>,
    /// the `container_signed` entry that signed this close later
    pub signed_later: Option<i64>,
}

impl CloseEvent {
    pub fn is_signed(&self) -> bool {
        self.gpg.is_some() || self.x509.is_some() || self.signed_later.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerDetail {
    pub summary: ContainerSummary,
    pub evidence_id: Option<i64>,
    pub file_name: String,
    pub base_path: String,
    pub created_utc: String,
    pub adds: Vec<AddEvent>,
    pub closes: Vec<CloseEvent>,
    /// (entry id, time)
    pub reopens: Vec<(i64, String)>,
    /// closes logged while the file was missing (entry id, time): no state was signed or written, so they are not
    /// in `closes`, whose order matches the closed states kept in the file
    pub closed_without_file: Vec<(i64, String)>,
    /// `container_signed` entries: (entry id, turtle_sha256, gpg fingerprint, x509 fingerprint)
    pub late_signatures: Vec<(i64, String, Option<String>, Option<String>)>,
}

impl ContainerDetail {
    /// The newest close was logged while the file was missing.
    pub fn last_closed_without_file(&self) -> bool {
        let without = self.closed_without_file.last().map(|(id, _)| *id);
        without > self.closes.last().map(|c| c.entry_id)
    }

    pub fn files(&self) -> impl Iterator<Item = (&AddEvent, &FileRecord)> {
        self.adds
            .iter()
            .flat_map(|add| add.files.iter().map(move |file| (add, file)))
    }
}

/// The signatures of one state and who made them.
struct SignedState {
    signatures: Signatures,
    gpg: Option<String>,
    x509: Option<String>,
    x509_refused: Option<String>,
}

struct Event {
    entry_id: i64,
    utc: String,
    payload: Map<String, Value>,
}

impl Event {
    fn text(&self, key: &str) -> String {
        self.payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    fn optional(&self, key: &str) -> Option<String> {
        self.payload.get(key).and_then(Value::as_str).map(str::to_string)
    }

    fn signatures(&self) -> (Option<String>, Option<String>) {
        let signatures = self.payload.get("signatures");
        let get = |key: &str| {
            signatures
                .and_then(|s| s.get(key))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        (get("gpg"), get("x509"))
    }
}

fn signatures_json(gpg: &Option<String>, x509: &Option<String>) -> Value {
    json!({"gpg": gpg, "x509": x509})
}

fn plural(count: usize, word: &str) -> String {
    format!("{count} {word}{}", if count == 1 { "" } else { "s" })
}

/// Records where the container's logged state ends, in the transaction of its log entry.
fn store_end(conn: &rusqlite::Connection, uuid: &str, end: u64) -> Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![end_setting(uuid), end.to_string()],
    )?;
    Ok(())
}

fn has_storage(graph: &crate::container::turtle::Graph, arn: &str) -> bool {
    use crate::container::AFF4_NS;
    graph.has_type(arn, &format!("{AFF4_NS}ZipSegment")) || graph.has_type(arn, &format!("{AFF4_NS}ImageStream"))
}

/// Differences between the files a container graph lists and the additions the log records up to entry `upto`.
pub fn compare_records(detail: &ContainerDetail, graph: &crate::container::turtle::Graph, upto: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut fail = |message: String, entry_id: Option<i64>| {
        findings.push(Finding::new(
            Level::Fail,
            "log_mismatch",
            message,
            Ref {
                entry_id,
                tree_head_id: None,
            },
        ));
    };
    let in_container: std::collections::HashMap<String, FileRecord> =
        file_records(graph).into_iter().map(|r| (r.arn.clone(), r)).collect();
    let mut in_log = std::collections::HashSet::new();
    for (add, record) in detail.files().filter(|(add, _)| add.entry_id <= upto) {
        in_log.insert(record.arn.clone());
        match in_container.get(&record.arn) {
            None => fail(
                format!(
                    "{} is in the case log (entry #{}) but not in the container.",
                    record.path, add.entry_id
                ),
                Some(add.entry_id),
            ),
            Some(_) if !record.metadata_only && record.link.is_none() && !has_storage(graph, &record.arn) => fail(
                format!(
                    "{} has no stored content in the container, though the case log (entry #{}) records it as stored.",
                    record.path, add.entry_id
                ),
                Some(add.entry_id),
            ),
            Some(stored) if stored != record => fail(
                format!(
                    "{} differs between the container and the case log (entry #{}).",
                    record.path, add.entry_id
                ),
                Some(add.entry_id),
            ),
            Some(_) => {}
        }
    }
    for (arn, record) in &in_container {
        if !in_log.contains(arn) {
            fail(
                format!(
                    "{} is in the container but in no addition the case log records.",
                    record.path
                ),
                None,
            );
        }
    }
    let logged_folders: Vec<&FolderRecord> = detail
        .adds
        .iter()
        .filter(|add| add.entry_id <= upto)
        .flat_map(|add| &add.folders)
        .collect();
    let stored_folders = crate::container::volume::folder_records(graph);
    for folder in &logged_folders {
        if !stored_folders.contains(folder) {
            fail(
                format!(
                    "The folder {} is in the case log but not in the container.",
                    folder.path
                ),
                None,
            );
        }
    }
    for folder in &stored_folders {
        if !logged_folders.contains(&folder) {
            fail(
                format!(
                    "The folder {} is in the container but in no addition the case log records.",
                    folder.path
                ),
                None,
            );
        }
    }
    let adds: std::collections::HashSet<i64> = detail.adds.iter().map(|a| a.entry_id).collect();
    for entry_id in task_entries(graph) {
        if !adds.contains(&entry_id) {
            fail(
                format!("The container names log entry #{entry_id}, which is not an addition to it."),
                None,
            );
        }
    }
    findings
}

impl Factum<'_> {
    /// The container events of a case (or of one container), in log order.
    fn container_events(&self, case_id: i64, uuid: Option<&str>) -> Result<Vec<Event>> {
        let mut statement = self.db.conn.prepare_cached(
            "SELECT id, created_utc, payload_json FROM entries WHERE case_id = ? AND kind = 'system' \
             AND (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.event') END) LIKE 'container\\_%' ESCAPE '\\' \
             AND (?2 IS NULL OR (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.container_id') END) = ?2) ORDER BY leaf_index",
        )?;
        let rows = statement.query_map(rusqlite::params![case_id, uuid], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (entry_id, utc, payload) = row?;
            if let Ok(Value::Object(payload)) = serde_json::from_str(&payload) {
                events.push(Event { entry_id, utc, payload });
            }
        }
        Ok(events)
    }

    pub fn container_path(&self, uuid: &str) -> Option<PathBuf> {
        let stored = self.db.get_setting(&path_setting(uuid)).unwrap_or_default();
        (!stored.is_empty()).then(|| PathBuf::from(stored))
    }

    fn summary(&self, id: i64, case_id: i64, uuid: String, name: String, evidence_id: Option<i64>) -> ContainerSummary {
        let path = self.container_path(&uuid);
        let missing = path.as_ref().is_none_or(|p| !p.is_file());
        ContainerSummary {
            id,
            case_id,
            uuid,
            name,
            open: true,
            file_count: 0,
            path,
            missing,
            evidence_id,
            signed: false,
            damaged: false,
        }
    }

    /// The containers of a case, read from the log without its file lists.
    pub fn list_containers(&self, case_id: i64) -> Result<Vec<ContainerSummary>> {
        let mut statement = self.db.conn.prepare_cached(
            "SELECT id, (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.event') END), \
             (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.container_id') END), \
             (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.name') END), \
             (CASE WHEN json_valid(payload_json) THEN json_array_length(payload_json, '$.files') END), \
             (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.evidence_id') END), \
             (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.signatures.gpg') IS NOT NULL \
                OR json_extract(payload_json, '$.signatures.x509') IS NOT NULL ELSE 0 END), \
             (CASE WHEN json_valid(payload_json) THEN json_type(payload_json, '$.damaged') IS NOT NULL ELSE 0 END) \
             FROM entries WHERE case_id = ? AND kind = 'system' \
             AND (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.event') END) LIKE 'container\\_%' ESCAPE '\\' ORDER BY leaf_index",
        )?;
        let rows = statement.query_map([case_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
            ))
        })?;
        // in creation order
        let mut containers: Vec<ContainerSummary> = Vec::new();
        for row in rows {
            let (entry_id, event, uuid, name, files, evidence_id, signed, damaged) = row?;
            if event == "container_created" {
                containers.push(self.summary(entry_id, case_id, uuid, name.unwrap_or_default(), evidence_id));
                continue;
            }
            let Some(container) = containers.iter_mut().find(|c| c.uuid == uuid) else {
                continue;
            };
            match event.as_str() {
                "container_files_added" => container.file_count += files.unwrap_or(0).max(0) as u64,
                "container_closed" => {
                    container.open = false;
                    container.signed = signed;
                    container.damaged = damaged;
                }
                "container_signed" => container.signed = true,
                "container_reopened" => container.open = true,
                _ => {}
            }
        }
        Ok(containers)
    }

    pub fn open_containers(&self, case_id: i64) -> Result<Vec<ContainerSummary>> {
        Ok(self.list_containers(case_id)?.into_iter().filter(|c| c.open).collect())
    }

    pub fn find_container_by_uuid(&self, uuid: &str) -> Result<Option<i64>> {
        Ok(self
            .db
            .conn
            .query_row(
                "SELECT id FROM entries WHERE kind = 'system' \
                 AND (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.event') END) = 'container_created' \
                 AND (CASE WHEN json_valid(payload_json) THEN json_extract(payload_json, '$.container_id') END) = ? ORDER BY id LIMIT 1",
                [uuid],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Everything the log says about one container.
    pub fn container(&self, id: i64) -> Result<ContainerDetail> {
        let not_found = || FactumError::general(format!("Container #{id} does not exist."));
        let entry = self.get_entry(id)?.ok_or_else(not_found)?;
        let created = match crate::notes::parse_payload(entry.payload_json.as_deref()) {
            Value::Object(payload) if payload.get("event").and_then(Value::as_str) == Some("container_created") => {
                Event {
                    entry_id: id,
                    utc: entry.created_utc.clone(),
                    payload,
                }
            }
            _ => return Err(not_found()),
        };
        let uuid = created.text("container_id");
        let mut detail = ContainerDetail {
            summary: self.summary(
                id,
                entry.case_id,
                uuid.clone(),
                created.text("name"),
                created.payload.get("evidence_id").and_then(Value::as_i64),
            ),
            evidence_id: created.payload.get("evidence_id").and_then(Value::as_i64),
            file_name: created.text("file_name"),
            base_path: created.text("base_path"),
            created_utc: created.text("created_utc"),
            adds: Vec::new(),
            closes: Vec::new(),
            reopens: Vec::new(),
            closed_without_file: Vec::new(),
            late_signatures: Vec::new(),
        };
        for event in self.container_events(entry.case_id, Some(&uuid))? {
            match event.text("event").as_str() {
                "container_files_added" => {
                    let files = event
                        .payload
                        .get("files")
                        .and_then(Value::as_array)
                        .map(|files| files.iter().filter_map(FileRecord::from_json).collect())
                        .unwrap_or_default();
                    let folders = event
                        .payload
                        .get("folders")
                        .and_then(Value::as_array)
                        .map(|folders| folders.iter().filter_map(FolderRecord::from_json).collect())
                        .unwrap_or_default();
                    let mounts = event
                        .payload
                        .get("sources")
                        .and_then(Value::as_array)
                        .map(|mounts| {
                            mounts
                                .iter()
                                .filter_map(crate::container::mounts::Mount::from_json)
                                .collect()
                        })
                        .unwrap_or_default();
                    detail.adds.push(AddEvent {
                        entry_id: event.entry_id,
                        utc: event.utc,
                        files,
                        folders,
                        mounts,
                    });
                }
                "container_closed" if event.payload.get("file_missing") == Some(&Value::Bool(true)) => {
                    detail.summary.open = false;
                    detail.closed_without_file.push((event.entry_id, event.utc));
                }
                "container_closed" => {
                    let (gpg, x509) = event.signatures();
                    detail.summary.open = false;
                    detail.closes.push(CloseEvent {
                        entry_id: event.entry_id,
                        utc: event.utc.clone(),
                        turtle_sha256: event.text("turtle_sha256"),
                        file_count: event.payload.get("file_count").and_then(Value::as_u64).unwrap_or(0),
                        gpg,
                        x509,
                        x509_refused: event.optional("x509_refused"),
                        signed_later: None,
                    });
                }
                "container_reopened" => {
                    detail.summary.open = true;
                    detail.reopens.push((event.entry_id, event.utc));
                }
                "container_signed" => {
                    let (gpg, x509) = event.signatures();
                    let sha = event.text("turtle_sha256");
                    // the close it names; identical states (close, reopen, close) share a hash, so the hash only
                    // picks among the closes that were not signed
                    let named = event
                        .payload
                        .get("close")
                        .and_then(Value::as_u64)
                        .and_then(|n| detail.closes.get_mut((n as usize).checked_sub(1)?))
                        .filter(|c| c.turtle_sha256 == sha && !c.is_signed());
                    let close = match named {
                        Some(close) => Some(close),
                        None => detail
                            .closes
                            .iter_mut()
                            .find(|c| c.turtle_sha256 == sha && !c.is_signed()),
                    };
                    if let Some(close) = close {
                        close.signed_later = Some(event.entry_id);
                    }
                    detail.late_signatures.push((event.entry_id, sha, gpg, x509));
                }
                _ => {}
            }
        }
        detail.summary.file_count = detail.adds.iter().map(|a| a.files.len() as u64).sum();
        detail.summary.signed =
            !detail.last_closed_without_file() && detail.closes.last().is_some_and(CloseEvent::is_signed);
        Ok(detail)
    }

    /// Creates the container file, then logs `container_created`; returns the container's number (its entry id).
    pub fn create_container(
        &self,
        case_id: i64,
        name: &str,
        evidence_id: i64,
        path: &Path,
        base_path: &str,
    ) -> Result<i64> {
        let name = strip(name);
        if name.is_empty() {
            return Err(FactumError::general("A container name is required."));
        }
        let case = self.require_case(case_id)?;
        ensure_case_open(&self.db.conn, case_id)?;
        let evidence = match self.get_evidence(evidence_id)? {
            Some(e) if !e.is_deleted() && e.case_id == case_id => Some((e.id, e.description, e.details)),
            _ => {
                return Err(FactumError::general(format!(
                    "Evidence #{evidence_id} does not exist in this case."
                )));
            }
        };
        let path = std::path::absolute(path)?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| FactumError::general("The container needs a file name."))?;
        let uuid = uuid::Uuid::new_v4().to_string();
        let created_utc = utc_now();
        let info = VolumeInfo {
            name: name.to_string(),
            case_file: case.case_file.clone(),
            case_id,
            evidence: evidence.clone(),
            created_utc: created_utc.clone(),
        };
        let volume = Volume::create(&path, &uuid, &info)?;
        let mut text = format!("Container \"{name}\" created");
        if let Some((evidence_id, _, _)) = &evidence {
            text += &format!(" (from evidence #{evidence_id})");
        }
        let payload = json!({"event": "container_created", "case_id": case_id, "container_id": uuid, "name": name,
                             "evidence_id": evidence_id, "file_name": file_name, "base_path": base_path,
                             "created_utc": created_utc});
        let end = volume.end();
        let remember = |conn: &rusqlite::Connection, _: i64| -> Result<()> {
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![path_setting(&uuid), path.display().to_string()],
            )?;
            store_end(conn, &uuid, end)
        };
        let appended = self.append(
            case_id,
            KIND_SYSTEM,
            &text,
            Append {
                payload: Some(payload),
                on_commit: Some(&remember),
                ..Default::default()
            },
        );
        drop(volume);
        let id = match appended {
            Ok(id) => id,
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(e);
            }
        };
        log::info!("Container #{id} created: {}", path.display());
        Ok(id)
    }

    /// A new evidence item and a container for it, named alike: two log entries, as if made one after the other.
    /// Returns (evidence id, container id); the evidence stays when the container cannot be created.
    pub fn create_evidence_with_container(
        &self,
        case_id: i64,
        name: &str,
        hash: &str,
        details: &str,
        path: &Path,
        base_path: &str,
    ) -> Result<(i64, i64)> {
        let evidence_id = self.create_evidence(case_id, name, hash, details)?;
        let container_id = self
            .create_container(case_id, name, evidence_id, path, base_path)
            .map_err(|e| {
                FactumError::general(format!(
                    "Evidence #{evidence_id} was created, but its container was not: {e}"
                ))
            })?;
        Ok((evidence_id, container_id))
    }

    /// Opens the container file of a container the log knows, checking that it is that container.
    fn open_volume(&self, detail: &ContainerDetail) -> Result<Volume> {
        let id = detail.summary.id;
        let path = match &detail.summary.path {
            Some(path) if !detail.summary.missing => path.clone(),
            path => {
                return Err(FactumError::general(format!(
                    "The file of container #{id} is missing{}. Use Locate… to find it.",
                    path.as_ref().map(|p| format!(" ({})", p.display())).unwrap_or_default()
                )));
            }
        };
        let hint = self
            .db
            .get_setting(&end_setting(&detail.summary.uuid))
            .ok()
            .and_then(|end| end.parse().ok());
        let (mut volume, discarded) = Volume::open(&path, hint)?;
        if volume.uuid() != detail.summary.uuid {
            return Err(FactumError::general(format!(
                "{} is not container #{id} (it is {}).",
                path.display(),
                volume.uuid()
            )));
        }
        if discarded > 0 {
            log::warn!("Container #{id}: an interrupted addition ({discarded} bytes) was discarded.");
        }
        // ahead of the log: written, but the log entry was never committed (a crash in between). The log's state
        // ends where the setting (written with each log entry) says; what follows is set aside, never cut off.
        let ahead = |volume: &Volume| {
            !compare_records(detail, volume.graph(), i64::MAX).is_empty()
                || volume.history_count() as usize > detail.closes.len()
        };
        if ahead(&volume)
            && let Some(end) = hint.filter(|end| *end < volume.end())
        {
            let mark = volume.mark();
            if volume.set_aside_after(end).is_ok() && !ahead(&volume) {
                log::warn!(
                    "Container #{id}: a state the case log does not record (written, then interrupted before it was \
                     logged) was set aside; the container continues from the logged state."
                );
            } else {
                volume.rollback_to(mark)?;
            }
        }
        Ok(volume)
    }

    /// Differences between the container file and the case log (spec 4.5); reported, never repaired.
    pub fn compare_with_log(&self, id: i64, volume: &Volume) -> Result<Vec<Finding>> {
        Ok(compare_records(&self.container(id)?, volume.graph(), i64::MAX))
    }

    fn ensure_matches_log(&self, id: i64, volume: &Volume) -> Result<()> {
        let findings = self.compare_with_log(id, volume)?;
        if let Some(first) = findings.first() {
            return Err(FactumError::general(format!(
                "Container #{id} differs from the case log; Verify Container… shows how ({} difference(s), e.g. {}).",
                findings.len(),
                first.message
            )));
        }
        Ok(())
    }

    /// The open, locked container file for an Add operation.
    pub fn open_container_for_add(&self, id: i64) -> Result<Volume> {
        let detail = self.container(id)?;
        ensure_case_open(&self.db.conn, detail.summary.case_id)?;
        if !detail.summary.open {
            return Err(FactumError::general(format!(
                "Container #{id} is closed. Reopen it to add files."
            )));
        }
        let volume = self.open_volume(&detail)?;
        self.ensure_matches_log(id, &volume)?;
        Ok(volume)
    }

    /// Logs a staged Add operation and lists it in the container, both or neither.
    pub fn commit_container_add(&self, id: i64, volume: &mut Volume, staged: Staged) -> Result<i64> {
        let detail = self.container(id)?;
        if staged.records.is_empty() && staged.folders.is_empty() {
            volume.discard(staged)?;
            return Err(FactumError::general("Nothing was added."));
        }
        let files: Vec<Value> = staged.records.iter().map(FileRecord::to_json).collect();
        let folders: Vec<Value> = staged.folders.iter().map(FolderRecord::to_json).collect();
        let text = if staged.records.is_empty() {
            format!("{} added to container #{id}", plural(staged.folders.len(), "folder"))
        } else {
            format!(
                "{} added to container #{id} ({})",
                plural(staged.records.len(), "file"),
                human_size(staged.bytes())
            )
        };
        // what was chosen but not added (unreadable, changed while read, special files) is recorded too, so the
        // entry never claims a folder was acquired whole when it was not
        let not_added: Vec<Value> = staged
            .errors
            .iter()
            .chain(&staged.skipped)
            .map(|(path, reason)| json!({"path": path, "reason": reason}))
            .collect();
        let text = match not_added.len() {
            0 => text,
            count => format!("{text} · {count} not added"),
        };
        let payload = json!({"event": "container_files_added", "case_id": detail.summary.case_id,
                             "container_id": detail.summary.uuid, "files": files, "folders": folders,
                             "not_added": not_added, "added_utc": utc_now(),
                             "base_path": staged.base().display().to_string(), "keep_path": staged.keep_path,
                             "sources": staged.mounts.iter().map(crate::container::mounts::Mount::to_json).collect::<Vec<_>>()});
        let mark = staged.mark();
        let result = {
            let cell = RefCell::new(&mut *volume);
            let finalize = |conn: &rusqlite::Connection, entry_id: i64| -> Result<()> {
                let end = cell.borrow_mut().finalize_add(&staged, entry_id)?;
                store_end(conn, &detail.summary.uuid, end)
            };
            self.append(
                detail.summary.case_id,
                KIND_SYSTEM,
                &text,
                Append {
                    payload: Some(payload),
                    on_commit: Some(&finalize),
                    ..Default::default()
                },
            )
        };
        match result {
            Ok(entry_id) => Ok(entry_id),
            Err(e) => {
                if let Err(rollback) = volume.rollback_to(mark) {
                    log::error!("Container #{id} could not be restored after a failed addition: {rollback}");
                }
                Err(e)
            }
        }
    }

    /// The GPG fingerprint of the active key (its key id where gpg does not list it).
    fn active_fingerprint(&self) -> Option<String> {
        let key = self.signer.active_key()?;
        Some(
            self.signer
                .list_keys()
                .into_iter()
                .find(|k| k.keyid == key)
                .map(|k| k.fingerprint)
                .unwrap_or(key),
        )
    }

    pub fn gpgsm(&self) -> Gpgsm {
        Gpgsm::new(self.signer.gpg_home())
    }

    /// Signs a container state: GPG with the active key (an error if it fails), X.509 when configured (a failure
    /// is returned as the reason, the state is then GPG-signed only).
    fn sign_state(&self, turtle: &[u8], gpgsm: &Gpgsm, failure: &str) -> Result<SignedState> {
        let mut signatures = Signatures::default();
        let gpg = match self.active_fingerprint() {
            Some(fingerprint) => {
                let signature = self
                    .signer
                    .sign_detached(turtle)
                    .ok_or_else(|| FactumError::signing(failure))?;
                let key = self.signer.export_public_keys(std::slice::from_ref(&fingerprint));
                signatures.gpg = Some((signature, key));
                Some(fingerprint)
            }
            None => None,
        };
        let certificate = self.db.get_setting(X509_CERT_SETTING).unwrap_or_default();
        let (mut x509, mut refused) = (None, None);
        if !certificate.is_empty() {
            let chain_files: Vec<PathBuf> = self
                .db
                .get_setting(X509_CHAIN_SETTING)
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .collect();
            match gpgsm.sign_with_chain(&certificate, turtle, &chain_files) {
                Ok(signed) => {
                    signatures.x509 = Some(signed);
                    x509 = Some(certificate);
                }
                Err(reason) => {
                    log::warn!("X.509 signature refused: {reason}");
                    refused = Some(reason);
                }
            }
        }
        Ok(SignedState {
            signatures,
            gpg,
            x509,
            x509_refused: refused,
        })
    }

    pub fn close_container(&self, id: i64) -> Result<CloseEvent> {
        self.close_container_with(id, &self.gpgsm())
    }

    /// Closes a container: signs its state and logs `container_closed`; the signatures and a copy of the state
    /// under factum/history/<n>/ are written inside the append.
    pub fn close_container_with(&self, id: i64, gpgsm: &Gpgsm) -> Result<CloseEvent> {
        let detail = self.container(id)?;
        ensure_case_open(&self.db.conn, detail.summary.case_id)?;
        if !detail.summary.open {
            return Err(FactumError::general(format!("Container #{id} is already closed.")));
        }
        let mut volume = self.open_volume(&detail)?;
        self.ensure_matches_log(id, &volume)?;
        let turtle = volume.turtle_bytes();
        let turtle_sha256 = hex::encode(sha2::Sha256::digest(&turtle));
        let SignedState {
            signatures,
            gpg,
            x509,
            x509_refused,
        } = self.sign_state(&turtle, gpgsm, "GPG signing failed — the container was not closed.")?;
        let file_count = detail.summary.file_count;
        let closed_utc = utc_now();
        let mut payload = json!({"event": "container_closed", "case_id": detail.summary.case_id,
                                 "container_id": detail.summary.uuid, "turtle_sha256": turtle_sha256,
                                 "file_count": file_count, "signatures": signatures_json(&gpg, &x509),
                                 "closed_utc": closed_utc});
        if let Some(reason) = &x509_refused {
            payload["x509_refused"] = json!(reason);
        }
        let signed = if signatures.gpg.is_some() || signatures.x509.is_some() {
            "signed"
        } else {
            "unsigned"
        };
        let text = format!("Container #{id} closed · {file_count} files · {signed}");
        let mark = volume.mark();
        let uuid = detail.summary.uuid.clone();
        let result = {
            let cell = RefCell::new(&mut volume);
            let close = |conn: &rusqlite::Connection, _: i64| -> Result<()> {
                let mut volume = cell.borrow_mut();
                volume.close(&signatures)?;
                store_end(conn, &uuid, volume.end())
            };
            self.append(
                detail.summary.case_id,
                KIND_SYSTEM,
                &text,
                Append {
                    payload: Some(payload),
                    on_commit: Some(&close),
                    ..Default::default()
                },
            )
        };
        let entry_id = match result {
            Ok(entry_id) => entry_id,
            Err(e) => {
                if let Err(rollback) = volume.rollback_to(mark) {
                    log::error!("Container #{id} could not be restored after a failed close: {rollback}");
                }
                return Err(e);
            }
        };
        Ok(CloseEvent {
            entry_id,
            utc: closed_utc,
            turtle_sha256,
            file_count,
            gpg,
            x509,
            x509_refused,
            signed_later: None,
        })
    }

    /// Closes an open container whose file is missing, so that its case can be archived: `container_closed` with
    /// `file_missing`, and nothing signed or written, as there is no file. Refused while the file is there.
    pub fn close_container_without_file(&self, id: i64) -> Result<i64> {
        let detail = self.container(id)?;
        ensure_case_open(&self.db.conn, detail.summary.case_id)?;
        if !detail.summary.open {
            return Err(FactumError::general(format!("Container #{id} is already closed.")));
        }
        if !detail.summary.missing {
            return Err(FactumError::general(format!(
                "The file of container #{id} is there; close it as usual."
            )));
        }
        let file_count = detail.summary.file_count;
        let path = detail
            .summary
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        self.append(
            detail.summary.case_id,
            KIND_SYSTEM,
            &format!("Container #{id} closed without its file (missing) · {file_count} files · nothing signed"),
            Append {
                payload: Some(json!({"event": "container_closed", "case_id": detail.summary.case_id,
                                     "container_id": detail.summary.uuid, "file_missing": true,
                                     "missing_path": path, "file_count": file_count,
                                     "closed_utc": utc_now()})),
                ..Default::default()
            },
        )
    }

    /// Logs `container_reopened`; Add is possible again. The file is not touched.
    pub fn reopen_container(&self, id: i64) -> Result<i64> {
        let detail = self.container(id)?;
        if detail.summary.open {
            return Err(FactumError::general(format!("Container #{id} is open.")));
        }
        self.append(
            detail.summary.case_id,
            KIND_SYSTEM,
            &format!("Container #{id} reopened"),
            Append {
                payload: Some(json!({"event": "container_reopened", "case_id": detail.summary.case_id,
                                     "container_id": detail.summary.uuid, "reopened_utc": utc_now()})),
                ..Default::default()
            },
        )
    }

    /// Signs every closed state of the case's containers that was closed without signatures; returns how many
    /// were signed and why others were left (missing file, a state that differs from the log).
    pub fn sign_unsigned_containers(&self, case_id: i64) -> Result<(usize, Vec<String>)> {
        let mut pending = Vec::new();
        for summary in self.list_containers(case_id)? {
            let detail = self.container(summary.id)?;
            for (index, close) in detail.closes.iter().enumerate() {
                if !close.is_signed() {
                    pending.push((detail.clone(), index as u32 + 1, close.clone()));
                }
            }
        }
        if pending.is_empty() {
            return Ok((0, Vec::new()));
        }
        if self.signer.active_key().is_none() {
            return Err(FactumError::signing(
                "No GPG key is active. Select a signing key first.",
            ));
        }
        let gpgsm = self.gpgsm();
        let (mut count, mut skipped) = (0, Vec::new());
        let mut pending = pending.into_iter();
        while let Some((detail, n, close)) = pending.next() {
            let id = detail.summary.id;
            // after a signing failure (a cancelled passphrase prompt, say) the rest is not tried; what was signed
            // stays signed and is counted
            let mut stop = |skipped: &mut Vec<String>, reason: String| {
                skipped.push(format!("Container #{id}: {reason}"));
                for (detail, ..) in pending.by_ref() {
                    skipped.push(format!(
                        "Container #{}: not tried after the failure above.",
                        detail.summary.id
                    ));
                }
            };
            let mut volume = match self.open_volume(&detail) {
                Ok(volume) => volume,
                Err(e) => {
                    skipped.push(format!("Container #{id}: {e}"));
                    continue;
                }
            };
            let turtle = match volume.member(&history_member(n, TURTLE)) {
                Ok(turtle) => turtle,
                Err(e) => {
                    skipped.push(format!(
                        "Container #{id}: its closed state {n} cannot be read ({e}); not signed."
                    ));
                    continue;
                }
            };
            if hex::encode(sha2::Sha256::digest(&turtle)) != close.turtle_sha256 {
                skipped.push(format!(
                    "Container #{id}: its closed state {n} differs from the case log; not signed."
                ));
                continue;
            }
            let SignedState {
                signatures, gpg, x509, ..
            } = match self.sign_state(&turtle, &gpgsm, "GPG signing failed; not signed.") {
                Ok(signed) => signed,
                Err(e) => {
                    stop(&mut skipped, e.to_string());
                    break;
                }
            };
            let mark = volume.mark();
            let uuid = detail.summary.uuid.clone();
            let result = {
                let cell = RefCell::new(&mut volume);
                let add = |conn: &rusqlite::Connection, _: i64| -> Result<()> {
                    let mut volume = cell.borrow_mut();
                    volume.add_late_signatures(n, &signatures)?;
                    store_end(conn, &uuid, volume.end())
                };
                self.append(
                    case_id,
                    KIND_SYSTEM,
                    &format!("Container #{id} signed"),
                    Append {
                        payload: Some(json!({"event": "container_signed", "case_id": case_id,
                                             "container_id": detail.summary.uuid, "close": n,
                                             "turtle_sha256": close.turtle_sha256,
                                             "signatures": signatures_json(&gpg, &x509), "signed_utc": utc_now()})),
                        on_commit: Some(&add),
                        // like late signatures of entries: signing what was closed changes nothing in the case
                        allow_archived: true,
                        ..Default::default()
                    },
                )
            };
            if let Err(e) = result {
                if let Err(rollback) = volume.rollback_to(mark) {
                    log::error!("Container #{id} could not be restored after a failed signature: {rollback}");
                }
                stop(&mut skipped, format!("{e}; not signed."));
                break;
            }
            count += 1;
        }
        Ok((count, skipped))
    }

    /// Points a container at a moved file; only a file with the container's UUID is accepted.
    pub fn locate_container(&self, id: i64, path: &Path) -> Result<()> {
        let detail = self.container(id)?;
        let uuid = Volume::uuid_of(path)?;
        if uuid != detail.summary.uuid {
            return Err(FactumError::general(format!(
                "{} is not container #{id}: it is container {uuid}.",
                path.display()
            )));
        }
        let path = std::path::absolute(path)?;
        self.db.set_setting(&path_setting(&uuid), &path.display().to_string())?;
        self.db.delete_setting(&end_setting(&uuid))?;
        Ok(())
    }
}

impl Factum<'_> {
    /// Verifies a container file (spec 4.6); for a container of this database also against its case log: the
    /// closed states against the logged closes, the files against the logged additions, and what the log
    /// recorded after the state the file is in.
    pub fn verify_container_file(
        &self,
        path: &Path,
        gpgsm: &Gpgsm,
        progress: &dyn Fn(u64, u64),
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<crate::container::verify::ContainerReport> {
        let mut report = crate::container::verify::verify_file(path, self.signer, gpgsm, progress, cancel)?;
        let (Some(uuid), Some(graph)) = (report.uuid.clone(), report.graph.clone()) else {
            return Ok(report);
        };
        let Some(id) = self.find_container_by_uuid(&uuid)? else {
            return Ok(report);
        };
        let detail = self.container(id)?;
        let fail = |message: String, entry_id: Option<i64>| {
            Finding::new(
                Level::Fail,
                "log_mismatch",
                message,
                Ref {
                    entry_id,
                    tree_head_id: None,
                },
            )
        };
        let mut findings = Vec::new();
        for state in &report.states {
            let Some(n) = state.close else { continue };
            match detail.closes.get(n as usize - 1) {
                Some(close) if close.turtle_sha256 == state.turtle_sha256 => {}
                Some(close) => findings.push(fail(
                    format!(
                        "Closed state {n} differs from the close the case log records (entry #{}).",
                        close.entry_id
                    ),
                    Some(close.entry_id),
                )),
                None => findings.push(fail(format!("Closed state {n} is not in the case log."), None)),
            }
        }
        let current = report.states.iter().find(|s| s.current);
        let matches_close = current.and_then(|s| s.close);
        // the file at the container's place must hold everything the log records; a copy elsewhere may be older
        let canonical = |p: &Path| std::fs::canonicalize(p).ok();
        let live = detail
            .summary
            .path
            .as_deref()
            .and_then(canonical)
            .is_some_and(|p| Some(p) == canonical(path));
        let upto = match matches_close {
            _ if live => i64::MAX,
            Some(n) => detail.closes.get(n as usize - 1).map_or(i64::MAX, |c| c.entry_id),
            None => task_entries(&graph).into_iter().max().unwrap_or(id),
        };
        findings.extend(compare_records(&detail, &graph, upto));
        let mut after: Vec<(i64, String)> = Vec::new();
        for add in detail.adds.iter().filter(|a| a.entry_id > upto) {
            after.push((add.entry_id, format!("{} added", plural(add.files.len(), "file"))));
        }
        for close in detail.closes.iter().filter(|c| c.entry_id > upto) {
            after.push((close.entry_id, "closed".into()));
        }
        for (entry_id, _) in detail.reopens.iter().filter(|(e, _)| *e > upto) {
            after.push((*entry_id, "reopened".into()));
        }
        for (entry_id, _) in detail.closed_without_file.iter().filter(|(e, _)| *e > upto) {
            after.push((*entry_id, "closed while its file was missing".into()));
        }
        for (entry_id, ..) in detail.late_signatures.iter().filter(|(e, ..)| *e > upto) {
            after.push((*entry_id, "signed".into()));
        }
        after.sort();
        if live {
            // the live file is in the newest state: its newest close is the log's newest (a reopen does not touch
            // the file), and it is not open while the log has it closed
            let lacking = match matches_close {
                Some(n) => (n as usize) < detail.closes.len(),
                None => !detail.summary.open,
            };
            if lacking && matches_close.is_none() && detail.last_closed_without_file() {
                let (entry_id, _) = detail.closed_without_file.last().cloned().unwrap_or_default();
                findings.push(fail(
                    format!(
                        "The case log closed this container while its file was missing (entry #{entry_id}); the \
                         file is in an open state that was never closed or signed."
                    ),
                    Some(entry_id),
                ));
            } else if lacking {
                findings.push(fail(
                    "The container file is in an earlier state than the case log records: the log has a later close."
                        .into(),
                    None,
                ));
            }
        }
        report.findings.extend(findings);
        report.log = Some(crate::container::verify::LogMatch {
            container_id: id,
            matches_close,
            recorded_after: after.into_iter().map(|(e, text)| format!("#{e} {text}")).collect(),
        });
        Ok(report)
    }
}
