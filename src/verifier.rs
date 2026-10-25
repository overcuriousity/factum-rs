//! Whole-case verification: recomputes every leaf and tree head, checks all signatures, all seals (database
//! and seal folder) and that case and evidence details match the log.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::Path;

use rusqlite::OptionalExtension;
use serde_json::Value;

use crate::cases::Case;
use crate::error::{FactumError, Result};
use crate::evidence::Evidence;
use crate::log_service::{entry_signed_payload, leaf_data};
use crate::merkle::{self, MerkleAccumulator};
use crate::notes::{Entry, parse_payload};
use crate::seals::seal_payload;
use crate::services::Factum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

pub const TRUSTED: [&str; 2] = ["TRUST_FULLY", "TRUST_ULTIMATE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub message: String,
    pub entry_id: Option<i64>,
    pub tree_head_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Ref {
    pub entry_id: Option<i64>,
    pub tree_head_id: Option<i64>,
}

impl Finding {
    pub fn new(level: Level, code: &'static str, message: impl Into<String>, reference: Ref) -> Self {
        Self {
            level,
            code,
            message: message.into(),
            entry_id: reference.entry_id,
            tree_head_id: reference.tree_head_id,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureCheck {
    pub present: bool,
    pub late: bool,
    pub late_signed_utc: Option<String>,
    pub valid: bool,
    pub covers_payload: bool,
    pub trusted: bool,
    pub status: String,
    pub key_id: Option<String>,
    pub fingerprint: Option<String>,
    pub username: Option<String>,
    pub trust: Option<String>,
    pub signature_timestamp: Option<String>,
}

impl SignatureCheck {
    pub fn absent() -> Self {
        Self::default()
    }

    pub fn present_unchecked() -> Self {
        Self {
            present: true,
            ..Default::default()
        }
    }
}

pub fn worst<'f>(findings: impl IntoIterator<Item = &'f Finding>) -> Level {
    findings.into_iter().map(|f| f.level).max().unwrap_or(Level::Ok)
}

#[derive(Debug, Clone)]
pub struct EntryResult {
    pub entry: Entry,
    pub recomputed_leaf_hash: String,
    pub recomputed_root_hash: String,
    pub recomputed_tree_size: i64,
    pub signature: SignatureCheck,
    pub findings: Vec<Finding>,
}

impl EntryResult {
    pub fn status(&self) -> Level {
        worst(&self.findings)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealSource {
    Database,
    File,
}

#[derive(Debug, Clone)]
pub struct TreeHeadResult {
    pub source: SealSource,
    pub label: String,
    pub tree_size: i64,
    pub root_hash: String,
    pub created_utc: Option<String>,
    pub reason: Option<String>,
    pub signature: SignatureCheck,
    pub tree_head_id: Option<i64>,
    pub path: Option<String>,
    pub findings: Vec<Finding>,
}

impl TreeHeadResult {
    pub fn status(&self) -> Level {
        worst(&self.findings)
    }
}

#[derive(Debug, Clone)]
pub struct CaseReport {
    pub case: Case,
    pub tree_size: i64,
    pub root_hash: String,
    pub entries: Vec<EntryResult>,
    pub tree_heads: Vec<TreeHeadResult>,
    /// every finding, including those attached to entries and tree heads
    pub findings: Vec<Finding>,
    /// (fingerprint, username)
    pub signers: Vec<(String, Option<String>)>,
    pub newest_seal_size: Option<i64>,
}

impl CaseReport {
    pub fn overall(&self) -> Level {
        worst(&self.findings)
    }

    pub fn count(&self, status: Level) -> usize {
        self.entries.iter().filter(|result| result.status() == status).count()
    }

    pub fn entry_result(&self, entry_id: i64) -> Option<&EntryResult> {
        self.entries.iter().find(|result| result.entry.id == entry_id)
    }
}

pub type LateSignatures = HashMap<(String, i64), (String, String)>;
pub type Progress<'p> = &'p mut dyn FnMut(usize, usize);

/// Python's repr() of a JSON value as it appears in messages.
fn value_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(text) => crate::pystr::repr(text),
        other => other.to_string(),
    }
}

fn text_value(text: &str) -> Value {
    Value::String(text.to_string())
}

fn optional_value(text: &Option<String>) -> Value {
    text.as_ref().map_or(Value::Null, |t| Value::String(t.clone()))
}

/// A dict key like Python's: integer ids sort numerically, anything else after them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum IdKey {
    Int(i64),
    Other(String),
}

impl IdKey {
    fn of(value: Option<&Value>) -> Self {
        match value {
            Some(v) if v.as_i64().is_some() => IdKey::Int(v.as_i64().unwrap()),
            Some(Value::Null) | None => IdKey::Other("None".into()),
            Some(Value::String(text)) => IdKey::Other(text.clone()),
            Some(other) => IdKey::Other(other.to_string()),
        }
    }
}

impl fmt::Display for IdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdKey::Int(id) => write!(f, "{id}"),
            IdKey::Other(text) => f.write_str(text),
        }
    }
}

impl Factum<'_> {
    pub fn load_case_row(&self, case_id: i64) -> Result<Case> {
        self.require_case(case_id)
    }

    pub fn load_entries(&self, case_id: i64) -> Result<Vec<Entry>> {
        let mut statement = self.db.conn.prepare(&format!(
            "SELECT {} FROM entries WHERE case_id = ? ORDER BY leaf_index",
            Entry::COLUMNS
        ))?;
        let rows = statement.query_map([case_id], Entry::from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn late_signatures(&self) -> Result<LateSignatures> {
        let mut statement = self
            .db
            .conn
            .prepare("SELECT target, target_id, signature, signed_utc FROM late_signatures")?;
        let rows = statement.query_map([], |row| Ok(((row.get(0)?, row.get(1)?), (row.get(2)?, row.get(3)?))))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn check_signature(
        &self,
        signature: Option<&str>,
        late: Option<&(String, String)>,
        expected: &str,
    ) -> SignatureCheck {
        let signature = signature.filter(|s| !s.is_empty());
        let block = match (signature, late) {
            (Some(block), _) => block,
            (None, Some((block, _))) => block.as_str(),
            (None, None) => return SignatureCheck::absent(),
        };
        let result = self.signer.verify_signature(block);
        SignatureCheck {
            present: true,
            late: signature.is_none(),
            late_signed_utc: if signature.is_some() {
                None
            } else {
                late.map(|(_, utc)| utc.clone())
            },
            valid: result.valid,
            covers_payload: result.signed_text.as_deref() == Some(expected),
            trusted: result.trust.as_deref().is_some_and(|t| TRUSTED.contains(&t)),
            status: result.status,
            key_id: result.key_id,
            fingerprint: result.fingerprint,
            username: result.username,
            trust: result.trust,
            signature_timestamp: result.signature_timestamp,
        }
    }

    pub fn signature_findings(check: &SignatureCheck, what: &str, reference: Ref) -> Vec<Finding> {
        let finding = |level, code, message: String| vec![Finding::new(level, code, message, reference)];
        let or_none = |value: &Option<String>| value.clone().unwrap_or_else(|| "None".into());
        if !check.present {
            return finding(Level::Fail, "unsigned", format!("{what} is not signed."));
        }
        if !check.valid {
            if check.status.contains("no public key") {
                return finding(
                    Level::Fail,
                    "key_unknown",
                    format!("{what}: signing key {} is not in the keyring.", or_none(&check.key_id)),
                );
            }
            return finding(
                Level::Fail,
                "signature_invalid",
                format!("{what}: the signature is invalid ({}).", check.status),
            );
        }
        if !check.covers_payload {
            return finding(
                Level::Fail,
                "signature_mismatch",
                format!("{what}: the signature was made over different data."),
            );
        }
        if !check.trusted {
            return finding(
                Level::Fail,
                "key_untrusted",
                format!(
                    "{what}: signing key {} is not trusted ({}).",
                    or_none(&check.fingerprint),
                    or_none(&check.trust)
                ),
            );
        }
        if check.late {
            return finding(
                Level::Warn,
                "signed_later",
                format!("{what} was signed later on {}.", or_none(&check.late_signed_utc)),
            );
        }
        Vec::new()
    }

    /// Recompute every leaf and tree head in order. Signatures are checked for all entries, or only for the
    /// ids in signatures_for. Returns the results and the recomputed root for every tree size.
    pub fn check_entries(
        &self,
        case_id: i64,
        rows: &[Entry],
        late: &LateSignatures,
        signatures_for: Option<&HashSet<i64>>,
        mut progress: Option<Progress<'_>>,
        total: Option<usize>,
    ) -> (Vec<EntryResult>, HashMap<i64, String>) {
        let mut accumulator = MerkleAccumulator::new();
        let mut roots = HashMap::from([(0i64, hex::encode(merkle::empty_root()))]);
        let by_id: HashMap<i64, &Entry> = rows.iter().map(|row| (row.id, row)).collect();
        let mut results = Vec::with_capacity(rows.len());
        for (position, row) in rows.iter().enumerate() {
            let mut findings = Vec::new();
            let reference = Ref {
                entry_id: Some(row.id),
                tree_head_id: None,
            };
            let what = format!("Entry #{} (leaf {})", row.id, row.leaf_index);
            if row.leaf_index != position as i64 {
                findings.push(Finding::new(
                    Level::Fail,
                    "gap",
                    format!("{what}: expected leaf index {position} — entries are missing or out of order."),
                    reference,
                ));
            }
            let payload = parse_payload(row.payload_json.as_deref());
            let data = leaf_data(
                case_id,
                row.leaf_index,
                &row.kind,
                row.evidence_id,
                &row.text,
                &payload,
                row.corrects_id,
                &row.created_utc,
                row.format,
            );
            let leaf = merkle::leaf_hash(data.as_bytes());
            let leaf_hex = hex::encode(leaf);
            if leaf_hex != row.leaf_hash {
                findings.push(Finding::new(
                    Level::Fail,
                    "leaf_hash",
                    format!("{what}: content does not match its leaf hash (modified)."),
                    reference,
                ));
            }
            accumulator.add(leaf);
            let size = accumulator.size as i64;
            let root = hex::encode(accumulator.root());
            roots.insert(size, root.clone());
            if row.tree_size != size || row.root_hash != root {
                findings.push(Finding::new(
                    Level::Fail,
                    "tree_head",
                    format!(
                        "{what}: stored tree head does not match the recomputed tree (an earlier entry was changed, removed or inserted)."
                    ),
                    reference,
                ));
            }
            let late_signature = late.get(&("entry".to_string(), row.id));
            let check = if signatures_for.is_none_or(|ids| ids.contains(&row.id)) {
                // the signature must vouch for the recomputed state, not just for what is stored
                let check = self.check_signature(
                    row.signature.as_deref(),
                    late_signature,
                    &entry_signed_payload(&leaf_hex, size, &root),
                );
                findings.extend(Self::signature_findings(&check, &what, reference));
                check
            } else {
                SignatureCheck {
                    present: row.signature.as_deref().is_some_and(|s| !s.is_empty()) || late_signature.is_some(),
                    ..Default::default()
                }
            };
            if let Some(corrects_id) = row.corrects_id {
                let target = by_id.get(&corrects_id);
                if row.kind != "note" || target.is_none_or(|t| t.kind != "note" || t.leaf_index >= row.leaf_index) {
                    findings.push(Finding::new(
                        Level::Fail,
                        "correction_target",
                        format!("{what}: corrects #{corrects_id}, which is not an earlier note of this case."),
                        reference,
                    ));
                }
            }
            results.push(EntryResult {
                entry: row.clone(),
                recomputed_leaf_hash: leaf_hex,
                recomputed_root_hash: root,
                recomputed_tree_size: size,
                signature: check,
                findings,
            });
            if let Some(progress) = progress.as_mut() {
                progress(position + 1, total.unwrap_or(rows.len()));
            }
        }
        (results, roots)
    }

    pub fn verify_entry(&self, entry_id: i64) -> Result<EntryResult> {
        let case_id: i64 = self
            .db
            .conn
            .query_row("SELECT case_id FROM entries WHERE id = ?", [entry_id], |row| row.get(0))
            .optional()?
            .ok_or_else(|| FactumError::general(format!("Entry #{entry_id} does not exist.")))?;
        let only = HashSet::from([entry_id]);
        let (results, _) = self.check_entries(
            case_id,
            &self.load_entries(case_id)?,
            &self.late_signatures()?,
            Some(&only),
            None,
            None,
        );
        Ok(results
            .into_iter()
            .find(|result| result.entry.id == entry_id)
            .expect("the entry is in its case log"))
    }

    fn head_findings(
        tree_size: i64,
        root_hash: &str,
        roots: &HashMap<i64, String>,
        size: i64,
        what: &str,
        reference: Ref,
    ) -> Vec<Finding> {
        if tree_size > size {
            return vec![Finding::new(
                Level::Fail,
                "seal_truncated",
                format!("{what}: covers {tree_size} entries but the log has only {size} — entries were removed."),
                reference,
            )];
        }
        if roots.get(&tree_size).map(String::as_str) != Some(root_hash) {
            return vec![Finding::new(
                Level::Fail,
                "seal_root",
                format!("{what}: root hash does not match the log (entries were changed)."),
                reference,
            )];
        }
        Vec::new()
    }

    pub fn verify_case(&self, case_id: i64, mut progress: Option<Progress<'_>>) -> Result<CaseReport> {
        let case = self.load_case_row(case_id)?;
        let rows = self.load_entries(case_id)?;
        let late = self.late_signatures()?;
        let db_heads = self.list_tree_heads(case_id)?;
        let total = rows.len() + db_heads.len();
        let (mut results, roots) = self.check_entries(
            case_id,
            &rows,
            &late,
            None,
            progress.as_mut().map(|p| &mut **p as Progress<'_>),
            Some(total),
        );
        let size = rows.len() as i64;
        let mut findings: Vec<Finding> = results.iter().flat_map(|r| r.findings.clone()).collect();

        let mut heads = Vec::new();
        for (number, head) in db_heads.iter().enumerate() {
            let reference = Ref {
                entry_id: None,
                tree_head_id: Some(head.id),
            };
            let what = format!("Seal #{} (size {}, {})", head.id, head.tree_size, head.reason);
            let mut head_findings =
                Self::head_findings(head.tree_size, &head.root_hash, &roots, size, &what, reference);
            let expected = seal_payload(
                case_id,
                &head.case_file,
                head.tree_size,
                &head.root_hash,
                &head.created_utc,
                &head.reason,
            );
            let check = self.check_signature(
                head.signature.as_deref(),
                late.get(&("tree_head".to_string(), head.id)),
                &expected,
            );
            head_findings.extend(Self::signature_findings(&check, &what, reference));
            if let Some(file_path) = head.file_path.as_deref().filter(|p| !p.is_empty())
                && !Path::new(file_path).exists()
            {
                head_findings.push(Finding::new(
                    Level::Warn,
                    "seal_file_missing",
                    format!("{what}: external copy {file_path} is missing."),
                    reference,
                ));
            }
            findings.extend(head_findings.iter().cloned());
            heads.push(TreeHeadResult {
                source: SealSource::Database,
                label: what,
                tree_size: head.tree_size,
                root_hash: head.root_hash.clone(),
                created_utc: Some(head.created_utc.clone()),
                reason: Some(head.reason.clone()),
                signature: check,
                tree_head_id: Some(head.id),
                path: head.file_path.clone(),
                findings: head_findings,
            });
            if let Some(progress) = progress.as_mut() {
                progress(rows.len() + number + 1, total);
            }
        }

        for seal_file in self.read_seal_files(case_id)? {
            let name = seal_file
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let what = format!("Seal file {name}");
            let mut head_findings = Self::head_findings(
                seal_file.tree_size(),
                seal_file.root_hash(),
                &roots,
                size,
                &what,
                Ref::default(),
            );
            let check = if let Some(signature) = &seal_file.signature {
                // the file's signature covers the file's own payload; what matters is that it is valid and trusted
                let check = self.check_signature(Some(signature), None, &seal_file.payload_text);
                head_findings.extend(Self::signature_findings(&check, &what, Ref::default()));
                check
            } else {
                // the database seal already enforces signing; an unsigned external copy is only weaker evidence
                head_findings.push(Finding::new(
                    Level::Warn,
                    "seal_file_unsigned",
                    format!("{what} is not signed."),
                    Ref::default(),
                ));
                SignatureCheck::absent()
            };
            findings.extend(head_findings.iter().cloned());
            heads.push(TreeHeadResult {
                source: SealSource::File,
                label: what,
                tree_size: seal_file.tree_size(),
                root_hash: seal_file.root_hash().to_string(),
                created_utc: seal_file.text_field("created_utc"),
                reason: seal_file.text_field("reason"),
                signature: check,
                tree_head_id: None,
                path: Some(seal_file.path.to_string_lossy().into_owned()),
                findings: head_findings,
            });
        }

        let newest = heads
            .iter()
            .filter(|h| h.status() != Level::Fail)
            .map(|h| h.tree_size)
            .max();
        for result in results.iter_mut() {
            if newest.is_none_or(|n| result.entry.leaf_index >= n) {
                let finding = Finding::new(
                    Level::Warn,
                    "not_sealed",
                    format!("Entry #{} was added after the newest seal.", result.entry.id),
                    Ref {
                        entry_id: Some(result.entry.id),
                        tree_head_id: None,
                    },
                );
                result.findings.push(finding.clone());
                findings.push(finding);
            }
        }
        let seal_dir_is_default = self.seal_dir_is_default();
        if !self.seal_dir().is_dir() && !seal_dir_is_default {
            findings.push(Finding::new(
                Level::Warn,
                "seal_dir_unreachable",
                format!(
                    "The seal folder {} is not reachable — external seal copies were not checked.",
                    self.seal_dir().display()
                ),
                Ref::default(),
            ));
        }
        if seal_dir_is_default {
            findings.push(Finding::new(
                Level::Warn,
                "seal_dir_default",
                "Seal copies are stored next to the database, not externally. Set FACTUM_SEAL_DIR or choose a seal folder.",
                Ref::default(),
            ));
        }
        findings.extend(self.metadata_findings(&case, &rows)?);

        let signers: BTreeSet<(String, Option<String>)> = results
            .iter()
            .map(|r| &r.signature)
            .chain(heads.iter().map(|h| &h.signature))
            .filter(|check| check.valid)
            .filter_map(|check| {
                check
                    .fingerprint
                    .clone()
                    .filter(|f| !f.is_empty())
                    .map(|f| (f, check.username.clone()))
            })
            .collect();
        let root_hash = roots[&size].clone();
        Ok(CaseReport {
            case,
            tree_size: size,
            root_hash,
            entries: results,
            tree_heads: heads,
            findings,
            signers: signers.into_iter().collect(),
            newest_seal_size: newest,
        })
    }

    pub fn metadata_findings(&self, case: &Case, rows: &[Entry]) -> Result<Vec<Finding>> {
        let events: Vec<serde_json::Map<String, Value>> = rows
            .iter()
            .filter(|row| row.kind == "system")
            .filter_map(|row| match parse_payload(row.payload_json.as_deref()) {
                Value::Object(map) => Some(map),
                _ => None,
            })
            .collect();
        let event_of =
            |payload: &serde_json::Map<String, Value>| payload.get("event").and_then(Value::as_str).map(str::to_string);
        let last = |names: &[&str]| {
            events
                .iter()
                .rev()
                .find(|p| event_of(p).is_some_and(|e| names.contains(&e.as_str())))
                .cloned()
        };
        let mut failures = Vec::new();
        let mut fail = |message: String| failures.push(Finding::new(Level::Fail, "metadata", message, Ref::default()));
        let get =
            |payload: &serde_json::Map<String, Value>, key: &str| payload.get(key).cloned().unwrap_or(Value::Null);

        match last(&["case_created", "case_edited"]) {
            None => fail("The case has no 'case created' entry in its log.".into()),
            Some(current) => {
                for (key, value) in [
                    ("case_file", &case.case_file),
                    ("case_name", &case.case_name),
                    ("description", &case.description),
                ] {
                    if text_value(value) != get(&current, key) {
                        fail(format!(
                            "Case field '{key}' was changed outside the log (log: {}, database: {}).",
                            value_repr(&get(&current, key)),
                            crate::pystr::repr(value)
                        ));
                    }
                }
            }
        }
        if let Some(created) = last(&["case_created"])
            && get(&created, "created_utc") != text_value(&case.created_utc)
        {
            fail("The case creation time was changed outside the log.".into());
        }
        let expected_archived = match last(&["case_archived", "case_reopened"]) {
            Some(state) if event_of(&state).as_deref() == Some("case_archived") => get(&state, "archived_utc"),
            _ => Value::Null,
        };
        if optional_value(&case.archived_utc) != expected_archived {
            fail("The archive state of the case was changed outside the log.".into());
        }

        let mut statement = self
            .db
            .conn
            .prepare(&format!("SELECT {} FROM evidence WHERE case_id = ?", Evidence::COLUMNS))?;
        let evidence_rows: BTreeMap<i64, Evidence> = statement
            .query_map([case.id], Evidence::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|evidence| (evidence.id, evidence))
            .collect();
        let mut created_events: BTreeMap<IdKey, serde_json::Map<String, Value>> = BTreeMap::new();
        let mut deleted_events: BTreeMap<IdKey, serde_json::Map<String, Value>> = BTreeMap::new();
        for payload in &events {
            match event_of(payload).as_deref() {
                Some("evidence_created") => {
                    created_events.insert(IdKey::of(payload.get("evidence_id")), payload.clone());
                }
                Some("evidence_deleted") => {
                    deleted_events.insert(IdKey::of(payload.get("evidence_id")), payload.clone());
                }
                _ => {}
            }
        }
        for (evidence_id, evidence) in &evidence_rows {
            let Some(event) = created_events.get(&IdKey::Int(*evidence_id)) else {
                fail(format!(
                    "Evidence #{evidence_id} has no 'evidence created' entry in this case's log."
                ));
                continue;
            };
            for (key, value) in [
                ("description", &evidence.description),
                ("evidence_hash", &evidence.evidence_hash),
                ("created_utc", &evidence.created_utc),
            ] {
                if text_value(value) != get(event, key) {
                    fail(format!(
                        "Evidence #{evidence_id} field '{key}' was changed outside the log."
                    ));
                }
            }
            let deleted = deleted_events
                .get(&IdKey::Int(*evidence_id))
                .map(|e| get(e, "deleted_utc"))
                .unwrap_or(Value::Null);
            if optional_value(&evidence.deleted_utc) != deleted {
                fail(format!(
                    "Evidence #{evidence_id} deletion state was changed outside the log."
                ));
            }
        }
        for evidence_id in created_events.keys() {
            let known = matches!(evidence_id, IdKey::Int(id) if evidence_rows.contains_key(id));
            if !known {
                fail(format!(
                    "Evidence #{evidence_id} is in the log, but its database row is missing or belongs to another case."
                ));
            }
        }
        for row in rows {
            if let Some(evidence_id) = row.evidence_id
                && !created_events.contains_key(&IdKey::Int(evidence_id))
            {
                fail(format!(
                    "Entry #{} refers to evidence #{evidence_id}, which was not created in this case.",
                    row.id
                ));
            }
        }
        Ok(failures)
    }
}
