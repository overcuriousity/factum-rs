//! What a report shows, built once from a verification report and rendered as HTML, Markdown and PDF.

use std::collections::HashMap;

use crate::cases::Case;
use crate::error::Result;
use crate::pystr::{head, tail};
use crate::seals::TreeHead;
use crate::services::Factum;
use crate::verifier::{CaseReport, Level, SignatureCheck};

/// 2026-10-05T14:03:22.417Z -> 2026-10-05 14:03:22 UTC; the exact value stays in the integrity appendix
pub fn readable_utc(timestamp: Option<&str>) -> String {
    match timestamp {
        None | Some("") => "—".into(),
        Some(timestamp) => {
            let replaced = timestamp.replace('T', " ");
            let first = replaced.split('.').next().unwrap_or_default();
            format!("{} UTC", first.trim_end_matches('Z'))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRow {
    pub id: i64,
    pub case_id: i64,
    pub description: String,
    pub evidence_hash: String,
    pub created_utc: String,
    pub deleted_utc: Option<String>,
    /// the evidence description
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct ReportEntry {
    pub entry_id: i64,
    pub leaf_index: i64,
    pub kind: String,
    pub created_utc: String,
    /// first version of the line this entry belongs to
    pub origin_id: i64,
    pub origin_created_utc: String,
    pub evidence: Option<String>,
    pub text: String,
    pub labels: Vec<String>,
    /// 1 = never corrected
    pub version: usize,
    /// OK / WARN / FAIL from the verifier
    pub status: Level,
    /// "signed", "signed later", "unsigned", "invalid", "untrusted"
    pub signature_state: &'static str,
    /// last 8 hex digits of the fingerprint
    pub signer_key: Option<String>,
    pub fingerprint: Option<String>,
    /// the clearsigned block that signs this entry
    pub signature: Option<String>,
    pub leaf_hash: String,
    pub tree_size: i64,
    pub root_hash: String,
}

impl ReportEntry {
    pub fn short_line(&self) -> String {
        let key = self.signer_key.clone().unwrap_or_else(|| "None".into());
        let signature = match self.signature_state {
            "signed" => format!("signed {key} ✓"),
            "signed later" => format!("signed later {key} ✓"),
            "invalid" => "signature ✗".into(),
            "untrusted" => format!("signed {key}, untrusted key ✗"),
            _ => "unsigned".into(),
        };
        format!("#{} · leaf {}… · {signature}", self.entry_id, head(&self.leaf_hash, 12))
    }

    pub fn correction_note(&self) -> Option<String> {
        if self.version == 1 {
            return None;
        }
        Some(format!(
            "Corrected {} (version {}, entry #{})",
            readable_utc(Some(&self.created_utc)),
            self.version,
            self.entry_id
        ))
    }

    pub fn integrity_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Entry #{}, leaf {}", self.entry_id, self.leaf_index),
            format!("Leaf hash:  {}", self.leaf_hash),
            format!("Tree head:  size {}, root {}", self.tree_size, self.root_hash),
            format!(
                "Signature:  {}{}",
                self.signature_state,
                self.fingerprint
                    .as_ref()
                    .map(|f| format!(" by {f}"))
                    .unwrap_or_default()
            ),
        ];
        if let Some(signature) = self.signature.as_deref().filter(|s| !s.is_empty()) {
            lines.push(String::new());
            lines.push(crate::pystr::strip(signature).to_string());
        }
        lines
    }
}

/// An evidence container of the case, as the reports list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRow {
    pub id: i64,
    pub name: String,
    pub file_name: String,
    pub uuid: String,
    /// "Evidence #2 disk"
    pub evidence: Option<String>,
    /// open or closed
    pub state: String,
    /// who signed the newest close, or "unsigned" / "not closed"
    pub signatures: String,
    /// (path, size, SHA-256)
    pub files: Vec<(String, u64, String)>,
}

impl ContainerRow {
    /// The key/value lines above a container's file list.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        let mut rows = vec![("File", self.file_name.clone()), ("UUID", self.uuid.clone())];
        if let Some(evidence) = &self.evidence {
            rows.push(("Evidence", evidence.clone()));
        }
        rows.push(("State", self.state.clone()));
        rows.push(("Signatures", self.signatures.clone()));
        rows
    }

    pub fn file_cells(&self) -> Vec<Vec<String>> {
        self.files
            .iter()
            .map(|(path, size, sha256)| vec![path.clone(), size.to_string(), sha256.clone()])
            .collect()
    }
}

pub struct ReportModel {
    pub case: Case,
    pub evidence: Vec<EvidenceRow>,
    pub containers: Vec<ContainerRow>,
    pub exported_utc: String,
    pub exporting_key: Option<String>,
    pub seal: TreeHead,
    pub report: CaseReport,
    /// newest version of every line, at the position of the line's first version
    pub timeline: Vec<ReportEntry>,
    /// every leaf in log order
    pub appendix: Vec<ReportEntry>,
}

impl ReportModel {
    pub fn notes(&self) -> Vec<&ReportEntry> {
        self.timeline.iter().filter(|item| item.kind == "note").collect()
    }

    pub fn activity(&self) -> Vec<&ReportEntry> {
        self.timeline.iter().filter(|item| item.kind == "system").collect()
    }
}

pub fn signature_state(check: &SignatureCheck) -> &'static str {
    if !check.present {
        "unsigned"
    } else if !(check.valid && check.covers_payload) {
        "invalid"
    } else if !check.trusted {
        "untrusted"
    } else if check.late {
        "signed later"
    } else {
        "signed"
    }
}

/// Every failure, and one line per kind of warning, so hundreds of 'not sealed' warnings stay readable.
pub fn grouped_findings(report: &CaseReport) -> Vec<(Level, String)> {
    let mut items: Vec<(Level, String)> = report
        .findings
        .iter()
        .filter(|f| f.level == Level::Fail)
        .map(|f| (Level::Fail, f.message.clone()))
        .collect();
    let mut warnings: Vec<(&str, Vec<&str>)> = Vec::new();
    for finding in report.findings.iter().filter(|f| f.level == Level::Warn) {
        match warnings.iter_mut().find(|(code, _)| *code == finding.code) {
            Some((_, messages)) => messages.push(&finding.message),
            None => warnings.push((finding.code, vec![&finding.message])),
        }
    }
    for (_, messages) in warnings {
        let more = if messages.len() > 1 {
            format!(" (and {} more like this)", messages.len() - 1)
        } else {
            String::new()
        };
        items.push((Level::Warn, format!("{}{more}", messages[0])));
    }
    items
}

/// One plain-language line for the top of a report; the details are in the verification section at the end.
pub fn status_sentence(report: &CaseReport) -> String {
    match report.overall() {
        Level::Fail => "Integrity check FAILED: the log or its signatures do not match. \
                        See Verification at the end of this report."
            .into(),
        Level::Warn => format!(
            "Integrity check passed with warnings ({} log entries). See Verification at the end of this report.",
            report.entries.len()
        ),
        Level::Ok => format!(
            "Integrity check passed: all {} log entries verified.",
            report.entries.len()
        ),
    }
}

pub fn verification_summary(report: &CaseReport) -> String {
    let signers = report
        .signers
        .iter()
        .map(|(fingerprint, _)| fingerprint.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} entries: {} OK, {} WARN, {} FAIL. Tree size {}, root {}. Signers: {}.",
        report.entries.len(),
        report.count(Level::Ok),
        report.count(Level::Warn),
        report.count(Level::Fail),
        report.tree_size,
        report.root_hash,
        if signers.is_empty() { "none" } else { &signers }
    )
}

impl Factum<'_> {
    pub fn evidence_rows(&self, case_id: i64) -> Result<Vec<EvidenceRow>> {
        let mut statement = self.db.conn.prepare(
            "SELECT id, case_id, description, evidence_hash, created_utc, deleted_utc, details FROM evidence WHERE case_id = ? ORDER BY id",
        )?;
        let rows = statement.query_map([case_id], |row| {
            Ok(EvidenceRow {
                id: row.get(0)?,
                case_id: row.get(1)?,
                description: row.get(2)?,
                evidence_hash: row.get(3)?,
                created_utc: row.get(4)?,
                deleted_utc: row.get(5)?,
                details: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The case's containers, read from its log.
    pub fn container_rows(&self, case_id: i64, evidence_names: &HashMap<i64, String>) -> Result<Vec<ContainerRow>> {
        let mut rows = Vec::new();
        for summary in self.list_containers(case_id)? {
            let detail = self.container(summary.id)?;
            let signatures = match detail.closes.last() {
                _ if detail.last_closed_without_file() => "none: closed while its file was missing".to_string(),
                None => "not closed".to_string(),
                Some(close) => {
                    let (gpg, x509) = match close.signed_later {
                        Some(entry) => detail
                            .late_signatures
                            .iter()
                            .find(|(id, ..)| *id == entry)
                            .map(|(_, _, gpg, x509)| (gpg.clone(), x509.clone()))
                            .unwrap_or_default(),
                        None => (close.gpg.clone(), close.x509.clone()),
                    };
                    let mut parts = Vec::new();
                    if let Some(gpg) = gpg {
                        parts.push(format!("GPG {gpg}"));
                    }
                    if let Some(x509) = x509 {
                        parts.push(format!("X.509 {x509}"));
                    }
                    if close.signed_later.is_some() && !parts.is_empty() {
                        parts.push("signed later".into());
                    }
                    if parts.is_empty() {
                        "unsigned".to_string()
                    } else {
                        parts.join(" · ")
                    }
                }
            };
            rows.push(ContainerRow {
                id: summary.id,
                name: summary.name.clone(),
                file_name: detail.file_name.clone(),
                uuid: summary.uuid.clone(),
                evidence: detail.evidence_id.and_then(|id| evidence_names.get(&id).cloned()),
                state: match (summary.open, detail.last_closed_without_file()) {
                    (true, _) => "open",
                    (false, true) => "closed (file missing)",
                    (false, false) => "closed",
                }
                .to_string(),
                signatures,
                files: detail
                    .files()
                    .map(|(_, f)| (report_path(f), f.size, f.sha256.clone()))
                    .collect(),
            });
        }
        Ok(rows)
    }

    pub fn build_model(
        &self,
        report: CaseReport,
        seal: TreeHead,
        exporting_key: Option<String>,
        exported_utc: &str,
    ) -> Result<ReportModel> {
        let case_id = report.case.id;
        let evidence = self.evidence_rows(case_id)?;
        let names: HashMap<i64, String> = evidence
            .iter()
            .map(|item| (item.id, format!("Evidence #{} {}", item.id, item.description)))
            .collect();
        let late = self.late_signatures()?;
        let mut origin: HashMap<i64, i64> = HashMap::new();
        let mut version: HashMap<i64, usize> = HashMap::new();
        let mut created: HashMap<i64, String> = HashMap::new();
        let mut appendix = Vec::new();
        for result in &report.entries {
            let (entry, check) = (&result.entry, &result.signature);
            let (line_origin, line_version) = match entry.corrects_id {
                Some(parent) => (
                    *origin.get(&parent).unwrap_or(&entry.id),
                    version.get(&parent).copied().unwrap_or(0) + 1,
                ),
                None => (entry.id, 1),
            };
            origin.insert(entry.id, line_origin);
            version.insert(entry.id, line_version);
            created.insert(entry.id, entry.created_utc.clone());
            let labels = crate::tags::get_tags_for_entry(&self.db.conn, entry.id)?
                .into_iter()
                .filter(|(_, source)| source == "label")
                .map(|(tag, _)| tag)
                .collect();
            appendix.push(ReportEntry {
                entry_id: entry.id,
                leaf_index: entry.leaf_index,
                kind: entry.kind.clone(),
                created_utc: entry.created_utc.clone(),
                origin_id: line_origin,
                origin_created_utc: created
                    .get(&line_origin)
                    .cloned()
                    .unwrap_or_else(|| entry.created_utc.clone()),
                evidence: entry.evidence_id.and_then(|id| names.get(&id).cloned()),
                text: entry.text.clone(),
                labels,
                version: line_version,
                status: result.status(),
                signature_state: signature_state(check),
                signer_key: check
                    .fingerprint
                    .as_deref()
                    .filter(|f| !f.is_empty())
                    .map(|f| tail(f, 8).to_string()),
                fingerprint: check.fingerprint.clone().filter(|f| !f.is_empty()),
                signature: entry.signature.clone().filter(|s| !s.is_empty()).or_else(|| {
                    late.get(&("entry".to_string(), entry.id))
                        .map(|(signature, _)| signature.clone())
                }),
                leaf_hash: entry.leaf_hash.clone(),
                tree_size: entry.tree_size,
                root_hash: entry.root_hash.clone(),
            });
        }
        let mut newest: HashMap<i64, &ReportEntry> = HashMap::new();
        let mut line_labels: HashMap<i64, Vec<String>> = HashMap::new();
        for item in &appendix {
            newest.insert(item.origin_id, item); // log order: the last one seen is the newest version
            // labels stay on the version they were added to; the timeline shows those of the whole line
            let labels = line_labels.entry(item.origin_id).or_default();
            for label in &item.labels {
                if !labels.contains(label) {
                    labels.push(label.clone());
                }
            }
        }
        let timeline = appendix
            .iter()
            .filter(|item| item.entry_id == item.origin_id)
            .map(|item| {
                // a copy: the appendix (and case.json) keep each label on the version it was added to
                let mut line = newest[&item.entry_id].clone();
                line.labels = line_labels[&item.entry_id].clone();
                line
            })
            .collect();
        let containers = self.container_rows(case_id, &names)?;
        Ok(ReportModel {
            case: report.case.clone(),
            evidence,
            containers,
            exported_utc: exported_utc.to_string(),
            exporting_key,
            seal,
            report,
            timeline,
            appendix,
        })
    }
}

/// A container file's path as reports show it: marked when its content is not (fully) stored.
fn report_path(file: &crate::container::volume::FileRecord) -> String {
    if file.metadata_only {
        format!("{} (metadata only, not stored)", file.path)
    } else if let Some((from, to)) = file.excerpt {
        format!("{} (excerpt, bytes {from}–{to})", file.path)
    } else if let Some(target) = &file.link {
        format!("{} (link to {target})", file.path)
    } else {
        file.path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_utc_drops_milliseconds() {
        assert_eq!(
            readable_utc(Some("2026-10-05T14:03:22.417Z")),
            "2026-10-05 14:03:22 UTC"
        );
        assert_eq!(readable_utc(None), "—");
    }
}
