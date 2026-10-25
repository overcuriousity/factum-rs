//! The verification bundle: a self-contained ZIP that anyone can verify without factum (verify.py).

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

use super::model::ReportModel;
use crate::canonical::pretty_json;
use crate::error::{FactumError, Result};
use crate::notes::parse_payload;
use crate::services::Factum;

/// The dependency-free verifier shipped in every bundle, byte for byte the one of factum-notes.
pub const VERIFY_PY: &[u8] = include_bytes!("verify.py");

pub const BUNDLE_README: &str = r#"# factum case bundle

This archive is a self-contained, verifiable export of one factum case.

## Verify it

    python3 verify.py <this-bundle>.zip

On Windows, run `py verify.py <this-bundle>.zip` instead.

Needs Python 3.8+ and gpg (on Windows: Gpg4win). By default your own keyring is used, so the signer's key must be in it and trusted.
Without the key: `python3 verify.py <bundle>.zip --use-bundled-keys` imports `public-keys.asc` into a temporary
keyring. Keys shipped inside the bundle prove nothing about who signed — compare the printed fingerprints with a
trusted source.

`sha256sum -c MANIFEST.sha256` checks the files, and `gpg --verify MANIFEST.sha256.asc MANIFEST.sha256` checks the
manifest signature, without Python. On Windows, `Get-FileHash -Algorithm SHA256 <file>` (PowerShell) prints a file's
hash to compare with the manifest.

## Contents

- `case.json` — case and evidence rows, every log entry with all hashed fields, seals, labels (labels are not signed)
- `signatures/` — `entry-<id>.asc` (signed at creation), `late-entry-<id>.asc` (signed later), `seal-<id>.asc`,
  `late-seal-<id>.asc`
- `public-keys.asc` — public keys of all signers
- `report.html`, `report.pdf`, `report.md` — readable reports
- `MANIFEST.sha256` (+ `.asc`) — SHA-256 of every file above, detached-signed

## Format (version 1)

Canonical JSON: keys sorted, separators `,` and `:` without spaces, non-ASCII characters unescaped, UTF-8.

Leaf data of an entry is the canonical JSON of
`{case_id, corrects_id, created_utc, evidence_id, format, kind, leaf_index, payload, text}`.
`leaf_hash = SHA-256(0x00 || leaf data)`. The tree hash follows RFC 9162 section 2.1.1: inner nodes are
`SHA-256(0x01 || left || right)`, the tree is split at the largest power of two smaller than the number of leaves,
and the empty tree hashes to `SHA-256("")`.

Each entry stores the tree head right after it was appended (`tree_size`, `root_hash`). Its signature is an OpenPGP
clearsigned block over `{"format":1,"leaf_hash":…,"root_hash":…,"tree_size":…}` (canonical JSON), so every signed
entry vouches for all entries before it.

A seal is a signed tree head beside the log: a clearsigned block over
`{"case_file","case_id","created_utc","format":1,"reason","root_hash","tree_size"}`, where `case_file` is the
case file number at the time of sealing (stored with the seal in `case.json`). A seal must match the root of the
first `tree_size` leaves; a seal larger than the log means entries were removed.

System entries (`kind = "system"`) record case and evidence changes in `payload` (events `case_created`,
`case_edited`, `case_archived`, `case_reopened`, `evidence_created`, `evidence_deleted`). The case and evidence rows
in `case.json` must match the newest event for them.

A correction is a note whose `corrects_id` points to an earlier note of the same case.
"#;

fn optional(text: &Option<String>) -> Value {
    text.as_ref()
        .map_or(Value::Null, |t| Value::String(t.clone()))
}

impl Factum<'_> {
    /// case.json content and the signature files it refers to (published path -> armored text).
    pub fn case_data(&self, model: &ReportModel) -> Result<(Value, BTreeMap<String, String>)> {
        let case_id = model.case.id;
        let late: HashMap<(String, i64), (String, String)> = self.late_signatures()?;
        let labels: HashMap<i64, &Vec<String>> = model
            .appendix
            .iter()
            .map(|item| (item.entry_id, &item.labels))
            .collect();
        let mut signatures = BTreeMap::new();
        let mut signature_fields =
            |target: &str, id: i64, signature: Option<&str>, prefix: &str, width: usize| {
                let mut fields = Map::new();
                fields.insert("signature_file".into(), Value::Null);
                fields.insert("late_signature_file".into(), Value::Null);
                fields.insert("late_signed_utc".into(), Value::Null);
                if let Some(signature) = signature.filter(|s| !s.is_empty()) {
                    let name = format!("signatures/{prefix}-{id:0width$}.asc");
                    signatures.insert(name.clone(), signature.to_string());
                    fields.insert("signature_file".into(), Value::String(name));
                }
                if let Some((signature, signed_utc)) = late.get(&(target.to_string(), id)) {
                    let name = format!("signatures/late-{prefix}-{id:0width$}.asc");
                    signatures.insert(name.clone(), signature.clone());
                    fields.insert("late_signature_file".into(), Value::String(name));
                    fields.insert("late_signed_utc".into(), Value::String(signed_utc.clone()));
                }
                fields
            };
        let mut entries = Vec::new();
        for result in &model.report.entries {
            let entry = &result.entry;
            let entry_labels = if entry.kind == "system" {
                Vec::new()
            } else {
                labels
                    .get(&entry.id)
                    .map(|l| (*l).clone())
                    .unwrap_or_default()
            };
            let mut item = json!({
                "id": entry.id, "leaf_index": entry.leaf_index, "kind": entry.kind, "evidence_id": entry.evidence_id,
                "text": entry.text, "payload": parse_payload(entry.payload_json.as_deref()),
                "corrects_id": entry.corrects_id, "created_utc": entry.created_utc, "format": entry.format,
                "leaf_hash": entry.leaf_hash, "tree_size": entry.tree_size, "root_hash": entry.root_hash,
                "labels": entry_labels,
            });
            item.as_object_mut().unwrap().extend(signature_fields(
                "entry",
                entry.id,
                entry.signature.as_deref(),
                "entry",
                6,
            ));
            entries.push(item);
        }
        let mut heads = Vec::new();
        for head in self.list_tree_heads(case_id)? {
            let mut item = json!({
                "id": head.id, "case_file": head.case_file, "tree_size": head.tree_size, "root_hash": head.root_hash,
                "created_utc": head.created_utc, "reason": head.reason,
            });
            item.as_object_mut().unwrap().extend(signature_fields(
                "tree_head",
                head.id,
                head.signature.as_deref(),
                "seal",
                4,
            ));
            heads.push(item);
        }
        let case = &model.case;
        let evidence: Vec<Value> = model
            .evidence
            .iter()
            .map(|e| {
                json!({"id": e.id, "case_id": e.case_id, "description": e.description, "evidence_hash": e.evidence_hash,
                       "created_utc": e.created_utc, "deleted_utc": optional(&e.deleted_utc)})
            })
            .collect();
        let data = json!({
            "format": 1, "exported_utc": model.exported_utc,
            "case": {"id": case.id, "case_file": case.case_file, "case_name": case.case_name,
                     "description": case.description, "created_utc": case.created_utc,
                     "archived_utc": optional(&case.archived_utc)},
            "evidence": evidence, "entries": entries, "tree_heads": heads,
        });
        Ok((data, signatures))
    }

    pub fn build_bundle(
        &self,
        model: &ReportModel,
        reports: &[(&str, Vec<u8>)],
        out_path: &Path,
    ) -> Result<PathBuf> {
        let (data, signatures) = self.case_data(model)?;
        let mut fingerprints: Vec<String> = model
            .report
            .signers
            .iter()
            .map(|(fingerprint, _)| fingerprint.clone())
            .collect();
        fingerprints.sort();
        fingerprints.dedup();
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("README.md".into(), BUNDLE_README.as_bytes().to_vec());
        files.insert("verify.py".into(), VERIFY_PY.to_vec());
        files.insert("case.json".into(), pretty_json(&data).into_bytes());
        files.insert(
            "public-keys.asc".into(),
            self.signer.export_public_keys(&fingerprints).into_bytes(),
        );
        for (name, content) in reports {
            files.insert(name.to_string(), content.clone());
        }
        for (name, text) in signatures {
            files.insert(name, text.into_bytes());
        }
        let manifest: String = files
            .iter()
            .map(|(name, content)| format!("{}  {name}\n", hex::encode(Sha256::digest(content))))
            .collect();
        let active = self.signer.active_key().is_some();
        let manifest_signature = if active {
            self.signer.sign_detached(manifest.as_bytes())
        } else {
            None
        };
        if active && manifest_signature.is_none() {
            return Err(FactumError::signing(
                "GPG signing of the bundle manifest failed — no bundle was written.",
            ));
        }
        let file = std::fs::File::create(out_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let zip_error = |e: zip::result::ZipError| {
            FactumError::general(format!("The bundle could not be written: {e}"))
        };
        let add =
            |zip: &mut zip::ZipWriter<std::fs::File>, name: &str, content: &[u8]| -> Result<()> {
                zip.start_file(name, options).map_err(zip_error)?;
                zip.write_all(content)?;
                Ok(())
            };
        for (name, content) in &files {
            add(&mut zip, name, content)?;
        }
        add(&mut zip, "MANIFEST.sha256", manifest.as_bytes())?;
        if let Some(signature) = manifest_signature {
            add(&mut zip, "MANIFEST.sha256.asc", signature.as_bytes())?;
        }
        zip.finish().map_err(zip_error)?;
        Ok(out_path.to_path_buf())
    }
}
