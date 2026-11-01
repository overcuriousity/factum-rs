//! Signing entries and seals that were created without a key.

use std::path::PathBuf;

use rusqlite::{OptionalExtension, params};

use crate::canonical::utc_now;
use crate::error::{FactumError, Result};
use crate::files::write_atomically;
use crate::log_service::entry_signed_payload;
use crate::seals::{TreeHead, seal_payload};
use crate::services::Factum;
use crate::verifier::{CaseReport, EntryResult, Level, SealSource};

/// failures that signing later is meant to fix; any other failure blocks signing, so a key never vouches for
/// tampered data
pub const SIGNABLE: [&str; 1] = ["unsigned"];

/// Refuses a report with a failure that signing later does not fix.
fn ensure_signable(report: &CaseReport) -> Result<()> {
    let blocking: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.level == Level::Fail && !SIGNABLE.contains(&f.code))
        .collect();
    match blocking.first() {
        Some(first) => Err(FactumError::log_broken(format!(
            "Nothing was signed: the case log has {} failure(s), e.g. {}",
            blocking.len(),
            first.message
        ))),
        None => Ok(()),
    }
}

// The verification signing rests on can run elsewhere (the GUI: on a worker thread, gpg per signature): the `_checked`
// calls sign on the strength of the report it gave.
impl Factum<'_> {
    pub fn ensure_log_intact(&self, case_id: i64) -> Result<CaseReport> {
        let report = self.verify_case(case_id, None)?;
        ensure_signable(&report)?;
        Ok(report)
    }

    fn late_sign(&self, payload: &str) -> Result<String> {
        if self.signer.active_key().is_none() {
            return Err(FactumError::signing(
                "No GPG key is active. Select a signing key first.",
            ));
        }
        self.signer
            .sign_text(payload)
            .ok_or_else(|| FactumError::signing("GPG signing failed."))
    }

    fn store_late_signature(&self, target: &str, target_id: i64, signature: &str) -> Result<()> {
        self.db.transaction(|conn| {
            conn.execute(
                "INSERT INTO late_signatures (target, target_id, signature, signed_utc) VALUES (?, ?, ?, ?)",
                params![target, target_id, signature, utc_now()],
            )?;
            Ok(())
        })
    }

    fn is_signed(&self, target: &str, target_id: i64, signature: Option<&str>) -> Result<bool> {
        if signature.is_some_and(|s| !s.is_empty()) {
            return Ok(true);
        }
        Ok(self
            .db
            .conn
            .query_row(
                "SELECT 1 FROM late_signatures WHERE target = ? AND target_id = ?",
                params![target, target_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// The case of an entry that can be signed later: it exists and is not signed.
    pub fn case_of_unsigned_entry(&self, entry_id: i64) -> Result<i64> {
        let row: Option<(i64, Option<String>)> = self
            .db
            .conn
            .query_row(
                "SELECT case_id, signature FROM entries WHERE id = ?",
                [entry_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (case_id, signature) =
            row.ok_or_else(|| FactumError::general(format!("Entry #{entry_id} does not exist.")))?;
        if self.is_signed("entry", entry_id, signature.as_deref())? {
            return Err(FactumError::general(format!("Entry #{entry_id} is already signed.")));
        }
        Ok(case_id)
    }

    pub fn sign_entry(&self, entry_id: i64) -> Result<()> {
        let case_id = self.case_of_unsigned_entry(entry_id)?;
        self.sign_entry_checked(&self.ensure_log_intact(case_id)?, entry_id)
    }

    pub fn sign_entry_checked(&self, report: &CaseReport, entry_id: i64) -> Result<()> {
        self.case_of_unsigned_entry(entry_id)?;
        ensure_signable(report)?;
        let result = report
            .entry_result(entry_id)
            .ok_or_else(|| FactumError::general(format!("Entry #{entry_id} was not verified.")))?;
        self.sign_entry_result(result)
    }

    fn sign_entry_result(&self, result: &EntryResult) -> Result<()> {
        let payload = entry_signed_payload(
            &result.recomputed_leaf_hash,
            result.recomputed_tree_size,
            &result.recomputed_root_hash,
        );
        self.store_late_signature("entry", result.entry.id, &self.late_sign(&payload)?)?;
        log::info!("Entry #{} signed later.", result.entry.id);
        Ok(())
    }

    /// A seal that can be signed later: it exists and is not signed.
    pub fn unsigned_tree_head(&self, tree_head_id: i64) -> Result<TreeHead> {
        let head = self
            .get_tree_head(tree_head_id)?
            .ok_or_else(|| FactumError::general(format!("Seal #{tree_head_id} does not exist.")))?;
        if self.is_signed("tree_head", tree_head_id, head.signature.as_deref())? {
            return Err(FactumError::general(format!("Seal #{tree_head_id} is already signed.")));
        }
        Ok(head)
    }

    pub fn sign_tree_head(&self, tree_head_id: i64) -> Result<()> {
        let case_id = self.unsigned_tree_head(tree_head_id)?.case_id;
        self.sign_tree_head_checked(&self.ensure_log_intact(case_id)?, tree_head_id)
    }

    pub fn sign_tree_head_checked(&self, report: &CaseReport, tree_head_id: i64) -> Result<()> {
        let head = self.unsigned_tree_head(tree_head_id)?;
        ensure_signable(report)?;
        if !report.tree_heads.iter().any(|h| h.tree_head_id == Some(tree_head_id)) {
            return Err(FactumError::general(format!("Seal #{tree_head_id} was not verified.")));
        }
        self.sign_tree_head_row(&head)
    }

    fn sign_tree_head_row(&self, head: &TreeHead) -> Result<()> {
        let signature = self.late_sign(&seal_payload(
            head.case_id,
            &head.case_file,
            head.tree_size,
            &head.root_hash,
            &head.created_utc,
            &head.reason,
        ))?;
        self.store_late_signature("tree_head", head.id, &signature)?;
        if let Some(file_path) = head.file_path.as_deref().filter(|p| !p.is_empty()) {
            let signed_copy = PathBuf::from(file_path).with_extension("asc");
            // written as gpg wrote it, see seal()
            write_atomically(&signed_copy, signature.as_bytes()).map_err(|e| {
                FactumError::general(format!(
                    "Seal #{} was signed, but the signed copy could not be written to {}: {e}",
                    head.id,
                    signed_copy.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Signs every unsigned entry and database seal of a case; returns how many were signed and, when that was not
    /// all of them, what stopped the run (what was signed stays signed; the text says how far it got). A failed
    /// verification signs nothing.
    pub fn sign_all_unsigned(&self, case_id: i64) -> Result<(usize, Option<FactumError>)> {
        self.sign_all_checked(&self.ensure_log_intact(case_id)?)
    }

    pub fn sign_all_checked(&self, report: &CaseReport) -> Result<(usize, Option<FactumError>)> {
        ensure_signable(report)?;
        let entries: Vec<&EntryResult> = report.entries.iter().filter(|r| !r.signature.present).collect();
        let heads: Vec<i64> = report
            .tree_heads
            .iter()
            .filter(|head| head.source == SealSource::Database && !head.signature.present)
            .map(|head| head.tree_head_id.expect("database seals have an id"))
            .collect();
        let sign_head = |id: i64| {
            let row = self
                .get_tree_head(id)?
                .ok_or_else(|| FactumError::general(format!("Seal #{id} does not exist.")))?;
            self.sign_tree_head_row(&row)
        };
        let signed = entries
            .iter()
            .map(|result| self.sign_entry_result(result))
            .chain(heads.iter().map(|id| sign_head(*id)));
        let mut count = 0;
        for result in signed {
            if let Err(mut e) = result {
                if count > 0 {
                    e.message = format!("Signed {count} of {}; stopped: {e}", entries.len() + heads.len());
                }
                return Ok((count, Some(e)));
            }
            count += 1;
        }
        Ok((count, None))
    }
}
