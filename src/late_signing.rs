//! Signing entries and seals that were created without a key.

use std::path::PathBuf;

use rusqlite::{OptionalExtension, params};

use crate::canonical::utc_now;
use crate::error::{FactumError, Result};
use crate::log_service::entry_signed_payload;
use crate::seals::{TreeHead, seal_payload};
use crate::services::Factum;
use crate::verifier::{CaseReport, EntryResult, Level, SealSource};

/// failures that signing later is meant to fix; any other failure blocks signing, so a key never vouches for
/// tampered data
pub const SIGNABLE: [&str; 1] = ["unsigned"];

impl Factum<'_> {
    pub fn ensure_log_intact(&self, case_id: i64) -> Result<CaseReport> {
        let report = self.verify_case(case_id, None)?;
        let blocking: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.level == Level::Fail && !SIGNABLE.contains(&f.code))
            .collect();
        if let Some(first) = blocking.first() {
            return Err(FactumError::log_broken(format!(
                "Nothing was signed: the case log has {} failure(s), e.g. {}",
                blocking.len(),
                first.message
            )));
        }
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
            .ok_or_else(|| FactumError::signing("GPG signing failed — nothing was signed."))
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

    pub fn sign_entry(&self, entry_id: i64) -> Result<()> {
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
            return Err(FactumError::general(format!(
                "Entry #{entry_id} is already signed."
            )));
        }
        let report = self.ensure_log_intact(case_id)?;
        let result = report
            .entry_result(entry_id)
            .expect("the entry is in its case log");
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

    pub fn sign_tree_head(&self, tree_head_id: i64) -> Result<()> {
        let head = self
            .get_tree_head(tree_head_id)?
            .ok_or_else(|| FactumError::general(format!("Seal #{tree_head_id} does not exist.")))?;
        if self.is_signed("tree_head", tree_head_id, head.signature.as_deref())? {
            return Err(FactumError::general(format!(
                "Seal #{tree_head_id} is already signed."
            )));
        }
        self.ensure_log_intact(head.case_id)?;
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
            std::fs::write(&signed_copy, signature.as_bytes()).map_err(|e| {
                FactumError::general(format!(
                    "Seal #{} was signed, but the signed copy could not be written to {}: {e}",
                    head.id,
                    signed_copy.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Signs every unsigned entry and database seal of a case; returns how many were signed.
    pub fn sign_all_unsigned(&self, case_id: i64) -> Result<usize> {
        let report = self.ensure_log_intact(case_id)?;
        let mut count = 0;
        for result in &report.entries {
            if !result.signature.present {
                self.sign_entry_result(result)?;
                count += 1;
            }
        }
        for head in &report.tree_heads {
            if head.source == SealSource::Database && !head.signature.present {
                let id = head.tree_head_id.expect("database seals have an id");
                let row = self
                    .get_tree_head(id)?
                    .ok_or_else(|| FactumError::general(format!("Seal #{id} does not exist.")))?;
                self.sign_tree_head_row(&row)?;
                count += 1;
            }
        }
        Ok(count)
    }
}
