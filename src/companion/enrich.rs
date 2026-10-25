//! Enrichment: the model writes keywords, a context sentence and an importance per entry, in batches; the FTS index
//! is kept current.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::llm::{ChatRequest, Client, LlmError, Role};
use super::prompts::{enrich_instruction, entry_line};
use super::retrieval::Enrichment;
use super::store::CompanionDb;
use super::tokens::{TextKind, budget, estimate_tokens};
use super::validate::parse_enrichment_output;
use crate::Factum;
use crate::db::Db;
use crate::error::{FactumError, Result};
use crate::notes::Entry;
use crate::signer::GnupgSigner;

/// Entries per model call.
pub const ENRICH_BATCH: usize = 10;
const OUTPUT_RESERVE: usize = 800;
const TIMEOUT: Duration = Duration::from_secs(180);
const MAX_KEYWORDS: usize = 8;
/// The window assumed when the endpoint does not report one.
const DEFAULT_CONTEXT_WINDOW: u32 = 16_000;

fn db_error(e: FactumError) -> LlmError {
    LlmError::BadResponse(format!("case database: {e}"))
}

/// Enriches the entries in batches of `ENRICH_BATCH`; returns how many got an enrichment. Entries the model skips
/// or answers with an importance outside 1..=10 stay unenriched; a failed call aborts the remaining batches.
pub fn enrich(
    case_db: &Db,
    cdb: &CompanionDb,
    client: &Client,
    case_id: i64,
    entry_ids: &[i64],
) -> std::result::Result<usize, LlmError> {
    let signer = GnupgSigner::without_key(None);
    let factum = Factum::new(case_db, &signer);
    let mut by_id: HashMap<i64, Entry> = factum
        .load_entries(case_id)
        .map_err(db_error)?
        .into_iter()
        .map(|entry| (entry.id, entry))
        .collect();
    let system = enrich_instruction();
    let window = client.settings().context_window.unwrap_or(DEFAULT_CONTEXT_WINDOW);
    let room = budget(window, OUTPUT_RESERVE).saturating_sub(estimate_tokens(&system, TextKind::Prose));

    let mut batches: Vec<Vec<(Entry, String)>> = Vec::new();
    for chunk in entry_ids.chunks(ENRICH_BATCH) {
        let mut batch = Vec::new();
        let mut used = 0;
        for id in chunk {
            let Some(entry) = by_id.remove(id) else { continue };
            let label = match entry.evidence_id {
                Some(evidence_id) => factum
                    .get_evidence(evidence_id)
                    .map_err(db_error)?
                    .map(|evidence| evidence.description),
                None => None,
            };
            let line = entry_line(&entry, label.as_deref());
            let tokens = estimate_tokens(&line, TextKind::Prose);
            // a batch that would overflow the window is split; a single oversized line goes alone
            if !batch.is_empty() && used + tokens > room {
                batches.push(std::mem::take(&mut batch));
                used = 0;
            }
            used += tokens;
            batch.push((entry, line));
        }
        if !batch.is_empty() {
            batches.push(batch);
        }
    }

    let mut done = 0;
    for batch in batches {
        let prompt = batch
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let response = client.chat(&ChatRequest {
            system: &system,
            turns: &[(Role::User, &prompt)],
            max_tokens: OUTPUT_RESERVE as u32,
            json: true,
            timeout: TIMEOUT,
        })?;
        let items = match parse_enrichment_output(&response.text) {
            Ok(items) => items,
            Err(reason) => {
                log::warn!("companion enrichment: unreadable reply, the batch stays unenriched: {reason}");
                continue;
            }
        };
        let requested: HashMap<i64, &Entry> = batch.iter().map(|(entry, _)| (entry.id, entry)).collect();
        let mut seen = HashSet::new();
        for (id, keywords, context, importance) in items {
            let Some(entry) = requested.get(&id) else { continue };
            if !(1..=10).contains(&importance) || !seen.insert(id) {
                continue;
            }
            let keywords: Vec<String> = keywords
                .iter()
                .map(|keyword| keyword.trim().to_string())
                .filter(|keyword| !keyword.is_empty())
                .take(MAX_KEYWORDS)
                .collect();
            let enrichment = Enrichment {
                entry_id: id,
                keywords,
                context: context.trim().to_string(),
                importance,
            };
            cdb.upsert_enrichment(case_id, entry, &enrichment).map_err(db_error)?;
            done += 1;
        }
    }
    Ok(done)
}

/// Gives every newest-version entry without an index row one (its stored text only), so that retrieval works before
/// enrichment, and drops the rows of superseded versions. Returns the number of rows added.
pub fn index_unindexed(case_db: &Db, cdb: &CompanionDb, case_id: i64) -> Result<usize> {
    let signer = GnupgSigner::without_key(None);
    let entries = Factum::new(case_db, &signer).load_entries(case_id)?;
    let superseded: HashSet<i64> = entries.iter().filter_map(|entry| entry.corrects_id).collect();
    let indexed = cdb.indexed_entry_ids(case_id)?;
    let mut added = 0;
    for entry in &entries {
        if superseded.contains(&entry.id) {
            if indexed.contains(&entry.id) {
                cdb.remove_entry_index(entry.id)?;
            }
        } else if !indexed.contains(&entry.id) {
            cdb.index_entry(case_id, entry, &[], "")?;
            added += 1;
        }
    }
    Ok(added)
}
