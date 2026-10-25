//! Ask: one question over the case log, answered by the model from retrieved entries only, with numbered
//! references and a mechanical check for paths, hashes, numbers and commands the excerpts do not contain.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::llm::{ChatRequest, Client, Role};
use super::prompts::{ABSTAIN_PREFIX, ask_system, entry_line};
use super::reflect::{PassError, load_case};
use super::retrieval::{RetrievalQuery, retrieve};
use super::store::CompanionDb;
use super::tokens::{TextKind, budget, estimate_tokens};
use crate::db::Db;
use crate::notes::Entry;

const OUTPUT_RESERVE: usize = 1000;
const TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_CONTEXT_WINDOW: u32 = 16_000;
/// Entries retrieved for the question, besides the pinned ones.
const K: usize = 8;
const SEPARATOR: &str = "\n\n---\n\n";

/// A model answer with the entries it cites and the literals the excerpts do not support.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub text: String,
    /// `(n, entry id)` for every `[n]` in the text that names an excerpt, in order of first appearance
    pub references: Vec<(usize, i64)>,
    /// paths, hashes, numbers and commands of the text that occur in no excerpt
    pub unsupported: Vec<String>,
    pub abstained: bool,
}

/// Asks one question. The answer is not stored. Reads what exists: entries that were never indexed are not found.
pub fn ask(
    case_db: &Db,
    cdb: &CompanionDb,
    client: &Client,
    case_id: i64,
    question: &str,
) -> Result<Answer, PassError> {
    let data = load_case(case_db, case_id)?;
    cdb.ensure_case(case_id)?;
    let importance = cdb.importance_map(case_id)?;
    let newest_created_utc = data.entries.last().map_or("", |e| e.created_utc.as_str());
    let hits = retrieve(
        cdb,
        &importance,
        &data.created,
        &RetrievalQuery {
            case_id,
            text: question,
            exclude: &HashSet::new(),
            k: K,
            newest_created_utc,
        },
    )?;
    let by_id: HashMap<i64, &Entry> = data.entries.iter().map(|e| (e.id, e)).collect();
    let labels: HashMap<i64, &str> = data
        .evidence
        .iter()
        .map(|item| (item.id, item.description.as_str()))
        .collect();
    // pinned notes first, then the hits by rank
    let mut seen = HashSet::new();
    let ranked: Vec<&Entry> = data
        .entries
        .iter()
        .filter(|e| e.is_pinned)
        .chain(hits.iter().filter_map(|hit| by_id.get(&hit.entry_id).copied()))
        .filter(|e| seen.insert(e.id))
        .collect();

    let window = client
        .settings()
        .context_window
        .or(client.context_window())
        .unwrap_or(DEFAULT_CONTEXT_WINDOW);
    let room = budget(window, OUTPUT_RESERVE);
    let mut used = 0;
    let mut excerpts: Vec<String> = Vec::new();
    let mut ids: Vec<i64> = Vec::new();
    for entry in ranked {
        let label = entry.evidence_id.and_then(|id| labels.get(&id).copied());
        let line = format!("[{}] {}", excerpts.len() + 1, entry_line(entry, label));
        used += estimate_tokens(&line, TextKind::Dense);
        if used > room {
            break;
        }
        excerpts.push(line);
        ids.push(entry.id);
    }

    let prompt = format!("Question: {question}\n\nExcerpts:\n\n{}", excerpts.join(SEPARATOR));
    let system = ask_system();
    let response = client.chat(&ChatRequest {
        system: &system,
        turns: &[(Role::User, &prompt)],
        max_tokens: OUTPUT_RESERVE as u32,
        json: false,
        timeout: TIMEOUT,
    })?;
    let text = response.text.trim().to_string();
    let references = references(&text, &ids);
    let unsupported = unsupported_literals(&text, &excerpts);
    let abstained = text.starts_with(ABSTAIN_PREFIX);
    Ok(Answer {
        text,
        references,
        unsupported,
        abstained,
    })
}

/// Every `[n]` of the text whose `n` names an excerpt (1-based into `ids`), once, in order of first appearance.
fn references(text: &str, ids: &[i64]) -> Vec<(usize, i64)> {
    let mut found: Vec<(usize, i64)> = Vec::new();
    for (open, _) in text.match_indices('[') {
        let rest = &text[open + 1..];
        let Some(close) = rest.find(']') else { continue };
        let digits = &rest[..close];
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(n) = digits.parse::<usize>() else { continue };
        if let Some(&id) = n.checked_sub(1).and_then(|i| ids.get(i))
            && !found.iter().any(|&(seen, _)| seen == n)
        {
            found.push((n, id));
        }
    }
    found
}

/// Paths (`/` or `\`), hashes (hex, 32 or more characters), numbers (four or more digits in a row) and backticked
/// commands of the answer that occur in none of the excerpts (case-insensitive), in order of first appearance.
pub fn unsupported_literals(answer: &str, excerpts: &[String]) -> Vec<String> {
    const PUNCTUATION: &[char] = &['.', ',', ';', ':', '(', ')', '[', ']', '"', '\''];
    let haystack = excerpts.join("\n").to_lowercase();
    let mut found: Vec<String> = Vec::new();
    for token in answer.split_whitespace() {
        let token = token.trim_matches(PUNCTUATION);
        let command = token.len() > 2 && token.starts_with('`') && token.ends_with('`');
        let core = token.trim_matches('`').trim_matches(PUNCTUATION);
        if core.is_empty() || !(command || is_literal(core)) {
            continue;
        }
        if !haystack.contains(&core.to_lowercase()) && !found.iter().any(|f| f == core) {
            found.push(core.to_string());
        }
    }
    found
}

/// A path, a hash or a number.
fn is_literal(token: &str) -> bool {
    let path = token.contains(['/', '\\']);
    let hash = token.len() >= 32 && token.bytes().all(|b| b.is_ascii_hexdigit());
    let number = token
        .as_bytes()
        .split(|b| !b.is_ascii_digit())
        .any(|digits| digits.len() >= 4);
    path || hash || number
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_not_in_excerpts_are_flagged() {
        let u = unsupported_literals(
            "See /etc/vz/conf and md5 0123456789abcdef0123456789abcdef and port 8080",
            &["found /etc/vz/conf".into()],
        );
        assert_eq!(u, vec!["0123456789abcdef0123456789abcdef", "8080"]);
    }
}
