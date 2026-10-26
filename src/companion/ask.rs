//! Ask: one question over the case log, answered by the model from retrieved entries only, with numbered
//! references and a mechanical check for paths, hashes, numbers and commands the excerpts do not contain.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::enrich::index_unindexed;
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

/// Asks one question. The answer is not stored. Indexes entries not yet indexed first; without any excerpt the answer
/// is an abstention and no model is called.
pub fn ask(
    case_db: &Db,
    cdb: &CompanionDb,
    client: &Client,
    case_id: i64,
    question: &str,
) -> Result<Answer, PassError> {
    index_unindexed(case_db, cdb, case_id)?;
    let data = load_case(case_db, case_id)?;
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

    let system = ask_system();
    let room = budget(client.window(), OUTPUT_RESERVE);
    // the system prompt and the question are sent as well
    let mut used = estimate_tokens(&system, TextKind::Prose) + estimate_tokens(&prompt(question, &[]), TextKind::Prose);
    let mut excerpts: Vec<String> = Vec::new();
    let mut ids: Vec<i64> = Vec::new();
    for entry in ranked {
        let label = entry.evidence_id.and_then(|id| labels.get(&id).copied());
        let line = format!("[{}] {}", excerpts.len() + 1, entry_line(entry, label));
        used += estimate_tokens(&line, TextKind::Dense) + estimate_tokens(SEPARATOR, TextKind::Prose);
        if used > room {
            break;
        }
        excerpts.push(line);
        ids.push(entry.id);
    }

    if excerpts.is_empty() {
        return Ok(Answer {
            text: ABSTAIN_PREFIX.to_string(),
            references: Vec::new(),
            unsupported: Vec::new(),
            abstained: true,
        });
    }

    let prompt = prompt(question, &excerpts);
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

fn prompt(question: &str, excerpts: &[String]) -> String {
    format!("Question: {question}\n\nExcerpts:\n\n{}", excerpts.join(SEPARATOR))
}

/// Most numbers a range such as `[2-5]` expands to.
const MAX_RANGE: usize = 50;

/// The numbers of one part of a reference bracket: `3`, or a range `2-5` (also with an en dash).
fn reference_numbers(part: &str) -> Option<Vec<usize>> {
    let number = |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<usize>().ok())?;
    match part.split_once(['-', '–']) {
        None => Some(vec![number(part)?]),
        Some((from, to)) => {
            let (from, to) = (number(from)?, number(to)?);
            (from <= to && to - from < MAX_RANGE).then(|| (from..=to).collect())
        }
    }
}

/// Every `[n]` of the text whose `n` names an excerpt (1-based into `ids`), once, in order of first appearance.
/// Also `[1, 2]`, `[1,2]` and ranges such as `[2-4]`; a bracket with anything else inside (a word) is no reference.
fn references(text: &str, ids: &[i64]) -> Vec<(usize, i64)> {
    let mut found: Vec<(usize, i64)> = Vec::new();
    for (open, _) in text.match_indices('[') {
        let rest = &text[open + 1..];
        let Some(close) = rest.find(']') else { continue };
        let parts: Option<Vec<Vec<usize>>> = rest[..close]
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|part| !part.is_empty())
            .map(reference_numbers)
            .collect();
        let Some(parts) = parts.filter(|parts| !parts.is_empty()) else {
            continue;
        };
        for n in parts.into_iter().flatten() {
            if let Some(&id) = n.checked_sub(1).and_then(|i| ids.get(i))
                && !found.iter().any(|&(seen, _)| seen == n)
            {
                found.push((n, id));
            }
        }
    }
    found
}

/// The haystack contains the literal as a whole: not as a part of a longer word or number.
fn contains_whole(haystack: &str, literal: &str) -> bool {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    haystack.match_indices(literal).any(|(at, _)| {
        let before = haystack[..at].chars().next_back();
        let after = haystack[at + literal.len()..].chars().next();
        // a literal that starts or ends with a word character must not continue a word there
        !(word(literal.chars().next()) && word(before)) && !(word(literal.chars().next_back()) && word(after))
    })
}

/// Paths, hashes (hex, 32 or more characters, also after a prefix such as `md5:`), IPv4 addresses, numbers (four or
/// more digits in a row) and commands (backticked spans on one line, and the lines of fenced code blocks) of the
/// answer that occur in none of the excerpts as a whole (case-insensitive), in order of first appearance.
pub fn unsupported_literals(answer: &str, excerpts: &[String]) -> Vec<String> {
    const PUNCTUATION: &[char] = &['.', ',', ';', ':', '(', ')', '[', ']', '"', '\'', '!', '?'];
    let haystack = excerpts.join("\n").to_lowercase();
    let mut found: Vec<String> = Vec::new();
    let mut check = |literal: &str| {
        if !contains_whole(&haystack, &literal.to_lowercase()) && !found.iter().any(|f| f == literal) {
            found.push(literal.to_string());
        }
    };
    let mut fenced = false;
    for line in answer.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            if !line.trim().is_empty() {
                check(line.trim());
            }
            continue;
        }
        // a stray backtick spoils only its own line: inline spans do not cross lines
        let segments: Vec<&str> = line.split('`').collect();
        for (i, segment) in segments.iter().enumerate() {
            if i % 2 == 1 && i + 1 < segments.len() {
                let command = segment.trim();
                if !command.is_empty() {
                    check(command);
                }
                continue;
            }
            for token in segment.split_whitespace() {
                let token = token.trim_matches(PUNCTUATION);
                // `md5:<hash>`, `sha256=<hash>`: the hash alone
                let prefixed = token
                    .split_once([':', '='])
                    .map(|(_, value)| value.trim_matches(PUNCTUATION))
                    .filter(|value| is_hash(value));
                if let Some(hash) = prefixed {
                    check(hash);
                } else if is_literal(token) {
                    check(token);
                }
            }
        }
    }
    found
}

fn is_hash(token: &str) -> bool {
    token.len() >= 32 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// A path: rooted (`/`, `\`, `~/`, `./`, a drive such as `C:\`), or with a separator and a digit, a dot or a second
/// separator in it. Words joined by one slash (`and/or`, `TCP/IP`) are prose.
fn is_path(token: &str) -> bool {
    if !token.contains(['/', '\\']) {
        return false;
    }
    let rooted = token.starts_with(['/', '\\', '~', '.'])
        || token
            .as_bytes()
            .get(1..3)
            .is_some_and(|b| b[0] == b':' && (b[1] == b'\\' || b[1] == b'/'));
    let separators = token.matches(['/', '\\']).count();
    rooted || separators >= 2 || token.contains(|c: char| c == '.' || c.is_ascii_digit())
}

/// A path, a hash, an IPv4 address or a number.
fn is_literal(token: &str) -> bool {
    let number = token
        .as_bytes()
        .split(|b| !b.is_ascii_digit())
        .any(|digits| digits.len() >= 4);
    is_path(token) || is_hash(token) || is_ipv4(token) || number
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_not_in_excerpts_are_flagged() {
        let u = unsupported_literals(
            "See /etc/vz/conf and md5 0123456789abcdef0123456789abcdef and port 8080, run `vzctl enter 101`.",
            &["found /etc/vz/conf".into()],
        );
        assert_eq!(u, vec!["0123456789abcdef0123456789abcdef", "8080", "vzctl enter 101"]);
    }

    #[test]
    fn literal_rules() {
        let excerpts = ["login from 10.0.0.5 on port 18080, md5 0123456789abcdef0123456789abcdef".to_string()];
        let u = unsupported_literals(
            "From 10.0.0.5 and/or 10.0.0.6 (TCP/IP) on port 8080, md5:0123456789abcdef0123456789abcdef, \
             sha256=ffffffffffffffffffffffffffffffff.",
            &excerpts,
        );
        // 8080 is only part of 18080
        assert_eq!(u, vec!["10.0.0.6", "8080", "ffffffffffffffffffffffffffffffff"]);
        assert!(unsupported_literals("see /etc/vz", &["found /etc/vz/conf".into()]).is_empty());
    }

    #[test]
    fn a_stray_backtick_spoils_only_its_line() {
        let u = unsupported_literals(
            "The file `a.txt is odd.\nRun `ls -l` then:\n```\nvzctl enter 101\n```\nDone.",
            &["ls -l".into()],
        );
        assert_eq!(u, vec!["vzctl enter 101"]);
    }

    #[test]
    fn references_take_lists_and_ranges() {
        let ids = [10, 11, 12, 13];
        assert_eq!(
            references("See [1, 2-3] and [4].", &ids),
            vec![(1, 10), (2, 11), (3, 12), (4, 13)]
        );
        assert_eq!(references("[see 1] [9] [3-1]", &ids), vec![]);
    }
}
