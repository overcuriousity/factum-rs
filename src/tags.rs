//! Tags parsed from note text (source 'text', covered by the note's hash) and labels added by hand
//! (source 'label', not signed).

use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{Connection, params};

use crate::db::{Db, ensure_entry_case_open};
use crate::error::Result;

static TAG_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#(\w+)").unwrap()); // words prefixed with #

pub const SOURCE_TEXT: &str = "text";
pub const SOURCE_LABEL: &str = "label";

// add_tag, map_tag and parse_tags_from_note do not commit on their own; the calling operation owns the transaction
pub fn add_tag(conn: &Connection, tag_text: &str) -> Result<i64> {
    // tag texts are unique, an existing tag is reused
    conn.execute(
        "INSERT INTO tags (tag_text) VALUES (?) ON CONFLICT(tag_text) DO NOTHING",
        [tag_text],
    )?;
    Ok(conn.query_row("SELECT id FROM tags WHERE tag_text = ?", [tag_text], |row| row.get(0))?)
}

pub fn map_tag(conn: &Connection, entry_id: i64, tag_id: i64, source: &str) -> Result<usize> {
    // a tag already on the entry keeps its source, so a label never replaces a text tag
    Ok(conn.execute(
        "INSERT OR IGNORE INTO entry_tag_map (entry_id, tag_id, source) VALUES (?, ?, ?)",
        params![entry_id, tag_id, source],
    )?)
}

pub fn parse_tags(text: &str) -> Vec<&str> {
    TAG_PATTERN
        .captures_iter(text)
        .map(|c| c.get(1).unwrap().as_str())
        .collect()
}

pub fn parse_tags_from_note(conn: &Connection, entry_id: i64, note_text: &str) -> Result<Vec<i64>> {
    let mut tag_ids = Vec::new();
    for tag in parse_tags(note_text) {
        let tag_id = add_tag(conn, tag)?;
        if !tag_ids.contains(&tag_id) {
            map_tag(conn, entry_id, tag_id, SOURCE_TEXT)?;
            tag_ids.push(tag_id);
        }
    }
    log::debug!("Parsed and mapped {} tags from entry ID: {entry_id}", tag_ids.len());
    Ok(tag_ids)
}

/// (tag, source) of an entry: text tags first ('text' sorts after 'label'), then alphabetically
pub fn get_tags_for_entry(conn: &Connection, entry_id: i64) -> Result<Vec<(String, String)>> {
    let mut statement = conn.prepare_cached(
        "SELECT t.tag_text, m.source FROM tags t JOIN entry_tag_map m ON t.id = m.tag_id \
         WHERE m.entry_id = ? ORDER BY m.source DESC, t.tag_text",
    )?;
    let rows = statement.query_map([entry_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn clean_label(label: &str) -> &str {
    crate::pystr::strip(label).trim_start_matches('#')
}

pub fn add_label(db: &Db, entry_id: i64, label: &str) -> Result<usize> {
    let label = clean_label(label);
    if label.is_empty() {
        return Ok(0);
    }
    db.transaction(|conn| {
        ensure_entry_case_open(conn, entry_id)?;
        map_tag(conn, entry_id, add_tag(conn, label)?, SOURCE_LABEL)
    })
    .inspect_err(|e| log::error!("Failed to add label '{label}' to entry {entry_id}: {e}"))
}

pub fn remove_label(db: &Db, entry_id: i64, label: &str) -> Result<usize> {
    let label = clean_label(label);
    db.transaction(|conn| {
        ensure_entry_case_open(conn, entry_id)?;
        let removed = conn.execute(
            "DELETE FROM entry_tag_map WHERE entry_id = ? AND source = 'label' \
             AND tag_id IN (SELECT id FROM tags WHERE tag_text = ?)",
            params![entry_id, label],
        )?;
        remove_orphaned_tags(conn)?;
        Ok(removed)
    })
    .inspect_err(|e| log::error!("Failed to remove label '{label}' from entry {entry_id}: {e}"))
}

/// Every tag and label in use, with the number of entries that carry it; the most used first.
pub fn tag_counts(conn: &Connection) -> Result<Vec<(String, usize)>> {
    let mut statement = conn.prepare(
        "SELECT t.tag_text, COUNT(*) FROM tags t JOIN entry_tag_map m ON t.id = m.tag_id \
         GROUP BY t.id ORDER BY COUNT(*) DESC, t.tag_text",
    )?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? as usize)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Edits (insert, delete, substitute, swap two neighbours) that turn `a` into `b`: the optimal string alignment
/// distance, so a swapped pair of letters is one typo, not two.
fn edit_distance(a: &[char], b: &[char]) -> usize {
    let mut rows = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in rows.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in rows[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (rows[i - 1][j] + 1)
                .min(rows[i][j - 1] + 1)
                .min(rows[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(rows[i - 2][j - 2] + 1);
            }
            rows[i][j] = best;
        }
    }
    rows[a.len()][b.len()]
}

/// How a suggestion matches what was typed, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    Exact,
    Prefix,
    /// contains the typed text at this character position
    Substring(usize),
    /// this many typos away, from the whole name or its beginning
    Typo(usize),
}

/// The known tags and labels to offer for `typed` (case is ignored), at most `limit`: exact, then those starting
/// with it, then those containing it, then those a typo or two away, as a whole or at their beginning (one typo for
/// 3 to 5 characters, two from 6); within each, the most used first. Nothing typed: the most used.
pub fn suggest<'a>(typed: &str, known: &'a [(String, usize)], limit: usize) -> Vec<(&'a str, usize, Match)> {
    let query: Vec<char> = clean_label(typed).to_lowercase().chars().collect();
    let typos = match query.len() {
        0..=2 => 0,
        3..=5 => 1,
        _ => 2,
    };
    let mut found: Vec<(&str, usize, Match)> = known
        .iter()
        .filter_map(|(name, count)| {
            let lower = name.to_lowercase();
            let chars: Vec<char> = lower.chars().collect();
            let query_text: String = query.iter().collect();
            let matched = if query.is_empty() {
                Match::Prefix
            } else if chars == query {
                Match::Exact
            } else if lower.starts_with(&query_text) {
                Match::Prefix
            } else if let Some(byte) = lower.find(&query_text) {
                Match::Substring(lower[..byte].chars().count())
            } else {
                // the whole name, or a beginning of it about as long as what was typed (a typo may drop or add
                // a letter)
                let lengths = query.len().saturating_sub(typos)..=(query.len() + typos).min(chars.len());
                let start = lengths
                    .map(|n| edit_distance(&query, &chars[..n]))
                    .min()
                    .unwrap_or(usize::MAX);
                let distance = edit_distance(&query, &chars).min(start);
                if typos == 0 || distance > typos {
                    return None;
                }
                Match::Typo(distance)
            };
            Some((name.as_str(), *count, matched))
        })
        .collect();
    // the class decides, not the position of a substring; then use, then the name
    let class = |m: &Match| match m {
        Match::Substring(_) => Match::Substring(0),
        other => *other,
    };
    found.sort_by(|a, b| class(&a.2).cmp(&class(&b.2)).then(b.1.cmp(&a.1)).then(a.0.cmp(b.0)));
    found.truncate(limit);
    found
}

pub fn remove_orphaned_tags(conn: &Connection) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM tags WHERE id NOT IN (SELECT tag_id FROM entry_tag_map)",
        [],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names<'a>(found: &[(&'a str, usize, Match)]) -> Vec<&'a str> {
        found.iter().map(|(name, _, _)| *name).collect()
    }

    #[test]
    fn suggestions_rank_prefix_substring_then_typos() {
        let known: Vec<(String, usize)> = [
            ("malware", 5),
            ("review", 2),
            ("antimalware", 9),
            ("Malta", 1),
            ("reviewed", 1),
            ("ioc", 3),
        ]
        .into_iter()
        .map(|(name, count)| (name.to_string(), count))
        .collect();
        // nothing typed: the most used
        assert_eq!(names(&suggest("", &known, 3)), ["antimalware", "malware", "ioc"]);
        // prefix before substring, case ignored, a leading # too
        assert_eq!(names(&suggest("#MAL", &known, 10)), ["malware", "Malta", "antimalware"]);
        assert_eq!(suggest("review", &known, 10)[0].2, Match::Exact);
        assert_eq!(names(&suggest("review", &known, 10)), ["review", "reviewed"]);
        // a swapped pair and a missing letter are one typo each
        assert_eq!(names(&suggest("mlaware", &known, 10))[0], "malware");
        assert_eq!(suggest("mlaware", &known, 10)[0].2, Match::Typo(1));
        assert_eq!(names(&suggest("revew", &known, 10)), ["review", "reviewed"]);
        // the beginning of a longer name counts: "rveiew" is one swap from "review", the start of "reviewed"
        assert_eq!(names(&suggest("rveiew", &known, 10)), ["review", "reviewed"]);
        // a swap and a dropped letter are two typos: too many for five letters
        assert!(suggest("rveiw", &known, 10).is_empty());
        // two letters are too few for typos
        assert!(suggest("xo", &known, 10).is_empty());
        // within substring matches the most used comes first; the position is kept for highlighting
        let ware = suggest("ware", &known, 10);
        assert_eq!(
            ware.iter().map(|(name, _, m)| (*name, *m)).collect::<Vec<_>>(),
            [("antimalware", Match::Substring(7)), ("malware", Match::Substring(3))]
        );
    }

    #[test]
    fn edit_distance_counts_a_swap_once() {
        let d = |a: &str, b: &str| edit_distance(&a.chars().collect::<Vec<_>>(), &b.chars().collect::<Vec<_>>());
        assert_eq!(d("malware", "malware"), 0);
        assert_eq!(d("mlaware", "malware"), 1);
        assert_eq!(d("malwre", "malware"), 1);
        assert_eq!(d("kitten", "sitting"), 3);
        assert_eq!(d("", "abc"), 3);
    }

    #[test]
    fn tags_are_unicode_words() {
        assert_eq!(
            parse_tags("found #malware and #Persistenz_ü #malware, #x-y"),
            vec!["malware", "Persistenz_ü", "malware", "x"]
        );
    }
}
