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

pub fn remove_orphaned_tags(conn: &Connection) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM tags WHERE id NOT IN (SELECT tag_id FROM entry_tag_map)",
        [],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_unicode_words() {
        assert_eq!(
            parse_tags("found #malware and #Persistenz_ü #malware, #x-y"),
            vec!["malware", "Persistenz_ü", "malware", "x"]
        );
    }
}
