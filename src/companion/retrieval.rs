//! Keyword retrieval over case entries: an FTS5 index of text plus model-written keywords, ranked with BM25.

use std::collections::{HashMap, HashSet};

use chrono::DateTime;
use rusqlite::{Connection, OptionalExtension, params};

use super::store::CompanionDb;
use crate::canonical::utc_now;
use crate::error::Result;
use crate::notes::Entry;

/// BM25 candidates taken before the boosts are applied.
const CANDIDATES: usize = 30;

/// The model's reading of one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrichment {
    pub entry_id: i64,
    pub keywords: Vec<String>,
    pub context: String,
    /// 0..=10
    pub importance: u8,
}

/// A retrieved entry with its combined score.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub entry_id: i64,
    pub score: f32,
}

pub struct RetrievalQuery<'a> {
    pub case_id: i64,
    pub text: &'a str,
    pub exclude: &'a HashSet<i64>,
    pub k: usize,
    /// the age of an entry is measured up to this timestamp
    pub newest_created_utc: &'a str,
}

/// Splits on whitespace and strips opening brackets and quotes and trailing punctuation from every token, so that
/// "found." matches "found": the tokenizer keeps `.` and `:` inside tokens. Paths and file names stay intact.
pub fn normalise_tokens(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            token
                .trim_start_matches(['(', '[', '"', '\''])
                .trim_end_matches(['.', ',', ':', ';', '!', '?', ')', ']', '"', '\''])
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The index body: text, keywords and context, normalised and separated by spaces.
fn body(text: &str, keywords: &[String], context: &str) -> String {
    [text, &keywords.join(" "), context]
        .iter()
        .map(|part| normalise_tokens(part))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Replaces the index row of the entry.
fn write_index(conn: &Connection, case_id: i64, entry: &Entry, keywords: &[String], context: &str) -> Result<()> {
    conn.execute("DELETE FROM entry_fts WHERE entry_id = ?", [entry.id])?;
    conn.execute(
        "INSERT INTO entry_fts (entry_id, case_id, body) VALUES (?, ?, ?)",
        params![entry.id, case_id, body(&entry.text, keywords, context)],
    )?;
    Ok(())
}

/// Normalises the tokens, keeps those of two or more characters and quotes each; empty when nothing is left.
pub fn fts_query(text: &str) -> String {
    normalise_tokens(text)
        .split_whitespace()
        .filter(|token| token.chars().count() >= 2)
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// The case's best matches for an FTS query: positive scores, best first.
pub fn bm25(db: &CompanionDb, case_id: i64, query: &str, limit: usize) -> Result<Vec<(i64, f32)>> {
    if query.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }
    let mut stmt = db.conn.prepare(
        "SELECT entry_id, bm25(entry_fts) AS score FROM entry_fts \
         WHERE entry_fts MATCH ?1 AND case_id = ?2 ORDER BY score LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![query, case_id, limit as i64], |row| {
        Ok((row.get::<_, i64>(0)?, -row.get::<_, f64>(1)? as f32))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// None when a timestamp does not parse.
fn age_days(created: &str, newest: &str) -> Option<f32> {
    let created = DateTime::parse_from_rfc3339(created).ok()?;
    let newest = DateTime::parse_from_rfc3339(newest).ok()?;
    Some((newest - created).num_milliseconds().max(0) as f32 / 86_400_000.0)
}

/// BM25 top candidates, normalised by the best score, with a small boost for importance and recency.
pub fn retrieve(
    db: &CompanionDb,
    importance: &HashMap<i64, u8>,
    created: &HashMap<i64, String>,
    q: &RetrievalQuery,
) -> Result<Vec<Hit>> {
    let candidates = bm25(db, q.case_id, &fts_query(q.text), CANDIDATES)?;
    let best = candidates.iter().map(|c| c.1).fold(0.0_f32, f32::max);
    let mut hits: Vec<Hit> = candidates
        .into_iter()
        .filter(|(id, _)| !q.exclude.contains(id))
        .map(|(entry_id, score)| {
            let normalised = if best > 0.0 { score / best } else { 0.0 };
            let importance = f32::from(importance.get(&entry_id).copied().unwrap_or(0)) / 10.0;
            let recency = created
                .get(&entry_id)
                .and_then(|created| age_days(created, q.newest_created_utc))
                .map_or(0.0, |age| 0.5_f32.powf(age / 30.0));
            Hit {
                entry_id,
                score: normalised + 0.05 * importance + 0.05 * recency,
            }
        })
        .collect();
    hits.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.entry_id.cmp(&b.entry_id)));
    hits.truncate(q.k);
    Ok(hits)
}

impl CompanionDb {
    /// Replaces the index row of the entry; its body is the text plus keywords and context.
    pub fn index_entry(&self, case_id: i64, entry: &Entry, keywords: &[String], context: &str) -> Result<()> {
        self.transaction(|conn| write_index(conn, case_id, entry, keywords, context))
    }

    pub fn remove_entry_index(&self, entry_id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM entry_fts WHERE entry_id = ?", [entry_id])?;
        Ok(())
    }

    /// Stores the enrichment and replaces the entry's index row (text, keywords, context) in one transaction.
    pub fn upsert_enrichment(&self, case_id: i64, entry: &Entry, e: &Enrichment) -> Result<()> {
        let keywords = serde_json::to_string(&e.keywords).expect("a list of strings serialises");
        self.transaction(|conn| {
            conn.execute(
                "INSERT INTO enrichment (case_id, entry_id, keywords, context, importance, created_utc) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(case_id, entry_id) DO UPDATE SET keywords = excluded.keywords, \
                 context = excluded.context, importance = excluded.importance, created_utc = excluded.created_utc",
                params![
                    case_id,
                    e.entry_id,
                    keywords,
                    e.context,
                    i64::from(e.importance.min(10)),
                    utc_now()
                ],
            )?;
            write_index(conn, case_id, entry, &e.keywords, &e.context)
        })
    }

    pub fn enrichment(&self, entry_id: i64) -> Result<Option<Enrichment>> {
        Ok(self
            .conn
            .query_row(
                "SELECT entry_id, keywords, context, importance FROM enrichment WHERE entry_id = ?",
                [entry_id],
                |row| {
                    let keywords: String = row.get(1)?;
                    Ok(Enrichment {
                        entry_id: row.get(0)?,
                        keywords: serde_json::from_str(&keywords).unwrap_or_default(),
                        context: row.get(2)?,
                        importance: row.get::<_, i64>(3)?.clamp(0, 10) as u8,
                    })
                },
            )
            .optional()?)
    }

    /// The ids without an enrichment row, in input order.
    pub fn unenriched(&self, case_id: i64, entry_ids: &[i64]) -> Result<Vec<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM enrichment WHERE case_id = ? AND entry_id = ?")?;
        let mut missing = Vec::new();
        for &id in entry_ids {
            if !stmt.exists(params![case_id, id])? {
                missing.push(id);
            }
        }
        Ok(missing)
    }

    pub fn importance_map(&self, case_id: i64) -> Result<HashMap<i64, u8>> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry_id, importance FROM enrichment WHERE case_id = ?")?;
        let rows = stmt.query_map([case_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?.clamp(0, 10) as u8))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::companion::CompanionDb;
    use crate::notes::Entry;

    fn temp_db() -> (tempfile::TempDir, CompanionDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = CompanionDb::open(&dir.path().join("f.companion.db")).unwrap();
        (dir, db)
    }

    fn entry(id: i64, text: &str) -> Entry {
        Entry {
            id,
            case_id: 1,
            leaf_index: id,
            kind: "note".into(),
            evidence_id: None,
            text: text.into(),
            payload_json: None,
            corrects_id: None,
            created_utc: "2026-10-01T10:00:00.000Z".into(),
            leaf_hash: String::new(),
            tree_size: id,
            root_hash: String::new(),
            signature: None,
            is_pinned: false,
            format: 1,
            late_signature: None,
        }
    }

    fn index(db: &CompanionDb, id: i64, text: &str) {
        db.index_entry(1, &entry(id, text), &[], "").unwrap();
    }

    fn query<'a>(text: &'a str, exclude: &'a HashSet<i64>, k: usize, newest: &'a str) -> RetrievalQuery<'a> {
        RetrievalQuery {
            case_id: 1,
            text,
            exclude,
            k,
            newest_created_utc: newest,
        }
    }

    #[test]
    fn fts_query_quotes_tokens() {
        assert_eq!(
            fts_query("wp-config.php  in /var/www"),
            "\"wp-config.php\" OR \"in\" OR \"/var/www\""
        );
        assert_eq!(fts_query("a"), "");
    }

    #[test]
    fn bm25_finds_paths_and_hashes() {
        let (_dir, db) = temp_db();
        index(&db, 1, "Copied the share to /vz/private/101 on the NAS");
        index(&db, 2, "Nothing relevant about backups here");
        index(&db, 3, "Image md5 d41d8cd98f00b204e9800998ecf8427e verified");
        index(&db, 4, "Webshell found. Shell uploaded: yes");
        let by_path = bm25(&db, 1, &fts_query("/vz/private/101"), 10).unwrap();
        assert_eq!(by_path.iter().map(|h| h.0).collect::<Vec<_>>(), vec![1]);
        let by_hash = bm25(&db, 1, &fts_query("d41d8cd98f00b204e9800998ecf8427e"), 10).unwrap();
        assert_eq!(by_hash.iter().map(|h| h.0).collect::<Vec<_>>(), vec![3]);
        let by_word = bm25(&db, 1, &fts_query("found uploaded"), 10).unwrap();
        assert_eq!(by_word.iter().map(|h| h.0).collect::<Vec<_>>(), vec![4]);
    }

    #[test]
    fn bm25_scores_are_positive_and_best_first() {
        let (_dir, db) = temp_db();
        index(&db, 1, "shell");
        index(&db, 2, "shell shell shell and more words around it");
        index(&db, 3, "other words entirely");
        let hits = bm25(&db, 1, &fts_query("shell"), 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.1 > 0.0));
        assert!(hits[0].1 >= hits[1].1);
    }

    #[test]
    fn retrieve_uses_bm25_and_excludes() {
        let (_dir, db) = temp_db();
        index(&db, 1, "webshell webshell webshell");
        index(&db, 2, "webshell found once");
        index(&db, 3, "webshell mentioned in a long sentence with many other words");
        let none = HashSet::new();
        let created = HashMap::new();
        let importance = HashMap::new();
        let all = retrieve(
            &db,
            &importance,
            &created,
            &query("webshell", &none, 10, "2026-10-01T10:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(all[0].entry_id, 1);
        assert_eq!(all.len(), 3);
        let exclude = HashSet::from([1]);
        let rest = retrieve(
            &db,
            &importance,
            &created,
            &query("webshell", &exclude, 1, "2026-10-01T10:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(rest.len(), 1);
        assert_ne!(rest[0].entry_id, 1);
        assert_eq!(rest[0].entry_id, all[1].entry_id);
    }

    #[test]
    fn retrieve_matches_english_query_against_german_note_via_keywords() {
        let (_dir, db) = temp_db();
        let keywords: Vec<String> = ["webshell", "uploads", "web shell", "upload directory"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        db.index_entry(1, &entry(1, "Webshell in uploads gefunden"), &keywords, "")
            .unwrap();
        index(&db, 2, "Backup gelaufen");
        let none = HashSet::new();
        let hits = retrieve(
            &db,
            &HashMap::new(),
            &HashMap::new(),
            &query("web shell upload directory", &none, 5, "2026-10-01T10:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(hits.first().map(|h| h.entry_id), Some(1));
    }

    #[test]
    fn retrieve_recency_and_importance_break_ties() {
        let (_dir, db) = temp_db();
        index(&db, 1, "same text about the shell");
        index(&db, 2, "same text about the shell");
        let importance = HashMap::from([(1, 0u8), (2, 9u8)]);
        let created = HashMap::from([
            (1, "2026-06-01T10:00:00.000Z".to_string()),
            (2, "2026-10-01T10:00:00.000Z".to_string()),
        ]);
        let none = HashSet::new();
        let hits = retrieve(
            &db,
            &importance,
            &created,
            &query("shell", &none, 2, "2026-10-01T10:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(hits.iter().map(|h| h.entry_id).collect::<Vec<_>>(), vec![2, 1]);
    }

    #[test]
    fn correction_replaces_index_row() {
        let (_dir, db) = temp_db();
        index(&db, 1, "the uploaded shell is in /var/www");
        db.remove_entry_index(1).unwrap();
        index(&db, 2, "the uploaded shell is in /var/www");
        let hits = bm25(&db, 1, &fts_query("/var/www"), 10).unwrap();
        assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn unenriched_and_importance_map() {
        let (_dir, db) = temp_db();
        index(&db, 1, "first");
        index(&db, 2, "second");
        db.upsert_enrichment(
            1,
            &entry(1, "first"),
            &Enrichment {
                entry_id: 1,
                keywords: vec!["alpha".into()],
                context: "ctx".into(),
                importance: 7,
            },
        )
        .unwrap();
        assert_eq!(db.unenriched(1, &[1, 2]).unwrap(), vec![2]);
        assert_eq!(db.importance_map(1).unwrap()[&1], 7);
        assert_eq!(db.enrichment(1).unwrap().unwrap().keywords, vec!["alpha".to_string()]);
        assert_eq!(
            bm25(&db, 1, &fts_query("alpha"), 10).unwrap().len(),
            1,
            "upsert re-indexes"
        );
    }
}
