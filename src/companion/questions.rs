use rusqlite::{Connection, OptionalExtension, Row, params};

use super::store::CompanionDb;
use crate::canonical::utc_now;
use crate::error::{FactumError, Result};

/// The kind of question, after the shape of the analytical gap it points at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Archetype {
    Coverage,
    Corroborate,
    Document,
    Integrity,
    Repeatability,
    Causality,
    Phase,
}

impl Archetype {
    pub const ALL: [Archetype; 7] = [
        Archetype::Coverage,
        Archetype::Corroborate,
        Archetype::Document,
        Archetype::Integrity,
        Archetype::Repeatability,
        Archetype::Causality,
        Archetype::Phase,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Archetype::Coverage => "coverage",
            Archetype::Corroborate => "corroborate",
            Archetype::Document => "document",
            Archetype::Integrity => "integrity",
            Archetype::Repeatability => "repeatability",
            Archetype::Causality => "causality",
            Archetype::Phase => "phase",
        }
    }

    /// Unknown names (a model may invent one) count as coverage.
    pub fn parse(s: &str) -> Archetype {
        let s = s.trim();
        Self::ALL
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(s))
            .unwrap_or(Archetype::Coverage)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuestionState {
    Open,
    Answered,
    Withdrawn,
    Rejected,
}

impl QuestionState {
    pub fn as_str(self) -> &'static str {
        match self {
            QuestionState::Open => "open",
            QuestionState::Answered => "answered",
            QuestionState::Withdrawn => "withdrawn",
            QuestionState::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> QuestionState {
        match s {
            "answered" => QuestionState::Answered,
            "withdrawn" => QuestionState::Withdrawn,
            "rejected" => QuestionState::Rejected,
            _ => QuestionState::Open,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rating {
    None,
    Plus,
    Minus,
}

impl Rating {
    pub fn as_str(self) -> &'static str {
        match self {
            Rating::None => "none",
            Rating::Plus => "plus",
            Rating::Minus => "minus",
        }
    }

    pub fn parse(s: &str) -> Rating {
        match s {
            "plus" => Rating::Plus,
            "minus" => Rating::Minus,
            _ => Rating::None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Question {
    pub id: i64,
    pub case_id: i64,
    pub text: String,
    pub archetype: Archetype,
    pub state: QuestionState,
    pub rating: Rating,
    pub created_pass_id: Option<i64>,
    pub resolved_pass_id: Option<i64>,
    pub resolved_entry_id: Option<i64>,
    pub position: i64,
    pub created_utc: String,
    pub resolved_utc: Option<String>,
    /// entries the question was derived from
    pub rests_on: Vec<i64>,
}

pub struct NewQuestion {
    pub text: String,
    pub archetype: Archetype,
    pub rests_on: Vec<i64>,
}

/// One step in a question's history; kinds: created, linked, unlinked, withdrawn, plus, minus, restored.
#[derive(Clone, Debug, PartialEq)]
pub struct QuestionEvent {
    pub id: i64,
    pub question_id: i64,
    pub kind: String,
    pub pass_id: Option<i64>,
    pub entry_id: Option<i64>,
    pub created_utc: String,
}

/// A rated question, kept across cases as an example for later prompts.
#[derive(Clone, Debug, PartialEq)]
pub struct RatedExample {
    pub id: i64,
    pub text: String,
    pub rating: Rating,
    pub archetype: Archetype,
    pub source_case_id: i64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PassKind {
    Diff,
    Full,
}

impl PassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PassKind::Diff => "diff",
            PassKind::Full => "full",
        }
    }
}

const QUESTION_COLUMNS: &str = "id, case_id, text, archetype, state, rating, created_pass_id, resolved_pass_id, \
     resolved_entry_id, position, created_utc, resolved_utc";

fn question_from_row(row: &Row) -> rusqlite::Result<Question> {
    Ok(Question {
        id: row.get(0)?,
        case_id: row.get(1)?,
        text: row.get(2)?,
        archetype: Archetype::parse(&row.get::<_, String>(3)?),
        state: QuestionState::parse(&row.get::<_, String>(4)?),
        rating: Rating::parse(&row.get::<_, String>(5)?),
        created_pass_id: row.get(6)?,
        resolved_pass_id: row.get(7)?,
        resolved_entry_id: row.get(8)?,
        position: row.get(9)?,
        created_utc: row.get(10)?,
        resolved_utc: row.get(11)?,
        rests_on: Vec::new(),
    })
}

fn add_event(
    conn: &Connection,
    question_id: i64,
    kind: &str,
    pass_id: Option<i64>,
    entry_id: Option<i64>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO question_events (question_id, kind, pass_id, entry_id, created_utc) VALUES (?, ?, ?, ?, ?)",
        params![question_id, kind, pass_id, entry_id, utc_now()],
    )?;
    Ok(())
}

/// The question's state, or an error when it does not exist.
fn state_of(conn: &Connection, id: i64) -> Result<QuestionState> {
    let state: Option<String> = conn
        .query_row("SELECT state FROM questions WHERE id = ?", [id], |row| row.get(0))
        .optional()?;
    match state {
        Some(state) => Ok(QuestionState::parse(&state)),
        None => Err(FactumError::general(format!("Question {id} does not exist"))),
    }
}

/// Fails unless the question is in one of the states.
fn require_state(conn: &Connection, id: i64, allowed: &[QuestionState], action: &str) -> Result<QuestionState> {
    let state = state_of(conn, id)?;
    if allowed.contains(&state) {
        Ok(state)
    } else {
        Err(FactumError::general(format!(
            "Question {id} is {}: it cannot be {action}",
            state.as_str()
        )))
    }
}

impl CompanionDb {
    fn questions_where(&self, filter: &str, order: &str, case_id: i64) -> Result<Vec<Question>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {QUESTION_COLUMNS} FROM questions WHERE case_id = ? AND {filter} ORDER BY {order}"
        ))?;
        let mut questions = stmt
            .query_map([case_id], question_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut entries = self
            .conn
            .prepare("SELECT entry_id FROM question_entries WHERE question_id = ? ORDER BY entry_id")?;
        for q in &mut questions {
            q.rests_on = entries
                .query_map([q.id], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
        }
        Ok(questions)
    }

    /// Open questions in the order they were asked.
    pub fn open_questions(&self, case_id: i64) -> Result<Vec<Question>> {
        self.questions_where("state = 'open'", "position", case_id)
    }

    /// Answered, withdrawn and rejected questions, the most recently resolved first.
    pub fn resolved_questions(&self, case_id: i64) -> Result<Vec<Question>> {
        self.questions_where("state != 'open'", "resolved_utc DESC, id DESC", case_id)
    }

    /// Appends the question behind the case's existing ones, resolved or not.
    pub fn insert_question(&self, case_id: i64, pass_id: Option<i64>, q: &NewQuestion) -> Result<i64> {
        self.transaction(|conn| {
            let now = utc_now();
            conn.execute(
                "INSERT INTO questions (case_id, text, archetype, created_pass_id, position, created_utc) \
                 VALUES (?1, ?2, ?3, ?4, (SELECT COALESCE(MAX(position), 0) + 1 FROM questions WHERE case_id = ?1), ?5)",
                params![case_id, q.text, q.archetype.as_str(), pass_id, now],
            )?;
            let id = conn.last_insert_rowid();
            for entry_id in &q.rests_on {
                conn.execute(
                    "INSERT OR IGNORE INTO question_entries (question_id, entry_id) VALUES (?, ?)",
                    params![id, entry_id],
                )?;
            }
            add_event(conn, id, "created", pass_id, None)?;
            Ok(id)
        })
    }

    /// An open question is answered by the entry.
    pub fn answer_question(&self, id: i64, entry_id: i64, pass_id: i64) -> Result<()> {
        self.transaction(|conn| {
            require_state(conn, id, &[QuestionState::Open], "answered")?;
            conn.execute(
                "UPDATE questions SET state = 'answered', resolved_pass_id = ?, resolved_entry_id = ?, resolved_utc = ? \
                 WHERE id = ?",
                params![pass_id, entry_id, utc_now(), id],
            )?;
            add_event(conn, id, "linked", Some(pass_id), Some(entry_id))
        })
    }

    /// The companion drops an open question that no longer applies.
    pub fn withdraw_question(&self, id: i64, pass_id: i64) -> Result<()> {
        self.transaction(|conn| {
            require_state(conn, id, &[QuestionState::Open], "withdrawn")?;
            conn.execute(
                "UPDATE questions SET state = 'withdrawn', resolved_pass_id = ?, resolved_utc = ? WHERE id = ?",
                params![pass_id, utc_now(), id],
            )?;
            add_event(conn, id, "withdrawn", Some(pass_id), None)
        })
    }

    /// Rates the question. A minus rejects it. Either rating is copied to the examples and counted per archetype;
    /// changing a rating replaces the earlier copy.
    pub fn rate_question(&self, id: i64, rating: Rating) -> Result<()> {
        if rating == Rating::None {
            return Err(FactumError::general("A rating is plus or minus"));
        }
        self.transaction(|conn| {
            let (case_id, text, archetype, previous): (i64, String, String, String) = conn
                .query_row(
                    "SELECT case_id, text, archetype, rating FROM questions WHERE id = ?",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?
                .ok_or_else(|| FactumError::general(format!("Question {id} does not exist")))?;
            let previous = Rating::parse(&previous);
            if previous == rating {
                // a restored question keeps its minus: rating it again rejects it again, the example is already there
                if rating == Rating::Minus && state_of(conn, id)? == QuestionState::Open {
                    conn.execute(
                        "UPDATE questions SET state = 'rejected', resolved_utc = ? WHERE id = ?",
                        params![utc_now(), id],
                    )?;
                    add_event(conn, id, "minus", None, None)?;
                }
                return Ok(());
            }
            if previous != Rating::None {
                let column = if previous == Rating::Plus { "plus_count" } else { "minus_count" };
                conn.execute(
                    &format!("UPDATE archetype_weights SET {column} = MAX({column} - 1, 0) WHERE archetype = ?"),
                    [&archetype],
                )?;
                conn.execute(
                    "DELETE FROM rated_fts WHERE example_id IN (SELECT id FROM rated_examples WHERE source_question_id = ?)",
                    [id],
                )?;
                conn.execute("DELETE FROM rated_examples WHERE source_question_id = ?", [id])?;
            }
            let now = utc_now();
            if rating == Rating::Minus {
                conn.execute(
                    "UPDATE questions SET rating = 'minus', state = 'rejected', resolved_utc = ? WHERE id = ?",
                    params![now, id],
                )?;
            } else {
                conn.execute("UPDATE questions SET rating = 'plus' WHERE id = ?", [id])?;
            }
            conn.execute(
                "INSERT INTO rated_examples (text, rating, archetype, source_case_id, source_question_id, created_utc) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![text, rating.as_str(), archetype, case_id, id, now],
            )?;
            conn.execute(
                "INSERT INTO rated_fts (example_id, body) VALUES (?, ?)",
                params![conn.last_insert_rowid(), text],
            )?;
            let column = if rating == Rating::Plus { "plus_count" } else { "minus_count" };
            conn.execute(
                &format!(
                    "INSERT INTO archetype_weights (archetype, {column}) VALUES (?, 1) \
                     ON CONFLICT(archetype) DO UPDATE SET {column} = {column} + 1"
                ),
                [&archetype],
            )?;
            add_event(conn, id, rating.as_str(), None, None)
        })
    }

    /// The user cuts the link to the answering entry: the question is open again.
    pub fn unlink_question(&self, id: i64) -> Result<()> {
        self.transaction(|conn| {
            require_state(conn, id, &[QuestionState::Answered], "unlinked")?;
            conn.execute(
                "UPDATE questions SET state = 'open', resolved_pass_id = NULL, resolved_entry_id = NULL, \
                 resolved_utc = NULL WHERE id = ?",
                [id],
            )?;
            add_event(conn, id, "unlinked", None, None)
        })
    }

    /// A withdrawn or rejected question is open again; its rating stays.
    pub fn restore_question(&self, id: i64) -> Result<()> {
        self.transaction(|conn| {
            require_state(
                conn,
                id,
                &[QuestionState::Withdrawn, QuestionState::Rejected],
                "restored",
            )?;
            conn.execute(
                "UPDATE questions SET state = 'open', resolved_pass_id = NULL, resolved_entry_id = NULL, \
                 resolved_utc = NULL WHERE id = ?",
                [id],
            )?;
            add_event(conn, id, "restored", None, None)
        })
    }

    pub fn question_events(&self, id: i64) -> Result<Vec<QuestionEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, question_id, kind, pass_id, entry_id, created_utc FROM question_events \
             WHERE question_id = ? ORDER BY id",
        )?;
        Ok(stmt
            .query_map([id], |row| {
                Ok(QuestionEvent {
                    id: row.get(0)?,
                    question_id: row.get(1)?,
                    kind: row.get(2)?,
                    pass_id: row.get(3)?,
                    entry_id: row.get(4)?,
                    created_utc: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }

    pub fn begin_pass(&self, case_id: i64, kind: PassKind, model: &str) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO passes (case_id, kind, started_utc, model) VALUES (?, ?, ?, ?)",
            params![case_id, kind.as_str(), utc_now(), model],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Closes a pass; `status` is "ok" or "error".
    #[allow(clippy::too_many_arguments)]
    pub fn finish_pass(
        &self,
        pass_id: i64,
        status: &str,
        error: Option<&str>,
        entries_from: i64,
        entries_to: i64,
        prompt_chars: usize,
        output_chars: usize,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE passes SET finished_utc = ?, status = ?, error = ?, entries_from = ?, entries_to = ?, \
             prompt_chars = ?, output_chars = ? WHERE id = ?",
            params![
                utc_now(),
                status,
                error.unwrap_or_default(),
                entries_from,
                entries_to,
                prompt_chars as i64,
                output_chars as i64,
                pass_id
            ],
        )?;
        Ok(())
    }

    /// Passes of the case that finished with status "ok"; skipped and failed ones do not count.
    pub fn pass_count(&self, case_id: i64) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM passes WHERE case_id = ? AND status = 'ok'",
            [case_id],
            |row| row.get(0),
        )?)
    }

    /// The latest finished pass of the case: id, finished_utc, status.
    pub fn last_finished_pass(&self, case_id: i64) -> Result<Option<(i64, String, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, finished_utc, status FROM passes WHERE case_id = ? AND finished_utc IS NOT NULL \
                 ORDER BY id DESC LIMIT 1",
                [case_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?)
    }

    fn rated_examples(&self, rating: Rating, query: Option<&str>, limit: i64) -> Result<Vec<RatedExample>> {
        let sql = match query {
            Some(_) => {
                "SELECT e.id, e.text, e.rating, e.archetype, COALESCE(e.source_case_id, 0) FROM rated_fts \
                 JOIN rated_examples e ON e.id = rated_fts.example_id WHERE rated_fts MATCH ?3 AND e.rating = ?1 \
                 ORDER BY bm25(rated_fts) LIMIT ?2"
            }
            None => {
                "SELECT id, text, rating, archetype, COALESCE(source_case_id, 0) FROM rated_examples \
                 WHERE rating = ?1 ORDER BY id DESC LIMIT ?2"
            }
        };
        let mut stmt = self.conn.prepare(sql)?;
        let map = |row: &Row| {
            Ok(RatedExample {
                id: row.get(0)?,
                text: row.get(1)?,
                rating: Rating::parse(&row.get::<_, String>(2)?),
                archetype: Archetype::parse(&row.get::<_, String>(3)?),
                source_case_id: row.get(4)?,
            })
        };
        let rows = match query {
            Some(query) => stmt.query_map(params![rating.as_str(), limit, query], map)?,
            None => stmt.query_map(params![rating.as_str(), limit], map)?,
        };
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Questions the user rejected, newest first.
    pub fn minus_examples(&self) -> Result<Vec<RatedExample>> {
        self.rated_examples(Rating::Minus, None, -1)
    }

    /// Questions the user found useful, newest first.
    pub fn plus_examples(&self) -> Result<Vec<RatedExample>> {
        self.rated_examples(Rating::Plus, None, -1)
    }

    /// The `limit` examples of the rating that match the FTS query best; the newest ones when the query is empty or
    /// matches none.
    pub fn nearest_examples(&self, rating: Rating, fts_query: &str, limit: usize) -> Result<Vec<RatedExample>> {
        let limit = limit as i64;
        if !fts_query.is_empty() {
            let nearest = self.rated_examples(rating, Some(fts_query), limit)?;
            if !nearest.is_empty() {
                return Ok(nearest);
            }
        }
        self.rated_examples(rating, None, limit)
    }

    /// Per archetype: (archetype, plus ratings, minus ratings).
    pub fn archetype_weights(&self) -> Result<Vec<(Archetype, i64, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT archetype, plus_count, minus_count FROM archetype_weights ORDER BY archetype")?;
        Ok(stmt
            .query_map([], |row| {
                Ok((Archetype::parse(&row.get::<_, String>(0)?), row.get(1)?, row.get(2)?))
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile::TempDir, CompanionDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = CompanionDb::open(&dir.path().join("f.companion.db")).unwrap();
        (dir, db)
    }

    fn nq_with(text: &str, archetype: Archetype) -> NewQuestion {
        NewQuestion {
            text: text.into(),
            archetype,
            rests_on: vec![],
        }
    }

    fn nq(text: &str) -> NewQuestion {
        nq_with(text, Archetype::Coverage)
    }

    #[test]
    fn positions_are_monotonic_and_order_is_stable() {
        let (_dir, db) = temp_db();
        let a = db.insert_question(1, None, &nq("A")).unwrap();
        let b = db.insert_question(1, None, &nq("B")).unwrap();
        db.withdraw_question(a, 1).unwrap();
        let c = db.insert_question(1, None, &nq("C")).unwrap();
        let open: Vec<i64> = db.open_questions(1).unwrap().iter().map(|q| q.id).collect();
        assert_eq!(open, vec![b, c]);
        assert!(db.open_questions(1).unwrap()[1].position > db.open_questions(1).unwrap()[0].position);
    }

    #[test]
    fn minus_rejects_and_records_example_and_weight() {
        let (_dir, db) = temp_db();
        let a = db
            .insert_question(1, None, &nq_with("Which vhost?", Archetype::Phase))
            .unwrap();
        db.rate_question(a, Rating::Minus).unwrap();
        assert!(db.open_questions(1).unwrap().is_empty());
        let ex = db.minus_examples().unwrap();
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0].text, "Which vhost?");
        let w = db.archetype_weights().unwrap();
        assert!(w.contains(&(Archetype::Phase, 0, 1)));
        let kinds: Vec<String> = db.question_events(a).unwrap().into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds, vec!["created", "minus"]);
    }

    #[test]
    fn plus_keeps_open_and_answer_links() {
        let (_dir, db) = temp_db();
        let a = db.insert_question(1, None, &nq("A")).unwrap();
        db.rate_question(a, Rating::Plus).unwrap();
        assert_eq!(db.open_questions(1).unwrap().len(), 1);
        db.answer_question(a, 42, 3).unwrap();
        let r = db.resolved_questions(1).unwrap();
        assert_eq!(r[0].resolved_entry_id, Some(42));
        assert_eq!(r[0].rating, Rating::Plus);
        db.unlink_question(a).unwrap();
        assert_eq!(db.open_questions(1).unwrap().len(), 1);
    }

    #[test]
    fn restore_reopens_rejected() {
        let (_dir, db) = temp_db();
        let a = db.insert_question(1, None, &nq("A")).unwrap();
        db.rate_question(a, Rating::Minus).unwrap();
        db.restore_question(a).unwrap();
        let open = db.open_questions(1).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].rating, Rating::Minus);
        assert_eq!(open[0].state, QuestionState::Open);
        db.rate_question(a, Rating::Minus).unwrap();
        assert!(db.open_questions(1).unwrap().is_empty());
        assert_eq!(db.minus_examples().unwrap().len(), 1);
    }

    #[test]
    fn passes_are_counted_per_case() {
        let (_dir, db) = temp_db();
        let p1 = db.begin_pass(1, PassKind::Diff, "m").unwrap();
        db.begin_pass(1, PassKind::Full, "m").unwrap();
        db.begin_pass(2, PassKind::Diff, "m").unwrap();
        db.finish_pass(p1, "ok", None, 0, 9, 100, 50).unwrap();
        assert_eq!(db.pass_count(1).unwrap(), 1, "only passes finished ok count");
        let (id, _finished, status) = db.last_finished_pass(1).unwrap().unwrap();
        assert_eq!((id, status.as_str()), (p1, "ok"));
        assert_eq!(db.last_finished_pass(2).unwrap(), None);
    }

    #[test]
    fn rests_on_round_trips() {
        let (_dir, db) = temp_db();
        let q = NewQuestion {
            text: "A".into(),
            archetype: Archetype::Corroborate,
            rests_on: vec![5, 6],
        };
        db.insert_question(1, None, &q).unwrap();
        assert_eq!(db.open_questions(1).unwrap()[0].rests_on, vec![5, 6]);
    }

    #[test]
    fn archetype_parse_defaults_to_coverage() {
        assert_eq!(Archetype::parse("bogus"), Archetype::Coverage);
    }
}
