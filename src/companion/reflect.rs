//! The reflection pass: a budgeted prompt from the case, two model calls (reasoning in prose, then flat JSON),
//! mechanical validation, and the surviving changes applied to the question ledger in one transaction.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use super::enrich::{enrich, index_unindexed};
use super::llm::{ChatRequest, Client, LlmError, Role};
use super::prompts::{
    DEFAULT_GUIDELINE, archetype_hints, case_header, entry_line, example_lines, question_line, reflect_instruction,
    serialize_instruction, timeline_line,
};
use super::questions::{PassKind, Question, Rating};
use super::retrieval::{RetrievalQuery, fts_query, retrieve};
use super::store::CompanionDb;
use super::tokens::{BudgetError, CUT_MARKER, Cut, Packed, Section, TextKind, budget, pack};
use super::validate::{PassOutput, ValidationContext, parse_pass_output, validate};
use crate::Factum;
use crate::cases::Case;
use crate::db::Db;
use crate::error::{FactumError, Result};
use crate::evidence::Evidence;
use crate::notes::{Entry, EntryFilter};
use crate::signer::GnupgSigner;

/// Most questions open at once.
pub const QUESTION_CAP: usize = 7;
/// Every tenth pass of a case is a full pass.
pub const FULL_EVERY: i64 = 10;
/// A pass that resolved this many questions is followed by a full pass.
pub const FULL_AFTER_RESOLVED: usize = 3;

const OUTPUT_RESERVE: usize = 1500;
const TIMEOUT: Duration = Duration::from_secs(180);
const NO_GOAL: &str = "No case goal has been set.";
const NEW_ENTRIES: &str = "new entries";
const RELATED: &str = "related";
/// Rated examples of each kind in the prompt.
const EXAMPLES: usize = 3;
/// Related entries per new entry, per open question in a diff pass and in a full pass.
const K_NEW: usize = 5;
const K_QUESTION_DIFF: usize = 3;
const K_QUESTION_FULL: usize = 5;
/// Entries enriched before a pass, and shown verbatim in a case's first full pass; the rest are timeline lines.
const RECENT: usize = 20;
/// The last resort of a prompt that still overflows once the related entries, the examples and all new entries but
/// the oldest are cut: lines of the fixed sections are shortened to these lengths in characters.
const PINNED_SHORT: usize = 300;
const EVIDENCE_SHORT: usize = 120;
const ENTRY_SHORT: usize = 400;
const GOAL_SHORT: usize = 600;
const GUIDELINE_SHORT: usize = 1200;

/// Full when forced, on the first pass of a case and on every `FULL_EVERY`th pass.
pub fn choose_kind(cdb: &CompanionDb, case_id: i64, forced_full: bool) -> Result<PassKind> {
    let count = cdb.pass_count(case_id)?;
    Ok(if forced_full || count == 0 || (count + 1) % FULL_EVERY == 0 {
        PassKind::Full
    } else {
        PassKind::Diff
    })
}

/// What a finished pass changed.
#[derive(Clone, Debug, PartialEq)]
pub struct PassSummary {
    pub pass_id: i64,
    pub kind: PassKind,
    pub answered: usize,
    pub withdrawn: usize,
    pub created: usize,
    /// the newest entry the pass has read
    pub entries_to: i64,
    /// one reason per item validation discarded
    pub dropped: Vec<String>,
}

impl PassSummary {
    /// The next pass should be a full one.
    pub fn wants_full(&self) -> bool {
        self.answered + self.withdrawn >= FULL_AFTER_RESOLVED
    }
}

#[derive(Debug)]
pub enum PassError {
    Llm(LlmError),
    Budget(BudgetError),
    /// call two gave nothing usable; the detail is for the log
    Output(String),
    Db(FactumError),
    Archived,
    NothingNew,
}

impl PassError {
    /// The short reason plus the detail, for the pass row and the log.
    fn detail(&self) -> String {
        match self {
            PassError::Budget(e) => format!("{self}: {e}"),
            PassError::Output(reason) => format!("{self}: {reason}"),
            _ => self.to_string(),
        }
    }
}

/// The short reason shown in the status bar.
impl fmt::Display for PassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassError::Llm(e) => write!(f, "{e}"),
            PassError::Budget(_) => f.write_str("model context too small even for a shortened prompt"),
            PassError::Output(_) => f.write_str("model output unusable"),
            PassError::Db(e) => f.write_str(&e.message),
            PassError::Archived => f.write_str("case is archived"),
            PassError::NothingNew => f.write_str("nothing new"),
        }
    }
}

impl From<LlmError> for PassError {
    fn from(e: LlmError) -> Self {
        PassError::Llm(e)
    }
}

impl From<BudgetError> for PassError {
    fn from(e: BudgetError) -> Self {
        PassError::Budget(e)
    }
}

impl From<FactumError> for PassError {
    fn from(e: FactumError) -> Self {
        PassError::Db(e)
    }
}

/// The counters of the pass row.
#[derive(Default)]
struct PassLog {
    entries_from: i64,
    entries_to: i64,
    prompt_chars: usize,
    output_chars: usize,
}

/// What a pass reads from the case database.
pub(super) struct CaseData {
    case: Case,
    /// deleted items included
    pub(super) evidence: Vec<Evidence>,
    /// the newest version of every entry, system entries included, by leaf index
    pub(super) entries: Vec<Entry>,
    /// creation time of every entry id, superseded versions included
    pub(super) created: HashMap<i64, String>,
}

pub(super) fn load_case(case_db: &Db, case_id: i64) -> Result<CaseData> {
    let signer = GnupgSigner::without_key(None);
    let factum = Factum::new(case_db, &signer);
    let case = factum
        .get_case(case_id)?
        .ok_or_else(|| FactumError::case_not_found(format!("Case #{case_id} does not exist.")))?;
    let mut evidence = Vec::new();
    for id in factum.list_evidence_for_case(case_id, true)? {
        evidence.extend(factum.get_evidence(id)?);
    }
    let newest: HashSet<i64> = factum
        .list_entries(case_id, &EntryFilter::default())?
        .into_iter()
        .collect();
    // load_entries returns every version, by leaf index
    let all = factum.load_entries(case_id)?;
    let created = all.iter().map(|e| (e.id, e.created_utc.clone())).collect();
    let entries = all.into_iter().filter(|e| newest.contains(&e.id)).collect();
    Ok(CaseData {
        case,
        evidence,
        entries,
        created,
    })
}

/// Runs one pass over the case. On any error the pass row is closed as failed (skipped for an archived case or
/// nothing new) and the ledger is left as it was.
pub fn run_pass(
    case_db: &Db,
    cdb: &CompanionDb,
    client: &Client,
    case_id: i64,
    kind: PassKind,
) -> std::result::Result<PassSummary, PassError> {
    let pass_id = cdb.begin_pass(case_id, kind, &client.settings().model)?;
    let mut log = PassLog::default();
    let result = reflect(case_db, cdb, client, case_id, kind, pass_id, &mut log);
    if let Err(e) = &result {
        let status = match e {
            PassError::Archived | PassError::NothingNew => "skipped",
            _ => {
                log::warn!("companion pass {pass_id} on case {case_id} failed: {}", e.detail());
                "failed"
            }
        };
        if let Err(db) = cdb.finish_pass(
            pass_id,
            status,
            Some(&e.detail()),
            log.entries_from,
            log.entries_to,
            log.prompt_chars,
            log.output_chars,
        ) {
            log::error!("companion pass {pass_id}: the pass row could not be closed: {db}");
        }
    }
    result
}

fn reflect(
    case_db: &Db,
    cdb: &CompanionDb,
    client: &Client,
    case_id: i64,
    kind: PassKind,
    pass_id: i64,
    log: &mut PassLog,
) -> std::result::Result<PassSummary, PassError> {
    let data = load_case(case_db, case_id)?;
    if data.case.is_archived() {
        return Err(PassError::Archived);
    }
    let case_settings = cdb.ensure_case(case_id)?;
    let last_seen = case_settings.last_seen_entry_id;
    let new: Vec<&Entry> = data.entries.iter().filter(|e| e.id > last_seen).collect();
    if kind == PassKind::Diff && new.is_empty() {
        return Err(PassError::NothingNew);
    }
    log.entries_from = last_seen;
    log.entries_to = data
        .entries
        .iter()
        .map(|e| e.id)
        .max()
        .unwrap_or(last_seen)
        .max(last_seen);

    index_unindexed(case_db, cdb, case_id)?;
    let new_ids: Vec<i64> = new.iter().map(|e| e.id).collect();
    // the newest only; the thread's backlog enrichment covers the rest
    let mut unenriched = cdb.unenriched(case_id, &new_ids)?;
    unenriched.sort_unstable();
    let unenriched = unenriched.split_off(unenriched.len().saturating_sub(RECENT));
    if !unenriched.is_empty()
        && let Err(e) = enrich(case_db, cdb, client, case_id, &unenriched)
    {
        log::warn!("companion enrichment failed, the pass goes on without it: {e}");
    }

    let open = cdb.open_questions(case_id)?;
    let guideline = match client.settings().global_guideline.trim() {
        "" => DEFAULT_GUIDELINE,
        _ => client.settings().global_guideline.as_str(),
    };
    let input = PromptInput {
        cdb,
        case_id,
        kind,
        data: &data,
        guideline,
        goal: &case_settings.goal,
        last_seen,
        new: &new,
        open: &open,
    };
    let room = budget(client.window(), OUTPUT_RESERVE);
    // the calls recalibrate the client; the retry is packed at the same ratio, so it cuts nothing more
    let calibration = client.calibration();
    let packed = pack(input.sections()?, room, &calibration)?;
    log.prompt_chars = packed.text.chars().count();
    if !packed.cut.is_empty() {
        log::info!("companion pass {pass_id}: lines cut for space: {:?}", packed.cut);
    }
    if !packed.shortened.is_empty() {
        log::warn!(
            "companion pass {pass_id}: lines shortened for space: {:?}",
            packed.shortened
        );
    }
    if kind == PassKind::Diff {
        log.entries_to = covered_to(&new, &packed, last_seen);
    }

    // the packed prompt is the first user turn of both calls, so a prompt cache can serve the second
    let reasoning = client.chat(&ChatRequest {
        system: "",
        turns: &[(Role::User, &packed.text)],
        max_tokens: OUTPUT_RESERVE as u32,
        json: false,
        timeout: TIMEOUT,
    })?;
    log.output_chars += reasoning.text.chars().count();
    if reasoning.text.trim().is_empty() {
        return Err(PassError::Output("the reasoning is empty".into()));
    }
    let output = match serialize(client, &packed.text, &reasoning.text, log) {
        Err(PassError::Output(reason)) => {
            // the prompt as sent, with half of the related lines it kept; without any, a retry could not be smaller
            let mut retry = packed.sections;
            let related = retry
                .iter_mut()
                .find(|s| s.name == RELATED)
                .expect("the related section is always built");
            if related.lines.is_empty() || related.lines == [CUT_MARKER] {
                return Err(PassError::Output(format!(
                    "{reason}; no related entries to drop for a retry"
                )));
            }
            related.lines.truncate(related.lines.len() / 2);
            if related.lines.is_empty() {
                related.lines.push(CUT_MARKER.to_string());
            }
            log::warn!("companion pass {pass_id}: {reason}; retrying with half the related entries");
            let smaller = pack(retry, room, &calibration)?;
            serialize(client, &smaller.text, &reasoning.text, log)?
        }
        other => other?,
    };

    let resolved = cdb.resolved_questions(case_id)?;
    let minus = cdb.minus_examples()?;
    let existing: HashSet<i64> = data.created.keys().copied().collect();
    let new_set: HashSet<i64> = new_ids.iter().copied().filter(|&id| id <= log.entries_to).collect();
    let mut validated = validate(
        output,
        &ValidationContext {
            open: &open,
            existing_entry_ids: &existing,
            new_entry_ids: &new_set,
            entry_created: &data.created,
            resolved: &resolved,
            minus_examples: &minus,
            cap: QUESTION_CAP,
        },
    );
    let applied = cdb.transaction(|_| {
        // the investigator may have rated, restored or unlinked questions while the model was busy
        let open_now: HashMap<i64, Rating> = cdb
            .open_questions(case_id)?
            .into_iter()
            .map(|q| (q.id, q.rating))
            .collect();
        let mut applied = (0, 0, 0);
        for &(question, entry) in &validated.answered {
            if open_now.contains_key(&question) {
                cdb.answer_question(question, entry, pass_id)?;
                applied.0 += 1;
            } else {
                validated
                    .dropped
                    .push(format!("answered: question {question} is no longer open"));
            }
        }
        for &question in &validated.withdraw {
            match open_now.get(&question) {
                None => validated
                    .dropped
                    .push(format!("withdraw: question {question} is no longer open")),
                Some(Rating::Plus) => validated
                    .dropped
                    .push(format!("withdraw: question {question} is rated plus")),
                Some(_) => {
                    cdb.withdraw_question(question, pass_id)?;
                    applied.1 += 1;
                }
            }
        }
        let room = QUESTION_CAP.saturating_sub(open_now.len() - applied.0 - applied.1);
        for (i, question) in validated.new.iter().enumerate() {
            if i < room {
                cdb.insert_question(case_id, Some(pass_id), question)?;
                applied.2 += 1;
            } else {
                validated.dropped.push(format!(
                    "new: \"{}\" exceeds the cap of {QUESTION_CAP} open questions",
                    question.text
                ));
            }
        }
        cdb.set_last_seen(case_id, log.entries_to, pass_id)?;
        cdb.finish_pass(
            pass_id,
            "ok",
            None,
            log.entries_from,
            log.entries_to,
            log.prompt_chars,
            log.output_chars,
        )?;
        Ok(applied)
    })?;
    for reason in &validated.dropped {
        log::info!("companion pass {pass_id}: dropped {reason}");
    }
    let (answered, withdrawn, created) = applied;
    Ok(PassSummary {
        pass_id,
        kind,
        answered,
        withdrawn,
        created,
        entries_to: log.entries_to,
        dropped: validated.dropped,
    })
}

/// The newest entry a diff pass covers: the newest one, or, when the new entries were cut from the newest end, the
/// newest one before the first cut line (pinned ones are shown in their own section). The oldest listed entry is
/// never cut, at most shortened, so a pass always covers at least one entry and a long one cannot stall the case.
fn covered_to(new: &[&Entry], packed: &Packed, last_seen: i64) -> i64 {
    let listed: Vec<&Entry> = new.iter().copied().filter(|e| !e.is_pinned).collect();
    let dropped = packed
        .cut
        .iter()
        .find(|(name, _)| *name == NEW_ENTRIES)
        .map_or(0, |&(_, n)| n);
    let newest = new.iter().map(|e| e.id).max().unwrap_or(last_seen).max(last_seen);
    let Some(first_cut) = listed.len().checked_sub(dropped).and_then(|i| listed.get(i)) else {
        return newest;
    };
    new.iter()
        .map(|e| e.id)
        .filter(|&id| id < first_cut.id)
        .max()
        .unwrap_or(last_seen)
}

/// Call two: the reasoning back to the model, a flat JSON object out. A cut-off, empty or unreadable answer is an
/// `Output` error, which the caller retries once.
fn serialize(
    client: &Client,
    packed: &str,
    reasoning: &str,
    log: &mut PassLog,
) -> std::result::Result<PassOutput, PassError> {
    let instruction = serialize_instruction();
    let response = client.chat(&ChatRequest {
        system: "",
        turns: &[
            (Role::User, packed),
            (Role::Assistant, reasoning),
            (Role::User, &instruction),
        ],
        max_tokens: OUTPUT_RESERVE as u32,
        json: true,
        timeout: TIMEOUT,
    })?;
    log.output_chars += response.text.chars().count();
    if response.truncated {
        return Err(PassError::Output("the JSON answer was cut off".into()));
    }
    if response.text.trim().is_empty() {
        return Err(PassError::Output("the JSON answer is empty".into()));
    }
    parse_pass_output(&response.text).map_err(PassError::Output)
}

/// Everything the prompt sections are built from.
struct PromptInput<'a> {
    cdb: &'a CompanionDb,
    case_id: i64,
    kind: PassKind,
    data: &'a CaseData,
    guideline: &'a str,
    goal: &'a str,
    last_seen: i64,
    /// entries after the last pass, by leaf index
    new: &'a [&'a Entry],
    open: &'a [Question],
}

fn section(name: &'static str, lines: Vec<String>, cuts: Vec<Cut>, kind: TextKind) -> Section {
    Section {
        name,
        lines,
        cuts,
        kind,
    }
}

fn drop_lines(priority: u8, from_start: bool, keep: usize) -> Cut {
    Cut::Lines {
        priority,
        from_start,
        keep,
    }
}

fn shorten(priority: u8, max_chars: usize, from_start: bool) -> Cut {
    Cut::Shorten {
        priority,
        max_chars,
        from_start,
    }
}

impl PromptInput<'_> {
    /// The sections of spec 4.5 in order.
    fn sections(&self) -> Result<Vec<Section>> {
        let full = self.kind == PassKind::Full;
        let labels: HashMap<i64, &str> = self
            .data
            .evidence
            .iter()
            .map(|item| (item.id, item.description.as_str()))
            .collect();
        let label = |e: &Entry| e.evidence_id.and_then(|id| labels.get(&id).copied());
        let new_ids: HashSet<i64> = self.new.iter().map(|e| e.id).collect();
        let pinned: Vec<&Entry> = self.data.entries.iter().filter(|e| e.is_pinned).collect();

        let goal = match self.goal.trim() {
            "" => NO_GOAL,
            goal => goal,
        };
        let questions = self
            .open
            .iter()
            .map(|q| question_line(q.id, q.archetype.as_str(), &q.text, &q.rests_on, q.rating.as_str()))
            .collect();
        // the first pass of a case shows only the newest entries verbatim, the rest as a compact timeline
        let verbatim: HashSet<i64> = if self.last_seen == 0 {
            let mut ids: Vec<i64> = new_ids.iter().copied().collect();
            ids.sort_unstable();
            ids.split_off(ids.len().saturating_sub(RECENT)).into_iter().collect()
        } else {
            new_ids.clone()
        };
        // pinned notes are already shown verbatim above
        let (entries_name, entries) = if full {
            let timeline = self
                .data
                .entries
                .iter()
                .filter(|e| !e.is_pinned)
                .map(|e| {
                    if verbatim.contains(&e.id) {
                        entry_line(e, label(e))
                    } else {
                        timeline_line(e, label(e))
                    }
                })
                .collect();
            ("timeline", timeline)
        } else {
            let lines = self
                .new
                .iter()
                .filter(|e| !e.is_pinned)
                .map(|e| entry_line(e, label(e)))
                .collect();
            (NEW_ENTRIES, lines)
        };
        let related = self
            .related(&new_ids, &pinned)?
            .into_iter()
            .map(|e| entry_line(e, label(e)))
            .collect();

        // the newest entries' words: the query keeps only its first few hundred distinct tokens
        let recent = &self.new[self.new.len().saturating_sub(RECENT)..];
        let query = fts_query(&recent.iter().map(|e| e.text.as_str()).collect::<Vec<_>>().join(" "));
        let plus_examples = self.cdb.nearest_examples(Rating::Plus, &query, EXAMPLES)?;
        let minus_examples = self.cdb.nearest_examples(Rating::Minus, &query, EXAMPLES)?;
        let plus: Vec<&str> = plus_examples.iter().map(|x| x.text.as_str()).collect();
        let minus: Vec<&str> = minus_examples.iter().map(|x| x.text.as_str()).collect();

        let weights = self.cdb.archetype_weights()?;
        let weights: Vec<(&str, i64, i64)> = weights
            .iter()
            .map(|&(a, plus, minus)| (a.as_str(), plus, minus))
            .collect();
        let instruction = reflect_instruction(full, &archetype_hints(&weights), QUESTION_CAP);

        let header = case_header(&self.data.case, &self.data.evidence);
        let header_lines = header.len() - self.data.evidence.len();
        // spec 4.5: the related entries are cut first, the examples after them, the entries last; a diff pass keeps
        // its oldest new entry. What still overflows is shortened, then dropped, in the fixed sections: pinned and
        // evidence lines and the kept entry shortened, evidence lines (entries name their evidence) and pinned notes
        // dropped, the goal and the guideline shortened. The questions and the instruction are never cut.
        Ok(vec![
            section(
                "guideline",
                vec![self.guideline.to_string()],
                vec![shorten(9, GUIDELINE_SHORT, false)],
                TextKind::Prose,
            ),
            section(
                "goal",
                vec![goal.to_string()],
                vec![shorten(8, GOAL_SHORT, false)],
                TextKind::Prose,
            ),
            section(
                "case",
                header,
                vec![shorten(4, EVIDENCE_SHORT, false), drop_lines(6, false, header_lines)],
                TextKind::Dense,
            ),
            section(
                "pinned",
                pinned.iter().map(|e| entry_line(e, label(e))).collect(),
                vec![shorten(3, PINNED_SHORT, true), drop_lines(7, true, 0)],
                TextKind::Dense,
            ),
            section("questions", questions, Vec::new(), TextKind::Dense),
            section(
                entries_name,
                entries,
                // the timeline loses its oldest lines; a diff pass its newest, which the next pass covers
                vec![drop_lines(2, full, usize::from(!full)), shorten(5, ENTRY_SHORT, full)],
                TextKind::Dense,
            ),
            section(RELATED, related, vec![drop_lines(0, false, 0)], TextKind::Dense),
            section(
                "examples",
                example_lines(&plus, &minus),
                vec![drop_lines(1, false, 0)],
                TextKind::Prose,
            ),
            section("instruction", vec![instruction], Vec::new(), TextKind::Prose),
        ])
    }

    /// Older entries retrieved for every new entry and open question, without the pinned and new ones, best rank
    /// first: every query's first hit, then every second hit, and so on.
    fn related(&self, new_ids: &HashSet<i64>, pinned: &[&Entry]) -> Result<Vec<&Entry>> {
        let mut exclude = new_ids.clone();
        exclude.extend(pinned.iter().map(|e| e.id));
        // a case's first pass shows every entry: there is nothing older to retrieve, and a query per entry is costly
        if self.data.entries.iter().all(|e| exclude.contains(&e.id)) {
            return Ok(Vec::new());
        }
        let importance = self.cdb.importance_map(self.case_id)?;
        let newest_created_utc = self.data.entries.last().map_or("", |e| e.created_utc.as_str());
        let per_question = if self.kind == PassKind::Full {
            K_QUESTION_FULL
        } else {
            K_QUESTION_DIFF
        };
        let queries = self
            .new
            .iter()
            .map(|e| (e.text.as_str(), K_NEW))
            .chain(self.open.iter().map(|q| (q.text.as_str(), per_question)));
        // entry id -> (best rank, best score)
        let mut best: HashMap<i64, (usize, f32)> = HashMap::new();
        for (text, k) in queries {
            let query = RetrievalQuery {
                case_id: self.case_id,
                text,
                exclude: &exclude,
                k,
                newest_created_utc,
            };
            for (rank, hit) in retrieve(self.cdb, &importance, &self.data.created, &query)?
                .into_iter()
                .enumerate()
            {
                let slot = best.entry(hit.entry_id).or_insert((rank, hit.score));
                if rank < slot.0 || (rank == slot.0 && hit.score > slot.1) {
                    *slot = (rank, hit.score);
                }
            }
        }
        let mut ranked: Vec<(i64, usize, f32)> =
            best.into_iter().map(|(id, (rank, score))| (id, rank, score)).collect();
        ranked.sort_by(|a, b| a.1.cmp(&b.1).then(b.2.total_cmp(&a.2)).then(a.0.cmp(&b.0)));
        let by_id: HashMap<i64, &Entry> = self.data.entries.iter().map(|e| (e.id, e)).collect();
        Ok(ranked
            .into_iter()
            .filter_map(|(id, ..)| by_id.get(&id).copied())
            .collect())
    }
}
