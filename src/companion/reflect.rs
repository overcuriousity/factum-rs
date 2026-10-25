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
use super::tokens::{BudgetError, Cut, Packed, Section, TextKind, budget, pack};
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
/// The window assumed when the settings name none (the client keeps no model listing).
const DEFAULT_CONTEXT_WINDOW: u32 = 16_000;
const NO_GOAL: &str = "No case goal has been set.";
const NEW_ENTRIES: &str = "new entries";
/// Rated examples of each kind in the prompt.
const EXAMPLES: usize = 3;
/// Related entries per new entry, per open question in a diff pass and in a full pass.
const K_NEW: usize = 5;
const K_QUESTION_DIFF: usize = 3;
const K_QUESTION_FULL: usize = 5;

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
            PassError::Budget(_) => f.write_str("case too large for this model's context"),
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
struct CaseData {
    case: Case,
    /// deleted items included
    evidence: Vec<Evidence>,
    /// the newest version of every entry, system entries included, by leaf index
    entries: Vec<Entry>,
    /// creation time of every entry id, superseded versions included
    created: HashMap<i64, String>,
}

fn load_case(case_db: &Db, case_id: i64) -> Result<CaseData> {
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
    let unenriched = cdb.unenriched(case_id, &new_ids)?;
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
        new: &new,
        open: &open,
    };
    let window = client.settings().context_window.unwrap_or(DEFAULT_CONTEXT_WINDOW);
    let room = budget(window, OUTPUT_RESERVE);
    let packed = pack(input.sections(1)?, room, &client.calibration())?;
    log.prompt_chars = packed.text.chars().count();
    if !packed.cut.is_empty() {
        log::info!("companion pass {pass_id}: lines cut for space: {:?}", packed.cut);
    }
    if kind == PassKind::Diff {
        log.entries_to = covered_to(&new, &packed, last_seen, room)?;
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
            log::warn!("companion pass {pass_id}: {reason}; retrying with half the related entries");
            let smaller = pack(input.sections(2)?, room, &client.calibration())?;
            serialize(client, &smaller.text, &reasoning.text, log)?
        }
        other => other?,
    };

    let resolved = cdb.resolved_questions(case_id)?;
    let minus = cdb.minus_examples()?;
    let existing: HashSet<i64> = data.created.keys().copied().collect();
    let new_set: HashSet<i64> = new_ids.iter().copied().filter(|&id| id <= log.entries_to).collect();
    let validated = validate(
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
    for reason in &validated.dropped {
        log::info!("companion pass {pass_id}: dropped {reason}");
    }
    cdb.transaction(|_| {
        for &(question, entry) in &validated.answered {
            cdb.answer_question(question, entry, pass_id)?;
        }
        for &question in &validated.withdraw {
            cdb.withdraw_question(question, pass_id)?;
        }
        for question in &validated.new {
            cdb.insert_question(case_id, Some(pass_id), question)?;
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
        )
    })?;
    Ok(PassSummary {
        pass_id,
        kind,
        answered: validated.answered.len(),
        withdrawn: validated.withdraw.len(),
        created: validated.new.len(),
        entries_to: log.entries_to,
        dropped: validated.dropped,
    })
}

/// The newest entry a diff pass covers: the newest one, or, when the new entries were cut from the newest end, the
/// newest one before the first cut line (pinned ones are shown in their own section). Nothing left is a budget error.
fn covered_to(new: &[&Entry], packed: &Packed, last_seen: i64, budget: usize) -> std::result::Result<i64, PassError> {
    let listed: Vec<&Entry> = new.iter().copied().filter(|e| !e.is_pinned).collect();
    let dropped = packed
        .cut
        .iter()
        .find(|(name, _)| *name == NEW_ENTRIES)
        .map_or(0, |&(_, n)| n);
    if dropped == 0 {
        return Ok(new.iter().map(|e| e.id).max().unwrap_or(last_seen).max(last_seen));
    }
    if dropped >= listed.len() {
        return Err(PassError::Budget(BudgetError::Uncuttable {
            section: NEW_ENTRIES,
            needed: packed.tokens,
            budget,
        }));
    }
    let first_cut = listed[listed.len() - dropped].id;
    Ok(new
        .iter()
        .map(|e| e.id)
        .filter(|&id| id < first_cut)
        .max()
        .unwrap_or(last_seen))
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
    /// entries after the last pass, by leaf index
    new: &'a [&'a Entry],
    open: &'a [Question],
}

fn section(name: &'static str, lines: Vec<String>, cut: Cut, kind: TextKind) -> Section {
    Section { name, lines, cut, kind }
}

impl PromptInput<'_> {
    /// The sections of spec 4.5 in order; `related_divisor` divides the number of related entries per query.
    fn sections(&self, related_divisor: usize) -> Result<Vec<Section>> {
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
        // pinned notes are already shown verbatim above
        let (entries_name, entries) = if full {
            let timeline = self
                .data
                .entries
                .iter()
                .filter(|e| !e.is_pinned)
                .map(|e| {
                    if new_ids.contains(&e.id) {
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
            .related(&new_ids, &pinned, related_divisor)?
            .into_iter()
            .map(|e| entry_line(e, label(e)))
            .collect();

        let query = fts_query(&self.new.iter().map(|e| e.text.as_str()).collect::<Vec<_>>().join(" "));
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

        let never = Cut::Never;
        Ok(vec![
            section("guideline", vec![self.guideline.to_string()], never, TextKind::Prose),
            section("goal", vec![goal.to_string()], never, TextKind::Prose),
            section(
                "case",
                case_header(&self.data.case, &self.data.evidence),
                never,
                TextKind::Dense,
            ),
            section(
                "pinned",
                pinned.iter().map(|e| entry_line(e, label(e))).collect(),
                never,
                TextKind::Dense,
            ),
            section("questions", questions, never, TextKind::Dense),
            section(
                entries_name,
                entries,
                // the timeline loses its oldest lines; a diff pass its newest, which the next pass covers
                Cut::Lines {
                    priority: 2,
                    from_start: full,
                },
                TextKind::Dense,
            ),
            section(
                "related",
                related,
                Cut::Lines {
                    priority: 1,
                    from_start: false,
                },
                TextKind::Dense,
            ),
            section(
                "examples",
                example_lines(&plus, &minus),
                Cut::Lines {
                    priority: 0,
                    from_start: false,
                },
                TextKind::Prose,
            ),
            section("instruction", vec![instruction], never, TextKind::Prose),
        ])
    }

    /// Older entries retrieved for every new entry and open question, without the pinned and new ones, best rank
    /// first: every query's first hit, then every second hit, and so on.
    fn related(&self, new_ids: &HashSet<i64>, pinned: &[&Entry], divisor: usize) -> Result<Vec<&Entry>> {
        let mut exclude = new_ids.clone();
        exclude.extend(pinned.iter().map(|e| e.id));
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
            let k = k / divisor.max(1);
            if k == 0 {
                continue;
            }
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
