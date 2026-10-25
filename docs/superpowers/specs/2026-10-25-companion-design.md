# Analytical companion: design

Date: 2026-10-25. Status: draft for review.

## 1. Intent

factum keeps a signed, append-only case log. The companion is a mentor that reads that log as it grows and keeps a
short list of analytical questions on screen: the questions a careful DFIR lead would ask next. It nudges the
investigator to document what was just seen, to verify it from independent artifacts, and to take the next sensible
step. It never solves the case and never writes into the log.

Why: in a long investigation it is easy to chase the interesting thing and leave documentation and cross-verification
undone, and easy to lose the red thread, for example when leaving the workstation on day one and returning on day
three. The companion keeps the investigation on track and keeps its quality up. It is a compass, not a judge of
completion: the investigator decides when the case is done.

The companion follows the BSI *Leitfaden IT-Forensik*: an investigation answers what, where, when and how happened,
and where relevant who did it and what prevents a repeat; every thesis is tested with traces that could support it
and traces that could refute it; methods must be accepted, credible, repeatable, integrity-preserving, able to link
cause and effect, and documented at every step; the process runs through strategic preparation, operational
preparation, collection, examination, analysis and documentation.

## 2. Goals, non-goals, anti-goals

Goals
- A small, stable, always-visible list of questions per case, each resting on named log entries.
- Questions appear, change and disappear only in response to changes in the case log.
- Works with local OpenAI-compatible or Anthropic-compatible endpoints at 16k to 32k context, better with more.
- Works on air-gapped machines: no new runtime dependencies, no model files to ship, no network except the
  configured endpoint.
- The interface is reading a question and clicking once. Nothing the companion does adds case-management work.
- Gets better with use: the investigator's plus and minus ratings shape future questions.
- A one-shot "Ask" over the case log, with references to entries.

Non-goals
- No autonomy: the companion calls no tools, reads no disk images, runs no commands.
- No judgment of completion or progress toward the goal.
- No temporal awareness of "now": it sees the timestamps of entries, nothing else.
- No cross-case retrieval: context and memory are case-scoped.
- No fine-tuning or weight updates of any model.
- Not a chat. Ask is one question, one answer.

Anti-goals (a build that does these has failed even if it works)
- Any AI-generated text entering the entries table, an export, a bundle, a seal or a verification result.
- A question that was rated minus coming back in different words.
- Questions reshuffling between passes so the list cannot be used as a place to resume.
- Questions that cite entries which do not exist or do not say what the question claims.
- Pop-ups, spinners in the reading column, or any companion element shown while unconfigured or switched off.
- Compatibility with factum-notes (Python) broken: the case database schema and its version stay untouched.

## 3. Constraints

- factum is one synchronous Rust binary (edition 2024, egui 0.37, rusqlite with bundled SQLite, no async runtime).
  Background work is plain threads reporting through channels and `ctx.request_repaint()`.
- The case database is schema 3, shared with factum-notes, whose version check refuses anything else. Nothing is
  added to it.
- The GUI already polls `PRAGMA data_version` every 0.75 s to notice CLI writes. The companion rides on that.
- Builds must stay vendorable (`cargo vendor`) and must not need a C++ toolchain beyond what bundled SQLite needs.
- Endpoints: OpenAI chat completions or Anthropic messages, on the local network, localhost or a cloud service.
  Context sizes from 16k, usually 32k, at best 128k for local models.
- The companion database is as sensitive as the case database (it holds an API key and derived case content).

## 4. Decisions

### 4.1 Storage: a companion database next to the case database

File: the case database path with `.companion.db` instead of `.db` (default `~/.local/share/factum/factum.companion.db`;
with `FACTUM_DB=/x/y.db` it is `/x/y.companion.db`). WAL mode, busy timeout 5 s, its own `PRAGMA user_version`,
created on first use. It is paired with its case database by location; case ids inside it are the case database's
ids. Everything in it is derived data: deleting the file loses ratings and settings but no evidence, and the
per-case parts are rebuilt from the log.

Tables (final column lists are the builder's; these are the required contents):

- `settings(key, value)`: app-level configuration (4.2) and the global guideline (4.4).
- `case_settings(case_id, enabled, goal, last_seen_entry_id, last_pass_id)`.
- `enrichment(case_id, entry_id, keywords, context, importance, embedding BLOB NULL, created_utc)`: (the
  `embedding` column is reserved for a possible bundled model later, see 4.6, and stays NULL):
  one row per processed entry (4.6).
- `entry_fts`: an FTS5 table over entry text, keyed by entry id, with the `unicode61` tokenizer and
  `tokenchars '-_./:\\'` so paths, hashes, hostnames and flags stay whole tokens (4.6).
- `questions(id, case_id, text, archetype, state, rating, created_pass_id, resolved_pass_id, resolved_entry_id,
  position, embedding BLOB NULL, created_utc, resolved_utc)`. `state` is one of `open`, `answered`, `withdrawn`,
  `rejected` (minus). `rating` is `none`, `plus` or `minus`. `position` is a per-case monotonic counter: new
  questions get the next value, order is by position, nothing ever moves.
- `question_entries(question_id, entry_id)`: the entries a question rests on, verified at write time.
- `question_events(id, question_id, kind, pass_id, entry_id, created_utc)`: the history (created, linked, unlinked,
  withdrawn, plus, minus, restored).
- `passes(id, case_id, kind, started_utc, finished_utc, model, status, error, entries_from, entries_to,
  prompt_chars, output_chars)`: one row per reflection pass, `kind` is `diff` or `full`.
- `rated_examples(id, text, rating, archetype, embedding BLOB NULL, source_case_id, created_utc)`: global.
- `archetype_weights(archetype, plus_count, minus_count)`: global.

Scoping rule: `enrichment`, `entry_fts`, `questions`, `question_entries`, `question_events`, `passes` and
`case_settings` are keyed by case id and a pass only ever reads its own case's rows. `rated_examples` and
`archetype_weights` are global: how the companion asks is the investigator's methodology and travels across cases;
what it looks at does not. (Decided with the user; the user accepts that rated question text may mention details
of the case it came from.)

Permanent deletion of a case in the GUI also deletes the case's companion rows. Archiving a case stops passes for it
(the log cannot change). Corrections: only the newest version of a corrected note is indexed and shown to the model;
when a correction arrives, the old version's enrichment and FTS rows are replaced.

### 4.2 Configuration

Settings live in the companion database (not in `.env`): `endpoint_url`, `protocol` (`openai` | `anthropic`),
`api_key`, `user_agent`, `extra_headers` (JSON object), `model`, `context_window` (tokens, optional),
`global_guideline`, `enabled` (default on once configured).
Values are trimmed on save. The API key is stored as entered; the settings dialog says so and reminds that the
database folder is sensitive. An `FACTUM_COMPANION_API_KEY` environment variable, if set, overrides the stored key
and the field is shown as "from environment".

TLS: plain `http://` is allowed (the usual case on a lab network). For `https://`, certificates are checked against
the operating system's trust store (rustls with the platform verifier), so a lab's private CA works once it is
installed in the OS, as it must be for every other tool. There is no "skip verification" toggle and no per-endpoint
CA file. An "Unreachable" probe result names the TLS error when that is the cause. The builder verifies that the
chosen crypto backend builds on all release targets without extra tools (the Windows runner has no NASM), and
picks the backend accordingly.

The settings dialog (menu: Companion → Settings…) copies Vestigo's experience:
- Fields: Endpoint URL, Protocol, API key (masked, "stored" indicator when a value exists and the field is empty),
  User-Agent, Extra headers, Context window, Model, Global guideline (multi-line, with "Reset to
  default"), Enabled.
- The model list is loaded from the unsaved draft values, debounced by about 600 ms after the last edit of URL,
  key, protocol or headers, with a 5 s timeout, on a background thread. `GET {url}/models` for OpenAI
  (`Authorization: Bearer`), `GET {url}/v1/models` for Anthropic (`x-api-key`, `anthropic-version: 2023-06-01`).
  Ids are de-duplicated and sorted. The Model field is a combo box with free text: typing keeps
  them free text, the listing fills the dropdown. A saved model that the listing does not contain stays selectable.
- Failures are never shown as errors. One status line under the field reads: "Loading models from the endpoint…",
  "N models from the endpoint.", "The endpoint listed no models. Enter the name by hand.", or "Set the endpoint URL
  to load the model list."
- A "Test connection" button saves pending edits, then probes (the same model listing, forced), and shows
  "Reachable" with ✓ or "Unreachable: <reason>" with ✗ next to the button.
- A plain notice: "Case content is sent to <url>."

Availability: the companion is *configured* when URL, protocol and model are set and `enabled` is on. It is
*available* when the last probe succeeded; the probe runs at GUI start and whenever settings change, and the result
is kept until the next probe. Unconfigured means no companion element anywhere in the GUI. Configured but
unavailable means the elements show, passes do not run, and the status bar says why.

Per case: Case menu → "Companion for this case" (checkbox, default on). Off hides the section for that case and stops
passes for it. Case menu → "Case goal…" opens a multi-line text dialog that writes `case_settings.goal`.

First configuration, and cases without a `case_settings` row: no model work happens for a case until it is selected
in the tree. Selecting a case that has entries but no companion state runs one full pass (4.7) with the compact
timeline, so the first questions appear within one pass; the newest 20 entries are enriched before it, the rest of
the history is enriched afterwards in batches of 50, newest first, only while the thread has nothing else to do.
Retrieval over not-yet-enriched entries works on their raw text. The status item shows "indexing n of m" during
backlog enrichment. The companion thread serves cases in the order: the selected case first, then any other case
with pending changes, one at a time.

### 4.3 GUI

Side panel (right), stacked, top to bottom:
1. **PINNED** with the existing Case/Evidence scope toggle. Always on top; nothing the companion does displaces it.
2. **QUESTIONS n** with a 2 px bar on the left in the accent color and a header line "reflected <relative time>"
   (or "reflecting…", or "endpoint unreachable", or "off for this case"). A small ▾ menu on the header offers
   History…, Ask…, Case goal…, Re-think now, and Settings…. Present only when configured and on for the case.
3. **▸ IOCS n**, a collapsible section (closed by default) instead of a tab.

The stacked layout applies always, also when the companion is unconfigured (then only Pinned and IoCs exist); the
tabbed panel and `SideTab` go away. Pinned and Questions each scroll on their own with a soft height limit (builder picks; roughly 40 % of the panel
each, growing into free space when the other is short), so a dozen pins cannot push the questions off screen and vice
versa. The side panel's existing width and visibility settings stay.

A question row: the text; underneath in small muted text the entry ids it rests on as clickable `#12` links that
jump to the entry (the existing `jump_to_entry`); on the right two small buttons `+` and `−`. Nothing else. Hover on
the text shows the archetype and when the question was created. Rows are ordered by `position`, never reordered.

Until a case goal is set, the first row of the section is a permanent, unrateable row "No goal set for this case.
Set it…" which opens the goal dialog. Passes still run with the global guideline alone.

Status bar: a right-aligned item "companion: idle · <model>", "companion: reflecting…", "companion: endpoint
unreachable", or "companion: off". Nothing else in the GUI animates for the companion.

History window (Companion → History…): a plain list of the case's non-open questions, newest first, with state,
rating, when, and for `answered` the linked entry id (clickable) and an "Unlink" button that restores the question
to `open` and records an `unlinked` event. Rejected and withdrawn questions have a "Restore" button. The window is
read from the companion database only.

Ask window (Companion → Ask…): hidden until opened. One text field, an Ask button, the answer below with `[n]`
references rendered as clickable entry links and a "Copy" button. Nothing is stored. Ask runs on its own worker
thread (the existing `Worker` pattern), not on the companion thread, so it never waits behind a running pass; the
window shows "asking…" while the call runs, and the endpoint may of course serialise the two requests itself.

Keyboard: none required. (Builder may add a shortcut for Ask.)

CLI: `factum --questions [case]` prints the open questions of a case with their entry ids, read-only, from the
companion database. The CLI never runs passes.

Dark theme: the accent bar and buttons use the existing palette; no new colors.

### 4.4 Prompts

Two layers, both plain text, both outside the signed corpus.

**Global guideline** (app level, shipped default, editable, rarely changed). The default, in English, states in
roughly this order:
- Role: a mentor looking over a digital forensics investigator's shoulder; gentle, concise, never doing the work.
- Output discipline: questions only, at most seven open at a time, each resting on specific entries by id; prefer
  withdrawing stale questions to piling up; one question per issue; written in the language the notes are written
  in; concrete over generic; never assume facts the log does not state.
- The BSI lens, used to find gaps: the core questions (what, where, when, how; who and prevention where relevant);
  supporting and refuting traces for every thesis; acceptance, credibility, repeatability, integrity and chain of
  custody, cause and effect, documentation; the six phases and what usually comes next.
- The three jobs of a question: document what was just seen, verify it from independent artifacts, point to the
  next sensible place to look.
- What not to ask: things the log already answers, things outside the case goal, management or reporting chores.

**Case goal** (per case, absent by default, free text). Strategic, external goals: scope, client questions, legal
frame, what must be answered. Sent verbatim.

### 4.5 Context assembly

Every model call is built from sections in a fixed order with a token budget per section. Token estimates: chars/3.0
for prose, chars/2.4 for JSON and identifier-heavy text; when a response carries usage counts, the ratio is
recalibrated from them for the session. Budget: `0.8 × context_window − output_reserve`, where `context_window` is
the setting; else, for the Anthropic protocol, the `max_input_tokens` field of the chosen model from the models
listing; else 16k, so an unknown endpoint never overflows. `output_reserve` is 1 500 tokens for a reflection pass, 800 for enrichment, 1 000 for Ask. A call
is refused (and logged, status "budget") if a section that cannot be cut does not fit.

Order and cutting rule for a reflection pass:
1. Global guideline (never cut).
2. Case goal, or "No case goal has been set." (never cut).
3. Case header: file number, name, description, created; evidence items with id, description, hash, created,
   deleted flag (never cut).
4. Pinned notes, verbatim, with timestamps and evidence id (never cut; if they alone overflow, the pass is refused).
5. Open questions: id, archetype, text, entry ids, rating (never cut; the ≤ 7 cap keeps this small).
6. New entries since the last pass, verbatim, oldest first, each as `#id · timestamp · evidence · text` (cut from the
   oldest end second; a pass that cuts here is followed by another pass covering the rest).
7. Related older entries: retrieved (4.6) for the new entries and for each open question, de-duplicated, with the
   same line format (cut first, lowest rank first).
8. Rated examples: the three nearest plus and three nearest minus examples to the new entries' text, labelled
   "the investigator found these useful / not useful" (cut after 7 if needed).
9. The task instruction for the pass.

Entries are always rendered with their id, timestamp (UTC, as stored) and evidence attribution. System entries
(case created, edited, evidence created or deleted, archived, reopened) are included as one-line events; they are
the only source of case metadata changes.

### 4.6 Memory: enrichment, index, retrieval

**Enrichment** runs before a reflection pass for every entry not yet enriched, in batches of up to ten entries per
call, single-pass JSON: per entry `keywords` (≤ 8, in the note's language and in English), `context` (one sentence
placing the entry in the case), `importance` (1 to 10). Output is repaired if syntactically broken and validated (every id present, ranges in
bounds); an entry that fails stays unenriched and is retried on the next pass. Enrichment failure never blocks the
reflection pass.

**Index**: `entry_fts` receives the entry text plus the keywords and context, so retrieval can match on the
enrichment as well. Keywords are requested in the note's language *and* in English, so a German note is found from
an English question and the other way round without any vector model.

**Retrieval** for a query text, scoped to the case:
- BM25 over `entry_fts` (SQLite's `bm25()`), top 30.
- Normalise the BM25 score to 0..1 by dividing by the best score of the list.
- Add `0.05 × importance/10` to the score; add a recency term `0.05 × 0.5^(age_days/30)` measured from the
  entry's created timestamp to the newest entry in the case (not to the wall clock).
- Exclude entries already in the prompt (pinned, new). Take the top k per query (k = 5 for a new entry, 3 for an
  open question), cap the merged set by the section budget.

No embeddings, no reranker, no vector database, no graph. Decided with the user on 2026-10-25: an optional,
user-chosen embedding model would make retrieval quality unreproducible between installs, and a bundled
multilingual model costs about 120 MB in the binary because of its vocabulary table. Keyword retrieval over text
plus model-written bilingual keywords and context is the shipped design. The queries are entries and questions
written in the case's own vocabulary, and forensic notes are identifier-heavy, which is where BM25 is strongest.

Follow-up, decided on evidence: the builder hand-labels 30 to 50 retrieval queries from a real case and reports
recall@10. If keyword retrieval misses material that matters, a fixed, bundled, CPU-friendly multilingual
embedding model (one named model, code tuned to it, inside the single binary, pure Rust inference) is added as a
second retrieval source fused by reciprocal rank fusion. The nullable `embedding` columns and the single
`retrieve` function keep that additive.

### 4.7 The reflection loop

A long-lived companion thread is started by the GUI when the companion is configured. It owns its own connections
(read-only to the case database, read-write to the companion database), receives commands over a channel
(`CaseChanged(case_id)`, `Rethink(case_id)`, `Ask{case_id, question}`, `Probe`, `SettingsChanged`, `Shutdown`), and
publishes status through a shared `Mutex<Status>` plus `ctx.request_repaint()`. The GUI reads questions from the
companion database on `rebuild`, the same way it reads notes, so no question data travels over channels.

**Triggers.** The GUI's existing data-version poll detects changes made by other processes; the GUI's own writes
(`submit_note`, corrections, case and evidence edits) do not move `data_version`, so `rebuild` sends `CaseChanged`
after local writes as well. For every case whose newest entry id is beyond `case_settings.last_seen_entry_id`, the
GUI sends `CaseChanged`. The thread waits for a quiet period of 30 s after
the last change to that case, then runs. A minimum spacing of 60 s between passes of the same case applies. Nothing
runs for a case that has not changed, including on GUI start or case open. Archived cases, cases switched off, and
an unavailable endpoint stop the loop for that case; pending changes are picked up when the condition clears.
`Rethink` forces a full pass regardless of changes. Setting or changing the case goal counts as a change to the
case and runs a full pass right away (decided with the user). A change to the global guideline takes effect on the
next pass and does not trigger one.

**Pass kinds.**
- A *diff pass* sees sections 1 to 9 as in 4.5 and is asked to: mark open questions answered by a new entry (with
  that entry's id), withdraw questions the new entries make moot, and propose new questions, keeping the open count
  at most seven. A plus-rated question may be answered but not withdrawn.
- A *full pass* replaces section 6 with a compact timeline: one line per entry, text truncated to about 100
  characters, newest entries complete, oldest first, cut from the oldest end if needed; and widens section 7 to
  the top 5 related entries per open question. It is asked the same thing plus to reconsider every open question
  against the whole case. A full pass runs on the first pass of a case, every tenth pass, after a diff pass that
  answered or withdrew three or more questions, and on `Rethink`.

**Two calls per pass.** Call one is free-form: the model is asked to reason in prose about what changed, what is
answered, what is missing, and what to ask, with entry ids. Call two sends that reasoning back and asks for a flat
JSON object only:

```
{"answered":[{"question":12,"entry":381}], "withdraw":[9], "new":[{"text":"…","archetype":"document","rests_on":[380,381]}]}
```

The format is described in the instruction; no grammar or JSON schema is sent, since constrained decoding
measurably hurts small models' accuracy. On the OpenAI protocol call two also sends
`response_format: {"type":"json_object"}`; if the server answers 400 to that, the request is repeated without it
and the fact is remembered for the session. On the Anthropic protocol nothing else is sent: assistant prefill is
rejected by current Claude models and `output_config` is not expected from local Anthropic-compatible servers, so
instruction plus repair and validation is the whole mechanism on both protocols. Cloud Claude models are in scope.

**Validation** (no model involved), applied to call two's output in this order:
1. `finish_reason == "length"`, `truncated`, or an empty body: the pass fails; retry once with section 7 halved, then
   give up (status "failed", logged with the error, questions unchanged).
2. Syntactic repair of the JSON (unquoted keys, trailing commas, a missing closing brace); if repair fails, as 1.
3. Every question id must be open in this case; every entry id must exist in this case and, for `answered`, be one
   of the new entries or an entry newer than the question; every `rests_on` id must exist in this case. Items that
   fail are dropped individually; a `new` item without any valid `rests_on` is dropped.
4. `archetype` must be one of the fixed set (4.8); unknown values become `coverage`.
5. Duplicate suppression: a new question is dropped when its normalized token-set overlap (Jaccard ≥ 0.6 on
   lowercased tokens longer than three characters) with any open, `answered` or `withdrawn` question of the case,
   or with any minus-rated example anywhere, is reached. Minus examples are compared against globally. The nearest
   minus examples are also in the prompt (4.8), so the model is told what not to resurrect before the mechanical
   check runs.
6. The cap: if more than seven would be open, the newest `new` items beyond the cap are dropped.
7. A withdraw of a plus-rated question is ignored.

Surviving changes are applied in one transaction: answered questions get `state=answered`, `resolved_entry_id`,
and a `linked` event; withdrawn get `state=withdrawn`; new questions get the next `position` and their
`question_entries`; the pass row is finished; `last_seen_entry_id` advances to the newest entry included in
section 6. Call failures (network, 4xx, 5xx, timeout) retry once after 5 s, then fail the pass; the thread goes back
to waiting and the status bar shows the reason. A pass never leaves the ledger half-applied.

Timeouts: 5 s for probes and model listing, 180 s per model call (setting, builder's default), 60 s for Ask.

### 4.8 Archetypes, ratings and learning

Archetypes, fixed and derived from the BSI lens: `coverage` (what, where, when, how, who, prevention), `corroborate`
(a trace that supports or refutes a thesis), `document` (a step just taken is not written down), `integrity`
(chain of custody, hashes, unchanged evidence), `repeatability` (tool, version, parameters, method noted),
`causality` (linking events, traces and actors), `phase` (what usually comes next; is a component's examination
complete before analysis).

**Minus**: one click. The question gets `state=rejected`, `rating=minus`, a `minus` event, disappears from the panel,
and is copied into `rated_examples` with `rating=minus`. `archetype_weights.minus_count` for its archetype
increments. No further input is asked for.

**Plus**: one click. `rating=plus`, a `plus` event, copied into `rated_examples` with `rating=plus`,
`plus_count` increments. The question stays; the companion may still answer it but may not withdraw it.

**How ratings change future questions**
- Exemplars: section 8 of every pass carries the nearest rated examples (by BM25 over a small FTS table over
  `rated_examples`), labelled useful / not useful.
- Do-not-resurrect: validation step 5 compares every new question against all minus-rated examples.
- Mix: the instruction of call one names the archetypes and, for each, a short hint derived from the weights: an
  archetype with `minus_count − plus_count ≥ 3` is marked "the investigator rarely finds these useful here; only
  when clearly warranted", one with `plus_count − minus_count ≥ 3` is marked "the investigator values these". No
  bandit sampling, no reranker: at fewer than a hundred ratings nothing more is supported by evidence.
- Everything needed for a later learned reranker is logged (`rated_examples` with archetypes and a nullable
  embedding column), so it can be added without a schema change.

### 4.9 Ask

Input: one question. Retrieval as 4.6 with k = 8 and no exclusion, plus every pinned note; packed greedily by rank
into the budget as numbered excerpts `[n] #id · timestamp · text`. One call, prose output. The instruction: answer
only from the excerpts, cite as `[n]`, quote paths and values exactly, answer partially if only part is covered, and
start with exactly "Not in the case log." when no excerpt mentions any part of the subject. After the answer, a
check without a model call flags paths, hashes, numbers and commands in the answer that occur in no excerpt and
shows them in muted text under the answer as "not found in the cited entries: …". `[n]` references become entry
links. The answer is not stored.

### 4.10 Error handling and status

- Unconfigured: nothing exists.
- Configured, probe failed: section shown with "endpoint unreachable"; questions stay as they were; no passes.
- Pass failure: status shows "last pass failed: <short reason>" until the next successful pass; the pass row holds
  the full error. Questions are never cleared on failure.
- Budget failure: "case too large for this model's context" in the status; the builder logs which section
  overflowed.
- The companion thread never panics the GUI: every command is wrapped, errors are stored in `passes.error`.
- Logging through the existing `log` facade at DEBUG for prompts (sizes only, not content), INFO for pass results,
  WARN for failures.

### 4.11 Dependencies

- `ureq` 3 (rustls, no tokio) for HTTP; `serde` with derive for request and response types (`serde_json` exists).
- SQLite FTS5 is already compiled into the bundled SQLite (rusqlite `bundled`), so no new native code.
- No ONNX, no llama.cpp, no model files, no embeddings call. The endpoint is used for chat only.
- All new code behind the existing `gui` feature except the companion database, retrieval and CLI `--questions`,
  which belong to the library so the CLI build can read questions.

### 4.12 Testing

- Unit tests: token estimation and budgeting (sections cut in the right order, refusal when uncuttable sections
  overflow), score terms, FTS tokenizer behaviour on paths and hashes, validation steps 1 to 7 with crafted
  outputs, duplicate suppression, position monotonicity, rating transitions.
- Loop tests with a fake endpoint: a tiny in-process HTTP server on a thread (std `TcpListener`) that returns
  scripted OpenAI and Anthropic responses, including truncated, malformed and error cases. Tests drive a temporary
  case database through the real `Factum` services and assert the ledger after each pass. No network in CI.
- GUI: `egui_kittest` tests of the stacked side panel in both themes, configured and unconfigured, with and without
  a goal, built like the existing `src/gui/tests.rs` (no wgpu in CI; screenshots only with `FACTUM_SCREENSHOTS`).
  Assertions are on widget presence and state through the harness, not on pixels.
- Compatibility: the existing integrity and export tests must pass unchanged; a test opens a case database after
  companion use with the schema-3 check and runs full verification.

## 5. Left to the builder

- Exact column types, indices, and the companion schema version handling.
- The default `context_window` when unset and how a probe may discover it.
- The precise wording of the default global guideline and the pass instructions, within the content in 4.4 and 4.7.
- Debounce, quiet period and spacing constants may be tuned; the 30 s / 60 s values are starting points.
- Height limits and scroll behaviour of the stacked panel.
- Whether to show a tiny "last pass took n s" in the status item.
- The exact JSON repair strategy (a small hand-written repair is fine; a crate is acceptable if vendorable).
- How `factum --questions` formats its output.

## 6. Status

Reviewed by a builder check on 2026-10-25; its questions are folded into sections 4.2, 4.3, 4.5, 4.7 and 4.12.
Approved by the user on 2026-10-25.
