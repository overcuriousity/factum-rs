# Setup wizard, companion presets, evidence description: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An evidence description (editable, signed, verified, fed to the companion), app-wide companion presets,
a first-run setup wizard, and the removal of the `--questions` CLI flag.

**Architecture:** The description is a new `evidence.details` column (first migration, v3 → v4) with an
`evidence_edited` log event checked by both verifiers. Presets are an enum in the companion settings that selects a
built-in guideline and archetype definitions; `Custom` keeps today's editable text. The wizard is a new dialog
(`gui/wizard.rs`) on the existing dialog stack, reusing the GPG key list and the companion settings form; it writes
nothing before Finish.

**Tech Stack:** Rust 2024, rusqlite, egui/eframe 0.37, egui_kittest, Python 3 (bundled `verify.py`).

**Spec:** `docs/superpowers/specs/2026-10-27-onboarding-presets-evidence-description-design.md`

## Global Constraints

- `cargo test`, `cargo test --no-default-features`, `cargo clippy --all-targets` (no warnings) and `cargo fmt --check`
  pass after every task (CONTRIBUTING.md).
- The evidence name keeps the column and payload key `description`; the new text is column and payload key `details`.
- `SCHEMA_VERSION = 4`; only `user_version == 3` is migrated; everything else except 0 (empty) and 4 is refused as now.
- Payloads without `details` verify as `""`.
- Name and hash of evidence stay immutable; only `details` is editable.
- Preset ids: `forensics`, `investigator`, `osint`, `source_criticism`, `custom`; settings key `preset`.
- `DEFAULT_GUIDELINE` (Forensics) text is unchanged.
- Main-database setting `onboarding_done` = `"1"` once the wizard was finished or cancelled.
- The wizard writes nothing before Finish; a declined companion on a fresh setup creates no companion database.
- The companion has no CLI surface after this work.

## Review Focus

1. A v3 database with evidence *and* signed entries is migrated: old logs still verify (no `details` in payloads).
   → Task 3 test `pre_v4_payload_without_details_verifies`.
2. Editing the description of evidence in an archived case or of deleted evidence is refused, not silently applied.
   → Task 2 tests.
3. Switching the preset from Custom to a built-in and back must not lose the custom text.
   → Task 7 test `custom_text_survives_preset_switch`.
4. The wizard's Cancel after a live theme preview restores the previous theme.
   → Task 9 test `cancel_restores_theme_and_sets_flag`.
5. An existing companion user who opens the wizard and keeps "use companion" ends with unchanged settings
   (stored API key kept, preset kept). → Task 9 test `wizard_prefills_and_keeps_companion_settings`.

---

### Task 1: Schema v4 and `Evidence.details`

**Files:**
- Modify: `src/db.rs` (SCHEMA, SCHEMA_VERSION, `initialize_schema`, header comment, tests)
- Modify: `src/evidence.rs` (`Evidence` struct, `COLUMNS`, `from_row`)

**Interfaces:**
- Produces: `Evidence { …, pub details: String }` (after `evidence_hash`), `Evidence::COLUMNS` ending
  `…, deleted_utc, details`; `SCHEMA_VERSION == 4`.

- [ ] **Step 1: Tests in `src/db.rs` tests module**
  - `new_database_gets_current_schema`: expects version 4 and a `details` column on `evidence`
    (`SELECT details FROM evidence` prepares).
  - `version_3_database_is_migrated`: build a v3 file by executing the *old* v3 `CREATE TABLE evidence` (without
    `details`) plus the other tables via the current SCHEMA with the `details` line removed
    (`SCHEMA.replace("    details TEXT NOT NULL DEFAULT '',\n", "")`), insert a case and an evidence row,
    `PRAGMA user_version = 3`; `Db::open` → version 4, the row is there with `details == ""`.
  - `older_versioned_database_is_refused` and `factum_1_0_database_is_refused` stay green.
- [ ] **Step 2:** `cargo test --lib db::` → the two new assertions fail.
- [ ] **Step 3: Implement.** Add `details TEXT NOT NULL DEFAULT ''` as the last column of `evidence` in SCHEMA.
  In `initialize_schema`, before the refusal: `if version == 3` → `execute_batch("BEGIN; ALTER TABLE evidence ADD
  COLUMN details TEXT NOT NULL DEFAULT ''; PRAGMA user_version = 4; COMMIT;")`, log debug, return Ok. Replace the
  doc comment "Schema-compatible with factum-notes (Python)…" with: "Schema v3 was shared with factum-notes
  (Python); v4 added evidence.details." Extend `Evidence`, `COLUMNS`, `from_row` (index 7).
- [ ] **Step 4:** `cargo test` → green (no caller constructs `Evidence` literally; fix any that does).
- [ ] **Step 5: Commit** `Add evidence.details and the v3 → v4 migration`.

### Task 2: Create and edit the evidence description

**Files:**
- Modify: `src/evidence.rs`
- Modify (call sites, append `""`): `src/cli.rs:343`, `src/gui/mod.rs:1100`, `src/gui/tests.rs`, `tests/*.rs`,
  `examples/` (grep `create_evidence(`)
- Test: `tests/core.rs`

**Interfaces:**
- Produces:
  - `Factum::create_evidence(&self, case_id: i64, name: &str, evidence_hash: &str, details: &str) -> Result<i64>`
  - `Factum::update_evidence_details(&self, evidence_id: i64, details: &str) -> Result<()>`
  - event `{"event":"evidence_edited","evidence_id":N,"details":"…"}`; entry text
    `Evidence #N description edited: <name>`

- [ ] **Step 1: Tests in `tests/core.rs`**
  - `create_evidence_writes_system_entry_without_evidence_id`: call with details `" Seized at desk 4 "`; expect
    `evidence.details == "Seized at desk 4"` and the payload gains `"details": "Seized at desk 4"`.
  - `update_evidence_details_writes_evidence_edited`: edit to `"imaged with FTK 4.7"` → row updated, last event
    `{"event":"evidence_edited","evidence_id":id,"details":"imaged with FTK 4.7"}`.
  - `unchanged_evidence_details_write_nothing`: same text twice → entry count unchanged after the second call.
  - `evidence_details_refused_when_archived_or_deleted`: archived case → `ErrorKind::CaseArchived`; deleted evidence
    → error whose message contains "does not exist".
- [ ] **Step 2:** `cargo test --test core` → fail (arity).
- [ ] **Step 3: Implement.** `create_evidence`: strip `details`, insert into the row, add `"details"` to the payload.
  `update_evidence_details`: like `update_case` (append with `on_commit` that runs
  `UPDATE evidence SET details = ? WHERE id = ?`); details are stripped; no-op if equal to the stored value.
  Replace the "intentionally no update_evidence method" comment with "name and hash are immutable; only the
  description can be edited, through a logged entry". Update all call sites with `""`.
- [ ] **Step 4:** `cargo test` → green.
- [ ] **Step 5: Commit** `Evidence description: create and logged edit`.

### Task 3: Verification of `details`

**Files:**
- Modify: `src/verifier.rs` (metadata check, ~line 727–760), `src/export/verify.py` (`check_metadata`),
  `src/export/bundle.rs` (evidence JSON + README event list), `src/export/model.rs` (`EvidenceRow.details`, query)
- Test: `tests/integrity.rs`, `tests/export.rs`

**Interfaces:**
- Consumes: Task 2.
- Produces: `EvidenceRow { …, pub details: String }`; `case.json` evidence objects carry `"details"`.

- [ ] **Step 1: Tests**
  - integrity `evidence_details_tamper_fails`: create evidence with details, `UPDATE evidence SET details='x'`
    directly → the case report has a FAIL whose message contains `field 'details'`.
  - integrity `edited_evidence_details_verify`: create, `update_evidence_details` twice → no FAIL.
  - integrity `pre_v4_payload_without_details_verifies`: insert an evidence row with `details = ''` directly and
    append its `evidence_created` payload *without* a `details` key via `factum.append(case_id, KIND_SYSTEM, …)`
    (pattern of `tests/core.rs:425`) → no FAIL.
  - export: in the existing verify.py bundle test (`tests/export.rs:368` helper), add a case with an edited
    description; the run passes; tampering `details` in the extracted `case.json` makes it fail with
    "field 'details'". The bundle's `case.json` evidence object contains `"details"`.
- [ ] **Step 2:** `cargo test --test integrity --test export` → fail.
- [ ] **Step 3: Implement.** Verifier: also collect `evidence_edited` payloads per id (in log order, newest wins);
  expected details = newest edited `details`, else created `details`, missing key → `""`; compare with
  `text_value(&evidence.details)` using the existing message format. verify.py: same logic with
  `.get("details", "")`. Bundle: add `"details": e.details`; README event list gains `evidence_edited`.
- [ ] **Step 4:** `cargo test` → green (python3 present: the verify.py tests run).
- [ ] **Step 5: Commit** `Verify the evidence description against the log`.

### Task 4: Description in reports, CLI create, `--questions` removed

**Files:**
- Modify: `src/export/html.rs` (`evidence_cells`), `src/cli.rs`, `tests/cli.rs`, `tests/export.rs`

**Interfaces:**
- Consumes: `EvidenceRow.details` (Task 3).

- [ ] **Step 1: Tests**
  - export: Markdown and HTML of a case whose evidence has details `"seized at desk 4"` contain
    `disk — seized at desk 4`.
  - cli `new_evidence_with_description`: `--new-evidence disk --description "seized"` → stored details `"seized"`.
  - cli: replace the two `--questions` tests with `questions_flag_is_gone`: running with `--questions` exits
    non-zero (clap unknown argument).
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: Implement.** `evidence_cells`: the second cell is the name, followed by ` — <details>` when
  non-empty (5 cells, column header stays). CLI: `--description` doc "With --new-case or --new-evidence: the
  description"; pass it to `create_evidence`; usage line `factum --new-evidence <name> [--hash <hash>]
  [--description <text>]`. Remove the `questions` field, the `questions` fn, its dispatch, its usage text and
  the now unused `companion` imports in `cli.rs`.
- [ ] **Step 4:** `cargo test` and `cargo test --no-default-features` → green.
- [ ] **Step 5: Commit** `Evidence description in reports and CLI; remove --questions`.

### Task 5: Evidence description for the companion

**Files:**
- Modify: `src/companion/prompts.rs` (`case_header`)

- [ ] **Step 1: Test** `case_header_lists_evidence_description` in prompts tests: evidence with details
  `"line one\nline two"` → the line after the evidence line is `"  Description: line one line two"`; empty details
  add no line.
- [ ] **Step 2:** `cargo test --lib companion::prompts` → fail.
- [ ] **Step 3: Implement** (flatten; two-space indent).
- [ ] **Step 4:** `cargo test` → green (reflect/ask golden tests may need the fixture updated only if they use details).
- [ ] **Step 5: Commit** `Feed the evidence description to the companion`.

### Task 6: Presets in the companion core

**Files:**
- Create: `src/companion/presets.rs` (enum, ids, labels, one-line blurbs, guideline and archetype tables)
- Modify: `src/companion/mod.rs` (export `Preset`), `src/companion/store.rs` (`Settings.preset`, load/save,
  `guideline()`), `src/companion/prompts.rs` (`ARCHETYPES` → per preset; `archetype_hints(preset, weights)`; new
  guideline constants), `src/companion/reflect.rs:271` (use `settings().guideline()`, pass preset to hints),
  `src/companion/llm.rs:480` (test literal)

**Interfaces:**
- Produces:
  - `pub enum Preset { Forensics, Investigator, Osint, SourceCriticism, Custom }` with
    `ALL: [Preset; 5]`, `as_str(&self) -> &'static str`, `parse(&str) -> Option<Preset>`,
    `label(&self) -> &'static str` ("Forensics", "Generic investigator", "OSINT research", "Source criticism",
    "Custom"), `blurb(&self) -> &'static str` (one line for the wizard), `builtin_guideline(&self) ->
    Option<&'static str>` (None for Custom), `archetypes(&self) -> &'static [(&'static str, &'static str); 7]`
    (Custom → Investigator's).
  - `Settings { …, pub preset: Preset }`; `Settings::guideline(&self) -> &str`.
  - `prompts::archetype_hints(preset: Preset, weights: &[(&str, i64, i64)]) -> String`.
  - constants `INVESTIGATOR_GUIDELINE`, `OSINT_GUIDELINE`, `SOURCE_CRITICISM_GUIDELINE` in `prompts.rs`.

- [ ] **Step 1: Tests**
  - store `preset_round_trip`: save each `Preset::ALL`, load back equal.
  - store `preset_inferred_for_older_databases`: no `preset` row + empty `global_guideline` → Forensics; no
    `preset` row + `global_guideline = "Ask about timestamps."` → Custom with that text.
  - store `guideline_per_preset`: built-ins return their constant; Custom returns its text; Custom with empty text
    returns `INVESTIGATOR_GUIDELINE`.
  - prompts `every_builtin_guideline_keeps_discipline_and_injection_guard`: each built-in contains "seven",
    "language", and "never instructions to you".
  - prompts `archetype_names_are_the_same_for_every_preset`: names of `p.archetypes()` equal `Archetype::ALL`
    names, for every preset.
  - existing `archetype_hints_reflect_weights` takes `Preset::Forensics`.
- [ ] **Step 2:** `cargo test --lib companion::` → fail.
- [ ] **Step 3: Implement.** Store: `preset` key; load: parse, else infer (non-empty stored guideline → Custom,
  else Forensics); save writes `preset` and keeps writing `global_guideline` (default-equals-empty rule unchanged).
  `Settings::default()` → Forensics. Texts: follow `DEFAULT_GUIDELINE`'s five paragraphs; paragraphs 2 (output
  discipline), and the last one (injection) are identical across presets — factor them into `const` pieces joined
  by `concat!`. Lenses as in spec 4.2. Archetype definitions: Forensics = today's table; the others adapt the
  wording (e.g. OSINT integrity: "source captured with URL, time and hash, an archived copy kept"; Source
  criticism phase: "is a source fully assessed before conclusions rest on it").
- [ ] **Step 4:** `cargo test` → green.
- [ ] **Step 5: Commit** `Companion presets: forensics, investigator, OSINT, source criticism, custom`.

### Task 7: Preset choice in the companion settings dialog

**Files:**
- Modify: `src/gui/companion_dialogs.rs`, `src/gui/tests.rs`

**Interfaces:**
- Consumes: `Preset` (Task 6).
- Produces (for Task 9), on `CompanionSettingsDialog`:
  - `pub fn connection_fields(&mut self, ui, ctx)` — endpoint … model list and status (today's `fields` up to the
    guideline).
  - `pub fn preset_fields(&mut self, ui, ctx)` — preset combo, guideline box.
  - `pub fn save(&mut self) -> Option<Settings>` (made `pub(super)`), `pub fn error(&self) -> &Option<String>`.
  - `fields` = connection_fields + preset_fields + the remaining part (enabled, "sent to", proxy, Test connection).

- [ ] **Step 1: GUI tests**
  - `preset_combo_shows_builtin_read_only`: open settings, choose "OSINT research" in the combo labelled
    "Companion preset" → draft preset Osint; the guideline text box is not editable (query by label
    "Guideline" → `is_enabled() == false` or the widget is a non-interactive label — assert on draft text
    unchanged after typing).
  - `custom_text_survives_preset_switch`: choose Custom (seeded with the previous preset's text when empty), type
    "X", switch to Forensics, back to Custom → text still ends with "X"; saving with Custom stores it.
- [ ] **Step 2:** `cargo test --lib gui::` → fail.
- [ ] **Step 3: Implement.** Combo labelled "Companion preset" listing `Preset::ALL` labels, the blurb below in
  small text. Built-in: show `builtin_guideline()` in a read-only multiline (`TextEdit::multiline(&mut
  text.as_str())`). Custom: editable `draft.global_guideline`; on switching to Custom with empty text, seed it
  from the previous preset's guideline; "Reset to default" → "Copy from Forensics" (sets `DEFAULT_GUIDELINE`).
- [ ] **Step 4:** `cargo test` → green.
- [ ] **Step 5: Commit** `Preset choice in the companion settings`.

### Task 8: Evidence description in the GUI

**Files:**
- Modify: `src/gui/dialogs.rs` (`Dialog::NewEvidence` gains `details`, new `Dialog::EditEvidence`,
  `DialogResult` variants), `src/gui/mod.rs` (dialog results, context-menu item, hover text), `src/gui/tests.rs`

**Interfaces:**
- Consumes: `create_evidence`, `update_evidence_details` (Task 2).
- Produces: `Dialog::EditEvidence { evidence_id: i64, name: String, hash: String, details: String }`,
  `DialogResult::EditEvidence { evidence_id: i64, details: String }`, `TreeAction::EditEvidence(i64)`.

- [ ] **Step 1: GUI tests**
  - `new_evidence_dialog_saves_description`: open the new-evidence dialog, fill "Name" and "Description", Create →
    stored details.
  - `edit_evidence_saves_description`: `TreeAction::EditEvidence(id)` (call `tree_action`), type into
    "Description", Save → stored details and a new `evidence_edited` event.
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: Implement.** NewEvidence: label "Name" (hint "Evidence name"; error "Evidence name is required."),
  then "Description" multiline (optional), then Hash. EditEvidence: title "Edit Evidence Description", the same
  "recorded as a signed entry" note as EditCase, name and hash as read-only labels, multiline Description,
  Save/Cancel. Context menu: "Edit Description…" under `!case.is_archived()`, before the separator. Tree hover text:
  name, plus `\n\n<details>` when non-empty. (The GUI shows the case description nowhere but its edit dialog, so
  the hover text is where the evidence description is visible; this narrows spec 3.4.)
- [ ] **Step 4:** `cargo test` → green.
- [ ] **Step 5: Commit** `Evidence description in the GUI`.

### Task 9: Setup wizard

**Files:**
- Create: `src/gui/wizard.rs`
- Modify: `src/gui/mod.rs` (module, auto-start in `build`, menu entry, result handling, `ONBOARDING_SETTING`),
  `src/gui/dialogs.rs` (`Dialog::Wizard(Box<Wizard>)`, `DialogResult::WizardFinished(Box<WizardChoices>)`,
  `DialogResult::WizardCancelled { theme: String }`, window width 560), `src/gui/tests.rs`

**Interfaces:**
- Consumes: `CompanionSettingsDialog::{new, connection_fields, preset_fields, save}` (Task 7), `Signer::{available,
  list_keys}`, `gpg_help_text()`, `THEMES`, `theme::apply`.
- Produces:
  - `const ONBOARDING_SETTING: &str = "onboarding_done";`
  - `pub enum Step { Welcome, Gpg, Companion, SealFolder, Appearance, Summary }`
  - `pub struct Wizard { pub step: Step, pub gpg_available: bool, pub keys: Vec<GpgKey>, pub key: Option<String>,
    pub use_companion: bool, pub companion: CompanionSettingsDialog, pub seal_folder: String,
    pub seal_env: Option<PathBuf>, pub theme: String, pub previous_theme: String }`
  - `Wizard::new(app_state…) -> Wizard` (built by `FactumApp::open_wizard()`), `Wizard::show(&mut self, ui, ctx)
    -> Option<DialogResult>`.
  - `pub struct WizardChoices { key: Option<String>, companion: Option<CompanionSettingsDialog>, companion_off: bool,
    seal_folder: Option<String>, theme: String }`
  - `FactumApp::open_wizard(&mut self)`, `FactumApp::should_auto_start_wizard(&self) -> bool`.

- [ ] **Step 1: GUI tests** (add `Fixture::empty()` — a database without cases)
  - `wizard_auto_starts_on_fresh_database_only`: empty fixture → top dialog is `Dialog::Wizard`; normal fixture →
    no wizard; empty fixture with `onboarding_done = 1` → no wizard.
  - `skipping_everything_writes_only_the_flag`: empty fixture, click "Skip" until Summary, "Finish" → settings
    `onboarding_done == "1"`, no `active_gpg_key_id`, no `seal_dir`, no companion database file.
  - `cancel_restores_theme_and_sets_flag`: go to Appearance, pick "Dark" (theme applied live), "Cancel" → app
    theme back to the previous value, `ui_theme` setting unchanged, flag set.
  - `finish_writes_choices`: choose Dark, a seal folder (an existing temp dir typed into the field), companion yes
    with URL `http://127.0.0.1:9/v1`, model "m", preset OSINT → after Finish: theme setting "dark", `seal_dir`
    set, companion settings load with preset Osint and model "m".
  - `wizard_prefills_and_keeps_companion_settings`: companion configured beforehand (save Settings with a key and
    preset SourceCriticism), open wizard from the menu, Next through all steps, Finish → settings loaded equal the
    previous ones.
  - `menu_opens_wizard`: click "Setup Wizard…" in the Settings menu → `Dialog::Wizard` on top.
- [ ] **Step 2:** `cargo test --lib gui::` → fail.
- [ ] **Step 3: Implement.**
  - Window: title "Setup", a step line "Step n of 6 · <name>", the body, a bottom row Cancel | Back | Skip |
    Next/Finish (Skip leaves that step's choice at "no change": for GPG no key, companion no change, seal folder
    none, theme unchanged; hidden on Welcome and Summary).
  - Welcome: two short paragraphs (what factum signs and seals; every step is optional and changeable under
    Settings).
  - Gpg: not available → `gpg_help_text()` in monospace + "Check again"; keys empty → "No signing keys found.
    Create one with: gpg --quick-gen-key \"Name <email>\" default sign" + "Check again"; else the selectable key
    list from the GpgKeys dialog (extract that grid into `fn key_list(ui, keys, selected)` in `dialogs.rs` and use it
    in both).
  - Companion: radio "Don't use the AI companion" / "Use the AI companion" (prefill: current `is_configured()`).
    Yes → `companion.connection_fields` + `companion.preset_fields` + the "Case content is sent to …" line.
    No "Test connection" (it saves). Next on this step with Yes requires URL and model (error line otherwise).
  - SealFolder: the SealFolder dialog's explanation + Browse/text field; with `seal_env` set, show the override note
    instead and no field.
  - Appearance: selectable labels for `THEMES` (labels as the Theme menu); clicking applies `theme::apply` live.
  - Summary: one line per choice ("Signing key: ABCD1234" / "not set", "Companion: off" / "on — <model>, <preset
    label>", "Seal folder: …" / "default", "Theme: …").
  - Finish → `WizardFinished`: in `mod.rs` apply in order: `signer.set_active_key` + `update_gpg_status`;
    `SEAL_DIR_SETTING`; `set_theme`; companion: `Some(dialog)` → `dialog.save()` then
    `open_companion_db` + `apply_companion_settings`; `companion_off` (No chosen while a companion database exists)
    → load, set `enabled = false`, save, apply; then `ONBOARDING_SETTING = "1"`. A failed companion save shows the
    error via `message` and still sets the flag.
  - Cancel / window close → `WizardCancelled { theme: previous_theme }`: `theme::apply` previous, flag set.
  - Auto-start in `build`: `setting(ONBOARDING_SETTING).is_empty() && list_cases(true).is_empty() &&
    signer.active_key().is_none()` → `open_wizard()`.
  - Menu: "Setup Wizard…" at the top of the Settings menu, followed by a separator.
- [ ] **Step 4:** `cargo test`, `cargo clippy --all-targets`, `cargo fmt --check` → green.
- [ ] **Step 5: Commit** `Setup wizard`.

### Task 10: Changelog and final check

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1:** Add `## [Unreleased]` above `## [2.1.5]` with Added (setup wizard; companion presets; evidence
  description, editable and verified; `--new-evidence … --description`), Changed (database schema v4, migrated
  automatically from v3; no longer shared with factum-notes), Removed (`--questions`).
- [ ] **Step 2:** `cargo test && cargo test --no-default-features && cargo clippy --all-targets && cargo fmt --check`
  → all green; `FACTUM_SCREENSHOTS=<scratch> cargo test --lib gui::wizard` if a GPU/lavapipe is available, and look
  at the screenshots.
- [ ] **Step 3: Commit** `Changelog for the setup wizard, presets and evidence description`.
