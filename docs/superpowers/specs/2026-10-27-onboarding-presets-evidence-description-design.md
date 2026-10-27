# Setup wizard, companion presets, evidence description: design

Date: 2026-10-27. Status: approved in conversation, awaiting review of this written spec.

## 1. Intent

Three features that make factum easier to start with and give the companion more to work with:

1. A setup wizard that runs on the first start of a fresh database (and on demand) and guides step by step through
   the GPG signing key, the optional AI companion, the external seal folder and the theme.
2. Companion presets: an app-wide choice of system prompt (guideline) for the companion. Forensics (today's text),
   generic investigator, OSINT research, source criticism, and custom.
3. A free-text description on evidence items, like the case description, editable later and fed to the companion.

Also in scope: removing the companion's only CLI surface (`--questions`), so the companion is GUI-only.

## 2. Decisions taken in conversation

| Topic | Decision |
|---|---|
| Evidence description storage | New column plus factum's first migration (v3 → v4). Python factum-notes schema compatibility is given up. |
| Evidence description editing | Like the case description: editable later, every edit is a signed system entry. Name and hash stay immutable. |
| Preset model | Built-in read-only presets plus `Custom` (editable text). Built-in texts improve with factum updates. |
| Fourth preset | Source criticism. |
| GPG step | Detect gpg and pick an existing signing key. No key generation in factum. |
| Wizard steps | Welcome, GPG, Companion (opt-in), Seal folder, Appearance, Summary. |
| Auto-start | Only on a fresh database: no `onboarding_done` flag, no cases, no active GPG key. Always available from the menu. |
| CLI and companion | The companion gets no CLI surface; the existing read-only `--questions` flag is removed. |
| CLI and evidence description | `--new-evidence <name> [--hash H] [--description D]`; editing stays GUI-only, as for cases. |

## 3. Evidence description

### 3.1 Storage and migration

- The existing `evidence.description` column keeps its meaning, the evidence *name*, and keeps its key
  `description` in signed payloads and bundle JSON. Renaming it would break verification of logs already signed.
- New column `evidence.details TEXT NOT NULL DEFAULT ''`. In the `Evidence` struct: `pub details: String`,
  appended to `Evidence::COLUMNS`. A doc comment on `description` states that it is the name.
- `SCHEMA_VERSION` becomes 4. `SCHEMA` (fresh databases) contains the column.
- `Db::initialize_schema` gains a migration step: `user_version == 3` → in one transaction
  `ALTER TABLE evidence ADD COLUMN details TEXT NOT NULL DEFAULT ''; PRAGMA user_version = 4`. Any other
  version than 0 (empty), 3 or 4 is refused with the existing message. The comment "Schema-compatible with
  factum-notes (Python)" is replaced by a note that v4 diverged.

### 3.2 Service

- `create_evidence(case_id, name, evidence_hash, details)`: `details` is stripped, optional, and written to the row
  and to the `evidence_created` payload as `"details"`. The system entry text is unchanged.
- New `update_evidence_details(evidence_id, details)`: refuses a missing or deleted evidence item and an archived
  case. Appends a system entry `Evidence #N description edited: <name>` with payload
  `{"event": "evidence_edited", "evidence_id": N, "details": "<text>"}`; the row is updated on commit, as
  `update_case` does. An unchanged text is a no-op (no entry).
- The comment "intentionally no update_evidence method" is updated: name and hash stay immutable.

### 3.3 Verification

- `verifier.rs` metadata check: for each evidence row, `details` must equal the `details` of the newest
  `evidence_edited` event for that id, else of its `evidence_created` event. A payload without `details` counts
  as `""`, so logs written before v4 still verify.
- The bundled `src/export/verify.py` does the same over `case.json`.
- `bundle.rs` writes `"details"` into each evidence object of `case.json`; the bundle README lists the new event
  `evidence_edited`.

### 3.4 Surfaces

- GUI: the "New evidence" dialog labels the first field **Name** and adds a multiline **Description** (optional).
  A new "Edit evidence…" action (context menu of an evidence item in the side panel) opens a dialog that shows
  name and hash read-only and edits the description. Disabled for archived cases and deleted evidence.
- GUI: the evidence description is shown where the case description is shown for cases (header area of the
  selected evidence), when non-empty.
- CLI: `--new-evidence` accepts `--description`; help text updated. `--list-evidence` is unchanged.
- Exports (HTML, Markdown, PDF): the evidence table/list gets the description.
- Companion: `prompts::case_header` adds an indented `Description: …` line after an evidence line when non-empty.

## 4. Companion presets

### 4.1 Model

```rust
pub enum Preset { Forensics, Investigator, Osint, SourceCriticism, Custom }
```

- Stored ids: `forensics`, `investigator`, `osint`, `source_criticism`, `custom`. Stored in the companion
  database's `settings` table under `preset`.
- `Settings` gains `pub preset: Preset`. `global_guideline` remains and is used only when `preset == Custom`.
- Loading a database without a `preset` row: a non-empty stored `global_guideline` → `Custom`, else
  `Forensics`. Current behaviour is unchanged for every existing user.
- `Settings::guideline() -> &str`: the preset's built-in text, or for `Custom` the stored text (falling back to
  the Investigator text if empty). `reflect.rs` uses it instead of reading `global_guideline` directly.

### 4.2 Texts

- `prompts.rs` keeps `DEFAULT_GUIDELINE` as the Forensics text, unchanged, and adds `INVESTIGATOR_GUIDELINE`,
  `OSINT_GUIDELINE`, `SOURCE_CRITICISM_GUIDELINE`. Each keeps the same structure: role, output discipline (same
  paragraph), the lens (preset-specific), the three jobs of a question, what not to ask, and the prompt-injection
  paragraph (same).
- Lenses in brief:
  - Investigator: the core questions (what, where, when, how, who, why), support and refute every thesis,
    documentation, sources of each fact, next sensible step. No forensic-specific vocabulary.
  - OSINT: source provenance and capture (URL, time, archived copy, hash of the capture), pivoting between
    identifiers, attribution confidence, operational security of the researcher, legal and ethical limits.
  - Source criticism: provenance and authenticity of each source, reliability and possible bias of its author,
    proximity to the event, independent confirmation, internal consistency, contradictions between sources.
- The seven archetype names stay fixed (they are persisted and drive rating weights). Each built-in preset has its
  own seven one-line definitions; `Custom` uses the Investigator definitions. `archetype_hints` takes the preset.

### 4.3 Settings dialog

- A preset combo box above the guideline.
- Built-in preset: its guideline is shown read-only.
- `Custom`: the box is editable; switching to `Custom` with an empty custom text seeds it with the previously
  selected preset's text. "Reset to default" becomes "Copy from preset" for `Custom`.

## 5. Setup wizard (GUI)

### 5.1 Structure

- New module `src/gui/wizard.rs`: `Wizard { step: Step, draft: WizardDraft, … }`, shown as one modal window with a
  step indicator and Back / Skip / Next (Finish on the last step) / Cancel.
- `Step`: `Welcome`, `Gpg`, `Companion`, `SealFolder`, `Appearance`, `Summary`.
- The companion connection form (endpoint, protocol, key, user agent, headers, model list with its listing
  worker, context window) moves out of `CompanionSettingsDialog` into a reusable widget used by both.

### 5.2 Steps

1. Welcome: what factum does, what the wizard will set, that every step can be skipped and changed later.
2. GPG: shows the gpg status. Missing gpg → the OS-specific install hint and a "Check again" button. Otherwise the
   list of signing keys (as in the key picker) to choose one, the current key preselected; with no keys, a short
   note on creating one with `gpg --quick-gen-key` and "Check again".
3. Companion: "Use the AI companion?" yes / no (default no on a fresh setup, current state otherwise). Yes → the
   connection form and the preset choice with a one-line description of each preset.
4. Seal folder: optional folder picker with the explanation from the existing seal-folder dialog. If
   `FACTUM_SEAL_DIR` is set, a note says it overrides this setting.
5. Appearance: theme (system, light, dark), previewed live; Cancel restores the previous theme.
6. Summary: every choice in a list; Finish applies.

### 5.3 Applying

- Nothing is written before Finish. Cancel discards the draft (and restores the theme).
- Finish writes, in order: active GPG key, seal folder, theme, companion settings (only when the companion was
  chosen; a declined companion on a fresh setup creates no companion database; declining with an existing
  companion sets it disabled), then `onboarding_done = 1` in the main database. The app then reloads the
  affected state as the existing dialogs do (`update_gpg_status`, `apply_companion_settings`).
- Cancel also sets `onboarding_done = 1`, so an auto-started wizard is not shown again.

### 5.4 Starting

- Automatically at startup when `onboarding_done` is unset, the database has no cases and no active GPG key.
- Menu entry "Setup wizard…" in the same menu as the other settings; it pre-fills the current values.

## 6. Removal of `--questions`

The `--questions` flag, its `questions` function, its help text and its tests in `tests/cli.rs` are removed.

## 7. Testing

- db: a v3 database with evidence is migrated to v4, data kept, `details` empty; versions 1–2 still refused.
- core: create with details (row and payload), edit writes `evidence_edited`, unchanged edit is a no-op, edit
  refused on archived case and deleted evidence.
- verifier and verify.py: tampering with `details` in the database fails; an old-style payload without `details`
  passes; an edited description passes.
- export: description appears in Markdown/HTML and in `case.json`.
- companion store: preset round trip; inference for databases without `preset`; `guideline()` per preset.
- prompts: each built-in guideline has the output discipline and injection paragraphs; `case_header` shows the
  evidence description.
- cli: `--new-evidence X --description D` stores it; `--questions` is rejected as unknown.
- gui (kittest): auto-start on a fresh database and not with cases or with the flag set; walking through the
  wizard with skips writes only the flag; Finish writes the chosen settings; Cancel restores the theme; the
  evidence edit dialog saves.

## 8. Housekeeping

A CHANGELOG entry under a new "Unreleased" section. No version bump.
