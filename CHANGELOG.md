# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [2.3.0] - 2026-10-27

### Changed
- Companion: every pass restates the open questions. A question whose context changed is reworded in place (it
  keeps its place, rating and history); one the pass leaves out is withdrawn, unless rated plus. The model answers
  with one `questions` list instead of separate answered, withdraw and new lists
- Companion: a full question list no longer freezes: a new question replaces the oldest one that is neither rated
  plus nor reworded in the pass
- Companion: a full pass runs on the first pass of a case, every tenth pass and on Re-think; the extra full passes
  after a pass that closed three questions or after three passes that closed none are gone
- GUI: the QUESTIONS heading collapses and expands the questions

## [2.2.0] - 2026-10-27

### Added
- Setup wizard: on the first start with a new database (no cases, no signing key) it guides through the GPG signing
  key, the AI companion (optional), the folder for seal copies and the theme; every step can be skipped, nothing is
  saved before Finish, and **Settings → Setup Wizard…** runs it again
- Companion presets, an app-wide choice of the guideline the companion asks through: Forensics (the previous
  default, unchanged), Generic investigator, OSINT research, Source criticism, and Custom (an own guideline). A
  database with an edited guideline keeps it as Custom
- Evidence description: a free-text description beside the evidence name, set on creation (GUI, or
  `--new-evidence <name> --description <text>`) and editable later through a signed `evidence_edited` entry. It is
  checked by verification and by the bundled `verify.py`, shown in the reports and the bundle, and read by the
  companion

### Changed
- Database schema 4: a schema 3 database is upgraded in place on first open (adds the evidence description);
  factum-notes (Python) cannot open it afterwards
- GUI: the evidence dialog names the first field "Name"

### Removed
- `factum --questions`: the companion has no command-line surface any more; its questions are in the GUI

## [2.1.5] - 2026-10-26

### Changed
- Companion: when all seven questions are open and three diff passes in a row closed none of them, the next pass
  rereads the whole case, so a full list no longer stays stuck until the tenth pass
## [2.1.4] - 2026-10-26

### Fixed
- GUI: at a small height the note editor reached into the Add Note button below it

## [2.1.3] - 2026-10-26

### Changed
- GUI: the note editor at the bottom can be resized by dragging its top edge (the height is remembered), and a longer
  note scrolls inside it instead of pushing the buttons off screen

## [2.1.2] - 2026-10-26

### Changed
- Companion: the default guideline describes its forensic lens without naming the guide it is drawn from
- Companion: the `+` / `−` buttons on a question are quieter, and a question rated `+` shows it

### Fixed
- GUI: a dialog opened after a taller one (e.g. Case goal after Companion Settings) kept the taller height, with its
  buttons floating in the middle

## [2.1.1] - 2026-10-26

### Fixed
- GUI: Ctrl+C, Ctrl+V and the copy buttons use the system clipboard again; the GUI was built without it, so text could
  only be copied and pasted within factum

## [2.1.0] - 2026-10-26

### Added
- Analytical companion: an optional, LLM-backed mentor that keeps a short list of open analytical questions per case
  (Companion → Settings…, per-case switch and case goal in the Case menu, questions in the side panel, Ask and
  History). Its state lives in a separate `*.companion.db`; nothing it writes enters the log, exports or verification
- `factum --questions [CASE]` lists the open questions of a case without creating anything
- `FACTUM_COMPANION_API_KEY` overrides the stored API key

### Changed
- GUI: the notes are a flat log separated by hairlines instead of boxed cards; the focused and the pinned note are
  marked by a bar on the left. Tighter padding fits more entries on screen; corners are square or 2 px

## [2.0.0] - 2026-10-25

First release of the Rust port of factum-notes. Databases (schema 3), seal files and verification bundles are
compatible with factum-notes in both directions; the bundled `verify.py` is unchanged.

### Added
- Single self-contained binary with CLI and GUI for Linux (glibc 2.28+), macOS and Windows, plus a static
  command-line-only Linux build
- `factum --new-case FILE_NO [NAME] [--description D]` and `factum --new-evidence DESCRIPTION [--hash H]`: cases and
  evidence can be created without the GUI (headless and air-gapped machines)
- GUI: **Edit Case…** (file number, name, description) through a signed `case_edited` entry
- GUI: **Remove Label** offers the note's labels to pick from instead of asking for the name
- Installers: `install.sh` (Linux/macOS, `curl | sh`) and `install.ps1` (Windows), both checking `SHA256SUMS`, with
  an offline `--archive` mode; air-gapped installation guide and a vendored source archive for offline builds
- Release builds with SHA-256 checksums and build provenance attestations

### Changed
- New GUI built with egui instead of Qt: a calmer, readability-focused design (Atkinson Hyperlegible Next and
  JetBrains Mono, off-white/off-black themes, color-blind-safe status colors with symbols)
- PDF reports are rendered by factum itself (A4, embedded fonts, searchable text) instead of Qt; no extra software
  needed
- The GUI picks up changes from the command line by polling the database instead of watching its files
- Signature marks of system entries use ◇ instead of ⚙

[Unreleased]: https://github.com/overcuriousity/factum-rs/compare/v2.1.4...HEAD
[2.1.4]: https://github.com/overcuriousity/factum-rs/compare/v2.1.3...v2.1.4
[2.1.3]: https://github.com/overcuriousity/factum-rs/compare/v2.1.2...v2.1.3
[2.1.2]: https://github.com/overcuriousity/factum-rs/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/overcuriousity/factum-rs/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/overcuriousity/factum-rs/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/overcuriousity/factum-rs/releases/tag/v2.0.0
