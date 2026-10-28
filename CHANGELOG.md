# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.7.0] - 2026-10-28

### Added
- Markdown in notes: a toolbar above the note field and the correction dialog (bold, italic, code, link, heading,
  list, quote); notes are shown formatted in the log and in HTML, Markdown and PDF reports, with a source toggle on
  each note in the log
- Images in notes: paste a screenshot (when the clipboard has no text), drop image files on the window or insert them
  with Image…; thumbnails show what the note will be saved with. The images are part of the note's signed payload,
  shown inline in the log and exported with the reports. Correcting a note, in the GUI or with `--correct`, keeps the
  images the corrected text still refers to. On Wayland, pasting an image depends on the compositor offering
  clipboard data control (not verified; GNOME likely does not); inserting from a file always works

### Changed
- Existing notes are shown as Markdown too, so some read differently than before: `__init__` turns bold, lines
  starting with `* x` or `1.` become lists. The source toggle in the log (and the source block in HTML reports) shows
  the note exactly as signed

## [2.6.0] - 2026-10-28

### Added
- Evidence containers: preserve files and folders (from a mounted image or an export folder) with their original
  path, timestamps, size and MD5, SHA-1 and SHA-256 in a standard AFF4-L v1.0 container (`.aff4l`). Create, add to,
  close and reopen them from the Case menu or the case list, like X-Ways evidence file containers; options for the
  base path, keeping only file names, metadata only and an excerpt of one file. Progress and Cancel in the status bar
- Every creation, addition, close, reopen and late signature of a container is a signed entry in the case log;
  an addition also lists what was chosen but not added (unreadable, changed while read, special files) and why.
  Archiving a case asks to close its open containers first
- Close Without File…: an open container whose file is lost can be closed without it (logged as such; nothing is
  signed or written), so its case can still be archived
- Closing signs a container with GPG, and with X.509 (gpgsm) when Settings → X.509 Certificate… (or the setup wizard)
  names a certificate; unsigned closes can be signed later with Sign All Unsigned. Every closed state is kept inside
  the container, so an earlier copy still verifies
- Verify Container…: stored files against their hashes, metadata, GPG and X.509 signatures, every closed state and
  the case log; AFF4-L v1.0 checks for other tools' containers
- `verify_container.py` inside every container, for recipients without factum (Python 3, `gpg`, `openssl`)
- Reports list each container with its files

## [2.5.0] - 2026-10-27

### Added
- GUI: typing a #tag in the note field suggests the tags and labels already in use, in a short list above the line
  (ranked like Add Label; labels that cannot be written as a #tag are left out): ↑ ↓ choose, Tab or a click completes
  it, Escape closes the list; Enter still starts a new line

### Fixed
- Labels follow a corrected note to its new version, like its pin; before, they stayed on the earlier version, out of
  view and out of the label filter. A label the corrected text already carries as a #tag is dropped

## [2.4.0] - 2026-10-27

### Added
- GUI: Add Label suggests the tags and labels already in use as you type, in a list under the field: matches at the
  start first, then anywhere in the name, then names a typo or two away (a swapped pair of letters counts as one);
  ↑ ↓ choose, Tab completes, Enter or a click adds

### Changed
- GUI: the case log is one centred column (search, log and note input share its width), so lines keep their length
  on wide screens; every entry, system entries included, starts with its full timestamp in one column and ends with
  its signature mark (✓ ⚠ ✗ ○), the state in its tooltip
- GUI: note actions (pin, correct, more) are small icons that show under the pointer; a corrected note's version chip
  (v2) shows and hides the earlier versions; the evidence name sits in the note's header line
- GUI: icons (Phosphor, embedded) with short tooltips naming them and their shortcut replace text buttons: + for a new
  case above the case list and for new evidence on a case row, ⋯ menus, the side panel toggle, copy, folder pickers
- GUI: the case list has no buttons below it; archived cases are behind "n archived" at its end; a database without
  cases shows a New case button in the log area; the case list can be resized
- GUI: the note input names its target under the editor, warns with ⚠ when notes will go unsigned and adds with
  Add; an archived case shows a read-only line with Reopen instead
- GUI: the status bar shows the selected case's size, its newest seal and the outcome of its last verification, and
  the signing key
- GUI: the Companion menu moved into Settings (Companion…), the GPG submenu became Signing Key… and Clear Signing Key;
  Case → Edit Evidence… added
- GUI: dialogs have more room, their main action on the right in the accent colour (destructive ones in red) and
  named confirmations (Archive, Delete) instead of Yes/No; Verify Case, Ask and History open centred with a close button
- GUI: Verify Case leads with a verdict line counting failures and warnings, then the entry count, tree size and root
  hash (with copy); rows show and sign through icons
- GUI: companion questions are rated with thumbs up and down; the companion settings are grouped (Connection,
  Model, Preset) with User-Agent and extra headers under Advanced; the setup wizard shows all its steps
- GUI: shorter tooltips throughout
- GUI: the signing key list (setup wizard, Settings → Signing Key…) has one clickable row per key with a radio mark,
  the key's algorithm, creation and expiry date (expired and revoked keys marked), its fingerprint and all user IDs in
  the tooltip; it scrolls when there are more keys than fit
- Setup wizard: less text on each step; the companion presets show only the chosen one's description, and a
  built-in guideline is folded away
- Setup wizard and Settings → Seal Folder…: they explain what a seal is, and the field starts with the folder the
  seals go to now (the default one next to the database included); choosing the default stores no setting, so it
  keeps following the database
- Setup wizard: it starts by asking whether notes have to be provable (who wrote them, nothing changed or removed);
  "Not now" leaves out the signing key and seal folder steps, both stay under Settings

### Fixed
- GUI: in a narrow window a note's header ran under its signature state; it now wraps
- GUI: Verify Case said "0 WARN" above a list of six warnings (it counted entries, the list findings)
- GUI: the model list button in the companion settings stuck out past the other fields
- GUI: the text field of Correct Note had no accessible name
- GUI: Enter in New Case, New Evidence and Add Label did not submit: the field took the keyboard back in the same frame
- GUI: Verify Case, Ask and History moved while their content grew

## [2.3.1] - 2026-10-27

### Changed
- Companion: at most three questions are open at a time (was seven). A case with more is trimmed on its next pass:
  the oldest ones that are neither rated plus nor reworded are withdrawn

### Fixed
- Companion: questions were kept unchanged and new ones added until the list was full, after which it froze. The
  instruction asked the model to list every open question, unchanged where it saw fit; it now asks for each kept
  question as it should read now. A full list no longer freezes: a new question replaces the oldest one that is
  neither rated plus nor reworded in the pass

## [2.3.0] - 2026-10-27

### Changed
- Companion: every pass restates the open questions. A question whose context changed is reworded in place (it
  keeps its place, rating and history); one the pass leaves out is withdrawn, unless rated plus. The model answers
  with one `questions` list instead of separate answered, withdraw and new lists
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
