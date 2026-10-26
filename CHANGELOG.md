# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Companion: the default guideline describes its forensic lens without naming the guide it is drawn from

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

[Unreleased]: https://github.com/overcuriousity/factum-rs/compare/v2.1.1...HEAD
[2.1.1]: https://github.com/overcuriousity/factum-rs/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/overcuriousity/factum-rs/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/overcuriousity/factum-rs/releases/tag/v2.0.0
