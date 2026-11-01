# Full code review fixes (2026-10-29)

Source: a full review of factum-rs 2.7.1 by eight area reviewers, plus a first-round review of the 2.7.0..2.7.1
changes. Each task below lists its findings with file:line (as of b1e7379), the defect, the scenario and the fix
direction. File:line numbers are hints; re-locate code before editing.

There is no separate spec. The user's decisions below are binding. Where the plan leaves a choice open, pick the
smallest change that removes the defect while keeping on-disk formats compatible.

## Global Constraints

- Work in the worktree `/home/user01/Projekte/factum/factum-rs-review-fixes` on branch `review-fixes`. Never push.
- Formats shared with the Python factum-notes (seal files, bundle layout, canonical JSON, case log payloads) stay
  compatible. Containers already written by 2.7.x must still open and verify.
- The target machines are air-gapped: add no feature that needs the internet.
- Code reads like the surrounding code: same comment density, naming and idiom (the project uses short lowercase
  comments, `FactumError::general(...)`, `Result<T>` from `crate::error`).
- The user prefers a minimal UI: icons with short tooltips, no extra dialogs unless a decision below says so.
- Tests: add a focused regression test for each behavioural fix (in the existing test file for that area). While
  working, run only the targeted tests (`cargo test --test <file> <name>` or `cargo test --lib <path>`). Do NOT run
  the full suite; the controller runs it once at the end. `cargo build` (with default features) and
  `cargo clippy --all-targets` must stay clean of new warnings.
- Add one line per user-visible change to the `## Unreleased` section at the top of CHANGELOG.md (create the section
  if it is missing, matching the existing entry style). Update README.md or docs/ where documented behaviour changes.
- Commit per logical fix group with a short imperative subject in the existing style (e.g. "Verifier: ...",
  "GUI: ..."). End every commit message with the line:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`

## User decisions (binding)

1. Seal folder: the setting moves out of the database into the user config `.env` (`FACTUM_SEAL_DIR` in
   `config::user_config_dir()/.env`). The GUI writes it there. A value still in the DB `settings` table is migrated
   once (written to the user config if none is set there) and then ignored by the verifier. Every verify report
   states which seal folder was checked. Changing the seal folder is recorded in the case log of each open case (a
   system entry), or, if that is too invasive, in the application log; record which you chose in the report.
2. Bundle verifier trust: `verify.py` prints its own SHA-256 at start. `factum --version` prints the SHA-256 of the
   embedded verify.py (and of verify_container.py). The bundle README tells readers to run a trusted copy of
   verify.py or to compare the printed hash with `factum --version` / the release notes.
3. PDF unsupported scripts: no new fonts. Characters neither embedded font has render as a visible placeholder
   glyph; copy/search (ToUnicode or ActualText) returns the real characters; the export reports a warning that the PDF
   cannot show these characters and that the HTML report shows them.
4. CLI case/evidence lookup: an exact file number or name match wins; a plain number is treated as an id only when
   nothing matches by name/number; an ambiguous match is an error that lists the candidates; `#12` always means id 12.
   `_` is no longer stripped.
5. `.env` in the current directory is no longer read. Only the user config `.env` and real environment variables.
   README updated. The CLI prints which database it uses when FACTUM_DB is set (to stderr, one line).
6. IOC TLDs: exclude only suffixes that are not real TLDs (exe, dll, txt, pdf, doc, ...). Real TLDs such as zip, mov,
   app, sh, py, md become domain IOCs.
7. Dialogs with typed text: once the text differs from its start value, Escape and backdrop clicks do nothing; only
   Cancel (or the dialog's own button) closes. No confirm dialog.
8. Duplicate case file numbers: refused when an open case already uses the number; archived cases may share it.

---

