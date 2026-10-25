# Porting notes (factum-notes → factum)

The port keeps the behaviour, data formats and messages of factum-notes. Where it differs, it is listed here.

## Identical

- Database schema 3, all SQL, transaction boundaries and the append retry logic (three attempts when another
  process appends while signing)
- Canonical JSON (byte-identical to `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`), leaf
  data, tree hashes (RFC 9162), signed payloads, seal payloads and seal file names
- Verification: every finding code and message, including the metadata checks and late signatures
- Exports: HTML and Markdown reports, `case.json` (like `json.dumps(indent=2, sort_keys=True)`), signature file names,
  manifest, the unchanged `verify.py`
- CLI options, output and exit codes; log messages on stderr in Python's `LEVEL:root:message` format
- Configuration: `.env` files, `FACTUM_DB`, `FACTUM_SEAL_DIR`, `LOG_LEVEL`, the same per-user folders
- GPG: the system `gpg` with `--status-fd`, as python-gnupg used it (keyring, trust model and pinentry unchanged)

Cross-checked: a database written by factum verifies with factum-notes and the other way round, including signed
notes and corrections from both; bundles from factum pass `verify.py`.

## Different

| factum-notes | factum | Why |
|---|---|---|
| PySide6 (Qt) GUI | egui GUI, redesigned | a single self-contained binary; no Qt runtime |
| PDF via Qt's HTML renderer | own PDF writer with embedded fonts | no Qt, works offline and headless |
| QFileSystemWatcher on the database files | polling `PRAGMA data_version` every 0.75 s | the same effect without file watchers |
| cases and evidence only from the GUI | `--new-case`, `--new-evidence` | headless and air-gapped use (decided in review) |
| no way to edit case details in the GUI | Edit Case… | `update_case` existed without a UI (decided in review) |
| Remove Label asks for the name | pick the label from a submenu | (decided in review) |
| PyInstaller workaround for `LD_LIBRARY_PATH` | not needed | Rust binaries do not bundle shared libraries |
| ⚙ before system entries | ◇ | the embedded fonts have no ⚙ |

Unicode details follow Python where it matters: `str.strip()`/`splitlines()` semantics (`pystr.rs`), `\w` in tags and
file names. Rust's regex engine treats a few rare combining characters as word characters where Python does not.
