# Porting notes (factum-notes → factum)

The port keeps the behaviour, data formats and messages of factum-notes. Where it differs, it is listed here.

## Identical

- Database schema 3 (up to factum 2.1), all SQL, transaction boundaries and the append retry logic (three attempts when another
  process appends while signing)
- Canonical JSON (byte-identical to `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`), leaf
  data, tree hashes (RFC 9162), signed payloads, seal payloads and seal file names
- Verification: every finding code and message, including the metadata checks and late signatures (codes added, see
  below)
- Exports: HTML and Markdown reports (one line added, see below), `case.json` (like `json.dumps(indent=2, sort_keys=True)`), signature file names,
  manifest, the unchanged `verify.py`
- CLI options, output and exit codes (one line added to `--verify`, see below); log messages on stderr in Python's
  `LEVEL:root:message` format
- Configuration: `FACTUM_DB`, `FACTUM_SEAL_DIR`, `LOG_LEVEL`, the same per-user folders and user config `.env`
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
| database schema 3 | schema 4 since factum 2.2 (adds `evidence.details`; schema 3 is upgraded on open) | evidence descriptions |
| `.env` read from the user config and the current directory | only from the user config | the start folder must not change the database |
| GUI seal folder stored in the database (`settings.seal_dir`) | stored as `FACTUM_SEAL_DIR` in the user config `.env`; on the first start the value of the database opened then is moved there, later no database is read | the verifier must not learn from the database it checks where the external seal copies are |
| unreadable seal files skipped silently | WARN `seal_file_unreadable` naming the file; a `.asc` replaces its `.json` only when it is a valid seal | a broken copy must not hide a seal |
| a seal folder in the database is what the verifier checks | WARN `seal_dir_unused` when a folder still stored in the database differs from the one in use; the stored folder is only named, never read | a real folder that was not moved must not go unnoticed, and a tampered database can plant no more than a hint |
| `--verify` and the HTML/Markdown/PDF reports do not say where seal files were looked for | `  seal folder checked: <path>` after the `--verify` summary; `Seal folder checked: <path>` in the reports' verification section | every verify report names the seal folder it checked (decided in review) |
| EXPKEYSIG (good signature, key expired since) is invalid | valid with WARN `key_expired` if made before the expiry; gpg gives no trust level for an expired key, so it counts as trusted only with ultimate owner trust, else `key_untrusted` | a key expiring must not invalidate what it signed |
| a signature counts on the last GOODSIG line | exactly one GOODSIG/EXPKEYSIG with one VALIDSIG, no BADSIG/ERRSIG/FAILURE, exit code 0; the same in `verify.py` | a second signature or a trailing bad one must not pass |
| the signing subkey's fingerprint in reports | the primary key's fingerprint; a signing subkey also in the entry's integrity lines | one key, one fingerprint; unchanged for a primary key |
| a malformed cell stops verification | FAIL `malformed` per cell, the report is still produced | one tampered cell must not hide the rest of the report |
| seal file names as long as the case file number | the case file number's part is cut at 100 bytes, with a short hash | names over 255 bytes cannot be written |

Unicode details follow Python where it matters: `str.strip()`/`splitlines()` semantics (`pystr.rs`), `\w` in tags and
file names. Rust's regex engine treats a few rare combining characters as word characters where Python does not.
