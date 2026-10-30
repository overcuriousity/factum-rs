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

### Task 1: Seal folder out of the database, no CWD .env, robust seal files

Files: src/seals.rs, src/config.rs, src/verifier.rs, src/late_signing.rs, src/canonical.rs, src/export/verify.py
(splitlines only), src/gui/mod.rs (only where the seal-folder setting is read/written), README.md, docs/AIRGAP.md,
.env.example, tests/integrity.rs, tests/core.rs.

1. seals.rs:151-162 (used verifier.rs:558, 623-641). HIGH. The verifier takes the seal folder from the `settings`
   table of the DB it verifies; tampering the DB can redirect the check to an empty folder so a removed signed entry
   only WARNs. Implement user decision 1. The verify report (and CLI/GUI output) names the folder checked. Keep
   `FACTUM_SEAL_DIR` env precedence. Migration: on open, if the DB setting is non-empty and the user config has no
   FACTUM_SEAL_DIR, write it there; afterwards the DB value is not used for verification. Test: tamper DB setting to
   an empty dir → verify still FAILs seal_truncated.
2. config.rs:97-99 / 242. Implement user decision 5 (drop CWD `.env`). Update README.md:266-277 and .env.example.
3. seals.rs:296-317. `read_seal_files` silently skips unreadable/unparseable seal files and discards a `.json` when a
   same-named `.asc` exists even if the `.asc` is corrupt. Emit a WARN finding per seal file that cannot be read or
   parsed (naming the file); let an `.asc` supersede its `.json` only after the `.asc` parsed.
4. canonical.rs:92 (`extract_clearsigned_text`, Python splitlines semantics). It splits on U+0085/U+2028/U+2029,
   which canonical JSON leaves unescaped, so a seal for a case file number containing one of them is silently
   ignored. Split only on `\n` / `\r\n` (respecting what gpg clearsign produces). Make the same fix in
   src/export/verify.py if it has the equivalent. Test with a U+2028 in a case file number.
5. seals.rs:233-236, late_signing.rs:492. Seal files are written with `fs::write`. Write to a temp file in the same
   folder, `sync_all`, rename, then sync the folder (best effort on Windows).
6. Seal file names: very long case file numbers (e.g. 80 CJK chars = 240 bytes) fail with "File name too long". Cap
   the file-name stem by bytes (at a char boundary) and append a short hash so names stay unique. Share the helper
   with export (Task 11 will use it for export file names; put it where both can reach, e.g. a `safe_filename`
   variant in the module that already has `safe_filename`).

### Task 2: GPG handling and verifier robustness

Files: src/signer.rs, src/verifier.rs, src/db.rs, src/late_signing.rs, src/export/verify.py, tests/integrity.rs,
tests/core.rs.

1. signer.rs:253-262 and verify.py:141. `EXPKEYSIG` (good signature, key expired since) is treated as invalid. Treat
   EXPKEYSIG + VALIDSIG as valid with a WARN finding ("signing key has expired since"), as long as the VALIDSIG
   signature time is before the key's expiry (if the expiry is not available, still valid + WARN). Keep REVKEYSIG
   and EXPSIG (expired signature) as they are unless clearly wrong; document the choice. Same in verify.py.
2. signer.rs:398. `list_keys` filters on lowercase `s` (primary-key capability), hiding keys with a certify-only
   primary and a signing subkey (`cSC`). Filter on uppercase `S` (usable capabilities of the whole key), which also
   drops expired/revoked keys. Add a parser test with a `cSC` listing.
3. signer.rs:277-281. The fingerprint from `VALIDSIG` is field 0 (signing subkey); the primary fingerprint is field 9.
   Report the primary fingerprint (fall back to field 0 when field 9 is absent); keep the subkey available where a
   report shows signer details if that is cheap. Check the bundle signer list and verify.py stay consistent with each
   other.
4. signer.rs:121-128, 463. Signatures from the DB/seal files are passed to `gpg --decrypt`/verify without `--batch`
   and `--pinentry-mode error`; a tampered signature holding a symmetric-encrypted message pops up pinentry. Add
   `--batch --pinentry-mode error` to verification calls only (never to signing calls). Same in verify.py's gpg calls.
5. verifier.rs:234-241 (`Entry::from_row`), `list_tree_heads`, `late_signatures`. One malformed cell (invalid UTF-8
   TEXT, BLOB/INTEGER where TEXT expected) aborts `verify_case` with an error. Read such columns tolerantly
   (`rusqlite::types::Value` or lossy) and turn decode failures into a per-row FAIL finding; the rest of the report
   is still produced. Test: `UPDATE entries SET text=CAST(X'6e6f74ff' AS TEXT)` → report with a FAIL for that entry.
6. db.rs:151-155. A DB with `user_version` above SCHEMA_VERSION says "created by an older factum version". Add a
   separate message: created by a newer factum version, upgrade factum.
7. verify.py:116-154 (`Gpg.run`/`check`). gpg's exit code and BADSIG/ERRSIG/FAILURE lines are ignored; last status
   line of each kind wins; trust is "any TRUST_ line". Require exit code 0 (or treat the EXPKEYSIG case from item 1
   consistently), exactly one GOODSIG/EXPKEYSIG with one VALIDSIG, and no BADSIG/ERRSIG. Mirror the same stricter
   rule in signer.rs if it does not already reject multiple signatures.
8. verifier.rs:264, late_signing.rs:384 (performance). One gpg process per signature, and every late signing runs a
   full `verify_case` first. Add an in-process cache of verification results keyed by (signature bytes hash, signed
   payload hash, keyring state if cheap) so repeated verifies in one process (GUI, sign-all) do not re-run gpg for
   unchanged signatures. Keep the cache correct: a changed signature or payload must miss.

### Task 3: Case, evidence, notes and tags domain

Files: src/cases.rs, src/evidence.rs, src/notes.rs, src/tags.rs, src/images.rs, src/log_service.rs,
src/gui/dialogs.rs (only `suggestion_list`), src/gui/tag_completion.rs, tests/core.rs, tests/integrity.rs.

1. cases.rs:55-78, evidence.rs:57-83. The case/evidence row is committed before the log entry is appended (after
   signing, possibly waiting for pinentry); a crash in between leaves a row without its log event and verify fails
   forever. Make row insert and log append one transaction: sign first (with the id the row will get, e.g. reserve it
   inside BEGIN IMMEDIATE or compute it and re-check), then insert the row in the same transaction as the log append
   (log_service has an on-commit hook). Keep the logged payload format unchanged.
2. cases.rs:48-62 (+ db.rs:11 has no UNIQUE). Implement user decision 8: refuse a case file number already used by an
   open case (trimmed, exact match). Also applies to renaming a case's file number on edit.
3. notes.rs:328-334 (`latest_version_id`), 337-357 (`history`). Walking `corrects_id` has no visited set; a cycle in
   a tampered DB loops forever. Add a visited set/step limit and return an "inconsistent correction chain" error.
4. notes.rs:231-236, 252 with images.rs:15. Each correction copies all referenced images again; only a per-image
   20 MB limit exists. Add a per-note total image limit (e.g. 50 MB of image bytes per note; pick a constant next to
   the per-image one and explain it in its comment) checked on append and correct, with a clear error message.
5. tags.rs:12 (`TAG_PATTERN`). `#(\w+)` has no left boundary: URL fragments (`page#section`) and hex colours
   (`#ff0000` is still a valid tag text — keep it as a tag only when preceded by start/whitespace/punctuation that
   is not `/`, `&`, `#` or a word char). Use e.g. `(?:^|[^\w/&#])#(\w+)` and keep `tag_before` (GUI completion) in
   line with it. Existing signed entries are not re-tagged; this affects new extraction only — check whether tags
   are stored or recomputed on read, and if recomputed, make sure verification does not depend on it.
6. tags.rs:144-151 (`tag_counts`, used gui/tag_completion.rs:98 and gui/mod.rs:1909). The tag/label vocabulary is
   global across cases. Limit it to the current case (`JOIN entries ... WHERE e.case_id=?`) and adapt the callers.
7. gui/dialogs.rs:425-427 with tags.rs:211-212. `suggestion_list` slices the original name's chars with a
   `Match::Substring(at)` offset computed on the lowercased name; `'İ'.to_lowercase()` is two chars, so `chars[..at]`
   panics (tag `#İZMİR`, typing `#r`). Compute the match on the original string with a case-insensitive comparison
   that yields offsets into the original, or drop the highlight when lowercasing changed the length. Add a unit test
   with `İZMİR`.

### Task 4: IOC extraction

Files: src/iocs.rs and its tests.

1. iocs.rs:17, 21. Non-ASCII (IDN) domains and emails are never extracted (`münchen.de`). Allow Unicode letters and
   digits in labels (`\p{L}\p{N}`); keep punycode `xn--` working. Do not normalise to punycode (store as written,
   lowercased per item 4).
2. iocs.rs:32-44 (`DOMAIN_EXCLUDED_SUFFIXES`). Implement user decision 6: remove real TLDs (zip, mov, app, sh, py,
   so, md, pkg, bin, dev and any other entry that is a real IANA TLD) from the exclusion list. Keep the list for
   non-TLD file extensions. Add a comment saying why real TLDs are not excluded.
3. iocs.rs:18 (URL). The trailing `\b` cuts a final `/` (`https://evil.com/` stored as `https://evil.com`). Match
   URLs up to whitespace/`<>"'`, then trim trailing `.,;:!?` and an unbalanced `)`/`]`.
4. iocs.rs:26. SHA-512 (128 hex) is never extracted. Add it (longest first so a 128-hex run is not seen as two 64s).
5. iocs.rs:61. `Evil.COM` and `evil.com` become two IOCs. Lowercase domains and emails (and URL scheme+host) before
   dedup; hashes compare case-insensitively too.

### Task 5: CLI behaviour and exit codes

Files: src/cli.rs, src/main.rs, examples/demo_db.rs, README.md, tests/cli.rs.

1. cli.rs:90-129 (`parse_int`, `find_case_id`, `find_evidence_id`). Implement user decision 4 for cases and evidence.
   Ambiguous → error listing `#id file-number name` of candidates (exit 2).
2. cli.rs:302-372 (`dispatch`). A positional note is silently ignored when an action flag is given (exit 0, nothing
   stored). Refuse a note combined with any action flag (clap `conflicts_with_all`/ArgGroup or an explicit check)
   with a clear message.
3. cli.rs:333-338, 356-362, 384-389. Exit codes: 0 OK, 1 verification FAIL, 2 operational error (no case found,
   bad arguments, I/O). `--export` of a case whose verdict is FAIL prints a warning to stderr and exits 1 (files are
   still written). Document the exit codes in README and `--help` text.
4. User decision 5 (second half): when FACTUM_DB is set, print `Database: <path>` to stderr once per run.
5. examples/demo_db.rs:8 uses `Db::open_default()`, writing a demo case into the user's real DB. Require FACTUM_DB
   (or a path argument) and refuse otherwise.
6. Carry-over from Task 2: `factum --verify 1` with a malformed `cases` cell aborts with "Database error: ..." while
   plain `--verify` reports it, and one bad case row can stop lookup by name for other cases (src/cli.rs:97-100). The
   lookup must skip a row it cannot read (naming it) instead of failing, so verification can still report it.
7. Carry-over from Task 2: `list_gpg` (src/cli.rs:177-190) prints an expired or revoked active key as `[active]` with no
   state, so the listing doesn't say it cannot sign. Add its state (expired, revoked) to that line.

### Task 6: Installers, scripts and repository housekeeping

Files: install.sh, install.ps1, scripts/airgap-download.sh, scripts/release.sh, .gitignore,
src/container/__pycache__/ (remove), docs/AIRGAP.md.

1. install.sh:175. `$DIR` goes unescaped into a sed replacement and the desktop `Exec=` line. Escape `\ & |` (and the
   sed delimiter) for sed and write `Exec="<dir>/factum" --gui` quoted per the Desktop Entry spec.
2. install.sh:155-160, install.ps1:68-75, scripts/airgap-download.sh:140,148,157. When `SHA256SUMS.asc` and gpg are
   available, run `gpg --verify SHA256SUMS.asc SHA256SUMS` and fail on a bad signature (warn, do not fail, when
   gpg or the .asc is absent — state clearly that only integrity, not authenticity, was checked). Make sure every
   downloaded asset is actually listed in SHA256SUMS and checked (no silent skip of `grep -F -f`). `--target <x>`
   with no match must print an error, not exit 1 silently.
3. install.ps1 user-PATH rewrite may expand `%VAR%` entries (reviewer: plausible). Read the user PATH raw
   (`Get-ItemProperty ... -Name Path` with `DoNotExpandEnvironmentNames` via the registry key API) and write it back
   as REG_EXPAND_SZ. Only change if confirmed by reading the script.
4. scripts/release.sh uses the GNU-only sed `0,` address. Make it portable (awk or a loop) if it is meant to run on
   macOS; otherwise add a comment that it needs GNU sed. Choose based on how CI/release run it.
5. `src/container/__pycache__/verify_container.cpython-313.pyc` is tracked and ships in the crate. `git rm --cached`
   it (and delete it) and add `__pycache__/` and `*.pyc` to .gitignore.

### Task 7: ZIP64 reader/writer correctness

Files: src/container/zip64.rs, src/container/volume.rs (only `Volume::open`/`Appender::new` truncation path),
tests/container_zip.rs.

1. zip64.rs:173-199 (`read_archive`). HIGH. Central directory parsing reads exactly `count` entries and ignores
   leftover bytes within `cd_size`; the local header name is never compared with the central name. A container with
   an entry hidden behind a lowered count is invisible to factum while Python/unzip/7-Zip read it. After the loop,
   require `at == directory.len()`. In `member_reader` (or a verify step), check that the local header's name,
   method and general-purpose flags match the central entry; error with InvalidData on mismatch. Test: craft the
   reviewer's scenario (two members, second renamed to `information.turtle`, ZIP64 counts set to 1) → error.
2. zip64.rs:268, 272, 229, 233 with volume.rs:728/752. `read_archive(..).is_ok()` turns real I/O errors into "no
   state ends here", so `Volume::open` may truncate newer valid states after a transient read error. Treat only
   InvalidData/UnexpectedEof as "not a state"; propagate other errors. Before truncating, refuse (error) when the cut
   would remove more than an incomplete trailing member beyond the newest valid end found by the members walk, unless
   the existing code proves the cut region holds no complete state; keep the existing "set aside after crash"
   behaviour working (tests/containers.rs covers it).
3. zip64.rs:282-307 (`walk_states`). An interrupted member whose size placeholder is still zero is treated as a
   finished empty member, so the walk parses evidence bytes as headers. Stop when the ZIP64 extra still holds the
   zero placeholder and CRC is 0 (factum always patches both). Fix the doc comment to match.
4. zip64.rs:572 vs 460. Central entries get the DOS time of `finish`, and every `finish` rewrites earlier members'
   times. Store the time in `CdEntry` at `add_member` and reuse it.
5. zip64.rs:340-357. Rust never checks member CRC-32. Compute CRC while streaming a member for verification and report
   a mismatch as a failure in the existing stream-hash/history findings (container verify), without slowing normal
   reads more than one CRC pass.

### Task 8: Container sources, mounts, Turtle and X.509

Files: src/container/source.rs, src/container/mounts.rs, src/container/turtle.rs, src/container/x509.rs,
src/container/stream.rs, src/container/volume.rs (only where it calls source/mounts or writes name/link fields),
tests/container_x509.rs, tests/containers.rs.

1. source.rs:84-98 with volume.rs:1047-1054. Metadata via `symlink_metadata`, but the file is opened by path without
   `O_NOFOLLOW|O_NONBLOCK`; nothing checks the opened fd is the same regular file; `stream::store` reads until EOF
   unbounded. On Unix open with `O_NOFOLLOW|O_NONBLOCK` (then clear O_NONBLOCK), `fstat` and compare type/dev/inode
   (and size) with the walk metadata, record a "changed" error on mismatch, and read at most `meta.size + 1` bytes
   (more than size means "changed while reading"). On Windows use the closest equivalents (FILE_FLAG_OPEN_REPARSE_POINT,
   compare file index) if cheap; otherwise keep current behaviour there with a comment.
2. mounts.rs:315-316. Loop partitions (`/dev/loop0p1`) are not under `/sys/block`, so no backing image is recorded.
   Resolve the partition's parent via `/sys/class/block/<dev>/..` (or the `partition` file) before reading
   `loop/backing_file`.
3. mounts.rs:313 (perf). `with_backing` runs per walked path, re-reading sysfs and cloning the Mount for every file.
   Resolve each MountEntry once (cache keyed by mount index/mount point) and reuse.
4. mounts.rs:353-356 (Windows `mounts_for`). The volume is cached per parent folder but looked up with the first child
   path; a mount-folder child poisons the cache for its siblings. Look the volume up with the parent folder itself
   (and handle the child being a mount point separately, as its own volume).
5. mounts.rs:249, 275. Mount points are decoded with `from_utf8_lossy` and matched with `Path::starts_with`; non-UTF-8
   mount points never match; over-mounted (hidden) mounts are still reported. Keep the octal-unescaped bytes as
   `OsString` (Unix `OsStringExt`), and use mount id / parent id from mountinfo to drop mounts hidden by a later mount
   on the same or a parent mount point.
6. mounts.rs:262. Only per-mount options are recorded; superblock options (`ro`, `norecovery`, `noload`, `errors=`)
   are dropped. Record both option sets; read-only if either says `ro`. Keep the Turtle property names compatible
   (add a new property for superblock options if needed, documented in the container README/spec).
7. source.rs:135-145, volume.rs:1015/1021, source.rs:64-66. Fidelity: Windows names with unpaired surrogates become
   U+FFFD with no raw form; `symlinkTarget` and `sourcePath` use lossy `display()` with no raw form; ctime before 1970
   is clamped. Keep a raw form for names/targets/paths that are not valid Unicode, the same way member names already
   have `encode_name`/raw handling (on Windows encode the UTF-16 as WTF-8 or hex of the raw UTF-16). Handle negative
   ctime/mtime correctly.
8. Lossy paths for Add Again (first round): volume.rs:999 records the source path (and containers.rs:805 the
   base_path) via `display().to_string()`; containers.rs:1092 turns it back with `PathBuf::from`, so non-UTF-8 sources
   can never be added again and `strip_prefix` breaks. Record a raw/exact form alongside the display form (backwards
   compatible: old logs without it fall back to the display string) and use it in `add_again_plan`. The `replaced`
   lookup in stage must compare exact forms.
9. volume.rs:935 (first round). The self-exclusion canonicalizes every walked item (following symlinks), so a symlink
   to the container is silently dropped and every file costs a realpath. Compare (dev, inode) (Windows: volume
   serial + file index) from the metadata already read, only for non-link items; record links as links.
10. turtle.rs:208/188 (write) and 256-261 (tokenize). IRIs are written raw and `\u` escapes in `<...>` are not decoded.
    When writing, refuse (error) or %-encode characters not allowed in IRIs (space, `<>"{}|^\`` and controls); when
    parsing, decode UCHAR in IRIs or reject them consistently with what verify_container.py does.
11. x509.rs:455. `valid` requires `GOODSIG`; after the leaf certificate expires gpgsm emits `EXPKEYSIG` (still with
    VALIDSIG and TRUST_FULLY), so every X.509-signed container fails once its certificate expires. Treat EXPKEYSIG +
    VALIDSIG as valid and leave time to `valid_at_signing`; take `signer_subject` from EXPKEYSIG too. Add a parser
    test with captured status lines.
12. x509.rs:454-471. Any signer chaining to any trusted root is accepted; the VALIDSIG fingerprint is never compared
    with `information.turtle.factum.cer` or the certificate recorded in the case log. Compare the leaf fingerprint
    with the stored certificate (and the logged one when verifying against the log) and FAIL on mismatch.

### Task 9: Container operations (open/add/close/reopen/verify) in Rust

Files: src/containers.rs, src/container/volume.rs, src/container/verify.rs, tests/containers.rs.

1. containers.rs:961-1008 (`close_container_with`). HIGH. The close accepts any `Recheck`; nothing ties it to the
   state being closed, and no lock is held from re-check to close; another process can add (and damage) a file in
   between and the close signs it as "re-checked". Store the logged end and the set of record ARNs (and the volume end
   offset) in `Recheck`; in `close_container_with` take the volume lock, recompute `recheck_input` and refuse with a
   clear error when it differs ("the container changed since the re-check; re-check again").
2. containers.rs:773-842 (`commit_container_add`) with 1044 (`close_container_damaged`), reopen and
   close-without-file. The commit never re-checks that the container is still open, and the log-only close/reopen
   paths take no volume lock. In `commit_container_add`, refuse unless the container is still open (re-read inside
   the commit transaction). Make the log-only close (damaged, without file) and reopen fail while another process
   holds the volume lock (try-lock; a missing file needs no lock).
3. verify.rs:930-974, containers.rs:1296-1352. A `factum:replacedBy` triple turns a content-hash failure into a
   warning and is never checked against the log's `replaces`. When verifying against the log, every replacedBy pair
   in the graph must match an `AddEvent.replaces` entry, otherwise FAIL. Extend `compare_records` to compare
   replacedBy pairs (FileRecord may need the field).
4. containers.rs:410 (first round). `list_containers` sets `signed = true` on any `container_signed`, but late signing
   can sign an older close, so the summary disagrees with `container()` ("the newest close decides"). Apply the
   signature only when it belongs to the newest close (match the close entry id / turtle hash the event refers to).
5. containers.rs:282-303 (`compare_records`) O(F²) folder `contains` scans (20k folders = 1 s; called twice per open).
   Use HashSets keyed by (arn, path). Same class: `add_again_plan` (containers.rs:1084-1088) scans every add's files
   per mismatch — index by ARN; volume.rs:1135-1146 `replaced` matching O(replaces × records) — use a map.
6. containers.rs:671 (first round). `create_evidence_with_container` appends the evidence entry before trying the
   container, leaving an orphan evidence entry on failure and a duplicate on retry. Run the path/name/case checks and
   create the container file before appending the evidence entry (or roll the container file back if the evidence
   append fails), so failure leaves no log entry.
7. volume.rs:826 + 1239-1266 (`close`), 1273 (`add_late_signatures`). The close signs `turtle_bytes()` (a
   re-serialization) but the root `information.turtle` keeps the bytes of the last commit; any serializer drift makes
   history n ≠ root. Sign the stored root bytes (`self.member(TURTLE)`), or write a fresh root TURTLE/HASHES in close;
   choose the one that keeps existing containers verifying.
8. volume.rs:295-303, 351 (`is_damage` in `recheck`). A persistent EIO or other "Other"-kind read error counts as
   transient, so close always errors and close-as-damaged/Add Again are never offered; the case can never be
   archived. Classify repeated non-transient read errors (e.g. EIO, or the same error on a second attempt) as damage
   so close-as-damaged becomes available.
9. containers.rs:1325, 1349 (`detail.closes.get(n as usize - 1)`). A hostile `factum/history/0/...` member makes n = 0
   and underflows. Use `checked_sub` / reject n = 0 when collecting closes (verify.rs:638-648) as a FAIL finding.
10. Misplaced doc comments (first round): containers.rs:1041 — `close_container_damaged` carries
    `close_container_without_file`'s doc; move each paragraph to its function. Same at volume.rs:32 for `readme_text`
    / `history_member`.

### Task 10: Python container verifier parity

Files: src/container/verify_container.py, tests/containers.rs (tests that run the Python verifier, if any exist;
otherwise add a Rust test that runs `python3 -I` on a tampered container when python3 is available, skipping
otherwise, following existing patterns).

1. verify_container.py:526-539 vs verify.rs:762-781. For a closed state that is also current, Python never compares
   the root `information.turtle.asc`, `.pubkey.asc`, `.factum.sig`, `.factum.cer` with `factum/history/n/` copies.
   Port the comparison.
2. verify_container.py:305-309. `zipfile.ZipFile` accepts trailing bytes after the last EOCD within 64 KiB. Find the
   end of the last complete state like Rust does and WARN `trailing_data` when it is before the file end.
3. verify_container.py:446-450. `read()` catches only KeyError; a bad CRC on an open state's `information.turtle`
   crashes with a traceback. Catch `zipfile.BadZipFile`/`zlib.error`/`OSError` and report a FAIL.
4. verify_container.py:225 (first round). `fail_or_replaced` calls `file_images(graph)` (full scan) per failure.
   Build the set once; skip the membership test when `replaced_by` is None.
5. Duplicate member names / count-vs-size mismatch: FAIL on duplicate names in the central directory (factum never
   writes them), matching the Rust check from Task 7.
6. If Task 9 item 3 adds replacedBy-vs-log checks, Python has no log; leave a comment that replacedBy is only
   cross-checked against the case log by factum, and make the Python verifier at least report every replacedBy as a
   WARN listing the pair (not silently OK).
7. Carry-over from Task 2: verify_container.py:345,366-373 still rejects EXPKEYSIG, reports VALIDSIG field 0 (the
   subkey), accepts any TRUST_ line and has no `--batch --pinentry-mode error`. Match what Task 2 did in
   src/export/verify.py: the same single-signature rule, EXPKEYSIG handling, trust rule and primary fingerprint.

### Task 11: Export and bundles

Files: src/export/*.rs, src/export/verify.py, src/main.rs or src/cli.rs (only for `--version`), tests/export.rs.

1. bundle.rs:25-29 and verify.py. Implement user decision 2. `factum --version` prints the SHA-256 of the embedded
   verify.py and verify_container.py (one line each). On Windows, verify.py resolves gpg to an absolute path that is
   not inside the bundle folder / current directory (refuse a gpg found in the bundle directory).
2. verify.py:101-105 (`load_bundle`). Duplicate ZIP member names are accepted (Python reads the last copy; unzip the
   first). FAIL on duplicate names and on names that are absolute, contain `..`, a backslash, or are case-only
   variants of another name.
3. pdf.rs:309-313 (`ensure`) with 836-879 (`grid`). A table row taller than a page is drawn past the page bottom and
   lost (evidence description, container path cells). Split rows across pages line by line, like `meta_table` and
   `rich_paragraph` do, and cap `keep` so a header is never left alone.
4. pdf.rs:323-331 (`glyph`) and 398 (ToUnicode `or_insert`). Implement user decision 3. Glyph 0 must never be mapped
   in ToUnicode to the first unsupported char; give each unsupported char correct extracted text (ActualText span or
   per-run mapping) and a visible placeholder glyph; return/print an export warning listing that unsupported
   characters occur.
5. html.rs:125-153, markdown.rs:248-274, pdf.rs:1284-1320, model.rs:417-438. No report contains the text of
   superseded versions, although the appendix says it covers them. Show earlier versions' text (at least in the
   appendix, with time and signature status) in HTML, Markdown and PDF, and flag a note in the timeline when any of
   its versions failed verification.
6. markdown.rs:84. Bare URLs, autolinks, emails and link text equal to its URL come out as plain text that GitHub-style
   viewers make clickable, contradicting "links are never clickable". Defang them in the Markdown report (e.g. put
   addresses in code spans, as is already done for differing link addresses).
7. export/mod.rs:41-87, bundle.rs:218-235. Export is not atomic: reports are written before the bundle, and a failure
   leaves partial files. Write each output to a temp file in the target folder, rename all at the end, and remove temp
   files on error.
8. export/mod.rs:47-51. File names are never shortened (80 CJK chars → os error 36). Use the byte-capped name helper
   from Task 1 item 6.
9. export/mod.rs:52. The HTML report (with base64 images) is built on every export even for pdf-only/md-only. Build
   only the requested formats (the bundle needs whatever it contains).

### Task 12: Companion

Files: src/companion/*.rs, tests/companion_*.rs.

1. thread.rs:434-455 (tick → backlog), 520-562. HIGH. Selecting a case sends its content immediately via backlog
   enrichment, defeating the 30 s first-seen opt-out window (spec 4.2: the rest of the history is enriched after the
   first pass). Skip backlog for a case with no successful pass yet or while the scheduler holds a pending first-seen
   entry; re-check runnable/enabled between backlog batches. Test with the fake LLM: after `Selected(case)`, no request
   before the quiet period ends.
2. thread.rs (no cancellation). Opt-out, delete, settings change and shutdown wait behind all in-flight model calls.
   Add a shared cancellation epoch (AtomicU64 or AtomicBool per case + global) that the GUI side bumps on toggle,
   delete, settings change and shutdown; check it between batches and before each model call, abort the pass, and do
   not send further content. Abort a pass when its pre-pass enrichment failed with Unreachable/Timeout instead of
   waiting out two more timeouts (reflect.rs:~250).
3. retrieval.rs:121-125. `exclude` is applied after BM25 is cut to CANDIDATES (30), so excluded entries use up the
   slots and older related entries are never seen. Push the exclusion into SQL (or over-fetch by
   `CANDIDATES + exclude.len()`).
4. reflect.rs:282 with 504/588. A Full pass marks new entries as seen even when packing dropped them. Compute coverage
   for Full passes from what survived packing (as Diff passes do with `covered_to`), so dropped entries get a later
   pass.
5. llm.rs:361 with reflect.rs:298. For a model with `thinks`, call one's `max_tokens` grows by up to 8192 and the
   reasoning can exceed the 1500-token OUTPUT_RESERVE; call two then overflows the window (HTTP 400, not retryable).
   Truncate the reasoning passed to call two to the remaining budget.
6. tokens.rs:54 (`Calibration::observe`). The last observation replaces the ratio; dense (hex/path) text is estimated
   at 0.8 × that ratio, which can exceed the window on every pass. Cap the dense ratio at the default 2.4 chars/token
   and smooth observations (e.g. take the more conservative of old and new, or an EMA).
7. validate.rs:19-33 (`repair_first_parsing`). O(n²) over unclosed `{`/`[` starts; a degenerate 10 MB reply can hang
   the thread. Cap the reply length before repair and the number of candidate starts tried.
8. ask.rs:85. Excerpt packing `break`s at the first entry that does not fit (pinned notes first), so big pinned notes
   crowd out every hit or make Ask abstain without calling the model. Use `continue`, reserve a share of the budget
   for retrieved hits, and shorten over-long pinned lines. Also reuse the companion's context-window/calibration
   knowledge for Ask instead of a fresh default `Client` if that is straightforward.

### Task 13: GUI core (mod.rs, workers, container views)

Files: src/gui/mod.rs, src/gui/workers.rs, src/gui/containers.rs, src/late_signing.rs (only to expose a split of
verify vs. sign if needed), src/gui/tests.rs.

1. mod.rs:1945-1950, 1794-1796, 3776-3778, 1594-1600. Sign, Sign All Unsigned, Sign Seal and Export run a full
   `verify_case` (gpg per signature) on the UI thread. Run the verification on a worker with the existing progress
   UI (like workers::verify_case), then sign on the GUI thread (pinentry) when it passed. Task 2's cache helps but is
   not a substitute.
2. workers.rs:25-45. A panicking worker drops its sender; `poll()` returns None forever (Disconnected treated like
   empty), so jobs never clear (verify modal forever, add/close guard blocks for the session). Treat
   `TryRecvError::Disconnected` as a failure ("the background task stopped unexpectedly") and clear the job.
3. gui/containers.rs:343. `&file.sha256[..16.min(len)]` slices bytes of an unvalidated string; a non-ASCII value from a
   tampered DB panics every frame. Use a char-safe prefix (and consider validating hex in `FileRecord::from_json`).
4. mod.rs:263, 1678, 3507-3509. `verified` is keyed by case id and not cleared on permanent delete; SQLite reuses the
   id, so a new case can show "✓ verified". Remove the entry on delete, and key the cached status on (case id, tree
   size, root hash) so a different case can never match.
5. mod.rs:1794-1806 (late_signing.rs:140-147). Sign All Unsigned reports "nothing was signed" after a partial run.
   Return (signed count, Option<error>) and report "Signed 5 of 20; stopped: ...".
6. mod.rs:3817-3819 / 2370-2383. Quit never asks and drops work (composer text, a running addition, a finished but not
   yet logged addition). Ruling (controller): on close request, if an add/close job is running or the composer or an
   open dialog holds unsubmitted text, cancel the close (`ViewportCommand::CancelClose`) and show one small confirm
   ("Quit anyway?" with the reason) — this is the one extra dialog allowed. When the user confirms during an add,
   set cancel and wait for the worker to rewind before exiting. If a finished add is waiting to be logged, finish it
   before exit.
7. mod.rs:605-622, 706-836, 678-704 (perf). Every rebuild (on every search keystroke) re-reads the whole tree and
   re-parses every card. Cache built cards by entry id (entries are immutable; invalidate on data_version change or
   when the entry's latest version changes) and debounce search rebuilds (~200 ms).
8. mod.rs:868 (first round). The view rebuild calls `list_containers` again although the tree already holds the
   summaries, and its `?` now fails the whole rebuild on a container read error. Reuse the tree's summaries and log +
   skip on error as before.
9. mod.rs:2263-2279, 1025-1040, 2285-2300. Ask results are matched by case id only; a stale job's answer can appear
   under a newer question. Give each Ask job a request id stored in the window; ignore non-matching results; make the
   question field read-only while running.
10. mod.rs:2432-2442 with 1963 / 2117-2120. `focused_card` keeps the superseded id after a correction; P toggles the
    pin on the old version. Map `focused_card` to `latest_version_id` after a correction and on rebuild (or resolve in
    TogglePin).
11. mod.rs:2593-2697 (`case_menu`). Buttons are enabled from cached `view.case` but then `current_case_id().unwrap()`
    re-queries and can be None. Take the id from `view.case` and replace the unwraps with `if let`.
12. mod.rs:1516-1517, 1554-1560, 1569. Close-and-Archive / DeleteEvidence end with `select(None, None)` even when the
    user moved to another case meanwhile or the call failed. Only clear the selection if it still points at the
    archived case/deleted evidence and the call succeeded.
13. mod.rs:2387-2443, 386. The active signing key is read once at startup; a CLI change is never picked up. Re-read
    ACTIVE_KEY_SETTING when `data_version` moves and call `update_gpg_status`.
14. mod.rs:1389 (first round). While a close's re-check runs only Add/Close/Reopen are blocked. Add Locate and
    CloseWithoutFile (and any other action that changes the container or its path) to the guard.
15. gui/containers.rs:92 (first round). `recheck_status` builds text by `replacen` on `add_status`'s output. Share a
    formatter that takes the verb.

### Task 14: GUI dialogs and widgets

Files: src/gui/dialogs.rs, src/gui/widgets.rs, src/gui/wizard.rs, src/gui/note_editor.rs, src/gui/markup_view.rs,
src/gui/companion_dialogs.rs, src/gui/mod.rs (only the dialog result handling it needs), src/gui/tests.rs.

1. dialogs.rs:736-741. Implement user decision 7 for all dialogs holding typed text (Correct, case goal, New
   Case/Evidence descriptions, companion settings, wizard). For the wizard, Escape/backdrop must not end setup or set
   ONBOARDING_SETTING while text was entered.
2. dialogs.rs:1293-1300. The Correct dialog's TextEdit grows with its content without a ScrollArea; the modal's title
   and buttons go off-screen for long notes. Wrap it like wizard.rs:296-299 (`ScrollArea::vertical().max_height(...)`)
   so the buttons stay visible.
3. dialogs.rs:1286 (`Id::unique("correct-editor")`). All Correct dialogs share one TextEdit id; Ctrl+Z restores another
   entry's text (which can then be signed as this entry's version) and the cursor is stale. Salt the id with the entry
   id and a per-open counter (or reset the TextEdit state when the dialog opens). Test: open Correct on A, then B, undo
   → B's text is not A's.
4. dialogs.rs:1397-1407 (Seal Folder dialog) with mod.rs:2150. Any folder is stored, including non-existent or
   relative ones. Apply the wizard's check (exists, is a directory, absolute) before accepting. The value goes to the
   user config per user decision 1 (Task 1 provides the writer).
5. widgets.rs:145-168 vs verifier.rs:289-321. The card shows "Key missing"/"Untrusted key" in the warning tone, but
   the verifier rates both FAIL. Use the bad tone (✗) for both, consistent with the verifier's levels.
6. dialogs.rs:648-669 (`signature_text`). An untrusted-key signature shows "valid · TRUST_UNDEFINED" next to a ✗
   verdict. Say "valid signature, key not trusted (...)" when not trusted.
7. dialogs.rs:815-820. Container "File name" is joined with `Path::join` unchecked: absolute names or `../` escape the
   validated folder; a name without `.aff4l` is accepted. Reject separators and `..`; append `.aff4l` when missing.
8. dialogs.rs:1162-1222 (Add Label). "Add" is enabled for `#`/`##`; the label is stripped to nothing and the dialog
   closes silently. Validate with `clean_label` in the dialog (disable Add when empty after cleaning).
9. note_editor.rs:372-376, dialogs.rs:1301. With images attached, `thumbnails()` parses the whole text with
   pulldown-cmark every frame. Cache `referenced_ids` keyed by a hash of the text.
10. dialogs.rs:1706-1721 (VerifyWindow "Entries OK"). Every OK entry is laid out every frame and the
    fails/warnings/ok vectors are rebuilt every frame. Build the lists once per report and use
    `ScrollArea::show_rows`.
