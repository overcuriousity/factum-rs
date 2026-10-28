# Containers as evidence: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Containers always belong to an evidence item (any number per item), shown as a symbol on the evidence row
and as sections below its notes; one-step acquisition of a mount; full paths without a base path; mount details per
add; a re-check before every close with a second chance (Add Again / Close as Damaged); a verifier hash in the
README; a public signed sample container.

**Architecture:** The case log stays the only record of container state (`container_*` system entries). The library
(`src/containers.rs`, `src/container/`) gains: a required evidence id, full-path storage, a `mounts` module, a
read-back `recheck`, a damaged close and replacement marking. The GUI drops container rows (except a fallback for old
data), renders container sections under the evidence's notes, and runs the re-check on a worker thread like adds.

**Tech Stack:** Rust 2024, rusqlite, egui 0.37 / egui_kittest, `libc` (Linux, macOS), `windows-sys` (Windows), system
`gpg`/`gpgsm`/`openssl` (sample script only), Python 3 stdlib (`verify_container.py`).

**Spec:** `docs/superpowers/specs/2026-10-28-containers-as-evidence-design.md` (approved 2026-10-28), building on
`docs/superpowers/specs/2026-10-26-evidence-containers-design.md` and the plan
`docs/superpowers/plans/2026-10-27-evidence-containers.md`.

## Changes since the spec (read these first)

1. **Schema.** The spec repeats "schema 3, shared with factum-notes" from the first design. The database is schema 4
   and factum-notes cannot open it (see the first plan, change 1). No schema change; `verify.py` must still pass.
2. **Add Again needs the source path.** The log records only the stored (relative) path. Every new file record gets
   `source` (the absolute path as read), and every add payload gets `base_path` and `keep_path`, so Add Again can
   repeat an add exactly. Records written before this version have neither; Add Again is unavailable for them.
3. **Damaged close writes nothing to the file**, like Close Without File: no closed state in `factum/history/`,
   nothing to sign later. After Reopen, the unreplaced damaged files are re-checked again.

## Global Constraints

- After every task: `cargo test`, `cargo test --no-default-features`, `cargo clippy --all-targets` (no warnings),
  `cargo fmt --check`. `src/container/` and `src/containers.rs` build without the `gui` feature.
- Never touch `canonical.rs`, `merkle.rs`, `leaf_data`, `entry_signed_payload`, `seal_payload`, `src/export/verify.py`.
- No schema change, no new table; `SCHEMA_VERSION` stays 4. Only new or extended `container_*` payloads.
- No network, no new crates. `libc = "0.2"` may be added under `cfg(target_os = "macos")`; `windows-sys` may gain
  features (`Win32_Storage_FileSystem` is already there).
- The container file stays append-only; earlier bytes never move. pyaff4 is not available (first plan, change 2):
  "opens in other readers" means Python `zipfile` reads every member and both factum verifiers pass.
- UI copy is fixed where this plan quotes it; other wording follows the existing dialogs (short, plain, no jargon).
- Platforms: Linux and Windows fully; macOS builds and works, mount details optional there.

## Review Focus

1. **Acquire into a folder that also holds the new container file** (save folder inside the Acquire folder): the
   container must not add itself. Test in Task 2.
2. **Mount points with spaces or special characters** (`/mnt/my disk` is `\040` in `mountinfo`): decoded, matched,
   shown correctly. Test in Task 3.
3. **The container file disappears between add and close** (USB drive pulled): Close shows the error, the container
   stays open, nothing is logged. Test in Task 5.
4. **A search is active when an evidence item with containers is selected**: the container sections still show
   below the (filtered) notes. Test in Task 7.
5. **Add Again when the source has been unmounted**: the error is shown, nothing is logged, the container stays
   open and can still be closed as damaged. Test in Task 9.

---

### Task 1: Containers require an evidence item

**Files:**
- Modify: `src/containers.rs` (`ContainerSummary`, `list_containers`, `container`, `create_container`)
- Modify: `src/evidence.rs` (`delete_evidence`)
- Modify: `src/gui/mod.rs` (only the existing `create_container` call, to compile; the dialog changes in Task 8)
- Test: `tests/containers.rs`

**Interfaces:**
- Produces:
  - `ContainerSummary` gains `pub evidence_id: Option<i64>`, `pub signed: bool` (the newest close is signed, now
    or later), `pub damaged: bool` (false until Task 6 sets it).
  - `Factum::create_container(&self, case_id: i64, name: &str, evidence_id: i64, path: &Path, base_path: &str) -> Result<i64>`
    (evidence required; `base_path` may be empty, see Task 2).
  - `Factum::create_evidence_with_container(&self, case_id: i64, name: &str, hash: &str, details: &str, path: &Path, base_path: &str) -> Result<(i64, i64)>`
    returns (evidence id, container id).
  - `Factum::delete_evidence` refuses evidence with a container: `FactumError::evidence_not_empty("Evidence #{id} has containers and cannot be deleted.")`.

- [ ] **Step 1: Write the failing tests** in `tests/containers.rs` (update `Setup::create` to pass `self.evidence_id`):
  - `create_requires_evidence_of_the_case`: evidence of another case → Err, message contains "does not exist in this case"; deleted evidence → Err.
  - `two_containers_on_one_evidence`: two `create_container` calls with the same evidence id succeed; `list_containers` returns both with `evidence_id == Some(evidence_id)`.
  - `case_level_create_logs_evidence_then_container`: `create_evidence_with_container(case, "USB 2", "abc", "seized", path, "")` → `events("evidence_created")` and `events("container_created")` each have one new entry, the container's `evidence_id` is the new evidence's id and `name == "USB 2"`; the evidence entry id < the container entry id.
  - `evidence_with_container_cannot_be_deleted`: `delete_evidence(evidence_id)` → Err containing "has containers".
  - `summary_says_signed`: after `close_container`, `list_containers(..)[0].signed == true`; with `FakeSigner::new(false)`, false.
- [ ] **Step 2: Run** `cargo test --test containers` → the new tests fail to compile or fail.
- [ ] **Step 3: Implement.** `list_containers` reads `$.evidence_id` from `container_created` and `$.signatures` / `container_signed` for `signed`. `create_evidence_with_container` calls `create_evidence` then `create_container`; if the second fails, return its error with the text "Evidence #{id} was created, but its container was not: {e}" (the evidence stays). `delete_evidence` checks `list_containers(case_id)` for the evidence id before the notes check.
- [ ] **Step 4: Run** `cargo test --test containers` and the full Global Constraints commands → pass.
- [ ] **Step 5: Commit** `Containers: an evidence item is required, several per item`.

### Task 2: Full paths, source paths and add parameters in the log

**Files:**
- Modify: `src/container/source.rs` (`stored_path`), `src/container/volume.rs` (`AddOptions`, `FileRecord`, `file_records`, `stage_add_with`, `finalize_add`), `src/containers.rs` (`commit_container_add`)
- Test: `src/container/source.rs` (unit), `tests/containers.rs`

**Interfaces:**
- Produces:
  - `AddOptions` derives `Default` and gains `pub replaces: Vec<(PathBuf, String)>` (source path, ARN it replaces; used in Task 6). An empty `base` means "no base path".
  - `FileRecord` gains `pub source: Option<String>` (absolute source path, `Path::display`), JSON key `"source"`, turtle `factum:sourcePath`; `file_records` reads it back.
  - `container_files_added` payload gains `"base_path"` (string, `""` = full paths) and `"keep_path"` (bool).
  - `stored_path(path: &Path, base: &Path, keep_path: bool) -> Result<Vec<u8>, String>`: with an empty `base`, the full path. Unix: without the leading `/` (`mnt/x/a.txt`), task `aff4l:filesystemRoot` = `/`. Windows: the prefix is the first component (`C:\Users\x\a.txt`, `\\server\share\x\a.txt`), `filesystemRoot` = `""`.

- [ ] **Step 1: Write the failing tests:**
  - unit `stored_path_without_base_keeps_full_path`: Unix `stored_path("/mnt/x/a.txt", "", true) == b"mnt/x/a.txt"`; `#[cfg(windows)]` `C:\Users\x\a.txt` → `C:\Users\x\a.txt` and `\\server\share\x\a.txt` → itself.
  - `add_without_base_from_two_folders`: container with base `""`; one add of a file from `mnt/Users/x` and one from a sibling temp folder → both records' `path` end with their full relative-to-root path; payload `base_path == ""`, `keep_path == true`; every record has `source` equal to the absolute path; `zipfile`-readability via the existing helper used in `tests/container_zip.rs`.
  - `log_and_container_agree_on_source`: `compare_with_log` (existing) reports no finding after such an add.
  - `acquire_skips_the_container_itself` (Review Focus 1): container file saved inside the folder being added → the add succeeds and no record's `source` equals the container path.
- [ ] **Step 2: Run** them → fail.
- [ ] **Step 3: Implement.** `stage_add_with` skips any walked path equal (canonicalized) to `self.path`. Validation in `stage_add_with` that sources lie below the base applies only when the base is non-empty.
- [ ] **Step 4: Run** the tests and the Global Constraints commands → pass.
- [ ] **Step 5: Commit** `Containers: full paths without a base path; each file records its source`.

### Task 3: Mount details per add

**Files:**
- Create: `src/container/mounts.rs` (declare in `src/container/mod.rs`)
- Modify: `src/container/volume.rs` (`Staged`, `stage_add_with`, `finalize_add`), `src/containers.rs` (`commit_container_add`, `AddEvent`)
- Test: unit tests in `src/container/mounts.rs`, `tests/containers.rs`

**Interfaces:**
- Produces (all `pub` in `crate::container::mounts`):
  - `struct Mount { mount_point: String, device: Option<String>, fs_type: Option<String>, options: Option<String>, read_only: Option<bool>, image: Option<String>, volume_serial: Option<String>, volume_label: Option<String>, volume_guid: Option<String>, backing: Option<Box<Mount>>, paths: Vec<String> }` with `to_json(&self) -> Value` / `from_json(&Value) -> Option<Mount>`. An empty `mount_point` with all `None` means "mount unknown".
  - `fn mounts_for(paths: &[PathBuf]) -> Vec<Mount>`: one `Mount` per distinct mount, `paths` = the sources below it.
  - `fn mount_line(m: &Mount) -> String`: `"/mnt/disk · /dev/loop0 · ntfs3 · ro,noatime · image /cases/disk.raw"` (absent parts left out; Windows: `"D:\ · NTFS · serial 1A2B-3C4D · label EVIDENCE · ro"`); unknown → `"mount unknown"`.
  - Linux internals, `pub(crate)` for tests: `struct MountEntry { mount_point: String, device: String, fs_type: String, options: String }`, `fn parse_mountinfo(text: &str) -> Vec<MountEntry>` (octal escapes `\040` etc. decoded; options = per-mount options field), `fn containing<'a>(entries: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry>` (longest mount-point prefix, component-wise).
  - `Staged.mounts: Vec<Mount>`; `AddEvent.mounts: Vec<Mount>`; payload key `"sources"` (list of `Mount::to_json`). Turtle: one subject per mount (`new_arn()`), type `factum:Mount`, properties `factum:mountPoint`, `factum:device`, `factum:fileSystem`, `factum:mountOptions`, `factum:readOnly` (xsd:boolean), `factum:image`, `factum:volumeSerial`, `factum:volumeLabel`, `factum:volumeGuid`, `factum:backingMount` (IRI); the task gets `factum:mount <arn>` per mount.

- [ ] **Step 1: Write the failing tests:**
  - `parse_mountinfo_decodes_and_matches`: a fixture with `/`, `/mnt/my\040disk` (`/dev/loop0`, `ntfs3`, `ro,noatime`), and `/mnt/xmount` (`fuse.xmount`); `containing(.., "/mnt/my disk/Users/a")` is the loop mount with `mount_point == "/mnt/my disk"`; `containing(.., "/home/x")` is `/`.
  - `read_only_from_options`: options `ro,noatime` → `Some(true)`; `rw,relatime` → `Some(false)`.
  - `mount_line_formats`: a full Linux `Mount` with a `backing` FUSE mount → the line contains `/dev/loop0`, `ntfs3`, `ro`; unknown → `"mount unknown"`.
  - `#[cfg(target_os = "linux")] mounts_for_temp_dir_is_known`: `mounts_for(&[tempdir])` → one mount, non-empty `mount_point`, `fs_type` present.
  - `#[cfg(windows)] mounts_for_temp_dir_has_volume`: one mount with `fs_type`, `volume_serial` and `volume_guid` present.
  - `add_logs_sources`: after `Setup::add`, the `container_files_added` payload has a non-empty `sources` list whose `paths` cover the added sources, and `container(id).adds[0].mounts` equals it.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement.** Linux: `/proc/self/mountinfo`; loop device → `/sys/block/loopN/loop/backing_file` into `image`, and `backing` = the mount containing that file when its `fs_type` starts with `fuse` (one level only). Windows: `GetVolumePathNameW`, `GetVolumeInformationW` (fs name, serial, label, `FILE_READ_ONLY_VOLUME` flag), `GetVolumeNameForVolumeMountPointW`. macOS: `statfs` (`f_mntonname`, `f_mntfromname`, `f_fstypename`, `MNT_RDONLY`), or unknown. Any failure → unknown, never an error. `stage_add_with` computes `mounts_for(sources)` before copying.
- [ ] **Step 4: Run** tests and Global Constraints → pass.
- [ ] **Step 5: Commit** `Containers: each add records the mounts its sources were read from`.

### Task 4: README names the verifier; LF for embedded files

**Files:**
- Create: `.gitattributes`
- Modify: `src/container/volume.rs` (`Volume::create`, the `README` constant), `src/container/README.txt`
- Test: unit test in `src/container/volume.rs`

**Interfaces:**
- Produces: `pub fn readme_text() -> String` in `volume.rs`: `README.txt` followed by
  ```
  Written by factum <VERSION>. verify_container.py in this container:
    SHA-256 <hex of VERIFY_CONTAINER_PY>
  The same script is published at
    https://github.com/overcuriousity/factum-rs/blob/v<VERSION>/src/container/verify_container.py
  Compare the hash with that copy (sha256sum verify_container.py) before running it.
  ```
  where `<VERSION>` is `env!("CARGO_PKG_VERSION")`. Written once at creation as `factum/README.txt` (the script is never rewritten either).
- `.gitattributes`: `src/container/verify_container.py text eol=lf`, `src/container/README.txt text eol=lf`, `src/export/verify.py text eol=lf`.

- [ ] **Step 1: Write the failing test** `readme_names_the_script_hash`: create a volume; its `factum/README.txt` member contains `hex(sha256(VERIFY_CONTAINER_PY))` and `blob/v{CARGO_PKG_VERSION}/src/container/verify_container.py`; the member `verify_container.py` hashes to the same value.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** `readme_text` and use it in `Volume::create`; add `.gitattributes`; run `git add --renormalize .` and check `git status` shows no content change for the three files on Linux.
- [ ] **Step 4: Run** tests and Global Constraints → pass.
- [ ] **Step 5: Commit** `Containers: the README names the bundled verifier's hash; embedded scripts stay LF`.

### Task 5: Re-check before close

**Files:**
- Modify: `src/container/volume.rs` (new `Recheck`, `recheck`), `src/containers.rs` (`recheck_input`, `close_container`, `close_container_with`)
- Test: `tests/containers.rs`

**Interfaces:**
- Produces:
  - `pub struct Recheck { pub files: u64, pub bytes: u64, pub uncached: bool, pub mismatches: Vec<FileRecord> }` in `volume.rs`.
  - `pub fn recheck(path: &Path, end: u64, records: &[FileRecord], progress: &AddProgress, cancel: &AtomicBool) -> Result<Recheck>`: opens the file read-only, reads the state ending at `end`, hashes each record's stored content (MD5, SHA-1, SHA-256 via the existing `stream` hashing), a record whose content cannot be read or differs goes to `mismatches`. Before reading: Linux `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)` → `uncached = true`; macOS `fcntl(F_NOCACHE, 1)` → `uncached = true`; Windows → `uncached = false`. Cancel → `Err("Re-check cancelled — the container was not closed.")`.
  - `pub struct RecheckInput { pub path: PathBuf, pub end: u64, pub records: Vec<FileRecord> }`; `Factum::recheck_input(&self, id: i64) -> Result<RecheckInput>`: the records of adds logged after the newest entry in `detail.closes` (all adds if none), without metadata-only files, links, and ARNs replaced (Task 6). Errors if the file is missing.
  - `Factum::close_container_with(&self, id: i64, gpgsm: &Gpgsm, recheck: &Recheck) -> Result<CloseEvent>`: refuses when `recheck.mismatches` is non-empty (`"{n} files in the container don't match their hashes."`); payload gains `"recheck": {"files", "bytes", "uncached"}`; text `Container #{id} closed · {file_count} files · re-checked · {signed|unsigned}`.
  - `Factum::close_container(&self, id: i64) -> Result<CloseEvent>`: `recheck_input` + `recheck` (no progress, no cancel) + `close_container_with(id, &self.gpgsm(), ..)`.

- [ ] **Step 1: Write the failing tests:**
  - `close_rechecks_and_logs_it`: add two files, close → payload `recheck.files == 2`, `recheck.bytes == 3`, text contains "re-checked"; on Linux `uncached == true`.
  - `close_after_reopen_rechecks_only_new_files`: add, close, reopen, add one file, close → second close `recheck.files == 1`.
  - `damaged_bytes_refuse_the_close`: add, then overwrite the stored bytes of one file in place (helper modelled on `swap_content_and_drop_storage_type`, keeping the length) → `close_container` Err containing "don't match their hashes"; no new `container_closed` event; `container(id).summary.open == true`.
  - `recheck_reports_the_damaged_file`: same setup, `recheck(..)` returns `mismatches.len() == 1` with that file's path.
  - `close_with_missing_file_fails_cleanly` (Review Focus 3): add, delete the container file → `close_container` Err; no event; still open.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** as specified; the close keeps its existing order otherwise (match with log, sign, write, log).
- [ ] **Step 4: Run** tests and Global Constraints → pass (existing close tests now see "re-checked" in texts; update their expected texts).
- [ ] **Step 5: Commit** `Containers: closing re-reads what was added and compares its hashes`.

### Task 6: Damaged close and replaced copies

**Files:**
- Modify: `src/containers.rs` (`ContainerDetail`, `container`, `list_containers`, new functions), `src/container/volume.rs` (`finalize_add`), `src/container/verify.rs` (stream check), `src/container/verify_container.py`
- Test: `tests/containers.rs`, `tests/container_zip.rs` (Python verifier test, where the existing Python tests live)

**Interfaces:**
- Consumes: `Recheck`, `RecheckInput` (Task 5); `AddOptions.replaces`, `FileRecord.source`, payload `base_path`/`keep_path` (Task 2).
- Produces:
  - `Factum::close_container_damaged(&self, id: i64, damaged: &[FileRecord]) -> Result<i64>`: logs `container_closed` with `"damaged": [paths]`, `"file_count"`, `"closed_utc"`, no signatures, writes nothing to the file. Text: `Container #{id} closed as damaged · {k} files don't match their hashes · not signed`.
  - `ContainerDetail.damaged_closes: Vec<(i64, String, Vec<String>)>` (entry id, time, paths); `ContainerSummary.damaged` = the newest close is a damaged one.
  - `Factum::add_again_plan(&self, id: i64, mismatches: &[FileRecord]) -> Result<Vec<(Vec<PathBuf>, AddOptions)>>`: one entry per original add (its `base_path`, `keep_path`, the record's `excerpt`, `replaces` = (source, old ARN)). Err `"{path}: its source is not recorded, so it cannot be added again."` when `source` or the add's `base_path` is missing.
  - `finalize_add` writes `<old arn> factum:replacedBy <new arn>` for each `replaces` entry whose source was added; `commit_container_add` adds payload `"replaces": [{"arn": old, "by": new}]` when non-empty. `recheck_input` excludes replaced ARNs.
  - `verify.rs`: a stream whose hash fails but which has `factum:replacedBy` → `Level::Warn`, code `"replaced_copy"`, message `"{name}: the content does not match its hashes; replaced by a copy added again ({new path})."`. `verify_container.py` prints the same as ⚠ and does not count it as failed.

- [ ] **Step 1: Write the failing tests:**
  - `damaged_close_logs_and_writes_nothing`: damage a file (Task 5 helper), `close_container_damaged(id, &mismatches)` → event has `damaged == [path]` and no `signatures`; container file length unchanged; `list_containers(..)[0].damaged && !open`; `sign_unsigned_containers` signs nothing for it.
  - `reopen_after_damaged_close_rechecks_again`: reopen → `recheck_input(id).records` still contains the damaged file.
  - `add_again_replaces_and_closes_signed`: damage a file; `add_again_plan` → one group; stage/commit it like `Setup::add`; payload `replaces[0].arn` = old ARN; `close_container` succeeds; `verify_container_file` has one `replaced_copy` warning and no `stream_hash` fail.
  - `add_again_needs_a_recorded_source`: a record with `source: None` → Err containing "its source is not recorded".
  - Python: `verify_container_py_warns_on_replaced_copy` → exit code 0, output contains ⚠ and "replaced".
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement** as specified. `compare_records` (log vs. container) must stay clean for replaced and damaged containers.
- [ ] **Step 4: Run** tests and Global Constraints → pass.
- [ ] **Step 5: Commit** `Containers: close as damaged, or add the failed files again`.

### Task 7: Tree symbol and container sections under the notes

**Files:**
- Modify: `src/gui/mod.rs` (`View`, `read_view`, tree drawing, `notes_column`, `select`, `select_container`), `src/gui/containers.rs` (`container_view` → `container_section`, `tree_label`, new `symbol_hover`), `src/gui/icons.rs`, `scripts/subset-icons.sh`, `assets/fonts/Phosphor-Regular-subset.ttf`
- Test: `src/gui/tests.rs`

**Interfaces:**
- Consumes: `ContainerSummary.{evidence_id, signed, damaged}` (Tasks 1, 6), `AddEvent.mounts`, `mount_line` (Task 3).
- Produces:
  - `icons::CONTAINER` (Phosphor `package`).
  - `View.containers: Vec<ContainerDetail>` (the selected evidence's containers, oldest first, or the one selected fallback container) replacing `View.container`; `View.container_times: HashMap<i64, HashMap<String, String>>` keyed by container id.
  - `containers::container_section(ui, detail: &ContainerDetail, times: &HashMap<String, String>, archived: bool, busy: bool, actions: &mut Vec<ContainerAction>)`: heading (symbol, name, file name, state `open` / `closed · signed` / `closed · unsigned` / `closed · damaged` / `file missing`, ⋯ menu = `containers::menu`), details (File, UUID with copy button, Base path or `full paths`), history (adds with `mount_line` per mount; closes; reopens), files.
  - `containers::symbol_hover(summaries: &[&ContainerSummary]) -> String`: one → `"Container · {state}"`; several → `"{n} containers · {k} open"`.
  - Fallback rows: containers whose `evidence_id` is `None` or not among the case's non-deleted evidence; row text = container name; hover adds `"Evidence #{n} (deleted)"` when the id is set. Clicking selects it (`container_id`) and shows only its section.

- [ ] **Step 1: Write the failing tests** (existing harness, `Fixture`/`select_case` helpers):
  - `evidence_row_shows_symbol_only_with_container`: evidence "disk" with a container, "usb stick" without → the tree has `icons::CONTAINER` exactly once, and no row labelled with the container name.
  - `selecting_evidence_shows_notes_then_containers`: select "disk" with two containers → the note text and both container names are visible; screenshot `evidence_with_containers`.
  - `search_keeps_container_sections` (Review Focus 4): with a search that matches no note, the container section is still visible.
  - `old_container_without_evidence_gets_its_own_row`: write a `container_created` entry with `evidence_id: null` through `Factum::append` (system kind, payload as in 2.6) → a tree row with the container name; selecting it shows its section.
  - `container_of_deleted_evidence_gets_its_own_row`: same with an evidence id that is deleted → row present, hover text contains "(deleted)".
  - `symbol_hover_texts` (unit): one open → "Container · open"; three, one open → "3 containers · 1 open".
  - Update or remove the old tests that select container rows (`tree_lists_container_with_count_and_state`, `selecting_container_shows_its_files`, `jump_to_entry_leaves_the_container_view`, `missing_file_is_marked_and_locate_enabled`, `add_disabled_while_closed`) to act on the section's ⋯ menu instead.
- [ ] **Step 2: Run** `cargo test --lib gui::` → fail.
- [ ] **Step 3: Implement.** Add the glyph to `scripts/subset-icons.sh` and regenerate the subset font. The symbol colour: `p.accent` if any container is open, else `p.muted`; ⚠ marker if any file is missing. The ShowEntry action from a section selects the case (as `jump_to_entry` does today).
- [ ] **Step 4: Run** tests and Global Constraints → pass; render screenshots with `FACTUM_SCREENSHOTS` (CONTRIBUTING.md) and look at `evidence_with_containers.png`.
- [ ] **Step 5: Commit** `GUI: containers shown as a symbol on their evidence and as sections under its notes`.

### Task 8: Menus and dialogs (New Container, Acquire, optional base path)

**Files:**
- Modify: `src/gui/dialogs.rs` (`Dialog::NewContainer`, `DialogResult::NewContainer`, `Dialog::AddToContainer`), `src/gui/mod.rs` (`open_new_container`, tree menus, `TreeAction`, result handling, `open_add_to_container`), `src/gui/containers.rs`
- Test: `src/gui/tests.rs`

**Interfaces:**
- Consumes: `create_container`, `create_evidence_with_container` (Task 1); `mounts_for` (Task 3); `start_add` (existing).
- Produces:
  - `Dialog::NewContainer { case_id: i64, evidence: Option<(i64, String)>, name: String, hash: String, details: String, acquire: String, folder: String, file_name: String, error: Option<String> }` (`evidence: None` = the case dialog).
  - `DialogResult::NewContainer { case_id: i64, evidence_id: Option<i64>, name: String, hash: String, details: String, path: PathBuf, acquire: Option<PathBuf> }`.
  - `TreeAction::NewContainerFor(i64)` (evidence id).
  - `Dialog::AddToContainer` gains `writable_hint: bool` (computed when opened: `cfg!(windows)` and any source's mount has `read_only == Some(false)`).

- [ ] **Step 1: Write the failing tests:**
  - `case_new_container_creates_evidence_and_container`: case dialog, Name "USB 2", Folder = temp dir → Create → a new evidence "USB 2" is selected and has one container; screenshot `new_container_case`.
  - `evidence_new_container_prefills_name`: evidence "disk" with one container → evidence dialog's name is "disk 2", title "New Container for disk"; no hash/description fields.
  - `acquire_adds_the_folder_in_one_step`: Acquire = a temp folder with two files → after the add job finishes (poll the harness until `add_job` is `None`), the container has 2 files and `base_path` = that folder.
  - `add_dialog_accepts_empty_base`: open Add Files with base cleared → no validation error; the add stores full paths.
  - `evidence_menu_has_new_container_and_delete_disabled`: evidence with a container → context menu contains "New Container…"; "Delete Evidence…" disabled with hover "Only evidence without notes or containers".
  - Update `new_container_dialog_creates_file_and_selects_it` and `new_container_dialog_validates` to the new fields.
- [ ] **Step 2: Run** `cargo test --lib gui::` → fail.
- [ ] **Step 3: Implement.** Case dialog copy, first line: "Creates a new evidence item with an AFF4-L container. Every addition, close and reopen is a signed entry in the case log." Field order: Name, Evidence hash (optional), Description (optional), Acquire (optional, folder picker, hint below: "Copied in right away, e.g. the read-only mount point. Leave empty to add files later."), Folder, File name. Evidence dialog: Name, Acquire, Folder, File name. The base path of the new container = Acquire (or `""`). Acquire → `start_add(id, vec![acquire], AddOptions { base: acquire, keep_path: true, ..Default::default() }, cancel)`. Add dialog: base label "Base path (optional)", hint "Removed from the sources' paths, e.g. the mount point. Empty: full paths are kept."; `writable_hint` shows "Windows may update access times on this writable volume." in the warning colour. Remove "From evidence" and the container's separate base path field. Case menus keep "New Container…"; evidence context menu gains "New Container…" after "Edit Description…" (not in archived cases).
- [ ] **Step 4: Run** tests and Global Constraints → pass; look at the dialog screenshots.
- [ ] **Step 5: Commit** `GUI: New Container on case and evidence, Acquire, optional base path`.

### Task 9: Close in the background; the damaged dialog

**Files:**
- Modify: `src/gui/workers.rs` (new `recheck` worker), `src/gui/mod.rs` (`CloseJob`, `poll`, `container_action` Close, `carry_out` `CloseContainersAndArchive`, status bar), `src/gui/dialogs.rs` (`Dialog::Damaged`, `DialogResult::AddAgain` / `CloseDamaged`)
- Test: `src/gui/tests.rs`

**Interfaces:**
- Consumes: `recheck_input`, `recheck`, `close_container_with` (Task 5); `close_container_damaged`, `add_again_plan` (Task 6); `start_add`, `AddJob` (existing).
- Produces:
  - `workers::recheck(ctx, input: RecheckInput, cancel) -> (Worker<Result<Recheck, String>>, Arc<AddProgress>)`.
  - `struct CloseJob { container_id: i64, name: String, worker, progress, cancel, then_archive: Option<i64> }` in `FactumApp.close_job: Option<CloseJob>`; status bar `Re-checking "{name}": {files} / {total} files · {bytes} / {total bytes}`, Cancel as for adds.
  - `Dialog::Damaged { container_id: i64, mismatches: Vec<FileRecord>, add_again: Result<Vec<(Vec<PathBuf>, AddOptions)>, String>, then_archive: Option<i64> }`; buttons "Add Again" (disabled with the Err text as hover when `add_again` is Err), "Close as Damaged", "Cancel". Text: "{n} files in the container don't match their hashes. The container file or its disk may be damaged." followed by the paths.
  - `FactumApp.pending_adds: VecDeque<(Vec<PathBuf>, AddOptions)>` and `close_after_adds: Option<(i64, Option<i64>)>`: Add Again queues the groups, starts the first; each finished add starts the next; after the last successful one, Close starts again. A failed add clears the queue and shows the error (container stays open).
  - Close and Archive: missing files are closed without file synchronously as today; the rest are closed one after another through `CloseJob` with `then_archive`; the case is archived after the last; a damaged dialog or a cancel stops the archive.

- [ ] **Step 1: Write the failing tests:**
  - `close_runs_in_background_and_logs_recheck`: Close from the section menu → `close_job` is set; after polling until done, the container is closed and the newest entry's text contains "re-checked".
  - `damaged_container_opens_the_dialog`: damage a stored file, Close → `Dialog::Damaged` with one mismatch; Cancel → still open, no new event; screenshot `damaged_dialog`.
  - `close_as_damaged_from_the_dialog`: → summary `damaged`, section state "closed · damaged".
  - `add_again_then_closes`: → after polling, a `container_files_added` with `replaces` and a signed close.
  - `add_again_with_source_gone_shows_error` (Review Focus 5): delete the source file before Add Again → error message shown, no new event, container open, the next Close shows the dialog again.
  - Update `pending archive` tests (`then: Pending::CloseContainersAndArchive`) to poll the close jobs.
- [ ] **Step 2: Run** `cargo test --lib gui::` → fail.
- [ ] **Step 3: Implement** as specified. While `close_job` or `add_job` runs, Add/Close/Reopen of any container wait with the existing "being added" style message ("A container is being re-checked. …").
- [ ] **Step 4: Run** tests and Global Constraints → pass.
- [ ] **Step 5: Commit** `GUI: closing re-checks in the background; Add Again or Close as Damaged after a mismatch`.

### Task 10: Reports

**Files:**
- Modify: `src/export/model.rs` (`ContainerRow`, `container_rows`), `src/export/html.rs`, `src/export/markdown.rs`, `src/export/pdf.rs`
- Test: `tests/export.rs`

**Interfaces:**
- Consumes: `AddEvent.mounts`, `mount_line` (Task 3), `ContainerDetail.damaged_closes` (Task 6).
- Produces: `ContainerRow` gains `sources: Vec<String>` (one line per add and mount: `"{short time} · {mount_line}"`), and its state text covers "closed as damaged"; a container without a base path shows `Base path: full paths`.

- [ ] **Step 1: Write the failing test** `report_lists_container_sources_and_damaged_state`: case with a container (one add, then a damaged close) → HTML, Markdown and PDF text (existing helpers) contain the mount line of the add and "damaged".
- [ ] **Step 2: Run** `cargo test --test export` → fail.
- [ ] **Step 3: Implement** in the existing key/value block above each container's file list.
- [ ] **Step 4: Run** tests and Global Constraints → pass.
- [ ] **Step 5: Commit** `Reports: container sources per add, damaged closes`.

### Task 11: Public sample container

**Files:**
- Create: `scripts/sample-container.sh`, `examples/sample_container.rs`, `samples/container/README.md`, and the generated `samples/container/{sample.aff4l, gpg-public.asc, root.pem, intermediate.pem}`
- Create: `tests/sample_container.rs`
- Modify: `.github/workflows/ci.yml` (Linux job)

**Interfaces:**
- Consumes: the library API (`Db`, `Factum`, `create_evidence_with_container`, add, `close_container`, `reopen_container`), the X.509 settings `X509_CERT_SETTING` / `X509_CHAIN_SETTING`, `active_gpg_key_id`.
- Produces: `cargo run --example sample_container -- <out dir>` writes `sample.aff4l` with: case "SAMPLE", evidence "Sample evidence", files `hello.txt` ("hello\n") and `docs/readme.md` (short text) → close → reopen → add `later.txt` → close. Signed with GPG and X.509.

- [ ] **Step 1: Write** `scripts/sample-container.sh`: temporary `GNUPGHOME`; `gpg --batch --passphrase '' --quick-gen-key 'factum sample (TEST ONLY) <sample@factum.invalid>' ed25519 sign never`; `openssl` root CA → intermediate → signing certificate (all marked TEST ONLY in the subject), imported into `gpgsm` (`--import` PKCS#12 without passphrase), root added to `$GNUPGHOME/trustlist.txt`; runs the example with the env; exports the GPG public key and the two CA certificates into `samples/container/`; deletes the temporary home. No private key leaves it.
- [ ] **Step 2: Write** `examples/sample_container.rs` (signer constructed as `src/main.rs` does; settings set before the first close).
- [ ] **Step 3: Run** `scripts/sample-container.sh` → the four files appear; `python3 src/container/verify_container.py samples/container/sample.aff4l --ca samples/container/root.pem --use-carried-key` exits 0 with two closed states.
- [ ] **Step 4: Write the test** `tests/sample_container.rs::sample_verifies`: `container::verify::verify_file` on the sample with a `FakeSigner` and a `Gpgsm` without trust → no `Level::Fail` finding with code `stream_hash`, `turtle_hash` or `history`; two closed states (`report.states.iter().filter(|s| s.close.is_some()).count() == 2`). Add the CI step running the Python command from Step 3 in the Linux job.
- [ ] **Step 5: Write** `samples/container/README.md`: what the sample is for (checking other AFF4-L tools against factum's GPG and X.509 signatures), that all keys are throwaway and TEST ONLY, how it was made (`scripts/sample-container.sh`), how to verify (factum Verify Container…; the Python command; other tools), and that it is regenerated by hand when the format changes.
- [ ] **Step 6: Run** tests and Global Constraints → pass.
- [ ] **Step 7: Commit** `Samples: a signed sample container with throwaway test keys`.

### Task 12: Documentation

**Files:**
- Modify: `README.md` (Evidence containers section, lines ~138–166), `CHANGELOG.md` (`[Unreleased]`)

- [ ] **Step 1: Update `README.md`**: containers belong to evidence (symbol in the tree, sections under the notes); New Container… on a case (creates evidence) and on evidence; Acquire; optional base path and full paths; mount details per add; re-check at close with Add Again / Close as Damaged; README hash and GitHub copy of the verifier; `samples/container/`. Add **Known limitations on Windows**: the re-check reads through the Windows file cache and may not detect a bad write to the disk; factum does not prevent the last-access time of sources on a writable volume from being updated, so add from a read-only mounted image or behind a write blocker.
- [ ] **Step 2: Update `CHANGELOG.md` `[Unreleased]`** with Added / Changed entries in the style of the 2.6.0 and 2.7.0 sections, including the two Windows limitations and that evidence with containers can no longer be deleted.
- [ ] **Step 3: Run** Global Constraints commands → pass.
- [ ] **Step 4: Commit** `Docs: containers as evidence, re-check, Windows limitations`.
