# Evidence containers: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Signed AFF4-L v1.0 evidence containers per case: created, filled, closed, reopened and verified from the
GUI, with every step a signed entry in the case log, plus a verifier that recipients can run without factum.

**Architecture:** A GUI-independent library module `src/container/` writes and reads the container file. It has its
own append-only ZIP64 writer (earlier bytes never move), a Turtle writer and a subset reader, streams that hash in the
same pass, a volume type for create/add/close, `gpgsm` signing and verification. A service file `src/containers.rs`
(`impl Factum`) ties it to the case log: the log entry is appended first and the container write runs in the append
transaction (`Append::on_commit`). The case log stays the only record of container state; the GUI derives everything
from it. Copying runs on a worker thread. The worker hands the open, locked volume back to the GUI thread, which
finalizes it inside the log append.

**Tech Stack:** Rust 2024, rusqlite (bundled SQLite 3.51, JSON functions), flate2, sha2, new: `md-5`, `sha1`,
`uuid` (v4), `base64`, `libc` (Linux only, for `O_NOATIME`). egui 0.37 / egui_kittest. System `gpg` and `gpgsm`.
Python 3 stdlib for the bundled `verify_container.py`.

**Spec:** `docs/superpowers/specs/2026-10-26-evidence-containers-design.md` (approved 2026-10-26)

## Changes since the spec (read these first)

The application has moved on since the spec was written. These points override it:

1. **Schema.** The spec says schema 3, shared with factum-notes. The database is now schema 4 and factum-notes cannot
   open it (CONTRIBUTING.md). The design stays as written: no tables, the case log is the only truth, file locations
   live in `settings`. The factum-notes cross-check in spec 5 is dropped. `verify.py` (the bundle verifier) must
   still pass on a case with container events.
2. **pyaff4.** pyaff4 (main, 2026-08) does not implement AFF4-L v1.0. It recognises only `version.txt` 1.1, and a
   2.1 container falls into its pre-standard reader. Decided by the user on 2026-10-27: write strict AFF4-L v1.0 (the
   most recent standard). The "opens in pyaff4" tests are replaced by: Python's `zipfile` reads every member,
   `unzip -t` passes where installed, and both factum verifiers pass. Pyaff4 interop moves to the open risks.
3. **Namespaces.** The standard's text and its examples disagree. The plan follows the spec's choices and pins them
   (Global Constraints). The reader accepts `aff4:` and `aff4l:` for every term, and `http`/`https` for the aff4l
   namespace.
4. **GUI.** The menus are now Case / Settings, with icon buttons and context menus on the case tree. "Sign Unsigned"
   is now **Sign All Unsigned**. Long work shows its progress in the status bar or a modal (verification).
   There is now a setup wizard. Its Signing key step also offers the X.509 certificate when `gpgsm` lists one
   (Task 14); the spec only had Settings.
5. **Evidence description.** Evidence now has a name (column `description`) and a free-text `details`. Both go into
   the volume metadata.
6. **Symlinks in the log.** Every file record in `container_files_added` gets a `link` field (target or `null`). The
   spec's field list has no place for a link, but the log/container comparison needs it.

## Global Constraints

- After every task: `cargo test`, `cargo test --no-default-features`, `cargo clippy --all-targets` (no warnings),
  `cargo fmt --check` pass (CONTRIBUTING.md). `src/container/` and `src/containers.rs` must build without the `gui`
  feature.
- Never touch `canonical.rs`, `merkle.rs`, `leaf_data`, `entry_signed_payload`, `seal_payload`, `src/export/verify.py`.
- No schema change, no new table; `SCHEMA_VERSION` stays 4.
- No network, no new runtime programs beyond `gpg`/`gpgsm`. New crates: `md-5 = "0.11"`, `sha1 = "0.11"`,
  `uuid = { version = "1", features = ["v4"] }`, `base64 = "0.22"`, and `libc = "0.2"` under
  `[target.'cfg(target_os = "linux")'.dependencies]`. Use the versions already in `Cargo.lock` where they exist.
- Streaming everywhere: no whole file in memory. Buffers are at most 1 MiB, except one ImageStream bevy (64 MiB).
- Sources are opened read-only, with `O_NOATIME` on Linux. On `EPERM`, retry without the flag.
- Container files: extension `.aff4l`. `version.txt` = `major=2\nminor=1\ntool=factum <VERSION>\n`.
  `container.description` and the ZIP archive comment are both `aff4://<uuid>`. Members are named by ARN unescaped
  (`aff4://<uuid>`). The volume ARN and every object ARN are `aff4://` + lowercase UUID v4.
- Namespaces: `aff4:` = `http://aff4.org/Schema#`, `aff4l:` = `https://aff4.org/Schema/2022/#`,
  `factum:` = `https://github.com/overcuriousity/factum-rs/schema/2026#`, `xsd:` =
  `http://www.w3.org/2001/XMLSchema#`, `rdf:` = `http://www.w3.org/1999/02/22-rdf-syntax-ns#`.
- Terms (spec 4.2): `aff4:FileImage`, `aff4:Image`, `aff4:ZipSegment`, `aff4:ImageStream`, `aff4:ZipVolume`,
  `aff4:size`, `aff4:hash` (`^^aff4:MD5`, `^^aff4:SHA1`, `^^aff4:SHA256`), `aff4:stored`, `aff4:chunkSize`,
  `aff4:chunksInSegment`, `aff4:compressionMethod`. Also `aff4l:Folder`, `aff4l:LogicalAcquisitionTask`,
  `aff4l:fileName`, `aff4l:fileNameRaw`, `aff4l:originalPathName`, `aff4l:originalPathNameRaw`, `aff4l:lastWritten`,
  `aff4l:lastAccessed`, `aff4l:recordChanged`, `aff4l:birthTime`, `aff4l:fileMode`, `aff4l:filesystemRoot`,
  `aff4l:pathSeparator`.
- factum properties: on the volume `factum:caseFile`, `factum:caseId`, `factum:containerName`,
  `factum:evidenceId`, `factum:evidenceName`, `factum:evidenceDescription`. On each task `factum:logEntry`. On files
  `factum:metadataOnly`, `factum:excerptStart`, `factum:excerptEnd` (exclusive), `factum:originalSize`,
  `factum:symlinkTarget`.
- Timestamps in Turtle: `xsd:dateTime`, UTC, `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, fraction trimmed of trailing zeros.
- ZipSegment up to `ZIP_SEGMENT_LIMIT = 1 << 30` bytes (deflated, `Compression::fast()`). Larger content is an
  ImageStream: chunk 32 KiB, 2048 chunks per bevy, zlib per chunk (`https://www.ietf.org/rfc/rfc1950.txt`). A chunk
  whose zlib output is not smaller than `chunk_size - 16` is stored raw, padded to `chunk_size`. Bevy member
  `<arn>/%08d`, stored (ZIP method 0). Index `<arn>/%08d.index`, entries `<QI` (u64 offset, u32 length).
- Metadata-only files and links are `aff4:FileImage` without a storage type and without a member.
- Signatures (spec 4.3): `information.turtle.asc`, `information.turtle.pubkey.asc`,
  `information.turtle.factum.sig`, `information.turtle.factum.cer`. History copies go to `factum/history/<n>/`,
  n from 1. `information.turtle.hashes` (SHA-256 and SHA-512, standard 10.1) is written with *every*
  `information.turtle`.
- Log events and payloads exactly as in spec 4.1, plus `container_signed` (spec 4.3), plus `link` per file record
  (Changes 6). `excerpt` is `null` or `[start, end]`. Text formats:
  `Container #N "<name>" created` (+ ` (from evidence #E)`), `<k> files added to container #N (<size>)`,
  `Container #N closed · <k> files · signed|unsigned`, `Container #N reopened`, `Container #N signed`. N is the
  entry id of `container_created`. Sizes are formatted like the status bar (`4.1 MB`, decimal units).
- Settings keys: `container_path:<uuid>`, `container_end:<uuid>` (byte length after the last successful write),
  `x509_certificate` (gpgsm fingerprint), `x509_chain_files` (newline-separated paths).
- GUI: icons only from `src/gui/icons.rs` as it is (no new glyphs). Tooltips a few words. The per-row timestamp and
  signature mark are untouched (memory: minimal UI).

## Review Focus

1. A source file that changes while it is read (a log being written) → that file is an error and is not added,
   the rest of the operation goes on. → Task 5 test `changed_file_is_reported_not_added`.
2. The same file selected twice in one Add (a folder plus a file inside it) → stored once.
   → Task 5 test `overlapping_sources_store_each_file_once`.
3. A source outside the base path (another mount) → refused before anything is copied, naming the file.
   → Task 3 test `source_outside_base_is_refused`.
4. Zero-byte files and empty folders → stored with the hashes of empty input; the folder is recorded.
   → Task 5 test `empty_file_and_empty_folder_round_trip`.
5. Excerpt with `start >= end` or `end > size` → refused before copying. → Task 5 test `excerpt_out_of_range_is_refused`.

---

### Task 1: Append-only ZIP64

**Files:**
- Modify: `Cargo.toml` (crates from Global Constraints)
- Modify: `src/lib.rs` (`pub mod container;`)
- Create: `src/container/mod.rs` (namespace constants, `ZIP_SEGMENT_LIMIT`, submodule list), `src/container/zip64.rs`
- Test: unit tests in `zip64.rs`; `tests/container_zip.rs`

**Interfaces:**
- Produces:
  - `pub struct CdEntry { pub name: Vec<u8>, pub method: u16, pub crc32: u32, pub compressed_size: u64, pub size: u64, pub header_offset: u64 }`
  - `pub struct Archive { pub entries: Vec<CdEntry>, pub comment: Vec<u8>, pub end: u64 }` and
    `Archive::get(&self, name: &str) -> Option<&CdEntry>`
  - `pub fn read_archive(file: &mut File, end: u64) -> io::Result<Archive>`: the EOCD must end exactly at `end`.
  - `pub fn find_last_end(file: &mut File, hint: Option<u64>) -> io::Result<Option<u64>>`: the file length first,
    then `hint`, then a backward scan for an EOCD whose central directory parses and ends where the ZIP64 EOCD
    record begins.
  - `pub fn member_reader<'f>(file: &'f mut File, entry: &CdEntry) -> io::Result<Box<dyn Read + 'f>>` (inflates
    method 8).
  - `pub struct Appender` with `new(file: File, start: u64, existing: Vec<CdEntry>) -> Appender`,
    `add_member(&mut self, name: &str, method: u16, data: &mut dyn Read, observe: &mut dyn FnMut(&[u8])) -> io::Result<CdEntry>`
    (`observe` sees uncompressed bytes; sizes and CRC are patched into the local header afterwards),
    `add_bytes(&mut self, name: &str, method: u16, bytes: &[u8]) -> io::Result<CdEntry>`, `position() -> u64`,
    `rewind_to(&mut self, pos: u64)`, `finish(&mut self, omit: &[&str], comment: &[u8]) -> io::Result<u64>`,
    `into_file(self) -> File`.

- [ ] **Step 1: Tests**
  - `round_trip_stored_and_deflated`: three members (empty, `b"abc"`, 3 MiB pattern, methods 0/8/8) →
    `read_archive` → each `member_reader` returns the input.
  - `zip_crate_reads_output`: after two Appender runs on the same file, `zip::ZipArchive` lists all names and reads
    the contents.
  - `python_zipfile_reads_output` (skip without `python3`):
    `python3 -I -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None"`.
  - `append_keeps_earlier_bytes`: copy the file after the first `finish`. After a second Appender run starting at
    the first `end`, the copy is a byte prefix of the new file.
  - `newest_member_of_a_name_wins_and_omit_removes`: add `information.turtle` twice, then `finish(&["x.asc"])` with
    an earlier `x.asc` → the directory has one `information.turtle` (the second) and no `x.asc`.
  - `interrupted_append_finds_previous_end`: `finish` → `end1`. A new Appender adds 200 KiB containing the bytes
    `PK\x05\x06`, dropped without `finish`. `read_archive(file, len)` fails; `find_last_end(file, None)` and
    `find_last_end(file, Some(end1))` both return `Some(end1)`.
- [ ] **Step 2:** `cargo test --lib container::zip64 && cargo test --test container_zip` → fail (module missing).
- [ ] **Step 3: Implement.** Always write ZIP64: local headers with a ZIP64 extra field, central directory entries
  with a ZIP64 extra field (sizes and offset), then the ZIP64 EOCD record, the locator and a classic EOCD with
  `0xFFFF`/`0xFFFFFFFF`. Set flag bit 11 for UTF-8 names. DOS time is the time of writing. `finish` deduplicates by
  name (the last entry wins), writes the directory at `position()`, and calls `sync_all`.
- [ ] **Step 4:** run the tests → pass; then the full check from Global Constraints.
- [ ] **Step 5: Commit** `Container: append-only ZIP64 writer and reader`.

### Task 2: Turtle writer and subset reader

**Files:**
- Create: `src/container/turtle.rs`

**Interfaces:**
- Produces:
  - `pub enum Term { Iri(String), Literal { value: String, datatype: Option<String> } }` (datatype is a full IRI)
  - `pub struct Triple { pub subject: String, pub predicate: String, pub object: Term }`
  - `pub struct Graph { pub triples: Vec<Triple> }` with `add(&mut self, s: &str, p: &str, o: Term)`,
    `objects<'g>(&'g self, s: &str, p: &str) -> impl Iterator<Item = &'g Term>`,
    `subjects_of_type<'g>(&'g self, type_iri: &str) -> impl Iterator<Item = &'g str>`. `objects` and
    `subjects_of_type` also match the same local name in the other aff4 namespace (Changes 3).
  - `pub fn write(graph: &Graph, prefixes: &[(&str, &str)]) -> String`
  - `pub fn parse(text: &str) -> Result<Graph, String>`

- [ ] **Step 1: Tests**
  - `round_trip_preserves_triples`: a graph with IRIs, plain and typed literals → `parse(write(g)) == g`.
  - `write_is_one_triple_per_line`: every line between `<subject>` and the closing ` .` is `    prefix:name object ;`.
    Subjects and predicates stay in insertion order. Output is byte-identical across two calls.
  - `escapes_round_trip`: values containing `"`, `\`, newline, tab and `ü` come back unchanged.
  - `parses_standard_examples`: the Turtle blocks of AFF4-L v1.0 sections 6.1, 9 and 10.1, verbatim (the 10.1 block
    uses `:/information.turtle`). Assert the expected subject/predicate/object of one triple each.
  - `blank_nodes_are_refused`: `[ … ]` → `Err` containing "blank node".
- [ ] **Step 2:** `cargo test --lib container::turtle` → fail.
- [ ] **Step 3: Implement.** Reader subset: `@prefix`/`PREFIX`, `<iri>`, prefixed names (local part may contain `/`
  and inner `.`), `a`, `"…"` and `"""…"""` with escapes, `^^` datatypes, language tags (dropped), bare integers and
  booleans (typed `xsd:long` / `xsd:boolean`), `;` `,` `.`, `#` comments. Writer escapes `\\ \" \n \r \t` and writes
  other control characters as `\uXXXX`.
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Container: Turtle writer and reader`.

### Task 3: Reading sources

**Files:**
- Create: `src/container/source.rs`

**Interfaces:**
- Produces:
  - `pub enum SourceKind { File, Folder, Link(PathBuf), Special }`
  - `pub struct SourceMeta { pub kind: SourceKind, pub size: u64, pub modified: Option<String>, pub accessed: Option<String>, pub changed: Option<String>, pub birth: Option<String>, pub mode: Option<u32> }`.
    Timestamps follow the Global Constraints format. `changed` and `mode` exist on Unix only.
  - `pub fn read_meta(path: &Path) -> io::Result<SourceMeta>` (`symlink_metadata`, never follows links)
  - `pub fn open_source(path: &Path) -> io::Result<File>`
  - `pub struct EncodedName { pub text: String, pub raw_b64: Option<String> }`; `pub fn encode_name(bytes: &[u8]) -> EncodedName`
  - `pub fn stored_path(path: &Path, base: &Path, keep_path: bool) -> Result<Vec<u8>, String>`
  - `pub fn walk(roots: &[PathBuf]) -> Vec<io::Result<(PathBuf, SourceMeta)>>`. Depth-first; entries of a folder
    sorted by name; a folder comes before its contents; a path reached twice is listed once.

- [ ] **Step 1: Tests**
  - `encode_name_follows_standard_section_5`: `b"\t\rmalware.exe\x08\x08\x08txt"` → text
    `"%09%0Dmalware.exe%08%08%08txt"` plus raw Base64 of the input. `b"caf\xe9"` → `"caf%E9"` plus raw.
    `"100%.txt"` → unchanged, `raw_b64 == None`.
  - `source_outside_base_is_refused`: `stored_path("/mnt/b/x", "/mnt/a", true)` → `Err` naming `/mnt/b/x`.
  - `stored_path_keeps_or_drops_the_path`: `/mnt/fs01/Users/x/evil.exe` with base `/mnt/fs01` →
    `Users/x/evil.exe`, or `evil.exe` with `keep_path = false`.
  - `walk_records_links_and_skips_nothing` (Unix): a folder with a file, a symlink and a FIFO (`libc::mkfifo` is
    Linux-only, so use `std::process::Command::new("mkfifo")` and skip when it is missing). Kinds come back as
    File, Link(target) and Special; the link target is not walked; the order is deterministic.
  - `meta_has_timestamps`: `modified` matches `fs::metadata().modified()` as text.
- [ ] **Step 2:** `cargo test --lib container::source` → fail.
- [ ] **Step 3: Implement** as specified. On Linux, `open_source` uses `OpenOptionsExt::custom_flags(libc::O_NOATIME)`.
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Container: source walking, metadata and AFF4-L name encoding`.

### Task 4: Content streams with hashing

**Files:**
- Create: `src/container/stream.rs`

**Interfaces:**
- Consumes: `Appender`, `CdEntry` (Task 1).
- Produces:
  - `pub struct Digests { pub md5: String, pub sha1: String, pub sha256: String }` (lowercase hex);
    `pub struct Hasher` with `new()`, `update(&mut self, &[u8])`, `finish(self) -> Digests`.
  - `pub enum Storage { ZipSegment, ImageStream { chunks: u64 } }`
  - `pub struct Stored { pub storage: Storage, pub size: u64, pub digests: Digests }`
  - `pub fn store(app: &mut Appender, arn: &str, src: &mut dyn Read, size_hint: u64, limit: u64, progress: &dyn Fn(u64), cancel: &AtomicBool) -> io::Result<Stored>`.
    `size_hint >= limit` → ImageStream. `progress` gets the bytes read so far. A set `cancel` →
    `io::ErrorKind::Interrupted`.
  - `pub fn hash_only(src: &mut dyn Read, progress: &dyn Fn(u64), cancel: &AtomicBool) -> io::Result<(u64, Digests)>`
  - `pub fn image_stream_reader<'f>(file: &'f mut File, archive: &Archive, arn: &str, size: u64, chunk_size: u64, chunks_per_segment: u64, compression: &str) -> io::Result<Box<dyn Read + 'f>>`
    (stored and zlib; other compression methods → `io::ErrorKind::Unsupported`)

- [ ] **Step 1: Tests**
  - `zip_segment_digests_of_abc`: md5 `900150983cd24fb0d6963f7d28e17f72`, sha1
    `a9993e364706816aba3e25717850c26c9cd0d89d`, sha256
    `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`. One member named after the ARN.
  - `image_stream_round_trips`: 200 KiB (half zeros, half pseudo-random bytes), `limit = 1` → members
    `<arn>/00000000` and `<arn>/00000000.index` (12 bytes per chunk). `image_stream_reader` returns the input, and
    the digests equal `hash_only` of the input.
  - `cancel_interrupts`: `cancel` set before the call → `Interrupted`.
  - `#[ignore] large_file_uses_image_stream`: 1.1 GiB sparse file, real limit → ImageStream, round-trips
    (run by hand: `cargo test -- --ignored`).
- [ ] **Step 2:** `cargo test --lib container::stream` → fail.
- [ ] **Step 3: Implement** with the pinned ImageStream layout (Global Constraints), hashing in the same read pass.
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Container: ZipSegment and ImageStream storage with one-pass hashing`.

### Task 5: The container volume (create, add, close, reopen, recovery)

**Files:**
- Create: `src/container/volume.rs`, `src/container/README.txt` (spec 4.2), placeholder
  `src/container/verify_container.py` (replaced in Task 10)
- Test: unit tests in `volume.rs`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `pub struct VolumeInfo { pub name: String, pub case_file: String, pub case_id: i64, pub evidence: Option<(i64, String, String)>, pub created_utc: String }`
    (evidence: id, name, description)
  - `pub struct AddOptions { pub base: PathBuf, pub keep_path: bool, pub metadata_only: bool, pub excerpt: Option<(u64, u64)> }`
  - `pub struct FileRecord { pub arn: String, pub path: String, pub size: u64, pub md5: String, pub sha1: String, pub sha256: String, pub metadata_only: bool, pub excerpt: Option<(u64, u64)>, pub link: Option<String> }`
    with `to_json(&self) -> Value` and `from_json(&Value) -> Option<Self>`. The keys are the payload keys of spec 4.1
    plus `link`. Links have empty hashes and size 0.
  - `pub struct AddProgress { pub files: AtomicU64, pub bytes: AtomicU64, pub total_files: AtomicU64, pub total_bytes: AtomicU64 }`
  - `pub struct Staged { pub start: u64, pub records: Vec<FileRecord>, pub skipped: Vec<(String, String)>, pub errors: Vec<(String, String)>, … }`
    (path, reason; other fields private)
  - `pub struct Signatures { pub gpg: Option<(String, String)>, pub x509: Option<(String, String)> }`
    (signature, public key / chain)
  - `pub struct Volume` (holds the locked `File` via `File::try_lock`, the `Archive`, the `Graph`, the uuid; `Send`):
    - `create(path: &Path, uuid: &str, info: &VolumeInfo) -> Result<Volume>`: fails if `path` exists. Writes
      `version.txt`, `container.description`, `verify_container.py`, `factum/README.txt`, `information.turtle`
      (volume only) and `.hashes`.
    - `open(path: &Path, end_hint: Option<u64>) -> Result<(Volume, u64)>`: for writing. An interrupted tail is
      truncated to `find_last_end`; the second value is the number of bytes discarded.
    - `uuid_of(path: &Path) -> Result<String>` (read-only; checks `container.description` against the comment)
    - `stage_add(&mut self, sources: &[PathBuf], options: &AddOptions, progress: &AddProgress, cancel: &AtomicBool) -> Result<Staged>`
      and `stage_add_with(…, after_read: &dyn Fn(&Path))` (test seam, called after each file is read)
    - `discard(&mut self, staged: Staged) -> Result<()>` (truncate to `staged.start`)
    - `finalize_add(&mut self, staged: &Staged, entry_id: i64) -> Result<u64>`: one `aff4l:LogicalAcquisitionTask`
      with `factum:logEntry`. Writes a new `information.turtle` and `.hashes`, and omits the root signature members.
    - `turtle_bytes(&self) -> Vec<u8>`, `history_count(&self) -> u32`, `end(&self) -> u64`, `path(&self) -> &Path`
    - `close(&mut self, signatures: &Signatures) -> Result<u32>`: writes the turtle, the hashes and the signature
      members. Copies them to `factum/history/<n>/` and returns n.
    - `add_late_signatures(&mut self, n: u32, signatures: &Signatures) -> Result<()>`: adds history members that
      are missing, never replaces existing ones. Writes root members only when n is the newest close.
- Errors: `FactumError::general` with user-facing text. A lock held elsewhere gives
  `"The container is in use by another factum process."`

- [ ] **Step 1: Tests**
  - `create_add_close_reopen_add_close_keeps_history`: two closes → `factum/history/1/` and `/2/` both present. The
    turtle in history 1 lists the first files only, and every member listed in history 1 is byte-identical in the
    final file.
  - `earlier_copy_is_prefix`: copy after close 1; the final file starts with those bytes.
  - `interrupted_add_is_discarded_on_open`: `stage_add` without finalize, drop the volume → `open` returns the
    discarded byte count > 0, and the archive equals the state before.
  - `changed_file_is_reported_not_added` (Review Focus 1): `after_read` appends to file b. Then a is recorded, b is
    in `errors` with a reason containing "changed while it was read", and nothing of b is listed.
  - `overlapping_sources_store_each_file_once` (Review Focus 2).
  - `empty_file_and_empty_folder_round_trip` (Review Focus 4): sha256 `e3b0c442…b855`; the folder is an
    `aff4l:Folder`.
  - `excerpt_out_of_range_is_refused` (Review Focus 5): `(5, 5)` and `(0, size + 1)` → `Err` before writing.
    `(2, 4)` on `b"abcdef"` stores `b"cd"` with `factum:originalSize 6`.
  - `metadata_only_hashes_original_and_stores_nothing`.
  - `special_files_are_skipped_and_listed` (Unix).
  - `cancel_adds_nothing`.
  - `second_open_is_refused_while_locked`.
  - `non_utf8_name_round_trips` (Linux): a file named `b"caf\xe9\x01.txt"` → `aff4l:fileName` `caf%E9%01.txt` and
    `aff4l:fileNameRaw` whose Base64 decodes to the original bytes; `originalPathName` likewise.
  - `thousands_of_small_files`: 5,000 files of 10 bytes in nested folders → one add, all listed, finalize under
    10 s in a debug build.
- [ ] **Step 2:** `cargo test --lib container::volume` → fail.
- [ ] **Step 3: Implement.** Content is written past the last EOCD. A file that failed is rewound with
  `Appender::rewind_to` to where it started. Changes are detected by comparing size and mtime before and after the
  read. Names go through `encode_name`. The task carries `aff4l:filesystemRoot` (the base path, encoded) and
  `aff4l:pathSeparator` (`std::path::MAIN_SEPARATOR`). Every stream object carries `aff4:stored <volume ARN>`.
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Container: volume with add, close, reopen, history and recovery`.

### Task 6: X.509 with gpgsm

**Files:**
- Modify: `src/signer.rs`: split the spawn-and-collect part of `run_gpg` into
  `fn run_program(command: Command, input: &[u8]) -> io::Result<GpgOutput>`. Make `GpgOutput` and `gpg_error`
  `pub(crate)`.
- Create: `src/container/x509.rs`
- Test: `tests/common/mod.rs` (`GpgsmHome`), `tests/container_x509.rs`

**Interfaces:**
- Produces:
  - `pub const X509_CERT_SETTING: &str = "x509_certificate"; pub const X509_CHAIN_SETTING: &str = "x509_chain_files";`
  - `pub struct X509Cert { pub fingerprint: String, pub subject: String, pub issuer: String, pub not_before: String, pub not_after: String }`
  - `pub struct X509Check { pub valid: bool, pub trusted: bool, pub signer_subject: Option<String>, pub root_subject: Option<String>, pub root_fingerprint: Option<String>, pub signed_utc: Option<String>, pub valid_at_signing: bool, pub status: String }`
  - `pub struct Gpgsm` with `new(home: Option<PathBuf>) -> Self`, `available(&self) -> bool`,
    `list_secret_certs(&self) -> Vec<X509Cert>`,
    `chain(&self, fingerprint: &str, extra_pem: &[PathBuf]) -> Result<String, String>` (PEM, leaf first, ending in a
    self-signed root; `Err` names what is missing),
    `sign_detached(&self, fingerprint: &str, data: &[u8]) -> Result<String, String>` (`--detach-sign --armor
    --include-certs -1`),
    `verify_detached(&self, signature: &str, data: &[u8]) -> X509Check`. All calls pass `--batch --status-fd 2`
    and `--homedir` when set. Verification passes `--disable-crl-checks --disable-ocsp` (offline). It imports
    nothing into the keybox.
  - `pub fn parse_cert_listing(listing: &str) -> Vec<X509Cert>` (`--with-colons`, `crt`/`crs` records)

- [ ] **Step 1: Tests**
  - unit `cert_listing_is_parsed` (a fixed `--with-colons` sample).
  - `GpgsmHome::new()` (None without `gpgsm` or `openssl`): openssl makes a root CA and a signing certificate in a
    temp dir. The PKCS#12 is imported with `--pinentry-mode loopback --passphrase ""`. `trusted(&self)` writes
    `<root fpr with colons> S relax` to `trustlist.txt`.
  - `sign_and_verify_with_trusted_root` → `valid && trusted && valid_at_signing`, `signer_subject` contains the CN.
  - `untrusted_root_fails_with_root_named` → `valid && !trusted`, `root_fingerprint` set.
  - `chain_without_root_is_refused`: the root is deleted from the keybox and not given as a file → `Err`. With the
    root's PEM in `extra_pem` → `Ok` with two certificates.
  - `tampered_data_is_invalid`.
- [ ] **Step 2:** `cargo test --test container_x509 --lib container::x509` → fail. Read gpgsm's status lines for
  this version while writing `verify_detached` (`GOODSIG`, `VALIDSIG`, `TRUST_*`, `ERROR`).
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** tests pass (they skip without gpgsm/openssl; say so in the task report); full check.
- [ ] **Step 5: Commit** `Container: X.509 signing and verification through gpgsm`.

### Task 7: Container service and log events

**Files:**
- Create: `src/containers.rs` (`impl Factum`), module in `src/lib.rs`
- Modify: `src/cases.rs` (`archive_case` guard)
- Test: `tests/containers.rs`

**Interfaces:**
- Consumes: Tasks 5 and 6, `Factum::append`/`sign_or_fail`, `Signer::sign_detached`/`export_public_keys`.
- Produces:
  - `pub struct ContainerSummary { pub id: i64, pub case_id: i64, pub uuid: String, pub name: String, pub open: bool, pub file_count: u64, pub path: Option<PathBuf>, pub missing: bool }`
  - `pub struct AddEvent { pub entry_id: i64, pub utc: String, pub files: Vec<FileRecord> }`;
    `pub struct CloseEvent { pub entry_id: i64, pub utc: String, pub turtle_sha256: String, pub file_count: u64, pub gpg: Option<String>, pub x509: Option<String>, pub x509_refused: Option<String>, pub signed_later: Option<i64> }`
  - `pub struct ContainerDetail { pub summary: ContainerSummary, pub evidence_id: Option<i64>, pub file_name: String, pub base_path: String, pub created_utc: String, pub adds: Vec<AddEvent>, pub closes: Vec<CloseEvent>, pub reopens: Vec<(i64, String)> }`
  - On `Factum`:
    - `list_containers(&self, case_id: i64) -> Result<Vec<ContainerSummary>>`. Uses SQL `json_extract` /
      `json_array_length` and never deserializes file lists.
    - `container(&self, id: i64) -> Result<ContainerDetail>`
    - `find_container_by_uuid(&self, uuid: &str) -> Result<Option<i64>>`
    - `create_container(&self, case_id: i64, name: &str, evidence_id: Option<i64>, path: &Path, base_path: &str) -> Result<i64>`.
      Creates the file, then logs `container_created`. If the append fails, the file is removed.
    - `compare_with_log(&self, id: i64, volume: &Volume) -> Result<Vec<Finding>>` (spec 4.5 "on opening"). Every
      log record has a FileImage with the same ARN, path, size and hashes. Every FileImage is in a log record. Every
      task's `factum:logEntry` is a `container_files_added` entry of this container. Differences → Fail
      `log_mismatch`, never repaired. Task 8 reuses it.
    - `open_container_for_add(&self, id: i64) -> Result<Volume>`. Refused when the container is closed, the case is
      archived, the file is missing, or `compare_with_log` has a Fail (message: "… differs from the case log;
      Verify Container… shows how").
    - `commit_container_add(&self, id: i64, volume: &mut Volume, staged: Staged) -> Result<i64>`: append with
      `on_commit` → `finalize_add` (through a `RefCell`). Any error → `discard`. On success,
      `container_end:<uuid>` is stored.
    - `close_container(&self, id: i64) -> Result<CloseEvent>`. GPG via `sign_or_fail` semantics on the turtle bytes
      (`sign_detached`, public key via `export_public_keys`). X.509 when `X509_CERT_SETTING` is set: a chain or
      signing failure goes into `x509_refused`, and the close is GPG-only. Logs `container_closed`, with
      `on_commit` → `Volume::close`.
    - `reopen_container(&self, id: i64) -> Result<()>` (logs `container_reopened`; the file is not touched)
    - `sign_unsigned_containers(&self, case_id: i64) -> Result<(usize, Vec<String>)>`. For each closed state without
      signatures: check the history turtle's SHA-256 against the log, sign, log `container_signed`, and `on_commit`
      → `add_late_signatures`. Containers with a missing file are skipped, with the reason listed.
    - `container_path(&self, uuid: &str) -> Option<PathBuf>`;
      `locate_container(&self, id: i64, path: &Path) -> Result<()>` (refused unless `Volume::uuid_of` matches)
    - `open_containers(&self, case_id: i64) -> Result<Vec<ContainerSummary>>`
  - `archive_case` returns `FactumError::general("… has open containers: #N \"name\" … Close them first.")` when
    `open_containers` is not empty.

- [ ] **Step 1: Tests** (FakeSigner; temp files)
  - `create_logs_event_with_spec_payload`: keys `event, case_id, container_id, name, evidence_id, file_name,
    base_path, created_utc`; text `Container #N "X" created (from evidence #E)`.
  - `add_logs_one_entry_per_operation`: two sources → one `container_files_added`. The `files` records equal
    `Staged.records`; the text says `2 files added to container #N (…)`.
  - `failed_finalize_rolls_back_entry_and_file`: set the test seam `Volume::fail_next_finalize` (a `#[doc(hidden)]`
    pub bool that Task 5 adds; `finalize_add` returns an error once when set) → no new entry, and the file length
    equals `staged.start`.
  - `failed_append_restores_container`: FakeSigner `fail_next` → no entry, and the container reads as before.
  - `close_signs_and_logs_turtle_hash`: the payload's `turtle_sha256` equals the SHA-256 of the
    `information.turtle` member, and `signatures.gpg` is set.
  - `close_without_key_then_sign_later`: unsigned close; `sign_unsigned_containers` → 1, a `container_signed` entry,
    and history `1/information.turtle.asc` present.
  - `reopen_and_add_requires_open_case`: archived case → `CaseArchived`.
  - `archive_refused_with_open_container` and `archive_allowed_after_close`.
  - `locate_refuses_other_container`.
  - `list_containers_counts_files`: after adds of 2 and 3 files → `file_count == 5`; `open` follows
    closed/reopened.
- [ ] **Step 2:** `cargo test --test containers` → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Containers: service, log events, signing and archive guard`.

### Task 8: Verification of factum containers

**Files:**
- Create: `src/container/verify.rs`
- Modify: `src/containers.rs` (`verify_container_file`)
- Test: `tests/containers.rs`

**Interfaces:**
- Consumes: Tasks 1–7; `Finding`, `Level`, `Ref`, `Factum::check_signature`-style GPG checks (`Signer::verify_signature`
  needs a clearsigned block, so add `Signer::verify_detached(&self, signature: &str, data: &[u8]) -> VerifyResult`
  to the trait: GnupgSigner runs `--verify sig -` through a temp file for the signature; FakeSigner checks its
  `FAKE DETACHED <sha256>` format).
- Produces:
  - `pub enum ContainerFormat { Factum, Aff4l, Legacy, NotAff4 }`
  - `pub struct StateResult { pub label: String, pub turtle_sha256: String, pub files: usize, pub gpg: Option<SignatureCheck>, pub x509: Option<X509Check>, pub findings: Vec<Finding> }`
    (labels `current`, `close 1`, …)
  - `pub struct LogMatch { pub matches_close: Option<u32>, pub recorded_after: Vec<String> }`
  - `pub struct ContainerReport { pub path: PathBuf, pub uuid: Option<String>, pub format: ContainerFormat, pub states: Vec<StateResult>, pub findings: Vec<Finding>, pub log: Option<LogMatch>, pub discarded_tail: u64 }`
    with `overall(&self) -> Level`
  - `pub fn verify_file(path: &Path, signer: &dyn Signer, gpgsm: &Gpgsm, progress: &dyn Fn(u64, u64), cancel: &AtomicBool) -> Result<ContainerReport>`
    (read-only: never truncates, never writes)
  - `Factum::verify_container_file(&self, path: &Path, gpgsm: &Gpgsm, progress, cancel) -> Result<ContainerReport>`:
    `verify_file`, plus the log checks of spec 4.6 when `find_container_by_uuid` finds the container.
  - Finding codes: `stream_hash`, `turtle_hash`, `unsigned`, `signature_invalid`, `key_untrusted`, `x509_invalid`,
    `x509_untrusted`, `history`, `log_mismatch`, `trailing_data`, `not_checked`, `unsupported`, `not_aff4`.

- [ ] **Step 1: Tests**
  - `clean_container_verifies` (all Ok, two states after one close).
  - `flipped_content_byte_fails_stream_hash` (patch one byte inside a ZipSegment's data on disk).
  - `edited_turtle_fails_turtle_hash_and_signature`.
  - `older_copy_verifies_as_earlier_state`: copy after close 1, then reopen, add, close → the copy's report has
    `log.matches_close == Some(1)`, and `recorded_after` names the later add and close.
  - `file_missing_from_container_is_log_mismatch`: `factum.append` a `container_files_added` entry for this
    container whose record is not in the file → Fail `log_mismatch` naming the path.
  - `untrusted_gpg_key_fails` (FakeSigner with trust `TRUST_UNDEFINED`).
  - `trailing_bytes_are_a_warning_and_last_state_verifies`.
  - `x509_untrusted_root_fails` (gated on `GpgsmHome`).
  - `unsigned_close_is_fail_unsigned` (matches the case log's rule: unsigned is a fail that Sign All Unsigned fixes).
- [ ] **Step 2:** `cargo test --test containers verify` → fail.
- [ ] **Step 3: Implement.** Revocation is never checked; every X.509 state result says so in its status text.
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Containers: verification against hashes, signatures, history and the case log`.

### Task 9: Verification of other tools' containers

**Files:**
- Modify: `src/container/verify.rs`
- Test: unit tests with hand-built fixtures (`Appender` + `turtle::write` in the test)

**Interfaces:**
- Consumes: Task 8 (`verify_file` dispatches on `ContainerFormat`).

- [ ] **Step 1: Tests**
  - `in_metadata_stream_verified`: an `aff4:FileImage` with `aff4:dataStream` (and the standard's typo
    `aff4:dataSteam`) as `xsd:base64Binary`, plus an `aff4:hash` → Ok; a wrong hash → Fail.
  - `map_over_image_stream_verified`: a Map with members `<map>/map` (entries `<QQQI`: mapped offset, length,
    target offset, target index) and `<map>/idx` (newline-separated target ARNs) over a zlib ImageStream. The
    linear `aff4:hash` matches → Ok. Block-map hashes → `not_checked` (Warn).
  - `snappy_stream_not_checked`: `aff4:compressionMethod <http://code.google.com/p/snappy/>` → Warn `not_checked`,
    not Fail.
  - `imports_are_hashed`: `aff4l:imports` → a secondary store whose hash is in the primary store. A wrong hash →
    Fail; its triples join the graph.
  - `legacy_container_is_unsupported`: no `version.txt`, or major < 2 → only Warn `unsupported`, no panic.
  - `hdt_and_multipart_not_checked`: `information.hdt` present, or a `.aff4l.1` sibling → Warn.
  - `not_a_zip_is_not_aff4`.
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: Implement.** No new compression crates.
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Containers: AFF4-L v1.0 checks for other tools' containers`.

### Task 10: `verify_container.py`

**Files:**
- Replace: `src/container/verify_container.py`
- Modify: `src/container/README.txt` (usage)
- Test: `tests/containers.rs` (python-gated, like `tests/export.rs` `run_verify`)

**Interfaces:**
- CLI: `python3 verify_container.py <container.aff4l> [--ca ROOT.pem]`. Exit 0 when everything passed, 1 otherwise.
  Every line starts with `✓`, `⚠` or `✗`. Python 3 stdlib only. It reads factum's fixed one-triple-per-line Turtle
  layout (Task 2), not general Turtle. It checks: stream hashes (ZipSegment and ImageStream with zlib), `.hashes`,
  the current state and every `factum/history/<n>/`, GPG via `gpg --verify` when `gpg` is installed (else ⚠ not
  checked), and X.509 via `openssl cms -verify -binary` against `--ca`. Without `--ca` it checks against the
  carried chain and prints `⚠ root not checked against a trusted certificate`.

- [ ] **Step 1: Tests**
  - `script_passes_clean_container` (two closes, one ImageStream file via a small test limit).
  - `script_fails_tampered_content` and `script_fails_tampered_history` (exit 1, a line containing "✗").
  - `script_x509_with_and_without_ca` (gated on `GpgsmHome` and openssl).
  - `script_runs_from_the_container`: extract `verify_container.py` with `zipfile` and run it
    (`python3 -I`), the same way the README tells recipients to.
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `verify_container.py for recipients without factum`.

### Task 11: Containers in reports

**Files:**
- Modify: `src/export/model.rs` (`ContainerRow`, `ReportModel.containers`), `html.rs`, `markdown.rs`, `pdf.rs`
- Test: `tests/export.rs`

**Interfaces:**
- Consumes: `list_containers`, `container` (Task 7).
- Produces: `pub struct ContainerRow { pub id: i64, pub name: String, pub file_name: String, pub uuid: String, pub evidence: Option<String>, pub state: String, pub signatures: String, pub files: Vec<(String, u64, String)> }`.
  `state` is `open` or `closed`. `signatures` is e.g. `GPG ABCD1234 · X.509 CN=…` or `unsigned`.

- [ ] **Step 1: Tests**
  - `reports_list_containers`: HTML, Markdown and PDF text (pdftotext-gated, like the existing test) contain the
    container name, its UUID, `closed` and each file's path and SHA-256.
  - `reports_without_containers_have_no_section`: no "Containers" heading.
  - `bundle_with_container_events_verifies` (python-gated): `verify.py` exits 0. `case.json` has the events and no
    `.aff4l` member.
- [ ] **Step 2:** `cargo test --test export` → fail.
- [ ] **Step 3: Implement.** Section "Containers" after "Evidence". Per container: a key/value block, then a
  Path | Size | SHA-256 table (PDF via `pdf.grid`).
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `Containers in HTML, PDF and Markdown reports`.

### Task 12: GUI — containers in the tree and the container view

**Files:**
- Create: `src/gui/containers.rs`
- Modify: `src/gui/mod.rs` (`CaseNode.containers`, `View.container`, `FactumApp.container_id`, `select_container`,
  `read_view`, `case_tree`, `notes_area`, `TreeAction`), `src/gui/tests.rs` (`Fixture::with_container()`)

**Interfaces:**
- Consumes: `ContainerSummary`, `ContainerDetail`, `locate_container` (Task 7).
- Produces:
  - `FactumApp::select_container(&mut self, id: i64)`. Selecting a case or evidence clears it; selecting a container
    sets `case_id` to its case so the status bar and menus follow.
  - `pub enum ContainerAction { AddFiles(i64), AddFolder(i64), Close(i64), Reopen(i64), Verify(i64), Locate(i64), ShowInFolder(i64), ShowEntry(i64) }`
  - `pub fn container_view(ui: &mut egui::Ui, detail: &ContainerDetail, actions: &mut Vec<ContainerAction>)`
  - `TreeAction::Container(ContainerAction)`, `TreeAction::NewContainer(i64)`
- Tree row (spec 4.7): after the case's evidence rows, indent 20. Name; the file count on the right like note
  counts; a muted `open` after the name while open; `⚠` with tooltip `File missing` when missing. The context menu
  has the spec 4.7 items. Add Files…/Add Folder… are disabled while closed or archived. Locate… is enabled only
  when missing.
- Container view (replaces the log column while a container is selected): a header line (name, state, UUID with
  copy, file, evidence). Files in `ScrollArea::show_rows` with columns path, size, SHA-256 (truncated; full hash in
  the tooltip) and modified, with metadata-only/excerpt marks. Below: the adds and closes as rows, each with its
  entry `#id` linking to the log (`ShowEntry`).
- Locate…: `rfd` file dialog filtered to `.aff4l` → `locate_container`; refusal → message.
- Show in Folder: new `fn show_in_folder(path: &Path) -> std::io::Result<()>` in `gui/containers.rs`, spawned and
  not waited for: Linux `xdg-open <parent>`, Windows `explorer /select,<path>`, macOS `open -R <path>`. An error
  becomes a message.

- [ ] **Step 1: GUI tests**
  - `tree_lists_container_with_count_and_state`: fixture container with 2 files, open → a row labelled with its
    name; the AccessKit label contains `open`. After close it does not.
  - `selecting_container_shows_its_files`: the view lists both paths; `view.items` is empty.
  - `missing_file_is_marked_and_locate_enabled`: delete the file → `⚠`; the `Locate…` item is enabled.
  - `add_disabled_while_closed`.
- [ ] **Step 2:** `cargo test --lib gui::` → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** tests pass; full check. With a GPU or lavapipe:
  `FACTUM_SCREENSHOTS=<scratch> cargo test --lib gui::tests::selecting_container -- --test-threads=1`, and look at
  the screenshot.
- [ ] **Step 5: Commit** `GUI: containers in the case tree and the container view`.

### Task 13: GUI — create, add with progress, close, reopen, sign, archive

**Files:**
- Modify: `src/gui/dialogs.rs` (`Dialog::NewContainer`, `Dialog::AddToContainer`, results,
  `Pending::CloseContainersAndArchive(i64)`), `src/gui/workers.rs` (`add_to_container`), `src/gui/mod.rs` (Case menu
  "New Container…" after "Edit Evidence…"; case row context menu; `AddJob`; status bar; `archive`;
  `sign_all_unsigned`), `src/gui/tests.rs`

**Interfaces:**
- Consumes: Task 7 service, Task 5 `Volume`/`Staged`/`AddProgress`/`AddOptions`.
- Produces:
  - `workers::add_to_container(ctx, volume: Volume, sources: Vec<PathBuf>, options: AddOptions) -> (Worker<Result<(Volume, Staged), String>>, Arc<AddProgress>, Arc<AtomicBool>)`
    (the volume goes back to the GUI thread; on cancel or error the worker has already called `discard`)
  - `struct AddJob { container_id: i64, name: String, worker, progress, cancel }` (one at a time)
  - `Dialog::NewContainer { case_id, name: String, evidence: Option<i64>, evidence_choices: Vec<(i64, String)>, folder: String, file_name: String, base: String, error: Option<String> }`.
    The file name defaults to `safe_filename(name) + ".aff4l"` until edited; the folder defaults to the export
    folder; the evidence defaults to the selected evidence. Validation: the name is required, the folder exists,
    the file does not exist.
  - `Dialog::AddToContainer { container_id, sources: Vec<PathBuf>, base: String, keep_path: bool, metadata_only: bool, excerpt_from: String, excerpt_to: String, error: Option<String> }`
    (excerpt fields only when `sources` is one file). Opened after the `rfd` pick (Add Files… multi-select,
    Add Folder… one folder); base defaults to the container's `base_path`.
- Status bar while an AddJob runs, left side instead of the case status:
  `Adding to "<name>": <files> / <total> files · <bytes> / <total>`, plus `IconButton::new(icons::CLOSE, "Cancel")`.
  Repaint through the worker's `request_repaint` and a 250 ms `request_repaint_after`.
- On completion: `commit_container_add`, then one message:
  `<k> files added (<size>).` plus `Skipped: …` and `Errors: …` lines when there are any. Cancelled → `Nothing was added.`
- Close: `close_container` through `run`, then a message when `x509_refused` is set. Reopen: direct.
- Archive: `open_containers` not empty → `Dialog::Confirm` "Container(s) #N "x" are open. Close them and archive the
  case?" → `Pending::CloseContainersAndArchive`.
- Sign All Unsigned: also calls `sign_unsigned_containers` and adds their count and skip reasons to the message.

- [ ] **Step 1: GUI tests**
  - `new_container_dialog_creates_file_and_selects_it`.
  - `add_runs_in_background_and_commits`: drive the dialog with a temp folder of 3 files; `run_until` the job ends →
    `container_files_added` with 3 files; the status bar label disappears.
  - `cancel_adds_nothing` (set the cancel flag before polling).
  - `archive_with_open_container_asks_to_close`: confirm → the container is closed and the case is archived.
  - `sign_all_unsigned_signs_containers` (FakeSigner active after an unsigned close).
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** tests pass; full check; screenshot of the status bar during a job if a renderer is available.
- [ ] **Step 5: Commit** `GUI: create and fill containers, close, reopen, sign, archive guard`.

### Task 14: GUI — Verify Container and the X.509 setting (Settings and setup wizard)

**Files:**
- Modify: `src/gui/dialogs.rs` (`ContainerVerifyWindow`, `Dialog::X509`, `x509_fields`), `src/gui/workers.rs`
  (`verify_container`), `src/gui/mod.rs` (Case menu "Verify Container…" for any file; container context menu;
  Settings menu "X.509 Certificate…" after "Signing Key…"; `save_x509`; `open_wizard`; `finish_wizard`),
  `src/gui/wizard.rs` (Signing key step, `WizardStart`, `WizardChoices`, Summary), `src/gui/tests.rs`

**Interfaces:**
- Consumes: `Factum::verify_container_file` (Task 8), `Gpgsm` (Task 6).
- Produces:
  - `workers::verify_container(ctx, db_path, gpg_home, path) -> (Worker<Result<ContainerReport, String>>, Arc<Progress>)`
    (progress in bytes; the same modal as case verification, text `Verifying container…`)
  - `ContainerVerifyWindow { id: u64, report: ContainerReport, open: bool }` drawn through `report_window`. It shows
    a verdict line in the style of Verify Case, then one section per state (signatures, signers, X.509 root
    subject/fingerprint), then the findings with ✓ ⚠ ✗. Findings with an `entry_id` link to the log.
  - `Dialog::X509 { certs: Vec<X509Cert>, selected: Option<String>, chain_files: Vec<String> }`: one clickable row
    per certificate (subject, validity; fingerprint in the tooltip), chain files added and removed with
    `icons::PLUS`/`icons::CLOSE`, plus a Clear button. When `gpgsm` is missing, the dialog says so and offers
    nothing else.
  - `pub fn x509_fields(ui: &mut egui::Ui, certs: &[X509Cert], selected: &mut Option<String>, chain_files: &mut Vec<String>)`
    in `dialogs.rs`: the certificate rows and the chain files, drawn by both `Dialog::X509` and the wizard (as
    `key_list` is for GPG keys).
  - `DialogResult::X509 { certificate: Option<String>, chain_files: Vec<String> }` →
    `FactumApp::save_x509(&mut self, certificate: Option<String>, chain_files: Vec<String>)`, which writes both
    settings and deletes them on `None` / empty.
  - Setup wizard (the only place it asks about X.509):
    - `WizardStart` gains `x509_certs: Vec<X509Cert>` (listed by `open_wizard` through
      `Gpgsm::new(self.signer.gpg_home())`), `x509: Option<String>` and `x509_chain: Vec<String>` (the current
      settings).
    - `Wizard` keeps the list, the choice and the current values. "Check again" on the Signing key step lists the
      certificates again.
    - The Signing key step shows, below the GPG key list, a small heading `X.509 certificate (optional)`, the note
      `Also signs evidence containers.`, and `x509_fields`. It shows this only when `x509_certs` is not empty.
      Without certificates, or with "Not now" (the step is left out), nothing about X.509 appears.
    - `WizardChoices` gains `x509: Option<(Option<String>, Vec<String>)>`: `None` = unchanged (step skipped or left
      out, no certificates listed, or nothing changed); otherwise the choice.
    - Summary: a line `X.509 certificate: <subject>` / `not set` / `unchanged`, only when the step showed the
      section.
    - `finish_wizard` applies `x509` right after the GPG key, through `save_x509`.

- [ ] **Step 1: GUI tests**
  - `verify_container_opens_report_window` (a fixture container) → a window titled `Verify Container <name>`
    with a ✓ verdict.
  - `x509_dialog_without_gpgsm_says_so`: a `Dialog::X509` with no certs and `gpgsm` unavailable shows the "not
    installed" line.
  - `x509_result_saves_and_clears_settings`: `handle_dialog_result(DialogResult::X509 { … })` writes both keys.
    With `None`/empty, both are removed.
  - `wizard_hides_x509_without_certificates`: an empty fixture (no certificates listed) → on the Signing key step
    there is no `X.509 certificate (optional)` label, and the Summary has no X.509 line.
  - `wizard_x509_choice_applied_on_finish`: set `x509_certs` on the open wizard (as the seal folder test sets its
    field), pick the certificate row, Next to Summary, Finish → `x509_certificate` holds its fingerprint.
  - `wizard_prefills_and_keeps_x509`: settings configured beforehand; open from the menu; Next through all steps;
    Finish → both settings unchanged.
  - `not_now_leaves_x509_unchanged`: configured beforehand; choose "Not now" on Welcome; Finish → unchanged.
- [ ] **Step 2:** run → fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** tests pass; full check.
- [ ] **Step 5: Commit** `GUI: Verify Container; X.509 certificate in Settings and the setup wizard`.

### Task 15: Documentation and final check

**Files:**
- Modify: `README.md` (an "Evidence containers" section: what, how to verify with and without factum, X.509 setup
  with gpgsm and `trustlist.txt`, the open risks of spec 8 plus pyaff4), `CHANGELOG.md` (`## [Unreleased]` → Added),
  `docs/AIRGAP.md` (gpgsm, offline revocation)

- [ ] **Step 1:** Write the docs. In the changelog: Added — evidence containers (AFF4-L v1.0), signed with GPG and
  optionally X.509; Verify Container; `verify_container.py`; containers in reports.
- [ ] **Step 2:** `cargo test && cargo test --no-default-features && cargo clippy --all-targets && cargo fmt --check`
  → green. `unzip -t` on a test container if `unzip` is installed. Run the ignored large-file test once:
  `cargo test --lib container::stream -- --ignored`.
- [ ] **Step 3: Commit** `Docs and changelog for evidence containers`.
