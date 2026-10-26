# Evidence containers: design

Date: 2026-10-26. Status: draft, written for review by the user (see 9 for the calls made without them).

## 1. Intent

During an examination, pieces of evidence are preserved: a couple of files, a folder, a binary, anything. Today
factum documents them only as a path and a hash in a note, and the report repeats that. The files themselves stay
inside the image. That is enough most of the time, but it is better to preserve the evidence itself, the way an
X-Ways *evidence file container* does: selected files copied into one container file, together with their original
path, timestamps, size and hashes, which can be kept, re-checked and handed to someone else (another examiner, a
prosecutor, a lawyer) without the source image.

factum does this with two differences from X-Ways:

- **Open format.** The container is a standard **AFF4-L** container (open, vendor-neutral, Apache-licensed
  specification), not a proprietary one. Other AFF4-L tools (e.g. Magnet AXIOM) can load it; at worst it opens
  with `unzip`.
- **Signed.** The container is signed with GPG, and additionally with X.509 when a certificate is configured. Anyone
  holding it can prove that nothing in it was changed, added or removed since it was signed, and by whom. Every
  addition is also a signed entry in the case log, so the log says what went into which container, and when.

## 2. Goals, non-goals, anti-goals

Goals
- Create a container in a case, fill it with files and folders over the course of the case, close it, reopen it and
  add more, like X-Ways.
- Preserve, per file: original path, file name, size, the timestamps the platform exposes (modified, accessed,
  changed, created), Unix mode where available, and MD5, SHA-1 and SHA-256 of the content.
- X-Ways-style options when adding: how much of the path to keep, metadata only (no content), excerpt (a byte range
  of one file).
- Every addition, every close and every reopen is a signed entry in the case log.
- Each close signs the container: GPG always (when a key is active), X.509 in addition when configured.
- Verification of any `.aff4l` container in the GUI (files against hashes, metadata against its hash, signatures,
  signers, and, for a container of a case in the open database, agreement with the case log), and by a recipient
  without factum through a bundled Python script.
- The written containers conform to the AFF4-L Standard v1.0 and open in pyaff4, the reference implementation.

Non-goals
- No reading of disk images, no file system parsing. Files come from a mounted image or from another tool's export
  folder, and factum preserves what the operating system shows (decided: "mount is enough for now"). Deleted files,
  slack, carving, NTFS record numbers and similar internals stay X-Ways' job.
- No command line for containers in this version (decided: "GUI only for now").
- No removal of files from a container, ever.
- No encryption of containers.
- No inclusion of container files in the export bundle; the bundle refers to them.

Anti-goals (a build that does these has failed even if it works)
- Compatibility with factum-notes broken: the case database schema and its version stay untouched, and a database
  with container entries verifies in factum-notes exactly as before (see 4.1).
- A source file changed by factum: the source is only read, and its access time should not be touched where the
  platform allows avoiding it (`O_NOATIME` on Linux when permitted).
- A container that standard AFF4-L readers reject, or a GPG signature placed where the standard expects X.509
  (`information.turtle.sig`, `information.turtle.*.sig`).
- A state once closed and signed that is altered by a later reopen: a copy handed over after the first close must
  stay verifiable, and every file it contains must be byte-identical in the later container.
- An interrupted addition (crash, power loss, cancel) that leaves the container unreadable or loses the last closed
  state.

## 3. Constraints

- factum is one synchronous Rust binary (edition 2024, egui 0.37, rusqlite with bundled SQLite, no async runtime).
  Background work is plain threads reporting through channels and `ctx.request_repaint()`, as the companion does.
- The case database is schema 3, shared with factum-notes. No table, column or schema version is added. Storing
  values in the existing `settings` key/value table is allowed (as `active_gpg_key_id` already does).
- Air-gapped machines: no network, no new runtime dependencies beyond what GnuPG already ships (`gpg`, `gpgsm`).
  New crates must be pure Rust and vendorable (`cargo vendor`); RustCrypto `md-5` and `sha1` are fine.
- Files of any size: from a few bytes to hundreds of GB, and folders with tens of thousands of files. Hashing and
  copying stream; nothing holds a whole file in memory.
- Signing uses the system `gpg` exactly as `src/signer.rs` does today; X.509 uses `gpgsm` the same way.

## 4. Design

### 4.1 Where container state lives

The case log is the source of truth. Containers are described entirely by system entries (kind `system`, as
`evidence_created` is), and the GUI derives the list of containers and their state from them. No new tables.

factum-notes and the bundled `verify.py` act only on the event names they know and ignore all others (checked:
`metadata_findings` in factum-notes' `verifier.py` and in `verify.py`). The new events therefore verify unchanged
there and display as ordinary system entries with their human-readable `text`. factum's own verifier treats them
the same way for the case log; container checks are separate (4.6).

Events (payloads are canonical JSON, like the existing ones; `container_id` is the AFF4 volume UUID):

| Event                | When                     | Payload (besides `event`, `case_id`, `container_id`)                                     |
|----------------------|--------------------------|-------------------------------------------------------------------------------------------|
| `container_created`  | New Container            | `name`, `evidence_id` (or null), `file_name` (the `.aff4l` file name), `base_path`, `created_utc` |
| `container_files_added` | one Add operation completes | `files`: list of `{arn, path, size, md5, sha1, sha256, metadata_only, excerpt}` for that operation; `added_utc` |
| `container_closed`   | Close Container          | `turtle_sha256` (SHA-256 of `information.turtle` as signed), `file_count`, `signatures` (`gpg` fingerprint, `x509` fingerprint or null), `closed_utc` |
| `container_reopened` | Reopen                   | `reopened_utc`                                                                            |

`text` examples: `Container #2 "FS01 preserved" created (from evidence #1)`, `12 files added to container #2
(4.1 MB)`, `Container #2 closed · 57 files · signed`.

The container number shown (`#2`) is the log entry id of its `container_created` entry; the UUID is shown in
details.

The container's file location is not part of the log: the GUI remembers the path per container in the `settings`
table (`container_path:<uuid>`), starting from the path chosen at creation. If the file is missing, the GUI offers
**Locate…** and accepts a file only if its volume UUID matches.

### 4.2 The container file

A standard AFF4-L v1.0 container (ZIP64), file extension `.aff4l`, `version.txt` with `major=2`, `minor=1`,
`tool=factum <version>`, and `container.description`.

Per file a `aff4:FileImage` with the AFF4-L properties: `aff4l:fileName`, `aff4l:originalPathName` (path below the
chosen base, see 4.4), `aff4:size`, `aff4l:lastWritten`, `aff4l:lastAccessed`, `aff4l:recordChanged`,
`aff4l:birthTime` (each only when the platform provides it), `aff4l:fileMode` (Unix), and `aff4:hash` three times
(`^^aff4:MD5`, `^^aff4:SHA1`, `^^aff4:SHA256`). Names that are not valid UTF-8 or contain control characters follow
the standard's rule (section 5: `*Raw` Base64 property plus %-escaped name). Folders are `aff4l:Folder` objects with
their own metadata. One `aff4l:LogicalAcquisitionTask` per Add operation, with `aff4l:filesystemRoot` and
`aff4l:pathSeparator`.

Content storage follows the standard's section 6: ZipSegment storage streams for files up to 1 GiB (stored or
deflated); ImageStream storage (AFF4 v1.0) for larger files, which the standard requires since ZipSegments should not
exceed 1 GiB.

`information.turtle.hashes` holds SHA-256 and SHA-512 of `information.turtle` (standard section 10.1, mandatory).

factum-specific facts go into RDF properties in a factum namespace (`https://factum.invalid/Schema/2026/#`, final
URI left to the builder), which other readers ignore:

- on the volume: case file number, case id, container name, evidence id and description, the `container_id`;
- on each Add task: the log entry id of its `container_files_added` entry;
- on each file: `factum:metadataOnly true`, or `factum:excerptStart` / `factum:excerptEnd` (byte offsets in the
  original file) together with `factum:originalSize`. For an excerpt, `aff4:size` and the hashes describe the stored
  bytes; for a metadata-only file the original size is kept and the hashes are of the original content (factum
  reads the file to hash it, but does not store it).

How a metadata-only file is represented so that pyaff4 opens the container without errors (e.g. a `FileImage` with
no storage stream, or a zero-length stream marked by `factum:metadataOnly`) is left to the builder, to be decided
by testing against pyaff4 (and AXIOM, if one is available).

The container also carries `verify_container.py` (4.6) and `factum/README.txt` (a short plain-text explanation for
recipients: what the container is, how to verify it). Other ZIP readers and AFF4 readers ignore these members.

### 4.3 Signatures

Signed is `information.turtle`, byte for byte; it contains every file's hashes, so the signature covers all content.

- **GPG** (always, when a key is active): an armored detached signature in `information.turtle.asc`, the signer's
  public key in `information.turtle.pubkey.asc`. Not in the `.sig` names, which the standard reserves for X.509.
- **X.509** (in addition, when configured): a detached CMS signature made with `gpgsm`, PEM-encoded, in
  `information.turtle.factum.sig`, and the full certificate chain (signing certificate, intermediates, root) in PEM
  in `information.turtle.factum.cer`, following the standard's multi-signature naming (section 10.2).

The standard does not say which PEM signature structure it expects, and no signed reference image exists. CMS
(PKCS#7 detached, `-----BEGIN SIGNED MESSAGE-----` or `-----BEGIN PKCS7-----` as gpgsm writes it) is the decided
default; compatibility with other tools' X.509 checks is an open risk (8).

Without an active GPG key, a container can still be closed, unsigned, and **signed later** (like entries and seals
today, through the existing Sign Unsigned action): the close entry then records no signatures and a later
`container_signed` entry (payload: `turtle_sha256`, `signatures`, `signed_utc`) records them.

**X.509 configuration** (in the GUI's settings, stored in the `settings` table): the signing certificate, picked
from the certificates with a secret key that `gpgsm --list-secret-keys` reports (smart cards included); optionally
the intermediate and root certificates as PEM files, if gpgsm's keybox does not already hold the chain. factum
builds the chain from gpgsm and the given files. If the chain cannot be completed to a self-signed root, the X.509
signature is refused with a clear message and the container is signed with GPG only; the close entry says so. The
case log itself is always GPG-signed only.

### 4.4 Adding files

Sources are files and folders on any mounted file system, typically a mounted image, sometimes an export folder.
A folder is added recursively. Symbolic links are recorded as links (target path in a factum property), not
followed. Special files (devices, sockets, FIFOs) are skipped and listed in the result.

Options per Add operation, asked in a small dialog before copying:
- **Base path**: the prefix removed from the original paths, defaulting to the container's base path (e.g. the mount
  point, so `/mnt/fs01/Users/x/evil.exe` is stored as `Users/x/evil.exe`).
- **Path**: keep the path below the base, or keep only the file name (X-Ways: "complete path optional").
- **Metadata only**: yes / no.
- **Excerpt**: only when a single file is added: from-offset and to-offset.

Copying and hashing run in a background thread: progress (files, bytes) and Cancel in the status bar. Each file is
hashed while it is copied into the container in the same read pass; afterwards the stored copy is not re-read.
A file that changes while it is being read (size or modification time differ before and after) is recorded as an
error and not added. A cancelled or failed operation adds nothing: neither files in the container nor a log entry.

On completion: one `container_files_added` log entry for the operation, then the container's `information.turtle`
is rewritten with the new files and the Add task carrying that entry's id.

### 4.5 Lifecycle: create, close, reopen

- **New Container…** (Case menu): name, the evidence item it draws from (optional), save location for the `.aff4l`
  file, base path. The container file is created, `container_created` is logged, and the container is open.
- **Close Container**: writes `information.turtle`, `information.turtle.hashes`, the signatures (4.3), logs
  `container_closed`.
- **Reopen Container**: logs `container_reopened`; Add is available again. The next close writes and signs the new
  state.
- **Archived cases**: no container can be created, filled or reopened in an archived case. Archiving a case with an
  open container asks to close it first.
- **Permanent case deletion** does not touch container files (as with external seal files).

Reopen and append must keep every previously closed state recoverable (anti-goal). The approach is left to the
builder; a sensible one: new content segments are appended to the ZIP after the existing ones, and new
`information.turtle` / hashes / signature members plus a new central directory are written at the end, so the
bytes of earlier content segments never move. An interrupted append must leave the last good central directory in
place or be recoverable from it. Whatever the approach: a signed `information.turtle` from an earlier close, with
its signatures, verifies against the files contained in the later container.

**Closed states are kept inside the container.** ZIP member names are unique, so the current `information.turtle`
and its signature files are replaced at each close. On every close, factum therefore also writes copies of that
close's signed members under `factum/history/<n>/` (`<n>` = 1 for the first close, counting up):
`information.turtle`, `information.turtle.hashes`, `information.turtle.asc`, `information.turtle.pubkey.asc` and,
if present, `information.turtle.factum.sig` / `.cer`. These names are outside the standard's reserved
`information.turtle.*` names at the root, so other readers do not try to check them against the current metadata.
History entries are never rewritten. Both verifiers check every historical state against the content in the file,
and recovery after an interrupted append falls back to the newest complete history entry.

**Log and container stay consistent.** The `container_files_added` entry is written first (the container's Add task
carries its id); the container write happens inside the append transaction before COMMIT (`Append::on_commit`
in `src/log_service.rs`), so a failure rolls back the entry. On opening a container, factum compares it with the
log and reports any difference as a finding rather than repairing silently.

### 4.6 Verification

**In factum** (GUI: *Verify Container…*, any `.aff4l` file; also from a container's context menu):
- every stored stream against its hashes;
- `information.turtle` against `information.turtle.hashes`;
- GPG signature (as for entries: valid, key, trust) and X.509 signature (valid, chain to a root, signer subject,
  certificate validity at the signing time; revocation is not checked offline and the result says so);
- for a factum container whose case is in the open database: that every file and every hash in the container
  matches the case log's `container_files_added` entries, that the signed `turtle_sha256` matches the newest
  `container_closed` or `container_signed` entry, and that the log lists no file missing from the container.
  An older handed-over copy verifies as an earlier state: the result names the close it matches and lists what the
  log recorded after it.

Findings use the existing pass / warning / fail vocabulary and symbols (✓ ⚠ ✗).

**X.509 trust**: a chain is trusted only if it ends at a root that gpgsm trusts on this machine (its `trustlist.txt`
/ keybox), never merely because the container carries the root. A valid signature whose root is not trusted is a
**fail** ("untrusted root"), consistent with how untrusted GPG keys are treated today; the finding names the root's
subject and fingerprint so the examiner can decide to trust it in gpgsm.

**Containers from other tools** get the AFF4-L checks only, and only for AFF4-L v1.0 containers: ZipSegment and
in-metadata streams, Map and ImageStream streams with stored or deflate compression (factum writes deflate
ImageStreams itself, so it reads them anyway), `information.turtle.hashes`, secondary information stores
(`aff4l:imports`). Streams with other codecs (snappy, lz4), HDT stores and multi-part volumes are reported as
"not checked" (warning), not failed. Legacy pre-v1.0 AFF4-L containers (path-based ARNs, old property names, such as
pyaff4's `test_images/AFF4-L`) are out of scope: factum must open them without crashing and report that the format
is not supported, nothing more. No new compression crates are added for foreign containers. The Turtle reader only
needs to handle what these containers use; a full general Turtle parser is not required.

**Without factum**: `verify_container.py` (Python 3 standard library only, like `verify.py`) checks a container
written by factum: stream hashes, metadata hash, GPG signature via the system `gpg` if present. It reads factum's
own Turtle output, which factum writes in a fixed, simple layout for this purpose; it need not parse arbitrary
Turtle. It checks the current state and every `factum/history/<n>/` state. X.509 checking in the script uses
`openssl` with a root certificate the recipient passes (`--ca ROOT.pem`); without it, the script verifies the
signature against the carried chain and says explicitly that the root was not checked against a trusted one.

### 4.7 GUI

- **Case tree**: under a case, after its evidence items, its containers: name, open/closed, file count. A missing
  container file is marked.
- **Container view** (selecting a container): its files with path, size, SHA-256, timestamps and options
  (metadata only, excerpt), the Add operations with their log entries, and the closes with their signatures.
- **Menus**: Case menu → New Container…; container context menu → Add Files…, Add Folder…, Close Container,
  Reopen Container, Verify Container…, Locate…, Show in Folder. Add is disabled while the container is closed.
- **Settings**: X.509 signing certificate and chain files (4.3).
- **Log**: the container events are system entries and appear in the log like the others.
- Keyboard and theme conventions as the rest of the GUI; no pop-ups beyond the dialogs listed.

### 4.8 Reports and bundle

HTML, PDF and Markdown reports list each container: name, file name, UUID, evidence item, state, signatures, and
its files (path, size, SHA-256). The export bundle's `case.json` carries the events as part of the log, as today;
container files are not copied into the bundle. `verify.py` is unchanged.

## 5. Testing expectations

- Containers written by factum open and list correctly in pyaff4 (the reference implementation) including after
  reopen and append; stream hashes verified by pyaff4 where it supports it. The pyaff4 `test_images/AFF4-L` files
  are read by factum's verifier.
- A database with container entries verifies cleanly in factum-notes and with `verify.py` (cross-check, as for the
  existing compatibility).
- Interruption: killing the process mid-append leaves a container whose last closed state verifies.
- An earlier closed copy verifies after the container has been reopened and extended.
- Large files (> 1 GiB, ImageStream path) and a folder of thousands of small files.
- Non-UTF-8 and control-character file names round-trip through the standard's encoding.

## 6. Prior art

- X-Ways evidence file containers: logical images of selected files with their metadata, filled from the directory
  browser, opened, closed and reopened from the Specialist menu; options for partial path, metadata only and
  excerpts. Proprietary XWFS2 file system; integrity rests on per-file hashes, the container itself is not signed.
- AFF4-L Standard v1.0 (pre-release, September 2026): github.com/aff4/Standard, `inprogress/AFF4-L-StandardSpecification-v1.0.md`.
  Reference implementation pyaff4 (github.com/aff4/pyaff4), which supports appending (`--append`) but does not yet
  write `information.turtle.hashes`. No Rust AFF4 library exists; factum writes the format itself with the `zip`
  crate it already uses.

## 7. Left to the builder

- Module layout, the Turtle writer, the ZIP64 append mechanics (within the constraints of 4.5).
- The exact representation of metadata-only files (4.2), decided by testing against pyaff4.
- Chunk size and compression of ImageStreams; whether to deflate ZipSegments.
- The final factum namespace URI.
- Wording of log texts, findings and dialogs, in the style of the existing ones.

## 8. Open risks

- **X.509 interoperability**: the standard does not define the PEM signature structure and has no signed reference
  image. Until a signed container from another tool (e.g. AXIOM) is available, other tools may not accept factum's
  X.509 signature. GPG is unaffected.
- **Pre-release standard**: AFF4-L v1.0 may still change before release; the standard says the reference images
  take precedence over the text.
- **Metadata-only files in other readers**: may look like broken files to tools that expect content for every
  FileImage.

## 9. Calls made without the user (to check)

- One log entry per **Add operation** (listing all files it added), not one per file. Earlier in the conversation
  it was described as "each added file becomes a signed entry"; per operation avoids thousands of GPG signatures
  (and pinentry prompts) for one folder and keeps the log readable, while every file and hash is still in a signed
  entry.
- MD5, SHA-1 and SHA-256 per file.
- Container file locations kept in the `settings` table, not in the log.
- Symbolic links recorded, not followed; special files skipped.
- Closing unsigned is allowed, with signing later through the existing Sign Unsigned action.
- `verify_container.py` and a README are carried inside the container.
- Archiving requires open containers to be closed first.
- Every closed state is kept inside the container under `factum/history/<n>/` and checked by both verifiers.
- X.509: only roots trusted by gpgsm on the verifying machine count; an untrusted root is a fail, like an untrusted
  GPG key.
- Foreign containers: AFF4-L v1.0 only, stored/deflate streams; other codecs, HDT and multi-part volumes are "not
  checked"; legacy pre-v1.0 containers are reported as unsupported.
- A folder with tens of thousands of files makes one `container_files_added` payload of several MB. Accepted for
  now; if it proves a problem in reports or `case.json`, the payload could carry a hash of the file list instead.
