# Containers as evidence: design

Date: 2026-10-28. Status: draft for the user's review (section 9 lists the calls made without them).

Builds on `2026-10-26-evidence-containers-design.md` (containers, shipped in 2.6.0). Everything there stays as it is
unless this document changes it.

## 1. Intent

Today a container is a tree row of its own under a case, next to the evidence items, and looks like one. Linking it
to an evidence item is an optional field in the New Container dialog. The user finds this unintuitive. Their model:

- A case has evidence items. A container always belongs to one of them: it is evidence.
- An evidence item has **no, one or several containers**.
- In the tree, evidence with at least one container shows a container symbol; evidence without one shows none.
  There are no separate container rows.
- Creating a container on the case creates a new evidence item that carries it. Creating one on an evidence item
  adds it there.

Two ways of working must be quick and easy (the user's words: "as long as it stays quick and easy to use"):
1. **Acquire a mount**: mount a suspect disk read-only (xmount or similar), point a new container at the mount, and
   its files and folders are copied in.
2. **Collect files**: have a container and put files into it over time, from wherever they come, with their
   original paths preserved.

The user's guiding requirement for the UI: as intuitive as possible, few menu items, and containers that just work
or fail transparently. Edge cases need not each get their own handling.

The same work also closes four gaps found when the container mechanism was evaluated (section 5): recording how the
source was mounted, re-reading the stored copy at close, letting a recipient check the bundled verifier against
GitHub, and a public sample container for testing other tools' X.509 handling.

## 2. Goals, non-goals, anti-goals

Goals
- The tree shows cases and evidence only; a container symbol marks evidence that has containers.
- Selecting an evidence item shows its notes, and below them its containers (details, history, files), as in the
  mockup the user approved (described in 4.2).
- New Container… on a case creates evidence and container in one dialog; New Container… on an evidence item adds a
  container to it.
- Scenario 1 in one step: New Container… with an Acquire folder creates the container and copies the folder (4.4).
- Scenario 2 without friction: the base path is optional; without one, the full original path is kept (4.6).
- Every add records the source's mount (Linux and Windows; 5.1).
- Every close re-reads what was added since the last close and compares it with the recorded hashes (5.2).
- The container's README names the factum version and the SHA-256 of the bundled `verify_container.py` (5.3).
- A signed sample container, with its throwaway test keys, is published in the repository (5.4).

Non-goals
- No change to the container file format beyond the new properties of 5.1/5.2 and the README text of 5.3.
- No issue on `aff4/Standard` (explicitly excluded by the user).
- No encryption, no trusted timestamps (evaluated and out of scope).
- No command line for containers (unchanged from the first design).

Anti-goals
- The case database schema or its version changes, or a database written by this version stops verifying in
  factum-notes or `verify.py`. As before, only new or extended system-entry payloads; no new tables or columns.
- A container from 2.6/2.7 that no longer shows up, or shows up with its files hidden.
- A close that signs a state with a failed copy that is not marked as replaced.
- A container that standard AFF4-L readers (pyaff4) stop opening.
- More menu items or dialog fields than today for the common paths.

## 3. Constraints

As in the first design (synchronous Rust binary, egui 0.37, background work on threads, air-gapped, schema 3
shared with factum-notes, files of any size). In addition:
- Builds run on Linux, Windows and macOS (CI and release). The user's examiners work on Linux and Windows; those
  two must be covered by 5.1 and 5.2. macOS must build and work; recording mount details there is optional.
- New dependencies: only what the platform crates already in use provide (`libc` on Linux, `windows-sys` with
  further features on Windows; `libc` may be added for macOS).
- The log is append-only: existing `container_created` entries cannot be changed.

## 4. Containers belong to evidence

### 4.1 Model

A container's evidence item is the `evidence_id` of its `container_created` entry, as today. From this version on,
`create_container` requires an evidence item of the same case that is not deleted. An evidence item can have any
number of containers.

**New Container… on a case** creates the evidence item first (the existing `create_evidence`, logged as
`evidence_created`), then the container for it (`container_created` with that `evidence_id`). Two signed entries,
as if done in two steps. If the container cannot be created after the evidence was, the evidence item stays, the
error says so, and New Container… on that item creates the container.

**The container's name** defaults to its evidence item's name, and for a second or later container of the same item
to "<name> 2", "<name> 3", …; the user can change it. On a case, the one Name field names both the evidence item and
the container. The default file name is derived from the container name, as today.

**Deleting evidence**: an evidence item with a container (open or closed) cannot be deleted. The menu item is
disabled with the hover text "Only evidence without notes or containers". (Today only evidence without notes can be
deleted.)

**Containers from 2.6/2.7** are shown as they are, without rewriting the log. Several containers on one evidence item
are now normal. Only these need a fallback:
- A container without evidence appears in the tree as a row of its own under the case, after the evidence, with
  the container symbol and its container name. Selecting it shows its container section (no notes). It cannot
  be attached to evidence afterwards.
- A container whose evidence item was deleted (2.6/2.7 allowed deleting evidence that had a container but no
  notes, and factum-notes still does) is shown the same way; the row's hover text and the container section's
  details say "Evidence #n (deleted)". No finding is raised.

### 4.2 Tree and evidence view

**Tree row** of an evidence item: name, then the container symbol if it has at least one container, then the note
count, as today. The symbol is a Phosphor icon (a box, e.g. `package`; added to
`assets/fonts/Phosphor-Regular-subset.ttf` with `scripts/subset-icons.sh`), in the accent colour while any of its
containers is open, else in the muted text colour. A missing container file adds the existing ⚠ marker. Hover text
on the symbol: "Container · open", "Container · closed · signed", … for one container; "3 containers · 1 open" for
several. The row's own hover text (name and description) stays.

**Evidence view** (selecting an evidence item): the notes as today, then one container section per container,
oldest first, each with:
- a heading: container symbol, the container name, the file name and the state ("open", "closed · signed", …), and
  a ⋯ button with the container menu at the right;
- the details: file, UUID (with the copy button), base path (or "full paths");
- the history: adds and closes with time, entry id (clickable, jumps to the entry in the case log as today), text,
  and for each add its source (5.1);
- the files, with path, size, time and SHA-256, as the current container view shows them.

The current container view (`gui/containers.rs::container_view`) provides most of this; it moves into the evidence
view instead of replacing the log. The search filters the notes only; the container sections stay below them.
Selecting a container on its own (`container_id` in the GUI state) goes away except for the fallback rows of 4.1.

### 4.3 Menus

- **Case** (tree context menu, case ⋯ menu, Case menu in the menu bar): **New Container…** opens the case dialog of
  4.4, which creates evidence and container.
- **Evidence**, context menu: **New Container…** after Edit Description…, opening the evidence dialog of 4.4.
  Container actions are not repeated here (an item may have several containers).
- **Container section**, ⋯ button: the container menu as it is today (Add Files…, Add Folder…, Close Container,
  Close Without File…, Reopen Container, Verify Container…, Locate…, Show in Folder). The fallback rows of 4.1 show
  it as their context menu, as today.
- Items that apply but are not possible right now (Add while closed) stay disabled with hover text, as today.

### 4.4 Dialogs

**New Container on a case**: first line "Creates a new evidence item with an AFF4-L container. Every addition,
close and reopen is a signed entry in the case log." Fields: Name, Evidence hash (optional), Description
(optional), Acquire (optional folder), Folder, File name (derived from the name until edited). Create selects the new
evidence item.

**New Container on an evidence item**: title "New Container for <evidence name>"; fields Name (prefilled, 4.1),
Acquire (optional folder), Folder, File name.

**Acquire** (scenario 1): a folder, typically the read-only mount point. If set, it becomes the container's base path
and, right after creation, the whole folder is added exactly as Add Folder… with the default options would (keep
paths, full content), in the background with progress and Cancel. The container stays open afterwards for more. If
empty, the container is created empty with no base path (scenario 2).

The Base path field and the old "From evidence" picker are removed from New Container. The base path stays in the
Add dialog (per add, as today), defaulting to the container's base path; it may be left empty (4.6).

### 4.5 Reports

Reports list containers as today; every container now names its evidence item. 2.6/2.7 containers without
evidence are listed as before. No layout change is required; the builder may group a container under its evidence
item if that reads better in the existing report layout.

### 4.6 Full paths without a base path

Today every source of an add must lie below the base path, so files from different places need `/` or a drive root
as base, and on Windows files from two drives cannot go into one add. From now on the base path is optional, in the
container and in the Add dialog. Without one, the full original path is stored: on Unix the absolute path, on Windows
with the drive (`C:\Users\x\evil.exe`). How that maps onto `aff4l:originalPathName` and `aff4l:filesystemRoot`
(e.g. the root as `/` or `C:\` on the Add task, one task per drive, or the drive as the first path component) is left
to the builder, as long as pyaff4 opens the result and the full original path can be read back.

## 5. Strengthening the containers

### 5.1 Recording the source's mount

With every add, factum records the mount the chosen sources lie on, so the log and the container say which device,
file system and options the files were read through, and, where it can be found, which image file.

- **Linux**: from `/proc/self/mountinfo`, the mount containing the base path (longest mount point prefix): mount
  point, source device, file system type, mount options. For a loop device (`/dev/loopN`), the backing file from
  `/sys/block/loopN/loop/backing_file`. For a device-mapper or NBD device, the device only.
  For xmount and similar (image → FUSE mount → loop device → mounted file system), the backing file lies on a FUSE
  mount; that mount is recorded too (its mount point, source and type as `mountinfo` shows them), which usually
  names the tool and often the image. Going further is not required.
- **Windows**: `GetVolumePathNameW` for the volume root, `GetVolumeInformationW` for file system name, volume serial
  number and label, `GetVolumeNameForVolumeMountPointW` for the volume GUID path. Read-only state from the volume
  flags. The image file behind a mounted image (Arsenal Image Mounter, FTK Imager, Windows' own VHD mount) is
  recorded only where Windows reports it without vendor tools (e.g. a VHD attached by Windows); otherwise left out.
- **macOS**: optional, from `statfs` (`f_mntfromname`, `f_fstypename`, `f_flags`).

If sources lie on several mounts, each mount is recorded once, with the sources below it. If nothing can be read,
the add proceeds and records that the mount is unknown.

Where it goes:
- the `container_files_added` payload gets `sources`: a list of
  `{mount_point, device, fs_type, options, read_only, image, volume_serial, volume_label, volume_guid}` (fields
  absent where the platform does not give them);
- the container's Add task (`aff4l:LogicalAcquisitionTask`) gets the same facts as factum properties;
- the log text stays as today; the evidence view shows the source line per add (4.2);
- reports show it with each add if the existing layout has a place for adds, else with the container.

A mount that is not read-only is neither refused nor warned about: export folders on a writable disk are a normal
source (first design, 4.4), so a warning would sit on most verifications. The source line shows the options
(`rw`/`ro`) as a plain fact, and so do the reports. An unknown mount is shown as "mount unknown", also without a
warning. Verify Container… and `verify_container.py` do not check the source facts.

### 5.2 Re-checking at close

Before signing, Close Container reads back every stream added since the previous close from the container file and
compares MD5, SHA-1 and SHA-256 with the recorded ones. Only then is the state signed and `container_closed`
logged.

- So that the read comes from the disk and not the operating system's cache: the container file is synced
  (`sync_all`, as today), and then on Linux its cached pages are dropped (`posix_fadvise(POSIX_FADV_DONTNEED)`) and
  on macOS the file is read with `F_NOCACHE`. On Windows the re-check reads through the cache (decided by the user:
  no unbuffered reading); this is a documented limitation (5.5).
- The `container_closed` payload gets `recheck: {files, bytes, uncached}` (`uncached` is false where the cache could
  not be bypassed). The log text adds "re-checked": `Container #2 closed · 57 files · re-checked · signed`.
- It runs in the background with progress and Cancel in the status bar, as adding does. Cancel leaves the container
  open, nothing logged.
- A mismatch does not sign anything. Instead of an error, Close opens one dialog: "N files in the container don't
  match their hashes. The container file or its disk may be damaged." with the files listed and three buttons
  (no new menu items; the user wants it simple, working or failing transparently, without covering every edge
  case):
  - **Add Again**: the failed files are added again from their original paths, as a normal add (one
    `container_files_added` entry, its payload naming the files it replaces). The damaged copies stay in the
    container (it only grows), marked as replaced by a factum property. Then the close continues: re-check, sign,
    log. If adding fails (e.g. the source is no longer mounted), the error is shown and the container stays open.
  - **Close as Damaged**: a logged `container_closed` with `damaged: [paths]` and no signatures; the container shows
    "closed · damaged". Reopen works as for any closed container.
  - **Cancel**: the container stays open; the next Close re-checks again.
- Verify Container… reports a replaced copy as a warning (naming the replacement) and an unreplaced mismatch as a
  fail, as for any stream today.
- Closing with nothing added since the last close re-checks nothing (`files: 0`).
- Close Without File… is unchanged (there is no file to read).

### 5.3 The README names the verifier

`factum/README.txt` inside each container is written at creation (and rewritten at each close) with two added
lines: the factum version that wrote the container, and the SHA-256 of the `verify_container.py` it carries, with
the address of the same script on GitHub for that version
(`https://github.com/overcuriousity/factum-rs/blob/v<version>/src/container/verify_container.py`). It tells the
recipient to compare the hash before running the script. Whether the README is rewritten at close or only written at
creation is up to the builder, given the append-only container layout; it must name the script actually in the
container.

The script is embedded with `include_bytes!`, and the Windows release job checks out with the runner's default
line-ending conversion, so a Windows build would embed a CRLF copy whose hash differs from GitHub's. A
`.gitattributes` pins `src/container/verify_container.py` (and the other embedded text files, e.g. `README.txt`,
`src/export/verify.py`) to LF (`eol=lf`).

### 5.4 A public sample container

A signed sample container is committed to the repository, so that anyone with AXIOM or another AFF4-L tool can check
whether factum's GPG and X.509 signatures are accepted, without real case data.

- `samples/container/`: `sample.aff4l` (a few small files, one add, one close, reopened, one more add, closed again,
  so it carries two closed states), the throwaway GPG public key, the throwaway X.509 root and intermediate
  certificates (PEM), and a `README.md` saying these keys are for testing only, how the sample was made and how to
  verify it (factum, `verify_container.py --ca root.pem`, pyaff4).
- Made by a script (`scripts/sample-container.sh`) that creates the throwaway GPG key and X.509 chain (openssl,
  imported into a temporary `gpgsm` home) and a small Rust example (`examples/sample_container.rs`) that builds the
  container with the library API. No private keys are committed.
- Regenerated by hand when the container format changes; not part of every release. CI checks that the committed
  sample still verifies with `verify_container.py` and factum's verifier.

### 5.5 Documented limitations on Windows

Decided by the user: Windows stays as it is for these two points, and both are documented as known limitations,
because evidence must not be tampered with and the examiner has to know where factum does not protect against it.

- **Re-check at close** reads through the Windows file cache, so it may not detect a bad write to the disk
  (`uncached: false` in the close entry).
- **Access times of the sources**: on Linux factum reads sources with `O_NOATIME` where permitted; on Windows it does
  not prevent the last-access time from being updated. Sources on a writable volume can therefore get a new access
  time when added. Examiners on Windows should add from a read-only mounted image or behind a write blocker.

Where: in `README.md` (Evidence containers section, as "Known limitations on Windows"), in the CHANGELOG entry of
this release, and in `docs/` wherever containers are described for examiners. On Windows, the Add dialog shows a
one-line hint under the source when the source's volume is not read-only: "Windows may update access times on this
writable volume." (uses 5.1's read-only state; no hint when the state is unknown).

## 6. Testing expectations

- GUI tests (existing harness): tree shows the symbol only on evidence with containers; selecting it shows notes
  and one section per container; menus per 4.3; both dialogs create what 4.1 says; delete disabled with a
  container.
- Acquire: New Container with an Acquire folder creates the container and adds the folder in one step.
- Full paths: an add without base path from two different folders stores both full paths; pyaff4 opens it.
- A database from 2.6/2.7 with a container without evidence and one whose evidence was deleted shows both as 4.1
  describes (fixture written through log entries).
- 5.1: Linux test against a loop-mounted image where the CI permits, otherwise a parsed `mountinfo` fixture;
  Windows test on the CI runner's own volume (file system, serial, GUID present).
- 5.2: a clean close logs `recheck`; a container whose stored bytes are altered after an add shows the dialog,
  Add Again then closes signed, Close as Damaged logs an unsigned damaged close, Cancel logs nothing.
- 5.3: README hash equals the SHA-256 of the bundled script.
- 5.4: CI verifies the committed sample.
- factum-notes and `verify.py` still verify a database with the extended payloads.

## 7. Left to the builder

- Module layout; where mount detection lives (`container/source.rs` or a new module).
- The exact Phosphor glyph, as long as it reads as a box or container.
- How far image detection on Windows goes (5.1).
- The factum property names for the source facts.
- Wording of dialogs and messages, in the style of the existing ones.

## 8. Open risks

- Mount details on Windows rarely name the image file behind a mounted image; the record often stops at the volume.
- Dropping the page cache is advisory on Linux; under memory pressure or on some file systems the read may still be
  served partly from cache. The `uncached` flag records the intent, not a guarantee.
- The sample container proves acceptance only if someone with another tool tries it.

## 9. Calls made without the user (to check)

- **2.6/2.7 containers** are shown as they are (4.1): without evidence, or with deleted evidence, as their own row
  marked accordingly. No migration, no new log entries, no "attach later" action.
- **Deleting evidence with a container is not allowed**, open or closed: a deleted evidence item would hide its
  containers while their files and log entries remain.
- Container name defaults to the evidence name ("<name> 2" for further ones); on a case one Name field serves both.
- Case-level New Container… logs two entries (evidence, then container); a failure after the first keeps the
  evidence item.
- **Container actions live on each container section's ⋯ button**, not in the evidence's context menu, because an
  item can have several containers; the context menu only gains New Container….
- Acquire uses Add Folder…'s default options (keep paths, full content); other options need Add Folder….
- Container log entries stay case-level system entries (not attached to the evidence item), so they appear in the
  container section's history, not among the evidence's notes.
- A container whose evidence item was deleted shows as its own row, marked "Evidence #n (deleted)" (4.1).
- A writable or unknown mount is shown, not warned about or refused (5.1).
- The re-check covers only what was added since the previous close (5.2).
- After a failed re-check (5.2): Add Again, Close as Damaged or Cancel in one dialog. The user asked for a second
  chance and simplicity; the details (replaced-by marking, `damaged` payload, verify as warning) are my call.
- The Close and Archive flow runs the same close, so it can stop at that dialog.
- Embedded text files are pinned to LF line endings (5.3).
- The Windows access-time limitation is also shown as a one-line hint in the Add dialog for writable volumes (5.5).
- The sample container lives in `samples/container/` and is regenerated by hand (5.4).
