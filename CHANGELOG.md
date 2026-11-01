# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- GUI: once text is typed into a dialog (Correct, case goal, new case or evidence, companion settings, setup), Escape
  and a click outside no longer close it; Cancel does. The Correct dialog's text field scrolls, so the buttons stay in
  view, and has its own undo history per dialog. The Seal Folder dialog and the setup refuse a folder that is not an
  existing absolute path. A container's file name may not hold a path and gets `.aff4l`. Add Label is off for a label
  that is only `#`. A key missing or not trusted shows as failed (✗), like the verifier rates it, and the signature
  line says "key not trusted". The verify window lays out only the OK entries in view.
- `verify.py` prints its own SHA-256 when it starts; `factum --version` prints the SHA-256 of the embedded `verify.py`
  and `verify_container.py` (`-V` stays one line), the release notes list both, and the bundle README says to run a
  trusted copy or compare the hash
- `verify.py` runs gpg by its absolute path and refuses one in the current folder or the bundle's, which Windows would
  otherwise run before the one on the `PATH`
- The bundle and container READMEs, `README.md` and `docs/AIRGAP.md` give the scripts' command as `python3 -I`, which
  keeps Python from loading a module planted beside the script
- CLI: a case or evidence item is found by `#<id>`, then an exact file number, then an exact name; a plain number is an
  id only when nothing matches, several matches are an error that lists them, `_` is no longer dropped from numbers.
  Exit codes: 0 done, 1 verification failed (also `--export` of a failing case, which warns and still writes the
  files), 2 any error (no case found, bad arguments, I/O; was 1). A note together with an option is refused. With
  `FACTUM_DB` set the CLI prints `Database: <path>` on stderr. `--list-gpg` names an expired or revoked active key.
  The demo example refuses without `FACTUM_DB` or a path.
- The seal folder setting is stored as `FACTUM_SEAL_DIR` in the user config `.env`, no longer in the database: the
  verifier no longer takes the folder it checks from the database it verifies, which a tamperer could point at an
  empty folder. A folder set in the GUI of an earlier version is moved there on the first start (with a warning), and no
  database is read for it afterwards. Verify reports (CLI, GUI, HTML, Markdown, PDF) name the seal folder they
  checked; a change of the seal folder is written to the application log. A folder still named in the database but
  not in use is mentioned in a warning and not checked; choosing a seal folder in the GUI removes it
- A `.env` in the current directory is no longer read, only the one in the user config directory
- Verifying a case again in the same session reuses good signature results as long as the keyring is unchanged (for at
  most 10 minutes, never on disk), so late signing and repeated checks no longer run gpg for every signature
- Reports and `verify.py` name the primary key's fingerprint of a signature made with a subkey (a primary key's
  fingerprint is unchanged); the entry's integrity lines also name the subkey
- A signature counts only as exactly one good signature with a clean gpg exit code, in factum and in `verify.py`
- `verify.py` needs gpg 2.1 or newer and says so on an older one
- Installers and `scripts/airgap-download.sh` check the signature on `SHA256SUMS` with `gpg` when `SHA256SUMS.asc` is
  there: a bad signature stops the install; a missing `gpg`, `.asc` or release key (never fetched), or a signing key that has expired since, only warns that
  integrity, not authenticity, was checked. The download script fails when a file is not listed in `SHA256SUMS` or a
  `--target` matches nothing. `install.sh` quotes and escapes the install folder in the menu entry's `Exec=` line;
  `install.ps1` keeps `%VAR%` entries of the user PATH unexpanded.

- `verify_container.py` ends each finding with factum's code for it, in square brackets, and reads a signature's
  certificates as of the signing time it states: a good signature by a certificate that has expired since is a warning
  (`x509_expired`), a chain not valid at signing fails, and a `.sig` without its `.cer` is a warning. A signature counts
  by the same rules as in `verify.py` (exactly one good signature, a key expired since is a warning, every trust line
  counts, the primary key's fingerprint), and it needs gpg 2.1 or newer to check one. Every `replacedBy` is a warning
  naming the pair: only factum can compare it with the case log

### Fixed
- `verify_container.py` reaches the verdicts of factum's own check: it reads the ZIP itself, so bytes after the last
  complete state are a warning only when they are an interrupted addition and otherwise fail, like a directory that
  holds more or less than its count or a member whose local header differs; a bad CRC-32 is a finding beside the hashes
  instead of a traceback or a stop; a closed current state's root signatures are compared with the kept ones; `history/0`
  fails; a crafted history number no longer exhausts memory; IRIs decode `\u` escapes and refuse what Turtle forbids
- Containers: a stored file in a compression method nobody reads fails verification instead of "not checked", which
  had let a swapped file in a signed container pass with a warning; `not_checked` stays for other tools' containers
- Containers: whether a container is factum's is told by its layout, not by `version.txt`, which is not signed: a
  missing or other `version.txt` or a missing `container.description` fails, the file is still checked, also against
  the case log, and naming another tool no longer turns off the signature checks. A file that names a container of
  the log but cannot be compared with it fails
- Containers: members under `factum/history/` outside a close that was read fail, as does a signature at the root of an
  open state, so a close can no longer be hidden behind a number or left out of the directory
- Containers: a file is checked as what the log expects of it: Verify on a container, or a file at a place the log
  records, must be that container, whatever uuid it names or none; `container.description` must agree with the ZIP
  comment and the signed metadata; `not_signed` is a warning in every format, so an unsigned file is never called good;
  the root `information.turtle.hashes` of a closed state is checked; a secondary store that cannot be read fails
- Containers: crafted files can no longer stop verification: a stray `>` in Turtle hung the parser, a search through
  end records has a limit linear in the file, an ImageStream index that repeats a chunk is damage, a signature or
  chain is at most 4 MiB, and metadata has a limit of 128 times what the file stores of the members read, from 4 GiB
  to 16 GiB, in factum and in `verify_container.py`, counted as a parse holds it, so a long subject or prefix repeated in
  a short file stops there too. A check that runs out stops with one `too_large` finding, which does not mean alteration
  and is no `log_mismatch`
- `verify_container.py` prints its own SHA-256 when it starts, and the container's README says to run a trusted copy or
  to compare that hash with `factum --version` or the release notes; neither is signed. It ends with `Result: NOT SIGNED`
  rather than `OK` when the state it checked is not signed; the exit code stays 0
- Containers: a source is opened without following a link or waiting on a FIFO, must still be the regular file of the
  same size that was listed (otherwise it is reported as changed, not added), and is read no further than one byte
  past that size
- Containers: a link to the container inside an added folder is recorded as a link, not dropped, and a hard link to it
  is listed as not added; files are no longer resolved one by one to find the container
- Containers: paths and link targets that are not valid Unicode keep their bytes beside the text
  (`factum:sourcePathRaw`, `factum:symlinkTargetRaw`, in the log `source_raw`, `base_path_raw`), and Add Again uses
  them, so such sources can be added again; a Windows name with an unpaired surrogate keeps a raw form too; change
  times before 1970 are no longer recorded as 1970
- Containers: a mount point that is not UTF-8 no longer leaves every mount of the add unknown; it is matched by its
  bytes and recorded with them (`factum:mountPointRaw`). A mount hidden by another is no longer reported
- Containers: superblock options are recorded beside the mount's own (`factum:superOptions`; the source line shows
  them when they say `ro` and the mount does not) and read-only counts if either says so; the image behind a partition of a loop device is recorded
- Containers: on Windows a mount folder among the sources no longer decides the volume of its siblings; adding many
  files no longer reads sysfs once per file
- Containers: an X.509 signature no longer fails once its certificate has expired: every certificate of its chain
  must have been valid at the time the signature states, and verification warns (`x509_expired`) that this rests on
  the time the signer stated. A signature by another certificate than the first one stored in the container is a
  failure, even when it chains to a trusted root, and a signature with no stored certificate a warning; this finds an
  inconsistent file, not someone who replaces both. Only the comparison with the certificate recorded in the case
  log, a failure too, defends against that
- Containers: IRIs that do not fit the Turtle grammar are %-encoded when written and refused when read, and `\u`
  escapes in IRIs are decoded
- Containers: reading a member checks it against the CRC-32 of the central directory. In verification a mismatch is a
  failure of its own, next to the hash results, and all other checks go on; the re-check before a close goes by the
  hashes. A container whose version, description or metadata differs from its CRC-32 is not opened, and the message
  says so and points to Verify Container
- Containers: a central directory with entries behind its count (invisible to factum, read by other ZIP tools) is
  refused, and a member whose local header differs from the central directory in name, method or flags fails
  verification; verifying reports such bytes after the last state as a failure, not as an interrupted addition
- Containers: a member keeps the time it was written; each later state rewrote the times of all earlier members
- Opening a container for writing no longer cuts anything off after a read error, and refuses when the bytes after the
  newest state could be more than an interrupted addition (a complete central directory that cannot be read, bytes no
  crash of the writer leaves, an end before the state the case log records); an interrupted member is no longer taken
  for a finished empty one and its content read as ZIP headers
- `factum --verify <id>` and the lookup by name no longer stop at a case row that cannot be read; it is skipped by
  name (and reported) and still reachable by id
- IOC extraction: domains and emails with non-ASCII letters (`münchen.de`) are found; a URL keeps its final `/` and
  loses trailing punctuation and an unbalanced `)`/`]`; SHA-512 hashes are found; real TLDs such as `.zip`, `.mov`,
  `.app`, `.sh`, `.py` are no longer taken for file names; domains, emails, hashes and the scheme and host of URLs are
  lowercased, so `Evil.COM` and `evil.com` are one IOC (IOCs stored by earlier versions are matched regardless of case)
- A case or evidence item and its log entry are now written in one transaction, so a crash while signing can no
  longer leave a row without its log event; the logged ids are unchanged
- A case file number already used by an open case is refused, when creating a case and when editing one (archived cases
  may share it)
- A correction chain that loops in a tampered database gives an error instead of hanging
- The images of one note version may add up to 50 MB; older notes over it can be corrected without adding images
- `page#section` in a URL, `a#b` and `&#38;` no longer create tags in new notes; existing notes keep their tags
- Tag and label suggestions come from the current case only
- A tag such as `#İZMİR` no longer crashes the suggestion list
- A signature made before its key expired is valid with a warning (`key_expired`) instead of invalid, in factum and in
  `verify.py`; one made after the expiry is invalid. gpg gives no trust level for an expired key, so it counts as
  trusted if it is ultimately trusted, or if only its signing subkey expired and the primary key is valid. An expired
  primary key that was trusted only through certification by another key (a colleague's key you signed) still fails,
  now as `key_untrusted`, not as an invalid signature
- Keys with a certify-only primary key and a signing subkey can be selected; expired and revoked keys can no longer be
  selected. A remembered key that expired or was revoked stays active and listed, so signing is still refused with an
  error, never silently unsigned
- Checking a tampered signature that holds a symmetric-encrypted message no longer opens a passphrase prompt
- A malformed database cell (invalid UTF-8, wrong type) gives a FAIL for its row instead of stopping `--verify`
- A database made by a newer factum says so and asks for an upgrade, instead of calling itself older
- A seal file that cannot be read or parsed is reported as a warning naming the file instead of being skipped
  silently, and a corrupt or incomplete signed copy (`.asc`) no longer hides the unsigned seal file (`.json`) it
  replaces
- Seal files of a case whose file number contains U+2028, U+2029 or U+0085 are no longer ignored by the verifier
- Seal files are written to a temporary file and renamed, so a crash leaves no half-written seal
- Very long case file numbers (e.g. 80 CJK characters) no longer fail to seal with "File name too long": the file
  name is shortened, with a short hash keeping it unique
- A container close signs only the state that was re-checked: it compares under the volume lock, and asks for a new
  re-check when another process changed the container since
- An addition or a close is refused when the container was closed meanwhile; Close as Damaged, Close Without File and
  Reopen fail with "in use" while another process holds the file, and go through when it cannot be reached at all (a
  dead mount)
- Opening a container goes by the log as it is once the lock is held, so a late signature can no longer drop an
  addition that another process committed while it waited
- A `factum:replacedBy` that no addition in the case log records (or the reverse) fails Verify Container, so a forged
  replacement no longer turns a failed hash into a warning
- The container list says signed only when the newest close is, as the container's own view does: a late signature of
  an older close no longer counts
- Comparing a container with the case log no longer takes seconds with many folders (20,000: 4.9 s to 0.11 s, debug
  build); Add Again plans and replaced files are looked up by ARN
- A new evidence item with a container is two entries in one transaction, both signed before it: a failure leaves no
  entry and no file, and trying again makes no duplicate
- A close signs the stored `information.turtle` bytes, not a new serialization, so the closed state and the root stay
  the same bytes whatever wrote them
- A read error during the re-check that repeats while the start or end of the file reads (EIO from a bad sector)
  counts as damage, so Close as Damaged and Add Again are offered; permissions, removed media and interrupted calls
  stay retryable
- A CRC-32 fault of a container's directory stops additions and signatures, even when the hashes match; Close as
  Damaged works then too, writes nothing, and logs `directory_fault` so the log does not claim lost files, nor
  undamaged ones it never reached (`unchecked_files`)
- A hostile `factum/history/0/` member is a failure in Verify Container instead of a crash, a crafted high close
  number no longer exhausts memory (one finding per gap) and a container cannot be closed past the highest number
- `verify.py` fails on ZIP member names read differently by other tools: repeated names (Python reads the last copy,
  unzip the first), absolute names, `..`, a backslash, names differing only in case
- A table row taller than a page in the PDF report (a long evidence description, a long container path) continues on
  the next page instead of running off the bottom and being lost, and a table header no longer stays alone
- Characters neither PDF font has are drawn as a visible `�`, and copy and search give the real character (glyph 0
  was mapped to the first such character in the whole report); the export warns about them and says the HTML report
  shows them
- Reports show the text of superseded note versions in the integrity appendix, with their time and signature, and a
  note in the timeline is flagged when any of its versions failed verification, not only the newest
- The Markdown report puts bare URLs, autolinks, e-mail addresses and link text equal to its address in code spans:
  GitHub-style viewers made them clickable, which the report says links never are
- An export that fails leaves no files behind: all are written to a temporary folder in the target folder and renamed
  at the end, so reports no longer stay behind when the bundle fails
- Export file names are shortened: 80 CJK characters in a case file number failed with "file name too long"
- Export builds only the requested formats, so PDF or Markdown alone no longer build the HTML with its embedded images
- Companion: selecting a case sends none of its content during the 30 seconds it can be opted out in; its history is
  enriched only after its first successful pass
- Companion: switching it off for a case, deleting the case, changing the settings and closing the program take effect
  after the model call in hand instead of after the whole pass or backlog batch; a pass ends at once when the endpoint
  stopped answering during its enrichment, instead of waiting out two more timeouts
- Companion: related older entries are found when the newest entries are the best matches
- Companion: new entries a later full pass had to cut for space are left to later passes instead of being marked as
  seen; a case's first pass stays an overview, so what it cuts counts as seen
- Companion: the long reasoning of a thinking model is shortened to what fits the second call, leaving it room to think;
  the call failed with HTTP 400
- Companion: token estimates follow the server's counts more carefully, so an identifier-heavy prompt no longer overflows
  the window after a prose-heavy one
- Companion: a huge or malformed model reply can no longer hang the repair of its JSON
- Ask: large pinned notes no longer crowd out the retrieved entries or end in "Not in the case log." without asking the
  model: they are shortened when they do not fit, half of the room is kept for the retrieved entries, and an excerpt
  that does not fit no longer stops the ones after it. Ask uses the model's window and token ratio the companion found
- GUI: a background task that dies no longer leaves its job hanging (the verify progress forever, additions blocked for
  the session): it is reported as a failure and the job ends
- GUI: a non-ASCII hash in a tampered log no longer panics the container view on every frame
- GUI: Sign, Sign All Unsigned, Sign Seal and Export verify the case on a worker with the progress dialog, instead of
  freezing the window for a gpg run per signature; signing follows on the GUI thread when the verification passed
- Sign All Unsigned that stops part way says so ("Signed 5 of 20; stopped: ..."), in the GUI and the CLI, instead of
  "nothing was signed"
- GUI: a case whose id was reused after a permanent delete no longer shows the deleted case's verification status
- GUI: a container with a directory fault offers Close as Damaged, also when an addition is refused for it and on the
  way of Close and Archive, which no longer stops there; the faults go into the log. A damaged close with no file to
  read back says the files were not checked
- GUI: searching waits until the field rests for 200 ms and reuses the case tree and the built cards, so a long log no
  longer re-reads and re-parses everything on every keystroke
- GUI: a container event that cannot be read no longer stops the whole window from filling; it is logged and the
  case shows without those containers
- GUI: Ask shows only the answer to the newest question, and the question field is read-only while it runs
- GUI: after a correction the focus moves to the new version, so P pins the note you see
- GUI: the Case menu acts on the case it shows, and no longer panics when the selection went away
- GUI: archiving or deleting evidence clears the selection only when it still points there and the call worked
- GUI: a signing key changed on the command line is picked up while the window is open
- GUI: Locate and Close Without File wait for a running addition or re-check, and so does archiving for a re-check
- GUI: quitting with a running addition or re-check, a verification for a signature or an export, a note being written
  or typed text in an open dialog asks once ("Quit anyway?", with the reason). Confirmed, a running addition is cancelled and the window closes after its rewind;
  a finished addition is logged before the window closes

## [2.7.1] - 2026-10-29

### Fixed
- A container's file list shortens long paths in the middle, so the file name stays visible: files whose names
  differ only at the end (`photo.png`, `photo.jpg`, `photo-1.png`) no longer look alike. A link keeps its own name,
  not its target's, and `(metadata only)` or `(excerpt …)` follows the name instead of pushing it out. A shortened
  path shows one tooltip with the whole path, not two; its context menu copies the whole path. The container's file
  and base path are shortened the same way
- The evidence on a note card and the target above the composer show one tooltip when they are cut off, not two

## [2.7.0] - 2026-10-28

### Added
- Markdown in notes: a toolbar above the note field and the correction dialog (bold, italic, code, link, heading,
  list, quote); notes are shown formatted in the log and in HTML, Markdown and PDF reports, with a source toggle on
  each note in the log
- Images in notes: paste a screenshot (when the clipboard has no text), drop image files on the window or insert them
  with Image…; thumbnails show what the note will be saved with. The images are part of the note's signed payload,
  shown inline in the log and exported with the reports. Correcting a note, in the GUI or with `--correct`, keeps the
  images the corrected text still refers to. An image whose reference the text does not show (inside code, escaped or
  edited) is marked under the field, and the note is not saved until it is fixed or removed. On Wayland, pasting an
  image depends on the compositor offering clipboard data control (not verified; GNOME likely does not); inserting
  from a file always works
- Containers are evidence: an evidence item can hold several containers and shows a container symbol in the case
  list (blue while one is open); selecting it shows its notes and, below them, each container with its file,
  history and files
- New Container… on a case creates a new evidence item with its container; on an evidence item it adds one.
  Acquire copies a folder (e.g. a disk image mounted read-only with xmount) in right away, in one step
- The base path of a container is optional: without it, the full original path is kept (with the drive on
  Windows), so files from anywhere, several drives included, go into one container
- Every addition to a container records the mount its files were read from (Linux: device, file system, options
  and the image behind a loop or xmount mount; Windows: file system, volume serial, label and GUID) and each file's
  absolute source path; reports list them
- Closing a container re-checks what was added since the last close against its hashes, reading past the page
  cache on Linux. A mismatch offers Add Again (copies the files again; the damaged copies stay, marked as replaced,
  and both verifiers report them as warnings), Close as Damaged (logged, not signed) or Cancel. On Windows the
  re-check reads through the file cache and may not detect a bad write to the disk
- A container's README names the factum version and the SHA-256 of its `verify_container.py`, with the same script
  on GitHub to compare
- `samples/container/`: a signed sample container with throwaway TEST ONLY GPG and X.509 keys, for testing other
  AFF4-L tools; CI checks that it verifies

### Changed
- A container always belongs to an evidence item; containers have no rows of their own in the case list any more
  (except those from 2.6 without an evidence item, or whose evidence item was deleted)
- An evidence item with containers cannot be deleted
- On Windows, adding from a writable volume may update the sources' last-access times (factum does not prevent it
  there; the Add dialog says so): add from a read-only mounted image or behind a write blocker
- Existing notes are shown as Markdown too, so some read differently than before: `__init__` turns bold, lines
  starting with `* x` or `1.` become lists. Backslashes and entity references stay as typed (`\\fs01`,
  `C:\$Recycle.Bin`, `&amp;`), so paths and names are never changed. The source toggle in the log (and the source
  block in HTML reports) shows the note exactly as signed

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
