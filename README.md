# factum

Cryptographically signed forensic logging — a Rust port of factum-notes.

[![CI](https://github.com/overcuriousity/factum-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/overcuriousity/factum-rs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/overcuriousity/factum-rs)](https://github.com/overcuriousity/factum-rs/releases/latest)

Every case is an append-only, tamper-evident log modelled on Certificate Transparency: each note and each change to
case or evidence details is a leaf in a Merkle tree (RFC 9162), timestamped (UTC) and optionally GPG-signed together
with the tree head it produces. Seals (signed tree heads) are copied to an external folder, and a case can be exported
as a self-contained bundle that anyone can verify without factum.

factum is a single binary with a command line and a desktop GUI. It shares the seal files and bundle format with
factum-notes. Since 2.2 its database (schema 4, which adds the evidence description) is no longer one factum-notes can
open; factum upgrades a factum-notes database (schema 3) when it first opens it.

## Install

**Linux and macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.sh | sh
```

The installer picks the build for your system, checks it against the release's `SHA256SUMS`, installs `factum` to
`~/.local/bin` (`/usr/local/bin` as root) and, on Linux, adds *Factum Notes* to the application menu. Options:
`--version v2.1.4`, `--dir DIR`, `--cli` (static command-line build without GUI), `--no-desktop`, `--uninstall`:

```bash
curl -fsSL https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.sh | sh -s -- --version v2.1.4
```

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.ps1 | iex
```

This installs to `%LOCALAPPDATA%\Programs\factum`, adds it to your `PATH` and creates a Start menu entry.

**Air-gapped machines**: see [docs/AIRGAP.md](docs/AIRGAP.md). In short: copy the archive for your platform,
`SHA256SUMS` and `install.sh` from the [release page](https://github.com/overcuriousity/factum-rs/releases/latest),
then run `sh install.sh --archive factum-x86_64-unknown-linux-gnu.tar.gz`. A vendored source archive allows building
from source without network access.

### Release builds

| Archive                                       | System                                                       |
|-----------------------------------------------|--------------------------------------------------------------|
| `factum-x86_64-unknown-linux-gnu.tar.gz`      | Linux x86_64 with glibc 2.28 or newer (RHEL/Alma/Rocky 8+, Debian 10+, Ubuntu 18.10+) |
| `factum-aarch64-unknown-linux-gnu.tar.gz`     | Linux ARM64, glibc 2.28 or newer                             |
| `factum-cli-x86_64-unknown-linux-musl.tar.gz` | Any Linux x86_64 (static; command line only, e.g. Alpine, servers) |
| `factum-aarch64-apple-darwin.tar.gz`          | macOS on Apple silicon                                       |
| `factum-x86_64-apple-darwin.tar.gz`           | macOS on Intel                                               |
| `factum-x86_64-pc-windows-msvc.zip`           | Windows 10/11 x64                                            |

Every release has `SHA256SUMS` and [build provenance attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations):
`gh attestation verify factum-x86_64-unknown-linux-gnu.tar.gz --repo overcuriousity/factum-rs`.

### Requirements

- **GPG** for signing and verification: `gpg` on the `PATH` (Linux: the `gnupg2`/`gnupg` package; macOS:
  `brew install gnupg`; Windows: [Gpg4win](https://www.gpg4win.org/)). Without it, notes can still be written, unsigned.
- **GUI on Linux**: OpenGL (Mesa) and an X11 or Wayland session; nothing else is linked. The GUI's file dialogs use
  the desktop portal (`xdg-desktop-portal`); without it, type the folder into the text field.
- Signing from the GUI needs a graphical pinentry (`pinentry-qt`, `pinentry-gnome3`, `pinentry-mac`, Gpg4win).

## Features

### Case log and integrity
- One Merkle tree per case (RFC 9162). Every note and every system entry (case created or edited, evidence created
  or deleted, case archived or reopened) is a leaf
- Each entry is signed together with the tree head right after it, so every signed entry vouches for all entries
  before it: changing or removing any earlier entry breaks every later signature
- **Seals** (signed tree heads) are created on archive, on export and on demand (`--checkpoint`, "Seal Now") and
  written to an external seal folder (`FACTUM_SEAL_DIR`). A seal file detects removed entries even if the database
  copy of the seal was removed too
- **Verify Case** (GUI) / `factum --verify`: recomputes every leaf and tree head, checks all signatures, all seals
  (database and seal folder) and that case and evidence details match the log. Failures: changed or missing entries,
  unsigned entries, invalid signatures, unknown or untrusted keys, broken seals. Warnings: entries signed later, entries
  added after the newest seal, seal folder next to the database
- Entries and seals created without a key can be **signed later**; they are then shown as "signed later on <date>"

### Cases and evidence
- Create cases (file number, name, description) and evidence items (name, hash, description), in the GUI or with
  `--new-case`/`--new-evidence`; both are recorded in the log
- **Edit Case** changes file number, name and description through a signed `case_edited` entry; earlier seals stay
  valid
- **Edit Description…** on an evidence item changes its description through a signed `evidence_edited` entry; name
  and hash stay as created
- **Archive** instead of delete: an archived case is read-only, hidden by default ("Show archived cases",
  `--list-cases --all`) and sealed; it can be reopened. Archived cases can be deleted permanently in the GUI by typing
  the case file number; external seal files are kept
- Evidence items can only be deleted while they have no notes

### Notes
- Notes are never edited. **Correct Note** adds a new, signed version; only the newest version is shown, earlier ones
  under "Show history". Tags, IOCs and pins follow the newest version
- `#tags` in the note text are covered by the signature; **labels** added by hand are not signed and look different
- Pin/unpin notes, filter by tag or label (substring match)
- Entry IDs are never reused

### Export
- Case report as **HTML** (integrity details in collapsible sections, no JavaScript), **PDF** (A4, rendered by factum
  itself — no browser or Qt needed) and **Markdown** (short integrity line per entry plus an integrity appendix)
- **Verification bundle** (ZIP): `case.json`, all signatures, signers' public keys, the three reports, a signed
  `MANIFEST.sha256` and a dependency-free `verify.py`: `python3 verify.py bundle.zip`
- Exporting seals the case first; a case that fails verification is still exported, with the failures on top

### IOC extraction
- IPv4 addresses, domains, URLs, emails, MD5/SHA-1/SHA-256 hashes, grouped by type in the side panel
- File names such as `evil.exe` or `notes.txt` are not reported as domains

### Analytical companion
- An optional mentor that reads the case log through an LLM and keeps a short list of open analytical questions per
  case ("what corroborates this?", "which log did you not check?"). It asks; it never writes notes for you
- Nothing it produces enters the log, exports, bundles or verification, and a case verifies identically with or
  without it. Case content is sent to the endpoint you configure, nowhere else
- **Companion → Settings…**: endpoint URL, protocol (OpenAI- or Anthropic-compatible), API key and model; a local
  server on the lab network works. Until it is configured, no companion section, status item or Case-menu item appears
- A preset sets the lens it asks through, for all cases: **Forensics** (the default), **Generic investigator**, **OSINT
  research**, **Source criticism**, or **Custom** with a guideline of your own
- Evidence descriptions are part of what it reads
- **Case menu**: "Companion for this case" switches it per case, "Case goal…" gives it the question the case is meant
  to answer
- The questions sit in the side panel; **+** and **−** rate them, which shapes later questions. The questions menu has
  **Ask…** (a question answered only from the case log, with cited entries) and **History**
- It keeps its state in a second SQLite file next to the case database (`factum.companion.db`). That file holds the
  API key and content derived from the case, so treat it as exactly as sensitive as the case database. Deleting it
  loses ratings and settings, no evidence. `FACTUM_COMPANION_API_KEY` overrides the stored key and is never saved

### Setup wizard
- On the first start with a new database, a wizard walks through the signing key, the companion (optional, with its
  preset), the folder for seal copies and the theme. Every step can be skipped; **Settings → Setup Wizard…** runs it
  again

### GPG
- Select a signing key from your secret keys; the choice is remembered (shared by CLI and GUI)
- A ✓ next to an entry means its signature was checked in the background, not merely stored
- Pinentry guidance for Linux, macOS and Windows when signing fails

## Usage

**CLI** — fast note entry without leaving the terminal:

```bash
factum --new-case 2026/041 "Ransomware Müller GmbH" --description "file server FS01"   # becomes the active case
factum --new-evidence "FS01 disk image" --hash e3b0c442… --description "seized in rack 3"   # in the active case
factum --set-active evidence 1          # by ID or name, must belong to the active case
factum "Checked disk image, found suspicious binary at /tmp/.hidden #malware"
factum --correct 42 "Binary was at /tmp/.cache, not /tmp/.hidden #malware"
factum --list-cases [--all]
factum --set-active case 1              # by ID, file number or name; clears the active evidence
factum --list-evidence                  # evidence of the active case
factum --set-active evidence none       # notes go to the case itself again
factum --verify [case] [-v]             # exit code 1 if verification fails
factum --checkpoint [case]              # seal the current state
factum --sign-unsigned [case]           # sign entries and seals created without a key
factum --export [case] --format html,pdf,md,bundle --out ./reports
factum --list-gpg
factum --set-active gpg <key-id>
factum --log-level DEBUG --list-cases
```

Without a case argument, `--verify`, `--checkpoint`, `--sign-unsigned` and `--export` use the active case. Archiving,
reopening and permanent deletion are only available in the GUI, so the typed confirmation cannot be scripted away.
Notes are added to the active evidence item if one is set, otherwise to the active case. Both can also be set from the
GUI (right-click a case or evidence item → Set as CLI Active).

**GUI** (`factum --gui`):
- Case/evidence tree with note counts; note cards with pinning, history, tags and labels; search (free text, or
  `#tag` for tags only)
- Note and whole-case verification, seals, signing later, archiving, corrections, export
- Pinned notes and IoC panel (toggle with Ctrl+B)
- Live sync between CLI and GUI: notes added on the command line appear in the open window
- Light and dark theme (View → Theme, follows the system by default)
- Keyboard shortcuts (Help → Keyboard Shortcuts, F1): Ctrl+Enter adds the note, Ctrl+F searches, Ctrl+N creates a
  case, P pins the clicked note

The interface is designed for long, focused sessions: dark text on an off-white background by default (better reading
performance than dark mode in normal lighting), a dark theme for dim rooms, a neutral palette with one accent color,
color-blind-safe status colors that always come with a symbol (✓ ⚠ ✗), [Atkinson Hyperlegible Next](https://www.brailleinstitute.org/freefont/)
for text and [JetBrains Mono](https://www.jetbrains.com/lp/mono/) for hashes, timestamps and IoCs. Both fonts are
embedded (SIL Open Font License).

## Storage

SQLite database in WAL mode for concurrent CLI and GUI access. The location does not depend on the folder you run
`factum` from:

| OS      | Default database location                                       |
|---------|-----------------------------------------------------------------|
| Linux   | `~/.local/share/factum/factum.db` (or `$XDG_DATA_HOME/factum/`) |
| macOS   | `~/Library/Application Support/factum/factum.db`               |
| Windows | `%LOCALAPPDATA%\factum\factum.db`                               |

Set `FACTUM_DB` to use a different file, e.g. one database per engagement or on an encrypted volume. Databases of
schema 3 (factum up to 2.1 and the current factum-notes) are upgraded in place to schema 4 on first open (it adds the
evidence description); factum-notes cannot open them afterwards. Databases of older factum versions are refused and
never modified — set `FACTUM_DB` to a new file.

## Configuration

Optional settings are read from a `.env` file in the user config directory (Linux: `~/.config/factum/.env`, macOS:
`~/Library/Application Support/factum/.env`, Windows: `%LOCALAPPDATA%\factum\.env`), then from `.env` in the current
directory; real environment variables override both. See [.env.example](.env.example).

| Variable                   | Meaning                                                                                       |
|----------------------------|-----------------------------------------------------------------------------------------------|
| `LOG_LEVEL`                | `DEBUG`, `INFO` (default), `WARNING`, `ERROR`, `CRITICAL`; `--log-level` overrides it         |
| `FACTUM_DB`                | Path of the database file                                                                     |
| `FACTUM_SEAL_DIR`          | Folder for external seal copies; must already exist (default: GUI setting, else `seals/` next to the database) |
| `FACTUM_COMPANION_API_KEY` | API key of the analytical companion; overrides the stored key                                 |

A launcher (application menu, Start menu) does not read `.env` from a working directory: put settings in the user
config directory.

## What the integrity checks protect against

- **Changed, inserted, reordered or removed entries** anywhere before the newest signed entry: every later
  signature breaks.
- **Removed entries at the end of the log**: detected by any seal that covers them, as long as a copy of that seal
  exists outside the database (seal folder, exported bundle). Entries added after the newest seal are only protected
  by their own signatures, so seal regularly (`--checkpoint`, "Seal Now").
- **Changed case or evidence details** (including the evidence hash): compared against the signed system entries.
- Not protected: labels and pins (organisational only), and anything done by someone who holds the signing key and
  rewrites the whole log *and* every external seal copy.
- Permanent deletion removes the case's rows from the database; SQLite may keep the freed pages until they are reused,
  so treat the database file itself as sensitive.

## Building from source

```bash
git clone https://github.com/overcuriousity/factum-rs && cd factum-rs
cargo build --release                         # target/release/factum, GUI + CLI
cargo build --release --no-default-features   # command line only, no GUI dependencies
cargo test
```

Requires Rust 1.95 or newer. On Linux no development packages are needed: SQLite is compiled in, and OpenGL,
X11 and Wayland are loaded at runtime. `cargo run --example demo_db` fills a database (`FACTUM_DB`) with a demo case.
GUI screenshots for review: `FACTUM_SCREENSHOTS=/tmp/shots cargo test --lib gui::` (needs a GPU or Mesa's lavapipe).

Releases: `scripts/release.sh 2.0.1 && git push origin HEAD v2.0.1` — the release workflow builds and publishes
everything. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

BSD-3-Clause. The embedded fonts are licensed under the SIL Open Font License 1.1 (see `assets/fonts/`).
