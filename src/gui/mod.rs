//! The desktop GUI (`factum --gui`): case tree on the left, the case log in the middle, pinned notes and IoCs on
//! the right. Everything shown is cached in a [`View`] that is rebuilt after every change, so drawing a frame
//! never queries the database.

mod dialogs;
mod theme;
mod widgets;
mod workers;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use egui::{Align, Key, KeyboardShortcut, Layout, Margin, Modifiers, RichText, TextEdit};

use crate::cases::Case;
use crate::db::Db;
use crate::error::{ErrorKind, FactumError, Result};
use crate::evidence::Evidence;
use crate::notes::{Entry, EntryFilter};
use crate::pystr::{strip, tail};
use crate::seals::{REASON_CHECKPOINT, SEAL_DIR_SETTING};
use crate::services::Factum;
use crate::signer::{ACTIVE_KEY_SETTING, GnupgSigner, Signer};
use crate::verifier::{CaseReport, SignatureCheck};
use dialogs::{Dialog, DialogResult, NoGpgChoice, Pending, VerifyAction, VerifyWindow};
use theme::{SMALL_SIZE, THEMES};
use widgets::{Card, CardAction, CardView, CheckView};

// GUI preferences, stored next to the other settings in the database
const THEME_SETTING: &str = "ui_theme";
const SIDE_PANEL_VISIBLE_SETTING: &str = "ui_side_panel_visible";
const SIDE_PANEL_WIDTH_SETTING: &str = "ui_side_panel_width";
const EXPORT_DIR_SETTING: &str = "export_dir";
const DEFAULT_SIDE_PANEL_WIDTH: f32 = 340.0;
const NOTE_PLACEHOLDER: &str = "Write a note. It is time-stamped when added; use #tags to categorize.";
const ICON: &[u8] = include_bytes!("../../assets/icon.png");

const fn shortcut(modifiers: Modifiers, key: Key) -> KeyboardShortcut {
    KeyboardShortcut::new(modifiers, key)
}

const CTRL_SHIFT: Modifiers = Modifiers {
    shift: true,
    ..Modifiers::COMMAND
};
const ADD_NOTE: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::Enter);
const EXPORT: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::E);
const QUIT: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::Q);
const NEW_CASE: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::N);
const NEW_EVIDENCE: KeyboardShortcut = shortcut(CTRL_SHIFT, Key::N);
const VERIFY_CASE: KeyboardShortcut = shortcut(CTRL_SHIFT, Key::V);
const SEARCH: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::F);
const WRITE_NOTE: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::L);
const SHOW_SYSTEM: KeyboardShortcut = shortcut(CTRL_SHIFT, Key::S);
const SIDE_PANEL: KeyboardShortcut = shortcut(Modifiers::COMMAND, Key::B);
const HELP: KeyboardShortcut = shortcut(Modifiers::NONE, Key::F1);

pub fn run(db: Db) -> std::result::Result<(), String> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Factum")
        .with_app_id("factum") // on Wayland the window gets the icon of the factum.desktop launcher
        .with_inner_size([1180.0, 820.0])
        .with_min_inner_size([900.0, 560.0]);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(ICON) {
        viewport = viewport.with_icon(Arc::new(icon));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "factum",
        options,
        Box::new(|creation| {
            theme::install_fonts(&creation.egui_ctx);
            Ok(Box::new(FactumApp::new(db, &creation.egui_ctx)))
        }),
    )
    .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SideTab {
    Pinned,
    Iocs,
}

struct CaseNode {
    case: Case,
    notes: usize,
    evidence: Vec<(Evidence, usize)>,
}

enum Item {
    Note(Card),
    System(Entry),
}

impl Item {
    fn entry(&self) -> &Entry {
        match self {
            Item::Note(card) => &card.entry,
            Item::System(entry) => entry,
        }
    }
}

/// Everything the window shows, read from the database in one go.
#[derive(Default)]
struct View {
    tree: Vec<CaseNode>,
    /// the case of the selection, and the evidence if evidence is selected
    case: Option<Case>,
    evidence: Option<Evidence>,
    evidence_deletable: bool,
    items: Vec<Item>,
    empty_text: Option<String>,
    note_count: String,
    pinned: Vec<Card>,
    pinned_empty_text: Option<String>,
    iocs: BTreeMap<String, Vec<String>>,
    cli_active: String,
}

struct VerifyJob {
    worker: workers::Worker<workers::VerifyResult>,
    progress: Arc<workers::Progress>,
    started: Instant,
}

struct FactumApp {
    db: Db,
    // one signing service for everything, so the active key and the pinentry state are shared
    signer: GnupgSigner,
    env_seal_dir: Option<PathBuf>,
    // what is selected in the tree; when evidence is selected, case_id is None (like the case tree items)
    case_id: Option<i64>,
    evidence_id: Option<i64>,
    filter: String,
    pinned_scope_evidence: bool,
    show_archived: bool,
    show_system: bool,
    theme: String,
    side_panel: bool,
    side_tab: SideTab,
    side_width: f32,
    composer: String,
    view: View,
    dirty: bool,
    focused_card: Option<i64>,
    history_open: HashSet<i64>,
    scroll_to: Option<i64>,
    // signature checks of the entries shown, for this session: a card shows ✓ only after its check
    signature_checks: HashMap<i64, SignatureCheck>,
    signature_worker: Option<workers::Worker<workers::SignatureChecks>>,
    signature_check_pending: bool,
    verify_job: Option<VerifyJob>,
    dialogs: Vec<Dialog>,
    verify_windows: Vec<VerifyWindow>,
    next_window_id: u64,
    gpg_help_prompted: bool,
    // asked once per GUI session before sealing without a key
    no_gpg_key_prompted: bool,
    // a seal or export that waits for the key dialog ("Configure…")
    after_key_dialog: Option<Pending>,
    data_version: i64,
    last_poll: Instant,
    focus_search: bool,
    focus_composer: bool,
    gpg_status: (String, bool),
}

impl FactumApp {
    fn new(db: Db, ctx: &egui::Context) -> Self {
        let signer = GnupgSigner::new(&db, None);
        let setting = |key: &str| db.get_setting(key).unwrap_or_default();
        let mut theme = setting(THEME_SETTING);
        if !THEMES.contains(&theme.as_str()) {
            theme = "system".into();
        }
        let side_panel = setting(SIDE_PANEL_VISIBLE_SETTING) != "0";
        let side_width = setting(SIDE_PANEL_WIDTH_SETTING)
            .parse()
            .unwrap_or(DEFAULT_SIDE_PANEL_WIDTH);
        theme::apply(ctx, &theme);
        let data_version = db.data_version().unwrap_or_default();
        let mut app = Self {
            db,
            signer,
            env_seal_dir: crate::config::settings().seal_dir.clone(),
            case_id: None,
            evidence_id: None,
            filter: String::new(),
            pinned_scope_evidence: false,
            show_archived: false,
            show_system: true,
            theme,
            side_panel,
            side_tab: SideTab::Pinned,
            side_width,
            composer: String::new(),
            view: View::default(),
            dirty: true,
            focused_card: None,
            history_open: HashSet::new(),
            scroll_to: None,
            signature_checks: HashMap::new(),
            signature_worker: None,
            signature_check_pending: false,
            verify_job: None,
            dialogs: Vec::new(),
            verify_windows: Vec::new(),
            next_window_id: 0,
            gpg_help_prompted: false,
            no_gpg_key_prompted: false,
            after_key_dialog: None,
            data_version,
            last_poll: Instant::now(),
            focus_search: false,
            focus_composer: false,
            gpg_status: (String::new(), false),
        };
        // pre-select the CLI active case or evidence so notes are shown on startup
        let factum = app.factum();
        if let Ok(Some(evidence_id)) = factum.get_active_evidence_id() {
            app.evidence_id = Some(evidence_id);
        } else if let Ok(Some(case_id)) = factum.get_active_case_id() {
            app.case_id = Some(case_id);
        }
        app.update_gpg_status();
        app
    }

    fn factum(&self) -> Factum<'_> {
        Factum {
            db: &self.db,
            signer: &self.signer,
            seal_dir_override: None,
            env_seal_dir: self.env_seal_dir.clone(),
        }
    }

    fn update_gpg_status(&mut self) {
        self.gpg_status = if !self.signer.available() {
            ("GPG not installed".into(), true)
        } else if let Some(key) = self.signer.active_key() {
            (tail(&key, 8).to_string(), false)
        } else {
            ("Not configured".into(), true)
        };
    }

    fn current_case_id(&self) -> Option<i64> {
        if self.case_id.is_some() {
            return self.case_id;
        }
        let evidence_id = self.evidence_id?;
        self.factum()
            .get_evidence(evidence_id)
            .ok()
            .flatten()
            .map(|e| e.case_id)
    }

    fn tag_and_search(&self) -> (Option<String>, Option<String>) {
        let cleaned = strip(&self.filter);
        if cleaned.starts_with('#') {
            let tag = cleaned.trim_start_matches('#');
            ((!tag.is_empty()).then(|| tag.to_string()), None)
        } else {
            (None, (!cleaned.is_empty()).then(|| cleaned.to_string()))
        }
    }

    // ---- reading the database into the view

    fn rebuild(&mut self, ctx: &egui::Context) {
        self.dirty = false;
        match self.read_view() {
            Ok(view) => self.view = view,
            Err(e) => log::error!("Failed to populate the window: {e}"),
        }
        self.check_shown_signatures(ctx);
    }

    fn card(&self, factum: &Factum, entry: Entry, case: &Case) -> Result<Card> {
        let evidence = match entry.evidence_id {
            Some(id) => factum.get_evidence(id)?,
            None => None,
        };
        let mut history = Vec::new();
        let versions = factum.history(entry.id)?;
        for id in &versions[..versions.len() - 1] {
            if let Some(old) = factum.get_entry(*id)? {
                history.push(old);
            }
        }
        Ok(Card {
            tags: crate::tags::get_tags_for_entry(&self.db.conn, entry.id)?,
            history,
            // the card names its evidence only when the view does not already say it
            evidence: evidence
                .filter(|e| Some(e.id) != self.evidence_id)
                .map(|e| e.description),
            archived: case.is_archived(),
            entry,
        })
    }

    fn read_view(&self) -> Result<View> {
        let factum = self.factum();
        let mut view = View::default();
        for case_id in factum.list_cases(self.show_archived)? {
            let Some(case) = factum.get_case(case_id)? else {
                continue;
            };
            let notes = factum.list_entries(case_id, &EntryFilter::notes())?.len();
            let mut evidence = Vec::new();
            for evidence_id in factum.list_evidence_for_case(case_id, false)? {
                if let Some(item) = factum.get_evidence(evidence_id)? {
                    let filter = EntryFilter {
                        evidence_id: Some(evidence_id),
                        ..EntryFilter::notes()
                    };
                    evidence.push((item, factum.list_entries(case_id, &filter)?.len()));
                }
            }
            view.tree.push(CaseNode { case, notes, evidence });
        }
        let case_id = self.current_case_id();
        view.case = match case_id {
            Some(id) => factum.get_case(id)?,
            None => None,
        };
        view.evidence = match self.evidence_id {
            Some(id) => factum.get_evidence(id)?,
            None => None,
        };
        view.evidence_deletable = match (&view.evidence, &view.case) {
            (Some(evidence), Some(case)) => !case.is_archived() && !factum.has_entries(evidence.id)?,
            _ => false,
        };
        let (tag, search) = self.tag_and_search();
        if let Some(case) = view.case.clone() {
            let filter = EntryFilter {
                evidence_id: self.evidence_id,
                tag: tag.as_deref(),
                include_system: self.show_system,
                pinned_only: false,
                search: search.as_deref(),
            };
            let entry_ids = factum.list_entries(case.id, &filter)?;
            if entry_ids.is_empty() {
                view.empty_text = Some(if let Some(tag) = &tag {
                    format!("No notes with a tag matching '{tag}'.")
                } else if let Some(search) = &search {
                    format!("No entries match '{search}'.")
                } else {
                    "No notes yet.\nWrite your first observation below; it is time-stamped when you add it.".into()
                });
            }
            for entry_id in entry_ids.iter().rev() {
                // newest first
                let Some(entry) = factum.get_entry(*entry_id)? else {
                    continue;
                };
                view.items.push(if entry.is_note() {
                    Item::Note(self.card(&factum, entry, &case)?)
                } else {
                    Item::System(entry)
                });
            }
            let notes = view.items.iter().filter(|item| matches!(item, Item::Note(_))).count();
            let mut text = format!("{notes} note{}", if notes == 1 { "" } else { "s" });
            if !self.show_system && tag.is_none() {
                // system entries are numbered like notes: say how many are hidden, so gaps in the numbers make sense
                let all = factum
                    .list_entries(
                        case.id,
                        &EntryFilter {
                            include_system: true,
                            ..filter.clone()
                        },
                    )?
                    .len();
                let hidden = all - notes;
                if hidden > 0 {
                    text += &format!(" · {hidden} system hidden");
                }
            } else if view.items.len() > notes {
                text += &format!(" · {} system", view.items.len() - notes);
            }
            view.note_count = text;
            let pinned_ids = if !self.pinned_scope_evidence {
                factum.list_entries(
                    case.id,
                    &EntryFilter {
                        pinned_only: true,
                        ..Default::default()
                    },
                )?
            } else if let Some(evidence_id) = self.evidence_id {
                factum.list_entries(
                    case.id,
                    &EntryFilter {
                        pinned_only: true,
                        evidence_id: Some(evidence_id),
                        ..Default::default()
                    },
                )?
            } else {
                Vec::new()
            };
            for entry_id in pinned_ids.iter().rev() {
                if let Some(entry) = factum.get_entry(*entry_id)? {
                    view.pinned.push(self.card(&factum, entry, &case)?);
                }
            }
        } else {
            view.empty_text = Some(if view.tree.is_empty() {
                "No cases yet.\nCreate your first case with + New Case (Ctrl+N).".into()
            } else {
                "Select a case or evidence on the left to see its notes.".into()
            });
        }
        if view.pinned.is_empty() {
            view.pinned_empty_text = Some(if self.pinned_scope_evidence && self.evidence_id.is_none() {
                "Select an evidence item to see its pinned notes.".into()
            } else {
                "No pinned notes yet.\nHover a note and click Pin, or click the note and press P.".into()
            });
        }
        view.iocs = if let Some(evidence_id) = self.evidence_id {
            crate::iocs::get_iocs_for_evidence(&self.db.conn, evidence_id)?
        } else if let Some(case_id) = self.case_id {
            crate::iocs::get_iocs_for_case(&self.db.conn, case_id)?
        } else {
            BTreeMap::new()
        };
        let mut parts = Vec::new();
        if let Some(case) = factum
            .get_active_case_id()?
            .and_then(|id| factum.get_case(id).ok().flatten())
        {
            parts.push(format!("Case: {}", case.case_name));
        }
        if let Some(evidence) = factum
            .get_active_evidence_id()?
            .and_then(|id| factum.get_evidence(id).ok().flatten())
        {
            parts.push(format!("Evid: {}", evidence.description));
        }
        view.cli_active = parts.join("  /  ");
        Ok(view)
    }

    /// Checks the signatures of the shown entries in the background; the cards update when it is done.
    fn check_shown_signatures(&mut self, ctx: &egui::Context) {
        let Some(case_id) = self.current_case_id() else { return };
        if !self.signer.available() {
            return;
        }
        if self.signature_worker.as_ref().is_some_and(|w| w.is_running()) {
            self.signature_check_pending = true; // checked when the running check is done
            return;
        }
        let entry_ids: HashSet<i64> = self
            .view
            .items
            .iter()
            .map(Item::entry)
            .chain(self.view.pinned.iter().map(|card| &card.entry))
            .filter(|entry| entry.is_signed() && !self.signature_checks.contains_key(&entry.id))
            .map(|entry| entry.id)
            .collect();
        if entry_ids.is_empty() {
            return;
        }
        self.signature_worker = Some(workers::check_signatures(
            ctx,
            self.db.path.clone(),
            self.signer.gpg_home(),
            case_id,
            entry_ids,
        ));
    }

    fn check_view(&self, entry: &Entry) -> CheckView<'_> {
        if !self.signer.available() {
            return CheckView::Unchecked;
        }
        match self.signature_checks.get(&entry.id) {
            Some(check) => CheckView::Done(check),
            None => CheckView::Pending,
        }
    }

    // ---- background work and external changes

    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(worker) = self.signature_worker.as_mut()
            && let Some(checks) = worker.poll()
        {
            self.signature_checks.extend(checks);
            self.signature_worker = None;
            if std::mem::take(&mut self.signature_check_pending) {
                self.check_shown_signatures(ctx);
            }
        }
        if let Some(job) = self.verify_job.as_mut()
            && let Some(result) = job.worker.poll()
        {
            self.verify_job = None;
            match result {
                Ok(report) => self.show_case_report(report),
                Err(message) => self.message("Factum", format!("Verification failed: {message}")),
            }
        }
        // notes added on the command line appear here: data_version only moves on commits of other connections
        if self.last_poll.elapsed() >= Duration::from_millis(750) {
            self.last_poll = Instant::now();
            if let Ok(version) = self.db.data_version()
                && version != self.data_version
            {
                self.data_version = version;
                self.dirty = true;
            }
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    // ---- running actions

    fn message(&mut self, title: &str, text: impl Into<String>) {
        self.dialogs.push(Dialog::Message {
            title: title.into(),
            text: text.into(),
        });
    }

    /// Runs a service call; user-facing errors become a message box.
    fn run<T>(&mut self, result: Result<T>) -> Option<T> {
        self.dirty = true;
        match result {
            Ok(value) => Some(value),
            Err(e) if e.is(ErrorKind::Signing) && self.signer.last_sign_failed() && !self.gpg_help_prompted => {
                self.gpg_help_prompted = true;
                self.dialogs.push(Dialog::GpgHelp);
                None
            }
            Err(e) if e.is(ErrorKind::Internal) => {
                log::error!("Unexpected error: {e}");
                self.message("Factum", format!("Unexpected error: {e}"));
                None
            }
            Err(e) => {
                self.message("Factum", e.to_string());
                None
            }
        }
    }

    fn select(&mut self, case_id: Option<i64>, evidence_id: Option<i64>) {
        if (self.case_id, self.evidence_id) != (case_id, evidence_id) {
            self.case_id = case_id;
            self.evidence_id = evidence_id;
            self.focused_card = None;
            self.dirty = true;
        }
    }

    /// Before sealing without a key, ask once per GUI session whether to configure one.
    fn with_key_check(&mut self, then: Pending) {
        if self.signer.active_key().is_some() || self.no_gpg_key_prompted {
            self.carry_out(then);
            return;
        }
        self.no_gpg_key_prompted = true;
        self.dialogs.push(Dialog::NoGpgKey { then });
    }

    fn carry_out(&mut self, pending: Pending) {
        match pending {
            Pending::Archive(case_id) => {
                let result = self.factum().archive_case(case_id);
                self.run(result); // the case is archived even when sealing failed
                self.select(None, None);
            }
            Pending::DeleteEvidence(evidence_id) => {
                let result = self.factum().delete_evidence(evidence_id);
                self.run(result);
                self.select(None, None);
            }
            Pending::Seal(case_id) => {
                let result = self.factum().seal(case_id, REASON_CHECKPOINT).and_then(|id| {
                    self.factum()
                        .get_tree_head(id)?
                        .ok_or_else(|| FactumError::general("The seal is missing."))
                });
                if let Some(head) = self.run(result) {
                    let unsigned = if head.signature.is_some() {
                        ""
                    } else {
                        "\nThe seal is unsigned — sign it later with 'Sign All Unsigned'."
                    };
                    self.message(
                        "Seal created",
                        format!(
                            "Seal #{} covers {} entries.\nExternal copy: {}{unsigned}",
                            head.id,
                            head.tree_size,
                            head.file_path.unwrap_or_default()
                        ),
                    );
                }
            }
            Pending::Export {
                case_id,
                formats,
                folder,
            } => {
                let formats: Vec<&str> = formats.iter().map(String::as_str).collect();
                let result = self.factum().export(case_id, &formats, &PathBuf::from(&folder));
                if let Some(paths) = self.run(result) {
                    let _ = self.db.set_setting(EXPORT_DIR_SETTING, &folder);
                    let written: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
                    self.message("Export finished", format!("Written:\n{}", written.join("\n")));
                }
            }
        }
    }

    fn open_new_case(&mut self) {
        self.dialogs.push(Dialog::NewCase {
            file: String::new(),
            name: String::new(),
            description: String::new(),
            error: None,
        });
    }

    fn open_new_evidence(&mut self) {
        // evidence goes into the selected case, or into the case of the selected evidence
        if let Some(case) = self.view.case.as_ref().filter(|c| !c.is_archived()) {
            self.dialogs.push(Dialog::NewEvidence {
                case_id: case.id,
                description: String::new(),
                hash: String::new(),
                error: None,
            });
        }
    }

    fn open_edit_case(&mut self, case_id: i64) {
        if let Ok(Some(case)) = self.factum().get_case(case_id) {
            self.dialogs.push(Dialog::EditCase {
                case_id,
                file: case.case_file,
                name: case.case_name,
                description: case.description,
                error: None,
            });
        }
    }

    fn open_gpg_keys(&mut self) {
        let keys = self.signer.list_keys();
        self.dialogs.push(Dialog::GpgKeys {
            keys,
            selected: self.signer.active_key(),
        });
    }

    fn verify_case(&mut self, ctx: &egui::Context, case_id: i64) {
        if self.verify_job.as_ref().is_some_and(|job| job.worker.is_running()) {
            self.message("Factum", "A verification is already running.");
            return;
        }
        let (worker, progress) = workers::verify_case(ctx, self.db.path.clone(), self.signer.gpg_home(), case_id);
        self.verify_job = Some(VerifyJob {
            worker,
            progress,
            started: Instant::now(),
        });
    }

    fn show_case_report(&mut self, report: CaseReport) {
        for result in &report.entries {
            if result.signature.present {
                self.signature_checks.insert(result.entry.id, result.signature.clone());
            }
        }
        self.next_window_id += 1;
        self.verify_windows.push(VerifyWindow {
            id: self.next_window_id,
            report,
            open: true,
        });
    }

    fn archive(&mut self, case_id: i64) {
        let Ok(Some(case)) = self.factum().get_case(case_id) else {
            return;
        };
        self.dialogs.push(Dialog::Confirm {
            message: format!(
                "Archive the case '{}'? It becomes read-only and a seal is created. You can reopen it later.",
                case.case_name
            ),
            then: Pending::Archive(case_id),
        });
    }

    fn delete_case(&mut self, case_id: i64) {
        let Ok(Some(case)) = self.factum().get_case(case_id) else {
            return;
        };
        self.dialogs.push(Dialog::TypedConfirm {
            case_id,
            message: format!(
                "Permanently delete the archived case '{}' with all its evidence, notes and seals from the database? \
                 External seal files are kept. This cannot be undone.\n\nType the case file number '{}' to confirm:",
                case.case_name, case.case_file
            ),
            expected: case.case_file,
            typed: String::new(),
        });
    }

    fn delete_evidence(&mut self, evidence_id: i64) {
        let Ok(Some(evidence)) = self.factum().get_evidence(evidence_id) else {
            return;
        };
        self.dialogs.push(Dialog::Confirm {
            message: format!(
                "Delete the empty evidence item '{}'? A deletion entry is added to the case log.",
                evidence.description
            ),
            then: Pending::DeleteEvidence(evidence_id),
        });
    }

    fn export(&mut self, case_id: i64) {
        let folder = Some(self.db.get_setting(EXPORT_DIR_SETTING).unwrap_or_default())
            .filter(|f| !f.is_empty())
            .or_else(|| dirs::home_dir().map(|h| h.display().to_string()))
            .unwrap_or_default();
        self.dialogs.push(Dialog::Export {
            case_id,
            formats: [false, false, false, true],
            folder,
            error: None,
        });
    }

    fn sign_all_unsigned(&mut self, case_id: i64) {
        let result = self.factum().sign_all_unsigned(case_id);
        if let Some(count) = self.run(result) {
            self.message("Factum", format!("Signed {count} item(s)."));
        }
    }

    fn set_cli_active_case(&mut self, case_id: i64) {
        let result = self.factum().set_active_case(case_id);
        self.run(result);
    }

    fn set_cli_active_evidence(&mut self, evidence_id: i64) {
        let result = self.factum().set_active_evidence(Some(evidence_id));
        self.run(result);
    }

    fn submit_note(&mut self) {
        let Some(case) = self.view.case.clone().filter(|c| !c.is_archived()) else {
            return;
        };
        let text = strip(&self.composer).to_string();
        if text.is_empty() {
            return;
        }
        let result = self.factum().create_note(&text, self.evidence_id, case.id);
        if self.run(result).is_some() {
            self.composer.clear();
        }
    }

    fn jump_to_entry(&mut self, entry_id: i64) {
        let factum = self.factum();
        let Ok(Some(entry)) = factum.latest_version_id(entry_id).and_then(|id| factum.get_entry(id)) else {
            return;
        };
        let archived = factum
            .get_case(entry.case_id)
            .ok()
            .flatten()
            .is_some_and(|c| c.is_archived());
        if !entry.is_note() {
            self.show_system = true;
        }
        if archived {
            self.show_archived = true; // the case may be archived and hidden
        }
        self.filter.clear();
        self.select(Some(entry.case_id), None);
        self.dirty = true;
        self.scroll_to = Some(entry.id);
        self.focused_card = Some(entry.id);
    }

    fn handle_card_action(&mut self, action: CardAction, ctx: &egui::Context) {
        match action {
            CardAction::TogglePin(entry_id) => {
                let result = self.factum().get_entry(entry_id).and_then(|entry| match entry {
                    Some(entry) => self.factum().set_pinned(entry_id, !entry.is_pinned),
                    None => Ok(()),
                });
                self.run(result);
            }
            CardAction::AddLabel(entry_id) => self.dialogs.push(Dialog::AddLabel {
                entry_id,
                label: String::new(),
            }),
            CardAction::RemoveLabel(entry_id, label) => {
                let result = crate::tags::remove_label(&self.db, entry_id, &label);
                self.run(result);
            }
            CardAction::Correct(entry_id) => {
                let factum = self.factum();
                if let Ok(Some(newest)) = factum.latest_version_id(entry_id).and_then(|id| factum.get_entry(id)) {
                    self.dialogs.push(Dialog::Correct {
                        entry_id: newest.id,
                        original: newest.text.clone(),
                        text: newest.text,
                    });
                }
            }
            CardAction::CopySignature(entry_id) => match self.factum().get_entry(entry_id) {
                Ok(Some(entry)) if entry.any_signature().is_some() => {
                    ctx.copy_text(entry.any_signature().unwrap_or_default().to_string());
                    log::info!("GPG clearsigned block copied to clipboard.");
                }
                _ => log::warn!("No GPG signature found."),
            },
            CardAction::Sign(entry_id) => {
                let result = self.factum().sign_entry(entry_id);
                if self.run(result).is_some() {
                    self.signature_checks.remove(&entry_id);
                }
            }
            CardAction::Verify(entry_id) => {
                let result = self.factum().verify_entry(entry_id);
                if let Some(result) = self.run(result) {
                    if result.signature.present {
                        self.signature_checks.insert(entry_id, result.signature.clone());
                    }
                    self.dialogs.push(Dialog::VerifyEntry {
                        result: Box::new(result),
                    });
                }
                self.dirty = false; // verifying changes nothing
            }
            CardAction::Focus(entry_id) => self.focused_card = Some(entry_id),
            CardAction::ToggleHistory(entry_id) => {
                if !self.history_open.remove(&entry_id) {
                    self.history_open.insert(entry_id);
                }
            }
        }
    }

    fn handle_dialog_result(&mut self, result: DialogResult) {
        match result {
            DialogResult::Cancel => {}
            DialogResult::NewCase {
                file,
                name,
                description,
            } => {
                let result = self.factum().create_case(&file, &name, &description);
                if let Some(case_id) = self.run(result) {
                    self.select(Some(case_id), None);
                }
            }
            DialogResult::NewEvidence {
                case_id,
                description,
                hash,
            } => {
                let result = self.factum().create_evidence(case_id, &description, &hash);
                if let Some(evidence_id) = self.run(result) {
                    self.select(None, Some(evidence_id));
                }
            }
            DialogResult::EditCase {
                case_id,
                file,
                name,
                description,
            } => {
                let result = self.factum().update_case(case_id, &file, &name, &description);
                self.run(result);
            }
            DialogResult::AddLabel { entry_id, label } => {
                let result = crate::tags::add_label(&self.db, entry_id, &label);
                self.run(result);
            }
            DialogResult::Confirmed(Pending::Archive(case_id)) => self.with_key_check(Pending::Archive(case_id)),
            DialogResult::Confirmed(pending) => self.carry_out(pending),
            DialogResult::TypedConfirmed { case_id, typed } => {
                let result = self.factum().delete_case_permanently(case_id, &typed);
                self.run(result);
                self.select(None, None);
            }
            DialogResult::Correct { entry_id, text } => {
                let result = self.factum().correct_note(entry_id, &text);
                self.run(result);
            }
            DialogResult::Export {
                case_id,
                formats,
                folder,
            } => self.with_key_check(Pending::Export {
                case_id,
                formats,
                folder,
            }),
            DialogResult::KeySelected(key_id) => {
                if self.signer.set_active_key(&self.db, &key_id) {
                    self.update_gpg_status();
                }
                if let Some(pending) = self.after_key_dialog.take() {
                    self.carry_out(pending);
                }
            }
            DialogResult::NoGpg(choice, pending) => match choice {
                NoGpgChoice::Configure => {
                    self.after_key_dialog = Some(pending);
                    self.open_gpg_keys();
                }
                NoGpgChoice::Continue => self.carry_out(pending),
                NoGpgChoice::Cancel => {}
            },
            DialogResult::SealFolder(folder) => {
                let _ = self.db.set_setting(SEAL_DIR_SETTING, &folder);
            }
        }
    }

    fn choose_seal_folder(&mut self) {
        if let Some(dir) = &self.env_seal_dir {
            let text = format!(
                "FACTUM_SEAL_DIR is set to {}; it overrides this setting.",
                dir.display()
            );
            self.message("Seal folder", text);
            return;
        }
        let folder = self.factum().seal_dir().display().to_string();
        self.dialogs.push(Dialog::SealFolder { folder });
    }

    fn set_theme(&mut self, ctx: &egui::Context, theme: &str) {
        self.theme = theme.to_string();
        theme::apply(ctx, theme);
        if self.db.get_setting(THEME_SETTING).unwrap_or_default() != theme {
            let _ = self.db.set_setting(THEME_SETTING, theme);
        }
    }

    fn shortcut_rows(&self, ctx: &egui::Context) -> Vec<(String, String)> {
        let keys = |s: &KeyboardShortcut| ctx.format_shortcut(s);
        let mut rows = vec![(keys(&ADD_NOTE), "Add the note".to_string())];
        for (shortcut, text) in [
            (WRITE_NOTE, "Write a Note"),
            (SEARCH, "Search Notes"),
            (NEW_CASE, "New Case"),
            (NEW_EVIDENCE, "New Evidence"),
            (VERIFY_CASE, "Verify Case"),
            (EXPORT, "Export Case"),
            (SHOW_SYSTEM, "Show System Entries"),
            (SIDE_PANEL, "Side Panel (Pinned Notes, IoCs)"),
            (HELP, "Keyboard Shortcuts"),
            (QUIT, "Quit"),
        ] {
            rows.push((keys(&shortcut), text.to_string()));
        }
        rows.push(("P".into(), "Pin or unpin the clicked note".into()));
        rows.push((
            "Right-click".into(),
            "More actions on a note, a case or evidence".into(),
        ));
        rows
    }

    fn save_layout(&self) {
        let _ = self
            .db
            .set_setting(SIDE_PANEL_VISIBLE_SETTING, if self.side_panel { "1" } else { "0" });
        if self.side_panel {
            let _ = self
                .db
                .set_setting(SIDE_PANEL_WIDTH_SETTING, &format!("{:.0}", self.side_width));
        }
    }

    fn quit(&mut self) {
        // a running verification is not torn down: let it finish first
        if let Some(job) = self.verify_job.as_mut() {
            job.worker.wait();
        }
        if let Some(worker) = self.signature_worker.as_mut() {
            worker.wait();
        }
        self.save_layout();
    }

    // ---- keyboard

    fn shortcuts(&mut self, ctx: &egui::Context) {
        if !self.dialogs.is_empty() {
            return;
        }
        let composer_focused = ctx.memory(|m| m.has_focus(egui::Id::unique("composer")));
        let pressed = |s: KeyboardShortcut| ctx.input_mut(|i| i.consume_shortcut(&s));
        if composer_focused && pressed(ADD_NOTE) {
            self.submit_note();
        }
        // shift variants first: a pattern without shift also matches with shift pressed
        if pressed(NEW_EVIDENCE) {
            self.open_new_evidence();
        } else if pressed(NEW_CASE) {
            self.open_new_case();
        }
        if pressed(VERIFY_CASE)
            && let Some(case_id) = self.current_case_id()
        {
            self.verify_case(ctx, case_id);
        }
        if pressed(SHOW_SYSTEM) {
            self.show_system = !self.show_system;
            self.dirty = true;
        }
        if pressed(EXPORT)
            && let Some(case_id) = self.current_case_id()
        {
            self.export(case_id);
        }
        if pressed(QUIT) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if pressed(SEARCH) {
            self.focus_search = true;
        }
        if pressed(WRITE_NOTE) {
            self.focus_composer = true;
        }
        if pressed(SIDE_PANEL) {
            self.side_panel = !self.side_panel;
        }
        if pressed(HELP) {
            let rows = self.shortcut_rows(ctx);
            self.dialogs.push(Dialog::Shortcuts { rows });
        }
        // P pins the clicked note, unless a text field has the keyboard
        let typing = ctx.memory(|m| m.focused().is_some());
        if !typing
            && ctx.input(|i| i.key_pressed(Key::P) && i.modifiers.is_none())
            && let Some(entry_id) = self.focused_card
        {
            let archived = self.view.case.as_ref().is_some_and(|c| c.is_archived());
            if !archived {
                self.handle_card_action(CardAction::TogglePin(entry_id), ctx);
            }
        }
    }

    // ---- drawing

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let case_id = self.current_case_id();
        let case = self.view.case.clone();
        let is_open = case.as_ref().is_some_and(|c| !c.is_archived());
        let archived = case.as_ref().is_some_and(|c| c.is_archived());
        let p = *theme::current(&ctx);
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui
                    .add_enabled(
                        case_id.is_some(),
                        egui::Button::new("Export Case…").shortcut_text(ctx.format_shortcut(&EXPORT)),
                    )
                    .clicked()
                {
                    self.export(case_id.unwrap());
                }
                ui.separator();
                if ui
                    .add(egui::Button::new("Quit").shortcut_text(ctx.format_shortcut(&QUIT)))
                    .clicked()
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Case", |ui| self.case_menu(ui, &ctx));
            ui.menu_button("View", |ui| {
                if ui
                    .add(egui::Button::new("Search Notes").shortcut_text(ctx.format_shortcut(&SEARCH)))
                    .clicked()
                {
                    self.focus_search = true;
                }
                if ui
                    .add(egui::Button::new("Write a Note").shortcut_text(ctx.format_shortcut(&WRITE_NOTE)))
                    .clicked()
                {
                    self.focus_composer = true;
                }
                ui.separator();
                if ui
                    .add(
                        egui::Button::selectable(self.show_system, "Show System Entries")
                            .shortcut_text(ctx.format_shortcut(&SHOW_SYSTEM)),
                    )
                    .on_hover_text("Entries Factum writes itself: case created, evidence added, ...")
                    .clicked()
                {
                    self.show_system = !self.show_system;
                    self.dirty = true;
                }
                if ui
                    .add(egui::Button::selectable(self.show_archived, "Show Archived Cases"))
                    .clicked()
                {
                    self.show_archived = !self.show_archived;
                    self.dirty = true;
                }
                if ui
                    .add(
                        egui::Button::selectable(self.side_panel, "Side Panel (Pinned Notes, IoCs)")
                            .shortcut_text(ctx.format_shortcut(&SIDE_PANEL)),
                    )
                    .clicked()
                {
                    self.side_panel = !self.side_panel;
                }
                ui.separator();
                ui.menu_button("Theme", |ui| {
                    for theme in THEMES {
                        let label = if theme == "system" {
                            "Follow System".to_string()
                        } else {
                            capitalize(theme)
                        };
                        if ui.add(egui::Button::selectable(self.theme == theme, label)).clicked() {
                            self.set_theme(&ctx, theme);
                        }
                    }
                });
            });
            ui.menu_button("Settings", |ui| {
                ui.menu_button("GPG", |ui| {
                    if ui.button("Select Signing Key…").clicked() {
                        self.open_gpg_keys();
                    }
                    if ui.button("Clear Active Key").clicked() {
                        self.signer.clear_active_key(&self.db);
                        self.update_gpg_status();
                    }
                });
                ui.separator();
                if ui.button("Seal Folder…").clicked() {
                    self.choose_seal_folder();
                }
            });
            ui.menu_button("Help", |ui| {
                if ui
                    .add(egui::Button::new("Keyboard Shortcuts").shortcut_text(ctx.format_shortcut(&HELP)))
                    .clicked()
                {
                    let rows = self.shortcut_rows(&ctx);
                    self.dialogs.push(Dialog::Shortcuts { rows });
                }
                if ui.button("About Factum").clicked() {
                    self.message(
                        "About Factum",
                        format!(
                            "Factum {}\n\nForensic notes with signed, tamper-evident case logs.",
                            crate::VERSION
                        ),
                    );
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new("FACTUM")
                        .family(theme::bold())
                        .color(p.accent)
                        .extra_letter_spacing(2.0),
                );
            });
            let _ = (is_open, archived);
        });
    }

    /// The Case menu; also opens from the "⋯" button above the case tree.
    fn case_menu(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let case_id = self.current_case_id();
        let case = self.view.case.clone();
        let is_open = case.as_ref().is_some_and(|c| !c.is_archived());
        let archived = case.as_ref().is_some_and(|c| c.is_archived());
        if ui
            .add(egui::Button::new("New Case…").shortcut_text(ctx.format_shortcut(&NEW_CASE)))
            .clicked()
        {
            self.open_new_case();
        }
        if ui
            .add_enabled(
                is_open,
                egui::Button::new("New Evidence…").shortcut_text(ctx.format_shortcut(&NEW_EVIDENCE)),
            )
            .clicked()
        {
            self.open_new_evidence();
        }
        if ui.add_enabled(is_open, egui::Button::new("Edit Case…")).clicked() {
            self.open_edit_case(case_id.unwrap());
        }
        ui.separator();
        if ui
            .add_enabled(
                case_id.is_some(),
                egui::Button::new("Verify Case").shortcut_text(ctx.format_shortcut(&VERIFY_CASE)),
            )
            .clicked()
        {
            self.verify_case(ctx, case_id.unwrap());
        }
        if ui
            .add_enabled(case_id.is_some(), egui::Button::new("Seal Now"))
            .clicked()
        {
            self.with_key_check(Pending::Seal(case_id.unwrap()));
        }
        if ui
            .add_enabled(case_id.is_some(), egui::Button::new("Sign All Unsigned"))
            .clicked()
        {
            self.sign_all_unsigned(case_id.unwrap());
        }
        if ui
            .add_enabled(
                case_id.is_some(),
                egui::Button::new("Export Case…").shortcut_text(ctx.format_shortcut(&EXPORT)),
            )
            .clicked()
        {
            self.export(case_id.unwrap());
        }
        let cli_text = if self.evidence_id.is_some() {
            "Set Evidence as CLI Active"
        } else {
            "Set Case as CLI Active"
        };
        if ui.add_enabled(is_open, egui::Button::new(cli_text)).clicked() {
            match (self.evidence_id, self.case_id) {
                (Some(evidence_id), _) => self.set_cli_active_evidence(evidence_id),
                (None, Some(case_id)) => self.set_cli_active_case(case_id),
                _ => {}
            }
        }
        ui.separator();
        if ui.add_enabled(is_open, egui::Button::new("Archive Case…")).clicked() {
            self.archive(case_id.unwrap());
        }
        if ui.add_enabled(archived, egui::Button::new("Reopen Case")).clicked() {
            let result = self.factum().reopen_case(case_id.unwrap());
            self.run(result);
            self.select(None, None);
        }
        let deletable = self.view.evidence_deletable;
        let delete = ui
            .add_enabled(deletable, egui::Button::new("Delete Evidence…"))
            .on_disabled_hover_text("Only evidence items without notes can be deleted.");
        if delete.clicked() {
            self.delete_evidence(self.evidence_id.unwrap());
        }
        if ui
            .add_enabled(archived, egui::Button::new("Delete Case Permanently…"))
            .clicked()
        {
            self.delete_case(case_id.unwrap());
        }
    }

    fn panel_header(ui: &mut egui::Ui, title: &str) {
        let p = theme::current(ui.ctx());
        ui.label(
            RichText::new(title.to_uppercase())
                .size(SMALL_SIZE)
                .family(theme::bold())
                .color(p.muted)
                .extra_letter_spacing(1.2),
        );
    }

    fn case_tree(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            Self::panel_header(ui, "Cases");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button("⋯", |ui| self.case_menu(ui, ctx))
                    .response
                    .on_hover_text("Case actions (also on right-click)");
            });
        });
        ui.separator();
        let bottom_height = 116.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(ui.available_height() - bottom_height)
            .show(ui, |ui| {
                if self.view.tree.is_empty() {
                    ui.label(RichText::new("No cases yet. Press Ctrl+N.").color(p.muted));
                }
                let mut clicked: Option<(Option<i64>, Option<i64>)> = None;
                let mut menu_action: Option<TreeAction> = None;
                for node in &self.view.tree {
                    let case = &node.case;
                    let selected = self.case_id == Some(case.id);
                    let name = format!(
                        "{}{}",
                        case.case_name,
                        if case.is_archived() { "  [archived]" } else { "" }
                    );
                    let color = if case.is_archived() { p.muted } else { p.text };
                    let response = tree_row(
                        ui,
                        selected,
                        RichText::new(name).family(theme::bold()).color(color),
                        node.notes,
                        4.0,
                    )
                    .on_hover_text(format!("{} — {}", case.case_file, case.case_name));
                    if response.clicked() {
                        clicked = Some((Some(case.id), None));
                    }
                    response.context_menu(|ui| {
                        if !case.is_archived() {
                            if ui.button("New Evidence…").clicked() {
                                menu_action = Some(TreeAction::NewEvidence(case.id));
                            }
                            if ui.button("Edit Case…").clicked() {
                                menu_action = Some(TreeAction::Edit(case.id));
                            }
                            if ui.button("Set as CLI Active Case").clicked() {
                                menu_action = Some(TreeAction::CliCase(case.id));
                            }
                            ui.separator();
                        }
                        for (label, action) in [
                            ("Verify Case", TreeAction::Verify(case.id)),
                            ("Seal Now", TreeAction::Seal(case.id)),
                            ("Export…", TreeAction::Export(case.id)),
                            ("Sign All Unsigned", TreeAction::SignAll(case.id)),
                        ] {
                            if ui.button(label).clicked() {
                                menu_action = Some(action);
                            }
                        }
                        ui.separator();
                        if case.is_archived() {
                            if ui.button("Reopen Case").clicked() {
                                menu_action = Some(TreeAction::Reopen(case.id));
                            }
                            if ui.button("Delete Permanently…").clicked() {
                                menu_action = Some(TreeAction::DeleteCase(case.id));
                            }
                        } else if ui.button("Archive Case…").clicked() {
                            menu_action = Some(TreeAction::Archive(case.id));
                        }
                    });
                    for (evidence, count) in &node.evidence {
                        let selected = self.evidence_id == Some(evidence.id);
                        let color = if case.is_archived() { p.muted } else { p.secondary };
                        let response = tree_row(
                            ui,
                            selected,
                            RichText::new(&evidence.description).color(color),
                            *count,
                            20.0,
                        )
                        .on_hover_text(&evidence.description);
                        if response.clicked() {
                            clicked = Some((None, Some(evidence.id)));
                        }
                        response.context_menu(|ui| {
                            if ui.button("Set as CLI Active Evidence").clicked() {
                                menu_action = Some(TreeAction::CliEvidence(evidence.id));
                            }
                            if !case.is_archived() {
                                ui.separator();
                                let empty = *count == 0 && !self.factum().has_entries(evidence.id).unwrap_or(true);
                                let label = if empty {
                                    "Delete Evidence…"
                                } else {
                                    "Delete Evidence… (only without notes)"
                                };
                                if ui.add_enabled(empty, egui::Button::new(label)).clicked() {
                                    menu_action = Some(TreeAction::DeleteEvidence(evidence.id));
                                }
                            }
                        });
                    }
                }
                if let Some((case_id, evidence_id)) = clicked {
                    self.select(case_id, evidence_id);
                }
                if let Some(action) = menu_action {
                    self.tree_action(action, ctx);
                }
            });
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.add_space(10.0);
            let width = ui.available_width();
            let evidence_tip = format!(
                "Add evidence to the selected case ({})",
                ctx.format_shortcut(&NEW_EVIDENCE)
            );
            let is_open = self.view.case.as_ref().is_some_and(|c| !c.is_archived());
            if ui
                .add_enabled(
                    is_open,
                    egui::Button::new("+ New Evidence").min_size(egui::vec2(width, 30.0)),
                )
                .on_hover_text(evidence_tip)
                .clicked()
            {
                self.open_new_evidence();
            }
            let new_case = egui::Button::new(RichText::new("+ New Case").color(p.on_accent).family(theme::bold()))
                .fill(p.accent)
                .min_size(egui::vec2(width, 30.0));
            if ui.add(new_case).on_hover_text(ctx.format_shortcut(&NEW_CASE)).clicked() {
                self.open_new_case();
            }
            if ui.checkbox(&mut self.show_archived, "Show archived cases").changed() {
                self.dirty = true;
            }
        });
    }

    fn tree_action(&mut self, action: TreeAction, ctx: &egui::Context) {
        match action {
            TreeAction::NewEvidence(case_id) => {
                self.select(Some(case_id), None);
                self.dialogs.push(Dialog::NewEvidence {
                    case_id,
                    description: String::new(),
                    hash: String::new(),
                    error: None,
                });
            }
            TreeAction::Edit(case_id) => self.open_edit_case(case_id),
            TreeAction::CliCase(case_id) => self.set_cli_active_case(case_id),
            TreeAction::CliEvidence(evidence_id) => self.set_cli_active_evidence(evidence_id),
            TreeAction::Verify(case_id) => self.verify_case(ctx, case_id),
            TreeAction::Seal(case_id) => self.with_key_check(Pending::Seal(case_id)),
            TreeAction::Export(case_id) => self.export(case_id),
            TreeAction::SignAll(case_id) => self.sign_all_unsigned(case_id),
            TreeAction::Reopen(case_id) => {
                let result = self.factum().reopen_case(case_id);
                self.run(result);
                self.select(None, None);
            }
            TreeAction::DeleteCase(case_id) => self.delete_case(case_id),
            TreeAction::Archive(case_id) => self.archive(case_id),
            TreeAction::DeleteEvidence(evidence_id) => self.delete_evidence(evidence_id),
        }
    }

    fn notes_area(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let mut actions = Vec::new();
        // search bar: free text, or #tag for tags only
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let hint = format!("Search notes, or #tag  ({})", ctx.format_shortcut(&SEARCH));
            let search = ui.add(
                TextEdit::singleline(&mut self.filter)
                    .id(egui::Id::unique("search"))
                    .hint_text(hint)
                    .desired_width(280.0),
            );
            if std::mem::take(&mut self.focus_search) {
                search.request_focus();
            }
            if search.changed() {
                self.dirty = true;
            }
            if !self.filter.is_empty() && ui.small_button("✕").on_hover_text("Clear the search").clicked() {
                self.filter.clear();
                self.dirty = true;
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let toggle = ui
                    .add(egui::Button::selectable(self.side_panel, "◨"))
                    .on_hover_text(format!(
                        "Show or hide pinned notes and IoCs ({})",
                        ctx.format_shortcut(&SIDE_PANEL)
                    ));
                if toggle.clicked() {
                    self.side_panel = !self.side_panel;
                }
                if self.view.case.is_some() {
                    ui.label(RichText::new(&self.view.note_count).size(SMALL_SIZE).color(p.muted));
                }
            });
        });
        ui.separator();

        // the composer at the bottom, the log above it
        let composer_height = 170.0;
        let log_height = (ui.available_height() - composer_height).max(120.0);
        let now = chrono::Utc::now();
        egui::ScrollArea::vertical()
            .id_salt("notes")
            .auto_shrink([false, false])
            .max_height(log_height)
            .show(ui, |ui| {
                ui.add_space(8.0);
                if let Some(text) = &self.view.empty_text {
                    ui.add_space(32.0);
                    ui.vertical_centered(|ui| ui.label(RichText::new(text).color(p.muted)));
                }
                for item in &self.view.items {
                    let response = match item {
                        Item::Note(card) => {
                            let view = CardView {
                                check: self.check_view(&card.entry),
                                compact: false,
                                focused: self.focused_card == Some(card.entry.id),
                                history_open: self.history_open.contains(&card.entry.id),
                                now,
                            };
                            widgets::note_card(ui, card, &view, &mut actions)
                        }
                        Item::System(entry) => widgets::system_row(ui, entry, self.check_view(entry), &mut actions),
                    };
                    if self.scroll_to == Some(item.entry().id) {
                        response.scroll_to_me(Some(Align::Center));
                        self.scroll_to = None;
                    }
                }
                ui.add_space(8.0);
            });
        for action in actions {
            self.handle_card_action(action, ctx);
        }
        self.composer(ui, ctx);
    }

    fn composer(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        ui.separator();
        let archived = self.view.case.as_ref().is_some_and(|c| c.is_archived());
        ui.horizontal(|ui| {
            ui.label(RichText::new("Adding to:").size(SMALL_SIZE).color(p.muted));
            match &self.view.case {
                None => {
                    ui.label(
                        RichText::new("nothing selected. Choose a case or evidence on the left.")
                            .size(SMALL_SIZE)
                            .color(p.muted)
                            .italics(),
                    );
                }
                Some(case) => {
                    let mut target = case.case_name.clone();
                    if let Some(evidence) = &self.view.evidence {
                        target += &format!(" › {}", evidence.description);
                    }
                    if archived {
                        target += "  (archived, read-only)";
                    }
                    ui.label(
                        RichText::new(target)
                            .size(SMALL_SIZE)
                            .family(theme::bold())
                            .color(p.secondary),
                    );
                }
            }
        });
        let is_open = self.view.case.is_some() && !archived;
        let placeholder = if archived {
            "Case archived — reopen to add notes."
        } else {
            NOTE_PLACEHOLDER
        };
        let editor = ui.add_enabled(
            is_open,
            TextEdit::multiline(&mut self.composer)
                .id(egui::Id::unique("composer"))
                .hint_text(placeholder)
                .font(egui::FontId::proportional(theme::NOTE_SIZE))
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        if std::mem::take(&mut self.focus_composer) {
            editor.request_focus();
        }
        ui.horizontal(|ui| {
            // the key itself is in the status bar; the composer only warns when notes will not be signed
            if self.signer.active_key().is_none() {
                let warning = if !self.signer.available() {
                    "⚠ GPG is not installed: notes will not be signed"
                } else {
                    "⚠ No GPG key selected: notes will not be signed (Settings → GPG)"
                };
                ui.label(RichText::new(warning).size(SMALL_SIZE).color(p.warn));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let button = egui::Button::new(
                    RichText::new(format!("Add Note   {}", ctx.format_shortcut(&ADD_NOTE)))
                        .color(p.on_accent)
                        .family(theme::bold()),
                )
                .fill(p.accent);
                if ui.add_enabled(is_open, button).clicked() {
                    self.submit_note();
                }
            });
        });
        ui.add_space(6.0);
    }

    fn side_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let pinned = if self.view.pinned.is_empty() {
                "PINNED".to_string()
            } else {
                format!("PINNED {}", self.view.pinned.len())
            };
            let ioc_count: usize = self.view.iocs.values().map(Vec::len).sum();
            let iocs = if ioc_count == 0 {
                "IOCS".to_string()
            } else {
                format!("IOCS {ioc_count}")
            };
            if ui
                .selectable_label(
                    self.side_tab == SideTab::Pinned,
                    RichText::new(pinned).size(SMALL_SIZE).family(theme::bold()),
                )
                .clicked()
            {
                self.side_tab = SideTab::Pinned;
            }
            if ui
                .selectable_label(
                    self.side_tab == SideTab::Iocs,
                    RichText::new(iocs).size(SMALL_SIZE).family(theme::bold()),
                )
                .clicked()
            {
                self.side_tab = SideTab::Iocs;
            }
            if self.side_tab == SideTab::Pinned {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let evidence =
                        ui.selectable_label(self.pinned_scope_evidence, RichText::new("Evidence").size(SMALL_SIZE));
                    if evidence
                        .on_hover_text("Pinned notes of the selected evidence")
                        .clicked()
                        && !self.pinned_scope_evidence
                    {
                        self.pinned_scope_evidence = true;
                        self.dirty = true;
                    }
                    let case = ui.selectable_label(!self.pinned_scope_evidence, RichText::new("Case").size(SMALL_SIZE));
                    if case.on_hover_text("Pinned notes of the whole case").clicked() && self.pinned_scope_evidence {
                        self.pinned_scope_evidence = false;
                        self.dirty = true;
                    }
                });
            }
        });
        ui.separator();
        let mut actions = Vec::new();
        egui::ScrollArea::vertical()
            .id_salt("side")
            .auto_shrink([false, false])
            .show(ui, |ui| match self.side_tab {
                SideTab::Pinned => {
                    if let Some(text) = &self.view.pinned_empty_text {
                        ui.add_space(24.0);
                        ui.vertical_centered(|ui| ui.label(RichText::new(text).color(p.muted)));
                    }
                    let now = chrono::Utc::now();
                    for card in &self.view.pinned {
                        let view = CardView {
                            check: self.check_view(&card.entry),
                            compact: true,
                            focused: false,
                            history_open: self.history_open.contains(&card.entry.id),
                            now,
                        };
                        widgets::note_card(ui, card, &view, &mut actions);
                    }
                }
                SideTab::Iocs => {
                    if self.view.iocs.is_empty() {
                        ui.add_space(24.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                RichText::new("No IoCs found. IPs, domains, hashes, ... in notes show up here.")
                                    .color(p.muted),
                            )
                        });
                    }
                    for (ioc_type, values) in &self.view.iocs {
                        egui::CollapsingHeader::new(
                            RichText::new(format!("{}  ({})", ioc_type.to_uppercase(), values.len()))
                                .family(theme::bold()),
                        )
                        .id_salt(("ioc", ioc_type))
                        .default_open(false)
                        .show(ui, |ui| {
                            for value in values {
                                let label = ui.add(
                                    egui::Label::new(RichText::new(value).monospace().color(p.text))
                                        .selectable(true)
                                        .wrap(),
                                );
                                label.context_menu(|ui| {
                                    if ui.button("Copy").clicked() {
                                        ctx.copy_text(value.clone());
                                    }
                                });
                            }
                        });
                    }
                }
            });
        for action in actions {
            self.handle_card_action(action, ctx);
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        ui.horizontal(|ui| {
            // only shown while a CLI target is set; the GUI selection is shown above the note input
            if !self.view.cli_active.is_empty() {
                let tip = "Notes written on the command line (factum \"text\") go here.\nChange it by right-clicking a case or evidence → Set as CLI Active.";
                ui.label(RichText::new("CLI active:").size(SMALL_SIZE).color(p.muted)).on_hover_text(tip);
                ui.label(RichText::new(&self.view.cli_active).size(SMALL_SIZE).color(p.secondary)).on_hover_text(tip);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (text, warning) = &self.gpg_status;
                let color = if *warning { p.warn } else { p.ok };
                let button = egui::Button::new(RichText::new(text).size(SMALL_SIZE).monospace().color(color)).frame(false);
                if ui.add(button).on_hover_text("Key used to sign notes and seals. Click to choose another one.").clicked() {
                    self.open_gpg_keys();
                }
                ui.label(RichText::new("GPG key:").size(SMALL_SIZE).color(p.muted));
            });
        });
    }

    fn verification_progress(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.verify_job else { return };
        if job.started.elapsed() < Duration::from_millis(300) {
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }
        let done = job.progress.done.load(Ordering::Relaxed);
        let total = job.progress.total.load(Ordering::Relaxed);
        egui::Modal::new(egui::Id::unique("verify-progress")).show(ctx, |ui| {
            ui.set_width(320.0);
            ui.label("Verifying case…");
            let fraction = if total == 0 { 0.0 } else { done as f32 / total as f32 };
            ui.add(egui::ProgressBar::new(fraction).text(format!("{done} / {total}")));
        });
    }
}

#[derive(Debug, Clone, Copy)]
enum TreeAction {
    NewEvidence(i64),
    Edit(i64),
    CliCase(i64),
    CliEvidence(i64),
    Verify(i64),
    Seal(i64),
    Export(i64),
    SignAll(i64),
    Reopen(i64),
    DeleteCase(i64),
    Archive(i64),
    DeleteEvidence(i64),
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// A row of the case tree: the name, and the number of notes on the right.
fn tree_row(ui: &mut egui::Ui, selected: bool, text: RichText, count: usize, indent: f32) -> egui::Response {
    let p = *theme::current(ui.ctx());
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 28.0), egui::Sense::click());
    if selected || response.hovered() {
        let fill = if selected { p.accent_soft } else { p.panel };
        ui.painter().rect_filled(rect, 2.0, fill);
    }
    if selected {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
            0.0,
            p.accent,
        );
    }
    let count_text = if count > 0 { count.to_string() } else { String::new() };
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(egui::vec2(8.0, 0.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    child.add_space(indent);
    child.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.label(RichText::new(count_text).size(SMALL_SIZE).color(p.muted))
            .on_hover_text(format!("{count} note{}", if count == 1 { "" } else { "s" }));
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.add(egui::Label::new(text).truncate().selectable(false));
        });
    });
    response
}

impl eframe::App for FactumApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        self.shortcuts(&ctx);
        if self.dirty {
            self.rebuild(&ctx);
        }
        let p = *theme::current(&ctx);

        egui::Panel::top("menu")
            .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(8, 4)))
            .show(ui, |ui| {
                self.menu_bar(ui);
            });
        egui::Panel::bottom("status")
            .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(10, 4)))
            .show(ui, |ui| {
                self.status_bar(ui, &ctx);
            });
        egui::Panel::left("cases")
            .resizable(false)
            .exact_size(260.0)
            .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(10, 4)))
            .show(ui, |ui| self.case_tree(ui, &ctx));
        if self.side_panel {
            let response = egui::Panel::right("side")
                .resizable(true)
                .default_size(self.side_width)
                .size_range(260.0..=640.0)
                .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(10, 4)))
                .show(ui, |ui| self.side_panel(ui, &ctx));
            self.side_width = response.response.rect.width();
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.bg).inner_margin(Margin::symmetric(16, 4)))
            .show(ui, |ui| self.notes_area(ui, &ctx));

        let mut verify_actions = Vec::new();
        for window in &mut self.verify_windows {
            window.show(&ctx, &mut verify_actions);
        }
        self.verify_windows.retain(|w| w.open);
        for action in verify_actions {
            match action {
                VerifyAction::ShowEntry(entry_id) => self.jump_to_entry(entry_id),
                VerifyAction::SignSeal(tree_head_id) => {
                    let result = self.factum().sign_tree_head(tree_head_id);
                    if self.run(result).is_some() {
                        self.message("Factum", format!("Seal #{tree_head_id} signed."));
                    }
                }
            }
        }
        self.verification_progress(&ctx);
        if let Some(dialog) = self.dialogs.last_mut()
            && let Some(result) = dialog.show(&ctx)
        {
            self.dialogs.pop();
            self.handle_dialog_result(result);
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            self.quit();
        }
        let _ = ACTIVE_KEY_SETTING;
    }
}

#[cfg(test)]
mod tests;
