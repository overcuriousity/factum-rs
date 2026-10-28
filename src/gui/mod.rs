//! The desktop GUI (`factum --gui`): case tree on the left, the case log in the middle, pinned notes, the
//! companion's questions and IoCs on the right. Everything shown is cached in a [`View`] that is rebuilt after
//! every change, so drawing a frame never queries the database.

mod companion_dialogs;
mod companion_panel;
mod companion_windows;
mod containers;
mod dialogs;
mod icons;
mod markup_view;
mod note_editor;
mod tag_completion;
mod theme;
mod widgets;
mod wizard;
mod workers;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use egui::{Align, Key, KeyboardShortcut, Layout, Margin, Modifiers, RichText, TextEdit};

use crate::cases::Case;
use crate::companion::ask::Answer;
use crate::companion::thread::{Command, CompanionHandle, Status};
use crate::companion::{CompanionDb, Settings, companion_db_path};
use crate::db::Db;
use crate::error::{ErrorKind, FactumError, Result};
use crate::evidence::Evidence;
use crate::images::{self, NoteImage};
use crate::markup;
use crate::notes::{Entry, EntryFilter};
use crate::pystr::{strip, tail};
use crate::seals::{REASON_CHECKPOINT, SEAL_DIR_SETTING};
use crate::services::Factum;
use crate::signer::{ACTIVE_KEY_SETTING, GnupgSigner, Signer};
use crate::verifier::{CaseReport, Level, SignatureCheck};
use companion_dialogs::CompanionSettingsDialog;
use companion_panel::{CompanionView, PanelAction};
use companion_windows::{CompanionWindow, WindowAction};
use containers::ContainerAction;
use dialogs::{Dialog, DialogResult, NoGpgChoice, Pending, VerifyAction, VerifyWindow};
use theme::{MAX_CARD_WIDTH, SMALL_SIZE, THEMES};
use widgets::{Card, CardAction, CardView, CheckView, IconButton};
#[cfg(test)]
use wizard::Step;
use wizard::{Wizard, WizardChoices, WizardStart};

// GUI preferences, stored next to the other settings in the database
const THEME_SETTING: &str = "ui_theme";
const SIDE_PANEL_VISIBLE_SETTING: &str = "ui_side_panel_visible";
const SIDE_PANEL_WIDTH_SETTING: &str = "ui_side_panel_width";
const TREE_WIDTH_SETTING: &str = "ui_tree_width";
const COMPOSER_HEIGHT_SETTING: &str = "ui_composer_height";
const EXPORT_DIR_SETTING: &str = "export_dir";
/// "1" once the setup wizard was finished or cancelled
const ONBOARDING_SETTING: &str = "onboarding_done";
const DEFAULT_SIDE_PANEL_WIDTH: f32 = 340.0;
const DEFAULT_TREE_WIDTH: f32 = 240.0;
const DEFAULT_COMPOSER_HEIGHT: f32 = 170.0;
const MIN_COMPOSER_HEIGHT: f32 = 150.0;
const NOTE_PLACEHOLDER: &str = "Write a note. It is time-stamped when added; #tags categorize it.";
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

struct CaseNode {
    case: Case,
    notes: usize,
    evidence: Vec<(Evidence, usize)>,
    containers: Vec<crate::containers::ContainerSummary>,
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

/// What the status bar says about the selected case.
struct CaseStatus {
    entries: usize,
    /// when the newest seal was made
    last_seal: Option<String>,
}

/// Everything the window shows, read from the database in one go.
#[derive(Default)]
struct View {
    tree: Vec<CaseNode>,
    /// archived cases, shown or not
    archived_cases: usize,
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
    case_status: Option<CaseStatus>,
    /// the Questions section: present while the companion is configured and a case is selected
    companion: Option<CompanionView>,
    /// the containers below the notes: the selected evidence's, or the one selected on its own (a row of its own)
    containers: Vec<crate::containers::ContainerDetail>,
    /// their files' last-written times, by container id, then by ARN, from the container files
    container_times: HashMap<i64, HashMap<String, String>>,
}

/// A container file's times as last read: (file, its length then, last-written time by ARN).
type TimesCache = (PathBuf, u64, HashMap<String, String>);

/// Files being added to a container, on a worker thread.
struct AddJob {
    container_id: i64,
    name: String,
    worker: workers::Worker<workers::AddResult>,
    progress: Arc<crate::container::volume::AddProgress>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
}

/// A container file being verified.
struct ContainerVerifyJob {
    worker: workers::Worker<workers::ContainerVerifyResult>,
    progress: Arc<workers::Progress>,
    started: Instant,
    cancel: Arc<std::sync::atomic::AtomicBool>,
}

struct VerifyJob {
    worker: workers::Worker<workers::VerifyResult>,
    progress: Arc<workers::Progress>,
    started: Instant,
}

struct FactumApp {
    db: Db,
    /// for worker threads that repaint when they are done
    egui_ctx: egui::Context,
    // one signing service for everything, so the active key and the pinentry state are shared
    signer: GnupgSigner,
    env_seal_dir: Option<PathBuf>,
    // what is selected in the tree; when evidence is selected, case_id is None (like the case tree items)
    case_id: Option<i64>,
    evidence_id: Option<i64>,
    /// a selected container (its case is case_id then)
    container_id: Option<i64>,
    filter: String,
    pinned_scope_evidence: bool,
    show_archived: bool,
    show_system: bool,
    theme: String,
    side_panel: bool,
    side_width: f32,
    tree_width: f32,
    /// the composer's panel, dragged at its top edge
    composer_height: f32,
    iocs_open: bool,
    questions_open: bool,
    /// the scrolled height of the pinned notes in the last frame, for splitting the side panel
    pinned_height: f32,
    composer: String,
    /// the images pasted, dropped or inserted into the composer; saved with the note that refers to them
    composer_images: Vec<NoteImage>,
    tag_completion: tag_completion::TagCompletion,
    view: View,
    dirty: bool,
    focused_card: Option<i64>,
    history_open: HashSet<i64>,
    /// the image shown full size: its entry and the image; one at a time
    image_viewer: Option<(i64, NoteImage)>,
    scroll_to: Option<i64>,
    // signature checks of the entries shown, for this session: a card shows ✓ only after its check
    signature_checks: HashMap<i64, SignatureCheck>,
    signature_worker: Option<workers::Worker<workers::SignatureChecks>>,
    signature_check_pending: bool,
    verify_job: Option<VerifyJob>,
    add_job: Option<AddJob>,
    /// the shown containers' file times: (file, its logged end (else its length) when read, times), by container id
    container_times_cache: std::cell::RefCell<HashMap<i64, TimesCache>>,
    /// the decoded images of the note entries shown, by entry id: entries never change, so a rebuild (every
    /// keystroke in the search, every action) does not parse and decode them again
    note_images: std::cell::RefCell<HashMap<i64, Arc<[NoteImage]>>>,
    container_verify_job: Option<ContainerVerifyJob>,
    container_verify_windows: Vec<containers::ContainerVerifyWindow>,
    /// each case's last verification in this session: outcome, time and the tree size it covered
    verified: HashMap<i64, (Level, String, i64)>,
    dialogs: Vec<Dialog>,
    verify_windows: Vec<VerifyWindow>,
    companion_windows: Vec<CompanionWindow>,
    // running Ask calls, by case
    ask_jobs: Vec<(i64, workers::Worker<workers::AskResult>)>,
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
    // None until the companion is first configured (the file is created on first use), or when it cannot be opened
    companion_db: Option<CompanionDb>,
    // the companion database exists but cannot be opened: its settings cannot be edited either
    companion_db_failed: bool,
    companion_settings: Settings,
    // running while the companion is configured
    companion: Option<CompanionHandle>,
    companion_status: Status,
    // per case, the newest entry the thread was told about with CaseChanged
    companion_seen: HashMap<i64, i64>,
}

impl FactumApp {
    fn new(db: Db, ctx: &egui::Context) -> Self {
        Self::build(db, ctx, true)
    }

    /// `start_companion`: start the companion thread when it is configured (tests have no endpoint).
    fn build(db: Db, ctx: &egui::Context, start_companion: bool) -> Self {
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
        let tree_width = setting(TREE_WIDTH_SETTING).parse().unwrap_or(DEFAULT_TREE_WIDTH);
        let composer_height = setting(COMPOSER_HEIGHT_SETTING)
            .parse()
            .unwrap_or(DEFAULT_COMPOSER_HEIGHT);
        theme::apply(ctx, &theme);
        let data_version = db.data_version().unwrap_or_default();
        // created on first use, by saving its settings: an unconfigured companion leaves no file behind
        let companion_path = companion_db_path(&db.path);
        let companion_db = companion_path
            .exists()
            .then(|| {
                CompanionDb::open(&companion_path)
                    .inspect_err(|e| log::error!("The companion database cannot be opened: {e}"))
                    .ok()
            })
            .flatten();
        let companion_db_failed = companion_path.exists() && companion_db.is_none();
        let companion_settings = companion_db
            .as_ref()
            .and_then(|cdb| {
                Settings::load(cdb)
                    .inspect_err(|e| log::error!("The companion settings cannot be read: {e}"))
                    .ok()
            })
            .unwrap_or_default();
        let mut app = Self {
            db,
            egui_ctx: ctx.clone(),
            signer,
            env_seal_dir: crate::config::settings().seal_dir.clone(),
            case_id: None,
            evidence_id: None,
            container_id: None,
            filter: String::new(),
            pinned_scope_evidence: false,
            show_archived: false,
            show_system: true,
            theme,
            side_panel,
            side_width,
            tree_width,
            composer_height,
            iocs_open: false,
            questions_open: true,
            pinned_height: 0.0,
            composer: String::new(),
            composer_images: Vec::new(),
            tag_completion: Default::default(),
            view: View::default(),
            dirty: true,
            focused_card: None,
            history_open: HashSet::new(),
            image_viewer: None,
            scroll_to: None,
            signature_checks: HashMap::new(),
            signature_worker: None,
            signature_check_pending: false,
            verify_job: None,
            add_job: None,
            container_times_cache: std::cell::RefCell::new(HashMap::new()),
            note_images: Default::default(),
            container_verify_job: None,
            container_verify_windows: Vec::new(),
            verified: HashMap::new(),
            dialogs: Vec::new(),
            verify_windows: Vec::new(),
            companion_windows: Vec::new(),
            ask_jobs: Vec::new(),
            next_window_id: 0,
            gpg_help_prompted: false,
            no_gpg_key_prompted: false,
            after_key_dialog: None,
            data_version,
            last_poll: Instant::now(),
            focus_search: false,
            focus_composer: false,
            gpg_status: (String::new(), false),
            companion_db,
            companion_db_failed,
            companion_settings,
            companion: None,
            companion_status: Status::default(),
            companion_seen: HashMap::new(),
        };
        // pre-select the CLI active case or evidence so notes are shown on startup
        let factum = app.factum();
        if let Ok(Some(evidence_id)) = factum.get_active_evidence_id() {
            app.evidence_id = Some(evidence_id);
        } else if let Ok(Some(case_id)) = factum.get_active_case_id() {
            app.case_id = Some(case_id);
        }
        app.update_gpg_status();
        if start_companion && app.companion_db.is_some() && app.companion_settings.is_configured() {
            app.start_companion(ctx);
        }
        if app.should_auto_start_wizard() {
            app.open_wizard();
        }
        app
    }

    /// A first start: the wizard never ran on this database, which has no cases and no signing key yet.
    fn should_auto_start_wizard(&self) -> bool {
        self.db.get_setting(ONBOARDING_SETTING).unwrap_or_default().is_empty()
            && self.factum().list_cases(true).is_ok_and(|cases| cases.is_empty())
            && self.signer.active_key().is_none()
    }

    fn open_wizard(&mut self) {
        let wizard = Wizard::new(WizardStart {
            gpg_home: self.signer.gpg_home(),
            current_key: self.signer.active_key(),
            companion: self.companion_settings.clone(),
            db_path: self.db.path.clone(),
            seal_folder: self.db.get_setting(SEAL_DIR_SETTING).unwrap_or_default(),
            default_seal_folder: self.factum().default_seal_dir().display().to_string(),
            seal_env: self.env_seal_dir.clone(),
            theme: self.theme.clone(),
            x509_certs: crate::container::x509::Gpgsm::new(self.signer.gpg_home()).list_secret_certs(),
            x509: Some(
                self.db
                    .get_setting(crate::container::x509::X509_CERT_SETTING)
                    .unwrap_or_default(),
            )
            .filter(|s| !s.is_empty()),
            x509_chain: self
                .db
                .get_setting(crate::container::x509::X509_CHAIN_SETTING)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .filter(|l| !l.trim().is_empty())
                .collect(),
        });
        self.dialogs.push(Dialog::Wizard(Box::new(wizard)));
    }

    /// Applies what the wizard collected, in the order of its steps.
    fn finish_wizard(&mut self, ctx: &egui::Context, choices: WizardChoices) {
        if let Some(key) = choices.key
            && self.signer.set_active_key(&self.db, &key)
        {
            self.update_gpg_status();
        }
        if let Some((certificate, chain_files)) = choices.x509 {
            self.save_x509(certificate, chain_files);
        }
        match choices.seal_folder.as_deref() {
            Some("") => {
                let _ = self.db.delete_setting(SEAL_DIR_SETTING);
            }
            Some(folder) => {
                let _ = self.db.set_setting(SEAL_DIR_SETTING, folder);
            }
            None => {}
        }
        match choices.theme {
            Some(theme) => self.set_theme(ctx, &theme),
            None => theme::apply(ctx, &self.theme),
        }
        if let Some(mut dialog) = choices.companion {
            match dialog.save() {
                Some(settings) if self.open_companion_db() => self.apply_companion_settings(ctx, settings),
                Some(_) => {}
                None => {
                    let error = dialog.error().unwrap_or_default().to_string();
                    self.message("Companion", error);
                }
            }
        }
        if choices.companion_off
            && let Some(cdb) = &self.companion_db
        {
            let mut settings = self.companion_settings.clone();
            settings.enabled = false;
            let saved = settings.save(cdb);
            if self.run(saved).is_some() {
                self.apply_companion_settings(ctx, settings);
            }
        }
        let _ = self.db.set_setting(ONBOARDING_SETTING, "1");
    }

    fn start_companion(&mut self, ctx: &egui::Context) {
        let handle = CompanionHandle::start(ctx.clone(), self.db.path.clone(), companion_db_path(&self.db.path));
        handle.send(Command::Selected(self.current_case_id()));
        self.companion = Some(handle);
        self.companion_seen.clear();
        self.dirty = true; // the next rebuild tells it which cases changed
    }

    /// Starts, updates or stops the companion thread to match the saved settings.
    fn apply_companion_settings(&mut self, ctx: &egui::Context, settings: Settings) {
        let configured = settings.is_configured();
        self.companion_settings = settings;
        match self.companion.take() {
            Some(handle) if configured => {
                handle.send(Command::SettingsChanged);
                self.companion = Some(handle);
            }
            Some(handle) => handle.detach(),
            None if configured && self.companion_db.is_some() => self.start_companion(ctx),
            None => {}
        }
        self.dirty = true;
    }

    /// Opens the companion database once the settings dialog has created it.
    fn open_companion_db(&mut self) -> bool {
        if self.companion_db.is_none() && companion_db_path(&self.db.path).exists() {
            match CompanionDb::open_for(&self.db.path) {
                Ok(cdb) => self.companion_db = Some(cdb),
                Err(e) => {
                    self.companion_db_failed = true;
                    self.message("Factum", format!("The companion database cannot be opened: {e}"));
                }
            }
        }
        self.companion_db.is_some()
    }

    /// "Test connection" saves the draft: after Cancel the stored settings may differ from the ones in use.
    fn reload_companion_settings(&mut self, ctx: &egui::Context) {
        if !self.open_companion_db() {
            return;
        }
        let Some(cdb) = &self.companion_db else { return };
        match Settings::load(cdb) {
            Ok(settings) if settings != self.companion_settings => self.apply_companion_settings(ctx, settings),
            Ok(_) => {}
            Err(e) => log::error!("The companion settings cannot be read: {e}"),
        }
    }

    #[cfg(test)]
    fn install_companion_stub(&mut self) -> std::sync::mpsc::Receiver<Command> {
        let (handle, commands) = CompanionHandle::test_stub();
        self.companion = Some(handle);
        self.companion_seen.clear();
        self.dirty = true;
        commands
    }

    fn send_companion(&self, cmd: Command) {
        if let Some(handle) = &self.companion {
            handle.send(cmd);
        }
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
            ("No signing key".into(), true)
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
        let shown: HashSet<i64> = self
            .view
            .items
            .iter()
            .map(|item| item.entry().id)
            .chain(self.view.pinned.iter().map(|card| card.entry.id))
            .collect();
        self.note_images.borrow_mut().retain(|id, _| shown.contains(id));
        self.reload_history();
        self.notify_companion();
        self.check_shown_signatures(ctx);
    }

    /// Rereads the rows of the open history windows: ratings, passes and the windows' own buttons change them.
    fn reload_history(&mut self) {
        let Some(cdb) = &self.companion_db else { return };
        for window in &mut self.companion_windows {
            if let CompanionWindow::History { case_id, rows, .. } = window {
                match cdb.resolved_questions(*case_id) {
                    Ok(questions) => *rows = questions,
                    Err(e) => log::error!("The companion history cannot be read: {e}"),
                }
            }
        }
    }

    /// Sends `CaseChanged` for every case the companion knows (it has a `case_settings` row) with entries the thread
    /// was neither told about nor has seen in a pass; the GUI's own writes do not move `data_version`, so this runs
    /// on every rebuild.
    fn notify_companion(&mut self) {
        let (Some(handle), Some(cdb)) = (&self.companion, &self.companion_db) else {
            return;
        };
        let newest = match crate::companion::newest_entry_by_case(&self.db) {
            Ok(newest) => newest,
            Err(e) => return log::error!("The newest entries cannot be read: {e}"),
        };
        let last_seen = match cdb.last_seen_by_case() {
            Ok(last_seen) => last_seen,
            Err(e) => return log::error!("The companion settings cannot be read: {e}"),
        };
        for (case_id, max_id) in newest {
            let told = self.companion_seen.get(&case_id).copied().unwrap_or(0);
            // a case without a row was not selected since the companion exists: its first pass starts then
            let Some(&seen) = last_seen.get(&case_id) else {
                continue;
            };
            if max_id > told && max_id > seen {
                handle.send(Command::CaseChanged(case_id));
                self.companion_seen.insert(case_id, max_id);
            }
        }
    }

    /// The note's images, decoded once per entry: the view reads its entries without the payload.
    fn card_images(&self, factum: &Factum, entry_id: i64) -> Result<Arc<[NoteImage]>> {
        if let Some(images) = self.note_images.borrow().get(&entry_id) {
            return Ok(images.clone());
        }
        let images: Arc<[NoteImage]> = match factum.get_entry(entry_id)? {
            Some(entry) => entry.images().into(),
            None => Arc::from([]),
        };
        self.note_images.borrow_mut().insert(entry_id, images.clone());
        Ok(images)
    }

    fn card(&self, factum: &Factum, entry: Entry, case: &Case) -> Result<Card> {
        let evidence = match entry.evidence_id {
            Some(id) => factum.get_evidence(id)?,
            None => None,
        };
        let mut history = Vec::new();
        let versions = factum.history(entry.id)?;
        for id in &versions[..versions.len() - 1] {
            if let Some(old) = factum.get_entry_without_payload(*id)? {
                history.push(old);
            }
        }
        let blocks: Arc<[markup::Block]> = markup::parse(&entry.text).into();
        Ok(Card {
            plain: markup::blocks_to_plain(&blocks),
            blocks,
            tags: crate::tags::get_tags_for_entry(&self.db.conn, entry.id)?,
            history,
            // the card names its evidence only when the view does not already say it
            evidence: evidence
                .filter(|e| Some(e.id) != self.evidence_id)
                .map(|e| e.description),
            archived: case.is_archived(),
            images: self.card_images(factum, entry.id)?,
            entry,
        })
    }

    fn read_view(&self) -> Result<View> {
        let factum = self.factum();
        let mut view = View {
            archived_cases: factum.list_cases(true)?.len() - factum.list_cases(false)?.len(),
            ..Default::default()
        };
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
            let containers = factum.list_containers(case_id)?;
            view.tree.push(CaseNode {
                case,
                notes,
                evidence,
                containers,
            });
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
            // a container selected on its own (no live evidence item) has no notes
            let entry_ids = if self.container_id.is_some() {
                Vec::new()
            } else {
                factum.list_entries(case.id, &filter)?
            };
            if entry_ids.is_empty() && self.container_id.is_none() {
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
                let Some(entry) = factum.get_entry_without_payload(*entry_id)? else {
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
            // the evidence scope only applies while evidence is selected
            let pinned_ids = factum.list_entries(
                case.id,
                &EntryFilter {
                    pinned_only: true,
                    evidence_id: self.evidence_id.filter(|_| self.pinned_scope_evidence),
                    ..Default::default()
                },
            )?;
            for entry_id in pinned_ids.iter().rev() {
                if let Some(entry) = factum.get_entry_without_payload(*entry_id)? {
                    view.pinned.push(self.card(&factum, entry, &case)?);
                }
            }
            if view.pinned.is_empty() {
                view.pinned_empty_text = Some("Nothing pinned yet. Click a note and press P.".into());
            }
            // the newest entry is never a superseded one; its tree size counts every entry, earlier versions too
            let newest = factum.list_entries(case.id, &EntryFilter::default())?.into_iter().max();
            let entries = match newest {
                Some(id) => factum
                    .get_entry_without_payload(id)?
                    .map_or(0, |entry| entry.tree_size as usize),
                None => 0,
            };
            view.case_status = Some(CaseStatus {
                entries,
                last_seal: factum
                    .list_tree_heads(case.id)?
                    .into_iter()
                    .map(|h| h.created_utc)
                    .max(),
            });
        } else {
            // without cases, the log area shows the button that creates the first one
            view.empty_text = Some(if view.tree.is_empty() {
                "No cases yet.".into()
            } else {
                "Select a case or evidence on the left.".into()
            });
        }
        view.iocs = if let Some(evidence_id) = self.evidence_id {
            crate::iocs::get_iocs_for_evidence(&self.db.conn, evidence_id)?
        } else if let Some(case_id) = self.case_id {
            crate::iocs::get_iocs_for_case(&self.db.conn, case_id)?
        } else {
            BTreeMap::new()
        };
        // the active evidence names its own case
        let evidence = factum
            .get_active_evidence_id()?
            .and_then(|id| factum.get_evidence(id).ok().flatten());
        let case_id = match &evidence {
            Some(evidence) => Some(evidence.case_id),
            None => factum.get_active_case_id()?,
        };
        if let Some(case) = case_id.and_then(|id| factum.get_case(id).ok().flatten()) {
            view.cli_active = match evidence {
                Some(evidence) => format!("{} › {}", case.case_name, evidence.description),
                None => case.case_name,
            };
        }
        let selected_case = view.case.as_ref().map(|c| c.id);
        let container_ids: Vec<i64> = match (self.container_id, self.evidence_id, selected_case) {
            (Some(id), ..) => vec![id],
            (None, Some(evidence_id), Some(case_id)) => factum
                .list_containers(case_id)?
                .into_iter()
                .filter(|c| c.evidence_id == Some(evidence_id))
                .map(|c| c.id)
                .collect(),
            _ => Vec::new(),
        };
        view.containers = container_ids
            .into_iter()
            .filter_map(|id| {
                factum
                    .container(id)
                    .inspect_err(|e| log::error!("Container #{id} cannot be read: {e}"))
                    .ok()
            })
            .collect();
        view.container_times = view
            .containers
            .iter()
            .filter(|detail| !detail.summary.missing)
            .filter_map(|detail| Some((detail.summary.path.clone()?, detail)))
            .map(|(path, detail)| {
                let times = self.container_times(&path, &detail.summary.uuid, detail.summary.id);
                (detail.summary.id, times)
            })
            .collect();
        view.companion = match (&self.companion_db, &view.case) {
            (Some(cdb), Some(case)) if self.companion_settings.is_configured() => {
                CompanionView::read(&factum, cdb, case.id)
                    .inspect_err(|e| log::error!("The companion questions cannot be read: {e}"))
                    .ok()
            }
            _ => None,
        };
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
        if let Some(job) = self.container_verify_job.as_mut()
            && let Some(result) = job.worker.poll()
        {
            self.container_verify_job = None;
            match result {
                Ok(report) => {
                    self.next_window_id += 1;
                    self.container_verify_windows.push(containers::ContainerVerifyWindow {
                        id: self.next_window_id,
                        report,
                        open: true,
                    });
                }
                Err(message) if message.contains("cancelled") => self.message("Factum", "Verification cancelled."),
                Err(message) => self.message("Factum", format!("Verification failed: {message}")),
            }
        }
        if let Some(job) = self.add_job.as_mut() {
            if let Some(result) = job.worker.poll() {
                let job = self.add_job.take().expect("polled");
                self.finish_add(job.container_id, result);
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }
        let mut finished = Vec::new();
        self.ask_jobs.retain_mut(|(case_id, worker)| match worker.poll() {
            Some(result) => {
                finished.push((*case_id, result));
                false
            }
            None => true,
        });
        for (case_id, result) in finished {
            self.set_ask_state(case_id, |answer, error, running| {
                *running = false;
                match result {
                    Ok(a) => *answer = Some(a),
                    Err(e) => *error = Some(format!("Asking failed: {e}")),
                }
            });
        }
        if let Some(handle) = &self.companion {
            let status = handle.status();
            // a finished pass changed the questions
            if status.last_pass_utc != self.companion_status.last_pass_utc {
                self.dirty = true;
            }
            self.companion_status = status;
        }
        // notes added on the command line appear here: data_version only moves on commits of other connections
        if self.last_poll.elapsed() >= Duration::from_millis(750) {
            self.last_poll = Instant::now();
            if let Ok(version) = self.db.data_version()
                && version != self.data_version
            {
                self.data_version = version;
                self.dirty = true;
                // another connection wrote: decode afresh what is shown, whatever it changed
                self.note_images.borrow_mut().clear();
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
        if (self.case_id, self.evidence_id) != (case_id, evidence_id) || self.container_id.is_some() {
            self.container_id = None;
            self.case_id = case_id;
            self.evidence_id = evidence_id;
            self.focused_card = None;
            self.dirty = true;
            self.send_companion(Command::Selected(self.current_case_id()));
        }
    }

    /// Shows a container in place of the log; its case becomes the current case.
    fn select_container(&mut self, id: i64) {
        let Ok(detail) = self.factum().container(id) else {
            return;
        };
        // a container belongs to its evidence item: that is what gets selected, while it exists
        let evidence = detail
            .evidence_id
            .and_then(|e| self.factum().get_evidence(e).ok().flatten())
            .filter(|e| !e.is_deleted());
        if let Some(evidence) = evidence {
            self.select(Some(detail.summary.case_id), Some(evidence.id));
            return;
        }
        self.case_id = Some(detail.summary.case_id);
        self.evidence_id = None;
        self.container_id = Some(id);
        self.focused_card = None;
        self.dirty = true;
        self.send_companion(Command::Selected(self.current_case_id()));
    }

    /// Verifies a container file in the background; the result opens in a window.
    fn verify_container_file(&mut self, path: PathBuf) {
        self.start_container_verification(path, Arc::new(std::sync::atomic::AtomicBool::new(false)));
    }

    /// `cancel` stops it (the progress dialog's Cancel sets it).
    fn start_container_verification(&mut self, path: PathBuf, cancel: Arc<std::sync::atomic::AtomicBool>) {
        if self
            .container_verify_job
            .as_ref()
            .is_some_and(|job| job.worker.is_running())
        {
            self.message("Factum", "A verification is already running.");
            return;
        }
        let ctx = self.egui_ctx.clone();
        let (worker, progress) =
            workers::verify_container(&ctx, self.db.path.clone(), self.signer.gpg_home(), path, cancel.clone());
        self.container_verify_job = Some(ContainerVerifyJob {
            worker,
            progress,
            started: Instant::now(),
            cancel,
        });
    }

    fn open_x509(&mut self) {
        let gpgsm = crate::container::x509::Gpgsm::new(self.signer.gpg_home());
        let setting = |key: &str| self.db.get_setting(key).unwrap_or_default();
        self.dialogs.push(Dialog::X509 {
            available: gpgsm.available(),
            certs: gpgsm.list_secret_certs(),
            selected: Some(setting(crate::container::x509::X509_CERT_SETTING)).filter(|s| !s.is_empty()),
            chain_files: setting(crate::container::x509::X509_CHAIN_SETTING)
                .lines()
                .map(str::to_string)
                .filter(|l| !l.trim().is_empty())
                .collect(),
        });
    }

    /// The X.509 certificate that signs containers, and the chain files; None and empty remove them.
    fn save_x509(&mut self, certificate: Option<String>, chain_files: Vec<String>) {
        use crate::container::x509::{X509_CERT_SETTING, X509_CHAIN_SETTING};
        let result = match certificate {
            Some(fingerprint) => self.db.set_setting(X509_CERT_SETTING, &fingerprint),
            None => self.db.delete_setting(X509_CERT_SETTING),
        }
        .and_then(|_| {
            if chain_files.is_empty() {
                self.db.delete_setting(X509_CHAIN_SETTING)
            } else {
                self.db.set_setting(X509_CHAIN_SETTING, &chain_files.join("\n"))
            }
        });
        self.run(result);
    }

    /// The container's file times, read from the file only when its logged state changed since the last read (an
    /// addition being written changes the file, not its logged state).
    fn container_times(&self, path: &std::path::Path, uuid: &str, id: i64) -> HashMap<String, String> {
        let end: Option<u64> = self
            .db
            .get_setting(&crate::containers::end_setting(uuid))
            .ok()
            .and_then(|end| end.parse().ok());
        let mut cache = self.container_times_cache.borrow_mut();
        let cached = cache.get(&id).filter(|(cached, ..)| cached == path);
        let busy = self.add_job.as_ref().is_some_and(|job| job.container_id == id);
        // without a logged end (after Locate…), finding the state means searching the file: not while it grows
        let key = match end {
            Some(end) => end,
            None if busy => return cached.map(|(.., times)| times.clone()).unwrap_or_default(),
            None => std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        };
        if let Some((_, cached_key, times)) = cached
            && *cached_key == key
        {
            return times.clone();
        }
        let times = crate::container::volume::read_graph(path, end)
            .map(|graph| crate::container::volume::modified_times(&graph))
            .inspect_err(|e| log::warn!("{e}"))
            .unwrap_or_default();
        cache.insert(id, (path.to_path_buf(), key, times.clone()));
        times
    }

    fn locate_container(&mut self, id: i64, path: &std::path::Path) {
        let result = self.factum().locate_container(id, path);
        self.run(result);
    }

    /// The case's New Container dialog: a new evidence item with a container.
    fn open_new_container(&mut self, case_id: i64) {
        self.push_new_container(case_id, None, String::new());
    }

    /// New Container for an evidence item; its name is the evidence's, numbered from the second container on.
    fn open_new_container_for(&mut self, evidence_id: i64) {
        let Ok(Some(evidence)) = self.factum().get_evidence(evidence_id) else {
            return;
        };
        let held = self
            .factum()
            .list_containers(evidence.case_id)
            .unwrap_or_default()
            .iter()
            .filter(|c| c.evidence_id == Some(evidence_id))
            .count();
        let name = match held {
            0 => evidence.description.clone(),
            n => format!("{} {}", evidence.description, n + 1),
        };
        self.push_new_container(evidence.case_id, Some((evidence_id, evidence.description)), name);
    }

    fn push_new_container(&mut self, case_id: i64, evidence: Option<(i64, String)>, name: String) {
        let folder = Some(self.db.get_setting(EXPORT_DIR_SETTING).unwrap_or_default())
            .filter(|f| !f.is_empty())
            .or_else(|| dirs::home_dir().map(|h| h.display().to_string()))
            .unwrap_or_default();
        self.dialogs.push(Dialog::NewContainer {
            case_id,
            evidence,
            name,
            hash: String::new(),
            details: String::new(),
            acquire: String::new(),
            folder,
            file_name: String::new(),
            error: None,
        });
    }

    fn open_add_to_container(&mut self, id: i64, sources: Vec<PathBuf>) {
        let Ok(detail) = self.factum().container(id) else {
            return;
        };
        // a documented limitation: Windows may update the access times of sources on a writable volume
        let writable_hint = cfg!(windows)
            && crate::container::mounts::mounts_for(&sources)
                .iter()
                .any(|m| m.read_only == Some(false));
        self.dialogs.push(Dialog::AddToContainer {
            container_id: id,
            sources,
            base: detail.base_path,
            keep_path: true,
            metadata_only: false,
            excerpt_from: String::new(),
            excerpt_to: String::new(),
            writable_hint,
            error: None,
        });
    }

    /// Starts an addition on a worker thread; its progress shows in the status bar.
    fn start_add(
        &mut self,
        id: i64,
        sources: Vec<PathBuf>,
        options: crate::container::volume::AddOptions,
        cancel: Arc<std::sync::atomic::AtomicBool>,
    ) {
        if self.add_job.is_some() {
            self.message(
                "Factum",
                "Files are being added already. Wait for it, or cancel it in the status bar.",
            );
            return;
        }
        let result = self.factum().open_container_for_add(id);
        let Some(volume) = self.run(result) else { return };
        let name = self.factum().container(id).map(|d| d.summary.name).unwrap_or_default();
        let ctx = self.egui_ctx.clone();
        let (worker, progress) = workers::add_to_container(&ctx, volume, sources, options, cancel.clone());
        self.add_job = Some(AddJob {
            container_id: id,
            name,
            worker,
            progress,
            cancel,
        });
    }

    /// Logs and lists what the worker staged, and says what happened.
    fn finish_add(&mut self, id: i64, result: workers::AddResult) {
        self.dirty = true;
        let (mut volume, staged) = match result {
            Ok(done) => done,
            Err(e) if e.contains("nothing was added") => return self.message("Factum", "Nothing was added."),
            Err(e) => return self.message("Factum", e),
        };
        let mut notes = Vec::new();
        if !staged.skipped.is_empty() {
            let lines: Vec<String> = staged
                .skipped
                .iter()
                .map(|(path, why)| format!("  {path}: {why}"))
                .collect();
            notes.push(format!("Skipped:\n{}", lines.join("\n")));
        }
        if !staged.errors.is_empty() {
            let lines: Vec<String> = staged
                .errors
                .iter()
                .map(|(path, why)| format!("  {path}: {why}"))
                .collect();
            notes.push(format!("Errors:\n{}", lines.join("\n")));
        }
        let (count, bytes, folders) = (staged.records.len(), staged.bytes(), staged.folders.len());
        let result = self.factum().commit_container_add(id, &mut volume, staged);
        drop(volume);
        let head = match result {
            Ok(_) if count == 0 => format!("{folders} folder{} added.", if folders == 1 { "" } else { "s" }),
            Ok(_) => format!(
                "{count} file{} added ({}).",
                if count == 1 { "" } else { "s" },
                crate::containers::human_size(bytes)
            ),
            Err(e) => e.to_string(),
        };
        notes.insert(0, head);
        self.message("Factum", notes.join("\n\n"));
    }

    fn container_action(&mut self, action: ContainerAction, _ctx: &egui::Context) {
        let summary = |app: &Self, id: i64| app.factum().container(id).ok().map(|d| d.summary);
        // a running addition holds the container's lock: changing it has to wait
        let changes = matches!(
            action,
            ContainerAction::AddFiles(_)
                | ContainerAction::AddFolder(_)
                | ContainerAction::Close(_)
                | ContainerAction::Reopen(_)
        );
        if let Some(job) = self.add_job.as_ref().filter(|_| changes) {
            let message = format!(
                "Files are being added to \"{}\". Wait for it, or cancel it in the status bar.",
                job.name
            );
            self.message("Factum", message);
            return;
        }
        match action {
            ContainerAction::ShowEntry(entry_id) => self.jump_to_entry(entry_id),
            ContainerAction::Locate(id) => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("AFF4-L container", &["aff4l"])
                    .pick_file()
                {
                    self.locate_container(id, &path);
                }
            }
            ContainerAction::ShowInFolder(id) => {
                if let Some(path) = summary(self, id).and_then(|s| s.path)
                    && let Err(e) = containers::show_in_folder(&path)
                {
                    self.message("Factum", format!("The folder cannot be opened: {e}"));
                }
            }
            ContainerAction::Close(id) => {
                let result = self.factum().close_container(id);
                if let Some(close) = self.run(result)
                    && let Some(reason) = close.x509_refused
                {
                    self.message(
                        "Container closed",
                        format!("Container #{id} was closed and signed with GPG only. X.509: {reason}"),
                    );
                }
            }
            ContainerAction::CloseWithoutFile(id) => {
                self.dialogs.push(Dialog::Confirm {
                    message: format!(
                        "The file of container #{id} is missing. Close the container without it? The case log \
                         records that it was closed while its file was missing; nothing is signed or written. If \
                         you can find the file, use Locate… and close it as usual instead."
                    ),
                    then: Pending::CloseContainerWithoutFile(id),
                });
            }
            ContainerAction::Reopen(id) => {
                let result = self.factum().reopen_container(id);
                self.run(result);
            }
            ContainerAction::AddFiles(id) | ContainerAction::AddFolder(id) => {
                let base = self.factum().container(id).map(|d| d.base_path).unwrap_or_default();
                let dialog = rfd::FileDialog::new().set_directory(&base);
                let picked = if matches!(action, ContainerAction::AddFiles(_)) {
                    dialog.pick_files().unwrap_or_default()
                } else {
                    dialog.pick_folder().into_iter().collect()
                };
                if !picked.is_empty() {
                    self.open_add_to_container(id, picked);
                }
            }
            ContainerAction::Verify(id) => {
                if let Some(path) = summary(self, id).and_then(|s| s.path) {
                    self.verify_container_file(path);
                }
            }
        }
        self.dirty = true;
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
            Pending::CloseContainersAndArchive(case_id) => {
                for container in self.factum().open_containers(case_id).unwrap_or_default() {
                    let closed = if container.missing {
                        let result = self.factum().close_container_without_file(container.id);
                        self.run(result).is_some()
                    } else {
                        let result = self.factum().close_container(container.id);
                        self.run(result).is_some()
                    };
                    if !closed {
                        return;
                    }
                }
                self.carry_out(Pending::Archive(case_id));
            }
            Pending::CloseContainerWithoutFile(id) => {
                let result = self.factum().close_container_without_file(id);
                self.run(result);
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
                name: String::new(),
                hash: String::new(),
                details: String::new(),
                error: None,
            });
        }
    }

    fn open_edit_evidence(&mut self, evidence_id: i64) {
        if let Ok(Some(evidence)) = self.factum().get_evidence(evidence_id) {
            self.dialogs.push(Dialog::EditEvidence {
                evidence_id,
                name: evidence.description,
                hash: evidence.evidence_hash,
                details: evidence.details,
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
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.verified
            .insert(report.case.id, (report.overall(), now, report.tree_size));
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
        let open = self.factum().open_containers(case_id).unwrap_or_default();
        if let Some(job) = self
            .add_job
            .as_ref()
            .filter(|job| open.iter().any(|c| c.id == job.container_id))
        {
            let message = format!(
                "Files are being added to \"{}\" in this case. Wait for it, or cancel it in the status bar.",
                job.name
            );
            self.message("Factum", message);
            return;
        }
        if !open.is_empty() {
            let names: Vec<String> = open.iter().map(|c| format!("#{} \"{}\"", c.id, c.name)).collect();
            let missing: Vec<String> = open
                .iter()
                .filter(|c| c.missing)
                .map(|c| format!("#{}", c.id))
                .collect();
            let missing = match missing.len() {
                0 => String::new(),
                1 => format!(
                    " The file of {} is missing: it is closed without its file (the log records that; nothing is \
                     signed).",
                    missing[0]
                ),
                _ => format!(
                    " The files of {} are missing: they are closed without their files (the log records that; \
                     nothing is signed).",
                    missing.join(", ")
                ),
            };
            self.dialogs.push(Dialog::Confirm {
                message: format!(
                    "Container{} {} {} open. Close {} (each close is signed) and archive the case '{}'?{missing}",
                    if open.len() == 1 { "" } else { "s" },
                    names.join(", "),
                    if open.len() == 1 { "is" } else { "are" },
                    if open.len() == 1 { "it" } else { "them" },
                    case.case_name
                ),
                then: Pending::CloseContainersAndArchive(case_id),
            });
            return;
        }
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
        let Some(count) = self.run(result) else { return };
        // the entries are signed already: say so even when the containers are not
        let (containers, skipped) = match self.factum().sign_unsigned_containers(case_id) {
            Ok(done) => done,
            Err(e) => (0, vec![format!("Containers: {e}")]),
        };
        let mut text = format!("Signed {} item(s).", count + containers);
        if !skipped.is_empty() {
            text += &format!("\n\nNot signed:\n{}", skipped.join("\n"));
        }
        self.message("Factum", text);
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
        let result = note_editor::check_shown(&text, &self.composer_images).and_then(|()| {
            self.factum()
                .create_note_with_images(&text, &self.composer_images, self.evidence_id, case.id)
        });
        if self.run(result).is_some() {
            self.composer.clear();
            self.composer_images.clear();
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

    /// The picture of a note at the size it was decoded to (larger than the GPU takes: scaled down), scrolled.
    fn image_viewer_window(&mut self, ctx: &egui::Context) {
        let Some((entry_id, image)) = &self.image_viewer else {
            return;
        };
        let texture = markup_view::texture(ctx, *entry_id, image);
        let mut open = true;
        dialogs::report_window(
            ctx,
            egui::Id::unique("image-viewer"),
            &format!("Image {}", image.id),
            &mut open,
            [720.0, 540.0],
            0.0,
            |ui| match &texture {
                Some(texture) => {
                    egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                        ui.image((texture.id(), texture.size_vec2()));
                    });
                }
                None => {
                    ui.label(
                        RichText::new(format!("[image {} could not be shown]", image.id))
                            .color(theme::current(ctx).muted),
                    );
                }
            },
        );
        if !open {
            self.image_viewer = None;
        }
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
            CardAction::AddLabel(entry_id) => {
                // the tags and labels in use, without the ones the note already has
                let own: Vec<String> = crate::tags::get_tags_for_entry(&self.db.conn, entry_id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(tag, _)| tag)
                    .collect();
                let known = crate::tags::tag_counts(&self.db.conn)
                    .inspect_err(|e| log::error!("The tags in use cannot be read: {e}"))
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|(tag, _)| !own.contains(tag))
                    .collect();
                self.dialogs.push(Dialog::AddLabel {
                    entry_id,
                    label: String::new(),
                    known,
                    highlight: None,
                });
            }
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
                        images: newest.images(),
                        text: newest.text,
                        error: None,
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
            CardAction::OpenImage(entry_id, image_id) => {
                // the card's images are decoded already
                let factum = self.factum();
                let image = self
                    .card_images(&factum, entry_id)
                    .map(|images| images::find(&images, &image_id).cloned());
                match self.run(image) {
                    Some(Some(image)) => self.image_viewer = Some((entry_id, image)),
                    Some(None) => log::warn!("Image {image_id} of entry #{entry_id} not found."),
                    None => {}
                }
                self.dirty = false; // looking changes nothing
            }
            CardAction::ToggleHistory(entry_id) => {
                if !self.history_open.remove(&entry_id) {
                    self.history_open.insert(entry_id);
                }
            }
        }
    }

    fn handle_dialog_result(&mut self, result: DialogResult, ctx: &egui::Context) {
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
                name,
                hash,
                details,
            } => {
                let result = self.factum().create_evidence(case_id, &name, &hash, &details);
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
            DialogResult::EditEvidence { evidence_id, details } => {
                let result = self.factum().update_evidence_details(evidence_id, &details);
                self.run(result);
            }
            DialogResult::AddLabel { entry_id, label } => {
                let result = crate::tags::add_label(&self.db, entry_id, &label);
                self.run(result);
            }
            // archiving seals the case; closing its containers first signs them: both ask about a missing key
            DialogResult::Confirmed(pending @ (Pending::Archive(_) | Pending::CloseContainersAndArchive(_))) => {
                self.with_key_check(pending)
            }
            DialogResult::Confirmed(pending) => self.carry_out(pending),
            DialogResult::NewContainer {
                case_id,
                evidence_id,
                name,
                hash,
                details,
                path,
                acquire,
            } => {
                let base = acquire.as_ref().map(|a| a.display().to_string()).unwrap_or_default();
                let result = match evidence_id {
                    Some(evidence_id) => self
                        .factum()
                        .create_container(case_id, &name, evidence_id, &path, &base)
                        .map(|id| (evidence_id, id)),
                    None => self
                        .factum()
                        .create_evidence_with_container(case_id, &name, &hash, &details, &path, &base),
                };
                if let Some((evidence_id, id)) = self.run(result) {
                    self.select(Some(case_id), Some(evidence_id));
                    if let Some(acquire) = acquire {
                        let options = crate::container::volume::AddOptions {
                            base: acquire.clone(),
                            keep_path: true,
                            ..Default::default()
                        };
                        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        self.start_add(id, vec![acquire], options, cancel);
                    }
                }
            }
            DialogResult::X509 {
                certificate,
                chain_files,
            } => self.save_x509(certificate, chain_files),
            DialogResult::AddToContainer {
                container_id,
                sources,
                options,
            } => {
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                self.start_add(container_id, sources, options, cancel);
            }
            DialogResult::TypedConfirmed { case_id, typed } => {
                let result = self.factum().delete_case_permanently(case_id, &typed);
                if self.run(result).is_some()
                    && let Some(cdb) = &self.companion_db
                {
                    if let Err(e) = cdb.delete_case(case_id) {
                        log::error!("The companion data of case {case_id} cannot be deleted: {e}");
                    }
                    self.companion_seen.remove(&case_id);
                    // a pass that was running may write rows again; the thread removes them after it
                    self.send_companion(Command::CaseDeleted(case_id));
                }
                self.select(None, None);
            }
            DialogResult::Correct { entry_id, text, images } => {
                let result = self.factum().correct_note_with_images(entry_id, &text, &images);
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
            // the default folder is stored as no setting, so it follows the database
            DialogResult::SealFolder(folder) if folder == self.factum().default_seal_dir().display().to_string() => {
                let _ = self.db.delete_setting(SEAL_DIR_SETTING);
            }
            DialogResult::SealFolder(folder) => {
                let _ = self.db.set_setting(SEAL_DIR_SETTING, &folder);
            }
            DialogResult::WizardFinished(choices) => self.finish_wizard(ctx, *choices),
            DialogResult::WizardCancelled { theme } => {
                theme::apply(ctx, &theme);
                let _ = self.db.set_setting(ONBOARDING_SETTING, "1");
            }
            // the dialog has saved them (creating the database on first use)
            DialogResult::CompanionSettings(settings) => {
                if self.open_companion_db() {
                    self.apply_companion_settings(ctx, settings);
                }
            }
            DialogResult::CaseGoal { case_id, goal } => {
                let Some(cdb) = &self.companion_db else { return };
                let saved = cdb.set_case_goal(case_id, &goal);
                if self.run(saved).is_some() {
                    self.send_companion(Command::GoalChanged(case_id));
                }
            }
        }
    }

    fn open_case_goal(&mut self, case_id: i64) {
        let Some(cdb) = &self.companion_db else { return };
        match cdb.case_settings(case_id) {
            Ok(case) => self.dialogs.push(Dialog::CaseGoal {
                case_id,
                goal: case.map(|c| c.goal).unwrap_or_default(),
            }),
            Err(e) => self.message("Factum", format!("The case goal cannot be read: {e}")),
        }
    }

    fn set_companion_for_case(&mut self, case_id: i64, enabled: bool) {
        let Some(cdb) = &self.companion_db else { return };
        let saved = cdb.set_case_enabled(case_id, enabled);
        if self.run(saved).is_some() {
            self.send_companion(Command::CaseToggled(case_id));
        }
    }

    fn handle_panel_action(&mut self, action: PanelAction) {
        let case_id = self.view.companion.as_ref().map(|c| c.case_id);
        match action {
            PanelAction::Jump(entry_id) => self.jump_to_entry(entry_id),
            PanelAction::Rate(question_id, rating) => {
                let Some(cdb) = &self.companion_db else { return };
                let rated = cdb.rate_question(question_id, rating);
                self.run(rated);
            }
            PanelAction::SetGoal => {
                if let Some(case_id) = case_id {
                    self.open_case_goal(case_id);
                }
            }
            PanelAction::OpenHistory => {
                if let Some(case_id) = case_id {
                    self.open_companion_window(CompanionWindow::History {
                        case_id,
                        rows: Vec::new(),
                        open: true,
                    });
                }
            }
            PanelAction::OpenAsk => {
                if let Some(case_id) = case_id {
                    self.open_companion_window(CompanionWindow::Ask {
                        case_id,
                        question: String::new(),
                        answer: None,
                        error: None,
                        running: false,
                        open: true,
                    });
                }
            }
            PanelAction::Rethink => {
                if let Some(case_id) = case_id {
                    self.send_companion(Command::Rethink(case_id));
                }
            }
            PanelAction::OpenSettings => self.open_companion_settings(),
        }
    }

    /// Opens the window, unless one of its kind is already open for the case.
    fn open_companion_window(&mut self, window: CompanionWindow) {
        let same = |w: &CompanionWindow| match (w, &window) {
            (CompanionWindow::History { case_id: a, .. }, CompanionWindow::History { case_id: b, .. })
            | (CompanionWindow::Ask { case_id: a, .. }, CompanionWindow::Ask { case_id: b, .. }) => a == b,
            _ => false,
        };
        if !self.companion_windows.iter().any(same) {
            self.companion_windows.push(window);
            self.reload_history();
        }
    }

    fn handle_window_action(&mut self, action: WindowAction, ctx: &egui::Context) {
        match action {
            WindowAction::Jump(entry_id) => self.jump_to_entry(entry_id),
            WindowAction::Unlink(question_id) => {
                let Some(cdb) = &self.companion_db else { return };
                let unlinked = cdb.unlink_question(question_id);
                self.run(unlinked);
            }
            WindowAction::Restore(question_id) => {
                let Some(cdb) = &self.companion_db else { return };
                let restored = cdb.restore_question(question_id);
                self.run(restored);
            }
            WindowAction::Ask { case_id, question } => {
                let Some(cdb) = &self.companion_db else { return };
                let worker = workers::ask(
                    ctx,
                    self.db.path.clone(),
                    cdb.path.clone(),
                    self.companion_settings.clone(),
                    case_id,
                    question,
                );
                self.ask_jobs.push((case_id, worker));
                self.set_ask_state(case_id, |answer, error, running| {
                    *answer = None;
                    *error = None;
                    *running = true;
                });
            }
            WindowAction::CopyAnswer(text) => ctx.copy_text(text),
        }
    }

    /// Updates the Ask window of the case, if it is still open.
    fn set_ask_state(&mut self, case: i64, f: impl FnOnce(&mut Option<Answer>, &mut Option<String>, &mut bool)) {
        for window in &mut self.companion_windows {
            if let CompanionWindow::Ask {
                case_id,
                answer,
                error,
                running,
                ..
            } = window
                && *case_id == case
            {
                f(answer, error, running);
                return;
            }
        }
    }

    fn open_companion_settings(&mut self) {
        let dialog = CompanionSettingsDialog::new(&self.companion_settings, self.db.path.clone());
        self.dialogs.push(Dialog::CompanionSettings(Box::new(dialog)));
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
            (SIDE_PANEL, "Side Panel"),
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
        let _ = self
            .db
            .set_setting(TREE_WIDTH_SETTING, &format!("{:.0}", self.tree_width));
        let _ = self
            .db
            .set_setting(COMPOSER_HEIGHT_SETTING, &format!("{:.0}", self.composer_height));
    }

    fn quit(&mut self) {
        // a running verification is not torn down: let it finish first
        if let Some(job) = self.verify_job.as_mut() {
            job.worker.wait();
        }
        if let Some(worker) = self.signature_worker.as_mut() {
            worker.wait();
        }
        // a pass can take minutes; its writes are transactional, so the thread is left to end on its own
        if let Some(companion) = self.companion.take() {
            companion.detach();
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
                    .on_hover_text("Case created, evidence added, …")
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
                        egui::Button::selectable(self.side_panel, "Side Panel")
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
                if ui.button("Signing Key…").clicked() {
                    self.open_gpg_keys();
                }
                if ui.button("X.509 Certificate…").clicked() {
                    self.open_x509();
                }
                if ui
                    .add_enabled(
                        self.signer.active_key().is_some(),
                        egui::Button::new("Clear Signing Key"),
                    )
                    .clicked()
                {
                    self.signer.clear_active_key(&self.db);
                    self.update_gpg_status();
                }
                if ui.button("Seal Folder…").clicked() {
                    self.choose_seal_folder();
                }
                if ui
                    .add_enabled(!self.companion_db_failed, egui::Button::new("Companion…"))
                    .on_disabled_hover_text("Companion database unreadable (see the log)")
                    .clicked()
                {
                    self.open_companion_settings();
                }
                ui.separator();
                if ui.button("Setup Wizard…").clicked() {
                    self.open_wizard();
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
        if ui
            .add_enabled(
                is_open && self.evidence_id.is_some(),
                egui::Button::new("Edit Evidence…"),
            )
            .clicked()
        {
            self.open_edit_evidence(self.evidence_id.unwrap());
        }
        if ui.add_enabled(is_open, egui::Button::new("New Container…")).clicked() {
            self.open_new_container(case_id.unwrap());
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
        if ui.button("Verify Container…").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("AFF4-L container", &["aff4l", "aff4"])
                .pick_file()
        {
            self.verify_container_file(path);
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
            .on_disabled_hover_text("Only evidence without notes");
        if delete.clicked() {
            self.delete_evidence(self.evidence_id.unwrap());
        }
        if ui
            .add_enabled(archived, egui::Button::new("Delete Case Permanently…"))
            .clicked()
        {
            self.delete_case(case_id.unwrap());
        }
        if self.companion_db.is_some() && self.companion_settings.is_configured() {
            ui.separator();
            let companion_case = self.view.companion.as_ref().map(|c| c.case_id);
            let mut enabled = self.view.companion.as_ref().is_some_and(|c| c.enabled_for_case);
            let toggle = ui.add_enabled(
                companion_case.is_some(),
                egui::Checkbox::new(&mut enabled, "Companion for this case"),
            );
            if toggle.changed()
                && let Some(case_id) = companion_case
            {
                self.set_companion_for_case(case_id, enabled);
            }
            if ui
                .add_enabled(companion_case.is_some(), egui::Button::new("Case goal…"))
                .clicked()
                && let Some(case_id) = companion_case
            {
                self.open_case_goal(case_id);
            }
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
        ui.add_space(6.0);
        header_row(ui, |ui| {
            Self::panel_header(ui, "Cases");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                IconButton::new(icons::MORE, "Case actions").menu(ui, |ui| self.case_menu(ui, ctx));
                let new_case = IconButton::new(icons::PLUS, "New case")
                    .shortcut(ctx.format_shortcut(&NEW_CASE))
                    .color(p.accent)
                    .show(ui);
                if new_case.clicked() {
                    self.open_new_case();
                }
            });
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let mut clicked: Option<(Option<i64>, Option<i64>)> = None;
            let mut clicked_container: Option<i64> = None;
            let mut menu_action: Option<TreeAction> = None;
            let new_evidence = ctx.format_shortcut(&NEW_EVIDENCE);
            for node in &self.view.tree {
                let case = &node.case;
                let selected = self.case_id == Some(case.id) && self.container_id.is_none();
                let (name, color) = if case.is_archived() {
                    (format!("{}  {}", case.case_name, icons::ARCHIVE), p.muted)
                } else {
                    (case.case_name.clone(), p.text)
                };
                let (response, add_evidence) = tree_row(
                    ui,
                    selected,
                    RichText::new(name).family(theme::bold()).color(color),
                    (node.notes, "note"),
                    4.0,
                    (!case.is_archived()).then_some(new_evidence.as_str()),
                    None,
                    None,
                );
                let response = response.on_hover_text(format!(
                    "{} — {}{}",
                    case.case_file,
                    case.case_name,
                    if case.is_archived() { " (archived)" } else { "" }
                ));
                if add_evidence {
                    menu_action = Some(TreeAction::NewEvidence(case.id));
                } else if response.clicked() {
                    clicked = Some((Some(case.id), None));
                }
                response.context_menu(|ui| {
                    if !case.is_archived() {
                        if ui
                            .add(egui::Button::new("New Evidence…").shortcut_text(&new_evidence))
                            .clicked()
                        {
                            menu_action = Some(TreeAction::NewEvidence(case.id));
                        }
                        if ui.button("Edit Case…").clicked() {
                            menu_action = Some(TreeAction::Edit(case.id));
                        }
                        if ui.button("New Container…").clicked() {
                            menu_action = Some(TreeAction::NewContainer(case.id));
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
                    let held: Vec<&crate::containers::ContainerSummary> = node
                        .containers
                        .iter()
                        .filter(|c| c.evidence_id == Some(evidence.id))
                        .collect();
                    let symbol_hover = (!held.is_empty()).then(|| containers::symbol_hover(&held));
                    let symbol = symbol_hover.as_deref().map(|hover| {
                        let color = if held.iter().any(|c| c.open) { p.accent } else { p.muted };
                        (icons::CONTAINER, hover, color)
                    });
                    let (response, _) = tree_row(
                        ui,
                        selected,
                        RichText::new(&evidence.description).color(color),
                        (*count, "note"),
                        20.0,
                        None,
                        held.iter()
                            .any(|c| c.missing)
                            .then_some(("⚠", "Container file missing")),
                        symbol,
                    );
                    let response = response.on_hover_text(if evidence.details.is_empty() {
                        evidence.description.clone()
                    } else {
                        format!("{}\n\n{}", evidence.description, evidence.details)
                    });
                    if response.clicked() {
                        clicked = Some((None, Some(evidence.id)));
                    }
                    response.context_menu(|ui| {
                        if ui.button("Set as CLI Active Evidence").clicked() {
                            menu_action = Some(TreeAction::CliEvidence(evidence.id));
                        }
                        if !case.is_archived() {
                            if ui.button("Edit Description…").clicked() {
                                menu_action = Some(TreeAction::EditEvidence(evidence.id));
                            }
                            if ui.button("New Container…").clicked() {
                                menu_action = Some(TreeAction::NewContainerFor(evidence.id));
                            }
                            ui.separator();
                            let empty = *count == 0
                                && held.is_empty()
                                && !self.factum().has_entries(evidence.id).unwrap_or(true);
                            if ui
                                .add_enabled(empty, egui::Button::new("Delete Evidence…"))
                                .on_disabled_hover_text("Only evidence without notes or containers")
                                .clicked()
                            {
                                menu_action = Some(TreeAction::DeleteEvidence(evidence.id));
                            }
                        }
                    });
                }
                // containers without a live evidence item (from before 2.8, or their evidence was deleted): rows
                // of their own
                let live: std::collections::HashSet<i64> = node.evidence.iter().map(|(e, _)| e.id).collect();
                for summary in node
                    .containers
                    .iter()
                    .filter(|c| c.evidence_id.is_none_or(|e| !live.contains(&e)))
                {
                    let selected = self.container_id == Some(summary.id);
                    let color = if case.is_archived() { p.muted } else { p.secondary };
                    let hover = containers::symbol_hover(&[summary]);
                    let symbol_color = if summary.open { p.accent } else { p.muted };
                    let (response, _) = tree_row(
                        ui,
                        selected,
                        RichText::new(&summary.name).color(color),
                        (summary.file_count as usize, "file"),
                        20.0,
                        None,
                        summary.missing.then_some(("⚠", "File missing")),
                        Some((icons::CONTAINER, &hover, symbol_color)),
                    );
                    let response =
                        response.on_hover_text(containers::row_hover(summary, summary.evidence_id.is_some()));
                    if response.clicked() {
                        clicked_container = Some(summary.id);
                    }
                    response.context_menu(|ui| {
                        let mut actions = Vec::new();
                        let busy = self.add_job.as_ref().is_some_and(|job| job.container_id == summary.id);
                        containers::menu(ui, summary, case.is_archived(), busy, &mut actions);
                        if let Some(action) = actions.pop() {
                            menu_action = Some(TreeAction::Container(action));
                        }
                    });
                }
            }
            // archived cases are hidden by default; the list says how many there are
            if self.view.archived_cases > 0 {
                ui.add_space(8.0);
                let text = RichText::new(format!("{}  {} archived", icons::ARCHIVE, self.view.archived_cases))
                    .size(SMALL_SIZE)
                    .color(if self.show_archived { p.accent } else { p.muted });
                let button = egui::Button::new(text).frame_when_inactive(self.show_archived);
                let button = if self.show_archived {
                    button.fill(p.accent_soft).stroke(egui::Stroke::NONE)
                } else {
                    button
                };
                let toggle = ui.add(button).on_hover_text(if self.show_archived {
                    "Hide archived cases"
                } else {
                    "Show archived cases"
                });
                if toggle.clicked() {
                    self.show_archived = !self.show_archived;
                    self.dirty = true;
                }
            }
            if let Some((case_id, evidence_id)) = clicked {
                self.select(case_id, evidence_id);
            }
            if let Some(id) = clicked_container {
                self.select_container(id);
            }
            if let Some(action) = menu_action {
                self.tree_action(action, ctx);
            }
        });
    }

    fn tree_action(&mut self, action: TreeAction, ctx: &egui::Context) {
        match action {
            TreeAction::NewEvidence(case_id) => {
                self.select(Some(case_id), None);
                self.dialogs.push(Dialog::NewEvidence {
                    case_id,
                    name: String::new(),
                    hash: String::new(),
                    details: String::new(),
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
            TreeAction::EditEvidence(evidence_id) => self.open_edit_evidence(evidence_id),
            TreeAction::NewContainer(case_id) => {
                self.select(Some(case_id), None);
                self.open_new_container(case_id);
            }
            TreeAction::NewContainerFor(evidence_id) => self.open_new_container_for(evidence_id),
            TreeAction::Container(action) => self.container_action(action, ctx),
        }
    }

    /// One centred column for the search, the log and the composer: the log keeps its line length on wide screens.
    fn notes_area(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let width = ui.available_width().min(MAX_CARD_WIDTH);
        let left = ((ui.available_width() - width) / 2.0).max(0.0);
        let column = egui::Rect::from_min_size(
            ui.cursor().min + egui::vec2(left, 0.0),
            egui::vec2(width, ui.available_height()),
        );
        ui.scope_builder(egui::UiBuilder::new().max_rect(column), |ui| self.notes_column(ui, ctx));
    }

    fn notes_column(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let mut actions = Vec::new();
        ui.add_space(6.0);
        header_row(ui, |ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                let toggle = IconButton::new(icons::SIDE_PANEL, "Side panel")
                    .shortcut(ctx.format_shortcut(&SIDE_PANEL))
                    .selected(self.side_panel)
                    .show(ui);
                if toggle.clicked() {
                    self.side_panel = !self.side_panel;
                }
                if self.view.case.is_some() && self.container_id.is_none() {
                    ui.add_space(8.0);
                    ui.label(RichText::new(&self.view.note_count).size(SMALL_SIZE).color(p.muted));
                }
                ui.add_space(8.0);
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| self.search_field(ui, ctx));
            });
        });
        ui.separator();

        // a container selected on its own (a row of its own, no evidence item) is shown without notes and composer
        if self.container_id.is_some() {
            egui::ScrollArea::vertical()
                .id_salt("container-alone")
                .auto_shrink([false, false])
                .show(ui, |ui| self.container_sections(ui, ctx));
            return;
        }

        // the composer at the bottom, resizable at its top edge; the log takes the rest
        match self.view.case.clone() {
            None => {}
            Some(case) if case.is_archived() => {
                egui::Panel::bottom("archived-panel")
                    .resizable(false)
                    .frame(egui::Frame::new().inner_margin(Margin::symmetric(0, 8)))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icons::ARCHIVE).size(theme::ICON_SIZE).color(p.muted));
                            ui.label(RichText::new(format!("{} (archived, read-only)", case.case_name)).color(p.muted));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button("Reopen").on_hover_text("Reopen for notes").clicked() {
                                    let result = self.factum().reopen_case(case.id);
                                    self.run(result);
                                }
                            });
                        });
                    });
            }
            Some(_) => {
                // with thumbnails the panel is taller; it keeps a size of its own, and the saved height is without
                let strip = if self.composer_images.is_empty() {
                    0.0
                } else {
                    note_editor::THUMBNAIL_STRIP
                };
                let max_composer = (ui.available_height() - 120.0).max(MIN_COMPOSER_HEIGHT + strip);
                let composer = egui::Panel::bottom(if strip > 0.0 {
                    "composer-panel-images"
                } else {
                    "composer-panel"
                })
                .resizable(true)
                .default_size((self.composer_height + strip).clamp(MIN_COMPOSER_HEIGHT + strip, max_composer))
                .size_range(MIN_COMPOSER_HEIGHT + strip..=max_composer)
                .frame(egui::Frame::new().inner_margin(Margin { top: 6, ..Margin::ZERO }))
                .show(ui, |ui| self.composer(ui, ctx));
                self.composer_height = composer.response.rect.height() - strip;
            }
        }
        let now = chrono::Utc::now();
        egui::ScrollArea::vertical()
            .id_salt("notes")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(8.0);
                if self.view.tree.is_empty() {
                    self.first_case(ui, ctx);
                } else if let Some(text) = &self.view.empty_text {
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
                self.container_sections(ui, ctx);
                ui.add_space(8.0);
            });
        for action in actions {
            self.handle_card_action(action, ctx);
        }
    }

    /// The shown containers, one section each, below the notes.
    fn container_sections(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let archived = self.view.case.as_ref().is_some_and(|c| c.is_archived());
        let mut container_actions = Vec::new();
        for detail in &self.view.containers {
            let busy = self
                .add_job
                .as_ref()
                .is_some_and(|job| job.container_id == detail.summary.id);
            let times = self
                .view
                .container_times
                .get(&detail.summary.id)
                .cloned()
                .unwrap_or_default();
            containers::container_section(ui, detail, &times, (archived, busy), &mut container_actions);
        }
        for action in container_actions {
            self.container_action(action, ctx);
        }
    }

    /// The search field: a magnifier, the text and, while there is one, a button that clears it.
    fn search_field(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let id = egui::Id::unique("search");
        let stroke = if ui.memory(|m| m.has_focus(id)) {
            ui.visuals().selection.stroke
        } else {
            ui.visuals().widgets.inactive.bg_stroke
        };
        let width = ui.available_width().min(340.0);
        egui::Frame::new()
            .fill(ui.visuals().text_edit_bg_color())
            .stroke(stroke)
            .corner_radius(ui.visuals().widgets.inactive.corner_radius)
            .inner_margin(Margin::symmetric(6, 0))
            .show(ui, |ui| {
                ui.set_width(width - 14.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    ui.label(RichText::new(icons::SEARCH).size(theme::ICON_SIZE).color(p.muted));
                    let clear = !self.filter.is_empty();
                    let field_width = ui.available_width() - if clear { 26.0 } else { 0.0 };
                    let search = ui
                        .add(
                            TextEdit::singleline(&mut self.filter)
                                .id(id)
                                .frame(egui::Frame::NONE.inner_margin(Margin::symmetric(4, 4)))
                                .hint_text("Search, or #tag")
                                .desired_width(field_width),
                        )
                        .on_hover_text(format!("Search notes ({})", ctx.format_shortcut(&SEARCH)));
                    if std::mem::take(&mut self.focus_search) {
                        search.request_focus();
                    }
                    if search.changed() {
                        self.dirty = true;
                    }
                    if clear && IconButton::new(icons::CLOSE, "Clear search").show(ui).clicked() {
                        self.filter.clear();
                        self.dirty = true;
                    }
                });
            });
    }

    /// The log area of a database without cases: one way in.
    fn first_case(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let shortcut = ctx.format_shortcut(&NEW_CASE);
        ui.add_space(56.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("No cases yet").heading().color(p.secondary));
            ui.add_space(10.0);
            let button = egui::Button::new(
                RichText::new(format!("{}  New case", icons::PLUS))
                    .color(p.on_accent)
                    .family(theme::bold()),
            )
            .fill(p.accent)
            .min_size(egui::vec2(140.0, 32.0));
            if ui.add(button).on_hover_text(&shortcut).clicked() {
                self.open_new_case();
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("or press {shortcut}"))
                    .size(SMALL_SIZE)
                    .color(p.muted),
            );
        });
    }

    /// The editor filling the panel's height; below it where the note goes, and the Add button.
    fn composer(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let Some(case) = self.view.case.clone() else { return };
        egui::Panel::bottom("composer-buttons")
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::NONE)
            .show(ui, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let add = egui::Button::new(RichText::new("Add").color(p.on_accent).family(theme::bold()))
                            .fill(p.accent)
                            .min_size(egui::vec2(72.0, 28.0));
                        if ui
                            .add(add)
                            .on_hover_text(format!("Add note ({})", ctx.format_shortcut(&ADD_NOTE)))
                            .clicked()
                        {
                            self.submit_note();
                        }
                        // the key itself is in the status bar; here only the warning that notes go unsigned
                        if self.signer.active_key().is_none() {
                            let tip = if self.signer.available() {
                                "Unsigned: no signing key"
                            } else {
                                "Unsigned: GPG not installed"
                            };
                            let warning = egui::Button::new(RichText::new("⚠").size(theme::NOTE_SIZE).color(p.warn))
                                .frame_when_inactive(false);
                            if ui.add(warning).on_hover_text(tip).clicked() && self.signer.available() {
                                self.open_gpg_keys();
                            }
                        }
                        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                            let mut target = case.case_name.clone();
                            if let Some(evidence) = &self.view.evidence {
                                target += &format!(" › {}", evidence.description);
                            }
                            ui.add(
                                egui::Label::new(RichText::new(target).size(SMALL_SIZE).color(p.secondary)).truncate(),
                            )
                            .on_hover_text("New notes go here");
                        });
                    });
                });
                ui.add_space(6.0);
            });
        let id = egui::Id::unique("composer");
        if !self.composer_images.is_empty() {
            egui::Panel::bottom("composer-thumbnails")
                .resizable(false)
                .show_separator_line(false)
                .frame(egui::Frame::NONE.inner_margin(Margin { top: 6, ..Margin::ZERO }))
                .show(ui, |ui| {
                    note_editor::thumbnails(ui, &mut self.composer, &mut self.composer_images)
                });
        }
        // run() marks the view for a rebuild: only for an error to show
        let toolbar = note_editor::toolbar(ui, id, &mut self.composer, &mut self.composer_images);
        let input = if self.dialogs.is_empty() {
            note_editor::handle_input(ctx, id, &mut self.composer, &mut self.composer_images)
        } else {
            Ok(())
        };
        if toolbar.is_err() || input.is_err() {
            self.run(toolbar.and(input));
        }
        // a longer note scrolls inside the frame, which keeps its place
        let stroke = if ui.memory(|m| m.has_focus(id)) {
            ui.visuals().selection.stroke
        } else {
            ui.visuals().widgets.inactive.bg_stroke
        };
        let inner = (ui.available_height() - 2.0 * stroke.width).max(24.0);
        let editor = egui::Frame::new()
            .fill(ui.visuals().text_edit_bg_color())
            .stroke(stroke)
            .corner_radius(ui.visuals().widgets.inactive.corner_radius)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("composer-scroll")
                    .auto_shrink([false, false])
                    .max_height(inner)
                    .min_scrolled_height(inner) // the default of 64 px would reach into the buttons
                    .show(ui, |ui| {
                        let field = TextEdit::multiline(&mut self.composer)
                            .hint_text(NOTE_PLACEHOLDER)
                            .font(egui::FontId::proportional(theme::NOTE_SIZE))
                            .frame(egui::Frame::NONE.inner_margin(Margin::symmetric(8, 6)))
                            .desired_width(f32::INFINITY)
                            // the panel sets the height, not the default of four rows
                            .desired_rows(1)
                            .min_size(egui::vec2(0.0, inner));
                        self.tag_completion.show(ui, &self.db, field, id)
                    })
                    .inner
            })
            .inner;
        if std::mem::take(&mut self.focus_composer) {
            editor.request_focus();
        }
    }

    /// Stacked: pinned notes on top, the companion's questions below, the IoCs collapsed at the bottom. Pinned and
    /// Questions scroll on their own, each within about 40 % of the panel, more when the other one is short.
    fn side_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let mut actions = Vec::new();
        let mut panel_actions = Vec::new();
        let questions_shown = self.view.companion.as_ref().is_some_and(|c| c.enabled_for_case);
        // room for the IoCs header below
        let share = 0.4 * (ui.available_height() - 60.0).max(120.0);
        let questions_height = if questions_shown {
            companion_panel::content_height(ctx)
        } else {
            0.0
        };
        let pinned_max = share + (share - questions_height).max(0.0);
        let questions_max = share + (share - self.pinned_height).max(0.0);

        ui.add_space(6.0);
        if self.view.case.is_none() {
            header_row(ui, |ui| Self::panel_header(ui, "Pinned"));
            ui.separator();
            ui.add_space(6.0);
            ui.label(
                RichText::new("The selected case's pinned notes, questions and IoCs show here.")
                    .size(SMALL_SIZE)
                    .color(p.muted),
            );
            return;
        }
        header_row(ui, |ui| {
            let pinned = if self.view.pinned.is_empty() {
                "PINNED".to_string()
            } else {
                format!("PINNED {}", self.view.pinned.len())
            };
            Self::panel_header(ui, &pinned);
            // the choice only means something while evidence is selected
            if self.view.evidence.is_some() {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    for (evidence, text, tip) in [
                        (true, "Evidence", "Pinned on this evidence"),
                        (false, "Case", "Pinned in the whole case"),
                    ] {
                        let chosen = self.pinned_scope_evidence == evidence;
                        let button = egui::Button::selectable(chosen, RichText::new(text).size(SMALL_SIZE))
                            .frame_when_inactive(false);
                        if ui.add(button).on_hover_text(tip).clicked() && !chosen {
                            self.pinned_scope_evidence = evidence;
                            self.dirty = true;
                        }
                    }
                });
            }
        });
        ui.separator();
        let pinned = egui::ScrollArea::vertical()
            .id_salt("pinned")
            .auto_shrink([false, true])
            .max_height(pinned_max)
            .show(ui, |ui| {
                if let Some(text) = &self.view.pinned_empty_text {
                    ui.add_space(6.0);
                    ui.label(RichText::new(text).size(SMALL_SIZE).color(p.muted));
                    ui.add_space(6.0);
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
            });
        let height = pinned.content_size.y;
        if (height - self.pinned_height).abs() > 0.5 {
            self.pinned_height = height;
            ctx.request_repaint(); // the questions take the rest of the split
        }

        if let Some(view) = self.view.companion.as_ref().filter(|c| c.enabled_for_case) {
            ui.add_space(12.0);
            // the header line on top of the rows' share
            let size = egui::vec2(ui.available_width(), questions_max + 28.0);
            ui.allocate_ui(size, |ui| {
                companion_panel::questions_section(
                    ui,
                    ctx,
                    view,
                    &self.companion_status,
                    &mut self.questions_open,
                    &mut panel_actions,
                );
            });
        }

        ui.add_space(8.0);
        ui.separator();
        let ioc_count: usize = self.view.iocs.values().map(Vec::len).sum();
        let iocs = match (self.iocs_open, ioc_count) {
            (true, 0) => "▾ IOCS".to_string(),
            (false, 0) => "▸ IOCS".to_string(),
            (true, n) => format!("▾ IOCS {n}"),
            (false, n) => format!("▸ IOCS {n}"),
        };
        let header = egui::Button::new(
            RichText::new(iocs)
                .size(SMALL_SIZE)
                .family(theme::bold())
                .color(p.muted)
                .extra_letter_spacing(1.2),
        )
        .frame(false);
        if ui
            .add(header)
            .on_hover_text("IPs, domains, hashes in the notes")
            .clicked()
        {
            self.iocs_open = !self.iocs_open;
        }
        if self.iocs_open && self.view.case.is_some() {
            egui::ScrollArea::vertical()
                .id_salt("iocs")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if self.view.iocs.is_empty() {
                        ui.label(
                            RichText::new("No IPs, domains or hashes in the notes.")
                                .size(SMALL_SIZE)
                                .color(p.muted),
                        );
                    }
                    for (ioc_type, values) in &self.view.iocs {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(format!("{} {}", ioc_type.to_uppercase(), values.len()))
                                .size(SMALL_SIZE)
                                .color(p.secondary),
                        );
                        for value in values {
                            ioc_row(ui, ctx, value);
                        }
                    }
                });
        }
        for action in actions {
            self.handle_card_action(action, ctx);
        }
        for action in panel_actions {
            self.handle_panel_action(action);
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = *theme::current(ctx);
        let small = |text: &str, color| RichText::new(text).size(SMALL_SIZE).color(color);
        let now = chrono::Utc::now();
        ui.horizontal(|ui| {
            // files being added to a container take the place of the case's status
            if let Some(job) = &self.add_job {
                ui.label(small(&containers::add_status(&job.progress, &job.name), p.secondary));
                if IconButton::new(icons::CLOSE, "Cancel").show(ui).clicked() {
                    job.cancel.store(true, Ordering::Relaxed);
                }
            } else if let (Some(case), Some(status)) = (&self.view.case, &self.view.case_status) {
                let entries = format!(
                    "{} entr{}",
                    status.entries,
                    if status.entries == 1 { "y" } else { "ies" }
                );
                ui.label(small(&entries, p.muted));
                ui.label(small("·", p.muted));
                let sealed = match &status.last_seal {
                    Some(utc) => format!("sealed {}", widgets::relative_time(utc, now)),
                    None => "not sealed".to_string(),
                };
                let tip = status
                    .last_seal
                    .as_deref()
                    .map(widgets::display_time)
                    .unwrap_or_else(|| "Case ▸ Seal Now".into());
                ui.label(small(&sealed, p.muted)).on_hover_text(tip);
                if let Some((level, utc, size)) = self.verified.get(&case.id)
                    && *size as usize == status.entries
                {
                    let (text, color) = match level {
                        Level::Ok => ("✓ verified", p.ok),
                        Level::Warn => ("⚠ verified with warnings", p.warn),
                        Level::Fail => ("✗ verification failed", p.fail),
                    };
                    ui.label(small("·", p.muted));
                    ui.label(small(text, color)).on_hover_text(format!(
                        "{} ({})",
                        widgets::display_time(utc),
                        widgets::relative_time(utc, now)
                    ));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (text, warning) = &self.gpg_status;
                let color = if *warning { p.warn } else { p.secondary };
                let key = egui::Button::new(
                    RichText::new(format!("{}  {text}", icons::KEY))
                        .size(SMALL_SIZE)
                        .monospace()
                        .color(color),
                )
                .frame_when_inactive(false);
                if ui.add(key).on_hover_text("Signing key").clicked() {
                    self.open_gpg_keys();
                }
                if self.companion.is_some() {
                    ui.add_space(12.0);
                    ui.label(small(&self.companion_status.line(), p.muted));
                }
                // only shown while a CLI target is set; the GUI selection is shown under the note input
                if !self.view.cli_active.is_empty() {
                    ui.add_space(12.0);
                    let tip = "factum \"text\" on the command line writes here (right-click → Set as CLI Active)";
                    ui.label(small(&self.view.cli_active, p.secondary)).on_hover_text(tip);
                    let icon = ui.label(small(icons::TERMINAL, p.muted)).on_hover_text(tip);
                    icon.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, "CLI target"));
                }
            });
        });
    }

    fn verification_progress(&mut self, ctx: &egui::Context) {
        let (started, progress, text, cancel) = match (&self.verify_job, &self.container_verify_job) {
            (Some(job), _) => (job.started, job.progress.clone(), "Verifying case…", None),
            (None, Some(job)) => (
                job.started,
                job.progress.clone(),
                "Verifying container…",
                Some(job.cancel.clone()),
            ),
            (None, None) => return,
        };
        if started.elapsed() < Duration::from_millis(300) {
            ctx.request_repaint_after(Duration::from_millis(100));
            return;
        }
        let done = progress.done.load(Ordering::Relaxed);
        let total = progress.total.load(Ordering::Relaxed);
        // entries for a case, bytes for a container
        let counted = if self.verify_job.is_some() {
            format!("{done} / {total}")
        } else {
            let size = |n: usize| crate::containers::human_size(n as u64);
            format!("{} / {}", size(done), size(total))
        };
        egui::Modal::new(egui::Id::unique("verify-progress"))
            .frame(theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.set_width(320.0);
                ui.label(text);
                let fraction = if total == 0 { 0.0 } else { done as f32 / total as f32 };
                ui.add(egui::ProgressBar::new(fraction).text(counted));
                if let Some(cancel) = &cancel
                    && ui.button("Cancel").clicked()
                {
                    cancel.store(true, Ordering::Relaxed);
                }
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
    EditEvidence(i64),
    NewContainer(i64),
    /// New Container for an evidence item
    NewContainerFor(i64),
    Container(ContainerAction),
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// An IoC value, selectable; under the pointer a button copies it.
fn ioc_row(ui: &mut egui::Ui, ctx: &egui::Context, value: &str) {
    let p = *theme::current(ctx);
    let id = ui.scope_id().with(("ioc", value));
    let hovered = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let row = ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let copy = if hovered {
                IconButton::new(icons::COPY, "Copy").show(ui).clicked()
            } else {
                ui.add_space(24.0);
                false
            };
            if copy {
                ctx.copy_text(value.to_string());
            }
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.add(
                    egui::Label::new(RichText::new(value).monospace().color(p.text))
                        .selectable(true)
                        .wrap(),
                );
            });
        });
    });
    let now = row.response.contains_pointer();
    if now != hovered {
        ui.data_mut(|d| d.insert_temp(id, now));
        ctx.request_repaint();
    }
}

/// A row of the case tree: the name, and the number of notes (or files) on the right; `mark` is an icon with its
/// tooltip. With `add` (the shortcut), a + for new evidence shows under the pointer; the second value is true when
/// it was clicked.
fn tree_row(
    ui: &mut egui::Ui,
    selected: bool,
    text: RichText,
    (count, unit): (usize, &str),
    indent: f32,
    add: Option<&str>,
    mark: Option<(&str, &str)>,
    symbol: Option<(&str, &str, egui::Color32)>,
) -> (egui::Response, bool) {
    let p = *theme::current(ui.ctx());
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 28.0), egui::Sense::click());
    let hovered = response.contains_pointer();
    if selected || hovered {
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
    let added = child
        .with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(count_text).size(SMALL_SIZE).color(p.muted))
                .on_hover_text(format!("{count} {unit}{}", if count == 1 { "" } else { "s" }));
            if let Some((icon, tip)) = mark {
                let mark = ui
                    .label(RichText::new(icon).size(SMALL_SIZE).color(p.warn))
                    .on_hover_text(tip);
                mark.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, tip));
            }
            let added = match add {
                Some(shortcut) if hovered => IconButton::new(icons::PLUS, "New evidence")
                    .shortcut(shortcut)
                    .show(ui)
                    .clicked(),
                _ => false,
            };
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.add(egui::Label::new(text).truncate().selectable(false));
                if let Some((icon, tip, color)) = symbol {
                    let symbol = ui
                        .label(RichText::new(icon).size(SMALL_SIZE).color(color))
                        .on_hover_text(tip);
                    symbol.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, tip));
                }
            });
            added
        })
        .inner;
    (response, added)
}

/// The first line of a column (CASES, the search, PINNED), the same height in all three.
fn header_row<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let size = egui::vec2(ui.available_width(), 28.0);
    ui.allocate_ui_with_layout(size, Layout::left_to_right(Align::Center), add)
        .inner
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
        let tree = egui::Panel::left("cases")
            .resizable(true)
            .default_size(self.tree_width)
            .size_range(180.0..=420.0)
            .frame(egui::Frame::new().fill(p.panel).inner_margin(Margin::symmetric(10, 4)))
            .show(ui, |ui| self.case_tree(ui, &ctx));
        self.tree_width = tree.response.rect.width();
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
        let mut container_verify_actions = Vec::new();
        for window in &mut self.container_verify_windows {
            window.show(&ctx, &mut container_verify_actions);
        }
        self.container_verify_windows.retain(|w| w.open);
        for action in container_verify_actions {
            if let VerifyAction::ShowEntry(entry_id) = action {
                self.jump_to_entry(entry_id);
            }
        }
        self.image_viewer_window(&ctx);
        markup_view::evict_unused(&ctx);
        let mut window_actions = Vec::new();
        for window in &mut self.companion_windows {
            window.show(&ctx, &mut window_actions);
        }
        self.companion_windows.retain(CompanionWindow::is_open);
        for action in window_actions {
            self.handle_window_action(action, &ctx);
        }
        self.verification_progress(&ctx);
        if let Some(dialog) = self.dialogs.last_mut()
            && let Some(result) = dialog.show(&ctx)
        {
            let closed = self.dialogs.pop();
            if matches!(
                (&closed, &result),
                (Some(Dialog::CompanionSettings(_)), DialogResult::Cancel)
            ) {
                self.reload_companion_settings(&ctx);
            }
            self.handle_dialog_result(result, &ctx);
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            self.quit();
        }
        let _ = ACTIVE_KEY_SETTING;
    }
}

#[cfg(test)]
mod tests;
