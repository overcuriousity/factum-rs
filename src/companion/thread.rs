//! The companion thread: probes the endpoint, runs reflection passes when the scheduler says a case is due and
//! enriches the selected case's backlog when idle. It owns its own connections and publishes a shared `Status`;
//! questions travel through the companion database, not over the channel.

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::enrich::{enrich, index_unindexed};
use super::llm::LlmError;
use super::llm::{Client, probe};
use super::reflect::{PassError, choose_kind, run_pass};
use super::schedule::Scheduler;
use super::store::{CompanionDb, Protocol, Settings};
use super::{newest_entry_by_case, open_case_db};
use crate::Factum;
use crate::canonical::utc_now;
use crate::db::Db;
use crate::error::{FactumError, Result};
use crate::notes::EntryFilter;
use crate::signer::GnupgSigner;

/// How often the thread looks for due work when no command arrives.
const TICK: Duration = Duration::from_secs(1);
/// Entries per backlog enrichment step.
const BACKLOG_BATCH: usize = 50;
/// How often an unreachable endpoint is asked again.
const REPROBE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    /// the case log has new entries
    CaseChanged(i64),
    Selected(Option<i64>),
    /// "Re-think now": a full pass at once
    Rethink(i64),
    GoalChanged(i64),
    /// the case's companion switch was flipped
    CaseToggled(i64),
    /// the case was deleted permanently: its rows go again once the work in hand is done, in case a pass that was
    /// running wrote some
    CaseDeleted(i64),
    SettingsChanged,
    Probe,
    Shutdown,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum State {
    Idle,
    Reflecting(i64),
    Indexing {
        done: usize,
        total: usize,
    },
    Unreachable,
    /// unconfigured or switched off
    #[default]
    Off,
    /// the short reason
    Failed(String),
}

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub state: State,
    pub model: String,
    /// when the last successful pass of a case finished
    pub last_pass_utc: HashMap<i64, String>,
}

impl Status {
    /// The status bar text.
    pub fn line(&self) -> String {
        match &self.state {
            State::Idle => format!("companion: idle · {}", self.model),
            State::Reflecting(_) => "companion: reflecting…".to_string(),
            State::Indexing { done, total } => format!("companion: indexing {done} of {total}"),
            State::Unreachable => "companion: endpoint unreachable".to_string(),
            State::Off => "companion: off".to_string(),
            State::Failed(reason) => format!("companion: last pass failed: {reason}"),
        }
    }
}

/// The GUI's side of the companion thread.
pub struct CompanionHandle {
    sender: Sender<Command>,
    status: Arc<Mutex<Status>>,
    thread: Option<JoinHandle<()>>,
}

impl CompanionHandle {
    pub fn start(ctx: egui::Context, case_db: PathBuf, companion_db: PathBuf) -> CompanionHandle {
        let (sender, receiver) = mpsc::channel();
        let status = Arc::new(Mutex::new(Status::default()));
        let shared = status.clone();
        let thread = std::thread::Builder::new()
            .name("companion".into())
            .spawn(move || run(ctx, receiver, shared, case_db, companion_db))
            .expect("spawn the companion thread");
        CompanionHandle {
            sender,
            status,
            thread: Some(thread),
        }
    }

    /// A handle without a thread: what is sent arrives at the returned receiver; `shutdown` joins nothing.
    #[doc(hidden)]
    pub fn test_stub() -> (CompanionHandle, Receiver<Command>) {
        let (sender, receiver) = mpsc::channel();
        let handle = CompanionHandle {
            sender,
            status: Arc::default(),
            thread: None,
        };
        (handle, receiver)
    }

    pub fn send(&self, cmd: Command) {
        // a finished thread has nobody to tell
        let _ = self.sender.send(cmd);
    }

    pub fn status(&self) -> Status {
        lock(&self.status).clone()
    }

    /// Waits for a running pass to end.
    pub fn shutdown(mut self) {
        self.send(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Stops the thread without waiting for it: it ends after the work in hand.
    pub fn detach(self) {
        self.send(Command::Shutdown);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The companion databases a thread works on: a thread started while a detached one still finishes its pass on
/// the same database waits for it, so two threads never run passes side by side.
static RUNNING: (Mutex<Vec<PathBuf>>, Condvar) = (Mutex::new(Vec::new()), Condvar::new());

/// Holds the companion database for one thread until dropped.
struct Running(PathBuf);

impl Running {
    fn wait_for(path: PathBuf) -> Running {
        let (running, released) = &RUNNING;
        let mut paths = lock(running);
        while paths.contains(&path) {
            paths = released.wait(paths).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        paths.push(path.clone());
        Running(path)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let (running, released) = &RUNNING;
        lock(running).retain(|path| *path != self.0);
        released.notify_all();
    }
}

fn run(
    ctx: egui::Context,
    receiver: Receiver<Command>,
    status: Arc<Mutex<Status>>,
    case_db: PathBuf,
    companion_db: PathBuf,
) {
    let _running = Running::wait_for(companion_db.clone());
    let opened = open_case_db(&case_db).and_then(|db| Ok((db, CompanionDb::open(&companion_db)?)));
    let (db, cdb) = match opened {
        Ok(dbs) => dbs,
        Err(e) => {
            log::warn!("companion: the databases cannot be opened: {e}");
            lock(&status).state = State::Failed(e.message);
            ctx.request_repaint();
            // nothing to do but wait for the end
            while !matches!(receiver.recv(), Ok(Command::Shutdown) | Err(_)) {}
            return;
        }
    };
    let mut companion = Companion {
        ctx,
        status,
        db,
        cdb,
        settings: Settings::default(),
        client: None,
        scheduler: Scheduler::new(),
        selected: None,
        full_next: HashSet::new(),
        retried: HashSet::new(),
        enrich_tried: HashSet::new(),
        backlog_done: HashSet::new(),
        last_probe: Instant::now(),
        after_indexing: State::Idle,
    };
    companion.guarded(|c| c.reload_settings());
    loop {
        let mut next = receiver.recv_timeout(TICK);
        // every queued command before the next pass, so a Shutdown does not wait behind one
        loop {
            match next {
                Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(cmd) => companion.guarded(|c| c.handle(cmd)),
                Err(RecvTimeoutError::Timeout) => break,
            }
            next = receiver.try_recv().map_err(|e| match e {
                mpsc::TryRecvError::Empty => RecvTimeoutError::Timeout,
                mpsc::TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
            });
        }
        companion.guarded(Companion::tick);
    }
}

struct Companion {
    ctx: egui::Context,
    status: Arc<Mutex<Status>>,
    db: Db,
    cdb: CompanionDb,
    settings: Settings,
    /// set while the endpoint answered the last probe
    client: Option<Client>,
    scheduler: Scheduler,
    selected: Option<i64>,
    /// cases whose next pass is full because the last one resolved many questions
    full_next: HashSet<i64>,
    /// cases already given their one retry after a failed model call, until a new change or a successful pass
    retried: HashSet<i64>,
    /// entries backlog enrichment has asked for (or given up on), until a successful probe or pass
    enrich_tried: HashSet<i64>,
    /// cases whose backlog was found empty, so the idle tick does not read them again until they change
    backlog_done: HashSet<i64>,
    last_probe: Instant,
    /// what the status shows again once indexing ends
    after_indexing: State,
}

impl Companion {
    fn state(&self) -> State {
        lock(&self.status).state.clone()
    }

    fn set_state(&self, state: State) {
        lock(&self.status).state = state;
        self.ctx.request_repaint();
    }

    /// The thread outlives a panic outside the pass and enrichment guards.
    fn guarded(&mut self, f: impl FnOnce(&mut Self)) {
        if catch_unwind(AssertUnwindSafe(|| f(self))).is_err() {
            log::error!("companion: internal error");
            self.set_state(State::Failed("internal error".into()));
        }
    }

    fn end_indexing(&self) {
        if matches!(self.state(), State::Indexing { .. }) {
            self.set_state(self.after_indexing.clone());
        }
    }

    /// Entries a pass has not seen yet, on a case that can run, get a pass in due course (after a switch-off or
    /// an unarchive, say).
    fn pick_up_unseen(&mut self, case_id: i64) -> Result<()> {
        let Some(case) = self.cdb.case_settings(case_id)? else {
            return Ok(());
        };
        let newest = self.entry_ids(case_id)?.first().copied().unwrap_or(0);
        if newest > case.last_seen_entry_id && !self.scheduler.is_pending(case_id) && self.runnable(case_id)? {
            self.scheduler.changed(case_id, Instant::now());
        }
        Ok(())
    }

    /// Every case with a row and entries no pass has seen gets a pass in due course, e.g. once the endpoint answers
    /// again after the changes were given up on.
    fn pick_up_all_unseen(&mut self) -> Result<()> {
        let newest = newest_entry_by_case(&self.db)?;
        for (case_id, seen) in self.cdb.last_seen_by_case()? {
            if newest.get(&case_id).is_some_and(|&newest| newest > seen)
                && !self.scheduler.is_pending(case_id)
                && self.runnable(case_id)?
            {
                self.scheduler.changed(case_id, Instant::now());
            }
        }
        Ok(())
    }

    fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::CaseChanged(case_id) => {
                self.retried.remove(&case_id);
                self.backlog_done.remove(&case_id);
                self.scheduler.changed(case_id, Instant::now());
            }
            Command::Selected(case_id) => {
                if let Some(case_id) = case_id {
                    self.backlog_done.remove(&case_id);
                }
                self.selected = case_id;
                self.scheduler.select(case_id);
                if case_id.is_none() {
                    self.end_indexing();
                }
                if let Some(case_id) = case_id
                    && let Err(e) = self.selected_case(case_id)
                {
                    log::warn!("companion: case {case_id} cannot be read: {e}");
                }
            }
            Command::Rethink(case_id) | Command::GoalChanged(case_id) => self.scheduler.force(case_id),
            Command::CaseDeleted(case_id) => {
                self.scheduler.clear(case_id);
                self.full_next.remove(&case_id);
                self.retried.remove(&case_id);
                lock(&self.status).last_pass_utc.remove(&case_id);
                if let Err(e) = self.cdb.delete_case(case_id) {
                    log::warn!("companion: the rows of deleted case {case_id} cannot be removed: {e}");
                }
            }
            Command::CaseToggled(case_id) => {
                self.backlog_done.remove(&case_id);
                let toggled = match self.cdb.case_settings(case_id) {
                    Ok(Some(case)) if !case.enabled => {
                        self.scheduler.clear(case_id);
                        Ok(())
                    }
                    Ok(_) => self.pick_up_unseen(case_id),
                    Err(e) => Err(e),
                };
                if let Err(e) = toggled {
                    log::warn!("companion: case {case_id} settings cannot be read: {e}");
                }
            }
            Command::SettingsChanged => self.reload_settings(),
            Command::Probe => self.probe(),
            Command::Shutdown => {}
        }
    }

    /// A case the companion has never seen gets a full first pass after the quiet period, so it can be opted out
    /// before anything is sent; the time of its last pass is shown.
    fn selected_case(&mut self, case_id: i64) -> Result<()> {
        if self.cdb.case_settings(case_id)?.is_none() && !self.entry_ids(case_id)?.is_empty() {
            self.cdb.ensure_case(case_id)?;
            self.scheduler.first_seen(case_id, Instant::now());
        } else {
            self.pick_up_unseen(case_id)?;
        }
        let mut status = lock(&self.status);
        if !status.last_pass_utc.contains_key(&case_id)
            && let Some(finished) = self.cdb.last_ok_pass(case_id)?
        {
            status.last_pass_utc.insert(case_id, finished);
        }
        Ok(())
    }

    fn reload_settings(&mut self) {
        match Settings::load(&self.cdb) {
            Ok(settings) => self.settings = settings,
            Err(e) => log::warn!("companion: the settings cannot be read: {e}"),
        }
        self.probe();
    }

    fn probe(&mut self) {
        self.client = None;
        self.last_probe = Instant::now();
        if !self.settings.is_configured() {
            self.set_state(State::Off);
            return;
        }
        match probe(&self.settings) {
            Ok(models) => {
                let client = Client::new(self.settings.clone());
                if self.settings.context_window.is_none() && self.settings.protocol == Protocol::Anthropic {
                    let listed = models.iter().find(|m| m.id == self.settings.model);
                    client.set_context_window(listed.and_then(|m| m.max_input_tokens));
                }
                self.client = Some(client);
                self.enrich_tried.clear();
                self.backlog_done.clear();
                lock(&self.status).model = self.settings.model.clone();
                self.set_state(State::Idle);
                if let Err(e) = self.pick_up_all_unseen() {
                    log::warn!("companion: the cases cannot be read: {e}");
                }
            }
            Err(e) => {
                log::warn!("companion: the endpoint does not answer: {e}");
                self.set_state(State::Unreachable);
            }
        }
    }

    /// The newest version of every entry of the case, system entries included, newest first.
    fn entry_ids(&self, case_id: i64) -> Result<Vec<i64>> {
        let signer = GnupgSigner::without_key(None);
        let mut ids = Factum::new(&self.db, &signer).list_entries(case_id, &EntryFilter::default())?;
        ids.sort_unstable_by(|a, b| b.cmp(a));
        Ok(ids)
    }

    /// The case exists, is not archived and has the companion switched on.
    fn runnable(&self, case_id: i64) -> Result<bool> {
        let signer = GnupgSigner::without_key(None);
        let open = Factum::new(&self.db, &signer)
            .get_case(case_id)?
            .is_some_and(|case| !case.is_archived());
        Ok(open && self.cdb.case_settings(case_id)?.is_none_or(|case| case.enabled))
    }

    fn tick(&mut self) {
        if self.client.is_none() && self.state() == State::Unreachable && self.last_probe.elapsed() >= REPROBE {
            self.probe();
        }
        if self.client.is_none() {
            return;
        }
        while let Some((case_id, forced)) = self.scheduler.next_due(Instant::now()) {
            // a panic here would otherwise come back every tick
            let runnable = catch_unwind(AssertUnwindSafe(|| self.runnable(case_id)))
                .unwrap_or_else(|_| Err(FactumError::general("internal error")));
            match runnable {
                Ok(true) => return self.reflect(case_id, forced),
                // picked up again on the next change once the condition clears
                Ok(false) => self.scheduler.clear(case_id),
                Err(e) => {
                    log::warn!("companion: case {case_id} cannot be read: {e}");
                    self.scheduler.passed(case_id, Instant::now());
                }
            }
        }
        self.backlog();
    }

    fn reflect(&mut self, case_id: i64, forced: bool) {
        let Some(client) = &self.client else { return };
        let before = self.state();
        self.set_state(State::Reflecting(case_id));
        let full = forced || self.full_next.contains(&case_id);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let kind = choose_kind(&self.cdb, case_id, full)?;
            run_pass(&self.db, &self.cdb, client, case_id, kind)
        }));
        self.scheduler.passed(case_id, Instant::now());
        if !matches!(result, Ok(Ok(_))) && full {
            // a full pass that did not happen is still owed
            self.full_next.insert(case_id);
        }
        match result {
            Ok(Ok(summary)) => {
                log::info!(
                    "companion pass on case {case_id}: {} answered, {} withdrawn, {} rephrased, {} new",
                    summary.answered,
                    summary.withdrawn,
                    summary.rephrased,
                    summary.created
                );
                self.full_next.remove(&case_id);
                self.retried.remove(&case_id);
                self.enrich_tried.clear();
                self.backlog_done.clear();
                lock(&self.status).last_pass_utc.insert(case_id, utc_now());
                self.set_state(State::Idle);
                // a diff pass that cut new entries for space leaves the rest to a pass after the spacing
                match self.entry_ids(case_id) {
                    Ok(ids) if ids.first().is_some_and(|&newest| newest > summary.entries_to) => {
                        self.scheduler.changed(case_id, Instant::now());
                    }
                    Ok(_) => {}
                    Err(e) => log::warn!("companion: case {case_id} cannot be read: {e}"),
                }
            }
            // nothing ran: whatever was shown before stays
            Ok(Err(PassError::NothingNew | PassError::Archived)) => self.set_state(before),
            Ok(Err(e)) => {
                // the endpoint may recover: one more try after the spacing, not a loop
                if matches!(e, PassError::Llm(_)) && self.retried.insert(case_id) {
                    self.scheduler.changed(case_id, Instant::now());
                }
                if matches!(e, PassError::Llm(LlmError::Unreachable(_) | LlmError::Timeout)) {
                    // gone: probed again every REPROBE, and what is pending runs once it answers
                    self.client = None;
                    self.last_probe = Instant::now();
                    self.set_state(State::Unreachable);
                } else {
                    self.set_state(State::Failed(e.to_string()));
                }
            }
            Err(_) => {
                log::error!("companion pass on case {case_id} panicked");
                self.set_state(State::Failed("internal error".into()));
            }
        }
    }

    /// One batch of the selected case's unenriched entries, newest first.
    fn backlog(&mut self) {
        let Some(case_id) = self.selected else { return };
        if self.backlog_done.contains(&case_id) {
            return;
        }
        let Some(client) = &self.client else { return };
        let read = || -> Result<(Vec<i64>, usize)> {
            let ids = if self.runnable(case_id)? {
                self.entry_ids(case_id)?
            } else {
                Vec::new()
            };
            Ok((self.cdb.unenriched(case_id, &ids)?, ids.len()))
        };
        let (unenriched, total) = match read() {
            Ok(read) => read,
            Err(e) => {
                log::warn!("companion: the backlog of case {case_id} cannot be read: {e}");
                self.backlog_done.insert(case_id);
                self.end_indexing();
                return;
            }
        };
        let pending: Vec<i64> = unenriched
            .iter()
            .copied()
            .filter(|id| !self.enrich_tried.contains(id))
            .collect();
        if pending.is_empty() {
            self.backlog_done.insert(case_id);
            self.end_indexing();
            return;
        }
        let done = total - unenriched.len();
        let state = self.state();
        if !matches!(state, State::Indexing { .. }) {
            self.after_indexing = state;
        }
        self.set_state(State::Indexing { done, total });
        let batch = &pending[..pending.len().min(BACKLOG_BATCH)];
        let result = catch_unwind(AssertUnwindSafe(|| {
            index_unindexed(&self.db, &self.cdb, case_id).map_err(|e| e.to_string())?;
            enrich(&self.db, &self.cdb, client, case_id, batch).map_err(|e| e.to_string())
        }));
        match result {
            Ok(Ok(enriched)) => {
                // entries the model skipped are not asked for again
                self.enrich_tried.extend(batch);
                if pending.len() > batch.len() {
                    self.set_state(State::Indexing {
                        done: done + enriched,
                        total,
                    });
                } else {
                    self.end_indexing();
                }
            }
            Ok(Err(e)) => {
                log::warn!("companion: backlog enrichment of case {case_id} failed: {e}");
                // until the next successful probe or pass, so a dead endpoint is not asked again and again
                self.enrich_tried.extend(&pending);
                self.end_indexing();
            }
            Err(_) => {
                log::error!("companion: backlog enrichment of case {case_id} panicked");
                self.set_state(State::Failed("internal error".into()));
            }
        }
    }
}
