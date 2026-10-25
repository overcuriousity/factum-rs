//! Work that must not block the GUI: whole-case verification, the signature checks of the entries on screen and
//! asking the companion. SQLite connections are bound to their thread, so each worker opens its own; workers only read.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use crate::companion::ask::Answer;
use crate::companion::llm::Client;
use crate::companion::{CompanionDb, Settings};
use crate::db::Db;
use crate::services::Factum;
use crate::signer::GnupgSigner;
use crate::verifier::{CaseReport, SignatureCheck};

pub struct Worker<T> {
    receiver: mpsc::Receiver<T>,
    handle: Option<JoinHandle<()>>,
}

impl<T: Send + 'static> Worker<T> {
    pub(crate) fn spawn(ctx: &egui::Context, work: impl FnOnce() -> T + Send + 'static) -> Self {
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        let handle = std::thread::spawn(move || {
            let _ = sender.send(work());
            ctx.request_repaint();
        });
        Self {
            receiver,
            handle: Some(handle),
        }
    }

    /// The result, once the work is done.
    pub fn poll(&mut self) -> Option<T> {
        let result = self.receiver.try_recv().ok()?;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        Some(result)
    }

    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Waits for the work to finish (on exit: a running verification is not torn down).
    pub fn wait(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub struct Progress {
    pub done: AtomicUsize,
    pub total: AtomicUsize,
}

pub type VerifyResult = Result<CaseReport, String>;

pub fn verify_case(
    ctx: &egui::Context,
    db_path: PathBuf,
    gpg_home: Option<PathBuf>,
    case_id: i64,
) -> (Worker<VerifyResult>, Arc<Progress>) {
    let progress = Arc::new(Progress {
        done: AtomicUsize::new(0),
        total: AtomicUsize::new(0),
    });
    let shared = progress.clone();
    let repaint = ctx.clone();
    let worker = Worker::spawn(ctx, move || {
        let db = Db::open(&db_path).map_err(|e| e.to_string())?;
        let signer = GnupgSigner::without_key(gpg_home);
        let factum = Factum::new(&db, &signer);
        let mut report_progress = |done: usize, total: usize| {
            shared.done.store(done, Ordering::Relaxed);
            shared.total.store(total, Ordering::Relaxed);
            repaint.request_repaint();
        };
        factum
            .verify_case(case_id, Some(&mut report_progress))
            .map_err(|e| e.to_string())
    });
    (worker, progress)
}

pub type SignatureChecks = HashMap<i64, SignatureCheck>;

/// Checks the signatures of the entries on screen, so a card's ✓ means checked, not just stored.
pub fn check_signatures(
    ctx: &egui::Context,
    db_path: PathBuf,
    gpg_home: Option<PathBuf>,
    case_id: i64,
    entry_ids: HashSet<i64>,
) -> Worker<SignatureChecks> {
    Worker::spawn(ctx, move || {
        let run = || -> crate::Result<SignatureChecks> {
            let db = Db::open(&db_path)?;
            let signer = GnupgSigner::without_key(gpg_home);
            let factum = Factum::new(&db, &signer);
            // the whole log is recomputed, so a signature is checked against the entry as it is now
            let (results, _) = factum.check_entries(
                case_id,
                &factum.load_entries(case_id)?,
                &factum.late_signatures()?,
                Some(&entry_ids),
                None,
                None,
            );
            Ok(results
                .into_iter()
                .filter(|r| entry_ids.contains(&r.entry.id))
                .map(|r| (r.entry.id, r.signature))
                .collect())
        };
        run().unwrap_or_else(|e| {
            log::error!("Checking signatures failed: {e}");
            HashMap::new()
        })
    })
}

pub type AskResult = Result<Answer, String>;

/// Asks the companion on a thread of its own, with its own connections, so it never waits behind a running pass.
pub fn ask(
    ctx: &egui::Context,
    db_path: PathBuf,
    companion_path: PathBuf,
    settings: Settings,
    case_id: i64,
    question: String,
) -> Worker<AskResult> {
    Worker::spawn(ctx, move || {
        let db = Db::open(&db_path).map_err(|e| e.to_string())?;
        let cdb = CompanionDb::open(&companion_path).map_err(|e| e.to_string())?;
        let client = Client::new(settings);
        crate::companion::ask::ask(&db, &cdb, &client, case_id, &question).map_err(|e| e.to_string())
    })
}
