use std::path::PathBuf;

use crate::db::Db;
use crate::signer::Signer;

/// The services of factum wired together: one database connection, one signer, one seal folder setting.
/// The managers of the Python version (CaseManager, NoteManager, SealService, Verifier, ...) are the
/// `impl Factum` blocks in the modules next to this one.
pub struct Factum<'a> {
    pub db: &'a Db,
    pub signer: &'a dyn Signer,
    /// explicit seal folder (tests, or a caller that knows better); overrides everything else
    pub seal_dir_override: Option<PathBuf>,
    /// FACTUM_SEAL_DIR
    pub env_seal_dir: Option<PathBuf>,
}

impl<'a> Factum<'a> {
    pub fn new(db: &'a Db, signer: &'a dyn Signer) -> Self {
        Self {
            db,
            signer,
            seal_dir_override: None,
            env_seal_dir: crate::config::settings().seal_dir.clone(),
        }
    }

    /// With an explicit seal folder and no FACTUM_SEAL_DIR, independent of the process environment.
    pub fn with_seal_dir(db: &'a Db, signer: &'a dyn Signer, seal_dir: Option<PathBuf>) -> Self {
        Self {
            db,
            signer,
            seal_dir_override: seal_dir,
            env_seal_dir: None,
        }
    }
}
