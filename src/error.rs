use std::fmt;

/// The kind of a [`FactumError`]; lets callers react to specific failures (e.g. the GUI shows the
/// GPG help dialog after a signing failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    General,
    UnsupportedDatabase,
    CaseNotFound,
    CaseArchived,
    Signing,
    InvalidCorrection,
    EvidenceNotEmpty,
    LogChanged,
    Confirmation,
    LogBroken,
    /// a database or file system error that is not a user error
    Internal,
}

/// An error whose message is shown to the user as-is (CLI: printed, exit 1; GUI: message box).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactumError {
    pub kind: ErrorKind,
    pub message: String,
}

impl FactumError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::General, message)
    }

    pub fn is(&self, kind: ErrorKind) -> bool {
        self.kind == kind
    }
}

impl fmt::Display for FactumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FactumError {}

impl From<rusqlite::Error> for FactumError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new(ErrorKind::Internal, format!("Database error: {error}"))
    }
}

impl From<std::io::Error> for FactumError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorKind::Internal, error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FactumError>;

macro_rules! constructors {
    ($($name:ident => $kind:ident),* $(,)?) => {
        impl FactumError {
            $(pub fn $name(message: impl Into<String>) -> Self { Self::new(ErrorKind::$kind, message) })*
        }
    };
}

constructors! {
    unsupported_database => UnsupportedDatabase,
    case_not_found => CaseNotFound,
    case_archived => CaseArchived,
    signing => Signing,
    invalid_correction => InvalidCorrection,
    evidence_not_empty => EvidenceNotEmpty,
    log_changed => LogChanged,
    confirmation => Confirmation,
    log_broken => LogBroken,
}
