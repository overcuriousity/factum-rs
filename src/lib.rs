//! factum: forensic notes with GPG-signed, tamper-evident case logs.
//!
//! Every case is an append-only log modelled on Certificate Transparency (RFC 9162). Databases, seal files and
//! verification bundles are compatible with factum-notes, the Python version.

pub mod canonical;
pub mod cases;
pub mod cli;
pub mod companion;
pub mod container;
pub mod containers;

pub mod config;
pub mod db;
pub mod error;
pub mod evidence;
pub mod export;

pub mod images;
pub mod iocs;
pub mod late_signing;
pub mod log_service;
pub mod logger;
pub mod markup;
pub mod merkle;
pub mod notes;
pub mod pystr;
pub mod seals;
pub mod services;
pub mod signer;
pub mod tags;
pub mod verifier;

pub use db::Db;
pub use error::{ErrorKind, FactumError, Result};
pub use services::Factum;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "gui")]
pub mod gui;
