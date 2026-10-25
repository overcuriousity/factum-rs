//! Log messages on stderr in the format of Python's logging.basicConfig: `WARNING:root:message`.

use log::{Level, LevelFilter, Log, Metadata, Record};

struct StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level() && metadata.target().starts_with("factum")
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            Level::Error => "ERROR",
            Level::Warn => "WARNING",
            Level::Info => "INFO",
            Level::Debug | Level::Trace => "DEBUG",
        };
        eprintln!("{level}:root:{}", record.args());
    }

    fn flush(&self) {}
}

/// DEBUG, INFO, WARNING, ERROR, CRITICAL like Python; anything else is INFO.
pub fn level_filter(name: &str) -> LevelFilter {
    match name.to_uppercase().as_str() {
        "DEBUG" => LevelFilter::Debug,
        "WARNING" | "WARN" => LevelFilter::Warn,
        "ERROR" | "CRITICAL" => LevelFilter::Error,
        _ => LevelFilter::Info,
    }
}

pub fn init(level: &str) {
    if log::set_logger(&StderrLogger).is_ok() {
        log::set_max_level(level_filter(level));
    }
}
