//! The command line: fast note entry without leaving the terminal, plus verification, seals and export.

use std::io::Write;
use std::path::PathBuf;

use clap::Parser;

use crate::db::Db;
use crate::error::{FactumError, Result};
use crate::pystr::{head, splitlines, strip};
use crate::seals::REASON_CHECKPOINT;
use crate::services::Factum;
use crate::signer::{LazySigner, Signer};
use crate::verifier::{CaseReport, Level};

/// value of an optional CASE argument given without a value: use the active case
pub const ACTIVE: &str = "";

#[derive(Debug, Parser, Default, Clone)]
#[command(name = "factum", version, about = "Factum Notes Application")]
pub struct Args {
    /// Note text to add to the active case/evidence
    pub note: Option<String>,
    /// Run with GUI
    #[arg(long)]
    pub gui: bool,
    /// List cases (archived ones with --all)
    #[arg(long)]
    pub list_cases: bool,
    /// With --list-cases: include archived cases
    #[arg(long)]
    pub all: bool,
    /// List evidence for the active case
    #[arg(long)]
    pub list_evidence: bool,
    /// List eligible GPG signing keys
    #[arg(long)]
    pub list_gpg: bool,
    /// Create a case (and make it the active case); the name defaults to the file number
    #[arg(long, num_args = 1..=2, value_names = ["FILE_NO", "NAME"], allow_hyphen_values = true)]
    pub new_case: Option<Vec<String>>,
    /// With --new-case or --new-evidence: the description
    #[arg(long, default_value = "")]
    pub description: String,
    /// Create an evidence item in the active case
    #[arg(long, value_name = "NAME", allow_hyphen_values = true)]
    pub new_evidence: Option<String>,
    /// With --new-evidence: the evidence hash
    #[arg(long, default_value = "")]
    pub hash: String,
    /// Set active case, evidence, or GPG key (type: case|evidence|gpg)
    #[arg(long, num_args = 2, value_names = ["TYPE", "ID"], allow_hyphen_values = true)]
    pub set_active: Option<Vec<String>>,
    /// Add a corrected version of a note
    #[arg(long, num_args = 2, value_names = ["NOTE_ID", "TEXT"], allow_hyphen_values = true)]
    pub correct: Option<Vec<String>>,
    /// Verify a case (default: the active case)
    #[arg(long, num_args = 0..=1, default_missing_value = ACTIVE, value_name = "CASE")]
    pub verify: Option<String>,
    /// With --verify: list every entry
    #[arg(short, long)]
    pub verbose: bool,
    /// Seal the current state of a case (default: the active case)
    #[arg(long, num_args = 0..=1, default_missing_value = ACTIVE, value_name = "CASE")]
    pub checkpoint: Option<String>,
    /// Sign all unsigned entries and seals of a case (default: the active case)
    #[arg(long, num_args = 0..=1, default_missing_value = ACTIVE, value_name = "CASE")]
    pub sign_unsigned: Option<String>,
    /// Export a case (default: the active case)
    #[arg(long, num_args = 0..=1, default_missing_value = ACTIVE, value_name = "CASE")]
    pub export: Option<String>,
    /// With --export: comma-separated html,pdf,md,bundle
    #[arg(long, default_value = "bundle")]
    pub format: String,
    /// With --export: output folder
    #[arg(long, default_value = ".")]
    pub out: PathBuf,
    /// Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL); overrides LOG_LEVEL, default INFO
    #[arg(long)]
    pub log_level: Option<String>,
}

impl Args {
    pub fn parse_from_strs<I: IntoIterator<Item = S>, S: Into<std::ffi::OsString> + Clone>(argv: I) -> Self {
        Self::parse_from(std::iter::once("factum".into()).chain(argv.into_iter().map(Into::into)))
    }
}

/// Python's int(): surrounding whitespace and a sign are fine.
fn parse_int(text: &str) -> Option<i64> {
    strip(text).replace('_', "").parse().ok()
}

/// by id, case file number or name; archived cases count too (verify/export work on them)
pub fn find_case_id(factum: &Factum, query: &str) -> Result<Option<i64>> {
    if let Some(case_id) = parse_int(query) {
        return Ok(factum.get_case(case_id)?.map(|_| case_id));
    }
    for candidate in factum.list_cases(true)? {
        if let Some(case) = factum.get_case(candidate)?
            && (query == case.case_file || query == case.case_name)
        {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

pub fn resolve_case(factum: &Factum, query: &str) -> Result<i64> {
    if query == ACTIVE {
        return factum.get_active_case_id()?.ok_or_else(|| {
            FactumError::general("No active case. Pass a case or set one with 'factum --set-active case <id>'.")
        });
    }
    find_case_id(factum, query)?.ok_or_else(|| FactumError::general(format!("No case found matching '{query}'.")))
}

pub fn find_evidence_id(factum: &Factum, query: &str, active_case_id: i64) -> Result<Option<i64>> {
    let evidence_ids = factum.list_evidence_for_case(active_case_id, false)?;
    if let Some(id) = parse_int(query) {
        return Ok(evidence_ids.contains(&id).then_some(id));
    }
    for id in evidence_ids {
        if factum.get_evidence(id)?.is_some_and(|e| e.description == query) {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

fn list_cases(factum: &Factum, include_archived: bool, out: &mut dyn Write) -> Result<()> {
    let case_ids = factum.list_cases(include_archived)?;
    if case_ids.is_empty() {
        log::warn!("No cases found.");
        return Ok(());
    }
    let active = factum.get_active_case_id()?;
    for case_id in case_ids {
        let Some(case) = factum.get_case(case_id)? else {
            continue;
        };
        let markers = format!(
            "{}{}",
            if Some(case_id) == active { " [active]" } else { "" },
            if case.is_archived() { " [archived]" } else { "" }
        );
        writeln!(
            out,
            "  [{}]{markers} {} — {}",
            case.id, case.case_name, case.description
        )?;
    }
    Ok(())
}

fn list_evidence(factum: &Factum, out: &mut dyn Write) -> Result<()> {
    let active_case_id = factum
        .get_active_case_id()?
        .ok_or_else(|| FactumError::general("No active case."))?;
    let evidence_ids = factum.list_evidence_for_case(active_case_id, false)?;
    if evidence_ids.is_empty() {
        log::warn!("No evidence found for the active case.");
        return Ok(());
    }
    let active = factum.get_active_evidence_id()?;
    for id in evidence_ids {
        let Some(evidence) = factum.get_evidence(id)? else {
            continue;
        };
        let marker = if Some(id) == active { " [active]" } else { "" };
        writeln!(out, "  [{}]{marker} {}", evidence.id, evidence.description)?;
    }
    Ok(())
}

fn list_gpg(signer: &dyn Signer, out: &mut dyn Write) -> Result<()> {
    let keys = signer.list_keys();
    if keys.is_empty() {
        log::warn!("No eligible GPG signing keys found.");
        return Ok(());
    }
    let active = signer.active_key();
    for key in keys {
        let marker = if Some(&key.keyid) == active.as_ref() {
            " [active]"
        } else {
            ""
        };
        let uid = key.uids.first().map(String::as_str).unwrap_or("(no uid)");
        writeln!(out, "  {}{marker}  {uid}", key.keyid)?;
    }
    Ok(())
}

fn set_active(factum: &Factum, type_str: &str, query: &str, out: &mut dyn Write) -> Result<()> {
    match type_str {
        "case" => {
            let case_id = find_case_id(factum, query)?;
            match case_id {
                Some(case_id) if factum.set_active_case(case_id)? => writeln!(out, "Active case set to #{case_id}.")?,
                _ => {
                    return Err(FactumError::general(format!("No case found matching '{query}'.")));
                }
            }
        }
        "evidence" => {
            let active_case_id = factum.get_active_case_id()?.ok_or_else(|| {
                FactumError::general("No active case. Set an active case before setting active evidence.")
            })?;
            if query.to_lowercase() == "none" {
                factum.set_active_evidence(None)?;
                writeln!(out, "Active evidence cleared. Notes will be added to the active case.")?;
                return Ok(());
            }
            match find_evidence_id(factum, query, active_case_id)? {
                Some(id) if factum.set_active_evidence(Some(id))? => writeln!(out, "Active evidence set to #{id}.")?,
                _ => {
                    return Err(FactumError::general(format!(
                        "No evidence found matching '{query}' in the active case."
                    )));
                }
            }
        }
        "gpg" => {
            if !factum.signer.set_active_key(factum.db, query) {
                return Err(FactumError::general(format!(
                    "GPG key '{query}' not found or lacks signing capability."
                )));
            }
            writeln!(out, "Active GPG key set to {query}.")?;
        }
        other => {
            return Err(FactumError::general(format!(
                "Unknown type '{other}'. Use: case, evidence, or gpg."
            )));
        }
    }
    Ok(())
}

fn warn_unsigned(signer: &dyn Signer) {
    if signer.active_key().is_none() {
        log::warn!("No GPG key is active: the seal is stored unsigned. Sign it later with 'factum --sign-unsigned'.");
    }
}

pub fn print_report(report: &CaseReport, verbose: bool, out: &mut dyn Write) -> std::io::Result<()> {
    for finding in &report.findings {
        writeln!(out, "  {:4}  {}", finding.level, finding.message)?;
    }
    if verbose {
        for result in &report.entries {
            let entry = &result.entry;
            let first_line = splitlines(&entry.text).first().copied().unwrap_or("");
            writeln!(
                out,
                "  [{:4}] #{} leaf {} {}: {}",
                result.status(),
                entry.id,
                entry.leaf_index,
                entry.kind,
                head(first_line, 70)
            )?;
        }
    }
    let seal = report
        .newest_seal_size
        .map(|size| format!("size {size}"))
        .unwrap_or_else(|| "none".into());
    writeln!(
        out,
        "Case {}: {} — {} entries ({} OK, {} WARN, {} FAIL), tree size {}, root {}…, newest seal: {seal}",
        report.case.case_file,
        report.overall(),
        report.entries.len(),
        report.count(Level::Ok),
        report.count(Level::Warn),
        report.count(Level::Fail),
        report.tree_size,
        head(&report.root_hash, 16)
    )?;
    for (fingerprint, username) in &report.signers {
        writeln!(
            out,
            "{}",
            format!("  signed by {fingerprint} {}", username.as_deref().unwrap_or("")).trim_end()
        )?;
    }
    Ok(())
}

pub fn usage() -> &'static str {
    "cli usage: factum \"<note text>\"\n       factum --list-cases [--all]\n       factum --list-evidence\n       \
     factum --new-case <file number> [name] [--description <text>]\n       \
     factum --new-evidence <name> [--hash <hash>] [--description <text>]\n       \
     factum --list-gpg\n       factum --set-active (case|evidence|gpg) <id|name>\n       factum --set-active evidence none\n       \
     factum --correct <note id> \"<corrected text>\"\n       factum --verify [case] [-v]\n       factum --checkpoint [case]\n       \
     factum --sign-unsigned [case]\n       factum --export [case] [--format html,pdf,md,bundle] [--out <folder>]\n       \
     factum --gui\n       factum --help"
}

fn dispatch(factum: &Factum, args: &Args, out: &mut dyn Write) -> Result<i32> {
    if args.list_cases {
        list_cases(factum, args.all, out)?;
    } else if args.list_evidence {
        list_evidence(factum, out)?;
    } else if args.list_gpg {
        list_gpg(factum.signer, out)?;
    } else if let Some(values) = &args.new_case {
        let name = values.get(1).map(String::as_str).unwrap_or("");
        let case_id = factum.create_case(&values[0], name, &args.description)?;
        factum.set_active_case(case_id)?;
        writeln!(out, "Case #{case_id} created and set as the active case.")?;
    } else if let Some(name) = &args.new_evidence {
        let case_id = factum
            .get_active_case_id()?
            .ok_or_else(|| FactumError::general("No active case. Set an active case before adding evidence."))?;
        let evidence_id = factum.create_evidence(case_id, name, &args.hash, &args.description)?;
        writeln!(
            out,
            "Evidence #{evidence_id} created in case #{case_id}. Make it the note target with 'factum --set-active evidence {evidence_id}'."
        )?;
    } else if let Some(values) = &args.set_active {
        set_active(factum, &values[0], &values[1], out)?;
    } else if let Some(values) = &args.correct {
        let note_id = parse_int(&values[0]).ok_or_else(|| FactumError::general("NOTE_ID must be a number."))?;
        let new_id = factum.correct_note(note_id, &values[1])?;
        let corrects = factum
            .get_entry(new_id)?
            .and_then(|e| e.corrects_id)
            .unwrap_or_default();
        writeln!(out, "Note #{new_id} added (corrects #{corrects}).")?;
    } else if let Some(query) = &args.verify {
        let report = factum.verify_case(resolve_case(factum, query)?, None)?;
        print_report(&report, args.verbose, out)?;
        if report.overall() == Level::Fail {
            return Ok(1);
        }
    } else if let Some(query) = &args.checkpoint {
        let case_id = resolve_case(factum, query)?;
        warn_unsigned(factum.signer);
        let head = factum
            .get_tree_head(factum.seal(case_id, REASON_CHECKPOINT)?)?
            .expect("the seal was just created");
        writeln!(
            out,
            "Seal #{} created over {} entries: {}",
            head.id,
            head.tree_size,
            head.file_path.unwrap_or_default()
        )?;
    } else if let Some(query) = &args.sign_unsigned {
        let case_id = resolve_case(factum, query)?;
        let count = factum.sign_all_unsigned(case_id)?;
        writeln!(out, "Signed {count} item(s).")?;
    } else if let Some(query) = &args.export {
        let case_id = resolve_case(factum, query)?;
        warn_unsigned(factum.signer);
        let formats: Vec<&str> = args.format.split(',').map(strip).filter(|f| !f.is_empty()).collect();
        for path in factum.export(case_id, &formats, &args.out)? {
            writeln!(out, "{}", path.display())?;
        }
    } else if let Some(note) = args.note.as_deref().filter(|n| !n.is_empty()) {
        let active_case_id = factum
            .get_active_case_id()?
            .ok_or_else(|| FactumError::general("No active case. Set an active case before adding notes."))?;
        let note_id = factum.create_note(note, factum.get_active_evidence_id()?, active_case_id)?;
        writeln!(out, "Note #{note_id} added.")?;
    } else {
        writeln!(out, "{}", usage())?;
        return Ok(1);
    }
    Ok(0)
}

/// Runs one CLI command and returns the exit code. Without a signer, gpg is only started when needed.
pub fn run(db: &Db, args: &Args, signer: Option<&dyn Signer>, seal_dir: Option<PathBuf>, out: &mut dyn Write) -> i32 {
    let lazy = LazySigner::new(db);
    let signer: &dyn Signer = signer.unwrap_or(&lazy);
    let mut factum = Factum::new(db, signer);
    if seal_dir.is_some() {
        factum.seal_dir_override = seal_dir;
    }
    match dispatch(&factum, args, out) {
        Ok(code) => code,
        Err(e) => {
            log::error!("{e}");
            1
        }
    }
}
