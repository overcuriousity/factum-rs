//! Ports of test_cli and test_gnupg_service.

mod common;

use common::Fixture;
use factum::cli::{self, Args};
use factum::notes::EntryFilter;
use factum::signer::{FakeSigner, GnupgSigner, Signer};

fn run(f: &Fixture, signer: &dyn Signer, argv: &[&str]) -> (i32, String) {
    let mut out = Vec::new();
    let code = cli::run(
        &f.db,
        &Args::parse_from_strs(argv),
        Some(signer),
        Some(f.seal_dir.clone()),
        &mut out,
    );
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn list_cases_hides_archived_unless_all() {
    let f = Fixture::new();
    let factum = f.factum();
    factum.create_case("C-1", "Open", "").unwrap();
    let archived = factum.create_case("C-2", "Closed", "").unwrap();
    factum.archive_case(archived).unwrap();
    let (_, out) = run(&f, &f.signer, &["--list-cases"]);
    assert!(out.contains("Open") && !out.contains("Closed"));
    let (_, out) = run(&f, &f.signer, &["--list-cases", "--all"]);
    assert!(out.contains("[archived] Closed"), "{out}");
}

#[test]
fn add_and_correct_a_note() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.set_active_case(case_id).unwrap();
    let (code, out) = run(&f, &f.signer, &["first version"]);
    let note_id = factum.list_entries(case_id, &EntryFilter::notes()).unwrap()[0];
    assert_eq!(code, 0);
    assert!(out.contains(&format!("Note #{note_id} added.")));
    let (_, out) = run(&f, &f.signer, &["--correct", &note_id.to_string(), "second version"]);
    assert!(out.contains(&format!("(corrects #{note_id})")), "{out}");
}

#[test]
fn notes_go_to_the_active_evidence() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "", "").unwrap();
    run(&f, &f.signer, &["--set-active", "case", "C-1"]);
    let (code, out) = run(&f, &f.signer, &["--set-active", "evidence", "disk"]);
    assert_eq!(
        (code, out.trim()),
        (0, format!("Active evidence set to #{evidence_id}.").as_str())
    );
    run(&f, &f.signer, &["on the disk"]);
    let on_disk = EntryFilter {
        evidence_id: Some(evidence_id),
        ..EntryFilter::notes()
    };
    assert_eq!(factum.list_entries(case_id, &on_disk).unwrap().len(), 1);
    let (_, out) = run(&f, &f.signer, &["--list-evidence"]);
    assert!(out.contains(&format!("[{evidence_id}] [active] disk")));
    let (_, out) = run(&f, &f.signer, &["--set-active", "evidence", "none"]);
    assert!(out.contains("Active evidence cleared"));
}

#[test]
fn new_case_and_evidence_from_the_cli() {
    let f = Fixture::new();
    let (code, out) = run(
        &f,
        &f.signer,
        &["--new-case", "2026/7", "Phishing", "--description", "mail server"],
    );
    assert_eq!(code, 0, "{out}");
    let factum = f.factum();
    let case_id = factum.get_active_case_id().unwrap().unwrap();
    let case = factum.get_case(case_id).unwrap().unwrap();
    assert_eq!(
        (
            case.case_file.as_str(),
            case.case_name.as_str(),
            case.description.as_str()
        ),
        ("2026/7", "Phishing", "mail server")
    );
    let (code, out) = run(&f, &f.signer, &["--new-evidence", "mailbox export", "--hash", "abc"]);
    assert_eq!(code, 0, "{out}");
    let [evidence_id] = factum.list_evidence_for_case(case_id, false).unwrap()[..] else {
        panic!()
    };
    assert_eq!(factum.get_evidence(evidence_id).unwrap().unwrap().evidence_hash, "abc");
    assert_eq!(
        factum
            .verify_case(case_id, None)
            .unwrap()
            .findings
            .iter()
            .filter(|f| f.level == factum::verifier::Level::Fail)
            .count(),
        0
    );
    assert_eq!(run(&f, &f.signer, &["--new-case", "  "]).0, 1);
}

#[test]
fn set_active_on_archived_case_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.archive_case(case_id).unwrap();
    assert_eq!(run(&f, &f.signer, &["--set-active", "case", "C-1"]).0, 1);
}

#[test]
fn verify_exit_codes() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.set_active_case(case_id).unwrap();
    run(&f, &f.signer, &["--checkpoint"]);
    let (code, out) = run(&f, &f.signer, &["--verify", "-v"]);
    assert_eq!(code, 0);
    assert!(out.contains("Case C-1: OK") && out.contains("[OK  ] #"), "{out}");
    f.exec("UPDATE entries SET text = 'tampered'");
    let (code, out) = run(&f, &f.signer, &["--verify", "C-1"]);
    assert_eq!(code, 1);
    assert!(out.contains("FAIL"));
}

#[test]
fn verify_without_active_case_fails() {
    let f = Fixture::new();
    assert_eq!(run(&f, &f.signer, &["--verify"]).0, 1);
}

#[test]
fn checkpoint_without_key_and_sign_unsigned_signs() {
    let f = Fixture::with_signer(FakeSigner::new(false));
    assert_eq!(run(&f, &f.signer, &["--list-cases"]).0, 0); // nothing yet, must not fail
    let case_id = f.factum().create_case("C-1", "Case", "").unwrap();
    let (code, out) = run(&f, &f.signer, &["--checkpoint", "C-1"]);
    assert_eq!(code, 0);
    assert!(out.contains("Seal #"));
    f.signer.set_active(true);
    let (_, out) = run(&f, &f.signer, &["--sign-unsigned", &case_id.to_string()]);
    assert!(out.contains("Signed 2 item(s)."), "{out}");
}

#[test]
fn cli_export() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("2026/04 Müller", "Case", "").unwrap();
    factum.create_note("hello", None, case_id).unwrap();
    let out_dir = f.path().join("out");
    let (code, out) = run(
        &f,
        &f.signer,
        &[
            "--export",
            &case_id.to_string(),
            "--format",
            "html,md",
            "--out",
            out_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines.len() == 2 && lines[0].ends_with(".html") && lines[1].ends_with(".md"),
        "{out}"
    );
}

#[test]
fn no_command_prints_usage() {
    let f = Fixture::new();
    let (code, out) = run(&f, &f.signer, &[]);
    assert_eq!(code, 1);
    assert!(out.starts_with("cli usage: factum"));
}

#[test]
fn optional_case_arguments_parse_like_argparse() {
    let args = Args::parse_from_strs(["--verify", "-v"]);
    assert_eq!((args.verify.as_deref(), args.verbose), (Some(""), true));
    let args = Args::parse_from_strs(["--export", "C-1", "--format", "md"]);
    assert_eq!((args.export.as_deref(), args.format.as_str()), (Some("C-1"), "md"));
    let args = Args::parse_from_strs(["--set-active", "evidence", "none"]);
    assert_eq!(args.set_active.unwrap(), vec!["evidence", "none"]);
    assert_eq!(Args::parse_from_strs(["a note"]).note.as_deref(), Some("a note"));
}

#[test]
fn unsupported_database_exits_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE notes(id INTEGER)")
        .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_factum"))
        .arg("--list-cases")
        .env("FACTUM_DB", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("ERROR:root:This database was created by an older factum version")
    );
}

// --- real gpg

fn gpg(f: &Fixture, home: &common::GpgHome) -> GnupgSigner {
    let signer = GnupgSigner::new(&f.db, Some(home.path()));
    let key = signer.list_keys()[0].keyid.clone();
    assert!(signer.set_active_key(&f.db, &key));
    signer
}

#[test]
fn sign_text_round_trip_and_tampering() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let signature = signer.sign_text(r#"{"a":1}"#).unwrap();
    assert!(signature.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
    let result = signer.verify_signature(&signature);
    assert!(result.valid);
    assert_eq!(result.signed_text.as_deref(), Some(r#"{"a":1}"#));
    assert_eq!(result.trust.as_deref(), Some("TRUST_ULTIMATE"));
    assert!(
        !signer
            .verify_signature(&signature.replace(r#"{"a":1}"#, r#"{"a":2}"#))
            .valid
    );
    assert!(
        signer
            .sign_detached(b"manifest\n")
            .unwrap()
            .starts_with("-----BEGIN PGP SIGNATURE-----")
    );
    let fingerprint = signer.list_keys()[0].fingerprint.clone();
    assert!(
        signer
            .export_public_keys(&[fingerprint])
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
    assert_eq!(signer.export_public_keys(&[]), "");
    signer.clear_active_key(&f.db);
    assert_eq!(signer.sign_text("x"), None);
}

#[test]
fn active_key_is_remembered() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let key = gpg(&f, &home).active_key().unwrap();
    assert_eq!(GnupgSigner::new(&f.db, Some(home.path())).active_key(), Some(key));
}

#[test]
fn real_gpg_end_to_end() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note("signed for real", None, case_id).unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), factum::verifier::Level::Ok, "{:?}", report.findings);
}

#[test]
fn non_ascii_user_id_verifies_under_c_locale() {
    let home = require_gpg!("Jürgen Stöckl <stoeckl@factum.invalid>");
    let f = Fixture::new();
    // SAFETY: tests in this binary do not read the locale concurrently in a way that matters
    unsafe {
        std::env::set_var("LC_ALL", "C");
        std::env::set_var("LANG", "C");
    }
    let signer = gpg(&f, &home);
    let result = signer.verify_signature(&signer.sign_text(r#"{"a":1}"#).unwrap());
    assert!(result.valid);
    assert_eq!(
        result.username.as_deref(),
        Some("Jürgen Stöckl <stoeckl@factum.invalid>")
    );
}

#[test]
fn signature_check_of_a_damaged_signature_is_invalid() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let good = factum.create_note("good", None, case_id).unwrap();
    let bad = factum.create_note("bad", None, case_id).unwrap();
    let signature = factum.get_entry(bad).unwrap().unwrap().signature.unwrap();
    let mut lines: Vec<String> = signature.lines().map(str::to_string).collect();
    let index = lines.iter().position(|l| l == "-----BEGIN PGP SIGNATURE-----").unwrap() + 2;
    let line = &lines[index];
    lines[index] = format!(
        "{}{}",
        &line[..line.len() - 4],
        if line.ends_with("AAAA") { "BBBB" } else { "AAAA" }
    );
    f.db.conn
        .execute(
            "UPDATE entries SET signature = ? WHERE id = ?",
            rusqlite::params![lines.join("\n"), bad],
        )
        .unwrap();
    let ids = std::collections::HashSet::from([good, bad]);
    let (results, _) = factum.check_entries(
        case_id,
        &factum.load_entries(case_id).unwrap(),
        &factum.late_signatures().unwrap(),
        Some(&ids),
        None,
        None,
    );
    let check = |id| &results.iter().find(|r| r.entry.id == id).unwrap().signature;
    assert!(check(good).valid && check(good).covers_payload && check(good).trusted);
    assert!(!check(bad).valid);
}

#[test]
fn questions_without_companion_db_says_not_configured() {
    let f = Fixture::new();
    f.factum().create_case("C-1", "Case", "").unwrap();
    let (code, out) = run(&f, &f.signer, &["--questions", "C-1"]);
    assert_eq!((code, out.trim()), (0, "The companion is not configured."));
    assert!(!factum::companion::companion_db_path(&f.db.path).exists());
}

#[test]
fn questions_lists_open_in_position_order() {
    use factum::companion::{Archetype, CompanionDb, NewQuestion};
    let f = Fixture::new();
    let case_id = f.factum().create_case("C-1", "Case", "").unwrap();
    let companion = CompanionDb::open_for(&f.db.path).unwrap();
    let ask = |text: &str, rests_on: Vec<i64>| {
        let q = NewQuestion {
            text: text.into(),
            archetype: Archetype::Corroborate,
            rests_on,
        };
        companion.insert_question(case_id, None, &q).unwrap()
    };
    let first = ask("Who else saw the login?", vec![3, 5]);
    let second = ask("Was the log rotated?", vec![]);
    let (code, out) = run(&f, &f.signer, &["--questions", "C-1"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(code, 0);
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(
        lines[0],
        format!("Q{first} [corroborate] Who else saw the login?  (rests on #3, #5)")
    );
    assert!(
        lines[1].starts_with(&format!("Q{second} [corroborate] Was the log rotated?")),
        "{out}"
    );
    // an empty case says so
    f.factum().create_case("C-2", "Empty", "").unwrap();
    let (_, out) = run(&f, &f.signer, &["--questions", "C-2"]);
    assert_eq!(out.trim(), "No open questions.");
}
