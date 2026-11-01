//! Ports of test_cli and test_gnupg_service.

mod common;

use common::Fixture;
use factum::cli::{self, Args};
use factum::notes::EntryFilter;
use factum::signer::{FakeSigner, GnupgSigner, Signer};
use factum::verifier::Level;

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
    assert_eq!(run(&f, &f.signer, &["--new-case", "  "]).0, 2);
}

#[test]
fn set_active_on_archived_case_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.archive_case(case_id).unwrap();
    assert_eq!(run(&f, &f.signer, &["--set-active", "case", "C-1"]).0, 2);
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
    assert!(
        out.contains(&format!("  seal folder checked: {}\n", f.seal_dir.display())),
        "{out}"
    );
    f.exec("UPDATE entries SET text = 'tampered'");
    let (code, out) = run(&f, &f.signer, &["--verify", "C-1"]);
    assert_eq!(code, 1);
    assert!(out.contains("FAIL"));
}

#[test]
fn verify_without_active_case_fails() {
    let f = Fixture::new();
    assert_eq!(run(&f, &f.signer, &["--verify"]).0, 2);
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
    assert_eq!(code, 2);
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
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("ERROR:root:This database was created by an older factum version")
    );
}

/// The factum binary with its user folders under `home` (XDG) and no FACTUM_* variables, started in `cwd`.
#[cfg(target_os = "linux")]
fn run_binary(home: &std::path::Path, cwd: &std::path::Path, argv: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_factum"))
        .args(argv)
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("FACTUM_DB")
        .env_remove("FACTUM_SEAL_DIR")
        .env_remove("LOG_LEVEL")
        .output()
        .unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn export_warns_of_characters_the_pdf_cannot_show() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    assert_eq!(
        run_binary(dir.path(), dir.path(), &["--new-case", "C-1", "Case"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(run_binary(dir.path(), dir.path(), &["案件"]).status.code(), Some(0));
    let argv = ["--export", "--format", "pdf", "--out", out.to_str().unwrap()];
    let stderr = String::from_utf8(run_binary(dir.path(), dir.path(), &argv).stderr).unwrap();
    assert!(stderr.contains("The PDF cannot show 2 character(s)"), "{stderr}");
    assert!(stderr.contains("the HTML report shows them"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_dotenv_in_the_current_directory_is_not_read() {
    let home = tempfile::tempdir().unwrap();
    let work = home.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let planted = home.path().join("planted.db");
    std::fs::write(work.join(".env"), format!("FACTUM_DB={}\n", planted.display())).unwrap();
    let output = run_binary(home.path(), &work, &["--list-cases"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(!planted.exists());
    assert!(home.path().join("data/factum/factum.db").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn starting_factum_moves_the_seal_folder_setting_to_the_user_config() {
    let home = tempfile::tempdir().unwrap();
    let env = home.path().join("config/factum/.env");
    let db_path = home.path().join("data/factum/factum.db");
    let plant = |folder: &str| {
        let db = factum::Db::open(&db_path).unwrap();
        db.set_setting(factum::seals::SEAL_DIR_SETTING, folder).unwrap();
    };
    plant("/media/usb/seals");
    let output = run_binary(home.path(), home.path(), &["--list-cases"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("WARNING:root:The seal folder /media/usb/seals was taken"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        factum::config::file_seal_dir(&env),
        Some(std::path::PathBuf::from("/media/usb/seals"))
    );
    // a database changed later cannot replace it
    plant("/tmp/empty");
    assert!(run_binary(home.path(), home.path(), &["--list-cases"]).status.success());
    assert_eq!(
        factum::config::file_seal_dir(&env),
        Some(std::path::PathBuf::from("/media/usb/seals"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn after_a_clean_first_start_a_planted_seal_folder_is_never_moved() {
    let home = tempfile::tempdir().unwrap();
    let env = home.path().join("config/factum/.env");
    assert!(run_binary(home.path(), home.path(), &["--list-cases"]).status.success());
    let db = factum::Db::open(&home.path().join("data/factum/factum.db")).unwrap();
    db.set_setting(factum::seals::SEAL_DIR_SETTING, "/tmp/empty").unwrap();
    drop(db);
    let before = std::fs::read(&env).ok();
    assert!(run_binary(home.path(), home.path(), &["--list-cases"]).status.success());
    assert_eq!(std::fs::read(&env).ok(), before);
    assert_eq!(factum::config::file_seal_dir(&env), None);
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
fn questions_flag_is_gone() {
    use clap::Parser;
    assert!(Args::try_parse_from(["factum", "--questions"]).is_err());
}

#[test]
fn new_evidence_with_description() {
    let f = Fixture::new();
    let case_id = f.factum().create_case("C-1", "Case", "").unwrap();
    f.factum().set_active_case(case_id).unwrap();
    let (code, _) = run(&f, &f.signer, &["--new-evidence", "disk", "--description", " seized "]);
    assert_eq!(code, 0);
    let evidence_id = f.factum().list_evidence_for_case(case_id, false).unwrap()[0];
    assert_eq!(f.factum().get_evidence(evidence_id).unwrap().unwrap().details, "seized");
}

// --- gpg's verdicts, with real signatures

const JANUARY: &str = "20200115T000000";
const AFTER_EXPIRY: &str = "20200301T000000";

/// A home with a key that expired on 2020-02-01, on a clock in January 2020 until `home.set_clock(None)`.
fn expiring_home() -> Option<common::GpgHome> {
    common::GpgHome::at_time(
        Some("20200101T000000"),
        "Expired Key <expired@factum.invalid>",
        "sign",
        "2020-02-01",
    )
}

#[test]
fn signature_of_a_key_expired_since_verifies_with_a_warning() {
    let Some(home) = expiring_home() else { return };
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let note = factum.create_note("signed before expiry", None, case_id).unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    assert_eq!(factum.verify_case(case_id, None).unwrap().overall(), Level::Ok);
    home.set_clock(None);
    let signer = GnupgSigner::without_key(Some(home.path()));
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Warn, "{:?}", report.findings);
    let check = &report.entry_result(note).unwrap().signature;
    assert!(check.valid && check.trusted && check.key_expired);
    assert_eq!(check.status, "signature valid");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "key_expired" && f.entry_id == Some(note) && f.message.contains("has expired since")),
        "{:?}",
        report.findings
    );
}

#[test]
fn expired_key_that_is_not_ultimately_trusted_stays_untrusted() {
    let Some(home) = expiring_home() else { return };
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let signature = signer.sign_text(r#"{"a":1}"#).unwrap();
    let key = home.gpg_ok(&["--armor", "--export"]).stdout;
    let elsewhere = require_gpg!("Someone Else <else@factum.invalid>");
    let path = elsewhere.path().join("key.asc");
    std::fs::write(&path, key).unwrap();
    elsewhere.gpg_ok(&["--batch", "--import", path.to_str().unwrap()]);
    let result = GnupgSigner::without_key(Some(elsewhere.path())).verify_signature(&signature);
    assert!(result.valid && result.key_expired);
    assert_eq!(result.trust, None);
}

/// A key valid only through this home's certification, whose signing subkey expired on 2020-02-01; and text it signed.
fn certified_key_with_expired_subkey(home: &common::GpgHome) -> Option<String> {
    let owner = common::GpgHome::at_time(Some("20200101T000000"), "Colleague <c@factum.invalid>", "cert", "never")?;
    let fingerprint = owner.fingerprints("c@factum.invalid")[0].clone();
    owner.gpg_ok(&[
        "--batch",
        "--passphrase",
        "",
        "--quick-add-key",
        &fingerprint,
        "ed25519",
        "sign",
        "2020-02-01",
    ]);
    let f = Fixture::new();
    let signature = gpg(&f, &owner).sign_text(r#"{"a":1}"#).unwrap();
    let path = home.path().join("key.asc");
    std::fs::write(&path, owner.gpg_ok(&["--armor", "--export"]).stdout).unwrap();
    home.gpg_ok(&["--batch", "--import", path.to_str().unwrap()]);
    home.gpg_ok(&["--batch", "--yes", "--quick-lsign-key", &fingerprint]);
    Some(signature)
}

#[test]
fn an_expired_subkey_on_a_certified_primary_key_stays_trusted() {
    let home = require_gpg!("Examiner <examiner@factum.invalid>");
    let Some(signature) = certified_key_with_expired_subkey(&home) else {
        return;
    };
    let listing = home
        .gpg_ok(&["--list-keys", "--with-colons", "c@factum.invalid"])
        .stdout;
    assert!(String::from_utf8_lossy(&listing).contains("\npub:f:"));
    let result = GnupgSigner::without_key(Some(home.path())).verify_signature(&signature);
    assert!(result.valid && result.key_expired, "{result:?}");
    assert_eq!(result.trust.as_deref(), Some("TRUST_FULLY"));
}

#[test]
fn a_remembered_expired_key_refuses_to_sign_instead_of_going_unsigned() {
    let Some(home) = expiring_home() else { return };
    let f = Fixture::new();
    let key = gpg(&f, &home).active_key().unwrap();
    home.set_clock(None);
    let signer = GnupgSigner::new(&f.db, Some(home.path()));
    assert_eq!(signer.active_key(), Some(key.clone()));
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let error = factum.create_case("C-1", "Case", "").unwrap_err();
    assert_eq!(error.kind, factum::error::ErrorKind::Signing, "{error:?}");
    assert_eq!(f.count("SELECT COUNT(*) FROM cases"), 0);
    // the key dialog shows it as expired; it is not offered to anyone who has not chosen it
    let listed = signer.list_keys();
    assert!(listed.len() == 1 && listed[0].keyid == key && listed[0].expired());
    assert!(GnupgSigner::without_key(Some(home.path())).list_keys().is_empty());
}

#[test]
fn a_remembered_revoked_key_refuses_to_sign() {
    let home = require_gpg!("Revoked <revoked@factum.invalid>");
    let f = Fixture::new();
    let key = gpg(&f, &home).active_key().unwrap();
    revoke(&home, "revoked@factum.invalid");
    let signer = GnupgSigner::new(&f.db, Some(home.path()));
    assert_eq!(signer.active_key(), Some(key));
    assert_eq!(signer.sign_text("text"), None);
    assert!(signer.last_sign_failed());
    assert!(signer.list_keys()[0].revoked());
}

#[test]
fn a_remembered_key_gone_from_the_keyring_is_no_active_key() {
    let home = require_gpg!("Gone <gone@factum.invalid>");
    let f = Fixture::new();
    gpg(&f, &home);
    let fingerprint = home.fingerprints("gone@factum.invalid")[0].clone();
    home.gpg_ok(&["--batch", "--yes", "--delete-secret-and-public-key", &fingerprint]);
    let signer = GnupgSigner::new(&f.db, Some(home.path()));
    assert_eq!(signer.active_key(), None);
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    assert!(factum.create_case("C-1", "Case", "").is_ok());
}

#[test]
fn signature_made_after_the_key_expired_is_invalid() {
    let home = common::GpgHome::at_time(Some("20200101T000000"), "Late <late@factum.invalid>", "sign", "never");
    let Some(home) = home else { return };
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    home.set_clock(Some(JANUARY));
    let before = signer.sign_text("before").unwrap();
    home.set_clock(Some(AFTER_EXPIRY));
    let after = signer.sign_text("after").unwrap();
    // gpg refuses to sign with an expired key: the expiry comes later, on a clock set back
    home.set_clock(Some("20200120T000000"));
    let fingerprint = &home.fingerprints("late@factum.invalid")[0];
    home.gpg_ok(&[
        "--batch",
        "--passphrase",
        "",
        "--quick-set-expire",
        fingerprint,
        "2020-02-01",
    ]);
    home.set_clock(None);
    assert!(signer.verify_signature(&before).valid);
    let result = signer.verify_signature(&after);
    assert!(!result.valid);
    assert_eq!(result.status, "signature made after the signing key expired");
}

#[test]
fn signature_of_a_revoked_key_stays_invalid() {
    let home = require_gpg!("Revoked <revoked@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let signature = signer.sign_text(r#"{"a":1}"#).unwrap();
    revoke(&home, "revoked@factum.invalid");
    let result = signer.verify_signature(&signature);
    assert!(!result.valid);
    assert_eq!(result.status, "signing key was revoked");
}

/// Imports the revocation certificate gpg made with the key.
fn revoke(home: &common::GpgHome, user_id: &str) {
    let fingerprint = &home.fingerprints(user_id)[0];
    let certificate = home.path().join(format!("openpgp-revocs.d/{fingerprint}.rev"));
    let text = std::fs::read_to_string(&certificate).unwrap();
    std::fs::write(&certificate, text.replace(":-----BEGIN", "-----BEGIN")).unwrap();
    home.gpg_ok(&["--batch", "--import", certificate.to_str().unwrap()]);
}

#[test]
fn a_key_with_a_signing_subkey_only_signs_and_reports_its_primary_fingerprint() {
    let user_id = "Subkey Signer <subkey@factum.invalid>";
    let Some(home) = common::GpgHome::with_key(user_id, "cert", "never") else {
        return;
    };
    let primary = home.fingerprints("subkey@factum.invalid")[0].clone();
    home.gpg_ok(&[
        "--batch",
        "--passphrase",
        "",
        "--quick-add-key",
        &primary,
        "ed25519",
        "sign",
        "never",
    ]);
    let subkey = home.fingerprints("subkey@factum.invalid")[1].clone();
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    assert_eq!(signer.list_keys()[0].fingerprint, primary);
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let note = factum.create_note("signed by the subkey", None, case_id).unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
    assert_eq!(report.signers, vec![(primary.clone(), Some(user_id.to_string()))]);
    let check = &report.entry_result(note).unwrap().signature;
    assert_eq!(check.fingerprint.as_ref(), Some(&primary));
    assert_eq!(check.signing_subkey.as_ref(), Some(&subkey));
}

#[test]
fn a_primary_key_signature_keeps_its_fingerprint() {
    let home = require_gpg!("Primary <primary@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let result = signer.verify_signature(&signer.sign_text("text").unwrap());
    assert_eq!(
        result.fingerprint.as_ref(),
        Some(&home.fingerprints("primary@factum.invalid")[0])
    );
    assert_eq!(result.signing_subkey, None);
}

#[cfg(unix)]
#[test]
fn checking_a_symmetric_message_asks_for_no_passphrase() {
    use std::os::unix::fs::PermissionsExt;
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let dir = home.path();
    let marker = dir.join("pinentry-was-started");
    let pinentry = dir.join("pinentry");
    std::fs::write(&pinentry, format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display())).unwrap();
    std::fs::set_permissions(&pinentry, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        dir.join("gpg-agent.conf"),
        format!("pinentry-program {}\n", pinentry.display()),
    )
    .unwrap();
    let message = dir.join("message.asc");
    std::fs::write(dir.join("plain"), "text").unwrap();
    home.gpg_ok(&[
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "secret",
        "--symmetric",
        "--armor",
        "--output",
        message.to_str().unwrap(),
        dir.join("plain").to_str().unwrap(),
    ]);
    let _ = std::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(&dir)
        .args(["--kill", "gpg-agent"])
        .output();
    let signer = GnupgSigner::without_key(Some(dir.clone()));
    let text = std::fs::read_to_string(&message).unwrap();
    assert!(!signer.verify_signature(&text).valid);
    assert!(!signer.verify_detached(&text, b"data").valid);
    assert!(!marker.exists());
}

#[test]
fn two_signatures_in_one_block_do_not_count() {
    let home = require_gpg!("First <first@factum.invalid>");
    home.gpg_ok(&[
        "--batch",
        "--passphrase",
        "",
        "--quick-gen-key",
        "Second <second@factum.invalid>",
        "ed25519",
        "sign",
        "never",
    ]);
    let input = home.path().join("input");
    let output = home.path().join("output.asc");
    std::fs::write(&input, "text").unwrap();
    home.gpg_ok(&[
        "--batch",
        "--local-user",
        "first@factum.invalid",
        "--local-user",
        "second@factum.invalid",
        "--output",
        output.to_str().unwrap(),
        "--clearsign",
        input.to_str().unwrap(),
    ]);
    let signature = std::fs::read_to_string(&output).unwrap();
    let result = GnupgSigner::without_key(Some(home.path())).verify_signature(&signature);
    assert!(!result.valid);
    assert_eq!(result.status, "more than one signature");
}

#[test]
fn a_good_signature_followed_by_garbage_does_not_count() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let signature = signer.sign_text("text").unwrap();
    assert!(signer.verify_signature(&signature).valid);
    let result = signer.verify_signature(&format!("{signature}{signature}"));
    assert!(!result.valid);
    assert_eq!(result.status, "bad signature");
}

// --- the verification cache

/// A signer that cannot run gpg: whatever it says good comes from the cache.
fn cache_only(home: &common::GpgHome) -> GnupgSigner {
    GnupgSigner::with_binary("/nonexistent/gpg".into(), Some(home.path()))
}

#[test]
fn repeated_checks_do_not_run_gpg_again() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let factum = factum::Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note("cached", None, case_id).unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    let first = factum.verify_case(case_id, None).unwrap();
    assert_eq!(first.overall(), Level::Ok);
    let signature = signer.sign_detached(b"data").unwrap();
    assert!(signer.verify_detached(&signature, b"data").valid);
    let cached = cache_only(&home);
    let factum = factum::Factum::with_seal_dir(&f.db, &cached, Some(f.seal_dir.clone()));
    let second = factum.verify_case(case_id, None).unwrap();
    assert_eq!(second.overall(), Level::Ok, "{:?}", second.findings);
    assert_eq!(second.signers, first.signers);
    assert!(cached.verify_detached(&signature, b"data").valid);
}

#[test]
fn a_changed_signature_or_changed_data_is_checked_again() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let clearsigned = signer.sign_text("text").unwrap();
    let detached = signer.sign_detached(b"data").unwrap();
    assert!(signer.verify_signature(&clearsigned).valid);
    assert!(signer.verify_detached(&detached, b"data").valid);
    assert!(!signer.verify_signature(&clearsigned.replace("text", "tExt")).valid);
    assert!(!signer.verify_detached(&detached, b"other data").valid);
    let cached = cache_only(&home);
    assert!(!cached.verify_signature(&format!("x{clearsigned}")).valid);
    assert!(!cached.verify_detached(&detached, b"other data").valid);
}

#[test]
fn a_key_removed_or_revoked_after_a_check_is_seen_at_once() {
    let home = require_gpg!("Removed <removed@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let signature = signer.sign_text("text").unwrap();
    assert!(signer.verify_signature(&signature).valid);
    assert!(signer.verify_signature(&signature).valid);
    revoke(&home, "removed@factum.invalid");
    let result = signer.verify_signature(&signature);
    assert!(!result.valid);
    assert_eq!(result.status, "signing key was revoked");
    let fingerprint = &home.fingerprints("removed@factum.invalid")[0];
    home.gpg_ok(&["--batch", "--yes", "--delete-secret-and-public-key", fingerprint]);
    let result = signer.verify_signature(&signature);
    assert!(!result.valid);
    assert_eq!(result.status, "no public key");
}

#[test]
fn a_trust_change_after_a_check_is_seen_at_once() {
    let home = require_gpg!("Trust <trust@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg(&f, &home);
    let signature = signer.sign_text("text").unwrap();
    assert_eq!(
        signer.verify_signature(&signature).trust.as_deref(),
        Some("TRUST_ULTIMATE")
    );
    let fingerprint = &home.fingerprints("trust@factum.invalid")[0];
    let path = home.path().join("ownertrust");
    std::fs::write(&path, format!("{fingerprint}:3:\n")).unwrap();
    home.gpg_ok(&["--batch", "--import-ownertrust", path.to_str().unwrap()]);
    assert_ne!(
        signer.verify_signature(&signature).trust.as_deref(),
        Some("TRUST_ULTIMATE")
    );
}

fn two_cases_sharing_a_number(f: &Fixture) -> (i64, i64) {
    let factum = f.factum();
    let first = factum.create_case("2026/1", "Alpha", "").unwrap();
    factum.archive_case(first).unwrap();
    let second = factum.create_case("2026/1", "Beta", "").unwrap();
    (first, second)
}

#[test]
fn an_exact_number_or_name_beats_a_numeric_id() {
    let f = Fixture::new();
    let factum = f.factum();
    let first = factum.create_case("2", "Alpha", "").unwrap();
    let second = factum.create_case("7", "Beta", "").unwrap();
    let named_two = factum.create_case("C-9", "1", "").unwrap();
    assert_eq!(cli::find_case_id(&factum, "2").unwrap(), Some(first));
    assert_eq!(cli::find_case_id(&factum, "1").unwrap(), Some(named_two));
    // nothing matches by number or name: an id
    assert_eq!(
        cli::find_case_id(&factum, &named_two.to_string()).unwrap(),
        Some(named_two)
    );
    assert_eq!(cli::find_case_id(&factum, "#2").unwrap(), Some(second));
    assert_eq!(cli::find_case_id(&factum, "#1").unwrap(), Some(first));
    assert_eq!(cli::find_case_id(&factum, "#99").unwrap(), None);
    assert_eq!(cli::find_case_id(&factum, "Beta").unwrap(), Some(second));
    // underscores are no longer dropped
    assert_eq!(cli::find_case_id(&factum, "1_0").unwrap(), None);
}

#[test]
fn an_ambiguous_case_lookup_lists_the_candidates() {
    let f = Fixture::new();
    let (first, second) = two_cases_sharing_a_number(&f);
    let (code, _) = run(&f, &f.signer, &["--set-active", "case", "2026/1"]);
    assert_eq!(code, 2);
    let error = cli::find_case_id(&f.factum(), "2026/1").unwrap_err().message;
    assert!(
        error.contains(&format!("#{first} 2026/1 Alpha")) && error.contains(&format!("#{second} 2026/1 Beta")),
        "{error}"
    );
    let (code, out) = run(&f, &f.signer, &["--set-active", "case", &format!("#{second}")]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn an_ambiguous_evidence_lookup_lists_the_candidates() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.set_active_case(case_id).unwrap();
    let a = factum.create_evidence(case_id, "disk", "", "").unwrap();
    let b = factum.create_evidence(case_id, "disk", "", "").unwrap();
    let error = cli::find_evidence_id(&factum, "disk", case_id).unwrap_err().message;
    assert!(
        error.contains(&format!("#{a} disk")) && error.contains(&format!("#{b} disk")),
        "{error}"
    );
    assert_eq!(
        cli::find_evidence_id(&factum, &format!("#{b}"), case_id).unwrap(),
        Some(b)
    );
    assert_eq!(
        cli::find_evidence_id(&factum, &a.to_string(), case_id).unwrap(),
        Some(a)
    );
    assert_eq!(run(&f, &f.signer, &["--set-active", "evidence", "disk"]).0, 2);
}

#[test]
fn a_case_row_that_cannot_be_read_does_not_stop_the_lookup_or_verify() {
    let f = Fixture::new();
    let factum = f.factum();
    let bad = factum.create_case("C-1", "Bad", "").unwrap();
    let good = factum.create_case("C-2", "Good", "").unwrap();
    f.exec(&format!("UPDATE cases SET case_name = X'00' WHERE id = {bad}"));
    assert_eq!(cli::find_case_id(&factum, "C-2").unwrap(), Some(good));
    assert_eq!(cli::find_case_id(&factum, &bad.to_string()).unwrap(), Some(bad));
    assert_eq!(cli::find_case_id(&factum, &format!("#{bad}")).unwrap(), Some(bad));
    let (code, out) = run(&f, &f.signer, &["--verify", &bad.to_string()]);
    assert!(out.contains("column 'case_name'"), "{out}");
    assert_eq!(code, 1, "{out}");
}

#[test]
fn a_note_with_an_action_flag_is_refused() {
    use clap::Parser;
    // flag plus the values it needs; every action flag of the conflict list
    let flags: [&[&str]; 12] = [
        &["--gui"],
        &["--list-cases"],
        &["--list-evidence"],
        &["--list-gpg"],
        &["--new-case", "N1"],
        &["--new-evidence", "E"],
        &["--set-active", "case", "1"],
        &["--correct", "1", "text"],
        &["--verify"],
        &["--checkpoint"],
        &["--sign-unsigned"],
        &["--export"],
    ];
    for flag in flags {
        let argv: Vec<&str> = ["factum", "a note"].into_iter().chain(flag.iter().copied()).collect();
        let error = Args::try_parse_from(argv).unwrap_err();
        assert_eq!(error.exit_code(), 2, "{flag:?}");
    }
    assert!(Args::try_parse_from(["factum", "a note", "--log-level", "DEBUG"]).is_ok());
}

#[test]
fn export_of_a_failing_case_warns_and_exits_1_with_the_files_written() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note("hello", None, case_id).unwrap();
    f.exec("UPDATE entries SET text = 'tampered' WHERE kind = 'note'");
    let out_dir = f.path().join("out");
    let (code, out) = run(
        &f,
        &f.signer,
        &["--export", "C-1", "--format", "md", "--out", out_dir.to_str().unwrap()],
    );
    assert_eq!(code, 1, "{out}");
    assert!(out.lines().any(|l| l.ends_with(".md")) && out_dir.read_dir().unwrap().count() == 1);
}

#[test]
fn an_expired_or_revoked_active_key_is_listed_with_its_state() {
    let key = |validity: &str| factum::signer::GpgKey {
        keyid: "ABCD1234".into(),
        uids: vec!["Jane <j@example.org>".into()],
        validity: validity.into(),
        ..Default::default()
    };
    assert_eq!(
        cli::gpg_line(&key("u"), true),
        "  ABCD1234 [active]  Jane <j@example.org>"
    );
    assert_eq!(
        cli::gpg_line(&key("e"), true),
        "  ABCD1234 [active] (expired)  Jane <j@example.org>"
    );
    assert_eq!(
        cli::gpg_line(&key("r"), false),
        "  ABCD1234 (revoked)  Jane <j@example.org>"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_database_line_goes_to_stderr_only_when_factum_db_is_set() {
    let home = tempfile::tempdir().unwrap();
    let output = run_binary(home.path(), home.path(), &["--list-cases"]);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Database:"));
    let db = home.path().join("x.db");
    let run_with_db = |argv: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_factum"))
            .args(argv)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("FACTUM_DB", &db)
            .output()
            .unwrap()
    };
    let output = run_with_db(&["--list-cases"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches(&format!("Database: {}\n", db.display())).count(),
        1,
        "{stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Database:"));
    // clap's own usage errors exit 2, and a note with an action flag is one
    assert_eq!(run_with_db(&["--no-such-flag"]).status.code(), Some(2));
    assert_eq!(run_with_db(&["a note", "--list-cases"]).status.code(), Some(2));
}

#[cfg(target_os = "linux")]
#[test]
fn a_missing_hash_id_or_a_padded_query_exits_2_through_the_binary() {
    let home = tempfile::tempdir().unwrap();
    let work = home.path();
    assert_eq!(
        run_binary(work, work, &["--new-case", "5", "Five"]).status.code(),
        Some(0)
    );
    for query in ["#99", "#2", " 5", "#5 ", "Five two", "F ive"] {
        let output = run_binary(work, work, &["--verify", query]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // id 2 does not exist and the number 5 is not matched by a padded query: no name fallback
        assert_eq!(output.status.code(), Some(2), "{query:?}: {stderr}");
        assert!(
            stderr.contains(&format!("No case found matching '{query}'")),
            "{stderr}"
        );
    }
    let output = run_binary(work, work, &["--verify", "5"]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Case 5:"));
}

#[test]
fn a_padded_or_signed_id_is_not_an_id() {
    let f = Fixture::new();
    let factum = f.factum();
    let id = factum.create_case("C-1", "Case", "").unwrap();
    assert_eq!(cli::find_case_id(&factum, &id.to_string()).unwrap(), Some(id));
    for query in [format!(" {id}"), format!("#{id} "), format!("+{id}"), format!("# {id}")] {
        assert_eq!(cli::find_case_id(&factum, &query).unwrap(), None, "{query:?}");
    }
}
