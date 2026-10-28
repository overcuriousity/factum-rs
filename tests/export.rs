//! Ports of test_reports, test_exporter and test_bundle (the verify.py runs need python3, and gpg for signatures).

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::Fixture;
use factum::Factum;
use factum::export::html::render_html;
use factum::export::markdown::{inline, prose, render_markdown};
use factum::export::model::ReportModel;
use factum::images::NoteImage;
use factum::signer::{FakeSigner, GnupgSigner, Signer};
use factum::verifier::Level;
use sha2::Digest;

const TRICKY: &str = "<script>alert(1)</script> **bold** ```fence``` \n-----BEGIN PGP SIGNATURE-----";
const EXPORTED: &str = "2026-10-05T12:00:00.000Z";

fn model_case(factum: &Factum) -> i64 {
    let case_id = factum.create_case("C-1", "Case <b>", "desc").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "abc", "").unwrap();
    let first = factum.create_note("first", Some(evidence_id), case_id).unwrap();
    factum.create_note(TRICKY, None, case_id).unwrap();
    factum.correct_note(first, "first, corrected").unwrap();
    factum::tags::add_label(factum.db, first, "review").unwrap();
    case_id
}

fn build(factum: &Factum, case_id: i64, seal_id: i64, key: Option<&str>) -> ReportModel {
    let report = factum.verify_case(case_id, None).unwrap();
    let seal = factum.get_tree_head(seal_id).unwrap().unwrap();
    factum
        .build_model(report, seal, key.map(str::to_string), EXPORTED)
        .unwrap()
}

fn model(f: &Fixture) -> ReportModel {
    let factum = f.factum();
    let case_id = model_case(&factum);
    let seal_id = factum.seal(case_id, "export").unwrap();
    build(&factum, case_id, seal_id, Some("FAKEKEY1"))
}

#[test]
fn timeline_shows_newest_version_at_the_original_position() {
    let f = Fixture::new();
    let model = model(&f);
    let texts: Vec<&str> = model.timeline.iter().map(|item| item.text.as_str()).collect();
    assert_eq!(texts[2..], ["first, corrected", TRICKY]);
    let corrected = &model.timeline[2];
    assert!(corrected.version == 2 && corrected.origin_id != corrected.entry_id);
    assert!(corrected.correction_note().unwrap().starts_with("Corrected "));
    assert_eq!(model.appendix.len(), 5); // every leaf, including the superseded version
}

#[test]
fn reports_show_the_evidence_description() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = model_case(&factum);
    let evidence_id = factum.list_evidence_for_case(case_id, false).unwrap()[0];
    factum.update_evidence_details(evidence_id, "seized at desk 4").unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    for text in [render_html(&model, false), render_markdown(&model)] {
        assert!(text.contains("disk — seized at desk 4"), "{text}");
    }
}

#[test]
fn short_line() {
    let f = Fixture::new();
    let model = model(&f);
    let item = model.timeline.last().unwrap();
    assert!(item.short_line().starts_with(&format!(
        "#{} · leaf {}… · signed ",
        item.entry_id,
        &item.leaf_hash[..12]
    )));
    assert!(item.short_line().ends_with('✓'));
}

#[test]
fn html_escapes_note_text() {
    let f = Fixture::new();
    let html = render_html(&model(&f), false);
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("Case &lt;b&gt;"));
    assert!(html.contains("<details>") && html.contains("Integrity appendix"));
    assert!(html.contains("Verification: OK"));
}

#[test]
fn print_variant_expands_the_appendix() {
    let f = Fixture::new();
    let html = render_html(&model(&f), true);
    assert!(!html.contains("<details>") && html.contains("Integrity appendix"));
}

#[test]
fn notes_come_first_and_technical_data_last() {
    let f = Fixture::new();
    let model = model(&f);
    for text in [render_html(&model, false), render_markdown(&model)] {
        let notes = text.find("Notes (2)").unwrap();
        let corrected = text.find("first, corrected").unwrap();
        let activity = text.find("Case activity").unwrap();
        let verification = text.find("Verification").unwrap();
        let appendix = text.find("Integrity appendix").unwrap();
        assert!(notes < corrected && corrected < activity && activity < verification && verification < appendix);
        // hashes and signatures stay out of the readable part
        let readable = &text[..verification];
        assert!(!readable.contains(&model.timeline.last().unwrap().leaf_hash[..12]));
        assert!(
            !readable
                .replace("-----BEGIN PGP SIGNATURE-----", "")
                .contains("BEGIN PGP")
        );
    }
}

#[test]
fn markdown_note_text_is_literal_prose() {
    let f = Fixture::new();
    let markdown = render_markdown(&model(&f));
    assert!(markdown.contains(&prose(TRICKY).join("\n")));
    assert!(!markdown.contains("<script>"));
    assert!(markdown.contains("## Integrity appendix"));
    assert!(markdown.contains("Labels (not signed): review"));
    assert_eq!(inline("R&D &amp; <b>"), "R\\&D \\&amp; \\<b\\>");
}

#[test]
fn failing_case_shows_fail_banner() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = model_case(&factum);
    let seal_id = factum.seal(case_id, "export").unwrap();
    let last = build(&factum, case_id, seal_id, None).timeline.last().unwrap().entry_id;
    f.exec(&format!("UPDATE entries SET text = 'tampered' WHERE id = {last}"));
    let failing = build(&factum, case_id, seal_id, None);
    let html = render_html(&failing, false);
    assert!(html.contains("Verification: FAIL") && html.contains("status-FAIL"));
    // the failure is visible at the top and on the note itself, not only in the technical part
    assert!(html.find("status-FAIL").unwrap() < html.find("Notes (").unwrap());
    assert!(html.contains("This note failed the integrity check"));
    let markdown = render_markdown(&failing);
    assert!(markdown.find("> **FAIL**").unwrap() < markdown.find("## Notes").unwrap());
    assert!(markdown.contains("**Result: FAIL**") && markdown.contains("This note failed the integrity check"));
}

#[test]
fn untrusted_signatures_are_not_shown_as_valid() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = model_case(&factum);
    let seal_id = factum.seal(case_id, "export").unwrap();
    let untrusted = FakeSigner::with_trust(true, "TRUST_UNDEFINED");
    let other = Factum::with_seal_dir(&f.db, &untrusted, Some(f.seal_dir.clone()));
    let model = build(&other, case_id, seal_id, None);
    let item = model.timeline.last().unwrap();
    assert_eq!(item.signature_state, "untrusted");
    assert!(!item.short_line().contains('✓') && item.short_line().contains("untrusted"));
}

// --- exporter

fn export_case(factum: &Factum) -> i64 {
    let case_id = factum.create_case("2026/04 Müller", "Case", "").unwrap();
    factum.create_note("hello", None, case_id).unwrap();
    case_id
}

#[test]
fn export_all_formats() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = export_case(&factum);
    let out = f.path().join("out");
    let paths = factum.export(case_id, &["html", "pdf", "md", "bundle"], &out).unwrap();
    let suffixes: Vec<String> = paths
        .iter()
        .map(|p| p.extension().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(suffixes, vec!["html", "pdf", "md", "zip"]);
    assert!(paths.iter().all(|p| std::fs::metadata(p).unwrap().len() > 0));
    assert_eq!(
        factum.list_tree_heads(case_id).unwrap().last().unwrap().reason,
        "export"
    );
    assert!(std::fs::read_to_string(&paths[0]).unwrap().contains("Verification: OK"));
    let pdf = std::fs::read(&paths[1]).unwrap();
    assert!(pdf.starts_with(b"%PDF-") && pdf.len() > 1000);
    assert!(read_zip(&paths[3])["report.pdf"].starts_with(b"%PDF-"));
}

#[test]
fn pdf_is_well_formed() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = model_case(&factum);
    for n in 0..60 {
        factum
            .create_note(
                &format!("note {n} with a long line {}", "word ".repeat(40)),
                None,
                case_id,
            )
            .unwrap();
    }
    let [path] = factum
        .export(case_id, &["pdf"], &f.path().join("out"))
        .unwrap()
        .try_into()
        .unwrap();
    let pdf = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&pdf);
    assert!(pdf.ends_with(b"%%EOF\n"));
    // every xref offset points at the start of its object
    let xref_at: usize = text
        .rsplit("startxref\n")
        .next()
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let table = String::from_utf8_lossy(&pdf[xref_at..]).into_owned();
    let mut checked = 0;
    for (number, line) in table
        .lines()
        .skip(3)
        .take_while(|line| line.ends_with(" n "))
        .enumerate()
    {
        let offset: usize = line[..10].parse().unwrap();
        assert!(
            pdf[offset..].starts_with(format!("{} 0 obj", number + 1).as_bytes()),
            "object {}",
            number + 1
        );
        checked += 1;
    }
    assert!(checked > 10);
    assert!(text.matches("/Type /Page ").count() > 2);
    if which::which("pdftotext").is_ok() {
        let output = Command::new("pdftotext").arg(&path).arg("-").output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let extracted = String::from_utf8_lossy(&output.stdout);
        assert!(
            extracted.contains("Case <b>") && extracted.contains("Integrity appendix"),
            "{extracted}"
        );
    }
}

#[test]
fn export_file_names_are_safe() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = export_case(&factum);
    let out = f.path().join("out");
    let paths = factum.export(case_id, &["md"], &out).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].parent().unwrap(), out);
    assert!(
        paths[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("2026-04-Müller_")
    );
}

#[test]
fn failing_case_is_still_exported() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = export_case(&factum);
    f.exec("UPDATE entries SET text = 'tampered' WHERE kind = 'note'");
    let paths = factum.export(case_id, &["html"], f.path()).unwrap();
    assert!(
        std::fs::read_to_string(&paths[0])
            .unwrap()
            .contains("Verification: FAIL")
    );
}

#[test]
fn unknown_format_is_refused() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = export_case(&factum);
    assert!(
        factum
            .export(case_id, &["docx"], f.path())
            .unwrap_err()
            .message
            .contains("Unknown export format")
    );
}

#[test]
fn case_with_unparsable_payload_is_still_exported() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = export_case(&factum);
    f.exec(&format!(
        "UPDATE entries SET payload_json = '{{bad' WHERE case_id = {case_id} AND kind = 'system'"
    ));
    let paths = factum.export(case_id, &["html", "bundle"], f.path()).unwrap();
    assert!(
        std::fs::read_to_string(&paths[0])
            .unwrap()
            .contains("Verification: FAIL")
            && paths[1].exists()
    );
}

// --- bundle

const REPORTS: [(&str, &[u8]); 3] = [
    ("report.html", b"<html></html>"),
    ("report.pdf", b"%PDF-1.4"),
    ("report.md", b"# report"),
];

fn make_bundle(db: &factum::Db, signer: &dyn Signer, seal_dir: &Path, out_dir: &Path, case_file: &str) -> PathBuf {
    let factum = Factum::with_seal_dir(db, signer, Some(seal_dir.to_path_buf()));
    let case_id = factum.create_case(case_file, "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "abc", "").unwrap();
    let first = factum
        .create_note("Müller ✓ 🦊\r\nzweite Zeile  ", Some(evidence_id), case_id)
        .unwrap();
    factum.correct_note(first, "corrected").unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, signer.active_key().as_deref());
    let reports: Vec<(&str, Vec<u8>)> = REPORTS
        .iter()
        .map(|(name, content)| (*name, content.to_vec()))
        .collect();
    factum.build_bundle(&model, &reports, &out_dir.join("C-1.zip")).unwrap()
}

fn read_zip(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut files = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).unwrap();
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        files.insert(file.name().unwrap().to_string(), content);
    }
    files
}

fn rewrite_zip(path: &Path, changes: &[(&str, Vec<u8>)]) {
    let mut files = read_zip(path);
    for (name, content) in changes {
        files.insert(name.to_string(), content.clone());
    }
    let mut writer = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    for (name, content) in files {
        writer
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&content).unwrap();
    }
    writer.finish().unwrap();
}

fn case_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&read_zip(path)["case.json"]).unwrap()
}

/// Runs the bundled verify.py from the bundle itself; None without python3.
fn run_verify(bundle: &Path, gnupg_home: Option<&Path>, flags: &[&str]) -> Option<(i32, String)> {
    let python = which::which("python3").ok()?;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("verify.py");
    std::fs::write(&script, factum::export::bundle::VERIFY_PY).unwrap();
    let mut command = Command::new(python);
    command.arg(&script).arg(bundle).args(flags);
    if let Some(home) = gnupg_home {
        command.env("GNUPGHOME", home);
    }
    let output = command.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some((output.status.code().unwrap_or(-1), text))
}

#[test]
fn bundle_contents() {
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let files = read_zip(&bundle);
    for name in [
        "README.md",
        "verify.py",
        "case.json",
        "public-keys.asc",
        "report.html",
        "report.pdf",
        "report.md",
        "MANIFEST.sha256",
        "MANIFEST.sha256.asc",
    ] {
        assert!(files.contains_key(name), "{name}");
    }
    assert!(files.keys().any(|n| n.starts_with("signatures/entry-")));
    assert!(files.keys().any(|n| n.starts_with("signatures/seal-")));
    let manifest = String::from_utf8(files["MANIFEST.sha256"].clone()).unwrap();
    assert!(manifest.contains("  case.json\n") && !manifest.contains("MANIFEST"));
    let data = case_json(&bundle);
    assert_eq!(data["entries"].as_array().unwrap().len(), 4);
    assert_eq!(data["case"]["case_file"], "C-1");
    assert_eq!(files["verify.py"], factum::export::bundle::VERIFY_PY);
}

#[test]
fn verify_py_reports_a_tampered_payload_instead_of_crashing() {
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let mut data = case_json(&bundle);
    data["entries"][1]["payload"] = "not an object".into();
    rewrite_zip(&bundle, &[("case.json", serde_json::to_vec(&data).unwrap())]);
    let Some((code, output)) = run_verify(&bundle, None, &[]) else {
        return;
    };
    assert_eq!(code, 1);
    assert!(
        !output.contains("Traceback") && output.contains("Result: FAIL"),
        "{output}"
    );
}

#[test]
fn verify_py_reports_references_to_unknown_evidence() {
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let mut data = case_json(&bundle);
    let note = data["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["kind"] == "note")
        .unwrap();
    note["evidence_id"] = 999.into();
    rewrite_zip(&bundle, &[("case.json", serde_json::to_vec(&data).unwrap())]);
    let Some((_, output)) = run_verify(&bundle, None, &[]) else {
        return;
    };
    assert!(
        output.contains("refers to evidence #999, which was not created in this case"),
        "{output}"
    );
}

#[test]
fn bundle_carries_evidence_details_and_verify_py_checks_them() {
    let f = Fixture::new();
    let factum = Factum::with_seal_dir(&f.db, &f.signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-9", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "", "seized").unwrap();
    factum.update_evidence_details(evidence_id, "seized at desk 4").unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    let reports: Vec<(&str, Vec<u8>)> = REPORTS.iter().map(|(n, c)| (*n, c.to_vec())).collect();
    let bundle = factum
        .build_bundle(&model, &reports, &f.path().join("C-9.zip"))
        .unwrap();
    let mut data = case_json(&bundle);
    assert_eq!(data["evidence"][0]["details"], "seized at desk 4");
    let Some((_, output)) = run_verify(&bundle, None, &[]) else {
        return;
    };
    assert!(!output.contains("field 'details'"), "{output}");
    data["evidence"][0]["details"] = "forged".into();
    rewrite_zip(&bundle, &[("case.json", serde_json::to_vec(&data).unwrap())]);
    let (_, output) = run_verify(&bundle, None, &[]).unwrap();
    assert!(
        output.contains("Evidence #1 field 'details' differs from the log"),
        "{output}"
    );
}

fn gpg_signer(db: &factum::Db, home: &common::GpgHome) -> GnupgSigner {
    let signer = GnupgSigner::new(db, Some(home.path()));
    let key = signer.list_keys()[0].keyid.clone();
    assert!(signer.set_active_key(db, &key));
    signer
}

#[test]
fn verify_py_accepts_a_clean_bundle_and_detects_changes() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "C-1");
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("Result: OK"));

    // a modified file
    let mut data = case_json(&bundle);
    data["entries"][3]["text"] = "forged".into();
    let original = read_zip(&bundle);
    rewrite_zip(&bundle, &[("case.json", serde_json::to_vec(&data).unwrap())]);
    let (code, output) = run_verify(&bundle, Some(&home.path()), &[]).unwrap();
    assert_eq!(code, 1);
    assert!(
        output.contains("case.json was modified") && output.contains("content does not match"),
        "{output}"
    );

    // a recomputed manifest
    let mut files = original;
    files.insert("report.md".into(), b"# a nicer story".to_vec());
    let manifest: String = files
        .iter()
        .filter(|(name, _)| !name.starts_with("MANIFEST"))
        .map(|(name, content)| format!("{}  {name}\n", hex::encode(sha2::Sha256::digest(content))))
        .collect();
    let changes: Vec<(&str, Vec<u8>)> = files
        .iter()
        .map(|(n, c)| (n.as_str(), c.clone()))
        .chain([("MANIFEST.sha256", manifest.into_bytes())])
        .collect();
    rewrite_zip(&bundle, &changes);
    let (code, output) = run_verify(&bundle, Some(&home.path()), &[]).unwrap();
    assert!(code == 1 && output.contains("Manifest: signature invalid"), "{output}");
}

#[test]
fn verify_py_with_bundled_keys() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "C-1");
    let empty_home = tempfile::Builder::new().prefix("fe-").tempdir_in("/tmp").unwrap();
    let Some((code, output)) = run_verify(&bundle, Some(empty_home.path()), &[]) else {
        return;
    };
    assert!(code == 1 && output.contains("signing key not in keyring"), "{output}");
    let (code, output) = run_verify(&bundle, Some(empty_home.path()), &["--use-bundled-keys"]).unwrap();
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("Compare them with a trusted source"));
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(empty_home.path())
        .args(["--kill", "gpg-agent"])
        .output();
}

#[test]
fn non_ascii_case_file_seals_verify_outside_factum() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "2026/04 Müller Łódź 🦊");
    for item in std::fs::read_dir(&f.seal_dir).unwrap() {
        let path = item.unwrap().path();
        if path.extension().is_some_and(|e| e == "asc") {
            let output = Command::new("gpg")
                .args(["--batch", "--homedir"])
                .arg(home.path())
                .arg("--verify")
                .arg(&path)
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
}

#[test]
fn verify_py_accepts_seals_made_before_a_rename() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let factum = Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    factum.update_case(case_id, "C-renamed", "Case", "").unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, signer.active_key().as_deref());
    assert_eq!(model.report.overall(), Level::Ok, "{:?}", model.report.findings);
    let reports: Vec<(&str, Vec<u8>)> = REPORTS
        .iter()
        .map(|(name, content)| (*name, content.to_vec()))
        .collect();
    let bundle = factum.build_bundle(&model, &reports, &f.path().join("b.zip")).unwrap();
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
}

// --- evidence containers

/// A case with a closed container of two files; returns the case, the container's UUID and the files' SHA-256.
fn container_case(factum: &Factum, dir: &Path) -> (i64, String, Vec<(String, String)>) {
    use factum::container::volume::{AddOptions, AddProgress};
    let case_id = factum.create_case("C-7", "Containers", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "", "").unwrap();
    let source = dir.join("mnt");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("evil.exe"), b"MZ").unwrap();
    std::fs::write(source.join("notes.txt"), b"notes").unwrap();
    let id = factum
        .create_container(
            case_id,
            "FS01 preserved",
            Some(evidence_id),
            &dir.join("fs01.aff4l"),
            &source.display().to_string(),
        )
        .unwrap();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let options = AddOptions {
        base: source.clone(),
        keep_path: true,
        metadata_only: false,
        excerpt: None,
    };
    let staged = volume
        .stage_add(
            &[source.join("evil.exe"), source.join("notes.txt")],
            &options,
            &AddProgress::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let files = staged
        .records
        .iter()
        .map(|r| (r.path.clone(), r.sha256.clone()))
        .collect();
    factum.commit_container_add(id, &mut volume, staged).unwrap();
    drop(volume);
    factum.close_container(id).unwrap();
    (case_id, factum.container(id).unwrap().summary.uuid, files)
}

#[test]
fn reports_list_containers() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, uuid, files) = container_case(&factum, f.path());
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    assert_eq!(model.containers.len(), 1);
    assert_eq!(model.containers[0].state, "closed");
    assert_eq!(model.containers[0].evidence.as_deref(), Some("Evidence #1 disk"));
    assert!(
        model.containers[0].signatures.starts_with("GPG "),
        "{}",
        model.containers[0].signatures
    );
    let mut texts = vec![render_html(&model, false), render_markdown(&model)];
    if which::which("pdftotext").is_ok() {
        let pdf = f.path().join("report.pdf");
        std::fs::write(&pdf, factum::export::pdf::render_pdf(&model)).unwrap();
        let output = Command::new("pdftotext")
            .args(["-layout"])
            .arg(&pdf)
            .arg("-")
            .output()
            .unwrap();
        texts.push(String::from_utf8_lossy(&output.stdout).replace('\n', " "));
    }
    for text in texts {
        assert!(text.contains("Containers"), "{text}");
        for needle in ["FS01 preserved", "fs01.aff4l", uuid.as_str(), "closed"] {
            assert!(text.contains(needle), "{needle} in {text}");
        }
        for (path, sha256) in &files {
            assert!(text.contains(path.as_str()), "{path}");
            // the PDF may break a long hash across lines: its first half is enough there
            assert!(text.contains(&sha256[..32]), "{sha256}");
        }
    }
}

#[test]
fn reports_without_containers_have_no_section() {
    let f = Fixture::new();
    let model = model(&f);
    assert!(model.containers.is_empty());
    assert!(!render_html(&model, false).contains("<h2>Containers"));
    assert!(!render_markdown(&model).contains("## Containers"));
}

#[test]
fn bundle_with_container_events_verifies() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let factum = Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let (case_id, _, _) = container_case(&factum, f.path());
    let [bundle] = factum
        .export(case_id, &["bundle"], &f.path().join("out"))
        .unwrap()
        .try_into()
        .unwrap();
    let files = read_zip(&bundle);
    assert!(!files.keys().any(|name| name.ends_with(".aff4l")));
    let data = case_json(&bundle);
    let events: Vec<&str> = data["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["payload"]["event"].as_str())
        .filter(|e| e.starts_with("container_"))
        .collect();
    assert_eq!(
        events,
        vec!["container_created", "container_files_added", "container_closed"]
    );
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
}

#[test]
fn reports_mark_files_whose_content_is_not_stored() {
    use factum::container::volume::{AddOptions, AddProgress};
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-8", "Marks", "").unwrap();
    let source = f.path().join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("huge.img"), b"only hashed").unwrap();
    std::fs::write(source.join("part.bin"), b"0123456789").unwrap();
    let id = factum
        .create_container(
            case_id,
            "Marks",
            None,
            &f.path().join("m.aff4l"),
            &source.display().to_string(),
        )
        .unwrap();
    for (name, metadata_only, excerpt) in [("huge.img", true, None), ("part.bin", false, Some((2, 5)))] {
        let mut volume = factum.open_container_for_add(id).unwrap();
        let options = AddOptions {
            base: source.clone(),
            keep_path: true,
            metadata_only,
            excerpt,
        };
        let staged = volume
            .stage_add(
                &[source.join(name)],
                &options,
                &AddProgress::default(),
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap();
        factum.commit_container_add(id, &mut volume, staged).unwrap();
    }
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    for text in [render_html(&model, false), render_markdown(&model)] {
        assert!(text.contains("huge.img (metadata only, not stored)"), "{text}");
        assert!(text.contains("part.bin (excerpt, bytes 2–5)"), "{text}");
    }
}

/// The HTML report of a case with one note carrying `text` and the given images.
fn html_of_note(f: &Fixture, text: &str, images: &[NoteImage]) -> (String, i64) {
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let id = factum.create_note_with_images(text, images, None, case_id).unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    (render_html(&model, false), id)
}

fn red_pixel() -> NoteImage {
    NoteImage::from_rgba(1, 1, &[255, 0, 0, 255]).unwrap()
}

#[test]
fn html_report_renders_markdown_and_embeds_images() {
    let f = Fixture::new();
    let image = red_pixel();
    let text = format!("a **bold** <b>claim</b>\n\n{}", image.reference("login page"));
    let (html, _) = html_of_note(&f, &text, std::slice::from_ref(&image));
    assert!(html.contains("<strong>bold</strong>"), "{html}");
    assert!(html.contains("<img src='data:image/png;base64,"), "{html}");
    assert!(html.contains("alt='login page'"), "{html}");
    assert!(
        html.contains(&format!(
            "<details class='source'><summary>Source</summary><pre>{}</pre></details>",
            factum::pystr::html_escape(&text)
        )),
        "{html}"
    );
}

#[test]
fn html_report_print_variant_has_no_source_block() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note("a **bold** note", None, case_id).unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    assert!(!render_html(&model, true).contains("class='source'"));
    assert!(render_html(&model, true).contains("<strong>bold</strong>"));
}

#[test]
fn html_report_shows_link_addresses() {
    let f = Fixture::new();
    let (html, _) = html_of_note(&f, "see [here](https://x.test) and <https://y.test>", &[]);
    assert!(html.contains("here (https://x.test)"), "{html}");
    assert_eq!(
        html.matches("https://y.test").count(),
        2,
        "once in the text, once in the source: {html}"
    );
    assert!(!html.contains("<a "), "{html}");
}

#[test]
fn html_report_escapes_raw_html() {
    let f = Fixture::new();
    let (html, _) = html_of_note(
        &f,
        "<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\n`<script>`\n\n```\n<script>\n```",
        &[],
    );
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{html}");
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"), "{html}");
    assert!(!html.contains("<script"), "{html}");
    assert!(!html.contains("<img src=x"), "{html}");
}

#[test]
fn html_report_marks_missing_and_external_images() {
    let f = Fixture::new();
    let image = red_pixel();
    let text = format!("{} ![out](https://x.test/a.png)", image.reference("x"));
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let id = factum
        .create_note_with_images(&text, std::slice::from_ref(&image), None, case_id)
        .unwrap();
    f.db.conn
        .execute("UPDATE entries SET payload_json = NULL WHERE id = ?", [id])
        .unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let html = render_html(&build(&factum, case_id, seal_id, None), false);
    assert!(html.contains(&format!("[image {} missing]", image.id)), "{html}");
    assert!(
        html.contains("[external image https://x.test/a.png not loaded]"),
        "{html}"
    );
    assert!(!html.contains("<img"), "{html}");
}

#[test]
fn html_report_never_trusts_a_stored_mime() {
    let f = Fixture::new();
    let image = red_pixel();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let id = factum
        .create_note_with_images(
            &image.reference("x\" onerror=\"y"),
            std::slice::from_ref(&image),
            None,
            case_id,
        )
        .unwrap();
    let json: String =
        f.db.conn
            .query_row("SELECT payload_json FROM entries WHERE id = ?", [id], |r| r.get(0))
            .unwrap();
    let tampered = json.replace("image/png", "image/png\\\" onerror=\\\"x");
    assert_ne!(tampered, json);
    f.db.conn
        .execute(
            "UPDATE entries SET payload_json = ? WHERE id = ?",
            rusqlite::params![tampered, id],
        )
        .unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let html = render_html(&build(&factum, case_id, seal_id, None), false);
    assert!(html.contains(&format!("[image {} missing]", image.id)), "{html}");
    assert!(!html.contains("data:image"), "{html}");
    assert!(!html.contains("onerror=\""), "{html}");
}
