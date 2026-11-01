//! Ports of test_reports, test_exporter and test_bundle (the verify.py runs need python3, and gpg for signatures).

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::Fixture;
use factum::Factum;
use factum::export::html::render_html;
use factum::export::markdown::{image_files, inline, render_markdown};
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
    for text in [render_html(&model, false), render_markdown(&model, "images")] {
        assert!(text.contains("disk — seized at desk 4"), "{text}");
    }
}

#[test]
fn reports_name_the_seal_folder_checked() {
    let f = Fixture::new();
    let model = model(&f);
    let line = format!("Seal folder checked: {}", f.seal_dir.display());
    assert!(render_html(&model, false).contains(&format!("<p class='mono'>{line}</p>")));
    assert!(render_markdown(&model, "images").contains(&format!("\n{}\n", inline(&line))));
    let pdf = factum::export::pdf::render_pdf(&model);
    if let Some(extracted) = pdf_text(&f, &pdf) {
        assert!(extracted.contains("Seal folder checked:"), "{extracted}");
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
    for text in [render_html(&model, false), render_markdown(&model, "images")] {
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
    let markdown = render_markdown(&model(&f), "images");
    // through the tree: a line of raw HTML stays literal text, and a line start that could open a list is escaped
    assert!(
        markdown.contains(r"\<script\>alert(1)\</script\> \*\*bold\*\* \`\`\`fence\`\`\`"),
        "{markdown}"
    );
    assert!(markdown.contains("\n\\-----BEGIN PGP SIGNATURE-----\n"), "{markdown}");
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
    let markdown = render_markdown(&failing, "images");
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
fn a_failed_export_leaves_nothing_behind() {
    let f = Fixture::with_signer(FakeSigner::new(true));
    let factum = f.factum();
    let case_id = export_case(&factum);
    let image = small_image();
    factum
        .create_note_with_images(&image.reference("x"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let out = f.path().join("out");
    // the bundle is the last output, and its manifest cannot be signed
    f.signer.fail_detached_after.set(Some(0));
    let formats = ["html", "pdf", "md", "bundle"];
    assert!(factum.export(case_id, &formats, &out).is_err());
    let left: Vec<_> = std::fs::read_dir(&out).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
    // nothing stays behind after a good one either, and all outputs are there
    let paths = factum.export(case_id, &formats, &out).unwrap();
    assert!(paths.iter().all(|path| path.is_file()), "{paths:?}");
    let mut names: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 5, "{names:?}"); // four files and the image folder
    assert!(names.iter().all(|name| !name.starts_with('.')), "{names:?}");
}

#[test]
fn long_case_file_numbers_make_short_file_names() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case(&"案".repeat(80), "Case", "").unwrap();
    let image = small_image();
    factum
        .create_note_with_images(&image.reference("x"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let paths = factum
        .export(case_id, &["html", "pdf", "md", "bundle"], &f.path().join("out"))
        .unwrap();
    assert_eq!(paths.len(), 5);
    for path in paths {
        assert!(path.is_file(), "{path:?}");
        assert!(path.file_name().unwrap().len() <= 143, "{path:?}");
    }
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
    factum
        .build_bundle(&model, &reports, &[], &out_dir.join("C-1.zip"))
        .unwrap()
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
        .build_bundle(&model, &reports, &[], &f.path().join("C-9.zip"))
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
fn verify_py_accepts_a_key_expired_since_with_a_warning() {
    let home = common::GpgHome::at_time(
        Some("20200101T000000"),
        "Expired Key <expired@factum.invalid>",
        "sign",
        "2020-02-01",
    );
    let Some(home) = home else { return };
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "C-1");
    home.set_clock(None);
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
    assert!(
        output.contains("has expired since") && output.contains("Result: OK"),
        "{output}"
    );
}

fn expired_key_bundle(f: &Fixture) -> Option<(common::GpgHome, PathBuf)> {
    let home = common::GpgHome::at_time(
        Some("20200101T000000"),
        "Expired Key <expired@factum.invalid>",
        "sign",
        "2020-02-01",
    )?;
    let signer = gpg_signer(&f.db, &home);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "C-1");
    Some((home, bundle))
}

#[test]
fn verify_py_refuses_an_expired_key_gpg_cannot_say_is_trusted() {
    let f = Fixture::new();
    let Some((home, bundle)) = expired_key_bundle(&f) else {
        return;
    };
    let elsewhere = require_gpg!("Someone Else <else@factum.invalid>");
    let path = elsewhere.path().join("key.asc");
    std::fs::write(&path, home.gpg_ok(&["--armor", "--export"]).stdout).unwrap();
    elsewhere.gpg_ok(&["--batch", "--import", path.to_str().unwrap()]);
    let Some((code, output)) = run_verify(&bundle, Some(&elsewhere.path()), &[]) else {
        return;
    };
    assert_eq!(code, 1, "{output}");
    assert!(
        output.contains("has expired and is not trusted as far as gpg can tell"),
        "{output}"
    );
}

#[test]
fn verify_py_with_bundled_keys_accepts_an_expired_key_with_a_warning() {
    let f = Fixture::new();
    let Some((_home, bundle)) = expired_key_bundle(&f) else {
        return;
    };
    let empty_home = tempfile::Builder::new().prefix("fe-").tempdir_in("/tmp").unwrap();
    let Some((code, output)) = run_verify(&bundle, Some(empty_home.path()), &["--use-bundled-keys"]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("has expired since"), "{output}");
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(empty_home.path())
        .args(["--kill", "gpg-agent"])
        .output();
}

#[test]
fn verify_py_accepts_an_expired_subkey_on_a_certified_primary_key() {
    let user_id = "Colleague <c@factum.invalid>";
    let Some(owner) = common::GpgHome::at_time(Some("20200101T000000"), user_id, "cert", "never") else {
        return;
    };
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
    let signer = gpg_signer(&f.db, &owner);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "C-1");
    let home = require_gpg!("Examiner <examiner@factum.invalid>");
    let path = home.path().join("key.asc");
    std::fs::write(&path, owner.gpg_ok(&["--armor", "--export"]).stdout).unwrap();
    home.gpg_ok(&["--batch", "--import", path.to_str().unwrap()]);
    home.gpg_ok(&["--batch", "--yes", "--quick-lsign-key", &fingerprint]);
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("has expired since"), "{output}");
}

/// Adds a member with python's zipfile, which writes what the zip crate refuses (repeated names).
fn append_member(bundle: &Path, name: &str, content: &str) {
    let code = "import sys, warnings, zipfile\n\
                warnings.simplefilter('ignore')\n\
                zipfile.ZipFile(sys.argv[1], 'a').writestr(sys.argv[2], sys.argv[3])";
    let python = which::which("python3").unwrap();
    let output = Command::new(python)
        .arg("-c")
        .arg(code)
        .arg(bundle)
        .arg(name)
        .arg(content)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn verify_py_fails_on_names_tools_read_differently() {
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let Some((_, clean)) = run_verify(&bundle, None, &[]) else {
        return;
    };
    assert!(clean.contains("File names\nManifest\n"), "{clean}");
    for (name, expected) in [
        ("case.json", "'case.json' is in the bundle more than once"),
        ("Case.json", "'case.json' and 'Case.json' differ only in case"),
        ("/etc/passwd", "'/etc/passwd' is not a safe name"),
        ("C:/windows/x", "'C:/windows/x' is not a safe name"),
        ("images/../../x", "'images/../../x' is not a safe name"),
        ("..", "'..' is not a safe name"),
        (r"images\x", r"'images\\x' is not a safe name"),
    ] {
        let copy = f.path().join("copy.zip");
        std::fs::copy(&bundle, &copy).unwrap();
        append_member(&copy, name, "{}");
        let (code, output) = run_verify(&copy, None, &[]).unwrap();
        assert_eq!(code, 1, "{name}: {output}");
        assert!(output.contains(&format!("FAIL  {expected}")), "{name}: {output}");
    }
}

#[test]
fn verify_py_checks_the_names_in_an_extracted_folder() {
    // an extracted folder can hold case-only variants on a file system that tells them apart
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let folder = f.path().join("extracted");
    for (name, content) in read_zip(&bundle) {
        let path = folder.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let Some((_, clean)) = run_verify(&folder, None, &[]) else {
        return;
    };
    assert!(!clean.contains("differ only in case"), "{clean}");
    std::fs::write(folder.join("CASE.JSON"), "{}").unwrap();
    if std::fs::read_dir(&folder).unwrap().count() == read_zip(&bundle).len() {
        return; // a file system that folds case
    }
    let (_, output) = run_verify(&folder, None, &[]).unwrap();
    assert!(output.contains("differ only in case"), "{output}");
}

#[test]
fn version_shows_the_hashes_the_scripts_print() {
    let Ok(python) = which::which("python3") else {
        return;
    };
    let f = Fixture::new();
    let version = |flag: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_factum"))
            .arg(flag)
            .env("HOME", f.path())
            .env("XDG_CONFIG_HOME", f.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };
    let scripts = [
        ("verify.py", factum::export::bundle::VERIFY_PY),
        ("verify_container.py", factum::container::volume::VERIFY_CONTAINER_PY),
    ];
    let lines: Vec<String> = scripts
        .iter()
        .map(|(name, content)| format!("{name} SHA-256 {}", hex::encode(sha2::Sha256::digest(content))))
        .collect();
    let first = format!("factum {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(version("--version"), format!("{first}\n{}\n{}\n", lines[0], lines[1]));
    // one line, for what reads the version
    assert_eq!(version("-V"), format!("{first}\n"));
    for ((name, content), line) in scripts.iter().zip(&lines) {
        let script = f.path().join(name);
        std::fs::write(&script, content).unwrap();
        let output = Command::new(&python)
            .arg(&script)
            .arg(f.path().join("missing"))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(text.lines().next(), Some(line.as_str()), "{text}");
    }
}

/// A gpg that leaves `ran` behind if it is ever started.
#[cfg(unix)]
fn planted_gpg(folder: &Path, ran: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(folder).unwrap();
    let gpg = folder.join("gpg");
    std::fs::write(&gpg, format!("#!/bin/sh\ntouch '{}'\n", ran.display())).unwrap();
    std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn verify_py_refuses_a_gpg_beside_the_bundle_or_in_the_current_folder() {
    let Ok(python) = which::which("python3") else {
        return;
    };
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let scripts = tempfile::tempdir().unwrap();
    let script = scripts.path().join("verify.py");
    std::fs::write(&script, factum::export::bundle::VERIFY_PY).unwrap();
    let ran = f.path().join("gpg-ran");
    let folder = f.path().join("extracted");
    let current = f.path().join("current");
    planted_gpg(&folder.join("sub"), &ran);
    planted_gpg(&current, &ran);
    planted_gpg(f.path(), &ran);
    for (target, path, working_folder) in [
        // inside an extracted bundle
        (&folder, folder.join("sub"), f.path()),
        // beside the ZIP
        (&bundle, f.path().to_path_buf(), &current),
        // the current folder: what Windows looks in first, here through the PATH
        (&bundle, PathBuf::from("."), &current),
    ] {
        let output = Command::new(&python)
            .arg(&script)
            .arg(target)
            .env("PATH", path)
            .current_dir(working_folder)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(1), "{text}");
        assert!(
            text.contains("Refusing ") && text.contains("Nothing was checked."),
            "{text}"
        );
        assert!(!text.contains("Result:"), "{text}");
        assert!(!ran.exists(), "{text}");
    }
}

#[cfg(unix)]
#[test]
fn verify_py_says_when_gpg_is_too_old() {
    use std::os::unix::fs::PermissionsExt;
    let Ok(python) = which::which("python3") else {
        return;
    };
    let f = Fixture::new();
    let bundle = make_bundle(&f.db, &f.signer, &f.seal_dir, f.path(), "C-1");
    let dir = tempfile::tempdir().unwrap();
    let gpg = dir.path().join("gpg");
    std::fs::write(&gpg, "#!/bin/sh\necho 'gpg (GnuPG) 2.0.22'\necho 'libgcrypt 1.5.3'\n").unwrap();
    std::fs::set_permissions(&gpg, std::fs::Permissions::from_mode(0o755)).unwrap();
    let script = dir.path().join("verify.py");
    std::fs::write(&script, factum::export::bundle::VERIFY_PY).unwrap();
    let output = Command::new(python)
        .arg(&script)
        .arg(&bundle)
        .env("PATH", dir.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("needs gpg 2.1 or newer, this is gpg 2.0.22"), "{text}");
    assert!(!text.contains("Result:"), "{text}");
}

#[test]
fn verify_py_names_the_primary_key_of_a_subkey_signature() {
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
    let signer = gpg_signer(&f.db, &home);
    let bundle = make_bundle(&f.db, &signer, &f.seal_dir, f.path(), "C-1");
    let Some((code, output)) = run_verify(&bundle, Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
    assert!(output.contains(&primary) && !output.contains(&subkey), "{output}");
}

/// The answer of verify.py's signature_problem to gpg's status lines and exit code; None without python3.
fn signature_problem(status: &str, exit_code: i32) -> Option<String> {
    let python = which::which("python3").ok()?;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("verify.py"), factum::export::bundle::VERIFY_PY).unwrap();
    let code = "import sys, verify\n\
                lines = [line.split(' ') for line in sys.argv[1].split('|')]\n\
                print(verify.signature_problem([(p[0], p[1:]) for p in lines], int(sys.argv[2])))";
    let output = Command::new(python)
        .arg("-c")
        .arg(code)
        .arg(status)
        .arg(exit_code.to_string())
        .env("PYTHONPATH", dir.path())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[test]
fn verify_py_wants_exactly_one_good_signature() {
    let valid = "VALIDSIG AAAA 2020-01-15 1000 0 4 0 22 10 01 AAAA";
    let cases = [
        (format!("GOODSIG 1 A|{valid}"), 0, "None"),
        (format!("GOODSIG 1 A|{valid}"), 2, "bad signature"),
        (format!("GOODSIG 1 A|{valid}|FAILURE gpg-exit 1"), 0, "bad signature"),
        (
            format!("GOODSIG 1 A|{valid}|GOODSIG 2 B|{valid}"),
            0,
            "more than one signature",
        ),
        (format!("GOODSIG 1 A|{valid}|BADSIG 2 B"), 1, "bad signature"),
        (
            format!("GOODSIG 1 A|{valid}|ERRSIG 2 22 10 01 1000 9"),
            0,
            "bad signature",
        ),
        ("GOODSIG 1 A".to_string(), 0, "bad signature"),
        (format!("REVKEYSIG 1 A|{valid}"), 0, "signing key was revoked"),
        (format!("EXPSIG 1 A|{valid}"), 1, "signature expired"),
        (format!("KEYEXPIRED 2000|EXPKEYSIG 1 A|{valid}"), 0, "None"),
        (format!("EXPKEYSIG 1 A|{valid}"), 0, "None"),
        (
            format!("KEYEXPIRED 500|EXPKEYSIG 1 A|{valid}"),
            0,
            "signature made after the signing key expired",
        ),
        // of the other subkeys, only the last one before EXPKEYSIG is the signing key's
        (
            format!("KEYEXPIRED 500|KEYEXPIRED 2000|EXPKEYSIG 1 A|{valid}|KEYEXPIRED 500"),
            0,
            "None",
        ),
        (format!("KEYEXPIRED 500|GOODSIG 1 A|{valid}"), 0, "None"),
    ];
    for (status, exit_code, expected) in cases {
        let Some(answer) = signature_problem(&status, exit_code) else {
            return;
        };
        assert_eq!(answer, expected, "{status}");
    }
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
    let bundle = factum
        .build_bundle(&model, &reports, &[], &f.path().join("b.zip"))
        .unwrap();
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
            evidence_id,
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
        replaces: Vec::new(),
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
    let mut texts = vec![render_html(&model, false), render_markdown(&model, "images")];
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
fn report_lists_container_sources_and_damaged_state() {
    use factum::container::volume::{AddOptions, AddProgress};
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-9", "Damaged", "").unwrap();
    let source = f.path().join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("a.txt"), b"a").unwrap();
    let (_, id) = factum
        .create_evidence_with_container(case_id, "disk", "", "", &f.path().join("d.aff4l"), "")
        .unwrap();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let options = AddOptions {
        keep_path: true,
        ..Default::default()
    };
    let staged = volume
        .stage_add(
            &[source.join("a.txt")],
            &options,
            &AddProgress::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
    let record = staged.records[0].clone();
    factum.commit_container_add(id, &mut volume, staged).unwrap();
    drop(volume);
    let recheck = factum::container::volume::Recheck {
        mismatches: vec![record],
        ..Default::default()
    };
    factum.close_container_damaged(id, &recheck).unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let model = build(&factum, case_id, seal_id, None);
    let row = &model.containers[0];
    assert_eq!(row.state, "closed as damaged");
    let mount = factum::container::mounts::mount_line(&factum.container(id).unwrap().adds[0].mounts[0]);
    let rows = row.rows();
    assert!(
        rows.iter().any(|(k, v)| *k == "Base path" && v == "full paths"),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|(k, v)| *k == "Source" && v.contains(&mount)),
        "{rows:?}"
    );
    let html = render_html(&model, false);
    assert!(html.contains("closed as damaged"), "{html}");
    assert!(
        html.contains(&mount) || html.contains(&mount.replace('·', "&middot;")),
        "{html}"
    );
    // Markdown escapes what it would otherwise read as markup (a Windows "C:\", an "_" in mount options)
    let markdown = render_markdown(&model, "images");
    assert!(markdown.contains("closed as damaged"), "{markdown}");
    assert!(
        markdown.contains(&factum::export::markdown::inline(&mount)),
        "{markdown}"
    );
}

#[test]
fn reports_without_containers_have_no_section() {
    let f = Fixture::new();
    let model = model(&f);
    assert!(model.containers.is_empty());
    assert!(!render_html(&model, false).contains("<h2>Containers"));
    assert!(!render_markdown(&model, "images").contains("## Containers"));
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
            factum.create_evidence(case_id, "disk", "", "").unwrap(),
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
            replaces: Vec::new(),
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
    for text in [render_html(&model, false), render_markdown(&model, "images")] {
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

/// The Markdown report of a case with one note carrying `text` and the given images.
fn markdown_of_note(f: &Fixture, text: &str, images: &[NoteImage]) -> String {
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note_with_images(text, images, None, case_id).unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    render_markdown(&build(&factum, case_id, seal_id, None), "images")
}

#[test]
fn markdown_report_renders_through_the_tree() {
    let f = Fixture::new();
    let markdown = markdown_of_note(&f, "**b** <b>x</b> [l](https://x.test)", &[]);
    assert!(markdown.contains("**b**"), "{markdown}");
    assert!(markdown.contains(r"\<b\>x\</b\>"), "{markdown}");
    assert!(markdown.contains("l (`https://x.test`)"), "{markdown}");
    assert!(!markdown.contains("](https://x.test)"), "{markdown}");
}

#[test]
fn markdown_report_renders_blocks_literally() {
    let f = Fixture::new();
    let text = "# Title\n\n- one\n  - two\n- `a` *e*\n\n3. x\n4. y\n\n> quoted\n> more\n\n````\nlet a = \"```\";\n````\n\n\\- not a list\n\n<https://y.test> and [https://z.test](https://z.test)";
    let markdown = markdown_of_note(&f, text, &[]);
    for expected in [
        "\n#### Title\n",
        "\n- one\n  - two\n- `a` *e*\n",
        "\n3. x\n4. y\n",
        "\n> quoted\\\n> more\n",
        "\n````\nlet a = \"```\";\n````\n",
        // the escape stays as typed: the report shows "\- not a list", never a list
        "\n\\\\- not a list\n",
        "https://y.test",
    ] {
        assert!(markdown.contains(expected), "{expected:?} in {markdown}");
    }
    assert!(!markdown.contains("(`https://z.test`)"), "{markdown}");
}

#[test]
fn markdown_report_marks_missing_and_external_images() {
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
    let markdown = render_markdown(&build(&factum, case_id, seal_id, None), "images");
    assert!(
        markdown.contains(&format!("[image {} missing]", image.id)),
        "{markdown}"
    );
    assert!(
        markdown.contains("[external image `https://x.test/a.png` not loaded]"),
        "{markdown}"
    );
    assert!(!markdown.contains("!["), "{markdown}");
}

/// A case with two notes that both show `image`; returns the written paths of the export in `out`.
fn export_two_notes_with(f: &Fixture, image: &NoteImage, formats: &[&str], out: &Path) -> Vec<PathBuf> {
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    for alt in ["first", "second"] {
        factum
            .create_note_with_images(&image.reference(alt), std::slice::from_ref(image), None, case_id)
            .unwrap();
    }
    factum.export(case_id, formats, out).unwrap()
}

#[test]
fn markdown_export_writes_image_files() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = red_pixel();
    factum
        .create_note_with_images(&image.reference("login"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let out = f.path().join("out");
    let paths = factum.export(case_id, &["md"], &out).unwrap();
    let report = &paths[0];
    let stem = report.file_stem().unwrap().to_string_lossy().into_owned();
    let relative = format!("{stem}_images/{}.png", image.sha256);
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[1], out.join(&relative));
    assert_eq!(std::fs::read(&paths[1]).unwrap(), image.bytes);
    let markdown = std::fs::read_to_string(report).unwrap();
    assert!(markdown.contains(&format!("![login]({relative})")), "{markdown}");
}

#[test]
fn export_without_images_writes_no_image_folder() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = export_case(&factum);
    let out = f.path().join("out");
    let paths = factum.export(case_id, &["md"], &out).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
}

#[test]
fn same_image_twice_is_written_once() {
    let f = Fixture::new();
    let image = red_pixel();
    let out = f.path().join("out");
    let paths = export_two_notes_with(&f, &image, &["md"], &out);
    assert_eq!(paths.len(), 2, "{paths:?}");
    let stem = paths[0].file_stem().unwrap().to_string_lossy().into_owned();
    let markdown = std::fs::read_to_string(&paths[0]).unwrap();
    let relative = format!("{stem}_images/{}.png", image.sha256);
    assert_eq!(markdown.matches(&relative).count(), 2, "{markdown}");
    assert_eq!(
        std::fs::read_dir(out.join(format!("{stem}_images"))).unwrap().count(),
        1
    );
}

#[test]
fn image_file_names_come_from_the_bytes_not_the_stored_hash() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = red_pixel();
    let id = factum
        .create_note_with_images(&image.reference("x"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let json: String =
        f.db.conn
            .query_row("SELECT payload_json FROM entries WHERE id = ?", [id], |r| r.get(0))
            .unwrap();
    let tampered = json.replace(&image.sha256, "../../x");
    assert_ne!(tampered, json);
    f.db.conn
        .execute(
            "UPDATE entries SET payload_json = ? WHERE id = ?",
            rusqlite::params![tampered, id],
        )
        .unwrap();
    let out = f.path().join("a").join("b").join("out");
    let paths = factum.export(case_id, &["md", "bundle"], &out).unwrap();
    let stem = paths[0].file_stem().unwrap().to_string_lossy().into_owned();
    let name = format!("{}.png", image.sha256);
    assert_eq!(paths[1], out.join(format!("{stem}_images")).join(&name));
    assert_eq!(std::fs::read(&paths[1]).unwrap(), image.bytes);
    assert!(!f.path().join("a").join("x").exists() && !f.path().join("x").exists());
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 3); // .md, _images, .zip
    let markdown = std::fs::read_to_string(&paths[0]).unwrap();
    assert!(!markdown.contains("../../x"), "{markdown}");
    let files = read_zip(paths.last().unwrap());
    assert!(files.contains_key(&format!("images/{name}")));
    assert!(files.keys().all(|n| !n.contains("..")), "{:?}", files.keys());
}

#[test]
fn images_with_a_foreign_stored_type_are_not_written() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = red_pixel();
    let id = factum
        .create_note_with_images(&image.reference("x"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    f.db.conn
        .execute(
            "UPDATE entries SET payload_json = replace(payload_json, 'image/png', 'image/svg+xml') WHERE id = ?",
            [id],
        )
        .unwrap();
    let out = f.path().join("out");
    let paths = factum.export(case_id, &["md"], &out).unwrap();
    assert_eq!(paths.len(), 1, "{paths:?}");
    let markdown = std::fs::read_to_string(&paths[0]).unwrap();
    assert!(
        markdown.contains(&format!("[image {} missing]", image.id)),
        "{markdown}"
    );
    let seal_id = factum.seal(case_id, "export").unwrap();
    assert!(image_files(&build(&factum, case_id, seal_id, None)).is_empty());
}

#[test]
fn bundle_carries_images_in_the_manifest() {
    let f = Fixture::new();
    let image = red_pixel();
    let out = f.path().join("out");
    let paths = export_two_notes_with(&f, &image, &["bundle"], &out);
    assert_eq!(paths.len(), 1);
    let files = read_zip(&paths[0]);
    let name = format!("images/{}.png", image.sha256);
    assert_eq!(files[&name], image.bytes);
    assert_eq!(files.keys().filter(|n| n.starts_with("images/")).count(), 1);
    let manifest = String::from_utf8(files["MANIFEST.sha256"].clone()).unwrap();
    assert!(
        manifest.contains(&format!(
            "{}  {name}\n",
            hex::encode(sha2::Sha256::digest(&image.bytes))
        )),
        "{manifest}"
    );
    let report = String::from_utf8(files["report.md"].clone()).unwrap();
    assert!(report.contains(&format!("]({name})")), "{report}");
    assert!(
        String::from_utf8(files["README.md"].clone())
            .unwrap()
            .contains("`images/`")
    );
    if let Some((_, output)) = run_verify(&paths[0], None, &[]) {
        assert!(!output.contains("images/"), "{output}");
    }
}

#[test]
fn verify_py_accepts_a_bundle_with_images_and_detects_a_swapped_one() {
    let home = require_gpg!("Factum Test <test@factum.invalid>");
    let f = Fixture::new();
    let signer = gpg_signer(&f.db, &home);
    let factum = Factum::with_seal_dir(&f.db, &signer, Some(f.seal_dir.clone()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = red_pixel();
    factum
        .create_note_with_images(&image.reference("x"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let paths = factum.export(case_id, &["bundle"], &f.path().join("out")).unwrap();
    let Some((code, output)) = run_verify(&paths[0], Some(&home.path()), &[]) else {
        return;
    };
    assert_eq!(code, 0, "{output}");
    rewrite_zip(
        &paths[0],
        &[(&format!("images/{}.png", image.sha256), b"not the image".to_vec())],
    );
    let (code, output) = run_verify(&paths[0], Some(&home.path()), &[]).unwrap();
    assert_eq!(code, 1, "{output}");
    assert!(
        output.contains(&format!("images/{}.png was modified after export", image.sha256)),
        "{output}"
    );
}

#[test]
fn markdown_report_keeps_indented_literal_lines_literal() {
    let f = Fixture::new();
    let markdown = markdown_of_note(&f, "<div>\n  - a\n  ===\n  1. x\n  ~~~\n    deep\n</div>", &[]);
    for line in [
        r"&nbsp;&nbsp;- a",
        r"&nbsp;&nbsp;===",
        r"&nbsp;&nbsp;1. x",
        r"&nbsp;&nbsp;~~~",
        r"&nbsp;&nbsp;&nbsp;&nbsp;deep",
    ] {
        assert!(markdown.contains(line), "{line:?} in {markdown}");
    }
    for structural in ["\n  - a", "\n  ===", "\n  1. x", "\n  ~~~", "\n    deep"] {
        assert!(!markdown.contains(structural), "{structural:?} in {markdown}");
    }
}

/// A 3×2 image with all pixels opaque
fn small_image() -> NoteImage {
    let pixels: Vec<u8> = (0..6).flat_map(|n| [n * 40, 90, 200, 255]).collect();
    NoteImage::from_rgba(3, 2, &pixels).unwrap()
}

/// The bytes of the PDF report of a case with one note carrying `text` and the given images.
fn pdf_of_note(f: &Fixture, text: &str, images: &[NoteImage]) -> Vec<u8> {
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note_with_images(text, images, None, case_id).unwrap();
    let [path] = factum
        .export(case_id, &["pdf"], &f.path().join("out"))
        .unwrap()
        .try_into()
        .unwrap();
    std::fs::read(path).unwrap()
}

fn pdf_text(f: &Fixture, pdf: &[u8]) -> Option<String> {
    which::which("pdftotext").ok()?;
    let path = f.path().join("check.pdf");
    std::fs::write(&path, pdf).unwrap();
    // UTF-8 explicitly: on Windows pdftotext writes the system code page by default, which has no "•"
    let output = Command::new("pdftotext")
        .args(["-layout", "-enc", "UTF-8"])
        .arg(&path)
        .arg("-")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn pdf_embeds_note_images() {
    let f = Fixture::new();
    let image = small_image();
    let pdf = pdf_of_note(&f, &image.reference("login"), std::slice::from_ref(&image));
    let text = String::from_utf8_lossy(&pdf);
    assert!(text.contains("/Subtype /Image"), "no image object");
    assert!(text.contains("/Width 3") && text.contains("/Height 2"));
    assert!(text.contains("/Im0 "));
}

#[test]
fn pdf_writes_a_shared_image_once() {
    let f = Fixture::new();
    let image = small_image();
    let out = f.path().join("out");
    let paths = export_two_notes_with(&f, &image, &["pdf"], &out);
    let pdf = std::fs::read(&paths[0]).unwrap();
    assert_eq!(String::from_utf8_lossy(&pdf).matches("/Subtype /Image").count(), 1);
}

#[test]
fn pdf_marks_missing_external_and_undecodable_images() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let good = small_image();
    let text = format!("{} ![out](https://x.test/a.png)", good.reference("x"));
    let truncated = f.db.conn.execute(
        "UPDATE entries SET payload_json = ? WHERE id = ?",
        (
            // the stored image keeps its id but loses the end of its data
            factum::images::to_payload(&[NoteImage {
                bytes: good.bytes[..good.bytes.len() / 2].to_vec(),
                ..good.clone()
            }])
            .unwrap()
            .to_string(),
            factum
                .create_note_with_images(&text, std::slice::from_ref(&good), None, case_id)
                .unwrap(),
        ),
    );
    assert_eq!(truncated.unwrap(), 1);
    let gone = factum
        .create_note_with_images(&good.reference("gone"), std::slice::from_ref(&good), None, case_id)
        .unwrap();
    f.db.conn
        .execute("UPDATE entries SET payload_json = NULL WHERE id = ?", [gone])
        .unwrap();
    let [path] = factum
        .export(case_id, &["pdf"], &f.path().join("out"))
        .unwrap()
        .try_into()
        .unwrap();
    let pdf = std::fs::read(path).unwrap();
    assert!(!String::from_utf8_lossy(&pdf).contains("/Subtype /Image"));
    if let Some(extracted) = pdf_text(&f, &pdf) {
        let flat = extracted.split_whitespace().collect::<Vec<_>>().join(" ");
        for expected in [
            format!("[image {} could not be shown]", good.id),
            "[external image https://x.test/a.png not loaded]".to_string(),
            format!("[image {} missing]", good.id),
        ] {
            assert!(flat.contains(&expected), "{expected:?} in {flat}");
        }
    }
}

#[test]
fn pdf_keeps_a_table_row_taller_than_a_page() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let words: Vec<String> = (0..4000).map(|n| format!("w{n}.")).collect();
    factum.create_evidence(case_id, "disk", "", &words.join(" ")).unwrap();
    let [path] = factum
        .export(case_id, &["pdf"], &f.path().join("out"))
        .unwrap()
        .try_into()
        .unwrap();
    let pdf = std::fs::read(path).unwrap();
    assert!(String::from_utf8_lossy(&pdf).contains("/CIDToGIDMap /Identity"));
    if let Some(extracted) = pdf_text(&f, &pdf) {
        for word in words {
            assert!(extracted.contains(&word), "{word} is lost");
        }
    }
}

#[test]
fn pdf_gives_the_text_of_characters_it_cannot_show_and_warns() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note("Fall 案件 مرحبا 🦊 Ende ✓", None, case_id).unwrap();
    let out = f.path().join("out");
    for formats in [&["pdf"][..], &["bundle"]] {
        let exported = factum.export_checked(case_id, formats, &out).unwrap();
        assert_eq!(exported.warnings.len(), 1, "{formats:?}");
        assert!(exported.warnings[0].contains("件, 案"), "{:?}", exported.warnings);
        assert!(exported.warnings[0].contains("HTML report"), "{:?}", exported.warnings);
        assert!(exported.warnings[0].contains("U+1F98A"), "{:?}", exported.warnings);
    }
    assert!(
        factum
            .export_checked(case_id, &["md"], &out)
            .unwrap()
            .warnings
            .is_empty()
    );
    let pdf = std::fs::read(factum.export(case_id, &["pdf"], &out).unwrap().remove(0)).unwrap();
    if let Some(extracted) = pdf_text(&f, &pdf) {
        // the right-to-left word changes the order pdftotext gives
        for expected in ["Fall 案件", "🦊", "ابحرم", "Ende ✓"] {
            assert!(extracted.contains(expected), "{expected} in {extracted}");
        }
    }
}

#[test]
fn pdf_has_no_warning_for_characters_its_fonts_have() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.create_note("Müller ✓ Привет", None, case_id).unwrap();
    let out = f.path().join("out");
    assert!(
        factum
            .export_checked(case_id, &["pdf"], &out)
            .unwrap()
            .warnings
            .is_empty()
    );
}

#[test]
fn reports_show_superseded_versions_with_time_and_signature() {
    let f = Fixture::new();
    let model = model(&f);
    let old = model.appendix.iter().find(|item| item.superseded).unwrap();
    assert_eq!(model.appendix.iter().filter(|item| item.superseded).count(), 1);
    let time = old.created_utc.clone();
    let written = format!("Superseded: version 1, written {time}");
    let html = render_html(&model, false);
    let markdown = render_markdown(&model, "images");
    for text in [&html, &markdown, &render_html(&model, true)] {
        let appendix = &text[text.find("Integrity appendix").unwrap()..];
        for expected in [&written, "Signature:  signed", "| first"] {
            assert!(appendix.contains(expected), "{expected} in {appendix}");
        }
        // the timeline keeps the newest text only
        assert!(!text[..text.find("Integrity appendix").unwrap()].contains("| first"));
    }
    // the plain variant does not hide the text in a closed section
    let before = &html[..html.find(&written).unwrap()];
    assert!(before.rfind("<details").unwrap() == before.rfind("<details open>").unwrap());
    assert_eq!(html.matches("<details open>").count(), 1);
    let pdf = factum::export::pdf::render_pdf(&model);
    if let Some(extracted) = pdf_text(&f, &pdf) {
        assert!(
            extracted.contains(&written) && extracted.contains("| first"),
            "{extracted}"
        );
    }
}

/// Every line of superseded text starts with its mark. Where a long line wraps, the PDF repeats the mark and the HTML
/// keeps the line in a barred block. Markdown has only the source line: a viewer that wraps code breaks it unmarked.
#[test]
fn every_line_of_superseded_text_carries_its_mark() {
    const FORGED: &str = "Signature:  signed by NOBODY";
    for separator in ["\n", "\r", "\r\n", "\u{2028}", "\u{85}", "\u{c}"] {
        let f = Fixture::new();
        let factum = f.factum();
        let case_id = factum.create_case("C-1", "Case", "").unwrap();
        let first = factum
            .create_note(&format!("x{separator}{FORGED}"), None, case_id)
            .unwrap();
        factum.correct_note(first, "y").unwrap();
        let seal_id = factum.seal(case_id, "export").unwrap();
        let model = build(&factum, case_id, seal_id, None);
        let markdown = render_markdown(&model, "images");
        assert!(
            markdown.contains(&format!("\n| x\n| {FORGED}\n")),
            "{separator:?}: {markdown}"
        );
        let html = render_html(&model, true);
        let span = format!("<span class='quoted'>| {FORGED}</span>");
        assert!(html.contains(&span), "{separator:?}: {html}");
        for text in [&markdown, &html] {
            assert!(!text.contains(separator) || separator == "\n", "{separator:?}: {text}");
        }
        let pdf = factum::export::pdf::render_pdf(&model);
        if let Some(extracted) = pdf_text(&f, &pdf) {
            // pdftotext closes up the two spaces
            assert!(extracted.contains("signed by NOBODY"), "{separator:?}: {extracted}");
            let mut forged = extracted.lines().filter(|line| line.contains("signed by NOBODY"));
            assert!(
                forged.all(|line| line.trim_start().starts_with("| ")),
                "{separator:?}: {extracted}"
            );
        }
    }
}

#[test]
fn a_long_superseded_line_keeps_its_mark_where_the_pdf_wraps_it() {
    const FORGED: &str = "Signature: signed by NOBODY";
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    // whatever the room on a line, one of these lengths puts the forged words at the start of a wrapped one
    let text: String = (100..130).map(|n| format!("{} {FORGED} ", "a".repeat(n))).collect();
    let first = factum.create_note(&text, None, case_id).unwrap();
    factum.correct_note(first, "y").unwrap();
    let seal_id = factum.seal(case_id, "export").unwrap();
    let pdf = factum::export::pdf::render_pdf(&build(&factum, case_id, seal_id, None));
    if let Some(extracted) = pdf_text(&f, &pdf) {
        assert!(extracted.contains(FORGED), "{extracted}");
        assert!(
            !extracted.lines().any(|line| line.trim_start().starts_with(FORGED)),
            "{extracted}"
        );
    }
}

#[test]
fn the_timeline_flags_a_note_when_an_earlier_version_failed() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = model_case(&factum);
    let seal_id = factum.seal(case_id, "export").unwrap();
    let clean = build(&factum, case_id, seal_id, None);
    let old = clean.appendix.iter().find(|item| item.superseded).unwrap().entry_id;
    assert!(!render_html(&clean, false).contains("This note failed the integrity check"));
    // a text change would fail the entries after it too; a signature fails on its own
    f.exec(&format!("UPDATE entries SET signature = 'forged' WHERE id = {old}"));
    let failing = build(&factum, case_id, seal_id, None);
    let line = failing.timeline.iter().find(|item| item.origin_id == old).unwrap();
    assert_eq!(line.status, Level::Fail);
    assert_eq!(line.text, "first, corrected");
    // the appendix keeps each version's own status
    let newest = failing
        .appendix
        .iter()
        .find(|item| item.entry_id == line.entry_id)
        .unwrap();
    assert_ne!(newest.status, Level::Fail);
    let html = render_html(&failing, false);
    assert!(html[..html.find("<h2>Evidence").unwrap()].contains("This note failed the integrity check"));
    let markdown = render_markdown(&failing, "images");
    assert!(markdown[..markdown.find("## Evidence").unwrap()].contains("This note failed the integrity check"));
    let pdf = factum::export::pdf::render_pdf(&failing);
    if let Some(extracted) = pdf_text(&f, &pdf) {
        assert!(
            extracted.contains("This note failed the integrity check"),
            "{extracted}"
        );
    }
}

#[test]
fn markdown_report_defangs_addresses() {
    let f = Fixture::new();
    let text = "See https://evil.test/a_b, www.evil.test, me@evil.test, <https://auto.test> and [https://same.test](https://same.test).";
    let markdown = markdown_of_note(&f, text, &[]);
    assert!(
        markdown.contains(
            "See `https://evil.test/a_b`, `www.evil.test`, `me@evil.test`, `https://auto.test` and `https://same.test`."
        ),
        "{markdown}"
    );
}

#[test]
fn pdf_renders_note_markdown() {
    let f = Fixture::new();
    let text = "# Heading\n\nSome **bold** and *italic* with `code` and <b>raw</b>, see [the site](https://x.test).\n\n- one\n  - nested\n- two\n\n3. three\n4. four\n\n> quoted\n\n```\nlet a = 1;\n```";
    let pdf = pdf_of_note(&f, text, &[]);
    assert!(String::from_utf8_lossy(&pdf).contains("/BaseFont /AtkinsonHyperlegibleNext-Italic"));
    if let Some(extracted) = pdf_text(&f, &pdf) {
        for expected in [
            "Heading",
            "Some bold and italic with code and <b>raw</b>, see the site (https://x.test).",
            "• one",
            "• nested",
            "3. three",
            "4. four",
            "quoted",
            "let a = 1;",
        ] {
            assert!(extracted.contains(expected), "{expected:?} in {extracted}");
        }
        assert!(!extracted.contains("**") && !extracted.contains("```"), "{extracted}");
    }
}
