//! Ports of test_seal_service, test_verifier and test_late_signing.

mod common;

use std::collections::HashSet;
use std::path::PathBuf;

use common::{Fixture, add_case_row};
use factum::canonical::utc_now;
use factum::error::ErrorKind;
use factum::images::NoteImage;
use factum::log_service::{Append, entry_signed_payload, leaf_data};
use factum::notes::parse_payload;
use factum::seals::{SEAL_DIR_SETTING, seal_payload};
use factum::signer::FakeSigner;
use factum::verifier::{CaseReport, Level, SealSource};
use factum::{Factum, merkle};

fn make_case(factum: &Factum, entries: usize, case_file: &str) -> i64 {
    let case_id = add_case_row(factum.db, case_file, false);
    for number in 0..entries {
        factum
            .append(case_id, "note", &format!("note {number}"), Append::default())
            .unwrap();
    }
    case_id
}

fn codes(report: &CaseReport, level: Option<Level>) -> HashSet<&'static str> {
    report
        .findings
        .iter()
        .filter(|f| level.is_none_or(|l| f.level == l))
        .map(|f| f.code)
        .collect()
}

// --- seals

#[test]
fn seal_records_current_head_and_writes_signed_file() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = make_case(&factum, 2, "C-1");
    let head = factum
        .get_tree_head(factum.seal(case_id, "checkpoint").unwrap())
        .unwrap()
        .unwrap();
    let hashes: Vec<merkle::Hash> = factum
        .leaf_hashes(case_id)
        .unwrap()
        .iter()
        .map(|h| merkle::from_hex(h))
        .collect();
    assert_eq!(
        (head.tree_size, head.root_hash.clone()),
        (2, hex::encode(merkle::root(&hashes)))
    );
    let expected = seal_payload(case_id, "C-1", 2, &head.root_hash, &head.created_utc, "checkpoint");
    assert_eq!(
        head.signature.as_deref(),
        Some(FakeSigner::fake_signature(&expected).as_str())
    );
    let path = PathBuf::from(head.file_path.unwrap());
    assert_eq!(path.parent().unwrap(), f.seal_dir);
    assert_eq!(path.extension().unwrap(), "asc");
    assert!(
        path.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(&format!("C-1_{case_id}_size2_"))
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), head.signature.unwrap());
}

#[test]
fn unsigned_seal_is_written_as_json() {
    let f = Fixture::with_signer(FakeSigner::new(false));
    let factum = f.factum();
    let case_id = make_case(&factum, 2, "C-1");
    let head = factum
        .get_tree_head(factum.seal(case_id, "archive").unwrap())
        .unwrap()
        .unwrap();
    assert!(head.signature.is_none());
    let payload: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(head.file_path.unwrap()).unwrap()).unwrap();
    assert_eq!(payload["reason"], "archive");
}

#[test]
fn signing_failure_creates_no_seal() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = make_case(&factum, 2, "C-1");
    f.signer.fail_next.set(true);
    assert!(factum.seal(case_id, "checkpoint").unwrap_err().is(ErrorKind::Signing));
    assert!(factum.list_tree_heads(case_id).unwrap().is_empty());
}

#[test]
fn seal_fails_cleanly_when_folder_unwritable() {
    let f = Fixture::new();
    let blocker = f.path().join("not-a-folder");
    std::fs::write(&blocker, "x").unwrap();
    let factum = Factum::with_seal_dir(&f.db, &f.signer, Some(blocker.join("seals")));
    let case_id = make_case(&factum, 2, "C-1");
    let error = factum.seal(case_id, "checkpoint").unwrap_err();
    assert!(error.message.contains("could not be written"), "{error}");
    assert!(factum.list_tree_heads(case_id).unwrap().is_empty());
}

#[test]
fn default_seal_dir_is_next_to_the_database() {
    let f = Fixture::new();
    let factum = f.factum_default_seals();
    assert_eq!(factum.seal_dir(), f.db.path.parent().unwrap().join("seals"));
    assert!(factum.seal_dir_is_default());
}

#[test]
fn seal_dir_from_settings_and_environment() {
    let f = Fixture::new();
    f.db.set_setting(SEAL_DIR_SETTING, f.path().join("usb").to_str().unwrap())
        .unwrap();
    let mut factum = f.factum_default_seals();
    assert_eq!(factum.seal_dir(), f.path().join("usb"));
    assert!(!factum.seal_dir_is_default());
    factum.env_seal_dir = Some(f.path().join("env"));
    assert_eq!(factum.seal_dir(), f.path().join("env"));
}

#[test]
fn read_seal_files_ignores_other_cases() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = make_case(&factum, 2, "C-1");
    factum.seal(case_id, "checkpoint").unwrap();
    // same case id, different case file: a seal of another database sharing this folder
    let other = seal_payload(case_id, "OTHER", 99, "00", "2026-01-01T00:00:00.000Z", "checkpoint");
    std::fs::write(f.seal_dir.join("OTHER_1_size99_x.json"), other).unwrap();
    std::fs::write(f.seal_dir.join("garbage.asc"), "not a seal").unwrap();
    let found = factum.read_seal_files(case_id).unwrap();
    assert_eq!(
        found
            .iter()
            .map(|s| s.text_field("case_file").unwrap())
            .collect::<Vec<_>>(),
        vec!["C-1"]
    );
    assert_eq!(
        found[0].payload_text,
        factum::canonical::canonical_json(&serde_json::Value::Object(found[0].payload.clone()))
    );
}

#[test]
fn external_seal_folder_must_already_exist() {
    // an unmounted stick: factum must not silently create the folder on the local disk
    let f = Fixture::new();
    let missing = f.path().join("usb").join("seals");
    let factum = Factum::with_seal_dir(&f.db, &f.signer, Some(missing.clone()));
    let case_id = make_case(&factum, 2, "C-1");
    assert!(
        factum
            .seal(case_id, "checkpoint")
            .unwrap_err()
            .message
            .contains("does not exist")
    );
    assert!(!missing.exists() && factum.list_tree_heads(case_id).unwrap().is_empty());
}

#[test]
fn default_seal_folder_is_created() {
    let f = Fixture::new();
    let factum = f.factum_default_seals();
    let case_id = make_case(&factum, 2, "C-1");
    factum.seal(case_id, "checkpoint").unwrap();
    assert!(factum.default_seal_dir().is_dir());
}

#[test]
fn seal_file_keeps_gpg_line_endings() {
    // text mode on Windows turned CRLF into CRCRLF, so read_seal_files could no longer parse the seal
    let f = Fixture::new();
    f.signer.crlf.set(true);
    let factum = f.factum();
    let case_id = make_case(&factum, 2, "C-1");
    let head = factum
        .get_tree_head(factum.seal(case_id, "checkpoint").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(head.file_path.unwrap()).unwrap(),
        head.signature.unwrap().into_bytes()
    );
    assert_eq!(
        factum
            .read_seal_files(case_id)
            .unwrap()
            .iter()
            .map(|s| s.tree_size())
            .collect::<Vec<_>>(),
        vec![2]
    );
}

// --- verifier

/// A case with evidence and three notes on it: five entries.
fn verifier_case(factum: &Factum) -> (i64, i64, Vec<i64>) {
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "abc", "").unwrap();
    let notes = (0..3)
        .map(|n| {
            factum
                .create_note(&format!("note {n}"), Some(evidence_id), case_id)
                .unwrap()
        })
        .collect();
    (case_id, evidence_id, notes)
}

#[test]
fn sealed_case_with_external_folder_is_ok() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, _) = verifier_case(&factum);
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
    assert_eq!((report.tree_size, report.newest_seal_size), (5, Some(5)));
    assert_eq!(report.count(Level::Ok), 5);
    assert_eq!(
        report.signers,
        vec![("FAKEFINGERPRINT1".to_string(), Some("Fake Signer".to_string()))]
    );
}

#[test]
fn unsealed_entries_and_default_seal_folder_warn() {
    let f = Fixture::new();
    let factum = f.factum_default_seals();
    let (case_id, _, _) = verifier_case(&factum);
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Warn);
    assert_eq!(codes(&report, None), HashSet::from(["not_sealed", "seal_dir_default"]));
}

#[test]
fn unicode_and_crlf_text_verifies() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, _) = verifier_case(&factum);
    factum
        .create_note("Müller ✓ 🦊\r\nzweite Zeile  ", None, case_id)
        .unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    assert_eq!(factum.verify_case(case_id, None).unwrap().overall(), Level::Ok);
}

#[test]
fn modified_text_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, notes) = verifier_case(&factum);
    factum.seal(case_id, "checkpoint").unwrap();
    f.exec(&format!("UPDATE entries SET text = 'changed' WHERE id = {}", notes[1]));
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Fail);
    assert_eq!(report.entry_result(notes[1]).unwrap().status(), Level::Fail);
    assert!(codes(&report, Some(Level::Fail)).contains("leaf_hash"));
}

#[test]
fn rewritten_hashes_without_the_key_fail_on_signatures() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, notes) = verifier_case(&factum);
    let mut accumulator = merkle::MerkleAccumulator::new();
    for entry in factum.load_entries(case_id).unwrap() {
        let text = if entry.id == notes[0] {
            "forged".to_string()
        } else {
            entry.text.clone()
        };
        let data = leaf_data(
            case_id,
            entry.leaf_index,
            &entry.kind,
            entry.evidence_id,
            &text,
            &parse_payload(entry.payload_json.as_deref()),
            entry.corrects_id,
            &entry.created_utc,
            1,
        );
        let leaf = merkle::leaf_hash(data.as_bytes());
        accumulator.add(leaf);
        f.db.conn
            .execute(
                "UPDATE entries SET text = ?, leaf_hash = ?, root_hash = ? WHERE id = ?",
                rusqlite::params![text, hex::encode(leaf), hex::encode(accumulator.root()), entry.id],
            )
            .unwrap();
    }
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(codes(&report, Some(Level::Fail)), HashSet::from(["signature_mismatch"]));
}

#[test]
fn deleted_middle_entry_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, notes) = verifier_case(&factum);
    f.exec(&format!("DELETE FROM entries WHERE id = {}", notes[0]));
    let failures = codes(&factum.verify_case(case_id, None).unwrap(), Some(Level::Fail));
    assert!(failures.contains("gap") && failures.contains("tree_head"));
}

#[test]
fn truncation_after_a_seal_fails_even_without_the_database_seal() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, notes) = verifier_case(&factum);
    factum.seal(case_id, "checkpoint").unwrap();
    f.exec(&format!(
        "DELETE FROM entries WHERE id = {}; DELETE FROM tree_heads;",
        notes[2]
    ));
    let report = factum.verify_case(case_id, None).unwrap();
    assert!(codes(&report, Some(Level::Fail)).contains("seal_truncated"));
    assert_eq!(
        report.tree_heads.iter().map(|h| h.source).collect::<Vec<_>>(),
        vec![SealSource::File]
    );
}

#[test]
fn edited_evidence_row_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, evidence_id, _) = verifier_case(&factum);
    f.exec(&format!(
        "UPDATE evidence SET evidence_hash = 'other' WHERE id = {evidence_id}"
    ));
    assert!(codes(&factum.verify_case(case_id, None).unwrap(), Some(Level::Fail)).contains("metadata"));
}

fn metadata_messages(report: &CaseReport) -> Vec<String> {
    report
        .findings
        .iter()
        .filter(|f| f.code == "metadata")
        .map(|f| f.message.clone())
        .collect()
}

#[test]
fn evidence_details_tamper_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "", "seized").unwrap();
    f.exec(&format!("UPDATE evidence SET details = 'x' WHERE id = {evidence_id}"));
    let messages = metadata_messages(&factum.verify_case(case_id, None).unwrap());
    assert!(messages.iter().any(|m| m.contains("field 'details'")), "{messages:?}");
}

#[test]
fn edited_evidence_details_verify() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "", "seized").unwrap();
    factum.update_evidence_details(evidence_id, "imaged").unwrap();
    factum.update_evidence_details(evidence_id, "imaged twice").unwrap();
    assert!(metadata_messages(&factum.verify_case(case_id, None).unwrap()).is_empty());
}

#[test]
fn pre_v4_payload_without_details_verifies() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let created_utc = utc_now();
    f.exec(&format!(
        "INSERT INTO evidence (id, case_id, description, created_utc) VALUES (7, {case_id}, 'old disk', '{created_utc}')"
    ));
    factum
        .append(
            case_id,
            "system",
            "Evidence #7 created: old disk",
            Append {
                payload: Some(
                    serde_json::json!({"event": "evidence_created", "evidence_id": 7, "case_id": case_id,
                    "description": "old disk", "evidence_hash": "", "created_utc": created_utc}),
                ),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(metadata_messages(&factum.verify_case(case_id, None).unwrap()).is_empty());
}

#[test]
fn edited_case_row_and_archive_state_fail() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, _) = verifier_case(&factum);
    f.exec(&format!(
        "UPDATE cases SET case_name = 'renamed', archived_utc = '{}' WHERE id = {case_id}",
        utc_now()
    ));
    let report = factum.verify_case(case_id, None).unwrap();
    let failures: Vec<_> = report.findings.iter().filter(|f| f.code == "metadata").collect();
    assert_eq!(failures.len(), 2);
    assert!(
        failures[0].message.contains("(log: 'Case', database: 'renamed')"),
        "{}",
        failures[0].message
    );
}

#[test]
fn correction_pointing_at_another_case_fails() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, notes) = verifier_case(&factum);
    let other_case = factum.create_case("C-2", "Other", "").unwrap();
    let foreign = factum.create_note("foreign", None, other_case).unwrap();
    f.exec(&format!(
        "UPDATE entries SET corrects_id = {foreign} WHERE id = {}",
        notes[2]
    ));
    assert!(codes(&factum.verify_case(case_id, None).unwrap(), Some(Level::Fail)).contains("correction_target"));
}

#[test]
fn unsigned_entries_fail() {
    let f = Fixture::with_signer(FakeSigner::new(false));
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    assert!(codes(&factum.verify_case(case_id, None).unwrap(), Some(Level::Fail)).contains("unsigned"));
}

#[test]
fn late_signature_is_only_a_warning() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, notes) = verifier_case(&factum);
    let entry = factum.get_entry(notes[0]).unwrap().unwrap();
    let late = FakeSigner::fake_signature(&entry_signed_payload(
        &entry.leaf_hash,
        entry.tree_size,
        &entry.root_hash,
    ));
    f.exec(&format!("UPDATE entries SET signature = NULL WHERE id = {}", notes[0]));
    f.db.conn
        .execute(
            "INSERT INTO late_signatures (target, target_id, signature, signed_utc) VALUES ('entry', ?, ?, ?)",
            rusqlite::params![notes[0], late, utc_now()],
        )
        .unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Warn);
    assert_eq!(codes(&report, None), HashSet::from(["signed_later"]));
}

#[test]
fn untrusted_key_fails() {
    let f = Fixture::new();
    let (case_id, _, _) = verifier_case(&f.factum());
    let untrusted = FakeSigner::with_trust(true, "TRUST_UNDEFINED");
    let factum = Factum::with_seal_dir(&f.db, &untrusted, Some(f.seal_dir.clone()));
    assert!(codes(&factum.verify_case(case_id, None).unwrap(), Some(Level::Fail)).contains("key_untrusted"));
}

#[test]
fn verify_entry_checks_one_signature() {
    let f = Fixture::new();
    let factum = f.factum();
    let (_, _, notes) = verifier_case(&factum);
    let result = factum.verify_entry(notes[1]).unwrap();
    assert!(result.status() == Level::Ok && result.signature.valid && result.recomputed_tree_size == 4);
}

#[test]
fn progress_is_reported() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, _) = verifier_case(&factum);
    let mut calls = Vec::new();
    let mut record = |done, total| calls.push((done, total));
    factum.verify_case(case_id, Some(&mut record)).unwrap();
    assert_eq!(calls.last(), Some(&(5, 5)));
}

#[test]
fn tampered_payload_is_a_failure_not_a_crash() {
    for tampered in ["{bad", "\"text\"", "[1, 2]", "null"] {
        let f = Fixture::new();
        let factum = f.factum();
        let (case_id, _, _) = verifier_case(&factum);
        f.db.conn
            .execute(
                "UPDATE entries SET payload_json = ? WHERE case_id = ? AND leaf_index = 1",
                rusqlite::params![tampered, case_id],
            )
            .unwrap();
        let report = factum.verify_case(case_id, None).unwrap();
        assert_eq!(report.overall(), Level::Fail, "{tampered}");
        let failures = codes(&report, Some(Level::Fail));
        assert!(
            failures.contains("leaf_hash") || failures.contains("metadata"),
            "{tampered}"
        );
        let entry_id = f.count(&format!(
            "SELECT id FROM entries WHERE case_id = {case_id} AND leaf_index = 1"
        ));
        assert!(factum.get_entry(entry_id).unwrap().is_some());
    }
}

#[test]
fn unreachable_seal_folder_is_reported() {
    let f = Fixture::new();
    let (case_id, _, _) = verifier_case(&f.factum());
    f.factum().seal(case_id, "checkpoint").unwrap();
    let unplugged = Factum::with_seal_dir(&f.db, &f.signer, Some(f.path().join("unplugged")));
    assert!(codes(&unplugged.verify_case(case_id, None).unwrap(), Some(Level::Warn)).contains("seal_dir_unreachable"));
}

#[test]
fn renaming_a_case_keeps_earlier_seals_valid() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, _) = verifier_case(&factum);
    factum.seal(case_id, "checkpoint").unwrap();
    factum.update_case(case_id, "C-renamed", "Case", "").unwrap();
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
}

#[test]
fn seal_files_from_before_a_rename_still_detect_truncation() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _, _) = verifier_case(&factum);
    factum.seal(case_id, "checkpoint").unwrap();
    factum.update_case(case_id, "C-renamed", "Case", "").unwrap();
    // drop the rename entry and the newest note: the old-name seal file (5 entries) now exceeds the log
    f.exec(&format!(
        "DELETE FROM entries WHERE case_id = {case_id} AND leaf_index >= 4; DELETE FROM tree_heads;"
    ));
    assert!(codes(&factum.verify_case(case_id, None).unwrap(), Some(Level::Fail)).contains("seal_truncated"));
}

// --- late signing

/// A case written without a key: case created entry, one note, one seal; the key becomes available later.
fn unsigned_case(f: &Fixture) -> (i64, i64, i64) {
    f.signer.set_active(false);
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let note = factum.create_note("written without a key", None, case_id).unwrap();
    let tree_head_id = factum.seal(case_id, "checkpoint").unwrap();
    f.signer.set_active(true);
    (case_id, note, tree_head_id)
}

#[test]
fn sign_entry_turns_failure_into_warning() {
    let f = Fixture::new();
    let (case_id, note, _) = unsigned_case(&f);
    let factum = f.factum();
    factum.sign_entry(note).unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(
        report
            .entry_result(note)
            .unwrap()
            .findings
            .iter()
            .map(|f| f.code)
            .collect::<Vec<_>>(),
        vec!["signed_later"]
    );
}

#[test]
fn sign_tree_head_writes_signed_copy_next_to_the_unsigned_file() {
    let f = Fixture::new();
    let (_, _, tree_head_id) = unsigned_case(&f);
    let factum = f.factum();
    factum.sign_tree_head(tree_head_id).unwrap();
    let path = PathBuf::from(factum.get_tree_head(tree_head_id).unwrap().unwrap().file_path.unwrap());
    assert!(path.with_extension("asc").exists());
    let payload: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(payload["tree_size"], 2);
}

#[test]
fn sign_all_unsigned_then_only_warnings_remain() {
    let f = Fixture::new();
    let (case_id, _, _) = unsigned_case(&f);
    let factum = f.factum();
    assert_eq!(factum.sign_all_unsigned(case_id).unwrap(), 3); // case created entry, note, seal
    let report = factum.verify_case(case_id, None).unwrap();
    assert!(
        !report.findings.iter().any(|f| f.level == Level::Fail),
        "{:?}",
        report.findings
    );
    assert_eq!(factum.sign_all_unsigned(case_id).unwrap(), 0);
}

#[test]
fn already_signed_entry_is_refused() {
    let f = Fixture::new();
    let (_, note, _) = unsigned_case(&f);
    let factum = f.factum();
    factum.sign_entry(note).unwrap();
    assert!(factum.sign_entry(note).unwrap_err().message.contains("already signed"));
}

#[test]
fn broken_log_is_not_signed() {
    let f = Fixture::new();
    let (case_id, note, _) = unsigned_case(&f);
    f.exec(&format!("UPDATE entries SET text = 'tampered' WHERE id = {note}"));
    let error = f.factum().sign_all_unsigned(case_id).unwrap_err();
    assert!(error.is(ErrorKind::LogBroken) && error.message.contains("Nothing was signed"));
}

#[test]
fn signing_needs_an_active_key() {
    let f = Fixture::new();
    let (_, note, _) = unsigned_case(&f);
    f.signer.set_active(false);
    let error = f.factum().sign_entry(note).unwrap_err();
    assert!(error.is(ErrorKind::Signing) && error.message.contains("No GPG key is active"));
}

#[test]
fn signed_copy_replaces_the_unsigned_seal_file_in_verification() {
    let f = Fixture::new();
    let (case_id, _, _) = unsigned_case(&f);
    let factum = f.factum();
    factum.sign_all_unsigned(case_id).unwrap();
    assert!(!codes(&factum.verify_case(case_id, None).unwrap(), None).contains("seal_file_unsigned"));
}

#[test]
fn signed_copy_keeps_gpg_line_endings() {
    let f = Fixture::new();
    let (_, _, tree_head_id) = unsigned_case(&f);
    f.signer.crlf.set(true);
    let factum = f.factum();
    factum.sign_tree_head(tree_head_id).unwrap();
    let path =
        PathBuf::from(factum.get_tree_head(tree_head_id).unwrap().unwrap().file_path.unwrap()).with_extension("asc");
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes.windows(3).any(|w| w == b"\r\r\n") && bytes.windows(2).any(|w| w == b"\r\n"));
}

// --- companion

#[test]
fn case_database_verifies_unchanged_after_companion_use() {
    use factum::companion::{Archetype, CompanionDb, NewQuestion, Rating};
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    for number in 0..3 {
        factum
            .append(case_id, "note", &format!("note {number}"), Append::default())
            .unwrap();
    }
    factum.seal(case_id, "checkpoint").unwrap();
    let tables_before = f.count("SELECT COUNT(*) FROM sqlite_master");
    let companion = CompanionDb::open_for(&f.db.path).unwrap();
    let q = NewQuestion {
        text: "What explains the gap?".into(),
        archetype: Archetype::Causality,
        rests_on: vec![1],
    };
    let id = companion.insert_question(case_id, None, &q).unwrap();
    companion.rate_question(id, Rating::Minus).unwrap();
    assert_eq!(companion.minus_examples().unwrap().len(), 1);
    let report = factum.verify_case(case_id, None).unwrap();
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(f.count("PRAGMA user_version"), factum::db::SCHEMA_VERSION);
    assert_eq!(f.count("SELECT COUNT(*) FROM sqlite_master"), tables_before);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%question%'"),
        0
    );
}

// --- notes with images

fn test_image(shade: u8) -> NoteImage {
    NoteImage::from_rgba(2, 2, &[shade; 16]).unwrap()
}

fn image_ids(images: &[NoteImage]) -> Vec<String> {
    let mut ids: Vec<String> = images.iter().map(|i| i.id.clone()).collect();
    ids.sort();
    ids
}

#[test]
fn note_images_are_stored_in_the_signed_payload() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = test_image(10);
    let text = format!("Screenshot: {}", image.reference("login page"));
    let id = factum
        .create_note_with_images(&text, std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let entry = factum.get_entry(id).unwrap().unwrap();
    assert_eq!(entry.images(), vec![image]);
    assert_eq!(entry.text, text);
    assert!(
        factum::iocs::get_iocs_for_entry(&f.db.conn, id)
            .unwrap()
            .iter()
            .all(|(kind, _)| kind != "hash")
    );
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
}

#[test]
fn changing_one_base64_character_fails_verification() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = test_image(10);
    let id = factum
        .create_note_with_images(&image.reference("x"), std::slice::from_ref(&image), None, case_id)
        .unwrap();
    let json: String =
        f.db.conn
            .query_row("SELECT payload_json FROM entries WHERE id = ?", [id], |r| r.get(0))
            .unwrap();
    let start = json.find("\"data\":\"").unwrap() + 8;
    let old = json.as_bytes()[start] as char;
    let new = if old == 'A' { 'B' } else { 'A' };
    let tampered = format!("{}{new}{}", &json[..start], &json[start + 1..]);
    f.db.conn
        .execute(
            "UPDATE entries SET payload_json = ? WHERE id = ?",
            rusqlite::params![tampered, id],
        )
        .unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.level == Level::Fail && x.code == "leaf_hash" && x.entry_id == Some(id)),
        "{:?}",
        report.findings
    );
}

#[test]
fn unreferenced_images_are_not_saved() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let (kept, dropped) = (test_image(10), test_image(20));
    let id = factum
        .create_note_with_images(&kept.reference("a"), &[kept.clone(), dropped], None, case_id)
        .unwrap();
    let entry = factum.get_entry(id).unwrap().unwrap();
    assert_eq!(entry.images(), vec![kept]);
}

#[test]
fn a_reference_without_its_image_is_refused() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let image = test_image(10);
    let err = factum
        .create_note_with_images(&image.reference("a"), &[], None, case_id)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("The note refers to image {}, which is not attached.", image.id)
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM entries WHERE kind = 'note'"), 0);
}

#[test]
fn a_correction_keeps_only_referenced_images() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let (a, b, c) = (test_image(10), test_image(20), test_image(30));
    let text = format!("{} {}", a.reference("a"), b.reference("b"));
    let note = factum
        .create_note_with_images(&text, &[a.clone(), b.clone()], None, case_id)
        .unwrap();
    // images are not carried over: the correction attaches exactly the ones it is given
    let corrected = format!("{} {}", b.reference("b"), c.reference("c"));
    let version = factum
        .correct_note_with_images(note, &corrected, &[b.clone(), c.clone()])
        .unwrap();
    let entry = factum.get_entry(version).unwrap().unwrap();
    assert_eq!(image_ids(&entry.images()), image_ids(&[b, c]));
    factum.seal(case_id, "checkpoint").unwrap();
    assert_eq!(factum.verify_case(case_id, None).unwrap().overall(), Level::Ok);
    let err = factum
        .correct_note_with_images(note, &a.reference("a"), &[])
        .unwrap_err();
    assert!(err.to_string().contains(&a.id), "{err}");
}

#[test]
fn notes_without_images_keep_a_null_payload() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let id = factum.create_note("plain", None, case_id).unwrap();
    let corrected = factum.correct_note(id, "plain, corrected").unwrap();
    for id in [id, corrected] {
        assert_eq!(
            f.count(&format!("SELECT payload_json IS NULL FROM entries WHERE id = {id}")),
            1
        );
        assert!(factum.get_entry(id).unwrap().unwrap().images().is_empty());
    }
}

#[test]
fn garbage_payload_still_lists_the_note() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let id = factum.create_note("plain", None, case_id).unwrap();
    f.exec(&format!(
        "UPDATE entries SET payload_json = '{{\"images\":5}}' WHERE id = {id}"
    ));
    assert!(factum.get_entry(id).unwrap().unwrap().images().is_empty());
    assert!(factum.list_entries(case_id, &Default::default()).unwrap().contains(&id));
}

#[test]
fn a_text_only_correction_keeps_the_images_it_still_refers_to() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let (kept, dropped) = (test_image(10), test_image(20));
    let text = format!("a {} b {}", kept.reference("one"), dropped.reference("two"));
    let first = factum
        .create_note_with_images(&text, &[kept.clone(), dropped], None, case_id)
        .unwrap();
    // the newest version's images are the source, also when the correction starts from an older id
    let second = factum
        .correct_note(first, &format!("a {} b, fixed", kept.reference("one")))
        .unwrap();
    assert_eq!(factum.get_entry(second).unwrap().unwrap().images(), vec![kept.clone()]);
    let third = factum
        .correct_note(first, &format!("a {} b, fixed again", kept.reference("one")))
        .unwrap();
    assert_eq!(factum.get_entry(third).unwrap().unwrap().images(), vec![kept]);
    factum.seal(case_id, "checkpoint").unwrap();
    let report = factum.verify_case(case_id, None).unwrap();
    assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
}
