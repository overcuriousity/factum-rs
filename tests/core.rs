//! Ports of test_log_service, test_cases_evidence, test_note_manager and test_tags_iocs.

mod common;

use common::{Fixture, add_case_row, add_raw_entry, system_events};
use factum::error::ErrorKind;
use factum::log_service::{Append, entry_signed_payload};
use factum::notes::EntryFilter;
use factum::signer::FakeSigner;
use factum::{Db, Factum, iocs, merkle, tags};
use serde_json::json;

type Row = (i64, String, i64, String, Option<String>, String);

fn rows(db: &Db, case_id: i64) -> Vec<Row> {
    let mut statement = db
        .conn
        .prepare("SELECT leaf_index, leaf_hash, tree_size, root_hash, signature, text FROM entries WHERE case_id = ? ORDER BY leaf_index")
        .unwrap();
    statement
        .query_map([case_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn root_of(stored: &[Row]) -> String {
    let hashes: Vec<merkle::Hash> = stored.iter().map(|r| merkle::from_hex(&r.1)).collect();
    hex::encode(merkle::root(&hashes))
}

// --- log service

#[test]
fn first_append_is_a_one_leaf_tree() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    f.factum().append(case_id, "note", "first", Append::default()).unwrap();
    let stored = rows(&f.db, case_id);
    let (index, leaf, size, root, signature, _) = &stored[0];
    assert_eq!((*index, *size, root), (0, 1, leaf));
    assert_eq!(
        signature.as_deref(),
        Some(FakeSigner::fake_signature(&entry_signed_payload(leaf, 1, root)).as_str())
    );
}

#[test]
fn root_covers_all_leaves() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    for text in ["a", "b", "c"] {
        f.factum().append(case_id, "note", text, Append::default()).unwrap();
    }
    let stored = rows(&f.db, case_id);
    assert_eq!(stored.iter().map(|r| r.2).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(stored[2].3, root_of(&stored));
}

#[test]
fn text_is_stored_exactly() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    f.factum()
        .append(case_id, "note", "Müller ✓\r\nline two  ", Append::default())
        .unwrap();
    assert_eq!(rows(&f.db, case_id)[0].5, "Müller ✓\r\nline two  ");
}

#[test]
fn archived_case_is_refused() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", true);
    let error = f.factum().append(case_id, "note", "x", Append::default()).unwrap_err();
    assert!(error.is(ErrorKind::CaseArchived));
    assert!(rows(&f.db, case_id).is_empty());
    f.factum()
        .append(
            case_id,
            "system",
            "Case reopened",
            Append {
                allow_archived: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(rows(&f.db, case_id).len(), 1);
}

#[test]
fn signing_failure_saves_nothing() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    f.signer.fail_next.set(true);
    let error = f.factum().append(case_id, "note", "x", Append::default()).unwrap_err();
    assert!(error.is(ErrorKind::Signing));
    assert!(rows(&f.db, case_id).is_empty());
}

#[test]
fn without_active_key_entries_are_unsigned() {
    let f = Fixture::with_signer(FakeSigner::new(false));
    let case_id = add_case_row(&f.db, "C-1", false);
    f.factum().append(case_id, "note", "x", Append::default()).unwrap();
    assert_eq!(rows(&f.db, case_id)[0].4, None);
}

#[test]
fn notes_get_tags_system_entries_do_not() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let factum = f.factum();
    let note = factum.append(case_id, "note", "#malware", Append::default()).unwrap();
    let system = factum
        .append(
            case_id,
            "system",
            "#notatag",
            Append {
                payload: Some(json!({"event": "x"})),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        tags::get_tags_for_entry(&f.db.conn, note).unwrap(),
        vec![("malware".to_string(), "text".to_string())]
    );
    assert!(tags::get_tags_for_entry(&f.db.conn, system).unwrap().is_empty());
    let stored: String =
        f.db.conn
            .query_row("SELECT payload_json FROM entries WHERE id = ?", [system], |r| r.get(0))
            .unwrap();
    assert_eq!(stored, r#"{"event":"x"}"#);
}

#[test]
fn on_commit_failure_rolls_back_the_entry() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let broken = |_: &rusqlite::Connection, _: i64| -> factum::Result<()> { Err(factum::FactumError::general("boom")) };
    assert!(
        f.factum()
            .append(
                case_id,
                "note",
                "x",
                Append {
                    on_commit: Some(&broken),
                    ..Default::default()
                }
            )
            .is_err()
    );
    assert!(rows(&f.db, case_id).is_empty());
}

/// A signer that lets "another process" (its own connection) append before every signature.
fn racing_signer(db_path: &std::path::Path, case_id: i64, races: usize, text: &'static str) -> FakeSigner {
    let other_db = Db::open(db_path).unwrap();
    let other_signer = FakeSigner::new(true);
    let mut remaining = races;
    let signer = FakeSigner::new(true);
    *signer.before_sign.borrow_mut() = Some(Box::new(move || {
        if remaining > 0 {
            remaining -= 1;
            Factum::with_seal_dir(&other_db, &other_signer, None)
                .append(case_id, "note", text, Append::default())
                .unwrap();
        }
    }));
    signer
}

#[test]
fn concurrent_append_retries_and_never_forks() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let racing = racing_signer(&f.db.path, case_id, 1, "written by the CLI meanwhile");
    Factum::with_seal_dir(&f.db, &racing, None)
        .append(case_id, "note", "written by the GUI", Append::default())
        .unwrap();
    let stored = rows(&f.db, case_id);
    let summary: Vec<(&str, i64, i64)> = stored.iter().map(|r| (r.5.as_str(), r.0, r.2)).collect();
    assert_eq!(
        summary,
        vec![("written by the CLI meanwhile", 0, 1), ("written by the GUI", 1, 2)]
    );
    assert_eq!(stored[1].3, root_of(&stored));
}

#[test]
fn gives_up_after_three_races() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let racing = racing_signer(&f.db.path, case_id, usize::MAX, "race");
    let error = Factum::with_seal_dir(&f.db, &racing, None)
        .append(case_id, "note", "mine", Append::default())
        .unwrap_err();
    assert!(error.is(ErrorKind::LogChanged) && error.message.contains("nothing was saved"));
    assert_eq!(
        rows(&f.db, case_id).iter().map(|r| r.5.as_str()).collect::<Vec<_>>(),
        vec!["race", "race", "race"]
    );
}

#[test]
fn correcting_an_already_corrected_entry_is_refused() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let factum = f.factum();
    let original = factum.append(case_id, "note", "v1", Append::default()).unwrap();
    factum
        .append(
            case_id,
            "note",
            "v2",
            Append {
                corrects_id: Some(original),
                ..Default::default()
            },
        )
        .unwrap();
    let error = factum
        .append(
            case_id,
            "note",
            "v2 again",
            Append {
                corrects_id: Some(original),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(error.is(ErrorKind::InvalidCorrection));
}

#[test]
fn locked_database_is_a_clear_error() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let blocker = Db::open(&f.db.path).unwrap();
    blocker.conn.execute_batch("BEGIN IMMEDIATE").unwrap(); // another factum process holds the write lock
    f.db.conn.busy_timeout(std::time::Duration::from_millis(50)).unwrap();
    let error = f.factum().append(case_id, "note", "x", Append::default()).unwrap_err();
    assert!(error.message.contains("locked"), "{error}");
    blocker.conn.execute_batch("ROLLBACK").unwrap();
    assert!(rows(&f.db, case_id).is_empty());
}

// --- cases and evidence

#[test]
fn create_case_writes_case_created_entry() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case(" C-1 ", "", "desc").unwrap();
    let case = factum.get_case(case_id).unwrap().unwrap();
    assert_eq!(
        (case.case_file.as_str(), case.case_name.as_str(), case.is_archived()),
        ("C-1", "C-1", false)
    );
    assert_eq!(
        system_events(&f.db, case_id),
        vec![
            json!({"event": "case_created", "case_id": case_id, "case_file": "C-1", "case_name": "C-1",
                    "description": "desc", "created_utc": case.created_utc})
        ]
    );
}

#[test]
fn failed_signature_leaves_no_case_behind() {
    let f = Fixture::new();
    f.signer.fail_next.set(true);
    assert!(
        f.factum()
            .create_case("C-1", "Case", "")
            .unwrap_err()
            .is(ErrorKind::Signing)
    );
    assert!(f.factum().list_cases(true).unwrap().is_empty());
}

#[test]
fn case_file_is_required() {
    let f = Fixture::new();
    assert!(f.factum().create_case("  ", "x", "").is_err());
}

#[test]
fn update_case_writes_case_edited() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Old", "").unwrap();
    factum.update_case(case_id, "C-1", "New", "more").unwrap();
    assert_eq!(factum.get_case(case_id).unwrap().unwrap().case_name, "New");
    assert_eq!(system_events(&f.db, case_id).last().unwrap()["event"], "case_edited");
}

#[test]
fn archive_makes_case_read_only_hidden_and_sealed() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.set_active_case(case_id).unwrap();
    let tree_head_id = factum.archive_case(case_id).unwrap();
    let case = factum.get_case(case_id).unwrap().unwrap();
    assert!(case.is_archived() && !case.is_active);
    assert_eq!(
        system_events(&f.db, case_id).last().unwrap(),
        &json!({"event": "case_archived", "case_id": case_id, "archived_utc": case.archived_utc})
    );
    assert_eq!(factum.get_tree_head(tree_head_id).unwrap().unwrap().reason, "archive");
    assert!(factum.list_cases(false).unwrap().is_empty());
    assert_eq!(factum.list_cases(true).unwrap(), vec![case_id]);
    assert!(
        factum
            .append(case_id, "note", "x", Append::default())
            .unwrap_err()
            .is(ErrorKind::CaseArchived)
    );
    assert!(factum.set_active_case(case_id).unwrap_err().is(ErrorKind::CaseArchived));
    assert!(
        factum
            .create_evidence(case_id, "disk", "")
            .unwrap_err()
            .is(ErrorKind::CaseArchived)
    );
}

#[test]
fn archive_reports_failed_seal_but_stays_archived() {
    let f = Fixture::new();
    let blocker = f.path().join("file");
    std::fs::write(&blocker, "x").unwrap();
    let factum = Factum::with_seal_dir(&f.db, &f.signer, Some(blocker.join("seals")));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let error = factum.archive_case(case_id).unwrap_err();
    assert!(
        error
            .message
            .contains("Case archived, but the seal could not be created"),
        "{error}"
    );
    assert!(factum.get_case(case_id).unwrap().unwrap().is_archived());
}

#[test]
fn reopen() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    factum.archive_case(case_id).unwrap();
    factum.reopen_case(case_id).unwrap();
    assert!(!factum.get_case(case_id).unwrap().unwrap().is_archived());
    assert_eq!(
        system_events(&f.db, case_id).last().unwrap(),
        &json!({"event": "case_reopened", "case_id": case_id})
    );
}

#[test]
fn delete_permanently_needs_archive_and_exact_case_file() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "abc").unwrap();
    factum
        .append(
            case_id,
            "note",
            "#tag 10.0.0.1",
            Append {
                evidence_id: Some(evidence_id),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        factum
            .delete_case_permanently(case_id, "C-1")
            .unwrap_err()
            .message
            .contains("Archive the case first")
    );
    factum.archive_case(case_id).unwrap();
    assert!(
        factum
            .delete_case_permanently(case_id, "c-1")
            .unwrap_err()
            .is(ErrorKind::Confirmation)
    );
    factum.delete_case_permanently(case_id, "C-1").unwrap();
    for table in [
        "cases",
        "evidence",
        "entries",
        "tree_heads",
        "tags",
        "ioc",
        "entry_tag_map",
        "entry_ioc_map",
    ] {
        assert_eq!(f.count(&format!("SELECT COUNT(*) FROM {table}")), 0, "{table}");
    }
}

#[test]
fn create_evidence_writes_system_entry_without_evidence_id() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, " Laptop HDD ", " abc ").unwrap();
    let evidence = factum.get_evidence(evidence_id).unwrap().unwrap();
    assert_eq!(
        (evidence.description.as_str(), evidence.evidence_hash.as_str()),
        ("Laptop HDD", "abc")
    );
    assert_eq!(
        system_events(&f.db, case_id).last().unwrap(),
        &json!({"event": "evidence_created", "evidence_id": evidence_id, "case_id": case_id,
                "description": "Laptop HDD", "evidence_hash": "abc", "created_utc": evidence.created_utc})
    );
    assert!(!factum.has_entries(evidence_id).unwrap());
}

#[test]
fn only_empty_evidence_can_be_deleted() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let empty = factum.create_evidence(case_id, "empty", "").unwrap();
    let used = factum.create_evidence(case_id, "used", "").unwrap();
    factum
        .append(
            case_id,
            "note",
            "x",
            Append {
                evidence_id: Some(used),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        factum
            .delete_evidence(used)
            .unwrap_err()
            .is(ErrorKind::EvidenceNotEmpty)
    );
    factum.delete_evidence(empty).unwrap();
    assert!(factum.get_evidence(empty).unwrap().unwrap().is_deleted());
    assert_eq!(factum.list_evidence_for_case(case_id, false).unwrap(), vec![used]);
    assert_eq!(factum.list_evidence_for_case(case_id, true).unwrap(), vec![empty, used]);
    assert_eq!(
        system_events(&f.db, case_id).last().unwrap()["event"],
        "evidence_deleted"
    );
    assert!(!factum.set_active_evidence(Some(empty)).unwrap());
}

#[test]
fn set_active_evidence_activates_its_case() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let evidence_id = factum.create_evidence(case_id, "disk", "").unwrap();
    assert!(factum.set_active_evidence(Some(evidence_id)).unwrap());
    assert_eq!(factum.get_active_case_id().unwrap(), Some(case_id));
    assert_eq!(factum.get_active_evidence_id().unwrap(), Some(evidence_id));
}

// --- notes

fn case_with_evidence(factum: &Factum) -> (i64, i64) {
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    (case_id, factum.create_evidence(case_id, "disk", "").unwrap())
}

#[test]
fn create_note_on_case_and_evidence() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, evidence_id) = case_with_evidence(&factum);
    let note = factum.create_note("on evidence", Some(evidence_id), case_id).unwrap();
    let entry = factum.get_entry(note).unwrap().unwrap();
    assert_eq!(
        (entry.kind.as_str(), entry.evidence_id, entry.leaf_index),
        ("note", Some(evidence_id), 2)
    );
    assert!(entry.late_signature.is_none() && entry.payload_json.is_none());
}

#[test]
fn create_note_validates_input() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, evidence_id) = case_with_evidence(&factum);
    let other_case = factum.create_case("C-2", "Other", "").unwrap();
    assert!(factum.create_note("   ", None, case_id).is_err());
    assert!(
        factum
            .create_note("x", Some(evidence_id), other_case)
            .unwrap_err()
            .message
            .contains("does not belong")
    );
}

#[test]
fn correction_attaches_to_newest_version() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _) = case_with_evidence(&factum);
    let v1 = factum.create_note("v1", None, case_id).unwrap();
    let v2 = factum.correct_note(v1, "v2").unwrap();
    let v3 = factum.correct_note(v1, "v3").unwrap(); // picked the old version: redirected to v2
    assert_eq!(factum.get_entry(v3).unwrap().unwrap().corrects_id, Some(v2));
    assert_eq!(factum.latest_version_id(v1).unwrap(), v3);
    assert_eq!(factum.history(v2).unwrap(), vec![v1, v2, v3]);
}

#[test]
fn system_entries_cannot_be_corrected() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _) = case_with_evidence(&factum);
    let system_entry = factum.list_entries(case_id, &EntryFilter::default()).unwrap()[0];
    assert!(
        factum
            .correct_note(system_entry, "x")
            .unwrap_err()
            .is(ErrorKind::InvalidCorrection)
    );
}

#[test]
fn list_entries_shows_newest_versions_at_the_original_position() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, evidence_id) = case_with_evidence(&factum);
    let first = factum.create_note("first", None, case_id).unwrap();
    let second = factum.create_note("second", Some(evidence_id), case_id).unwrap();
    let first_v2 = factum.correct_note(first, "first, corrected").unwrap();
    let all = factum.list_entries(case_id, &EntryFilter::default()).unwrap();
    assert_eq!(all[2..], [first_v2, second]);
    assert_eq!(
        factum.list_entries(case_id, &EntryFilter::notes()).unwrap(),
        vec![first_v2, second]
    );
    let on_evidence = EntryFilter {
        evidence_id: Some(evidence_id),
        ..Default::default()
    };
    assert_eq!(factum.list_entries(case_id, &on_evidence).unwrap(), vec![second]);
}

#[test]
fn tag_filter_matches_text_tags_and_labels() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _) = case_with_evidence(&factum);
    let tagged = factum.create_note("found #malware", None, case_id).unwrap();
    let labelled = factum.create_note("plain", None, case_id).unwrap();
    tags::add_label(&f.db, labelled, "malicious").unwrap();
    let by_tag = |tag| {
        factum
            .list_entries(
                case_id,
                &EntryFilter {
                    tag: Some(tag),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    assert_eq!(by_tag("mal"), vec![tagged, labelled]);
    assert!(by_tag("100%_").is_empty());
}

#[test]
fn search_matches_text_tags_labels_and_system_entries() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _) = case_with_evidence(&factum);
    let in_text = factum.create_note("Found PowerShell history", None, case_id).unwrap();
    let tagged = factum.create_note("see #persistence", None, case_id).unwrap();
    let labelled = factum.create_note("plain", None, case_id).unwrap();
    tags::add_label(&f.db, labelled, "powershell-review").unwrap();
    let search = |text| {
        factum
            .list_entries(
                case_id,
                &EntryFilter {
                    search: Some(text),
                    ..Default::default()
                },
            )
            .unwrap()
    };
    assert_eq!(search("powershell"), vec![in_text, labelled]);
    assert_eq!(search("persist"), vec![tagged]);
    assert_eq!(search("case created").len(), 1); // system entries are searched too
    assert!(search("100%_").is_empty());
}

#[test]
fn pin_moves_to_the_correction() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _) = case_with_evidence(&factum);
    let note = factum.create_note("x", None, case_id).unwrap();
    factum.pin_note(note).unwrap();
    let correction = factum.correct_note(note, "y").unwrap();
    assert_eq!(
        factum
            .list_entries(
                case_id,
                &EntryFilter {
                    pinned_only: true,
                    ..Default::default()
                }
            )
            .unwrap(),
        vec![correction]
    );
    assert!(!factum.get_entry(note).unwrap().unwrap().is_pinned);
}

#[test]
fn pinning_is_refused_on_archived_cases() {
    let f = Fixture::new();
    let factum = f.factum();
    let (case_id, _) = case_with_evidence(&factum);
    let note = factum.create_note("x", None, case_id).unwrap();
    factum.archive_case(case_id).unwrap();
    assert!(factum.pin_note(note).unwrap_err().is(ErrorKind::CaseArchived));
}

// --- tags and IOCs

#[test]
fn text_tags_are_parsed_with_source_text() {
    let f = Fixture::new();
    let entry_id = add_raw_entry(
        &f.db,
        add_case_row(&f.db, "C-1", false),
        "found #malware and #persistence #malware",
        None,
    );
    tags::parse_tags_from_note(&f.db.conn, entry_id, "found #malware and #persistence #malware").unwrap();
    assert_eq!(
        tags::get_tags_for_entry(&f.db.conn, entry_id).unwrap(),
        vec![("malware".into(), "text".into()), ("persistence".into(), "text".into())]
    );
}

#[test]
fn label_does_not_replace_text_tag_and_cannot_remove_it() {
    let f = Fixture::new();
    let entry_id = add_raw_entry(&f.db, add_case_row(&f.db, "C-1", false), "#malware", None);
    tags::parse_tags_from_note(&f.db.conn, entry_id, "#malware").unwrap();
    assert_eq!(tags::add_label(&f.db, entry_id, "#review").unwrap(), 1);
    assert_eq!(tags::add_label(&f.db, entry_id, "malware").unwrap(), 0);
    assert_eq!(tags::remove_label(&f.db, entry_id, "malware").unwrap(), 0);
    assert_eq!(
        tags::get_tags_for_entry(&f.db.conn, entry_id).unwrap(),
        vec![("malware".into(), "text".into()), ("review".into(), "label".into())]
    );
    assert_eq!(tags::remove_label(&f.db, entry_id, "review").unwrap(), 1);
    assert_eq!(
        tags::get_tags_for_entry(&f.db.conn, entry_id).unwrap(),
        vec![("malware".into(), "text".into())]
    );
}

#[test]
fn labels_are_refused_on_archived_cases() {
    let f = Fixture::new();
    let entry_id = add_raw_entry(&f.db, add_case_row(&f.db, "C-1", true), "note", None);
    assert!(
        tags::add_label(&f.db, entry_id, "x")
            .unwrap_err()
            .is(ErrorKind::CaseArchived)
    );
}

#[test]
fn case_iocs_only_count_newest_versions() {
    let f = Fixture::new();
    let case_id = add_case_row(&f.db, "C-1", false);
    let original = add_raw_entry(&f.db, case_id, "contacted 10.0.0.1", None);
    let correction = add_raw_entry(&f.db, case_id, "contacted 10.0.0.2", Some(original));
    iocs::parse_ioc_from_note(&f.db.conn, original, "contacted 10.0.0.1").unwrap();
    iocs::parse_ioc_from_note(&f.db.conn, correction, "contacted 10.0.0.2").unwrap();
    let for_case = iocs::get_iocs_for_case(&f.db.conn, case_id).unwrap();
    assert_eq!(
        for_case.into_iter().collect::<Vec<_>>(),
        vec![("ip".to_string(), vec!["10.0.0.2".to_string()])]
    );
    assert_eq!(
        iocs::get_iocs_for_entry(&f.db.conn, original).unwrap(),
        vec![("ip".into(), "10.0.0.1".into())]
    );
}
