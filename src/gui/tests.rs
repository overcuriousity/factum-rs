//! GUI tests, ported from test_main_window and test_gui_widgets. They drive the real window through
//! egui_kittest (AccessKit). With FACTUM_SCREENSHOTS=<folder> they also save rendered screenshots.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

use super::*;
use crate::signer::FakeSigner;

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Fixture {
    /// A case with evidence, notes on both, a correction, a label and a pinned note (all unsigned).
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("factum.db");
        let db = Db::open(&path).unwrap();
        let signer = FakeSigner::new(false);
        let factum = Factum::with_seal_dir(&db, &signer, None);
        let case_id = factum.create_case("C-1", "Case", "").unwrap();
        let evidence_id = factum.create_evidence(case_id, "disk", "").unwrap();
        let note = factum
            .create_note("first note #tag 10.0.0.1", Some(evidence_id), case_id)
            .unwrap();
        factum
            .correct_note(note, "first note, corrected #tag 10.0.0.1")
            .unwrap();
        factum.create_evidence(case_id, "usb stick", "").unwrap();
        Self { _dir: dir, path }
    }

    fn db(&self) -> Db {
        Db::open(&self.path).unwrap()
    }

    fn harness(&self) -> Harness<'static, FactumApp> {
        let db = self.db();
        let builder = Harness::builder().with_size(egui::vec2(1280.0, 820.0));
        // rendering needs a GPU adapter (CI runners have none): only for screenshots
        let builder = if std::env::var_os("FACTUM_SCREENSHOTS").is_some() {
            builder.wgpu()
        } else {
            builder
        };
        let mut harness = builder.build_eframe(move |cc| {
            theme::install_fonts(&cc.egui_ctx);
            FactumApp::new(db, &cc.egui_ctx)
        });
        harness.run_ok();
        harness
    }
}

fn screenshot(harness: &mut Harness<'_, FactumApp>, name: &str) {
    let Ok(folder) = std::env::var("FACTUM_SCREENSHOTS") else {
        return;
    };
    match harness.render() {
        Ok(image) => image.save(PathBuf::from(folder).join(format!("{name}.png"))).unwrap(),
        Err(e) => eprintln!("cannot render {name}: {e}"),
    }
}

fn select_case(harness: &mut Harness<'_, FactumApp>) {
    let case_id = harness.state().factum().list_cases(false).unwrap()[0];
    harness.state_mut().select(Some(case_id), None);
    harness.run_ok();
}

#[test]
fn case_view_shows_system_rows_and_newest_versions() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let app = harness.state();
    let systems = app.view.items.iter().filter(|i| matches!(i, Item::System(_))).count();
    let cards: Vec<&Card> = app
        .view
        .items
        .iter()
        .filter_map(|i| match i {
            Item::Note(c) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(systems, 3);
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].history.len(), 1);
    assert!(
        harness
            .query_by_label_contains("Show history (1 earlier version)")
            .is_some()
    );
    assert_eq!(app.view.note_count, "1 note · 3 system");
    harness.state_mut().show_system = false;
    harness.state_mut().dirty = true;
    harness.run_ok();
    assert!(!harness.state().view.items.iter().any(|i| matches!(i, Item::System(_))));
    assert_eq!(harness.state().view.note_count, "1 note · 3 system hidden");
}

#[test]
fn archived_case_disables_note_input() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    let case_id = harness.state().factum().list_cases(false).unwrap()[0];
    harness.state().factum().archive_case(case_id).unwrap();
    harness.state_mut().show_archived = true;
    harness.state_mut().select(Some(case_id), None);
    harness.run_ok();
    assert!(harness.query_by_label_contains("(archived, read-only)").is_some());
    assert!(harness.state().view.case.as_ref().unwrap().is_archived());
}

#[test]
fn evidence_view_and_deletable_evidence() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    let factum_db = fixture.db();
    let signer = FakeSigner::new(false);
    let factum = Factum::with_seal_dir(&factum_db, &signer, None);
    let case_id = factum.list_cases(false).unwrap()[0];
    let [disk, usb] = factum.list_evidence_for_case(case_id, false).unwrap()[..] else {
        panic!()
    };
    harness.state_mut().select(None, Some(disk));
    harness.run_ok();
    assert!(!harness.state().view.evidence_deletable); // it has notes
    let cards: Vec<&Card> = harness
        .state()
        .view
        .items
        .iter()
        .filter_map(|i| match i {
            Item::Note(c) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(cards[0].evidence, None); // the view already says which evidence
    harness.state_mut().select(None, Some(usb));
    harness.run_ok();
    assert!(harness.state().view.evidence_deletable);
    assert!(harness.query_by_label_contains("Case › usb stick").is_some());
}

#[test]
fn search_field_searches_text_or_tags() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    harness.state_mut().filter = "#tag".into();
    harness.state_mut().dirty = true;
    harness.run_ok();
    assert_eq!(harness.state().tag_and_search(), (Some("tag".to_string()), None));
    assert_eq!(harness.state().view.items.len(), 1);
    assert_eq!(harness.state().view.note_count, "1 note");
    harness.state_mut().filter = "nothing like this".into();
    harness.state_mut().dirty = true;
    harness.run_ok();
    assert!(
        harness
            .state()
            .view
            .empty_text
            .as_deref()
            .unwrap()
            .starts_with("No entries match")
    );
}

#[test]
fn tree_shows_note_counts_and_follows_new_notes() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    assert_eq!(harness.state().view.tree[0].notes, 1);
    assert_eq!(harness.state().view.tree[0].evidence[0].1, 1);
    harness.state_mut().composer = "a second note".into();
    harness.state_mut().submit_note();
    harness.run_ok();
    assert_eq!(harness.state().view.tree[0].notes, 2);
    assert!(harness.state().composer.is_empty());
}

#[test]
fn p_pins_the_focused_note() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let entry_id = harness
        .state()
        .view
        .items
        .iter()
        .find_map(|i| match i {
            Item::Note(c) => Some(c.entry.id),
            _ => None,
        })
        .unwrap();
    harness.state_mut().focused_card = Some(entry_id);
    harness.key_press(egui::Key::P);
    harness.run_ok();
    assert_eq!(harness.state().view.pinned.len(), 1);
    assert!(harness.query_by_label("PINNED 1").is_some());
    screenshot(&mut harness, "pinned");
}

#[test]
fn side_panel_and_theme_are_remembered() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.state_mut().side_panel = false;
    let ctx = harness.ctx.clone();
    harness.state_mut().set_theme(&ctx, "dark");
    harness.state_mut().quit();
    drop(harness);
    let reopened = fixture.harness();
    assert!(!reopened.state().side_panel);
    assert_eq!(reopened.state().theme, "dark");
}

#[test]
fn cli_target_is_shown_when_set() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    assert!(harness.state().view.cli_active.is_empty());
    let case_id = harness.state().factum().list_cases(false).unwrap()[0];
    harness.state_mut().set_cli_active_case(case_id);
    harness.run_ok();
    assert_eq!(harness.state().view.cli_active, "Case: Case");
    assert!(harness.query_by_label("CLI active:").is_some());
}

#[test]
fn external_changes_appear() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let case_id = harness.state().case_id.unwrap();
    // the CLI writes through its own connection
    let db = fixture.db();
    let signer = FakeSigner::new(false);
    Factum::with_seal_dir(&db, &signer, None)
        .create_note("written on the command line", None, case_id)
        .unwrap();
    harness.state_mut().last_poll = Instant::now() - Duration::from_secs(5);
    harness.run_ok();
    assert!(harness.query_by_label_contains("written on the command line").is_some());
}

#[test]
fn jump_to_superseded_entry_shows_the_newest_version() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    let case_id = harness.state().factum().list_cases(false).unwrap()[0];
    let first_note = harness
        .state()
        .factum()
        .list_entries(case_id, &EntryFilter::notes())
        .unwrap()[0];
    let original = harness.state().factum().history(first_note).unwrap()[0];
    harness.state_mut().jump_to_entry(original);
    harness.run_ok();
    assert_eq!(harness.state().current_case_id(), Some(case_id));
    assert_eq!(harness.state().focused_card, Some(first_note));
}

#[test]
fn verification_runs_in_the_background_and_opens_a_report() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let ctx = harness.ctx.clone();
    let case_id = harness.state().case_id.unwrap();
    harness.state_mut().verify_case(&ctx, case_id);
    for _ in 0..200 {
        harness.step();
        if !harness.state().verify_windows.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    harness.run_ok();
    assert_eq!(harness.state().verify_windows.len(), 1);
    assert!(harness.query_by_label_contains("Failures (").is_some());
    screenshot(&mut harness, "verify");
}

#[test]
fn dialogs_validate_their_input() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.state_mut().open_new_case();
    harness.run_ok();
    harness.get_by_label("Create").click();
    harness.run_ok();
    assert!(harness.query_by_label("Case file number is required.").is_some());
    screenshot(&mut harness, "new-case");
}

#[test]
fn dark_theme_renders() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    let ctx = harness.ctx.clone();
    harness.state_mut().set_theme(&ctx, "dark");
    select_case(&mut harness);
    screenshot(&mut harness, "case-dark");
    harness.state_mut().set_theme(&ctx, "light");
    harness.run_ok();
    screenshot(&mut harness, "case-light");
}
