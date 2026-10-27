//! GUI tests, ported from test_main_window and test_gui_widgets. They drive the real window through
//! egui_kittest (AccessKit). With FACTUM_SCREENSHOTS=<folder> they also save rendered screenshots.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

use super::*;
use crate::companion::{Preset, Rating};
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
        let evidence_id = factum.create_evidence(case_id, "disk", "", "").unwrap();
        let note = factum
            .create_note("first note #tag 10.0.0.1", Some(evidence_id), case_id)
            .unwrap();
        factum
            .correct_note(note, "first note, corrected #tag 10.0.0.1")
            .unwrap();
        factum.create_evidence(case_id, "usb stick", "", "").unwrap();
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
            // no companion thread: tests have no endpoint; a stub handle is installed where commands matter
            FactumApp::build(db, &cc.egui_ctx, false)
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

fn evidence_named(harness: &Harness<'_, FactumApp>, name: &str) -> crate::evidence::Evidence {
    let factum = harness.state().factum();
    let case_id = factum.list_cases(false).unwrap()[0];
    factum
        .list_evidence_for_case(case_id, false)
        .unwrap()
        .into_iter()
        .filter_map(|id| factum.get_evidence(id).unwrap())
        .find(|e| e.description == name)
        .unwrap()
}

#[test]
fn new_evidence_dialog_saves_description() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    harness.state_mut().open_new_evidence();
    harness.run_ok();
    type_into(&mut harness, "Name", "laptop");
    type_into(&mut harness, "Description", "seized at desk 4");
    click_label(&mut harness, "Create");
    assert_eq!(evidence_named(&harness, "laptop").details, "seized at desk 4");
}

#[test]
fn edit_evidence_saves_description() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    let disk = evidence_named(&harness, "disk");
    let ctx = harness.ctx.clone();
    harness.state_mut().tree_action(TreeAction::EditEvidence(disk.id), &ctx);
    harness.run_ok();
    assert!(matches!(harness.state().dialogs.last(), Some(Dialog::EditEvidence { name, .. }) if name == "disk"));
    type_into(&mut harness, "Description", "imaged with FTK");
    click_label(&mut harness, "Save");
    assert_eq!(evidence_named(&harness, "disk").details, "imaged with FTK");
    assert!(harness.state().dialogs.is_empty());
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

fn open_companion_settings(harness: &mut Harness<'_, FactumApp>) {
    harness.get_by_label("Companion").click();
    harness.run_ok();
    harness.get_by_label("Settings…").click();
    harness.run_ok();
}

fn settings_dialog<'a>(harness: &'a Harness<'_, FactumApp>) -> &'a CompanionSettingsDialog {
    match harness.state().dialogs.last() {
        Some(Dialog::CompanionSettings(dialog)) => dialog,
        _ => panic!("the companion settings dialog is not open"),
    }
}

fn type_into(harness: &mut Harness<'_, FactumApp>, label: &str, text: &str) {
    harness.get_by_label(label).focus();
    harness.run_ok();
    harness.get_by_label(label).type_text(text);
    harness.run_ok();
}

/// Steps the GUI for up to 3 s until `done` holds (the listing waits 600 ms after the last edit).
fn run_until(harness: &mut Harness<'_, FactumApp>, done: impl Fn(&Harness<'_, FactumApp>) -> bool) {
    for _ in 0..30 {
        harness.run_ok();
        if done(harness) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn companion_menu_absent_until_configured_and_settings_dialog_lists_models() {
    let fixture = Fixture::new();
    let llm = crate::companion::fake_llm::FakeLlm::start();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    assert!(harness.query_by_label_contains("QUESTIONS").is_none());
    assert!(harness.query_by_label_contains("companion:").is_none());
    open_companion_settings(&mut harness);
    assert_eq!(
        settings_dialog(&harness).models_status,
        "Set the endpoint URL to load the model list."
    );
    type_into(&mut harness, "Endpoint URL", &llm.url);
    run_until(&mut harness, |h| {
        settings_dialog(h).models_status == "2 models from the endpoint."
    });
    assert_eq!(settings_dialog(&harness).models_status, "2 models from the endpoint.");
    assert_eq!(
        settings_dialog(&harness).draft.model,
        "",
        "the listing fills the dropdown, not the field"
    );
    screenshot(&mut harness, "companion-settings");
}

#[test]
fn an_invalid_context_window_keeps_the_dialog_and_saves_nothing() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    open_companion_settings(&mut harness);
    type_into(&mut harness, "Endpoint URL", "http://127.0.0.1:1");
    type_into(&mut harness, "Context window", "lots");
    harness.get_by_label("Test connection").scroll_to_me();
    harness.run_ok();
    harness.get_by_label("Test connection").click();
    harness.run_ok();
    assert!(settings_dialog(&harness).probe_worker.is_none());
    harness.get_by_label("OK").click();
    harness.run_ok();
    assert!(
        harness
            .query_by_label("The context window is a number of tokens.")
            .is_some()
    );
    settings_dialog(&harness);
    assert!(!companion_db_path(&fixture.path).exists());
}

#[test]
fn settings_dialog_saves_trimmed_and_starts_thread() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    open_companion_settings(&mut harness);
    type_into(&mut harness, "Endpoint URL", " http://127.0.0.1:1 ");
    type_into(&mut harness, "Model", " m ");
    harness.get_by_label("OK").click();
    harness.run_ok();
    let cdb = CompanionDb::open_for(&fixture.path).unwrap();
    let saved = Settings::load(&cdb).unwrap();
    assert_eq!(saved.model, "m");
    assert_eq!(saved.endpoint_url, "http://127.0.0.1:1");
    assert!(harness.state().companion.is_some());
}

/// Clicks a widget through AccessKit: a pointer click on a radio button in a freshly opened modal can be lost.
fn click_label(harness: &mut Harness<'_, FactumApp>, label: &str) {
    harness.get_by_label(label).click_accesskit();
    harness.run_ok();
}

#[test]
fn preset_choice_shows_builtin_read_only() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    open_companion_settings(&mut harness);
    click_label(&mut harness, "OSINT research");
    assert_eq!(settings_dialog(&harness).draft.preset, Preset::Osint);
    type_into(&mut harness, "Guideline", "X");
    assert_eq!(settings_dialog(&harness).draft.global_guideline, "");
}

#[test]
fn custom_text_survives_preset_switch() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    open_companion_settings(&mut harness);
    click_label(&mut harness, "Custom");
    // seeded from the preset chosen before
    assert_eq!(
        settings_dialog(&harness).draft.global_guideline,
        crate::companion::prompts::DEFAULT_GUIDELINE
    );
    type_into(&mut harness, "Guideline", "Mine.");
    click_label(&mut harness, "Forensics");
    click_label(&mut harness, "Custom");
    assert!(settings_dialog(&harness).draft.global_guideline.contains("Mine."));
    click_label(&mut harness, "OK");
    let saved = Settings::load(&CompanionDb::open_for(&fixture.path).unwrap()).unwrap();
    assert_eq!(saved.preset, Preset::Custom);
    assert!(saved.guideline().contains("Mine."));
}

#[test]
fn test_connection_reports_unreachable() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    open_companion_settings(&mut harness);
    type_into(&mut harness, "Endpoint URL", "http://127.0.0.1:1");
    // the dialog scrolls in a small window
    harness.get_by_label("Test connection").scroll_to_me();
    harness.run_ok();
    harness.get_by_label("Test connection").click();
    run_until(&mut harness, |h| settings_dialog(h).probe.is_some());
    let probe = settings_dialog(&harness).probe.clone().unwrap();
    assert!(probe.unwrap_err().contains("Unreachable"));
}

/// Saves configured companion settings, so the Questions section exists without a running thread.
fn configure_companion(fixture: &Fixture) -> CompanionDb {
    let cdb = CompanionDb::open_for(&fixture.path).unwrap();
    Settings {
        endpoint_url: "http://127.0.0.1:1".into(),
        model: "m".into(),
        ..Settings::default()
    }
    .save(&cdb)
    .unwrap();
    cdb
}

fn first_note_versions(fixture: &Fixture) -> (i64, Vec<i64>) {
    let db = fixture.db();
    let signer = FakeSigner::new(false);
    let factum = Factum::with_seal_dir(&db, &signer, None);
    let case_id = factum.list_cases(false).unwrap()[0];
    let note = factum.list_entries(case_id, &EntryFilter::notes()).unwrap()[0];
    (case_id, factum.history(note).unwrap())
}

fn ask(cdb: &CompanionDb, case_id: i64, text: &str, rests_on: Vec<i64>) -> i64 {
    let question = crate::companion::NewQuestion {
        text: text.into(),
        archetype: crate::companion::Archetype::Document,
        rests_on,
    };
    cdb.insert_question(case_id, None, &question).unwrap()
}

#[test]
fn side_panel_is_stacked_pinned_first() {
    let fixture = Fixture::new();
    let (_, versions) = first_note_versions(&fixture);
    let mut harness = fixture.harness();
    harness.state().factum().set_pinned(versions[1], true).unwrap();
    select_case(&mut harness);
    let pinned = harness.get_by_label("PINNED 1").rect();
    let iocs = harness.get_by_label_contains("IOCS").rect();
    assert!(pinned.min.y < iocs.min.y, "Pinned is above the IoCs");
    // both sections are on screen at once (the note in the log and pinned), the IoCs closed
    assert_eq!(harness.get_all_by_label_contains("first note, corrected").count(), 2);
    assert!(harness.query_by_label_contains("IP  (1)").is_none());
}

#[test]
fn questions_section_absent_when_unconfigured() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    assert!(harness.query_by_label_contains("QUESTIONS").is_none());
    assert!(harness.query_by_label_contains("No goal set").is_none());
    assert!(harness.query_by_label("Companion for this case").is_none());
    assert!(
        !companion_db_path(&fixture.path).exists(),
        "an unconfigured companion leaves no file behind"
    );
}

#[test]
fn questions_section_shows_goal_row_and_rows_in_position_order() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let (case_id, versions) = first_note_versions(&fixture);
    ask(&cdb, case_id, "Which tool imaged the disk?", vec![versions[1]]);
    let rated = ask(&cdb, case_id, "Who held the disk overnight?", vec![versions[1]]);
    cdb.rate_question(rated, Rating::Plus).unwrap(); // the screenshots show a given rating
    let mut harness = fixture.harness();
    select_case(&mut harness);
    assert!(harness.query_by_label("QUESTIONS 2").is_some());
    let goal = harness.get_by_label("No goal set for this case. Set it…").rect();
    let first = harness.get_by_label("Which tool imaged the disk?").rect();
    let second = harness.get_by_label("Who held the disk overnight?").rect();
    assert!(goal.min.y < first.min.y && first.min.y < second.min.y);
    let ctx = harness.ctx.clone();
    harness.state_mut().set_theme(&ctx, "light");
    harness.run_ok();
    screenshot(&mut harness, "questions-light");
    harness.state_mut().set_theme(&ctx, "dark");
    harness.run_ok();
    screenshot(&mut harness, "questions-dark");
}

#[test]
fn minus_removes_row_and_plus_keeps_it() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let (case_id, versions) = first_note_versions(&fixture);
    let q1 = ask(&cdb, case_id, "Which tool imaged the disk?", vec![versions[1]]);
    let q2 = ask(&cdb, case_id, "Who held the disk overnight?", vec![versions[1]]);
    let mut harness = fixture.harness();
    select_case(&mut harness);
    harness.get_all_by_label("−").next().unwrap().click();
    harness.run_ok();
    assert!(harness.query_by_label("Which tool imaged the disk?").is_none());
    harness.get_by_label("+").click();
    harness.run_ok();
    assert!(harness.query_by_label("Who held the disk overnight?").is_some());
    let open = cdb.open_questions(case_id).unwrap();
    assert_eq!(
        open.iter().map(|q| (q.id, q.rating)).collect::<Vec<_>>(),
        [(q2, Rating::Plus)]
    );
    assert!(
        cdb.resolved_questions(case_id)
            .unwrap()
            .iter()
            .any(|q| q.id == q1 && q.rating == Rating::Minus)
    );
}

#[test]
fn entry_link_jumps_to_newest_version() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let (case_id, versions) = first_note_versions(&fixture);
    ask(&cdb, case_id, "Which tool imaged the disk?", vec![versions[0]]);
    let mut harness = fixture.harness();
    select_case(&mut harness);
    assert_eq!(harness.state().focused_card, None);
    harness.get_by_label(&format!("#{}", versions[0])).click();
    harness.run_ok();
    assert_eq!(harness.state().focused_card, Some(versions[1]));
}

#[test]
fn case_toggle_hides_section_and_goal_dialog_writes_goal() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let (case_id, _) = first_note_versions(&fixture);
    let mut harness = fixture.harness();
    select_case(&mut harness);
    harness.get_by_label("⋯").click();
    harness.run_ok();
    harness.get_by_label("Case goal…").click();
    harness.run_ok();
    type_into(&mut harness, "Case goal", "Establish how the disk left the building");
    harness.get_by_label("OK").click();
    harness.run_ok();
    assert_eq!(
        cdb.case_settings(case_id).unwrap().unwrap().goal,
        "Establish how the disk left the building"
    );
    assert!(harness.query_by_label_contains("No goal set").is_none());
    assert!(harness.query_by_label_contains("QUESTIONS").is_some());
    harness.get_by_label("⋯").click();
    harness.run_ok();
    harness.get_by_label("Companion for this case").click();
    harness.run_ok();
    assert!(!cdb.case_settings(case_id).unwrap().unwrap().enabled);
    assert!(harness.query_by_label_contains("QUESTIONS").is_none());
}

#[test]
fn local_note_sends_case_changed() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let case_id = harness.state().case_id.unwrap();
    cdb.ensure_case(case_id).unwrap(); // what the thread does when the case is selected
    let commands = harness.state_mut().install_companion_stub();
    harness.run_ok();
    let _: Vec<Command> = commands.try_iter().collect(); // what the first rebuild reports
    harness.state_mut().composer = "a second note".into();
    harness.state_mut().submit_note();
    harness.run_ok();
    assert!(commands.try_iter().any(|cmd| cmd == Command::CaseChanged(case_id)));
}

/// Opens an item of the Questions section's ▾ menu.
fn questions_menu(harness: &mut Harness<'_, FactumApp>, item: &str) {
    harness.get_by_label("▾").click();
    harness.run_ok();
    harness.get_by_label(item).click();
    harness.run_ok();
}

#[test]
fn history_lists_resolved_and_unlink_restores() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let (case_id, versions) = first_note_versions(&fixture);
    let answered = ask(&cdb, case_id, "Which tool imaged the disk?", vec![versions[1]]);
    let rejected = ask(&cdb, case_id, "Who held the disk overnight?", vec![versions[1]]);
    let pass = cdb.begin_pass(case_id, crate::companion::PassKind::Full, "m").unwrap();
    cdb.answer_question(answered, versions[1], pass).unwrap();
    cdb.rate_question(rejected, Rating::Minus).unwrap();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    questions_menu(&mut harness, "History…");
    assert!(harness.query_by_label("Which tool imaged the disk?").is_some());
    assert!(harness.query_by_label("Who held the disk overnight?").is_some());
    screenshot(&mut harness, "companion-history");
    harness.get_by_label("Unlink").click();
    harness.run_ok();
    harness.get_by_label("Restore").click();
    harness.run_ok();
    let open: Vec<i64> = cdb.open_questions(case_id).unwrap().iter().map(|q| q.id).collect();
    assert_eq!(open, [answered, rejected]);
    assert!(harness.query_by_label("Unlink").is_none());
    assert!(harness.query_by_label("No resolved questions.").is_some());
    assert!(harness.query_by_label("QUESTIONS 2").is_some());
}

#[test]
fn ask_window_runs_on_worker_and_shows_references() {
    let fixture = Fixture::new();
    let llm = crate::companion::fake_llm::FakeLlm::start();
    let cdb = CompanionDb::open_for(&fixture.path).unwrap();
    Settings {
        endpoint_url: llm.url.clone(),
        model: "m".into(),
        ..Settings::default()
    }
    .save(&cdb)
    .unwrap();
    llm.push(200, &crate::companion::fake_llm::openai_chat("See [1].", "stop", 10));
    let (_, versions) = first_note_versions(&fixture);
    let mut harness = fixture.harness();
    // pinned notes come first: the corrected note is excerpt [1]
    harness.state().factum().set_pinned(versions[1], true).unwrap();
    select_case(&mut harness);
    questions_menu(&mut harness, "Ask…");
    type_into(&mut harness, "Question", "Which tool imaged the disk?");
    harness.get_by_label("Ask").click();
    let link = format!("[1] #{}", versions[1]);
    run_until(&mut harness, |h| h.query_by_label(&link).is_some());
    assert!(harness.query_by_label("See [1].").is_some());
    assert!(
        harness
            .query_by_label_contains("not found in the cited entries")
            .is_none()
    );
    screenshot(&mut harness, "companion-ask");
    harness.get_by_label(&link).click();
    harness.run_ok();
    assert_eq!(harness.state().focused_card, Some(versions[1]));
}

#[test]
fn rethink_sends_command() {
    let fixture = Fixture::new();
    configure_companion(&fixture);
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let case_id = harness.state().case_id.unwrap();
    let commands = harness.state_mut().install_companion_stub();
    harness.run_ok();
    questions_menu(&mut harness, "Re-think now");
    assert!(commands.try_iter().any(|cmd| cmd == Command::Rethink(case_id)));
}

#[test]
fn a_dialog_does_not_keep_the_size_of_a_taller_one() {
    let fixture = Fixture::new();
    configure_companion(&fixture);
    let mut harness = fixture.harness();
    select_case(&mut harness);
    open_companion_settings(&mut harness);
    harness.get_by_label("Cancel").click();
    harness.run_ok();
    let case_id = harness.state().factum().list_cases(false).unwrap()[0];
    harness.state_mut().dialogs.push(Dialog::CaseGoal {
        case_id,
        goal: String::new(),
    });
    harness.run_ok();
    screenshot(&mut harness, "case-goal-after-settings");
    // the buttons sit right under the field, not centred in the settings dialog's height
    let field = harness.get_by_label("Case goal").rect();
    let ok = harness.get_by_label("OK").rect();
    assert!(ok.min.y - field.max.y < 40.0, "{field:?} {ok:?}");
}

#[test]
fn a_long_note_scrolls_inside_the_composer() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    screenshot(&mut harness, "composer");
    harness.state_mut().composer = (1..=40).map(|i| format!("line {i}\n")).collect();
    harness.run_ok();
    screenshot(&mut harness, "composer-long");
    // the editor keeps the panel's height; the button row stays on screen
    let button = harness.get_by_label_contains("Add Note").rect();
    assert!(button.max.y < 820.0, "{button:?}");
    let height = harness.state().composer_height;
    assert!((height - DEFAULT_COMPOSER_HEIGHT).abs() < 1.0, "{height}");
    // dragging the panel's top edge up makes it taller
    let top = harness.get_by_label_contains("Adding to").rect().min.y - 8.0;
    let pointer = |harness: &mut Harness<'_, FactumApp>, event: egui::Event| {
        harness.input_mut().events.push(event);
        harness.step();
    };
    pointer(&mut harness, egui::Event::PointerMoved(egui::pos2(600.0, top)));
    pointer(
        &mut harness,
        egui::Event::PointerButton {
            pos: egui::pos2(600.0, top),
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        },
    );
    for y in [top - 50.0, top - 100.0, top - 150.0] {
        pointer(&mut harness, egui::Event::PointerMoved(egui::pos2(600.0, y)));
    }
    pointer(
        &mut harness,
        egui::Event::PointerButton {
            pos: egui::pos2(600.0, top - 150.0),
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        },
    );
    harness.run_ok();
    screenshot(&mut harness, "composer-dragged");
    let dragged = harness.state().composer_height;
    assert!(dragged > height + 100.0, "{height} -> {dragged}");
}

#[test]
fn the_editor_stays_above_the_buttons_at_the_smallest_height() {
    let fixture = Fixture::new();
    let height = format!("{MIN_COMPOSER_HEIGHT}");
    fixture.db().set_setting(COMPOSER_HEIGHT_SETTING, &height).unwrap();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    screenshot(&mut harness, "composer-smallest");
    let editor = harness.get_by_role(egui::accesskit::Role::MultilineTextInput).rect();
    let button = harness.get_by_label_contains("Add Note").rect();
    assert!(editor.max.y <= button.min.y, "{editor:?} {button:?}");
}
