//! GUI tests, ported from test_main_window and test_gui_widgets. They drive the real window through
//! egui_kittest (AccessKit). With FACTUM_SCREENSHOTS=<folder> they also save rendered screenshots.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

use super::*;
use crate::companion::{Preset, Rating};
use crate::signer::FakeSigner;
use companion_dialogs::BUILTIN_GUIDELINE;

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

    /// A database without cases: what a first start sees.
    fn empty() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("factum.db");
        drop(Db::open(&path).unwrap());
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
    assert!(harness.query_by_label("Show 1 earlier version").is_some());
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
    screenshot(&mut harness, "archived");
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
    assert_eq!(harness.state().view.cli_active, "Case");
    assert!(harness.query_by_label("CLI target").is_some());
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
    assert!(harness.query_by_label_contains("Failures ").is_some());
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
    harness.get_by_label("Settings").click();
    harness.run_ok();
    harness.get_by_label("Companion…").click();
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
    // a built-in guideline is behind its heading, and typing into it changes nothing
    let field = |h: &Harness<'_, FactumApp>| {
        h.query_by_role_and_label(egui::accesskit::Role::MultilineTextInput, BUILTIN_GUIDELINE)
            .is_some()
    };
    assert!(!field(&harness));
    click_label(&mut harness, "Guideline");
    assert!(field(&harness));
    harness
        .get_by_role_and_label(egui::accesskit::Role::MultilineTextInput, BUILTIN_GUIDELINE)
        .focus();
    harness.run_ok();
    harness
        .get_by_role_and_label(egui::accesskit::Role::MultilineTextInput, BUILTIN_GUIDELINE)
        .type_text("X");
    harness.run_ok();
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
    assert!(harness.query_by_label("IP 1").is_none());
}

#[test]
fn questions_section_absent_when_unconfigured() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    assert!(harness.query_by_label_contains("QUESTIONS").is_none());
    assert!(harness.query_by_label_contains("Set a goal").is_none());
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
    assert!(harness.query_by_label("▾ QUESTIONS 2").is_some());
    let goal = harness.get_by_label("Set a goal for this case…").rect();
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
    // the heading hides and shows the rows
    harness.get_by_label("▾ QUESTIONS 2").click();
    harness.run_ok();
    assert!(harness.query_by_label("Which tool imaged the disk?").is_none());
    harness.get_by_label("▸ QUESTIONS 2").click();
    harness.run_ok();
    assert!(harness.query_by_label("Which tool imaged the disk?").is_some());
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
    harness.get_all_by_label("Not useful").next().unwrap().click();
    harness.run_ok();
    assert!(harness.query_by_label("Which tool imaged the disk?").is_none());
    harness.get_by_label("Useful").click();
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
    harness.get_by_label("Case actions").click();
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
    assert!(harness.query_by_label_contains("Set a goal").is_none());
    assert!(harness.query_by_label_contains("QUESTIONS").is_some());
    harness.get_by_label("Case actions").click();
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

/// Opens an item of the Questions section's menu.
fn questions_menu(harness: &mut Harness<'_, FactumApp>, item: &str) {
    harness.get_by_label("Companion").click();
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
    assert!(harness.query_by_label("▾ QUESTIONS 2").is_some());
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
    let button = harness.get_by_label("Add").rect();
    assert!(button.max.y < 820.0, "{button:?}");
    let height = harness.state().composer_height;
    assert!((height - DEFAULT_COMPOSER_HEIGHT).abs() < 1.0, "{height}");
    // dragging the panel's top edge up makes it taller
    // the panel's top edge, just above the editor
    let top = harness
        .get_by_role(egui::accesskit::Role::MultilineTextInput)
        .rect()
        .min
        .y
        - 6.0;
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
    let button = harness.get_by_label("Add").rect();
    assert!(editor.max.y <= button.min.y, "{editor:?} {button:?}");
}

fn wizard_open(harness: &Harness<'_, FactumApp>) -> bool {
    matches!(harness.state().dialogs.last(), Some(Dialog::Wizard(_)))
}

fn wizard<'a>(harness: &'a Harness<'_, FactumApp>) -> &'a Wizard {
    match harness.state().dialogs.last() {
        Some(Dialog::Wizard(wizard)) => wizard,
        _ => panic!("the setup wizard is not open"),
    }
}

/// Clicks Next (or Skip) until the wizard shows `step`.
fn wizard_to(harness: &mut Harness<'_, FactumApp>, button: &str, step: Step) {
    for _ in 0..6 {
        if wizard(harness).step == step {
            return;
        }
        click_label(harness, button);
    }
    assert_eq!(wizard(harness).step, step);
}

#[test]
fn wizard_auto_starts_on_fresh_database_only() {
    let fresh = Fixture::empty();
    assert!(wizard_open(&fresh.harness()));
    assert!(!wizard_open(&Fixture::new().harness()));
    let done = Fixture::empty();
    done.db().set_setting(ONBOARDING_SETTING, "1").unwrap();
    assert!(!wizard_open(&done.harness()));
}

#[test]
fn skipping_everything_writes_only_the_flag() {
    let fixture = Fixture::empty();
    let mut harness = fixture.harness();
    wizard_to(&mut harness, "Next", Step::Gpg);
    wizard_to(&mut harness, "Skip", Step::Summary);
    click_label(&mut harness, "Finish");
    assert!(harness.state().dialogs.is_empty());
    let db = fixture.db();
    assert_eq!(db.get_setting(ONBOARDING_SETTING).unwrap(), "1");
    assert_eq!(db.get_setting(ACTIVE_KEY_SETTING).unwrap(), "");
    assert_eq!(db.get_setting(SEAL_DIR_SETTING).unwrap(), "");
    assert_eq!(db.get_setting(THEME_SETTING).unwrap(), "");
    assert!(!companion_db_path(&fixture.path).exists());
}

#[test]
fn cancel_restores_theme_and_sets_flag() {
    let fixture = Fixture::empty();
    let mut harness = fixture.harness();
    wizard_to(&mut harness, "Next", Step::Gpg);
    wizard_to(&mut harness, "Skip", Step::Appearance);
    click_label(&mut harness, "Dark");
    assert_eq!(harness.ctx.options(|o| o.theme_preference), egui::ThemePreference::Dark);
    click_label(&mut harness, "Cancel");
    assert!(harness.state().dialogs.is_empty());
    assert_eq!(
        harness.ctx.options(|o| o.theme_preference),
        egui::ThemePreference::System
    );
    assert_eq!(harness.state().theme, "system");
    let db = fixture.db();
    assert_eq!(db.get_setting(THEME_SETTING).unwrap(), "");
    assert_eq!(db.get_setting(ONBOARDING_SETTING).unwrap(), "1");
}

#[test]
fn finish_writes_choices() {
    let fixture = Fixture::empty();
    let seals = tempfile::tempdir().unwrap();
    let mut harness = fixture.harness();
    wizard_to(&mut harness, "Next", Step::Gpg);
    wizard_to(&mut harness, "Skip", Step::Companion);
    click_label(&mut harness, "Use the AI companion");
    type_into(&mut harness, "Endpoint URL", "http://127.0.0.1:9/v1");
    type_into(&mut harness, "Model", "m");
    click_label(&mut harness, "OSINT research");
    wizard_to(&mut harness, "Next", Step::SealFolder);
    // the field starts with the folder in use
    if let Some(Dialog::Wizard(wizard)) = harness.state_mut().dialogs.last_mut() {
        wizard.seal_folder.clear();
    }
    type_into(&mut harness, "Seal folder", &seals.path().display().to_string());
    wizard_to(&mut harness, "Next", Step::Appearance);
    click_label(&mut harness, "Dark");
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    assert!(harness.state().dialogs.is_empty());
    let db = fixture.db();
    assert_eq!(db.get_setting(THEME_SETTING).unwrap(), "dark");
    assert_eq!(
        db.get_setting(SEAL_DIR_SETTING).unwrap(),
        seals.path().display().to_string()
    );
    assert_eq!(db.get_setting(ONBOARDING_SETTING).unwrap(), "1");
    let saved = Settings::load(&CompanionDb::open_for(&fixture.path).unwrap()).unwrap();
    assert_eq!((saved.preset, saved.model.as_str()), (Preset::Osint, "m"));
    assert!(saved.is_configured());
}

#[test]
fn wizard_requires_endpoint_and_model_for_the_companion() {
    let fixture = Fixture::empty();
    let mut harness = fixture.harness();
    wizard_to(&mut harness, "Next", Step::Gpg);
    wizard_to(&mut harness, "Skip", Step::Companion);
    click_label(&mut harness, "Use the AI companion");
    click_label(&mut harness, "Next");
    assert_eq!(wizard(&harness).step, Step::Companion);
    assert!(
        harness
            .query_by_label("Set the endpoint URL and the model, or don't use the companion.")
            .is_some()
    );
}

#[test]
fn wizard_prefills_and_keeps_companion_settings() {
    let fixture = Fixture::new();
    let cdb = CompanionDb::open_for(&fixture.path).unwrap();
    let before = Settings {
        endpoint_url: "http://127.0.0.1:1".into(),
        model: "m".into(),
        api_key: "secret".into(),
        preset: Preset::SourceCriticism,
        ..Settings::default()
    };
    before.save(&cdb).unwrap();
    let expected = Settings::load(&cdb).unwrap();
    let mut harness = fixture.harness();
    harness.state_mut().open_wizard();
    harness.run_ok();
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    let after = Settings::load(&cdb).unwrap();
    assert_eq!(after, expected);
    assert_eq!(
        (after.api_key.as_str(), after.preset),
        ("secret", Preset::SourceCriticism)
    );
}

#[test]
fn declining_the_companion_disables_an_existing_one() {
    let fixture = Fixture::new();
    let cdb = configure_companion(&fixture);
    let mut harness = fixture.harness();
    harness.state_mut().open_wizard();
    harness.run_ok();
    wizard_to(&mut harness, "Next", Step::Companion);
    click_label(&mut harness, "Don't use the AI companion");
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    assert!(!Settings::load(&cdb).unwrap().enabled);
}

#[test]
fn menu_opens_wizard() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.get_by_label("Settings").click();
    harness.run_ok();
    harness.get_by_label("Setup Wizard…").click();
    harness.run_ok();
    assert!(wizard_open(&harness));
    screenshot(&mut harness, "wizard");
}

#[test]
fn clearing_the_seal_folder_in_the_wizard_clears_the_setting() {
    let fixture = Fixture::new();
    let seals = tempfile::tempdir().unwrap();
    fixture
        .db()
        .set_setting(SEAL_DIR_SETTING, &seals.path().display().to_string())
        .unwrap();
    let mut harness = fixture.harness();
    harness.state_mut().open_wizard();
    harness.run_ok();
    wizard_to(&mut harness, "Next", Step::SealFolder);
    if let Some(Dialog::Wizard(wizard)) = harness.state_mut().dialogs.last_mut() {
        wizard.seal_folder.clear();
    }
    wizard_to(&mut harness, "Next", Step::Summary);
    assert!(harness.query_by_label_contains("(next to the database)").is_some());
    click_label(&mut harness, "Finish");
    assert_eq!(fixture.db().get_setting(SEAL_DIR_SETTING).unwrap(), "");
}

#[test]
fn the_note_header_wraps_instead_of_overlapping_at_the_smallest_window() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.set_size(egui::vec2(900.0, 560.0)); // the window's minimum size
    select_case(&mut harness);
    let note = harness
        .state()
        .view
        .items
        .iter()
        .find_map(|i| match i {
            Item::Note(c) => Some(c.entry.id),
            _ => None,
        })
        .unwrap();
    harness.state_mut().focused_card = Some(note); // its actions show
    harness.run_ok();
    screenshot(&mut harness, "smallest-window");
    // the left part of each header (timestamps, chip) never runs under the right part (mark, actions)
    let left: Vec<egui::Rect> = harness
        .query_all_by_label_contains(" UTC")
        .chain(harness.query_all_by_label_contains("2026-"))
        .chain(harness.query_all_by_label("Show 1 earlier version"))
        .map(|node| node.rect())
        .collect();
    assert!(left.len() >= 3);
    let right_side = harness
        .query_all_by_label("Not signed")
        .chain(harness.query_all_by_label("More"))
        .chain(harness.query_all_by_label("Correct"))
        .chain(harness.query_all_by_label("Pin"));
    for node in right_side {
        for rect in &left {
            assert!(!node.rect().intersects(*rect), "{:?} overlaps {rect:?}", node.rect());
        }
    }
}

#[test]
fn the_log_is_a_centred_column_on_a_wide_screen() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.set_size(egui::vec2(1920.0, 1080.0));
    select_case(&mut harness);
    harness.run_ok();
    screenshot(&mut harness, "wide-window");
    let editor = harness.get_by_role(egui::accesskit::Role::MultilineTextInput).rect();
    let app = harness.state();
    let middle = (app.tree_width + (1920.0 - app.side_width)) / 2.0;
    assert!(editor.width() <= theme::MAX_CARD_WIDTH + 1.0, "{editor:?}");
    assert!((editor.center().x - middle).abs() < 20.0, "{editor:?} {middle}");
}

#[test]
fn a_database_without_cases_shows_how_to_create_one() {
    let fixture = Fixture::empty();
    fixture.db().set_setting(ONBOARDING_SETTING, "1").unwrap();
    let mut harness = fixture.harness();
    screenshot(&mut harness, "no-cases");
    // no note input without a case
    assert!(
        harness
            .query_by_role(egui::accesskit::Role::MultilineTextInput)
            .is_none()
    );
    harness.get_by_label(&format!("{}  New case", icons::PLUS)).click();
    harness.run_ok();
    assert!(matches!(harness.state().dialogs.last(), Some(Dialog::NewCase { .. })));
}

#[test]
fn a_notes_actions_show_under_the_pointer() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    harness.get_by_label("first note, corrected #tag 10.0.0.1").hover();
    harness.run_ok();
    screenshot(&mut harness, "note-hovered");
    harness.get_by_label("Correct").click();
    harness.run_ok();
    assert!(matches!(harness.state().dialogs.last(), Some(Dialog::Correct { .. })));
}

#[test]
fn a_label_is_completed_from_the_tags_in_use() {
    let fixture = Fixture::new();
    let (case_id, versions) = first_note_versions(&fixture);
    {
        let db = fixture.db();
        let signer = FakeSigner::new(false);
        Factum::with_seal_dir(&db, &signer, None)
            .create_note("second note #malware", None, case_id)
            .unwrap();
    }
    let note = versions[1];
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let ctx = harness.ctx.clone();
    harness.state_mut().handle_card_action(CardAction::AddLabel(note), &ctx);
    harness.run_ok();
    // the note's own #tag is not offered
    assert!(
        matches!(harness.state().dialogs.last(), Some(Dialog::AddLabel { known, .. })
        if known.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>() == ["malware"])
    );
    // a typo still finds it; ↓ and Enter take it
    type_into(&mut harness, "Label", "mlaware");
    let option = egui::accesskit::Role::ListBoxOption;
    assert!(harness.query_by_role_and_label(option, "malware").is_some());
    screenshot(&mut harness, "label-suggestions");
    harness.key_press(egui::Key::ArrowDown);
    harness.run_ok();
    harness.key_press(egui::Key::Enter);
    harness.run_ok();
    assert!(harness.state().dialogs.is_empty());
    let tags = crate::tags::get_tags_for_entry(&fixture.db().conn, note).unwrap();
    assert!(tags.contains(&("malware".to_string(), "label".to_string())), "{tags:?}");
}

#[test]
fn a_clicked_suggestion_is_added() {
    let fixture = Fixture::new();
    let (case_id, versions) = first_note_versions(&fixture);
    {
        let db = fixture.db();
        let signer = FakeSigner::new(false);
        Factum::with_seal_dir(&db, &signer, None)
            .create_note("second note #review", None, case_id)
            .unwrap();
    }
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let ctx = harness.ctx.clone();
    harness
        .state_mut()
        .handle_card_action(CardAction::AddLabel(versions[1]), &ctx);
    harness.run_ok();
    type_into(&mut harness, "Label", "rev");
    harness
        .get_by_role_and_label(egui::accesskit::Role::ListBoxOption, "review")
        .click();
    harness.run_ok();
    let tags = crate::tags::get_tags_for_entry(&fixture.db().conn, versions[1]).unwrap();
    assert!(tags.contains(&("review".to_string(), "label".to_string())), "{tags:?}");
}

/// The fixture plus #malware on two notes, #mailbox on one, and a label that cannot be written as a #tag.
fn tagged_fixture() -> Fixture {
    let fixture = Fixture::new();
    let (case_id, _) = first_note_versions(&fixture);
    let db = fixture.db();
    let signer = FakeSigner::new(false);
    let factum = Factum::with_seal_dir(&db, &signer, None);
    factum.create_note("#malware #mailbox", None, case_id).unwrap();
    factum.create_note("#malware", None, case_id).unwrap();
    let labelled = factum.create_note("plain", None, case_id).unwrap();
    crate::tags::add_label(&db, labelled, "mal-report").unwrap();
    fixture
}

fn type_into_composer(harness: &mut Harness<'_, FactumApp>, text: &str) {
    let input = egui::accesskit::Role::MultilineTextInput;
    harness.get_by_role(input).focus();
    harness.run_ok();
    harness.get_by_role(input).type_text(text);
    harness.run_ok();
}

#[test]
fn a_tag_is_completed_in_the_composer() {
    let fixture = tagged_fixture();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    type_into_composer(&mut harness, "found #ma");
    let option = egui::accesskit::Role::ListBoxOption;
    assert!(harness.query_by_role_and_label(option, "malware").is_some());
    assert!(harness.query_by_role_and_label(option, "mailbox").is_some());
    // "mal-report" would be read as #mal
    assert!(harness.query_by_role_and_label(option, "mal-report").is_none());
    screenshot(&mut harness, "tag-suggestions");
    // the most used is on top; ↓ moves to the next, Tab takes it and the note field keeps the focus
    harness.key_press(egui::Key::ArrowDown);
    harness.run_ok();
    harness.key_press(egui::Key::Tab);
    harness.run_ok();
    assert_eq!(harness.state().composer, "found #mailbox ");
    assert!(harness.query_by_role_and_label(option, "malware").is_none());
    assert!(
        harness
            .get_by_role(egui::accesskit::Role::MultilineTextInput)
            .is_focused()
    );
}

#[test]
fn escape_closes_the_tag_list_and_enter_still_breaks_the_line() {
    let fixture = tagged_fixture();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    type_into_composer(&mut harness, "#ma");
    let option = egui::accesskit::Role::ListBoxOption;
    harness.key_press(egui::Key::Escape);
    harness.run_ok();
    assert!(harness.query_by_role_and_label(option, "malware").is_none());
    // the field keeps the focus; typing on brings the list back
    harness
        .get_by_role(egui::accesskit::Role::MultilineTextInput)
        .type_text("l");
    harness.run_ok();
    assert!(harness.query_by_role_and_label(option, "malware").is_some());
    harness.key_press(egui::Key::Enter);
    harness.run_ok();
    assert_eq!(harness.state().composer, "#mal\n");
}

#[test]
fn a_clicked_tag_is_completed() {
    let fixture = tagged_fixture();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    type_into_composer(&mut harness, "#mai");
    harness
        .get_by_role_and_label(egui::accesskit::Role::ListBoxOption, "mailbox")
        .click();
    harness.run_ok();
    assert_eq!(harness.state().composer, "#mailbox ");
    assert!(
        harness
            .get_by_role(egui::accesskit::Role::MultilineTextInput)
            .is_focused()
    );
}

#[test]
fn enter_creates_the_case() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.state_mut().open_new_case();
    harness.run_ok();
    type_into(&mut harness, "File number", "C-2");
    harness.key_press(egui::Key::Enter);
    harness.run_ok();
    assert!(harness.state().dialogs.is_empty());
    assert_eq!(harness.state().factum().list_cases(false).unwrap().len(), 2);
}

#[test]
fn a_key_is_chosen_by_clicking_its_row() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    let key = |n: u8, name: &str, validity: &str| crate::signer::GpgKey {
        keyid: format!("{:016X}", 0xA1B2_C3D4_0000_0000u64 + n as u64),
        fingerprint: format!("{:040X}", 0x1234_5678_9ABC_DEF0u64 + n as u64),
        uids: vec![format!(
            "{name} <{}@example.org>",
            name.to_lowercase().replace(' ', ".")
        )],
        cap: "scSC".into(),
        algorithm: "ed25519".into(),
        created: "2025-03-01".into(),
        expires: if validity == "e" {
            "2026-01-01".into()
        } else {
            String::new()
        },
        validity: validity.into(),
    };
    let keys = vec![
        key(1, "Ana Analyst", "u"),
        key(2, "Lab Signing", "u"),
        key(3, "Old Key", "e"),
        key(4, "Field Team", "u"),
        key(5, "Backup", "u"),
    ];
    let first = keys[0].keyid.clone();
    harness.state_mut().dialogs.push(Dialog::GpgKeys {
        keys,
        selected: Some(first),
    });
    harness.run_ok();
    screenshot(&mut harness, "signing-keys");
    let row = egui::accesskit::Role::RadioButton;
    harness
        .get_by_role_and_label(row, "Lab Signing <lab.signing@example.org>")
        .click();
    harness.run_ok();
    match harness.state().dialogs.last() {
        Some(Dialog::GpgKeys { selected, .. }) => assert_eq!(selected.as_deref(), Some("A1B2C3D400000002")),
        _ => panic!("the key dialog closed"),
    }
}

#[test]
fn the_wizard_shows_the_seal_folder_in_use() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.state_mut().open_wizard();
    harness.run_ok();
    wizard_to(&mut harness, "Next", Step::SealFolder);
    let default = harness.state().factum().default_seal_dir().display().to_string();
    assert_eq!(wizard(&harness).seal_folder, default);
    screenshot(&mut harness, "wizard-seal-folder");
    // the default may not exist yet, and leaving it writes no setting
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    assert_eq!(fixture.db().get_setting(SEAL_DIR_SETTING).unwrap(), "");
}

#[test]
fn without_signing_the_wizard_leaves_out_key_and_seal_folder() {
    let fixture = Fixture::empty();
    let mut harness = fixture.harness();
    screenshot(&mut harness, "wizard-welcome");
    click_label(&mut harness, "Not now: skip signing and seals");
    assert!(harness.query_by_label_contains("Signing key").is_none());
    click_label(&mut harness, "Next");
    assert_eq!(wizard(&harness).step, Step::Companion);
    wizard_to(&mut harness, "Next", Step::Appearance);
    click_label(&mut harness, "Back");
    assert_eq!(wizard(&harness).step, Step::Companion);
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    let db = fixture.db();
    assert_eq!(db.get_setting(ACTIVE_KEY_SETTING).unwrap(), "");
    assert_eq!(db.get_setting(SEAL_DIR_SETTING).unwrap(), "");
    assert_eq!(db.get_setting(ONBOARDING_SETTING).unwrap(), "1");
}

// --- evidence containers

impl Fixture {
    /// The usual case, plus an open container "FS01 preserved" with two files; returns its id and file.
    fn with_container() -> (Self, i64, PathBuf) {
        use crate::container::volume::{AddOptions, AddProgress};
        let fixture = Self::new();
        let db = fixture.db();
        let signer = FakeSigner::new(false);
        let factum = Factum::with_seal_dir(&db, &signer, None);
        let case_id = factum.list_cases(false).unwrap()[0];
        let source = fixture._dir.path().join("mnt");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("evil.exe"), b"MZ").unwrap();
        std::fs::write(source.join("notes.txt"), b"notes").unwrap();
        let path = fixture._dir.path().join("fs01.aff4l");
        let id = factum
            .create_container(case_id, "FS01 preserved", None, &path, &source.display().to_string())
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
        factum.commit_container_add(id, &mut volume, staged).unwrap();
        (fixture, id, path)
    }
}

fn close_container(fixture: &Fixture, id: i64) {
    let db = fixture.db();
    let signer = FakeSigner::new(false);
    Factum::with_seal_dir(&db, &signer, None).close_container(id).unwrap();
}

#[test]
fn tree_lists_container_with_count_and_state() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    let node = &harness.state().view.tree[0];
    assert_eq!(node.containers.len(), 1);
    assert_eq!((node.containers[0].id, node.containers[0].file_count), (id, 2));
    assert!(harness.query_by_label_contains("FS01 preserved · open").is_some());
    close_container(&fixture, id);
    harness.state_mut().dirty = true;
    harness.run_ok();
    assert!(harness.query_by_label_contains("FS01 preserved").is_some());
    assert!(harness.query_by_label_contains("FS01 preserved · open").is_none());
}

#[test]
fn selecting_container_shows_its_files() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    harness.state_mut().select_container(id);
    harness.run_ok();
    let app = harness.state();
    assert_eq!(app.container_id, Some(id));
    assert!(app.case_id.is_some(), "the case of the container is the current case");
    assert!(app.view.items.is_empty());
    assert_eq!(app.view.container.as_ref().map(|c| c.summary.id), Some(id));
    assert!(harness.query_by_label("evil.exe").is_some());
    assert!(harness.query_by_label("notes.txt").is_some());
    screenshot(&mut harness, "container_view");
    // selecting the case again leaves the container
    let case_id = harness.state().case_id;
    harness.state_mut().select(case_id, None);
    harness.run_ok();
    assert!(harness.state().container_id.is_none());
    assert!(harness.state().view.container.is_none());
}

#[test]
fn jump_to_entry_leaves_the_container_view() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    harness.state_mut().select_container(id);
    harness.run_ok();
    harness.state_mut().jump_to_entry(id);
    harness.run_ok();
    assert!(harness.state().container_id.is_none());
    assert!(harness.state().view.items.iter().any(|i| i.entry().id == id));
}

#[test]
fn missing_file_is_marked_and_locate_enabled() {
    let (fixture, id, path) = Fixture::with_container();
    std::fs::remove_file(&path).unwrap();
    let mut harness = fixture.harness();
    harness.run_ok();
    let summary = harness.state().view.tree[0].containers[0].clone();
    assert!(summary.missing);
    assert!(harness.query_by_label("File missing").is_some());
    let items = containers::menu_items(&summary, false, false);
    let enabled = |label: &str| items.iter().find(|(l, _, _)| *l == label).unwrap().2;
    assert!(enabled("Locate…"));
    assert!(!enabled("Add Files…") && !enabled("Show in Folder") && !enabled("Verify Container…"));
    let _ = id;
}

#[test]
fn add_disabled_while_closed() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    let summary = harness.state().view.tree[0].containers[0].clone();
    let items = containers::menu_items(&summary, false, false);
    let enabled =
        |items: &[(&str, ContainerAction, bool)], label: &str| items.iter().find(|(l, _, _)| *l == label).unwrap().2;
    assert!(enabled(&items, "Add Files…") && enabled(&items, "Close Container"));
    assert!(!enabled(&items, "Reopen Container") && !enabled(&items, "Locate…"));
    close_container(&fixture, id);
    harness.state_mut().dirty = true;
    harness.run_ok();
    let summary = harness.state().view.tree[0].containers[0].clone();
    let items = containers::menu_items(&summary, false, false);
    assert!(!enabled(&items, "Add Files…") && !enabled(&items, "Add Folder…") && !enabled(&items, "Close Container"));
    assert!(enabled(&items, "Reopen Container"));
    // an archived case takes nothing and reopens nothing
    let items = containers::menu_items(&summary, true, false);
    assert!(!enabled(&items, "Reopen Container") && enabled(&items, "Verify Container…"));
}

#[test]
fn locate_accepts_the_moved_file() {
    let (fixture, id, path) = Fixture::with_container();
    let moved = fixture._dir.path().join("moved.aff4l");
    std::fs::rename(&path, &moved).unwrap();
    let mut harness = fixture.harness();
    harness.state_mut().locate_container(id, &moved);
    harness.run_ok();
    assert!(!harness.state().view.tree[0].containers[0].missing);
    assert!(harness.state().dialogs.is_empty());
    // another file is refused with a message
    std::fs::write(fixture._dir.path().join("x.aff4l"), b"no").unwrap();
    harness
        .state_mut()
        .locate_container(id, &fixture._dir.path().join("x.aff4l"));
    harness.run_ok();
    assert!(matches!(harness.state().dialogs.last(), Some(Dialog::Message { .. })));
}

#[test]
fn new_container_dialog_creates_file_and_selects_it() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let case_id = harness.state().case_id.unwrap();
    harness.state_mut().open_new_container(case_id);
    harness.run_ok();
    let folder = fixture._dir.path().to_path_buf();
    if let Some(Dialog::NewContainer {
        folder: field, base, ..
    }) = harness.state_mut().dialogs.last_mut()
    {
        *field = folder.display().to_string();
        *base = folder.display().to_string();
    } else {
        panic!("the New Container dialog is not open");
    }
    type_into(&mut harness, "Name", "FS01 preserved");
    screenshot(&mut harness, "new_container_dialog");
    click_label(&mut harness, "Create");
    let path = folder.join("FS01-preserved.aff4l");
    assert!(path.is_file());
    let app = harness.state();
    let id = app.container_id.expect("the new container is selected");
    assert_eq!(
        app.factum().container(id).unwrap().summary.path.as_deref(),
        Some(path.as_path())
    );
}

#[test]
fn new_container_dialog_validates() {
    let (fixture, _, path) = Fixture::with_container();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let case_id = harness.state().case_id.unwrap();
    harness.state_mut().open_new_container(case_id);
    harness.run_ok();
    click_label(&mut harness, "Create");
    assert!(harness.query_by_label("A container name is required.").is_some());
    // an existing file is not overwritten
    if let Some(Dialog::NewContainer {
        name,
        folder,
        file_name,
        base,
        ..
    }) = harness.state_mut().dialogs.last_mut()
    {
        *name = "Again".into();
        *folder = path.parent().unwrap().display().to_string();
        *file_name = "fs01.aff4l".into();
        *base = "/".into();
    }
    harness.run_ok();
    click_label(&mut harness, "Create");
    assert!(harness.query_by_label_contains("exists already").is_some());
}

#[test]
fn add_runs_in_background_and_commits() {
    let (fixture, id, _) = Fixture::with_container();
    let more = fixture._dir.path().join("mnt/more");
    std::fs::create_dir_all(&more).unwrap();
    for name in ["1", "2", "3"] {
        std::fs::write(more.join(name), name.repeat(10)).unwrap();
    }
    let mut harness = fixture.harness();
    harness.state_mut().select_container(id);
    harness.state_mut().open_add_to_container(id, vec![more.clone()]);
    harness.run_ok();
    screenshot(&mut harness, "add_to_container_dialog");
    click_label(&mut harness, "Add");
    run_until(&mut harness, |h| h.state().add_job.is_none());
    let detail = harness.state().factum().container(id).unwrap();
    assert_eq!(detail.adds.len(), 2);
    assert_eq!(detail.adds[1].files.len(), 3);
    assert!(harness.query_by_label_contains("Adding to").is_none());
    assert!(harness.query_by_label_contains("3 files added (30 B).").is_some());
}

#[test]
fn cancel_adds_nothing() {
    let (fixture, id, path) = Fixture::with_container();
    let before = std::fs::read(&path).unwrap();
    let mut harness = fixture.harness();
    let source = fixture._dir.path().join("mnt");
    let options = crate::container::volume::AddOptions {
        base: source.clone(),
        keep_path: true,
        metadata_only: false,
        excerpt: None,
    };
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    harness.state_mut().start_add(id, vec![source], options, cancel);
    run_until(&mut harness, |h| h.state().add_job.is_none());
    assert_eq!(harness.state().factum().container(id).unwrap().adds.len(), 1);
    assert!(harness.query_by_label_contains("Nothing was added.").is_some());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn add_status_line() {
    let progress = crate::container::volume::AddProgress::default();
    use std::sync::atomic::Ordering::Relaxed;
    progress.files.store(1, Relaxed);
    progress.total_files.store(3, Relaxed);
    progress.bytes.store(2_000, Relaxed);
    progress.total_bytes.store(7_000_000, Relaxed);
    assert_eq!(
        containers::add_status(&progress, "FS01"),
        "Adding to \"FS01\": 1 / 3 files · 2.0 kB / 7.0 MB"
    );
}

#[test]
fn archive_with_open_container_asks_to_close() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    select_case(&mut harness);
    let case_id = harness.state().case_id.unwrap();
    harness.state_mut().archive(case_id);
    harness.run_ok();
    match harness.state().dialogs.last() {
        Some(Dialog::Confirm {
            message,
            then: Pending::CloseContainersAndArchive(_),
        }) => assert!(
            message.contains(&format!("#{id} \"FS01 preserved\" is open")),
            "{message}"
        ),
        _ => panic!("no confirmation"),
    }
    click_label(&mut harness, "Close and Archive");
    let factum = harness.state().factum();
    assert!(!factum.container(id).unwrap().summary.open);
    assert!(factum.get_case(case_id).unwrap().unwrap().is_archived());
}

#[test]
fn close_and_reopen_from_the_menu() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    let ctx = harness.ctx.clone();
    harness.state_mut().container_action(ContainerAction::Close(id), &ctx);
    harness.run_ok();
    assert!(!harness.state().factum().container(id).unwrap().summary.open);
    harness.state_mut().container_action(ContainerAction::Reopen(id), &ctx);
    harness.run_ok();
    assert!(harness.state().factum().container(id).unwrap().summary.open);
}

#[test]
fn verify_container_opens_report_window() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    let ctx = harness.ctx.clone();
    harness.state_mut().container_action(ContainerAction::Verify(id), &ctx);
    run_until(&mut harness, |h| !h.state().container_verify_windows.is_empty());
    harness.run_ok();
    assert!(
        harness
            .query_all_by_label("Verify Container FS01 preserved")
            .next()
            .is_some()
    );
    // open and never closed: nothing fails, but nothing is signed either
    assert!(harness.query_by_label_contains("\u{26a0} 1 warning").is_some());
    assert!(harness.query_by_label_contains("never closed").is_some());
    screenshot(&mut harness, "verify_container");
}

fn x509_cert(fingerprint: &str, subject: &str) -> crate::container::x509::X509Cert {
    crate::container::x509::X509Cert {
        fingerprint: fingerprint.into(),
        subject: subject.into(),
        issuer: "CN=Root".into(),
        issuer_fingerprint: "R".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2027-01-01T00:00:00Z".into(),
        can_sign: true,
        has_secret: true,
    }
}

#[test]
fn x509_dialog_without_gpgsm_says_so() {
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.state_mut().dialogs.push(Dialog::X509 {
        available: false,
        certs: Vec::new(),
        selected: None,
        chain_files: Vec::new(),
    });
    harness.run_ok();
    assert!(harness.query_by_label_contains("gpgsm is not installed").is_some());
}

#[test]
fn x509_result_saves_and_clears_settings() {
    use crate::container::x509::{X509_CERT_SETTING, X509_CHAIN_SETTING};
    let fixture = Fixture::new();
    let mut harness = fixture.harness();
    harness.state_mut().dialogs.push(Dialog::X509 {
        available: true,
        certs: vec![x509_cert("ABC", "CN=Examiner One")],
        selected: None,
        chain_files: vec!["/certs/intermediate.pem".into()],
    });
    harness.run_ok();
    click_label(&mut harness, "CN=Examiner One");
    click_label(&mut harness, "Save");
    let db = fixture.db();
    assert_eq!(db.get_setting(X509_CERT_SETTING).unwrap(), "ABC");
    assert_eq!(db.get_setting(X509_CHAIN_SETTING).unwrap(), "/certs/intermediate.pem");
    let ctx = harness.ctx.clone();
    harness.state_mut().handle_dialog_result(
        DialogResult::X509 {
            certificate: None,
            chain_files: Vec::new(),
        },
        &ctx,
    );
    let db = fixture.db();
    assert_eq!(db.get_setting(X509_CERT_SETTING).unwrap(), "");
    assert_eq!(db.get_setting(X509_CHAIN_SETTING).unwrap(), "");
}

fn with_wizard_certs(harness: &mut Harness<'_, FactumApp>, certs: Vec<crate::container::x509::X509Cert>) {
    if let Some(Dialog::Wizard(wizard)) = harness.state_mut().dialogs.last_mut() {
        wizard.x509_certs = certs;
    }
    harness.run_ok();
}

#[test]
fn wizard_hides_x509_without_certificates() {
    let fixture = Fixture::empty();
    let mut harness = fixture.harness();
    with_wizard_certs(&mut harness, Vec::new());
    wizard_to(&mut harness, "Next", Step::Gpg);
    assert!(harness.query_by_label("X.509 certificate (optional)").is_none());
    wizard_to(&mut harness, "Next", Step::Summary);
    assert!(harness.query_by_label("X.509 certificate").is_none());
}

#[test]
fn wizard_x509_choice_applied_on_finish() {
    use crate::container::x509::X509_CERT_SETTING;
    let fixture = Fixture::empty();
    let mut harness = fixture.harness();
    with_wizard_certs(&mut harness, vec![x509_cert("ABC", "CN=Examiner One")]);
    wizard_to(&mut harness, "Next", Step::Gpg);
    assert!(harness.query_by_label("X.509 certificate (optional)").is_some());
    click_label(&mut harness, "CN=Examiner One");
    screenshot(&mut harness, "wizard_x509");
    wizard_to(&mut harness, "Next", Step::Summary);
    assert!(harness.query_by_label("CN=Examiner One").is_some());
    click_label(&mut harness, "Finish");
    assert_eq!(fixture.db().get_setting(X509_CERT_SETTING).unwrap(), "ABC");
}

#[test]
fn wizard_prefills_and_keeps_x509() {
    use crate::container::x509::{X509_CERT_SETTING, X509_CHAIN_SETTING};
    let fixture = Fixture::new();
    let db = fixture.db();
    db.set_setting(X509_CERT_SETTING, "ABC").unwrap();
    db.set_setting(X509_CHAIN_SETTING, "/certs/root.pem").unwrap();
    let mut harness = fixture.harness();
    harness.state_mut().open_wizard();
    harness.run_ok();
    with_wizard_certs(&mut harness, vec![x509_cert("ABC", "CN=Examiner One")]);
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    let db = fixture.db();
    assert_eq!(db.get_setting(X509_CERT_SETTING).unwrap(), "ABC");
    assert_eq!(db.get_setting(X509_CHAIN_SETTING).unwrap(), "/certs/root.pem");
}

#[test]
fn not_now_leaves_x509_unchanged() {
    use crate::container::x509::X509_CERT_SETTING;
    let fixture = Fixture::empty();
    fixture.db().set_setting(X509_CERT_SETTING, "ABC").unwrap();
    let mut harness = fixture.harness();
    with_wizard_certs(&mut harness, vec![x509_cert("XYZ", "CN=Other")]);
    click_label(&mut harness, "Not now: skip signing and seals");
    wizard_to(&mut harness, "Next", Step::Summary);
    click_label(&mut harness, "Finish");
    assert_eq!(fixture.db().get_setting(X509_CERT_SETTING).unwrap(), "ABC");
}

#[test]
fn container_view_shows_modified_times() {
    let (fixture, id, _) = Fixture::with_container();
    let source = fixture._dir.path().join("mnt/evil.exe");
    let modified = crate::container::source::xsd_time(std::fs::metadata(&source).unwrap().modified().unwrap());
    let mut harness = fixture.harness();
    harness.state_mut().select_container(id);
    harness.run_ok();
    assert_eq!(harness.state().view.container_times.len(), 2);
    let shown = containers::short_time(&modified);
    assert!(shown.ends_with(" UTC") && shown.as_bytes()[10] == b' ', "{shown}");
    assert!(harness.query_all_by_label(&shown).next().is_some(), "{shown}");
}

/// An addition to container `id` that is still running (its worker waits).
fn running_add_job(harness: &mut Harness<'_, FactumApp>, id: i64) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wait = release.clone();
    let ctx = harness.ctx.clone();
    let worker = workers::Worker::spawn(&ctx, move || {
        while !wait.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(10));
        }
        Err("cancelled — nothing was added".to_string())
    });
    harness.state_mut().add_job = Some(AddJob {
        container_id: id,
        name: "FS01 preserved".into(),
        worker,
        progress: Default::default(),
        cancel: Default::default(),
    });
    release
}

#[test]
fn a_running_addition_blocks_its_container() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    let summary = harness.state().view.tree[0].containers[0].clone();
    let items = containers::menu_items(&summary, false, true);
    let enabled = |label: &str| items.iter().find(|(l, _, _)| *l == label).unwrap().2;
    assert!(!enabled("Add Files…") && !enabled("Close Container") && !enabled("Reopen Container"));
    assert!(enabled("Verify Container…"));
    let release = running_add_job(&mut harness, id);
    let ctx = harness.ctx.clone();
    let started = std::time::Instant::now();
    harness.state_mut().container_action(ContainerAction::Close(id), &ctx);
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(harness.state().factum().container(id).unwrap().summary.open);
    let case_id = harness.state().factum().list_cases(false).unwrap()[0];
    harness.state_mut().archive(case_id);
    harness.run_ok();
    assert!(harness.query_by_label_contains("being added").is_some());
    release.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn verify_container_can_be_cancelled() {
    let (fixture, _, path) = Fixture::with_container();
    let mut harness = fixture.harness();
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    harness.state_mut().start_container_verification(path, cancel);
    run_until(&mut harness, |h| h.state().container_verify_job.is_none());
    harness.run_ok();
    assert!(harness.state().container_verify_windows.is_empty());
    assert!(harness.query_by_label("Verification cancelled.").is_some());
}

#[test]
fn add_dialog_needs_a_base_path() {
    let (fixture, id, _) = Fixture::with_container();
    let mut harness = fixture.harness();
    let source = fixture._dir.path().join("mnt/evil.exe");
    harness.state_mut().open_add_to_container(id, vec![source]);
    if let Some(Dialog::AddToContainer { base, .. }) = harness.state_mut().dialogs.last_mut() {
        base.clear();
    }
    harness.run_ok();
    click_label(&mut harness, "Add");
    assert!(harness.state().add_job.is_none());
    assert!(harness.query_by_label_contains("Choose the base path").is_some());
}
