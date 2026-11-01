#![cfg(feature = "gui")]

mod common;

use std::time::{Duration, Instant};

use common::fake_llm::{FakeLlm, FakeRequest, anthropic_models, openai_chat, openai_models};
use common::{Fixture, add_case_row};
use factum::companion::thread::{Command, CompanionHandle, State, Status};
use factum::companion::{CompanionDb, Protocol, Settings, companion_db_path};
use serde_json::json;

fn settings(endpoint_url: &str) -> Settings {
    Settings {
        endpoint_url: endpoint_url.into(),
        protocol: Protocol::OpenAi,
        api_key: "k".into(),
        api_key_from_env: false,
        user_agent: "factum-test".into(),
        extra_headers: String::new(),
        model: "m".into(),
        context_window: Some(32000),
        preset: factum::companion::Preset::Forensics,
        global_guideline: String::new(),
        enabled: true,
    }
}

fn configure(f: &Fixture, endpoint_url: &str) {
    settings(endpoint_url)
        .save(&CompanionDb::open_for(&f.db.path).unwrap())
        .unwrap();
}

fn start(f: &Fixture) -> CompanionHandle {
    CompanionHandle::start(
        egui::Context::default(),
        f.db.path.clone(),
        companion_db_path(&f.db.path),
    )
}

/// Polls the status until `done` holds or the timeout passes.
fn wait_for(handle: &CompanionHandle, timeout: Duration, done: impl Fn(&Status) -> bool) -> Status {
    let start = Instant::now();
    loop {
        let status = handle.status();
        if done(&status) || start.elapsed() > timeout {
            return status;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The model calls the endpoint saw.
fn chats(fake: &FakeLlm) -> Vec<FakeRequest> {
    fake.requests().into_iter().filter(|r| r.method == "POST").collect()
}

/// Polls until the endpoint has seen `n` model calls.
fn wait_for_chats(fake: &FakeLlm, n: usize) {
    let start = Instant::now();
    while chats(fake).len() < n && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(chats(fake).len() >= n, "{} of {n} model calls", chats(fake).len());
}

/// A case of `notes` notes, numbered from 1.
fn case_with_notes(f: &Fixture, notes: usize) -> i64 {
    let factum = f.factum();
    let case = factum.create_case("C-12", "Webserver", "Defaced web site").unwrap();
    for n in 1..=notes {
        factum.create_note(&format!("Finding {n:02}"), None, case).unwrap();
    }
    case
}

fn last_pass_status(f: &Fixture, case: i64) -> String {
    CompanionDb::open_for(&f.db.path)
        .unwrap()
        .conn
        .query_row(
            "SELECT status FROM passes WHERE case_id = ? ORDER BY id DESC LIMIT 1",
            [case],
            |row| row.get(0),
        )
        .unwrap()
}

/// The endpoint's answers for the first pass of a case of 25 notes (the newest 20 are enriched before it, in two
/// calls).
fn script_first_pass(fake: &FakeLlm) {
    fake.push(200, &openai_models(&["m"]));
    for _ in 0..2 {
        fake.push(200, &openai_chat("[]", "stop", 100));
    }
    fake.push(200, &openai_chat("Nothing stands out.", "stop", 100));
    fake.push(200, &openai_chat(r#"{"questions":[]}"#, "stop", 100));
}

/// Starts the thread and gives it the selected case's `Rethink`.
fn rethink(f: &Fixture, case: i64) -> CompanionHandle {
    let handle = start(f);
    wait_for(&handle, Duration::from_secs(5), |s| s.state == State::Idle);
    handle.send(Command::Selected(Some(case)));
    handle.send(Command::Rethink(case));
    handle
}

#[test]
fn selecting_a_new_case_sends_nothing_in_the_quiet_period() {
    let f = Fixture::new();
    let case = case_with_notes(&f, 3);
    let fake = FakeLlm::start();
    configure(&f, &format!("{}/v1", fake.url));
    let handle = start(&f);
    let status = wait_for(&handle, Duration::from_secs(5), |s| s.state == State::Idle);
    assert_eq!(status.state, State::Idle);
    handle.send(Command::Selected(Some(case)));
    // several ticks of the thread, each of which would have run a backlog batch
    std::thread::sleep(Duration::from_millis(3500));
    assert_eq!(chats(&fake).len(), 0);
    assert_eq!(handle.status().state, State::Idle);
    handle.shutdown();
}

#[test]
fn a_selected_case_whose_passes_all_failed_gets_no_backlog() {
    let f = Fixture::new();
    let case = case_with_notes(&f, 3);
    let fake = FakeLlm::start();
    configure(&f, &format!("{}/v1", fake.url));
    fake.push(200, &openai_models(&["m"]));
    for _ in 0..2 {
        fake.push(404, r#"{"error":{"message":"no such model"}}"#);
    }
    let handle = rethink(&f, case);
    let status = wait_for(&handle, Duration::from_secs(5), |s| matches!(s.state, State::Failed(_)));
    assert!(matches!(status.state, State::Failed(_)), "{status:?}");
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(chats(&fake).len(), 2, "enrichment and the reasoning, no backlog");
    handle.shutdown();
}

#[test]
fn the_backlog_follows_the_first_pass_oldest_last() {
    let f = Fixture::new();
    let case = case_with_notes(&f, 25);
    let fake = FakeLlm::start();
    configure(&f, &format!("{}/v1", fake.url));
    script_first_pass(&fake);
    for _ in 0..3 {
        fake.push(200, &openai_chat("[]", "stop", 100));
    }
    let handle = rethink(&f, case);
    wait_for_chats(&fake, 7);
    let calls = chats(&fake);
    assert!(calls[6].body.contains("Finding 01"), "{}", calls[6].body);
    handle.shutdown();
}

/// A case of three notes with its pass in the enrichment call, which takes its time.
fn pass_in_flight(f: &Fixture, fake: &FakeLlm) -> (i64, CompanionHandle) {
    let case = case_with_notes(f, 3);
    configure(f, &format!("{}/v1", fake.url));
    fake.push(200, &openai_models(&["m"]));
    fake.push_delayed(200, &openai_chat("[]", "stop", 100), Duration::from_millis(600));
    let handle = start(f);
    wait_for(&handle, Duration::from_secs(5), |s| s.state == State::Idle);
    handle.send(Command::Rethink(case));
    wait_for_chats(fake, 1);
    (case, handle)
}

#[test]
fn opting_out_ends_a_running_pass() {
    let f = Fixture::new();
    let fake = FakeLlm::start();
    let (case, handle) = pass_in_flight(&f, &fake);
    CompanionDb::open_for(&f.db.path)
        .unwrap()
        .set_case_enabled(case, false)
        .unwrap();
    handle.send(Command::CaseToggled(case));
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(chats(&fake).len(), 1);
    assert_eq!(handle.status().state, State::Idle);
    handle.shutdown();
    assert_eq!(last_pass_status(&f, case), "skipped");
}

#[test]
fn deleting_a_case_ends_a_running_pass() {
    let f = Fixture::new();
    let fake = FakeLlm::start();
    let (case, handle) = pass_in_flight(&f, &fake);
    handle.send(Command::CaseDeleted(case));
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(chats(&fake).len(), 1);
    handle.shutdown();
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    assert!(cdb.case_settings(case).unwrap().is_none());
}

#[test]
fn a_settings_change_ends_a_running_pass_and_probes_again() {
    let f = Fixture::new();
    let fake = FakeLlm::start();
    let (case, handle) = pass_in_flight(&f, &fake);
    handle.send(Command::SettingsChanged);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(chats(&fake).len(), 1);
    assert_eq!(fake.requests().iter().filter(|r| r.method == "GET").count(), 2);
    assert_eq!(handle.status().state, State::Idle);
    handle.shutdown();
    assert_eq!(last_pass_status(&f, case), "skipped");
}

#[test]
fn shutdown_does_not_wait_for_the_rest_of_a_pass() {
    let f = Fixture::new();
    let fake = FakeLlm::start();
    let (_, handle) = pass_in_flight(&f, &fake);
    handle.shutdown();
    assert_eq!(chats(&fake).len(), 1);
}

#[test]
fn opting_out_stops_the_backlog_between_its_calls() {
    let f = Fixture::new();
    let case = case_with_notes(&f, 25);
    let fake = FakeLlm::start();
    configure(&f, &format!("{}/v1", fake.url));
    script_first_pass(&fake);
    fake.push_delayed(200, &openai_chat("[]", "stop", 100), Duration::from_millis(600));
    fake.push(200, &openai_chat("[]", "stop", 100));
    let handle = rethink(&f, case);
    wait_for_chats(&fake, 5);
    CompanionDb::open_for(&f.db.path)
        .unwrap()
        .set_case_enabled(case, false)
        .unwrap();
    handle.send(Command::CaseToggled(case));
    std::thread::sleep(Duration::from_millis(2000));
    assert_eq!(chats(&fake).len(), 5);
    handle.shutdown();
}

#[test]
fn what_the_client_learned_is_published_for_ask() {
    let f = Fixture::new();
    let fake = FakeLlm::start();
    let mut anthropic = settings(&fake.url);
    anthropic.protocol = Protocol::Anthropic;
    anthropic.context_window = None;
    anthropic.save(&CompanionDb::open_for(&f.db.path).unwrap()).unwrap();
    fake.push(200, &anthropic_models(&[("m", 200_000)]));
    let handle = start(&f);
    let status = wait_for(&handle, Duration::from_secs(5), |s| s.learned.context_window.is_some());
    assert_eq!(status.learned.context_window, Some(200_000));
    handle.shutdown();
}

#[test]
fn thread_probes_on_start_and_reports_unreachable() {
    let f = Fixture::new();
    configure(&f, "http://127.0.0.1:1/v1");
    let handle = start(&f);
    // Windows retries a refused connection for about two seconds before it gives up
    let status = wait_for(&handle, Duration::from_secs(15), |s| s.state == State::Unreachable);
    assert_eq!(status.state, State::Unreachable);
    assert_eq!(status.line(), "companion: endpoint unreachable");
    handle.shutdown();
}

#[test]
fn rethink_runs_a_full_pass_and_updates_status() {
    let f = Fixture::new();
    let (case, note) = {
        let factum = f.factum();
        let case = factum.create_case("C-10", "Webserver", "Defaced web site").unwrap();
        let note = factum
            .create_note("Image of /dev/sda acquired, md5 verified", None, case)
            .unwrap();
        (case, note)
    };
    let fake = FakeLlm::start();
    configure(&f, &format!("{}/v1", fake.url));
    fake.push(200, &openai_models(&["m"]));
    fake.push(200, &openai_chat("[]", "stop", 100));
    fake.push(200, &openai_chat("I would ask about the hashing tool.", "stop", 100));
    let output = json!({"questions": [
        {"text": "Which tool and version computed the md5 of the image?", "archetype": "repeatability",
         "rests_on": [note]}
    ]});
    fake.push(200, &openai_chat(&output.to_string(), "stop", 100));

    let handle = start(&f);
    handle.send(Command::Rethink(case));
    let status = wait_for(&handle, Duration::from_secs(5), |s| s.last_pass_utc.contains_key(&case));
    assert!(status.last_pass_utc.contains_key(&case));
    assert_eq!(status.state, State::Idle);
    assert_eq!(status.line(), "companion: idle · m");
    handle.shutdown();
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    assert!(!cdb.open_questions(case).unwrap().is_empty());
}

#[test]
fn failed_pass_is_reported_and_does_not_spin() {
    let f = Fixture::new();
    // no entries, so the pass makes no enrichment call
    let case = add_case_row(&f.db, "C-11", false);
    let fake = FakeLlm::start();
    configure(&f, &format!("{}/v1", fake.url));
    // the probe gets the default listing, every chat call a 500 (the client retries once after 5 s)
    let handle = start(&f);
    handle.send(Command::Rethink(case));
    let status = wait_for(&handle, Duration::from_secs(10), |s| {
        matches!(s.state, State::Failed(_))
    });
    assert!(matches!(status.state, State::Failed(_)), "{status:?}");
    assert!(status.line().starts_with("companion: last pass failed: "));
    // the one retry it is owed waits for the minimum spacing
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(fake.requests().len(), 3);
    handle.shutdown();
}
