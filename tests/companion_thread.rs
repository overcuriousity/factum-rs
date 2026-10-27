#![cfg(feature = "gui")]

mod common;

use std::time::{Duration, Instant};

use common::fake_llm::{FakeLlm, openai_chat, openai_models};
use common::{Fixture, add_case_row};
use factum::companion::thread::{Command, CompanionHandle, State, Status};
use factum::companion::{CompanionDb, Protocol, Settings, companion_db_path};
use serde_json::json;

fn configure(f: &Fixture, endpoint_url: &str) {
    let settings = Settings {
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
    };
    settings.save(&CompanionDb::open_for(&f.db.path).unwrap()).unwrap();
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
    let output = json!({"answered": [], "withdraw": [], "new": [
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
