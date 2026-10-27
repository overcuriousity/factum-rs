#![cfg(feature = "gui")]

mod common;

use std::time::Duration;

use common::Fixture;
use common::fake_llm::{FakeLlm, openai_chat};
use factum::companion::ask::ask;
use factum::companion::enrich::index_unindexed;
use factum::companion::llm::Client;
use factum::companion::{CompanionDb, Protocol, Settings};
use serde_json::Value;

struct Env {
    f: Fixture,
    cdb: CompanionDb,
    fake: FakeLlm,
    client: Client,
    case: i64,
    notes: Vec<i64>,
}

/// An indexed case with five notes, the second one pinned.
fn env() -> Env {
    let f = Fixture::new();
    let (case, notes) = {
        let factum = f.factum();
        let case = factum.create_case("C-9", "Webserver", "Defaced web site").unwrap();
        let evidence = factum
            .create_evidence(case, "Webserver image", "sha256:abc", "")
            .unwrap();
        let notes: Vec<i64> = [
            "Image of /dev/sda acquired, md5 verified",
            "Webshell found in /var/www/uploads/x.php",
            "Apache access.log shows a POST to x.php",
            "Timeline built with plaso",
            "Suspect address 203.0.113.5 in the logs",
        ]
        .iter()
        .map(|text| factum.create_note(text, Some(evidence), case).unwrap())
        .collect();
        factum.pin_note(notes[1]).unwrap();
        (case, notes)
    };
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    index_unindexed(&f.db, &cdb, case).unwrap();
    let fake = FakeLlm::start();
    let settings = Settings {
        endpoint_url: format!("{}/v1", fake.url),
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
    let client = Client::with_retry_delay(settings, Duration::ZERO);
    Env {
        f,
        cdb,
        fake,
        client,
        case,
        notes,
    }
}

/// The only user turn of the one request the endpoint saw.
fn sent_prompt(e: &Env) -> String {
    let requests = e.fake.requests();
    assert_eq!(requests.len(), 1);
    let body: Value = serde_json::from_str(&requests[0].body).unwrap();
    body["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string()
}

fn ask_with(e: &Env, question: &str, answer: &str) -> factum::companion::ask::Answer {
    e.fake.push(200, &openai_chat(answer, "stop", 100));
    ask(&e.f.db, &e.cdb, &e.client, e.case, question).unwrap()
}

#[test]
fn ask_builds_numbered_excerpts_and_maps_references() {
    let e = env();
    let answer = ask_with(
        &e,
        "Which request hit the Apache access.log?",
        "The shell is at [2], see also [9].",
    );
    let prompt = sent_prompt(&e);
    assert!(prompt.starts_with("Question: Which request hit the Apache access.log?\n\nExcerpts:\n\n[1] #"));
    assert!(prompt.contains(&format!("[2] #{} · ", e.notes[2])));
    assert!(prompt.contains("\n\n---\n\n[2] #"));
    assert_eq!(answer.references, vec![(2, e.notes[2])]);
    assert!(!answer.abstained);
    assert!(answer.unsupported.is_empty());
}

#[test]
fn ask_detects_abstention() {
    let e = env();
    let answer = ask_with(
        &e,
        "Who is the client's lawyer?",
        "Not in the case log. Nothing mentions a lawyer.",
    );
    assert!(answer.abstained);
    assert!(answer.references.is_empty());
    assert!(answer.unsupported.is_empty());
}

#[test]
fn ask_includes_pinned_even_when_not_retrieved() {
    let e = env();
    ask_with(&e, "Which tool built the timeline?", "plaso [2]");
    let prompt = sent_prompt(&e);
    assert!(prompt.contains(&format!("[1] #{} · ", e.notes[1])));
    assert!(prompt.contains("Webshell found in /var/www/uploads/x.php"));
    assert!(prompt.contains(&format!("[2] #{} · ", e.notes[3])));
}
