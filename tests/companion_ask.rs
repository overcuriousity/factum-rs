#![cfg(feature = "gui")]

mod common;

use std::time::Duration;

use common::Fixture;
use common::fake_llm::{FakeLlm, openai_chat};
use factum::companion::ask::ask;
use factum::companion::enrich::index_unindexed;
use factum::companion::llm::{Client, Learned};
use factum::companion::tokens::Calibration;
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
fn big_pinned_notes_leave_room_for_the_hits() {
    let e = env();
    for n in 1..=8 {
        let text = format!("Pinned finding {n}: {}", "registry run key persistence ".repeat(70));
        let id = e.f.factum().create_note(&text, None, e.case).unwrap();
        e.f.factum().pin_note(id).unwrap();
    }
    let hit = format!("Timeline filters: {}", "timeline filter settings ".repeat(45));
    e.f.factum().create_note(&hit, None, e.case).unwrap();
    let mut settings = e.client.settings().clone();
    settings.context_window = Some(4000);
    let small = Client::with_retry_delay(settings, Duration::ZERO);
    e.fake.push(200, &openai_chat("plaso [1]", "stop", 100));
    ask(&e.f.db, &e.cdb, &small, e.case, "Which tool built the timeline?").unwrap();
    let prompt = sent_prompt(&e);
    assert!(prompt.contains("Timeline built with plaso"), "{prompt}");
    assert!(prompt.contains(&hit), "{prompt}");
    assert!(
        prompt.contains("Pinned finding 1"),
        "pinned notes keep their part of the room"
    );
}

#[test]
fn pinned_notes_are_shortened_and_no_excerpt_stops_the_others() {
    let e = env();
    let long = format!("Pinned finding: {}", "registry run key persistence ".repeat(70));
    let pinned = e.f.factum().create_note(&long, None, e.case).unwrap();
    e.f.factum().pin_note(pinned).unwrap();
    // ranks first and does not fit; the short hit after it does
    let big = format!("carved fragment {}", "carved fragment ".repeat(120));
    e.f.factum().create_note(&big, None, e.case).unwrap();
    let short = e.f.factum().create_note("carved fragment", None, e.case).unwrap();
    let mut settings = e.client.settings().clone();
    settings.context_window = Some(2200);
    let small = Client::with_retry_delay(settings, Duration::ZERO);
    e.fake.push(200, &openai_chat("Seen once [1].", "stop", 100));
    let answer = ask(&e.f.db, &e.cdb, &small, e.case, "carved fragment").unwrap();
    assert!(!answer.abstained);
    let prompt = sent_prompt(&e);
    assert!(prompt.contains(&format!("#{short} · ")), "{prompt}");
    assert!(!prompt.contains(&big));
    assert!(prompt.contains("Pinned finding: registry"), "{prompt}");
    assert!(!prompt.contains(&"registry run key persistence ".repeat(20)));
    assert!(prompt.contains('…'));
}

#[test]
fn a_pinned_note_that_is_a_hit_stays_whole() {
    let e = env();
    let text = format!("Pinned finding: plaso {}", "registry run key persistence ".repeat(40));
    let id = e.f.factum().create_note(&text, None, e.case).unwrap();
    e.f.factum().pin_note(id).unwrap();
    // it fits the room, not the part of it for pinned notes
    let mut settings = e.client.settings().clone();
    settings.context_window = Some(2600);
    let small = Client::with_retry_delay(settings, Duration::ZERO);
    e.fake.push(200, &openai_chat("plaso [1]", "stop", 100));
    ask(&e.f.db, &e.cdb, &small, e.case, "plaso").unwrap();
    assert!(sent_prompt(&e).contains(&text));
}

#[test]
fn ask_budgets_with_what_the_companion_learned() {
    let e = env();
    let mut settings = e.client.settings().clone();
    settings.context_window = None;
    // the default window and ratio would hold the note, the learned ones do not
    let client = Client::with_retry_delay(settings, Duration::ZERO);
    client.learn(Learned {
        context_window: Some(2000),
        calibration: Calibration { chars_per_token: 1.5 },
    });
    let text = format!("plaso {}", "registry run key persistence ".repeat(30));
    e.f.factum().create_note(&text, None, e.case).unwrap();
    assert_eq!(client.window(), 2000);
    e.fake.push(200, &openai_chat("plaso [1]", "stop", 100));
    ask(&e.f.db, &e.cdb, &client, e.case, "plaso").unwrap();
    assert!(!sent_prompt(&e).contains(&text));
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
