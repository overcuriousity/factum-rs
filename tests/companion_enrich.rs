#![cfg(feature = "gui")]

mod common;

use std::time::Duration;

use common::Fixture;
use common::fake_llm::{FakeLlm, openai_chat};
use factum::companion::enrich::{ENRICH_BATCH, enrich, index_unindexed};
use factum::companion::llm::Client;
use factum::companion::retrieval::{bm25, fts_query};
use factum::companion::{CompanionDb, Protocol, Settings};
use serde_json::json;

fn client(fake: &FakeLlm) -> Client {
    Client::with_retry_delay(
        Settings {
            endpoint_url: format!("{}/v1", fake.url),
            protocol: Protocol::OpenAi,
            api_key: "k".into(),
            api_key_from_env: false,
            user_agent: "factum-test".into(),
            extra_headers: String::new(),
            model: "m".into(),
            context_window: None,
            global_guideline: String::new(),
            enabled: true,
        },
        Duration::ZERO,
    )
}

/// A case with twelve notes; the notes' entry ids in log order.
fn case_with_notes(f: &Fixture) -> (i64, Vec<i64>) {
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let ids = (1..=12)
        .map(|n| {
            factum
                .create_note(&format!("Festplatte {n} wurde abgebildet"), None, case_id)
                .unwrap()
        })
        .collect();
    (case_id, ids)
}

fn reply(items: &[(i64, &str, u32)]) -> String {
    let items: Vec<_> = items
        .iter()
        .map(|(id, keyword, importance)| {
            json!({"id": id, "keywords": [keyword], "context": "ctx", "importance": importance})
        })
        .collect();
    openai_chat(&serde_json::Value::Array(items).to_string(), "stop", 100)
}

#[test]
fn enriches_in_batches_of_ten_and_skips_missing() {
    let f = Fixture::new();
    let (case_id, ids) = case_with_notes(&f);
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    let fake = FakeLlm::start();
    // batch 1: nine of ten answered, one unknown id; the tenth comes back with an importance out of range
    let mut first: Vec<_> = ids[..9].iter().map(|&id| (id, "disk", 5)).collect();
    first.push((999_999, "ghost", 5));
    first.push((ids[9], "disk", 50));
    fake.push(200, &reply(&first));
    fake.push(200, &reply(&[(ids[10], "disk", 10), (ids[11], "disk", 1)]));

    let done = enrich(&f.db, &cdb, &client(&fake), case_id, &ids).unwrap();

    assert_eq!(ENRICH_BATCH, 10);
    assert_eq!(done, 11);
    let requests = fake.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].body.contains("response_format"));
    assert_eq!(cdb.unenriched(case_id, &ids).unwrap(), vec![ids[9]]);
    assert_eq!(cdb.enrichment(ids[10]).unwrap().unwrap().importance, 10);
    assert!(cdb.enrichment(999_999).unwrap().is_none());
}

#[test]
fn keywords_land_in_the_fts_index() {
    let f = Fixture::new();
    let (case_id, ids) = case_with_notes(&f);
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    let fake = FakeLlm::start();
    fake.push(200, &reply(&[(ids[0], "disk image", 7)]));

    enrich(&f.db, &cdb, &client(&fake), case_id, &ids[..1]).unwrap();

    let hits = bm25(&cdb, case_id, &fts_query("disk"), 5).unwrap();
    assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![ids[0]]);
}

#[test]
fn call_failure_aborts_and_leaves_rest_unenriched() {
    let f = Fixture::new();
    let (case_id, ids) = case_with_notes(&f);
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    let fake = FakeLlm::start();
    fake.push(500, "{}");
    fake.push(500, "{}");

    assert!(enrich(&f.db, &cdb, &client(&fake), case_id, &ids).is_err());

    assert_eq!(fake.requests().len(), 2, "one try and one retry, no second batch");
    assert_eq!(cdb.unenriched(case_id, &ids).unwrap(), ids);
}

#[test]
fn index_unindexed_covers_newest_versions_only() {
    let f = Fixture::new();
    let factum = f.factum();
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let old = factum.create_note("Image of sdb taken", None, case_id).unwrap();
    let new = factum.correct_note(old, "Image of sdc taken").unwrap();
    let cdb = CompanionDb::open_for(&f.db.path).unwrap();
    let old_entry = factum.get_entry(old).unwrap().unwrap();
    cdb.index_entry(case_id, &old_entry, &[], "").unwrap();

    index_unindexed(&f.db, &cdb, case_id).unwrap();

    assert!(bm25(&cdb, case_id, &fts_query("sdb"), 5).unwrap().is_empty());
    let hits = bm25(&cdb, case_id, &fts_query("sdc"), 5).unwrap();
    assert_eq!(hits.iter().map(|h| h.0).collect::<Vec<_>>(), vec![new]);
}
