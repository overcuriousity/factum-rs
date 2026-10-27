//! Evidence containers and the case log: creating, filling, closing, reopening, signing later, locating.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use common::{Fixture, system_events};
use factum::container::volume::{AddOptions, AddProgress, HASHES, SIG_GPG, TURTLE, Volume, history_member};
use factum::error::ErrorKind;
use factum::signer::FakeSigner;
use sha2::Digest;

struct Setup {
    f: Fixture,
    case_id: i64,
    evidence_id: i64,
    source: PathBuf,
}

impl Setup {
    fn new() -> Self {
        Self::with_signer(FakeSigner::new(true))
    }

    fn with_signer(signer: FakeSigner) -> Self {
        let f = Fixture::with_signer(signer);
        let case_id = f.factum().create_case("C-1", "Case", "").unwrap();
        let evidence_id = f.factum().create_evidence(case_id, "disk", "", "seized").unwrap();
        let source = f.path().join("mnt");
        std::fs::create_dir_all(source.join("Users/x")).unwrap();
        for (name, content) in [
            ("a.txt", "a"),
            ("b.txt", "bb"),
            ("c.txt", "ccc"),
            ("d.txt", "dddd"),
            ("e.txt", "e"),
        ] {
            std::fs::write(source.join("Users/x").join(name), content).unwrap();
        }
        Self {
            f,
            case_id,
            evidence_id,
            source,
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.source.join("Users/x").join(name)
    }

    fn container_path(&self) -> PathBuf {
        self.f.path().join("preserved.aff4l")
    }

    fn create(&self) -> i64 {
        self.f
            .factum()
            .create_container(
                self.case_id,
                "FS01 preserved",
                Some(self.evidence_id),
                &self.container_path(),
                &self.source.display().to_string(),
            )
            .unwrap()
    }

    fn options(&self) -> AddOptions {
        AddOptions {
            base: self.source.clone(),
            keep_path: true,
            metadata_only: false,
            excerpt: None,
        }
    }

    fn add(&self, id: i64, sources: &[PathBuf]) -> i64 {
        let factum = self.f.factum();
        let mut volume = factum.open_container_for_add(id).unwrap();
        let staged = volume
            .stage_add(
                sources,
                &self.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        factum.commit_container_add(id, &mut volume, staged).unwrap()
    }

    fn events(&self, name: &str) -> Vec<serde_json::Value> {
        system_events(&self.f.db, self.case_id)
            .into_iter()
            .filter(|e| e["event"] == name)
            .collect()
    }

    fn entry_text(&self, entry_id: i64) -> String {
        self.f.factum().get_entry(entry_id).unwrap().unwrap().text
    }
}

fn member(path: &Path, name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut file = archive.by_name(name).ok()?;
    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut data).unwrap();
    Some(data)
}

#[test]
fn create_logs_event_with_spec_payload() {
    let s = Setup::new();
    let id = s.create();
    let events = s.events("container_created");
    assert_eq!(events.len(), 1);
    let event = &events[0];
    let mut keys: Vec<&str> = event.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "base_path",
            "case_id",
            "container_id",
            "created_utc",
            "event",
            "evidence_id",
            "file_name",
            "name"
        ]
    );
    assert_eq!(event["file_name"], "preserved.aff4l");
    assert_eq!(event["evidence_id"], s.evidence_id);
    let uuid = event["container_id"].as_str().unwrap();
    assert_eq!(Volume::uuid_of(&s.container_path()).unwrap(), uuid);
    assert_eq!(
        s.entry_text(id),
        format!(
            "Container \"FS01 preserved\" created (from evidence #{})",
            s.evidence_id
        )
    );
    let factum = s.f.factum();
    assert_eq!(factum.find_container_by_uuid(uuid).unwrap(), Some(id));
    assert_eq!(factum.container_path(uuid), Some(s.container_path()));
    // the case log still verifies: the new events are ordinary system entries
    let report = factum.verify_case(s.case_id, None).unwrap();
    assert!(
        report.findings.iter().all(|f| f.code == "not_sealed"),
        "{:?}",
        report.findings
    );
}

#[test]
fn create_refuses_existing_file_and_unknown_evidence() {
    let s = Setup::new();
    s.create();
    let factum = s.f.factum();
    let again = factum.create_container(s.case_id, "x", None, &s.container_path(), "/");
    assert!(again.is_err());
    let other = s.f.path().join("other.aff4l");
    assert!(factum.create_container(s.case_id, "x", Some(999), &other, "/").is_err());
    assert!(!other.exists());
    assert!(factum.create_container(s.case_id, "  ", None, &other, "/").is_err());
}

#[test]
fn add_logs_one_entry_per_operation() {
    let s = Setup::new();
    let id = s.create();
    let factum = s.f.factum();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let staged = volume
        .stage_add(
            &[s.file("a.txt"), s.file("b.txt")],
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let records: Vec<serde_json::Value> = staged.records.iter().map(|r| r.to_json()).collect();
    let entry = factum.commit_container_add(id, &mut volume, staged).unwrap();
    let events = s.events("container_files_added");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["files"].as_array().unwrap(), &records);
    assert!(events[0]["added_utc"].is_string());
    assert_eq!(s.entry_text(entry), format!("2 files added to container #{id} (3 B)"));
    drop(volume);
    let detail = factum.container(id).unwrap();
    assert_eq!(detail.adds.len(), 1);
    assert_eq!(detail.adds[0].entry_id, entry);
    assert_eq!(detail.summary.file_count, 2);
}

#[test]
fn failed_finalize_rolls_back_entry_and_file() {
    let s = Setup::new();
    let id = s.create();
    let factum = s.f.factum();
    let entries = s.f.count("SELECT COUNT(*) FROM entries");
    let mut volume = factum.open_container_for_add(id).unwrap();
    let staged = volume
        .stage_add(
            &[s.file("a.txt")],
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let start = staged.start;
    volume.fail_next_finalize = true;
    assert!(factum.commit_container_add(id, &mut volume, staged).is_err());
    assert_eq!(s.f.count("SELECT COUNT(*) FROM entries"), entries);
    assert_eq!(std::fs::metadata(s.container_path()).unwrap().len(), start);
}

#[test]
fn failed_append_restores_container() {
    let s = Setup::new();
    let id = s.create();
    let factum = s.f.factum();
    let before = std::fs::read(s.container_path()).unwrap();
    let entries = s.f.count("SELECT COUNT(*) FROM entries");
    let mut volume = factum.open_container_for_add(id).unwrap();
    let staged = volume
        .stage_add(
            &[s.file("a.txt")],
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    s.f.signer.fail_next.set(true);
    let error = factum.commit_container_add(id, &mut volume, staged).unwrap_err();
    assert!(error.is(ErrorKind::Signing), "{error}");
    assert_eq!(s.f.count("SELECT COUNT(*) FROM entries"), entries);
    drop(volume);
    assert_eq!(std::fs::read(s.container_path()).unwrap(), before);
}

#[test]
fn close_signs_and_logs_turtle_hash() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
    let close = s.f.factum().close_container(id).unwrap();
    let event = &s.events("container_closed")[0];
    let turtle = member(&s.container_path(), TURTLE).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(&turtle));
    assert_eq!(event["turtle_sha256"], sha.as_str());
    assert_eq!(close.turtle_sha256, sha);
    assert_eq!(event["file_count"], 2);
    assert!(event["signatures"]["gpg"].is_string());
    assert!(event["signatures"]["x509"].is_null());
    assert_eq!(
        member(&s.container_path(), SIG_GPG).unwrap(),
        format!("FAKE DETACHED {sha}").into_bytes()
    );
    assert!(member(&s.container_path(), &history_member(1, HASHES)).is_some());
    assert_eq!(
        s.entry_text(close.entry_id),
        format!("Container #{id} closed · 2 files · signed")
    );
    let detail = s.f.factum().container(id).unwrap();
    assert!(!detail.summary.open);
    // a closed container takes nothing
    let error = s.f.factum().open_container_for_add(id).err().unwrap();
    assert!(error.to_string().contains("closed"), "{error}");
}

#[test]
fn close_without_key_then_sign_later() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let close = s.f.factum().close_container(id).unwrap();
    assert!(close.gpg.is_none());
    assert_eq!(
        s.entry_text(close.entry_id),
        format!("Container #{id} closed · 1 files · unsigned")
    );
    assert!(member(&s.container_path(), SIG_GPG).is_none());
    // without a key there is nothing to sign with
    assert!(s.f.factum().sign_unsigned_containers(s.case_id).is_err());
    s.f.signer.set_active(true);
    let (count, skipped) = s.f.factum().sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!((count, skipped.len()), (1, 0));
    let signed = &s.events("container_signed")[0];
    assert_eq!(signed["turtle_sha256"], close.turtle_sha256.as_str());
    assert!(member(&s.container_path(), &history_member(1, SIG_GPG)).is_some());
    assert!(member(&s.container_path(), SIG_GPG).is_some());
    let detail = s.f.factum().container(id).unwrap();
    assert!(detail.closes[0].signed_later.is_some());
    assert_eq!(s.f.factum().sign_unsigned_containers(s.case_id).unwrap().0, 0);
}

#[test]
fn sign_later_skips_missing_files() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.f.factum().close_container(id).unwrap();
    std::fs::remove_file(s.container_path()).unwrap();
    s.f.signer.set_active(true);
    let (count, skipped) = s.f.factum().sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!(count, 0);
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].contains(&format!("#{id}")), "{}", skipped[0]);
}

#[test]
fn reopen_and_add_requires_open_case() {
    let s = Setup::new();
    let id = s.create();
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    let reopen = factum.reopen_container(id).unwrap();
    assert_eq!(s.entry_text(reopen), format!("Container #{id} reopened"));
    assert!(factum.container(id).unwrap().summary.open);
    assert!(factum.reopen_container(id).is_err()); // already open
    factum.close_container(id).unwrap();
    factum.archive_case(s.case_id).unwrap();
    let error = factum.reopen_container(id).unwrap_err();
    assert!(error.is(ErrorKind::CaseArchived), "{error}");
}

#[test]
fn archive_refused_with_open_container() {
    let s = Setup::new();
    let id = s.create();
    let error = s.f.factum().archive_case(s.case_id).unwrap_err();
    assert!(
        error.to_string().contains(&format!("#{id} \"FS01 preserved\"")),
        "{error}"
    );
    assert!(!s.f.factum().get_case(s.case_id).unwrap().unwrap().is_archived());
}

#[test]
fn archive_allowed_after_close() {
    let s = Setup::new();
    let id = s.create();
    s.f.factum().close_container(id).unwrap();
    s.f.factum().archive_case(s.case_id).unwrap();
    assert!(s.f.factum().get_case(s.case_id).unwrap().unwrap().is_archived());
}

#[test]
fn locate_refuses_other_container() {
    let s = Setup::new();
    let id = s.create();
    let other = s.f.path().join("other.aff4l");
    let factum = s.f.factum();
    factum.create_container(s.case_id, "Other", None, &other, "/").unwrap();
    let moved = s.f.path().join("moved.aff4l");
    std::fs::rename(s.container_path(), &moved).unwrap();
    let summary = &factum.list_containers(s.case_id).unwrap()[0];
    assert!(summary.missing);
    let error = factum.locate_container(id, &other).unwrap_err();
    assert!(error.to_string().contains("not container"), "{error}");
    factum.locate_container(id, &moved).unwrap();
    let summary = &factum.list_containers(s.case_id).unwrap()[0];
    assert!(!summary.missing);
    assert_eq!(summary.path.as_deref(), Some(moved.as_path()));
    assert!(factum.open_container_for_add(id).is_ok());
}

#[test]
fn list_containers_counts_files() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
    s.add(id, &[s.file("c.txt"), s.file("d.txt"), s.file("e.txt")]);
    let factum = s.f.factum();
    let list = factum.list_containers(s.case_id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].id, list[0].file_count, list[0].open), (id, 5, true));
    assert_eq!(list[0].name, "FS01 preserved");
    factum.close_container(id).unwrap();
    assert!(!factum.list_containers(s.case_id).unwrap()[0].open);
    assert!(factum.open_containers(s.case_id).unwrap().is_empty());
    factum.reopen_container(id).unwrap();
    assert_eq!(factum.open_containers(s.case_id).unwrap().len(), 1);
}

#[test]
fn container_differing_from_the_log_is_not_written() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    // the log entry of the addition disappears (another database, say): the container lists a file the log lacks
    let factum = s.f.factum();
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    let findings = factum.compare_with_log(id, &volume).unwrap();
    assert!(findings.is_empty(), "{findings:?}");
    drop(volume);
    s.f.exec("UPDATE entries SET payload_json = replace(payload_json, 'container_files_added', 'something_else')");
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    let findings = factum.compare_with_log(id, &volume).unwrap();
    assert!(findings.iter().any(|f| f.code == "log_mismatch"), "{findings:?}");
    drop(volume);
    let error = factum.open_container_for_add(id).err().unwrap();
    assert!(error.to_string().contains("differs from the case log"), "{error}");
}
