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
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).ok()?;
    let mut file = archive.by_name(name).ok()?;
    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut data).unwrap();
    Some(data)
}

/// The review's attack: replace a file's content after a signed close and hide it from the hash check by dropping
/// its storage type in a new, unsigned "open" state.
fn swap_content_and_drop_storage_type(path: &Path, arn: &str) {
    use factum::container::turtle::{self, Graph, Term};
    use factum::container::zip64::{Appender, read_archive};
    use factum::container::{AFF4_NS, RDF_NS};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let old = turtle::parse(&String::from_utf8(member(path, TURTLE).unwrap()).unwrap()).unwrap();
    let mut graph = Graph::default();
    for t in old.triples() {
        let storage = t.subject == arn
            && t.predicate == format!("{RDF_NS}type")
            && t.object == Term::Iri(format!("{AFF4_NS}ZipSegment"));
        if !storage {
            graph.add(&t.subject, &t.predicate, t.object.clone());
        }
    }
    let text = turtle::write(&graph, &turtle::factum_prefixes());
    let mut hashes = Graph::default();
    let uuid = String::from_utf8(member(path, "container.description").unwrap()).unwrap();
    for (name, value) in [
        ("SHA256", hex::encode(sha2::Sha256::digest(text.as_bytes()))),
        ("SHA512", hex::encode(sha2::Sha512::digest(text.as_bytes()))),
    ] {
        hashes.add(
            &format!("{uuid}/{TURTLE}"),
            &format!("{AFF4_NS}hash"),
            Term::Literal {
                value,
                datatype: Some(format!("{AFF4_NS}{name}")),
            },
        );
    }
    let mut app = Appender::new(file, len, archive.entries).unwrap();
    app.add_bytes(arn, 8, b"forged content").unwrap();
    app.add_bytes(TURTLE, 8, text.as_bytes()).unwrap();
    app.add_bytes(HASHES, 0, turtle::write(&hashes, &[("aff4", AFF4_NS)]).as_bytes())
        .unwrap();
    app.finish(&[SIG_GPG, "information.turtle.pubkey.asc"], &archive.comment)
        .unwrap();
}

/// Adds a second central directory entry for `arn` with other content (a placeholder renamed in the directory).
fn duplicate_member(path: &Path, arn: &str) {
    use factum::container::zip64::{Appender, read_archive};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let placeholder = "X".repeat(arn.len());
    let mut app = Appender::new(file, len, archive.entries).unwrap();
    app.add_bytes(&placeholder, 8, b"other bytes").unwrap();
    app.finish(&[], &archive.comment).unwrap();
    drop(app);
    let mut bytes = std::fs::read(path).unwrap();
    let at = bytes
        .windows(placeholder.len())
        .rposition(|w| w == placeholder.as_bytes())
        .unwrap();
    bytes[at..at + arn.len()].copy_from_slice(arn.as_bytes());
    std::fs::write(path, bytes).unwrap();
}

/// Rewrites the directory without close 1's history members.
fn drop_history_1(path: &Path) {
    use factum::container::zip64::{Appender, read_archive};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let dropped: Vec<String> = archive
        .entries
        .iter()
        .map(|e| e.name_lossy())
        .filter(|n| n.starts_with("factum/history/1/"))
        .collect();
    let omit: Vec<&str> = dropped.iter().map(String::as_str).collect();
    let mut app = Appender::new(file, len, archive.entries.clone()).unwrap();
    app.finish(&omit, &archive.comment).unwrap();
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
fn sign_later_signs_the_unsigned_close_of_identical_states() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let first = factum.close_container(id).unwrap();
    assert!(first.gpg.is_some());
    factum.reopen_container(id).unwrap();
    s.f.signer.set_active(false);
    let second = factum.close_container(id).unwrap();
    // nothing was added in between: both closes signed the same state
    assert_eq!(first.turtle_sha256, second.turtle_sha256);
    assert!(second.gpg.is_none());
    s.f.signer.set_active(true);
    let (count, skipped) = factum.sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!((count, skipped.len()), (1, 0), "{skipped:?}");
    let detail = factum.container(id).unwrap();
    assert!(detail.closes[0].signed_later.is_none());
    assert!(detail.closes[1].signed_later.is_some());
    assert_eq!(s.events("container_signed")[0]["close"], 2);
    assert_eq!(factum.sign_unsigned_containers(s.case_id).unwrap().0, 0);
    assert_eq!(s.events("container_signed").len(), 1);
}

#[test]
fn sign_later_keeps_what_was_signed_when_signing_fails() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let mut ids = Vec::new();
    for name in ["one", "two", "three"] {
        let id =
            s.f.factum()
                .create_container(s.case_id, name, None, &s.f.path().join(format!("{name}.aff4l")), "/")
                .unwrap();
        s.f.factum().close_container(id).unwrap();
        ids.push(id);
    }
    s.f.signer.set_active(true);
    // the second signature fails (a cancelled passphrase prompt)
    s.f.signer.fail_detached_after.set(Some(1));
    let (count, skipped) = s.f.factum().sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!(count, 1);
    assert_eq!(s.events("container_signed").len(), 1);
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert!(
        skipped[0].contains(&format!("#{}", ids[1])) && skipped[0].contains("GPG"),
        "{}",
        skipped[0]
    );
    assert!(skipped[1].contains(&format!("#{}", ids[2])), "{}", skipped[1]);
    // the rest is signed on the next run
    assert_eq!(s.f.factum().sign_unsigned_containers(s.case_id).unwrap().0, 2);
}

#[test]
fn sign_later_works_in_an_archived_case() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    s.f.factum().close_container(id).unwrap();
    s.f.factum().archive_case(s.case_id).unwrap();
    s.f.signer.set_active(true);
    let (count, skipped) = s.f.factum().sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!((count, skipped.len()), (1, 0), "{skipped:?}");
}

#[test]
fn sign_later_goes_on_after_a_broken_container() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let broken = s.create();
    s.f.factum().close_container(broken).unwrap();
    drop_history_1(&s.container_path());
    let other =
        s.f.factum()
            .create_container(s.case_id, "Other", None, &s.f.path().join("other.aff4l"), "/")
            .unwrap();
    s.f.factum().close_container(other).unwrap();
    s.f.signer.set_active(true);
    let (count, skipped) = s.f.factum().sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!(count, 1);
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].contains(&format!("#{broken}")), "{}", skipped[0]);
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
fn a_container_whose_file_is_missing_is_closed_without_it() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    // while the file is there, it is closed as usual
    assert!(factum.close_container_without_file(id).is_err());
    let copy = s.f.path().join("found-again.aff4l");
    std::fs::rename(s.container_path(), &copy).unwrap();
    assert!(factum.close_container(id).is_err());
    assert!(factum.archive_case(s.case_id).is_err());
    let entry = factum.close_container_without_file(id).unwrap();
    assert!(
        s.entry_text(entry).contains("without its file"),
        "{}",
        s.entry_text(entry)
    );
    let event = &s.events("container_closed")[0];
    assert_eq!(event["file_missing"], true);
    let detail = factum.container(id).unwrap();
    assert!(!detail.summary.open);
    assert!(detail.closes.is_empty());
    assert_eq!(detail.closed_without_file.len(), 1);
    assert!(factum.close_container_without_file(id).is_err());
    factum.archive_case(s.case_id).unwrap();
    // the file found again: it was never closed, and the log says why
    factum.locate_container(id, &copy).unwrap();
    let report = factum
        .verify_container_file(
            &copy,
            &factum::container::x509::Gpgsm::unavailable(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
    let mismatch = report
        .findings
        .iter()
        .find(|f| f.code == "log_mismatch")
        .expect("a log mismatch");
    assert!(
        mismatch.message.contains("while its file was missing"),
        "{}",
        mismatch.message
    );
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
fn crash_between_container_write_and_log_commit_is_set_aside() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    // the container was written, the process died before the log entry was committed
    let (mut volume, _) = Volume::open(&s.container_path()).unwrap();
    let staged = volume
        .stage_add(
            &[s.file("b.txt")],
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    volume.finalize_add(&staged, 999_999).unwrap();
    drop(volume);
    let written = std::fs::metadata(s.container_path()).unwrap().len();
    // the container goes on from the logged state; the unlogged one stays in the file, unreferenced
    s.add(id, &[s.file("c.txt")]);
    assert!(std::fs::metadata(s.container_path()).unwrap().len() > written);
    let detail = s.f.factum().container(id).unwrap();
    let paths: Vec<String> = detail.files().map(|(_, f)| f.path.clone()).collect();
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert!(!paths.iter().any(|p| p.ends_with("b.txt")));
    let (volume, _) = Volume::open(&s.container_path()).unwrap();
    assert!(s.f.factum().compare_with_log(id, &volume).unwrap().is_empty());
}

#[test]
fn crash_after_close_before_log_commit_is_set_aside() {
    use factum::container::volume::Signatures;
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let (mut volume, _) = Volume::open(&s.container_path()).unwrap();
    volume.close(&Signatures::default()).unwrap();
    drop(volume);
    s.f.factum().close_container(id).unwrap();
    let report =
        s.f.factum()
            .verify_container_file(
                &s.container_path(),
                &factum::container::x509::Gpgsm::unavailable(),
                &|_, _| {},
                &AtomicBool::new(false),
            )
            .unwrap();
    assert_eq!(report.overall(), factum::verifier::Level::Ok, "{:?}", report.findings);
    assert_eq!(report.states.len(), 1);
}

#[test]
fn stale_end_setting_never_cuts_committed_data() {
    let s = Setup::new();
    let id = s.create();
    let uuid = s.f.factum().container(id).unwrap().summary.uuid;
    let before_add = s.f.db.get_setting(&format!("container_end:{uuid}")).unwrap();
    s.add(id, &[s.file("a.txt")]);
    // the setting lags behind (a restored database, say) and an addition was interrupted
    s.f.db
        .set_setting(&format!("container_end:{uuid}"), &before_add)
        .unwrap();
    let mut bytes = std::fs::read(s.container_path()).unwrap();
    bytes.extend(vec![1u8; 100_000]);
    std::fs::write(s.container_path(), bytes).unwrap();
    s.add(id, &[s.file("b.txt")]);
    assert_eq!(s.f.factum().container(id).unwrap().summary.file_count, 2);
    let (volume, _) = Volume::open(&s.container_path()).unwrap();
    assert!(s.f.factum().compare_with_log(id, &volume).unwrap().is_empty());
}

#[test]
fn end_setting_moves_with_the_log_entry() {
    let s = Setup::new();
    let id = s.create();
    let uuid = s.f.factum().container(id).unwrap().summary.uuid;
    let key = format!("container_end:{uuid}");
    let before = s.f.db.get_setting(&key).unwrap();
    let factum = s.f.factum();
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
    assert!(factum.commit_container_add(id, &mut volume, staged).is_err());
    assert_eq!(s.f.db.get_setting(&key).unwrap(), before);
    drop(volume);
    s.add(id, &[s.file("a.txt")]);
    assert_eq!(
        s.f.db.get_setting(&key).unwrap(),
        std::fs::metadata(s.container_path()).unwrap().len().to_string()
    );
}

#[test]
fn an_empty_folder_alone_is_added_and_logged() {
    let s = Setup::new();
    let id = s.create();
    let void = s.source.join("void");
    std::fs::create_dir(&void).unwrap();
    let entry = s.add(id, &[void]);
    assert_eq!(s.entry_text(entry), format!("1 folder added to container #{id}"));
    let detail = s.f.factum().container(id).unwrap();
    assert_eq!(detail.adds[0].files.len(), 0);
    assert_eq!(detail.adds[0].folders.len(), 1);
    assert_eq!(detail.adds[0].folders[0].path, "void");
    let (volume, _) = Volume::open(&s.container_path()).unwrap();
    assert!(s.f.factum().compare_with_log(id, &volume).unwrap().is_empty());
    drop(volume);
    // a folder the log does not record is a difference
    s.f.exec("UPDATE entries SET payload_json = replace(payload_json, '\"folders\":[{', '\"folders\":[],\"x\":[{')");
    let (volume, _) = Volume::open(&s.container_path()).unwrap();
    let findings = s.f.factum().compare_with_log(id, &volume).unwrap();
    assert!(findings.iter().any(|f| f.message.contains("void")), "{findings:?}");
}

#[test]
fn container_differing_from_the_log_is_not_written() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    // the log entry of the addition disappears (another database, say): the container lists a file the log lacks
    let factum = s.f.factum();
    let (volume, _) = Volume::open(&s.container_path()).unwrap();
    let findings = factum.compare_with_log(id, &volume).unwrap();
    assert!(findings.is_empty(), "{findings:?}");
    drop(volume);
    s.f.exec("UPDATE entries SET payload_json = replace(payload_json, 'container_files_added', 'something_else')");
    let (volume, _) = Volume::open(&s.container_path()).unwrap();
    let findings = factum.compare_with_log(id, &volume).unwrap();
    assert!(findings.iter().any(|f| f.code == "log_mismatch"), "{findings:?}");
    drop(volume);
    let error = factum.open_container_for_add(id).err().unwrap();
    assert!(error.to_string().contains("differs from the case log"), "{error}");
}

// --- verification

mod verify {
    use super::*;
    use factum::container::verify::{ContainerFormat, ContainerReport};
    use factum::container::x509::{Gpgsm, X509_CERT_SETTING};
    use factum::container::zip64::{Appender, read_archive};
    use factum::log_service::Append;
    use factum::verifier::Level;

    fn verify(s: &Setup, path: &Path) -> ContainerReport {
        s.f.factum()
            .verify_container_file(path, &Gpgsm::unavailable(), &|_, _| {}, &AtomicBool::new(false))
            .unwrap()
    }

    fn codes(report: &ContainerReport, level: Level) -> Vec<&'static str> {
        report
            .findings
            .iter()
            .filter(|f| f.level == level)
            .map(|f| f.code)
            .collect()
    }

    fn closed_with_files(s: &Setup) -> i64 {
        let id = s.create();
        s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
        s.f.factum().close_container(id).unwrap();
        id
    }

    #[test]
    fn clean_container_verifies() {
        let s = Setup::new();
        closed_with_files(&s);
        let report = verify(&s, &s.container_path());
        assert_eq!(report.format, ContainerFormat::Factum);
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        assert_eq!(report.states.len(), 1);
        assert_eq!(report.states[0].label, "close 1 (current)");
        assert_eq!(report.states[0].files, 2);
        assert!(report.states[0].gpg.as_ref().is_some_and(|g| g.valid));
        assert_eq!(report.log.as_ref().unwrap().matches_close, Some(1));
        assert!(report.log.as_ref().unwrap().recorded_after.is_empty());
    }

    #[test]
    fn open_state_after_a_close_is_its_own_state() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        s.f.factum().reopen_container(id).unwrap();
        // a reopen does not touch the file: it is still in its closed state, as the log expects
        let report = verify(&s, &s.container_path());
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        s.add(id, &[s.file("c.txt")]);
        let report = verify(&s, &s.container_path());
        assert_eq!(report.overall(), Level::Warn, "{:?}", report.findings);
        let labels: Vec<&str> = report.states.iter().map(|st| st.label.as_str()).collect();
        assert_eq!(labels, vec!["close 1", "current (open)"]);
        assert_eq!(report.states[1].files, 3);
    }

    #[test]
    fn flipped_content_byte_fails_stream_hash() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        let path = s.container_path();
        let mut file = std::fs::File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let entry = read_archive(&mut file, len).unwrap().get(&arn).unwrap().clone();
        let mut bytes = std::fs::read(&path).unwrap();
        let header = entry.header_offset as usize;
        let name_len = u16::from_le_bytes([bytes[header + 26], bytes[header + 27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[header + 28], bytes[header + 29]]) as usize;
        bytes[header + 30 + name_len + extra_len] ^= 0x55;
        std::fs::write(&path, bytes).unwrap();
        let report = verify(&s, &path);
        assert!(
            codes(&report, Level::Fail).contains(&"stream_hash"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn edited_turtle_fails_turtle_hash_and_signature() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let turtle = member(&path, TURTLE).unwrap();
        let edited = String::from_utf8(turtle).unwrap().replace("Users", "Usurp");
        let mut app = Appender::new(file, len, archive.entries).unwrap();
        app.add_bytes(TURTLE, 8, edited.as_bytes()).unwrap();
        app.finish(&[], &archive.comment).unwrap();
        let report = verify(&s, &path);
        let fails = codes(&report, Level::Fail);
        assert!(fails.contains(&"turtle_hash"), "{fails:?}");
        assert!(
            fails.contains(&"signature_mismatch") || fails.contains(&"signature_invalid"),
            "{fails:?}"
        );
    }

    #[test]
    fn older_copy_verifies_as_earlier_state() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let copy = s.f.path().join("handed-over.aff4l");
        std::fs::copy(s.container_path(), &copy).unwrap();
        let factum = s.f.factum();
        factum.reopen_container(id).unwrap();
        s.add(id, &[s.file("c.txt")]);
        factum.close_container(id).unwrap();
        let report = verify(&s, &copy);
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        let log = report.log.unwrap();
        assert_eq!(log.matches_close, Some(1));
        let after = log.recorded_after.join("\n");
        assert!(
            after.contains("reopened") && after.contains("added") && after.contains("closed"),
            "{after}"
        );
        // the newer file verifies too, with both closed states
        let report = verify(&s, &s.container_path());
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        assert_eq!(report.states.len(), 2);
        assert_eq!(report.log.unwrap().matches_close, Some(2));
    }

    #[test]
    fn swapped_content_of_a_signed_close_fails() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        // a copy elsewhere: what a recipient gets, without the case log
        let copy = s.f.path().join("received.aff4l");
        std::fs::copy(s.container_path(), &copy).unwrap();
        swap_content_and_drop_storage_type(&copy, &arn);
        let report = verify(&s, &copy);
        let fails = codes(&report, Level::Fail);
        assert!(fails.contains(&"history"), "{:?}", report.findings);
        assert!(fails.contains(&"stream_hash"), "{:?}", report.findings);
        // on the live file, the unlogged state is set aside: the container goes on from the logged, signed state
        swap_content_and_drop_storage_type(&s.container_path(), &arn);
        s.f.factum().reopen_container(id).unwrap();
        let mut volume = s.f.factum().open_container_for_add(id).unwrap();
        assert!(s.f.factum().compare_with_log(id, &volume).unwrap().is_empty());
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut volume.read_file(&arn).unwrap(), &mut content).unwrap();
        assert_eq!(content, b"a");
    }

    #[test]
    fn unparsable_metadata_of_a_signed_close_fails_and_is_still_checked() {
        let s = Setup::new();
        closed_with_files(&s);
        let copy = s.f.path().join("received.aff4l");
        std::fs::copy(s.container_path(), &copy).unwrap();
        // a forged hash, hidden from the parser by a line it refuses
        let turtle = String::from_utf8(member(&copy, TURTLE).unwrap()).unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(b"a"));
        assert!(turtle.contains(&sha256));
        let forged = turtle.replace(&sha256, &"0".repeat(64)) + "@base <x> .\n";
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&copy).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let mut app = Appender::new(file, len, archive.entries).unwrap();
        app.add_bytes(TURTLE, 8, forged.as_bytes()).unwrap();
        app.add_bytes(&history_member(1, TURTLE), 8, forged.as_bytes()).unwrap();
        app.finish(&[], &archive.comment).unwrap();
        let report = verify(&s, &copy);
        assert_eq!(report.overall(), Level::Fail, "{:?}", report.findings);
        let fails = codes(&report, Level::Fail);
        assert!(fails.contains(&"turtle_hash"), "{fails:?}");
        assert!(
            fails.contains(&"signature_mismatch") || fails.contains(&"signature_invalid"),
            "the signature is still checked: {fails:?}"
        );
        assert_eq!(report.states.len(), 1);
    }

    #[test]
    fn duplicate_member_names_fail() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        duplicate_member(&s.container_path(), &arn);
        let report = verify(&s, &s.container_path());
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "duplicate_member")
            .expect("a duplicate finding");
        assert!(fail.message.contains(&arn), "{}", fail.message);
    }

    #[test]
    fn a_missing_closed_state_fails() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        s.f.factum().reopen_container(id).unwrap();
        s.add(id, &[s.file("c.txt")]);
        s.f.factum().close_container(id).unwrap();
        let copy = s.f.path().join("received.aff4l");
        std::fs::copy(s.container_path(), &copy).unwrap();
        drop_history_1(&copy);
        let report = verify(&s, &copy);
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "history")
            .expect("a history failure");
        assert!(fail.message.contains("close 1"), "{}", fail.message);
        assert_eq!(report.states.len(), 1, "close 2 is still checked");
    }

    #[test]
    fn an_unreadable_member_is_a_finding() {
        use factum::container::zip64::read_archive;
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let mut file = std::fs::File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let entry = read_archive(&mut file, len)
            .unwrap()
            .get("factum/history/1/information.turtle.hashes")
            .unwrap()
            .clone();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[entry.header_offset as usize..entry.header_offset as usize + 4].copy_from_slice(b"XXXX");
        std::fs::write(&path, bytes).unwrap();
        let report = verify(&s, &path);
        assert!(
            codes(&report, Level::Fail).contains(&"turtle_hash"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn unsigned_states_are_a_warning() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        s.f.factum().reopen_container(id).unwrap();
        s.add(id, &[s.file("c.txt")]);
        let report = verify(&s, &s.container_path());
        assert_eq!(codes(&report, Level::Warn), vec!["not_signed"], "{:?}", report.findings);
        let warning = report.findings.iter().find(|f| f.code == "not_signed").unwrap();
        assert!(warning.message.contains("1 file"), "{}", warning.message);
    }

    #[test]
    fn live_file_replaced_by_an_older_copy_fails() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let copy = std::fs::read(s.container_path()).unwrap();
        let factum = s.f.factum();
        factum.reopen_container(id).unwrap();
        s.add(id, &[s.file("c.txt")]);
        factum.close_container(id).unwrap();
        std::fs::write(s.container_path(), copy).unwrap();
        let report = verify(&s, &s.container_path());
        assert!(
            codes(&report, Level::Fail).contains(&"log_mismatch"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn file_missing_from_container_is_log_mismatch() {
        let s = Setup::new();
        let id = s.create();
        let uuid = s.f.factum().container(id).unwrap().summary.uuid;
        let record = serde_json::json!({"arn": "aff4://ghost", "path": "ghost.txt", "size": 1, "md5": "", "sha1": "",
                                        "sha256": "", "metadata_only": false, "excerpt": null, "link": null});
        s.f.factum()
            .append(
                s.case_id,
                "system",
                "1 file added",
                Append {
                    payload: Some(
                        serde_json::json!({"event": "container_files_added", "case_id": s.case_id,
                                                     "container_id": uuid, "files": [record], "added_utc": "x"}),
                    ),
                    ..Default::default()
                },
            )
            .unwrap();
        let report = verify(&s, &s.container_path());
        let mismatch = report
            .findings
            .iter()
            .find(|f| f.code == "log_mismatch")
            .expect("a log mismatch");
        assert!(mismatch.message.contains("ghost.txt"), "{}", mismatch.message);
        assert_eq!(mismatch.level, Level::Fail);
    }

    #[test]
    fn untrusted_gpg_key_fails() {
        let s = Setup::with_signer(FakeSigner::with_trust(true, "TRUST_UNDEFINED"));
        closed_with_files(&s);
        let report = verify(&s, &s.container_path());
        assert!(
            codes(&report, Level::Fail).contains(&"key_untrusted"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn unsigned_close_is_fail_unsigned() {
        let s = Setup::with_signer(FakeSigner::new(false));
        closed_with_files(&s);
        let report = verify(&s, &s.container_path());
        assert_eq!(codes(&report, Level::Fail), vec!["unsigned"], "{:?}", report.findings);
        // a container never closed is not signed at all: a warning, so nobody reads ✓ as "signed"
        let t = Setup::with_signer(FakeSigner::new(false));
        let id = t.create();
        t.add(id, &[t.file("a.txt")]);
        let report = verify(&t, &t.container_path());
        assert_eq!(codes(&report, Level::Warn), vec!["not_signed"], "{:?}", report.findings);
        assert!(codes(&report, Level::Fail).is_empty());
    }

    #[test]
    fn trailing_bytes_are_a_warning_and_last_state_verifies() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let before = std::fs::read(&path).unwrap();
        let mut junk = before.clone();
        junk.extend(vec![7u8; 100_000]);
        std::fs::write(&path, &junk).unwrap();
        let report = verify(&s, &path);
        assert_eq!(report.discarded_tail, 100_000);
        assert_eq!(codes(&report, Level::Warn), vec!["trailing_data"]);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
        // verifying never repairs
        assert_eq!(std::fs::read(&path).unwrap().len(), junk.len());
    }

    #[test]
    fn not_a_container_is_reported() {
        let s = Setup::new();
        let path = s.f.path().join("text.aff4l");
        std::fs::write(&path, b"hello").unwrap();
        let report = verify(&s, &path);
        assert_eq!(report.format, ContainerFormat::NotAff4);
        assert_eq!(codes(&report, Level::Fail), vec!["not_aff4"]);
    }

    #[test]
    fn x509_untrusted_root_fails() {
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        let s = Setup::new();
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        home.trusted();
        s.f.db.set_setting(X509_CERT_SETTING, &home.leaf_fingerprint).unwrap();
        let gpgsm = Gpgsm::new(Some(home.path()));
        let close = s.f.factum().close_container_with(id, &gpgsm).unwrap();
        assert_eq!(
            close.x509.as_deref(),
            Some(home.leaf_fingerprint.as_str()),
            "{:?}",
            close.x509_refused
        );
        let check = |s: &Setup| {
            s.f.factum()
                .verify_container_file(&s.container_path(), &gpgsm, &|_, _| {}, &AtomicBool::new(false))
                .unwrap()
        };
        let report = check(&s);
        assert_eq!(report.overall(), Level::Ok, "{:?}", report.findings);
        assert!(report.states[0].x509.as_ref().is_some_and(|x| x.trusted));
        home.untrusted();
        let report = check(&s);
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "x509_untrusted")
            .expect("untrusted root");
        assert!(fail.message.contains(&home.root_fingerprint), "{}", fail.message);
    }
}

// --- verify_container.py, as a recipient runs it

mod script {
    use super::*;
    use factum::container::volume::VERIFY_CONTAINER_PY;
    use factum::container::x509::{Gpgsm, X509_CERT_SETTING};
    use factum::container::zip64::{Appender, read_archive};
    use factum::signer::{GnupgSigner, Signer as _};
    use factum::{Db, Factum};
    use std::process::Command;

    /// Extracts verify_container.py from the container and runs it there; None without python3.
    fn run(container: &Path, flags: &[&str], gnupg_home: Option<&Path>) -> Option<(i32, String)> {
        let python = which::which("python3").ok()?;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("verify_container.py");
        // from the container, as recipients do; from this build when the ZIP cannot be read (a damaged tail)
        let carried = member(container, "verify_container.py").unwrap_or_else(|| VERIFY_CONTAINER_PY.to_vec());
        std::fs::write(&script, carried).unwrap();
        let mut command = Command::new(python);
        command.arg("-I").arg(&script).arg(container).args(flags);
        if let Some(home) = gnupg_home {
            command.env("GNUPGHOME", home);
        }
        let output = command.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Some((output.status.code().unwrap_or(-1), text))
    }

    /// A container signed with a real gpg key: two closes, one file stored as an ImageStream.
    fn signed_container(dir: &tempfile::TempDir, home: &common::GpgHome) -> PathBuf {
        let db = Db::open(&dir.path().join("factum.db")).unwrap();
        let signer = GnupgSigner::new(&db, Some(home.path()));
        let key = signer.list_keys()[0].keyid.clone();
        assert!(signer.set_active_key(&db, &key));
        let factum = Factum::with_seal_dir(&db, &signer, Some(dir.path().to_path_buf()));
        let case_id = factum.create_case("C-1", "Case", "").unwrap();
        let source = dir.path().join("mnt");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("small.txt"), b"small").unwrap();
        std::fs::write(
            source.join("big.bin"),
            (0..200_000u32).map(|i| (i % 249) as u8).collect::<Vec<_>>(),
        )
        .unwrap();
        let path = dir.path().join("c.aff4l");
        let id = factum
            .create_container(case_id, "C", None, &path, &source.display().to_string())
            .unwrap();
        let options = AddOptions {
            base: source.clone(),
            keep_path: true,
            metadata_only: false,
            excerpt: None,
        };
        for (index, name) in ["small.txt", "big.bin"].iter().enumerate() {
            if index > 0 {
                factum.reopen_container(id).unwrap();
            }
            let mut volume = factum.open_container_for_add(id).unwrap();
            volume.segment_limit = 100_000;
            let staged = volume
                .stage_add(
                    &[source.join(name)],
                    &options,
                    &AddProgress::default(),
                    &AtomicBool::new(false),
                )
                .unwrap();
            factum.commit_container_add(id, &mut volume, staged).unwrap();
            drop(volume);
            factum.close_container(id).unwrap();
        }
        path
    }

    macro_rules! gpg_or_skip {
        () => {
            match common::GpgHome::new("Factum Test <test@factum.invalid>") {
                Some(home) => home,
                None => {
                    eprintln!("skipped: gpg is not installed");
                    return;
                }
            }
        };
    }

    #[test]
    fn script_runs_from_the_container() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        assert_eq!(
            member(&s.container_path(), "verify_container.py").unwrap(),
            VERIFY_CONTAINER_PY
        );
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            eprintln!("skipped: python3 is not installed");
            return;
        };
        // open and never closed: nothing has to be signed yet
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("\u{2713} 1 file(s) checked"), "{output}");
        assert!(output.contains("\u{26a0} The container was never closed"), "{output}");
    }

    #[test]
    fn script_reads_names_with_line_separators() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let odd = s.source.join("Users/x/in\u{2028}voice\u{85}.txt");
        std::fs::write(&odd, b"odd").unwrap();
        let id = s.create();
        s.add(id, &[odd]);
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("1 file(s) checked"), "{output}");
    }

    #[test]
    fn script_warns_about_a_long_interrupted_tail() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let mut bytes = std::fs::read(s.container_path()).unwrap();
        bytes.extend(vec![3u8; 100_000]);
        std::fs::write(s.container_path(), bytes).unwrap();
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("\u{26a0} 100000 bytes after the last complete state"),
            "{output}"
        );
        assert!(output.contains("1 file(s) checked"), "{output}");
    }

    #[test]
    fn script_reports_an_image_stream_without_size() {
        use factum::container::AFF4_NS;
        use factum::container::turtle::{self, Graph};
        use factum::container::zip64::{Appender, read_archive};
        let s = Setup::with_signer(FakeSigner::new(false));
        let big = s.source.join("big.bin");
        std::fs::write(&big, vec![7u8; 50_000]).unwrap();
        let id = s.create();
        let factum = s.f.factum();
        let mut volume = factum.open_container_for_add(id).unwrap();
        volume.segment_limit = 1000;
        let staged = volume
            .stage_add(&[big], &s.options(), &AddProgress::default(), &AtomicBool::new(false))
            .unwrap();
        let arn = staged.records[0].arn.clone();
        factum.commit_container_add(id, &mut volume, staged).unwrap();
        drop(volume);
        let path = s.container_path();
        let old = turtle::parse(&String::from_utf8(member(&path, TURTLE).unwrap()).unwrap()).unwrap();
        let mut graph = Graph::default();
        for t in old.triples() {
            if !(t.subject == arn && t.predicate == format!("{AFF4_NS}size")) {
                graph.add(&t.subject, &t.predicate, t.object.clone());
            }
        }
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let mut app = Appender::new(file, len, archive.entries).unwrap();
        app.add_bytes(TURTLE, 8, turtle::write(&graph, &turtle::factum_prefixes()).as_bytes())
            .unwrap();
        app.finish(&[], &archive.comment).unwrap();
        let Some((code, output)) = run(&path, &[], None) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(!output.contains("Traceback"), "{output}");
        assert!(output.contains("aff4:size"), "{output}");
    }

    #[test]
    fn script_passes_clean_container() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let Some((code, output)) = run(&path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("Close 1") && output.contains("Close 2 (current)"),
            "{output}"
        );
        assert!(output.contains("2 file(s) checked"), "{output}");
        assert!(!output.contains('\u{2717}'), "{output}");
        // with the key the container carries, in a keyring of its own
        let empty = tempfile::tempdir().unwrap();
        let Some((code, output)) = run(&path, &["--use-carried-key"], Some(empty.path())) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("Compare them with a trusted source"), "{output}");
    }

    #[test]
    fn script_fails_tampered_content() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let mut bytes = std::fs::read(&path).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let archive = read_archive(&mut file, bytes.len() as u64).unwrap();
        let bevy = archive
            .entries
            .iter()
            .find(|e| e.name_lossy().ends_with("/00000000"))
            .unwrap();
        bytes[bevy.header_offset as usize + 30 + bevy.name.len() + 20 + 5] ^= 0x01;
        std::fs::write(&path, bytes).unwrap();
        let Some((code, output)) = run(&path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(output.contains('\u{2717}'), "{output}");
    }

    #[test]
    fn script_fails_swapped_content_of_a_signed_close() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let graph = factum::container::turtle::parse(
            &String::from_utf8(member(&path, "factum/history/1/information.turtle").unwrap()).unwrap(),
        )
        .unwrap();
        let arn = factum::container::volume::file_records(&graph)[0].arn.clone();
        swap_content_and_drop_storage_type(&path, &arn);
        let Some((code, output)) = run(&path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("differs from the newest state") || output.contains("no stored content"),
            "{output}"
        );
    }

    #[test]
    fn script_fails_duplicate_member_names() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        duplicate_member(&path, "version.txt");
        let Some((code, output)) = run(&path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("listed more than once: version.txt"), "{output}");
    }

    #[test]
    fn script_fails_a_missing_closed_state() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        drop_history_1(&path);
        let Some((code, output)) = run(&path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("closed state 1 is missing"), "{output}");
        assert!(output.contains("Close 2 (current)"), "{output}");
    }

    #[test]
    fn script_fails_tampered_history() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let history = "factum/history/1/information.turtle";
        let edited = String::from_utf8(member(&path, history).unwrap())
            .unwrap()
            .replace("small", "large");
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let mut app = Appender::new(file, len, archive.entries).unwrap();
        app.add_bytes(history, 0, edited.as_bytes()).unwrap();
        app.finish(&[], &archive.comment).unwrap();
        let Some((code, output)) = run(&path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("\u{2717} close 1"), "{output}");
    }

    #[test]
    fn script_x509_with_and_without_ca() {
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        home.trusted();
        s.f.db.set_setting(X509_CERT_SETTING, &home.leaf_fingerprint).unwrap();
        let close =
            s.f.factum()
                .close_container_with(id, &Gpgsm::new(Some(home.path())))
                .unwrap();
        assert!(close.x509.is_some(), "{:?}", close.x509_refused);
        let root = home.file("root.pem");
        let Some((code, output)) = run(&s.container_path(), &["--ca", root.to_str().unwrap()], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("X.509 signature good, chain ends at your root"),
            "{output}"
        );
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(
            output.contains("\u{26a0} close 1 (current): root not checked against a trusted certificate"),
            "{output}"
        );
        // a root that is not the chain's own fails
        let other = tempfile::tempdir().unwrap();
        let other_root = other.path().join("other.pem");
        let made = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
            .arg(other.path().join("k"))
            .arg("-out")
            .arg(&other_root)
            .args(["-days", "1", "-subj", "/CN=Other Root"])
            .output()
            .unwrap();
        assert!(made.status.success());
        let Some((code, output)) = run(&s.container_path(), &["--ca", other_root.to_str().unwrap()], None) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
    }
}
