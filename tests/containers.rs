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

    /// What an Add leaves that dies before its finish: members after the newest state.
    fn interrupted_add(&self) {
        let source = self.file("interrupted.txt");
        std::fs::write(&source, vec![1u8; 100_000]).unwrap();
        let (mut volume, _) = Volume::open(&self.container_path(), None).unwrap();
        volume
            .stage_add(
                &[source],
                &self.options(),
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
    }

    fn create(&self) -> i64 {
        self.f
            .factum()
            .create_container(
                self.case_id,
                "FS01 preserved",
                self.evidence_id,
                &self.container_path(),
                &self.source.display().to_string(),
            )
            .unwrap()
    }

    fn options(&self) -> AddOptions {
        AddOptions {
            base: self.source.clone(),
            keep_path: true,
            ..Default::default()
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
    let member = factum::container::member_name(arn, &uuid);
    app.add_bytes(&member, 8, b"forged content").unwrap();
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
    let again = factum.create_container(s.case_id, "x", s.evidence_id, &s.container_path(), "/");
    assert!(again.is_err());
    let other = s.f.path().join("other.aff4l");
    assert!(factum.create_container(s.case_id, "x", 999, &other, "/").is_err());
    assert!(!other.exists());
    assert!(
        factum
            .create_container(s.case_id, "  ", s.evidence_id, &other, "/")
            .is_err()
    );
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
fn what_was_not_added_is_logged() {
    let s = Setup::new();
    let id = s.create();
    let factum = s.f.factum();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let staged = volume
        .stage_add(
            &[s.file("a.txt"), s.file("gone.txt")],
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let entry = factum.commit_container_add(id, &mut volume, staged).unwrap();
    assert_eq!(
        s.entry_text(entry),
        format!("1 file added to container #{id} (1 B) · 1 not added")
    );
    let not_added = s.events("container_files_added")[0]["not_added"].clone();
    assert_eq!(not_added.as_array().unwrap().len(), 1);
    assert!(
        not_added[0]["path"].as_str().unwrap().ends_with("gone.txt"),
        "{not_added}"
    );
    assert!(not_added[0]["reason"].is_string());
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
        format!("Container #{id} closed · 2 files · re-checked · signed")
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
        format!("Container #{id} closed · 1 files · re-checked · unsigned")
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
                .create_container(
                    s.case_id,
                    name,
                    s.evidence_id,
                    &s.f.path().join(format!("{name}.aff4l")),
                    "/",
                )
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
            .create_container(s.case_id, "Other", s.evidence_id, &s.f.path().join("other.aff4l"), "/")
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
    factum
        .create_container(s.case_id, "Other", s.evidence_id, &other, "/")
        .unwrap();
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
    let (mut volume, _) = Volume::open(&s.container_path(), None).unwrap();
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
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    assert!(s.f.factum().compare_with_log(id, &volume).unwrap().is_empty());
}

#[test]
fn crash_after_close_before_log_commit_is_set_aside() {
    use factum::container::volume::Signatures;
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let (mut volume, _) = Volume::open(&s.container_path(), None).unwrap();
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
    let committed = std::fs::metadata(s.container_path()).unwrap().len();
    s.interrupted_add();
    assert!(std::fs::metadata(s.container_path()).unwrap().len() > committed);
    s.add(id, &[s.file("b.txt")]);
    assert_eq!(s.f.factum().container(id).unwrap().summary.file_count, 2);
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
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
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    assert!(s.f.factum().compare_with_log(id, &volume).unwrap().is_empty());
    drop(volume);
    // a folder the log does not record is a difference
    s.f.exec("UPDATE entries SET payload_json = replace(payload_json, '\"folders\":[{', '\"folders\":[],\"x\":[{')");
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
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
        let entry = read_archive(&mut file, len).unwrap().get_arn(&arn).unwrap().clone();
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
    fn a_member_that_fails_its_crc_is_a_failure() {
        use std::io::{Seek, SeekFrom, Write};
        let s = Setup::new();
        let id = closed_with_files(&s);
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        let path = s.container_path();
        let mut file = std::fs::File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let good = std::fs::read(&path).unwrap();
        let base = verify(&s, &path);
        // the CRC field of each central entry: the content is as it was, so every verdict but that stays
        for (entry, code) in [
            (archive.get_arn(&arn).unwrap(), "stream_hash"),
            (archive.get("factum/history/1/information.turtle").unwrap(), "history"),
            (
                archive.get("factum/history/1/information.turtle.hashes").unwrap(),
                "turtle_hash",
            ),
            (archive.get("information.turtle").unwrap(), "turtle_hash"),
            (archive.get("version.txt").unwrap(), "history"),
            (archive.get("container.description").unwrap(), "history"),
        ] {
            std::fs::write(&path, &good).unwrap();
            // the name as the directory has it: followed by the ZIP64 extra
            let name = [entry.name.as_slice(), &[1, 0, 24, 0]].concat();
            let name_at = good
                .windows(name.len())
                .enumerate()
                .rev()
                .find(|(at, w)| *w == name && good[at - 46..at - 42] == *b"PK\x01\x02")
                .unwrap()
                .0 as u64;
            let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(name_at - 46 + 16)).unwrap();
            file.write_all(&(entry.crc32 ^ 1).to_le_bytes()).unwrap();
            let report = verify(&s, &path);
            let fails: Vec<_> = report.findings.iter().filter(|f| f.level == Level::Fail).collect();
            assert_eq!(fails.len(), 1, "{fails:?}");
            assert_eq!(fails[0].code, code);
            assert!(fails[0].message.contains("CRC-32 differs"), "{}", fails[0].message);
            assert_eq!(report.checked_files, base.checked_files);
            assert_eq!(report.format, base.format);
            assert_eq!(report.states.len(), base.states.len());
            assert_eq!(codes(&report, Level::Warn), codes(&base, Level::Warn));
        }
    }

    #[test]
    fn a_damaged_member_is_told_by_its_digest_and_by_its_crc() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let name = "factum/history/1/information.turtle.hashes";
        let hashes = member(&path, name).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let entry = read_archive(&mut file, len).unwrap().get(name).unwrap().clone();
        assert_eq!(entry.method, 0);
        // one digit of the SHA-256 in a stored member, read back in full by the check
        let digit = hashes
            .windows(64)
            .position(|w| w.iter().all(u8::is_ascii_hexdigit))
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let header = entry.header_offset as usize;
        let data = header + 30 + name.len() + 20;
        bytes[data + digit] = if bytes[data + digit] == b'0' { b'1' } else { b'0' };
        std::fs::write(&path, bytes).unwrap();
        let report = verify(&s, &path);
        let messages: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.level == Level::Fail)
            .map(|f| f.message.as_str())
            .collect();
        assert!(messages.iter().any(|m| m.contains("CRC-32 differs")), "{messages:?}");
        assert!(
            messages.iter().any(|m| m.contains("does not match its SHA256")),
            "{messages:?}"
        );
    }

    #[test]
    fn an_unreadable_information_turtle_is_one_failure() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let mut file = std::fs::File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let entry = read_archive(&mut file, len).unwrap().get(TURTLE).unwrap().clone();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[entry.header_offset as usize + 30] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let report = verify(&s, &path);
        let turtle: Vec<_> = report.findings.iter().filter(|f| f.message.contains(TURTLE)).collect();
        assert_eq!(turtle.len(), 1, "{turtle:?}");
        assert!(turtle[0].message.contains("cannot be read"), "{}", turtle[0].message);
    }

    #[test]
    fn an_entry_hidden_behind_a_lowered_count_fails() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let mut bytes = std::fs::read(&path).unwrap();
        let record = bytes.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap();
        let count = u64::from_le_bytes(bytes[record + 32..record + 40].try_into().unwrap()) - 1;
        bytes[record + 24..record + 32].copy_from_slice(&count.to_le_bytes());
        bytes[record + 32..record + 40].copy_from_slice(&count.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let report = verify(&s, &path);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.level == Level::Fail && f.code == "trailing_data"),
            "{:?}",
            report.findings
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn a_local_header_that_differs_from_the_directory_fails() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        let path = s.container_path();
        let mut file = std::fs::File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let good = std::fs::read(&path).unwrap();
        for (entry, code) in [
            (archive.get_arn(&arn).unwrap(), "stream_hash"),
            (archive.get("factum/history/1/information.turtle").unwrap(), "history"),
            (archive.get("version.txt").unwrap(), "history"),
        ] {
            let mut bytes = good.clone();
            // the first letter of its name
            bytes[entry.header_offset as usize + 30] ^= 1;
            std::fs::write(&path, bytes).unwrap();
            let report = verify(&s, &path);
            assert!(codes(&report, Level::Fail).contains(&code), "{:?}", report.findings);
        }
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
    fn progress_never_passes_the_total() {
        let s = Setup::new();
        let id = s.create();
        let factum = s.f.factum();
        let mut volume = factum.open_container_for_add(id).unwrap();
        let options = AddOptions {
            metadata_only: true,
            ..s.options()
        };
        let staged = volume
            .stage_add(
                &[s.file("d.txt")],
                &options,
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        factum.commit_container_add(id, &mut volume, staged).unwrap();
        drop(volume);
        s.add(id, &[s.file("a.txt")]);
        let seen = std::cell::RefCell::new(Vec::new());
        factum
            .verify_container_file(
                &s.container_path(),
                &Gpgsm::unavailable(),
                &|done, total| seen.borrow_mut().push((done, total)),
                &AtomicBool::new(false),
            )
            .unwrap();
        let seen = seen.into_inner();
        assert!(!seen.is_empty());
        // one stored byte; the metadata-only file's four bytes are not read
        assert!(
            seen.iter().all(|&(done, total)| total == 1 && done <= total),
            "{seen:?}"
        );
    }

    #[test]
    fn duplicate_member_names_fail() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        let member = factum::container::member_name(&arn, "");
        duplicate_member(&s.container_path(), &member);
        let report = verify(&s, &s.container_path());
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "duplicate_member")
            .expect("a duplicate finding");
        assert!(fail.message.contains(&member), "{}", fail.message);
    }

    /// One byte of a file flipped, and what should tell who wrote the container gone with it: the file is still
    /// checked, and against the log as well.
    #[test]
    fn a_signed_container_without_version_txt_is_still_checked() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let path = s.container_path();
        damage_content(&path, &s.f.factum().container(id).unwrap().adds[0].files[0].arn);
        rewrite(&path, &[], &["version.txt"]);
        let report = verify(&s, &path);
        let fails = codes(&report, Level::Fail);
        assert!(
            fails.contains(&"unsupported") && fails.contains(&"stream_hash"),
            "{fails:?}"
        );
        assert_eq!(report.format, ContainerFormat::Factum);
        assert!(report.log.is_some());
        assert_eq!(report.states.len(), 1);
    }

    fn log_mismatch(report: &ContainerReport) -> bool {
        report
            .findings
            .iter()
            .any(|f| f.level == Level::Fail && f.code == "log_mismatch")
    }

    /// What a file says it is cannot keep it from the log at the place the log has for it.
    #[test]
    fn at_its_logged_place_a_file_cannot_name_itself_out_of_the_log() {
        let other: &[u8] = b"aff4://11111111-2222-4333-8444-555555555555";
        for description in [other, b""] {
            let s = Setup::new();
            closed_with_files(&s);
            let path = s.container_path();
            rewrite(&path, &[("container.description", description)], &[]);
            let report = verify(&s, &path);
            assert!(log_mismatch(&report), "{:?}", report.findings);
            assert!(report.log.is_none());
        }
    }

    /// Swaps a file, gives it matching hashes, and takes the closes, the signatures and the uuid away.
    fn forged(s: &Setup) -> PathBuf {
        use factum::container::volume::file_records;
        let path = s.container_path();
        let text = String::from_utf8(member(&path, TURTLE).unwrap()).unwrap();
        let graph = factum::container::turtle::parse(&text).unwrap();
        let record = file_records(&graph).remove(0);
        let uuid = String::from_utf8(member(&path, "container.description").unwrap()).unwrap();
        let name = factum::container::member_name(&record.arn, &uuid);
        let new = b"z";
        let other = "aff4://11111111-2222-4333-8444-555555555555";
        let forged = text
            .replace(&record.md5, &hex::encode(md5::Md5::digest(new)))
            .replace(&record.sha1, &hex::encode(sha1::Sha1::digest(new)))
            .replace(&record.sha256, &hex::encode(sha2::Sha256::digest(new)));
        rewrite(&path, &[(name.as_str(), new)], &[]);
        write_turtle(&path, &forged.replace(&uuid, other));
        rewrite(&path, &[("container.description", other.as_bytes())], &[]);
        without_layout(&path, &[]);
        path
    }

    #[test]
    fn a_forged_file_at_a_logged_place_fails_and_nowhere_passes_as_good() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = forged(&s);
        let report = verify(&s, &path);
        assert!(log_mismatch(&report), "{:?}", report.findings);
        // elsewhere nothing is expected of it, and it is simply an unsigned file
        let copy = s.f.path().join("handed-over.aff4l");
        std::fs::rename(&path, &copy).unwrap();
        let report = verify(&s, &copy);
        assert!(!log_mismatch(&report), "{:?}", report.findings);
        assert_eq!(report.overall(), Level::Warn, "{:?}", report.findings);
        assert!(
            codes(&report, Level::Warn).contains(&"not_signed"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn a_file_asked_for_as_a_container_has_to_be_it() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let copy = s.f.path().join("elsewhere.aff4l");
        std::fs::copy(s.container_path(), &copy).unwrap();
        let expect = |path: &Path, expected| {
            s.f.factum()
                .verify_expected_container(
                    path,
                    expected,
                    &Gpgsm::unavailable(),
                    &|_, _| {},
                    &AtomicBool::new(false),
                )
                .unwrap()
        };
        // the right file, wherever it is
        let report = expect(&copy, Some(id));
        assert!(!log_mismatch(&report) && report.log.is_some(), "{:?}", report.findings);
        // nothing expected: any container, and any file
        rewrite(&copy, &[("container.description", b"aff4://other")], &[]);
        assert!(!log_mismatch(&expect(&copy, None)));
        // asked for: not this one
        let report = expect(&copy, Some(id));
        assert!(log_mismatch(&report), "{:?}", report.findings);
        assert!(report.log.is_none());
    }

    #[test]
    fn a_signed_file_in_a_format_nobody_reads_fails_with_the_log_too() {
        let s = Setup::new();
        let id = closed_with_files(&s);
        let path = s.container_path();
        let arn = s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone();
        damage_content(&path, &arn);
        let entry = directory_entry(&path, |archive| archive.get_arn(&arn));
        let mut bytes = std::fs::read(&path).unwrap();
        let listed = [entry.name.as_slice(), &[1, 0, 24, 0]].concat();
        let at = bytes.windows(listed.len()).rposition(|w| w == listed).unwrap();
        bytes[at - 46 + 10] = 99;
        bytes[entry.header_offset as usize + 8] = 99;
        std::fs::write(&path, bytes).unwrap();
        let report = verify(&s, &path);
        assert!(
            codes(&report, Level::Fail).contains(&"stream_hash"),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn a_forged_tool_line_with_the_signatures_gone_fails_unsigned() {
        use factum::container::volume::{KEY_GPG, SIGNATURE_MEMBERS};
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let kept = [SIG_GPG, KEY_GPG].map(|name| history_member(1, name));
        let omit: Vec<&str> = kept.iter().map(String::as_str).chain(SIGNATURE_MEMBERS).collect();
        rewrite(&path, &[("version.txt", b"major=2\nminor=1\ntool=other 1.0\n")], &omit);
        let report = verify(&s, &path);
        assert!(
            codes(&report, Level::Fail).contains(&"unsigned"),
            "{:?}",
            report.findings
        );
        assert_eq!(report.format, ContainerFormat::Factum);
    }

    #[test]
    fn without_container_description_the_file_fails_and_the_log_is_still_compared() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        rewrite(&path, &[], &["container.description"]);
        let report = verify(&s, &path);
        assert!(
            codes(&report, Level::Fail).contains(&"history"),
            "{:?}",
            report.findings
        );
        assert!(report.log.is_some());
    }

    #[test]
    fn a_file_stripped_of_all_signs_of_factum_still_meets_the_log() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        without_layout(&path, &["version.txt"]);
        let report = verify(&s, &path);
        assert_eq!(report.format, ContainerFormat::Legacy);
        assert!(
            codes(&report, Level::Fail).contains(&"log_mismatch"),
            "{:?}",
            report.findings
        );
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
    fn an_interrupted_addition_is_a_warning_and_last_state_verifies() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let before = std::fs::metadata(&path).unwrap().len();
        s.interrupted_add();
        let after = std::fs::read(&path).unwrap();
        assert!(after.len() as u64 > before);
        let report = verify(&s, &path);
        assert_eq!(report.discarded_tail, after.len() as u64 - before);
        assert_eq!(codes(&report, Level::Warn), vec!["trailing_data"]);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
        // verifying never repairs
        assert_eq!(std::fs::read(&path).unwrap(), after);
    }

    #[test]
    fn bytes_no_addition_leaves_fail_and_last_state_verifies() {
        let s = Setup::new();
        closed_with_files(&s);
        let path = s.container_path();
        let mut junk = std::fs::read(&path).unwrap();
        junk.extend(vec![7u8; 100_000]);
        std::fs::write(&path, &junk).unwrap();
        let report = verify(&s, &path);
        assert_eq!(report.discarded_tail, 100_000);
        assert_eq!(codes(&report, Level::Fail), vec!["trailing_data"]);
        assert_eq!(report.states.iter().filter(|s| s.close.is_some()).count(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), junk);
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
        let recheck = s.f.factum().recheck_container(id).unwrap();
        let close = s.f.factum().close_container_with(id, &gpgsm, &recheck).unwrap();
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

    /// Closes a container of this case with the test certificate.
    fn x509_closed(s: &Setup, home: &common::GpgsmHome, gpgsm: &Gpgsm) -> i64 {
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        home.trusted();
        s.f.db.set_setting(X509_CERT_SETTING, &home.leaf_fingerprint).unwrap();
        let recheck = s.f.factum().recheck_container(id).unwrap();
        let close = s.f.factum().close_container_with(id, gpgsm, &recheck).unwrap();
        assert!(close.x509.is_some(), "{:?}", close.x509_refused);
        id
    }

    /// A container outside any log, closed with an X.509 signature and `chain` beside it.
    pub(super) fn loose_container(s: &Setup, gpgsm: &Gpgsm, home: &common::GpgsmHome, chain: Option<&str>) -> PathBuf {
        home.trusted();
        loose_signed(s, &|turtle| {
            let (signature, own_chain) = gpgsm.sign_with_chain(&home.leaf_fingerprint, turtle, &[]).unwrap();
            (signature, chain.map_or(own_chain, str::to_string))
        })
    }

    /// A container outside any log, closed with the (signature, chain) `sign` makes of its metadata.
    pub(super) fn loose_signed(s: &Setup, sign: &dyn Fn(&[u8]) -> (String, String)) -> PathBuf {
        use factum::container::volume::{Signatures, VolumeInfo};
        let path = s.f.path().join("loose.aff4l");
        let _ = std::fs::remove_file(&path);
        let info = VolumeInfo::default();
        let mut volume = Volume::create(&path, "44444444-4444-4444-4444-444444444444", &info).unwrap();
        let options = AddOptions {
            base: s.source.clone(),
            keep_path: true,
            ..Default::default()
        };
        let staged = volume
            .stage_add(
                &[s.file("a.txt")],
                &options,
                &AddProgress::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
        volume.finalize_add(&staged, 1).unwrap();
        let (signature, chain) = sign(&volume.member(TURTLE).unwrap());
        let signatures = Signatures {
            gpg: None,
            x509: Some((signature, chain)),
        };
        volume.close(&signatures).unwrap();
        path
    }

    fn verify_with(s: &Setup, path: &Path, gpgsm: &Gpgsm) -> ContainerReport {
        s.f.factum()
            .verify_container_file(path, gpgsm, &|_, _| {}, &AtomicBool::new(false))
            .unwrap()
    }

    #[test]
    fn x509_signature_by_another_certificate_than_the_stored_one_fails() {
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let path = loose_container(&s, &gpgsm, &home, None);
        let report = verify_with(&s, &path, &gpgsm);
        assert!(
            !codes(&report, Level::Fail).contains(&"x509_mismatch"),
            "{:?}",
            report.findings
        );
        // the signature chains to the trusted root all the same: only the comparison finds this
        let root = std::fs::read_to_string(home.file("root.pem")).unwrap();
        let path = loose_container(&s, &gpgsm, &home, Some(&root));
        let report = verify_with(&s, &path, &gpgsm);
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "x509_mismatch")
            .expect("a mismatch");
        assert_eq!(fail.level, Level::Fail);
        assert!(fail.message.contains(&home.leaf_fingerprint), "{}", fail.message);
        assert!(fail.message.contains(&home.root_fingerprint), "{}", fail.message);
        assert!(report.states[0].x509.as_ref().is_some_and(|x| x.valid && x.trusted));
        // a chain nothing can be read from says no more than a wrong one
        let path = loose_container(&s, &gpgsm, &home, Some("not a certificate"));
        assert!(codes(&verify_with(&s, &path, &gpgsm), Level::Fail).contains(&"x509_mismatch"));
    }

    #[test]
    fn x509_signature_without_a_stored_certificate_is_a_warning() {
        use factum::container::volume::{CER_X509, SIG_X509};
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let path = loose_container(&s, &gpgsm, &home, None);
        // as a container with the certificates left out of the directory reads
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let history_chain = history_member(1, CER_X509);
        let app = &mut Appender::new(file, len, archive.entries.clone()).unwrap();
        app.finish(&[CER_X509, &history_chain], &archive.comment).unwrap();
        let report = verify_with(&s, &path, &gpgsm);
        assert!(
            !codes(&report, Level::Fail).contains(&"x509_mismatch"),
            "{:?}",
            report.findings
        );
        assert!(
            codes(&report, Level::Warn).contains(&"x509_no_certificate"),
            "{:?}",
            report.findings
        );
        assert_eq!(member(&path, CER_X509), None);
        assert!(member(&path, SIG_X509).is_some());
        assert!(report.states[0].x509.as_ref().is_some_and(|x| x.fingerprint.is_some()));
    }

    #[test]
    fn x509_certificate_expired_since_is_a_warning_that_names_what_it_rests_on() {
        let Some(home) = common::GpgsmHome::with_expired_leaf() else {
            eprintln!("skipped: no gpgsm, or an openssl without -not_before");
            return;
        };
        home.trusted();
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let chain = gpgsm.chain(&home.leaf_fingerprint, &[]).unwrap();
        let path = loose_signed(&s, &|turtle| (home.sign_while_valid(turtle), chain.clone()));
        let report = verify_with(&s, &path, &gpgsm);
        assert!(codes(&report, Level::Fail).is_empty(), "{:?}", report.findings);
        let warning = report
            .findings
            .iter()
            .find(|f| f.code == "x509_expired")
            .expect("a warning");
        assert_eq!(warning.level, Level::Warn);
        assert!(
            warning.message.contains("signing time the signer stated"),
            "{}",
            warning.message
        );
        let check = report.states[0].x509.as_ref().unwrap();
        assert!(check.status.contains("has expired"), "{}", check.status);
    }

    #[test]
    fn x509_certificate_other_than_the_logged_one_fails() {
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let _id = x509_closed(&s, &home, &gpgsm);
        let path = s.container_path();
        assert_eq!(verify_with(&s, &path, &gpgsm).overall(), Level::Ok);
        s.f.exec(&format!(
            "UPDATE entries SET payload_json = replace(payload_json, '{}', '{}')",
            home.leaf_fingerprint, home.root_fingerprint
        ));
        let report = verify_with(&s, &path, &gpgsm);
        let fail = report
            .findings
            .iter()
            .find(|f| f.code == "log_mismatch")
            .expect("a mismatch");
        assert_eq!(fail.level, Level::Fail);
        assert!(fail.message.contains(&home.leaf_fingerprint), "{}", fail.message);
        assert!(fail.message.contains(&home.root_fingerprint), "{}", fail.message);
        assert!(!codes(&report, Level::Fail).contains(&"x509_mismatch"));
    }

    #[test]
    fn x509_certificate_of_a_late_signature_is_compared_with_the_log_too() {
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let id = x509_closed(&s, &home, &gpgsm);
        let detail = s.f.factum().container(id).unwrap();
        // the log as a close without signatures, signed later by what `logged` names
        s.f.exec(&format!(
            "UPDATE entries SET payload_json = replace(payload_json, '\"gpg\":\"{0}\"', '\"gpg\":null') \
             WHERE payload_json LIKE '%container_closed%'",
            detail.closes[0].gpg.as_deref().unwrap_or_default()
        ));
        s.f.exec(&format!(
            "UPDATE entries SET payload_json = replace(payload_json, '\"x509\":\"{}\"', '\"x509\":null') \
             WHERE payload_json LIKE '%container_closed%'",
            home.leaf_fingerprint
        ));
        let sign_later = |logged: &str| {
            let payload = serde_json::json!({"event": "container_signed", "case_id": s.case_id,
                                             "container_id": detail.summary.uuid, "close": 1,
                                             "turtle_sha256": detail.closes[0].turtle_sha256,
                                             "signatures": {"gpg": null, "x509": logged}, "signed_utc": "x"});
            let append = Append {
                payload: Some(payload),
                ..Default::default()
            };
            s.f.factum().append(s.case_id, "system", "signed", append).unwrap();
        };
        sign_later(&home.root_fingerprint);
        assert!(s.f.factum().container(id).unwrap().closes[0].signed_later.is_some());
        let path = s.container_path();
        let report = verify_with(&s, &path, &gpgsm);
        let mismatch = report
            .findings
            .iter()
            .find(|f| f.code == "log_mismatch")
            .expect("a mismatch");
        assert!(
            mismatch.message.contains(&home.root_fingerprint),
            "{}",
            mismatch.message
        );
    }
}

// --- verify_container.py, as a recipient runs it

mod script {
    use super::*;
    use factum::container::verify::verify_file;
    use factum::container::volume::VERIFY_CONTAINER_PY;
    use factum::container::x509::{Gpgsm, X509_CERT_SETTING};
    use factum::container::zip64::{Appender, read_archive};
    use factum::signer::{GnupgSigner, Signer as _};
    use factum::verifier::Level;
    use factum::{Db, Factum};
    use std::process::Command;

    /// Extracts verify_container.py from the container and runs it there; None without python3.
    fn run(container: &Path, flags: &[&str], gnupg_home: Option<&Path>) -> Option<(i32, String)> {
        // from the container, as recipients do; from this build when the ZIP cannot be read (a damaged tail)
        let carried = member(container, "verify_container.py").unwrap_or_else(|| VERIFY_CONTAINER_PY.to_vec());
        run_script(&carried, container, flags, gnupg_home)
    }

    fn run_script(source: &[u8], container: &Path, flags: &[&str], gnupg_home: Option<&Path>) -> Option<(i32, String)> {
        let python = which::which("python3").ok()?;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("verify_container.py");
        std::fs::write(&script, source).unwrap();
        let mut command = Command::new(python);
        // UTF-8 output whatever the console's code page (Windows pipes default to it), so the ✓ ⚠ ✗ are checked
        command
            .args(["-I", "-X", "utf8"])
            .arg(&script)
            .arg(container)
            .args(flags);
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

    #[test]
    fn verify_container_py_warns_on_replaced_copy() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let (id, recheck) = damaged(&s);
        add_again(&s, id, &recheck);
        s.f.factum().close_container(id).unwrap();
        // unsigned (a fake key): the signature check fails, the content checks are what is looked at here
        let Some((_, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert!(
            output
                .lines()
                .any(|l| l.starts_with('⚠') && l.contains("replaced by a copy added again")),
            "{output}"
        );
        assert!(
            !output
                .lines()
                .any(|l| l.starts_with('✗') && l.contains("does not match")),
            "{output}"
        );
    }

    #[test]
    fn verify_container_py_fails_a_replacement_with_other_content() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let (id, _) = damaged(&s);
        let detail = s.f.factum().container(id).unwrap();
        add_triple(
            &s.container_path(),
            &detail.adds[0].files[0].arn,
            &format!("{}replacedBy", factum::container::FACTUM_NS),
            &detail.adds[0].files[1].arn,
        );
        let Some((_, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert!(
            output
                .lines()
                .any(|l| l.starts_with('✗') && l.contains("different content")),
            "{output}"
        );
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
            .create_container(
                case_id,
                "C",
                factum.create_evidence(case_id, "disk", "", "").unwrap(),
                &path,
                &source.display().to_string(),
            )
            .unwrap();
        let options = AddOptions {
            base: source.clone(),
            keep_path: true,
            metadata_only: false,
            excerpt: None,
            replaces: Vec::new(),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn script_reads_the_raw_form_of_paths_that_are_not_unicode() {
        let s = Setup::with_signer(FakeSigner::new(false));
        added_from_a_path_that_is_not_unicode(&s);
        assert!(turtle_text(&s.container_path()).contains("sourcePathRaw"));
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("2 file(s) checked"), "{output}");
    }

    #[test]
    fn script_warns_about_an_interrupted_addition() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        s.interrupted_add();
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(
            output
                .lines()
                .any(|l| l.starts_with('\u{26a0}') && l.contains("bytes after the last complete state")),
            "{output}"
        );
        assert!(output.contains("[trailing_data]"), "{output}");
        assert!(output.contains("1 file(s) checked"), "{output}");
    }

    #[test]
    fn script_fails_bytes_no_addition_leaves() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let mut bytes = std::fs::read(s.container_path()).unwrap();
        bytes.extend(vec![3u8; 100_000]);
        std::fs::write(s.container_path(), bytes).unwrap();
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("\u{2717} 100000 bytes after the last complete state"),
            "{output}"
        );
        assert!(output.contains("[trailing_data]"), "{output}");
        // the last complete state is still checked
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
    fn script_fails_a_malformed_x509_signature_without_a_traceback() {
        if Command::new("openssl").arg("version").output().is_err() {
            eprintln!("skipped: openssl is not installed");
            return;
        }
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        s.f.factum().close_container(id).unwrap();
        let path = s.container_path();
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let archive = read_archive(&mut file, len).unwrap();
        let mut app = Appender::new(file, len, archive.entries).unwrap();
        let signature = "-----BEGIN SIGNED MESSAGE-----\nnot base64 at all!\n-----END SIGNED MESSAGE-----\n";
        let chain = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        app.add_bytes(
            &history_member(1, "information.turtle.factum.sig"),
            0,
            signature.as_bytes(),
        )
        .unwrap();
        app.add_bytes(&history_member(1, "information.turtle.factum.cer"), 0, chain.as_bytes())
            .unwrap();
        app.finish(&[], &archive.comment).unwrap();
        let Some((code, output)) = run(&path, &[], None) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(!output.contains("Traceback"), "{output}");
        assert!(output.contains("the X.509 signature cannot be read"), "{output}");
        // the files were still checked
        assert!(output.contains("1 file(s) checked"), "{output}");
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
                .close_container_with(
                    id,
                    &Gpgsm::new(Some(home.path())),
                    &s.f.factum().recheck_container(id).unwrap(),
                )
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

    // --- verify_container.py and factum's verifier on the same files. factum's verifier also runs here without the
    // case log: what only the log can tell is left out, as a recipient of the container does not have it either.

    /// The verdict of this build's script, run as a recipient runs it; None without python3.
    fn script_verdict(path: &Path, flags: &[&str], gnupg_home: Option<&Path>) -> Option<(Level, String)> {
        let (code, output) = run_script(VERIFY_CONTAINER_PY, path, flags, gnupg_home)?;
        assert!(!output.contains("Traceback"), "{output}");
        let level = match code {
            0 if output.contains(", 0 warning(s)") => Level::Ok,
            0 => Level::Warn,
            1 => Level::Fail,
            other => panic!("exit code {other}: {output}"),
        };
        Some((level, output))
    }

    /// Both verifiers on `path`: the same verdict, the one expected, and `code` (empty: none asked for) among the
    /// findings of both. Returns false without python3.
    fn assert_verdict(
        what: &str,
        path: &Path,
        expected: Level,
        code: &str,
        verifiers: (&dyn factum::signer::Signer, &Gpgsm),
        flags: &[&str],
        gnupg_home: Option<&Path>,
    ) -> bool {
        let (signer, gpgsm) = verifiers;
        let report = verify_file(path, signer, gpgsm, &|_, _| {}, &AtomicBool::new(false)).unwrap();
        let Some((level, output)) = script_verdict(path, flags, gnupg_home) else {
            eprintln!("skipped: python3 is not installed");
            return false;
        };
        let findings = &report.findings;
        assert_eq!(report.overall(), expected, "{what}: factum: {findings:?}");
        assert_eq!(level, expected, "{what}: the script: {output}\nfactum: {findings:?}");
        if !code.is_empty() {
            assert!(findings.iter().any(|f| f.code == code), "{what}: {code}: {findings:?}");
            assert!(output.contains(&format!("[{code}]")), "{what}: {code}: {output}");
        }
        true
    }

    /// Where the directory of the newest state lists `name`.
    fn directory_at(bytes: &[u8], name: &str) -> usize {
        // the name as the directory has it: followed by the ZIP64 extra
        let listed = [name.as_bytes(), &[1, 0, 24, 0]].concat();
        let at = bytes
            .windows(listed.len())
            .enumerate()
            .rev()
            .find(|(at, w)| *w == listed && bytes[at - 46..at - 42] == *b"PK\x01\x02");
        at.unwrap().0 - 46
    }

    fn entry_of(path: &Path, name: &str) -> factum::container::zip64::CdEntry {
        directory_entry(path, |archive| archive.get(name))
    }

    fn flip_crc(path: &Path, name: &str) {
        let mut bytes = std::fs::read(path).unwrap();
        let listed = directory_at(&bytes, name);
        bytes[listed + 16] ^= 1;
        std::fs::write(path, bytes).unwrap();
    }

    /// Flips one byte of a member's stored data; the directory stays as it was.
    fn flip_data(path: &Path, name: &str) {
        let entry = entry_of(path, name);
        let mut bytes = std::fs::read(path).unwrap();
        bytes[entry.header_offset as usize + 30 + name.len() + 20 + entry.compressed_size as usize / 2] ^= 0x55;
        std::fs::write(path, bytes).unwrap();
    }

    /// A compression method nobody reads, in the local header and the directory alike.
    fn set_method(path: &Path, name: &str) {
        let entry = entry_of(path, name);
        let mut bytes = std::fs::read(path).unwrap();
        let listed = directory_at(&bytes, name);
        bytes[listed + 10] = 99;
        bytes[entry.header_offset as usize + 8] = 99;
        std::fs::write(path, bytes).unwrap();
    }

    fn differ_local_header(path: &Path, name: &str) {
        let entry = entry_of(path, name);
        let mut bytes = std::fs::read(path).unwrap();
        bytes[entry.header_offset as usize + 30] ^= 1;
        std::fs::write(path, bytes).unwrap();
    }

    /// The entry count of the end records, moved by `by`: the directory then holds more or less than it says.
    fn change_count(path: &Path, by: i64) {
        let mut bytes = std::fs::read(path).unwrap();
        let record = bytes.windows(4).rposition(|w| w == b"PK\x06\x06").unwrap();
        let count = u64::from_le_bytes(bytes[record + 32..record + 40].try_into().unwrap());
        let count = count.checked_add_signed(by).unwrap();
        bytes[record + 24..record + 32].copy_from_slice(&count.to_le_bytes());
        bytes[record + 32..record + 40].copy_from_slice(&count.to_le_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    fn append(path: &Path, tail: &[u8]) {
        let mut bytes = std::fs::read(path).unwrap();
        bytes.extend(tail);
        std::fs::write(path, bytes).unwrap();
    }

    fn cut(path: &Path, count: usize) {
        let bytes = std::fs::read(path).unwrap();
        std::fs::write(path, &bytes[..bytes.len() - count]).unwrap();
    }

    fn turtle_text(path: &Path) -> String {
        String::from_utf8(member(path, TURTLE).unwrap()).unwrap()
    }

    /// The ARN and the member of the file stored as a ZipSegment, and the first bevy of the ImageStream.
    fn stored_names(path: &Path) -> (String, String, String) {
        let graph = factum::container::turtle::parse(&turtle_text(path)).unwrap();
        let small = factum::container::volume::file_records(&graph)
            .into_iter()
            .find(|r| r.path.ends_with("small.txt"))
            .unwrap();
        let uuid = String::from_utf8(member(path, "container.description").unwrap()).unwrap();
        let small_member = factum::container::member_name(&small.arn, &uuid);
        let mut file = std::fs::File::open(path).unwrap();
        let len = file.metadata().unwrap().len();
        let bevy = read_archive(&mut file, len)
            .unwrap()
            .entries
            .iter()
            .map(|e| e.name_lossy())
            .find(|n| n.ends_with("/00000000"))
            .unwrap();
        (small.arn, small_member, bevy)
    }

    /// Stands in for an ARN: the same IRI with its last character written as an escape.
    fn escaped_last_character(arn: &str) -> String {
        let (start, last) = arn.split_at(arn.len() - 1);
        format!("{start}\\u{:04X}", last.chars().next().unwrap() as u32)
    }

    type Tamper = Box<dyn Fn(&Path)>;

    /// (what is done, the verdict, a finding both must name, what does it)
    fn tamperings(base: &Path, source: &Path) -> Vec<(&'static str, Level, &'static str, Tamper)> {
        use factum::container::FACTUM_NS;
        use factum::container::volume::KEY_GPG;
        let (small, small_member, bevy) = stored_names(base);
        let close_1_turtle = history_member(1, TURTLE);
        let close_1_signature = member(base, &history_member(1, SIG_GPG)).unwrap();
        let source = source.to_path_buf();
        let big = stored_big_arn(base);
        let doubled = [close_1_signature.as_slice(), close_1_signature.as_slice()].concat();
        let on = |tamper: fn(&Path, &str), name: &str| -> Tamper {
            let name = name.to_string();
            Box::new(move |p| tamper(p, &name))
        };
        let replaced = small.clone();
        let swapped = small.clone();
        vec![
            ("nothing", Level::Ok, "", Box::new(|_| {})),
            // the end of the file
            (
                "a member hidden behind a lowered count",
                Level::Fail,
                "trailing_data",
                Box::new(|p| change_count(p, -1)),
            ),
            (
                "a count above what is listed",
                Level::Fail,
                "trailing_data",
                Box::new(|p| change_count(p, 1)),
            ),
            (
                "a few trailing bytes",
                Level::Fail,
                "trailing_data",
                Box::new(|p| append(p, b"junk")),
            ),
            (
                "many trailing bytes",
                Level::Fail,
                "trailing_data",
                Box::new(|p| append(p, &[7; 100_000])),
            ),
            (
                "the end records cut short",
                Level::Fail,
                "trailing_data",
                Box::new(|p| cut(p, 30)),
            ),
            (
                "the directory cut short",
                Level::Warn,
                "trailing_data",
                Box::new(|p| cut(p, 300)),
            ),
            (
                "an interrupted addition",
                Level::Warn,
                "trailing_data",
                Box::new(move |p| {
                    let file = source.join("interrupted.bin");
                    std::fs::write(&file, vec![1u8; 100_000]).unwrap();
                    let (mut volume, _) = Volume::open(p, None).unwrap();
                    let options = AddOptions {
                        base: source.clone(),
                        keep_path: true,
                        metadata_only: false,
                        excerpt: None,
                        replaces: Vec::new(),
                    };
                    let progress = AddProgress::default();
                    volume
                        .stage_add(&[file], &options, &progress, &AtomicBool::new(false))
                        .unwrap();
                }),
            ),
            // the directory
            (
                "a duplicate name",
                Level::Fail,
                "duplicate_member",
                Box::new(|p| duplicate_member(p, "version.txt")),
            ),
            (
                "the CRC-32 of a file",
                Level::Fail,
                "stream_hash",
                on(flip_crc, &small_member),
            ),
            ("the CRC-32 of a bevy", Level::Fail, "stream_hash", on(flip_crc, &bevy)),
            (
                "the CRC-32 of information.turtle",
                Level::Fail,
                "turtle_hash",
                on(flip_crc, TURTLE),
            ),
            (
                "the CRC-32 of a kept information.turtle",
                Level::Fail,
                "history",
                on(flip_crc, &close_1_turtle),
            ),
            (
                "the CRC-32 of a kept hashes file",
                Level::Fail,
                "turtle_hash",
                on(flip_crc, &history_member(1, HASHES)),
            ),
            (
                "the CRC-32 of version.txt",
                Level::Fail,
                "history",
                on(flip_crc, "version.txt"),
            ),
            (
                "the CRC-32 of container.description",
                Level::Fail,
                "history",
                on(flip_crc, "container.description"),
            ),
            (
                "the CRC-32 of the root signature",
                Level::Fail,
                "history",
                on(flip_crc, SIG_GPG),
            ),
            (
                "the CRC-32 of a kept signature",
                Level::Fail,
                "signature_invalid",
                on(flip_crc, &history_member(2, SIG_GPG)),
            ),
            (
                "a local header that differs, of a file",
                Level::Fail,
                "stream_hash",
                on(differ_local_header, &small_member),
            ),
            (
                "a local header that differs, of metadata",
                Level::Fail,
                "history",
                on(differ_local_header, &history_member(2, TURTLE)),
            ),
            // the content
            ("a byte of a bevy", Level::Fail, "stream_hash", on(flip_data, &bevy)),
            (
                "a byte of a file",
                Level::Fail,
                "stream_hash",
                on(flip_data, &small_member),
            ),
            (
                "a bevy in a method nobody reads",
                Level::Fail,
                "stream_hash",
                on(set_method, &bevy),
            ),
            (
                "a file in a method nobody reads",
                Level::Fail,
                "stream_hash",
                on(set_method, &small_member),
            ),
            (
                "the storage type dropped in a new state",
                Level::Fail,
                "history",
                Box::new(move |p| swap_content_and_drop_storage_type(p, &swapped)),
            ),
            // the states
            (
                "the root signature swapped for an older one",
                Level::Fail,
                "history",
                Box::new(move |p| rewrite(p, &[(SIG_GPG, &close_1_signature)], &[])),
            ),
            (
                "the root key swapped",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[(KEY_GPG, b"another key")], &[])),
            ),
            (
                "two signatures in one",
                Level::Fail,
                "signature_invalid",
                Box::new(move |p| rewrite(p, &[(&history_member(1, SIG_GPG), &doubled)], &[])),
            ),
            (
                "a close without its signature",
                Level::Fail,
                "unsigned",
                Box::new(|p| rewrite(p, &[], &[&history_member(1, SIG_GPG)])),
            ),
            ("a close removed", Level::Fail, "history", Box::new(drop_history_1)),
            (
                "a kept state edited",
                Level::Fail,
                "turtle_hash",
                Box::new(move |p| {
                    let edited = String::from_utf8(member(p, &close_1_turtle).unwrap()).unwrap();
                    rewrite(
                        p,
                        &[(&close_1_turtle, edited.replace("small", "large").as_bytes())],
                        &[],
                    );
                }),
            ),
            (
                "history/0",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[(&history_member(0, TURTLE), b"")], &[])),
            ),
            (
                "a huge history number",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[(&history_member(u32::MAX, TURTLE), b"")], &[])),
            ),
            (
                "a history number that is no close to factum",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[("factum/history/4294967296/information.turtle", b"")], &[])),
            ),
            (
                "a history folder that is no number",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[("factum/history/x/information.turtle", b"")], &[])),
            ),
            (
                "the newest close moved out of reach",
                Level::Fail,
                "history",
                Box::new(|p| {
                    let (turtle, moved) = (history_member(2, TURTLE), history_member(4_000_000_000, TURTLE));
                    let moved = moved.replace("4000000000", "4294967298");
                    let data = member(p, &turtle).unwrap();
                    rewrite(p, &[(&moved, &data)], &[&turtle]);
                }),
            ),
            (
                "the newest close left out of the directory",
                Level::Fail,
                "history",
                Box::new(|p| {
                    let members = [TURTLE, HASHES, SIG_GPG, KEY_GPG].map(|name| history_member(2, name));
                    rewrite(p, &[], &members.each_ref().map(String::as_str));
                }),
            ),
            (
                "a signature left at the root of a new state",
                Level::Fail,
                "history",
                Box::new(|p| {
                    let text = turtle_text(p).replace("small.txt", "large.txt");
                    write_turtle(p, &text);
                    rewrite(p, &[(SIG_GPG, b"signature")], &[]);
                }),
            ),
            (
                "version.txt removed",
                Level::Fail,
                "unsupported",
                Box::new(|p| rewrite(p, &[], &["version.txt"])),
            ),
            (
                "one bit of version.txt in the directory",
                Level::Fail,
                "unsupported",
                Box::new(|p| {
                    let mut bytes = std::fs::read(p).unwrap();
                    let listed = directory_at(&bytes, "version.txt");
                    bytes[listed + 46] ^= 1;
                    std::fs::write(p, bytes).unwrap();
                }),
            ),
            (
                "another version",
                Level::Fail,
                "unsupported",
                Box::new(|p| rewrite(p, &[("version.txt", b"major=1\nminor=0\ntool=factum\n")], &[])),
            ),
            (
                "another tool named, the signatures taken out",
                Level::Fail,
                "unsigned",
                Box::new(|p| {
                    let version = b"major=2\nminor=1\ntool=other 1.0\n";
                    let members = [1, 2].map(|n| [SIG_GPG, KEY_GPG].map(|name| history_member(n, name)));
                    let [one, two] = members.each_ref().map(|m| m.each_ref().map(String::as_str));
                    let omit = [&one[..], &two[..], &[SIG_GPG, KEY_GPG]].concat();
                    rewrite(p, &[("version.txt", version)], &omit);
                }),
            ),
            (
                "container.description naming another container",
                Level::Fail,
                "history",
                Box::new(|p| {
                    let other = b"aff4://11111111-2222-4333-8444-555555555555";
                    rewrite(p, &[("container.description", other)], &[]);
                }),
            ),
            (
                "container.description emptied",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[("container.description", b"")], &[])),
            ),
            (
                "the ZIP comment naming another container",
                Level::Fail,
                "history",
                Box::new(|p| {
                    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(p).unwrap();
                    let len = file.metadata().unwrap().len();
                    let archive = read_archive(&mut file, len).unwrap();
                    let mut app = Appender::new(file, len, archive.entries).unwrap();
                    let other = b"aff4://11111111-2222-4333-8444-555555555555";
                    app.finish(&[], other).unwrap();
                }),
            ),
            (
                "metadata that describes another volume",
                Level::Fail,
                "history",
                Box::new(|p| {
                    let volume = String::from_utf8(member(p, "container.description").unwrap()).unwrap();
                    let other = "aff4://11111111-2222-4333-8444-555555555555";
                    write_turtle(p, &turtle_text(p).replace(&volume, other));
                }),
            ),
            (
                "the root hashes file another one",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| rewrite(p, &[(HASHES, b"<a>\n    <b> \"0\"^^<c#SHA256> .\n")], &[])),
            ),
            (
                "the root hashes file removed",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| rewrite(p, &[], &[HASHES])),
            ),
            (
                "a signature far larger than any",
                Level::Fail,
                "x509_invalid",
                Box::new(|p| {
                    let name = history_member(1, "information.turtle.factum.sig");
                    rewrite(p, &[(&name, &vec![0x41; 5 << 20])], &[]);
                }),
            ),
            (
                "records that each claim a long directory",
                Level::Fail,
                "not_aff4",
                Box::new(|p| std::fs::write(p, claimed_directories(40_000, 1_000)).unwrap()),
            ),
            (
                "container.description removed",
                Level::Fail,
                "history",
                Box::new(|p| rewrite(p, &[], &["container.description"])),
            ),
            // the metadata
            (
                "metadata edited",
                Level::Fail,
                "history",
                Box::new(|p| write_turtle(p, &turtle_text(p).replace("small.txt", "large.txt"))),
            ),
            (
                "a forged replacedBy",
                Level::Fail,
                "history",
                Box::new(move |p| add_triple(p, &replaced, &format!("{FACTUM_NS}replacedBy"), &big)),
            ),
            (
                "an ARN written with an escape",
                Level::Warn,
                "not_signed",
                Box::new(move |p| {
                    let text = turtle_text(p);
                    write_turtle(p, &text.replace(&small, &escaped_last_character(&small)));
                }),
            ),
            (
                "a space in an IRI",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let text = turtle_text(p);
                    let (arn, _, _) = stored_names(p);
                    write_turtle(p, &text.replace(&arn, &format!("{arn} x")));
                }),
            ),
            (
                "an escape in an IRI that stands for a space",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let text = turtle_text(p);
                    let (arn, _, _) = stored_names(p);
                    write_turtle(p, &text.replace(&arn, &format!("{arn}\\u0020x")));
                }),
            ),
            (
                "a secondary store that is missing",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let volume = String::from_utf8(member(p, "container.description").unwrap()).unwrap();
                    let imports = format!("{}imports", factum::container::AFF4L_NS);
                    add_triple(p, &volume, &imports, &format!("{volume}/information.turtle.2"));
                }),
            ),
            (
                "a secondary store without a hash",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let volume = String::from_utf8(member(p, "container.description").unwrap()).unwrap();
                    let imports = format!("{}imports", factum::container::AFF4L_NS);
                    add_triple(p, &volume, &imports, &format!("{volume}/information.turtle.2"));
                    rewrite(p, &[("information.turtle.2", b"")], &[]);
                }),
            ),
            (
                "a secondary store that is no Turtle",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let volume = String::from_utf8(member(p, "container.description").unwrap()).unwrap();
                    let store = b"x> .";
                    let hash = hex::encode(sha2::Sha256::digest(store));
                    let text = format!(
                        "{}\n<{volume}/information.turtle.2>\n    aff4:hash \"{hash}\"^^aff4:SHA256 .\n\n<{volume}>\n    \
                         aff4l:imports <{volume}/information.turtle.2> .\n",
                        turtle_text(p)
                    );
                    write_turtle(p, &text);
                    rewrite(p, &[("information.turtle.2", store)], &[]);
                }),
            ),
            (
                "a second type beside FileImage",
                Level::Fail,
                "",
                Box::new(|p| {
                    let text = turtle_text(p).replacen("a aff4:FileImage ;", "a aff4:FileImage , aff4:Other ;", 1);
                    write_turtle(p, &text);
                }),
            ),
            (
                "a statement that does not end",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let text = turtle_text(p);
                    let last = text.rfind(" .\n").unwrap();
                    write_turtle(p, &format!("{} ;\n", &text[..last]));
                }),
            ),
            (
                "a statement that runs into the next subject",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| {
                    let text = turtle_text(p);
                    let first = text.find(" .\n\n<").unwrap();
                    write_turtle(p, &format!("{} ;{}", &text[..first], &text[first + 2..]));
                }),
            ),
            (
                "a stray bracket in a hashes file",
                Level::Fail,
                "turtle_hash",
                Box::new(|p| rewrite(p, &[(&history_member(1, HASHES), b"x> .")], &[])),
            ),
            (
                "an index that repeats a chunk",
                Level::Fail,
                "stream_hash",
                Box::new({
                    let index = format!("{bevy}.index");
                    move |p| {
                        let mut repeated = member(p, &index).unwrap();
                        let first = repeated[..12].to_vec();
                        repeated[12..24].copy_from_slice(&first);
                        rewrite(p, &[(&index, &repeated)], &[]);
                    }
                }),
            ),
            (
                "end records repeated after the end",
                Level::Fail,
                "trailing_data",
                Box::new(|p| append(p, &b"PK\x05\x06".repeat(4_000))),
            ),
            (
                "more end records after the end than a search goes through",
                Level::Fail,
                "not_aff4",
                Box::new(|p| append(p, &b"PK\x05\x06".repeat(1 << 16))),
            ),
            (
                "a store nothing here reads",
                Level::Warn,
                "not_checked",
                Box::new(|p| rewrite(p, &[("information.hdt", b"HDT")], &[])),
            ),
            (
                "no ZIP at all",
                Level::Fail,
                "not_aff4",
                Box::new(|p| std::fs::write(p, vec![0u8; 5000]).unwrap()),
            ),
        ]
    }

    /// `entries` valid directory entries, then `records` end records that each claim them all.
    fn claimed_directories(entries: u32, records: u32) -> Vec<u8> {
        let mut bytes = b"JUNK".to_vec();
        for _ in 0..entries {
            bytes.extend(b"PK\x01\x02");
            bytes.extend([0; 42]);
        }
        for _ in 0..records {
            let size = bytes.len() as u32 - 4;
            bytes.extend(b"PK\x05\x06");
            bytes.extend([0; 4]);
            bytes.extend((entries as u16).to_le_bytes());
            bytes.extend((entries as u16).to_le_bytes());
            bytes.extend(size.to_le_bytes());
            bytes.extend(4u32.to_le_bytes());
            bytes.extend(0u16.to_le_bytes());
        }
        bytes
    }

    /// The ARN of the file stored as an ImageStream.
    fn stored_big_arn(path: &Path) -> String {
        let graph = factum::container::turtle::parse(&turtle_text(path)).unwrap();
        factum::container::volume::file_records(&graph)
            .into_iter()
            .find(|r| r.path.ends_with("big.bin"))
            .unwrap()
            .arn
    }

    #[test]
    fn both_verifiers_agree_on_tampered_containers() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let base = signed_container(&dir, &home);
        let db = Db::open(&dir.path().join("factum.db")).unwrap();
        let signer = GnupgSigner::new(&db, Some(home.path()));
        let gpgsm = Gpgsm::unavailable();
        let copy = dir.path().join("tampered.aff4l");
        for (what, expected, code, tamper) in tamperings(&base, &dir.path().join("mnt")) {
            std::fs::copy(&base, &copy).unwrap();
            tamper(&copy);
            let home = home.path();
            if !assert_verdict(what, &copy, expected, code, (&signer, &gpgsm), &[], Some(&home)) {
                return;
            }
        }
    }

    /// What stays different, on purpose, and README and spec say so: the script checks what factum wrote and has no
    /// reader for anything else, so where factum, which also opens other tools' containers, warns or has nothing to
    /// say, it warns or fails. Not the other way round.
    #[test]
    fn the_script_fails_what_is_not_factums_where_factum_does_not() {
        let verdicts = |path: &Path| {
            let report = verify_file(
                path,
                &FakeSigner::new(false),
                &Gpgsm::unavailable(),
                &|_, _| {},
                &AtomicBool::new(false),
            )
            .unwrap();
            let script = script_verdict(path, &[], None);
            (report, script)
        };
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        // a legacy file: nothing shows who wrote it
        let legacy = s.f.path().join("legacy.aff4l");
        std::fs::copy(s.container_path(), &legacy).unwrap();
        without_layout(&legacy, &["version.txt"]);
        let (report, script) = verdicts(&legacy);
        assert_eq!(report.overall(), Level::Warn, "{:?}", report.findings);
        let Some((level, output)) = script else { return };
        assert_eq!(level, Level::Fail, "{output}");
        assert!(output.contains("[unsupported]"), "{output}");
        // another tool's file: unsigned, so neither calls it good
        let foreign = s.f.path().join("foreign.aff4l");
        std::fs::copy(s.container_path(), &foreign).unwrap();
        without_layout(&foreign, &[]);
        let (report, script) = verdicts(&foreign);
        assert_eq!(report.overall(), Level::Warn, "{:?}", report.findings);
        assert!(
            report.findings.iter().any(|f| f.code == "not_signed"),
            "{:?}",
            report.findings
        );
        let (level, output) = script.unwrap();
        assert_eq!(level, Level::Warn);
        assert!(output.contains("Result: NOT SIGNED"), "{output}");
        // Turtle that is not factum's layout, though valid: a comment
        let text = format!("# a comment\n{}", turtle_text(&s.container_path()));
        write_turtle(&s.container_path(), &text);
        let (report, script) = verdicts(&s.container_path());
        assert_eq!(report.overall(), Level::Warn, "{:?}", report.findings);
        let (level, output) = script.unwrap();
        assert_eq!(level, Level::Fail, "{output}");
        assert!(output.contains("[turtle_hash]"), "{output}");
    }

    /// What ends a name in Turtle ends it for both: on damaged content, a name that hid it from the script left the
    /// file out of the check.
    #[test]
    fn both_verifiers_fail_a_type_a_name_cannot_hold() {
        for (from, to) in [
            ("a aff4:FileImage ;", "a aff4:FileImage,aff4:Other ;"),
            ("a aff4:FileImage ;", "a aff4:FileImage#x ;"),
            ("a aff4:FileImage ;", "a aff4:FileImage(x) ;"),
            ("a aff4:FileImage ;", "a aff4:FileImage;x ;"),
            ("a aff4:FileImage ;", "a aff4:FileImage'x ;"),
            ("a aff4:FileImage ;", "a aff4:FileImage. ;"),
            ("a aff4:FileImage ;", "a aff4:FileImage , aff4:Other ;"),
        ] {
            let s = Setup::with_signer(FakeSigner::new(false));
            let id = s.create();
            s.add(id, &[s.file("a.txt")]);
            let path = s.container_path();
            damage_content(&path, &first_arn(&s, id));
            write_turtle(&path, &turtle_text(&path).replacen(from, to, 1));
            let signer = FakeSigner::new(false);
            let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &Gpgsm::unavailable());
            if !assert_verdict(to, &path, Level::Fail, "", verifiers, &[], None) {
                return;
            }
        }
    }

    /// The script, with what a check may hold set to `limit`.
    fn script_within(path: &Path, limit: u64) -> Option<String> {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("verify_container.py");
        std::fs::write(&script, VERIFY_CONTAINER_PY).unwrap();
        let code = format!(
            "import importlib.util as u, sys\ns = u.spec_from_file_location('v', sys.argv[1])\nv = u.module_from_spec(s)\n\
             s.loader.exec_module(v)\nv.MIN_METADATA_BUDGET = {limit}\nv.METADATA_BUDGET_PER_STORED_BYTE = 0\n\
             sys.exit(v.main(sys.argv[2:]))\n"
        );
        let output = Command::new(which::which("python3").ok()?)
            .args(["-I", "-X", "utf8", "-c", &code])
            .arg(&script)
            .arg(path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// A check that runs out of what it may hold says that, once, and reads nothing into what it did not get to.
    #[test]
    fn the_script_stops_with_one_finding_when_the_metadata_does_not_fit() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let sizes = member(&path, TURTLE).unwrap().len() as u64;
        // enough for the first copy only
        let Some(output) = script_within(&path, sizes + 1000) else {
            return;
        };
        assert!(!output.contains("Traceback"), "{output}");
        let findings: Vec<&str> = output.lines().filter(|l| l.starts_with('\u{2717}')).collect();
        assert_eq!(findings.len(), 1, "{output}");
        assert!(findings[0].ends_with("[too_large]"), "{output}");
        assert!(findings[0].contains("does not mean"), "{output}");
        assert!(findings[0].contains("GiB"), "{output}");
        assert!(
            !output.contains("not signed") && !output.contains("never closed"),
            "{output}"
        );
    }

    /// Exit 0, as nothing failed, and the words for what that means.
    #[test]
    fn the_script_says_ok_only_of_what_is_signed() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let Some((code, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("Result: NOT SIGNED"), "{output}");
        assert!(!output.contains("Result: OK"), "{output}");
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let (code, output) = run(&path, &[], Some(&home.path())).unwrap();
        assert_eq!(code, 0, "{output}");
        assert!(output.contains("Result: OK"), "{output}");
    }

    #[test]
    fn the_script_refuses_a_line_factum_never_writes() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let path = s.container_path();
        let long = format!("x{}", "y".repeat(2 << 20));
        write_turtle(&path, &turtle_text(&path).replacen("a.txt", &long, 1));
        let Some((code, output)) = run_script(VERIFY_CONTAINER_PY, &path, &[], None) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("[turtle_hash]") && output.contains("a line of"),
            "{output}"
        );
        // factum reads it: another difference that only ever fails
        let report = verify_file(
            &path,
            &FakeSigner::new(false),
            &Gpgsm::unavailable(),
            &|_, _| {},
            &AtomicBool::new(false),
        );
        assert!(!report.unwrap().findings.iter().any(|f| f.code == "turtle_hash"));
    }

    #[test]
    fn the_end_of_a_search_is_not_called_not_a_zip() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let path = s.container_path();
        append(&path, &b"PK\x05\x06".repeat(1 << 16));
        let report = verify_file(
            &path,
            &FakeSigner::new(false),
            &Gpgsm::unavailable(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.overall(), Level::Fail);
        assert!(
            report.findings[0].message.contains("stopped at its limit"),
            "{:?}",
            report.findings
        );
        let through_log =
            s.f.factum()
                .verify_container_file(&path, &Gpgsm::unavailable(), &|_, _| {}, &AtomicBool::new(false))
                .unwrap();
        let log = through_log
            .findings
            .iter()
            .find(|f| f.code == "log_mismatch")
            .expect("a log finding");
        assert!(log.message.contains("nothing could be read"), "{}", log.message);
        let Some((code, output)) = run_script(VERIFY_CONTAINER_PY, &path, &[], None) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(output.contains("stopped at its limit"), "{output}");
    }

    #[test]
    fn the_script_prints_its_own_hash_first() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let hash = hex::encode(sha2::Sha256::digest(VERIFY_CONTAINER_PY));
        let Some((_, output)) = run(&s.container_path(), &[], None) else {
            return;
        };
        assert!(output.lines().next().unwrap().ends_with(&hash), "{output}");
    }

    #[test]
    fn an_unreadable_close_is_not_called_an_open_state() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        differ_local_header(&path, &history_member(2, TURTLE));
        let db = Db::open(&dir.path().join("factum.db")).unwrap();
        let signer = GnupgSigner::new(&db, Some(home.path()));
        let report = verify_file(
            &path,
            &signer,
            &Gpgsm::unavailable(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        let messages: Vec<&str> = report.findings.iter().map(|f| f.message.as_str()).collect();
        assert!(messages.iter().any(|m| m.contains("cannot be read")), "{messages:?}");
        assert!(!messages.iter().any(|m| m.contains("never closed")), "{messages:?}");
        let Some((code, output)) = run_script(VERIFY_CONTAINER_PY, &path, &[], Some(&home.path())) else {
            return;
        };
        assert_eq!(code, 1, "{output}");
        assert!(!output.contains("never closed"), "{output}");
    }

    /// Only the subject that names the volume differs: no file, hash or close has any other reason to fail.
    #[test]
    fn both_verifiers_fail_metadata_of_another_volume() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let path = s.container_path();
        let volume = String::from_utf8(member(&path, "container.description").unwrap()).unwrap();
        let subject = format!("<{volume}>\n");
        let other = "<aff4://11111111-2222-4333-8444-555555555555>\n";
        write_turtle(&path, &turtle_text(&path).replacen(&subject, other, 1));
        let signer = FakeSigner::new(false);
        let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &Gpgsm::unavailable());
        assert_verdict("another volume", &path, Level::Fail, "history", verifiers, &[], None);
    }

    #[test]
    fn a_forged_tool_line_changes_nothing() {
        let s = Setup::with_signer(FakeSigner::new(false));
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        rewrite(
            &s.container_path(),
            &[("version.txt", b"major=2\nminor=1\ntool=other 1.0\n")],
            &[],
        );
        let signer = FakeSigner::new(false);
        let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &Gpgsm::unavailable());
        assert_verdict(
            "an open container",
            &s.container_path(),
            Level::Warn,
            "not_signed",
            verifiers,
            &[],
            None,
        );
    }

    #[test]
    fn both_verifiers_say_so_when_the_key_is_unknown_or_has_expired() {
        let home = gpg_or_skip!();
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        let db = Db::open(&dir.path().join("factum.db")).unwrap();
        let empty = tempfile::tempdir().unwrap();
        let signer = GnupgSigner::new(&db, Some(empty.path().to_path_buf()));
        let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &Gpgsm::unavailable());
        assert_verdict(
            "no key",
            &path,
            Level::Fail,
            "key_unknown",
            verifiers,
            &[],
            Some(empty.path()),
        );
        let Some(home) = common::GpgHome::at_time(
            Some("20200101T000000"),
            "Expired Key <expired@factum.invalid>",
            "sign",
            "2020-02-01",
        ) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let path = signed_container(&dir, &home);
        home.set_clock(None);
        let db = Db::open(&dir.path().join("factum.db")).unwrap();
        let signer = GnupgSigner::new(&db, Some(home.path()));
        assert_verdict(
            "an expired key",
            &path,
            Level::Warn,
            "key_expired",
            (&signer, &Gpgsm::unavailable()),
            &[],
            Some(&home.path()),
        );
    }

    #[test]
    fn both_verifiers_agree_on_replacements() {
        use factum::container::FACTUM_NS;
        let replaced_by = format!("{FACTUM_NS}replacedBy");
        for (what, damage, content, expected, code, said) in [
            (
                "forged, the file is fine",
                false,
                "a",
                Level::Warn,
                "not_signed",
                "listed as replaced by",
            ),
            (
                "a copy added again",
                true,
                "a",
                Level::Warn,
                "replaced_copy",
                "replaced by a copy added again",
            ),
            (
                "a copy with other content",
                true,
                "other",
                Level::Fail,
                "stream_hash",
                "replaced by a copy with different content",
            ),
        ] {
            let s = Setup::with_signer(FakeSigner::new(false));
            std::fs::write(s.file("twin.txt"), content).unwrap();
            let id = s.create();
            s.add(id, &[s.file("a.txt"), s.file("twin.txt")]);
            let detail = s.f.factum().container(id).unwrap();
            let (original, twin) = (&detail.adds[0].files[0].arn, &detail.adds[0].files[1].arn);
            if damage {
                damage_content(&s.container_path(), original);
            }
            add_triple(&s.container_path(), original, &replaced_by, twin);
            let signer = FakeSigner::new(false);
            let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &Gpgsm::unavailable());
            if !assert_verdict(what, &s.container_path(), expected, code, verifiers, &[], None) {
                return;
            }
            // the script has no log to compare a replacement with: it always names the pair
            let (_, output) = script_verdict(&s.container_path(), &[], None).unwrap();
            assert!(output.contains(said), "{what}: {output}");
        }
    }

    /// The same PEM with another month in the UTCTime of the signing time.
    fn with_signing_month(signature: &str, month: &str) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let body: String = signature
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.contains(':'))
            .collect();
        let mut der = engine.decode(body).unwrap();
        // the OID of signingTime, its SET and the tag and length of a UTCTime
        let oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
        let at = der.windows(oid.len()).position(|w| w == oid).unwrap() + oid.len();
        assert_eq!(der[at + 2..at + 4], [0x17, 0x0D]);
        der[at + 6..at + 8].copy_from_slice(month.as_bytes());
        let encoded = engine.encode(der);
        format!("-----BEGIN SIGNED MESSAGE-----\n{encoded}\n-----END SIGNED MESSAGE-----\n")
    }

    #[test]
    fn both_verifiers_agree_on_x509_signatures() {
        use factum::container::volume::CER_X509;
        let Some(home) = common::GpgsmHome::new() else {
            eprintln!("skipped: gpgsm or openssl is not installed");
            return;
        };
        home.trusted();
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let signer = FakeSigner::new(false);
        let root = home.file("root.pem");
        let flags = ["--ca", root.to_str().unwrap()];
        let root_pem = std::fs::read_to_string(&root).unwrap();
        let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &gpgsm);
        let endless = "-----BEGIN CERTIFICATE-----\n".repeat(80_000);
        let endless = endless.as_str();
        for (what, chain, expected, code) in [
            ("its own chain", None, Level::Ok, ""),
            (
                "another certificate stored",
                Some(root_pem.as_str()),
                Level::Fail,
                "x509_mismatch",
            ),
            (
                "nothing readable stored",
                Some("not a certificate"),
                Level::Fail,
                "x509_mismatch",
            ),
            ("no end to a certificate", Some(endless), Level::Fail, "x509_mismatch"),
        ] {
            let path = super::verify::loose_container(&s, &gpgsm, &home, chain);
            if !assert_verdict(what, &path, expected, code, verifiers, &flags, None) {
                return;
            }
        }
        // a signing time that is no date, in bytes the signature no longer matches
        for month in ["13", "00"] {
            let path = super::verify::loose_signed(&s, &|turtle| {
                let (signature, chain) = gpgsm.sign_with_chain(&home.leaf_fingerprint, turtle, &[]).unwrap();
                (with_signing_month(&signature, month), chain)
            });
            let what = format!("signed in month {month}");
            assert_verdict(&what, &path, Level::Fail, "x509_invalid", verifiers, &flags, None);
        }
        // no chain beside the signature: what it carries itself is what can be checked
        let path = super::verify::loose_container(&s, &gpgsm, &home, None);
        rewrite(&path, &[], &[CER_X509, &history_member(1, CER_X509)]);
        assert_verdict(
            "no stored chain",
            &path,
            Level::Warn,
            "x509_no_certificate",
            verifiers,
            &flags,
            None,
        );
        // the same without a root to compare with: the script cannot say more than that it was not compared
        let (_, output) = script_verdict(&path, &[], None).unwrap();
        assert!(output.contains("x509_no_certificate"), "{output}");
        // a root that is not the chain's: neither trusts the signature
        let untrusted = Gpgsm::new(Some(tempfile::tempdir().unwrap().path().to_path_buf()));
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
        let path = super::verify::loose_container(&s, &gpgsm, &home, None);
        assert_verdict(
            "another root",
            &path,
            Level::Fail,
            "x509_untrusted",
            (&signer, &untrusted),
            &["--ca", other_root.to_str().unwrap()],
            None,
        );
    }

    #[test]
    fn both_verifiers_agree_on_certificates_that_expired() {
        let Some(home) = common::GpgsmHome::with_expired_leaf() else {
            eprintln!("skipped: no gpgsm, or an openssl without -not_before");
            return;
        };
        home.trusted();
        let gpgsm = Gpgsm::new(Some(home.path()));
        let s = Setup::new();
        let signer = FakeSigner::new(false);
        let root = home.file("root.pem");
        let flags = ["--ca", root.to_str().unwrap()];
        let verifiers: (&dyn factum::signer::Signer, &Gpgsm) = (&signer, &gpgsm);
        // expired since: good, as long as it was valid when it signed
        let chain = gpgsm.chain(&home.leaf_fingerprint, &[]).unwrap();
        let path = super::verify::loose_signed(&s, &|turtle| (home.sign_while_valid(turtle), chain.clone()));
        if !assert_verdict(
            "expired since",
            &path,
            Level::Warn,
            "x509_expired",
            verifiers,
            &flags,
            None,
        ) {
            return;
        }
        // an intermediate that had expired when it signed: the whole chain counts
        let path = super::verify::loose_signed(&s, &|turtle| {
            let signature = home.sign_below_expired_intermediate(turtle);
            let chain = ["leaf2.pem", "int.pem", "root.pem"].map(|f| std::fs::read_to_string(home.file(f)).unwrap());
            (signature, chain.concat())
        });
        assert_verdict(
            "expired at signing",
            &path,
            Level::Fail,
            "x509_invalid",
            verifiers,
            &flags,
            None,
        );
    }
}

#[test]
fn create_requires_evidence_of_the_case() {
    let s = Setup::new();
    let factum = s.f.factum();
    let other_case = factum.create_case("C-2", "Other", "").unwrap();
    let foreign = factum.create_evidence(other_case, "foreign", "", "").unwrap();
    let path = s.f.path().join("x.aff4l");
    let error = factum.create_container(s.case_id, "x", foreign, &path, "").unwrap_err();
    assert!(error.to_string().contains("does not exist in this case"), "{error}");
    let empty = factum.create_evidence(s.case_id, "empty", "", "").unwrap();
    factum.delete_evidence(empty).unwrap();
    assert!(factum.create_container(s.case_id, "x", empty, &path, "").is_err());
    assert!(!path.exists());
}

#[test]
fn two_containers_on_one_evidence() {
    let s = Setup::new();
    s.create();
    let factum = s.f.factum();
    factum
        .create_container(s.case_id, "second", s.evidence_id, &s.f.path().join("second.aff4l"), "")
        .unwrap();
    let containers = factum.list_containers(s.case_id).unwrap();
    assert_eq!(containers.len(), 2);
    assert!(containers.iter().all(|c| c.evidence_id == Some(s.evidence_id)));
}

#[test]
fn case_level_create_logs_evidence_then_container() {
    let s = Setup::new();
    let factum = s.f.factum();
    let path = s.f.path().join("usb2.aff4l");
    let (evidence_id, container_id) = factum
        .create_evidence_with_container(s.case_id, "USB 2", "abc", "seized", &path, "")
        .unwrap();
    let evidence = factum.get_evidence(evidence_id).unwrap().unwrap();
    assert_eq!(
        (evidence.description.as_str(), evidence.details.as_str()),
        ("USB 2", "seized")
    );
    let created = s.events("container_created");
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["evidence_id"], evidence_id);
    assert_eq!(created[0]["name"], "USB 2");
    assert!(
        s.events("evidence_created")
            .iter()
            .any(|e| e["evidence_id"] == evidence_id)
    );
    let evidence_entry: i64 =
        s.f.db
            .conn
            .query_row(
                "SELECT id FROM entries WHERE json_extract(payload_json, '$.event') = 'evidence_created' \
             AND json_extract(payload_json, '$.evidence_id') = ?",
                [evidence_id],
                |row| row.get(0),
            )
            .unwrap();
    assert!(evidence_entry < container_id);
    assert!(path.is_file());
    let summary = &factum.list_containers(s.case_id).unwrap()[0];
    assert_eq!(summary.evidence_id, Some(evidence_id));
}

#[test]
fn evidence_with_container_cannot_be_deleted() {
    let s = Setup::new();
    s.create();
    let error = s.f.factum().delete_evidence(s.evidence_id).unwrap_err();
    assert!(error.to_string().contains("has containers"), "{error}");
}

#[test]
fn summary_says_signed() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    s.f.factum().close_container(id).unwrap();
    assert!(s.f.factum().list_containers(s.case_id).unwrap()[0].signed);

    let unsigned = Setup::with_signer(FakeSigner::new(false));
    let id = unsigned.create();
    unsigned.add(id, &[unsigned.file("a.txt")]);
    unsigned.f.factum().close_container(id).unwrap();
    assert!(!unsigned.f.factum().list_containers(unsigned.case_id).unwrap()[0].signed);
}

#[test]
fn add_without_base_from_two_folders() {
    let s = Setup::new();
    let factum = s.f.factum();
    let id = factum
        .create_container(s.case_id, "anywhere", s.evidence_id, &s.container_path(), "")
        .unwrap();
    let elsewhere = s.f.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("z.txt"), "zz").unwrap();
    let options = AddOptions {
        base: PathBuf::new(),
        keep_path: true,
        ..Default::default()
    };
    for source in [s.file("a.txt"), elsewhere.join("z.txt")] {
        let mut volume = factum.open_container_for_add(id).unwrap();
        let staged = volume
            .stage_add(&[source], &options, &AddProgress::default(), &AtomicBool::new(false))
            .unwrap();
        factum.commit_container_add(id, &mut volume, staged).unwrap();
    }
    let added = s.events("container_files_added");
    assert_eq!(added.len(), 2);
    for (event, source) in added.iter().zip([s.file("a.txt"), elsewhere.join("z.txt")]) {
        assert_eq!(event["base_path"], "");
        assert_eq!(event["keep_path"], true);
        let record = &event["files"][0];
        assert_eq!(record["source"], source.display().to_string());
        // compared by components: the stored path uses the platform's separator throughout
        let path = Path::new(record["path"].as_str().unwrap());
        assert!(source.ends_with(path), "{} vs {}", path.display(), source.display());
        assert!(
            path.components().count() + 1 >= source.components().count(),
            "{}",
            path.display()
        );
    }
    let volume = factum.open_container_for_add(id).unwrap();
    assert!(factum.compare_with_log(id, &volume).unwrap().is_empty());
    let records = factum::container::volume::file_records(volume.graph());
    assert!(records.iter().all(|r| r.source.is_some()));
}

#[test]
fn acquire_skips_the_container_itself() {
    let s = Setup::new();
    let factum = s.f.factum();
    let inside = s.source.join("preserved.aff4l");
    let id = factum
        .create_container(
            s.case_id,
            "inside",
            s.evidence_id,
            &inside,
            &s.source.display().to_string(),
        )
        .unwrap();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let staged = volume
        .stage_add(
            std::slice::from_ref(&s.source),
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert!(
        staged
            .records
            .iter()
            .all(|r| r.source.as_deref() != Some(&*inside.display().to_string()))
    );
    assert_eq!(staged.records.len(), 5);
    factum.commit_container_add(id, &mut volume, staged).unwrap();
}

#[test]
fn add_logs_sources() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
    let event = &s.events("container_files_added")[0];
    let sources = event["sources"].as_array().expect("sources are logged");
    assert!(!sources.is_empty());
    let paths: Vec<&str> = sources
        .iter()
        .flat_map(|m| m["paths"].as_array().unwrap())
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(paths.contains(&&*s.file("a.txt").display().to_string()));
    assert!(paths.contains(&&*s.file("b.txt").display().to_string()));
    let detail = s.f.factum().container(id).unwrap();
    let logged: Vec<_> = sources
        .iter()
        .filter_map(factum::container::mounts::Mount::from_json)
        .collect();
    assert_eq!(detail.adds[0].mounts, logged);
}

/// Flips one byte inside the stored content of `arn`, in place: the container's structure stays intact.
fn damage_content(path: &Path, arn: &str) {
    use factum::container::zip64::read_archive;
    use std::io::{Read, Seek, SeekFrom, Write};
    let uuid = String::from_utf8(member(path, "container.description").unwrap()).unwrap();
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let entry = archive
        .get(&factum::container::member_name(arn, &uuid))
        .unwrap()
        .clone();
    let mut header = [0u8; 30];
    file.seek(SeekFrom::Start(entry.header_offset)).unwrap();
    file.read_exact(&mut header).unwrap();
    let name_len = u16::from_le_bytes([header[26], header[27]]) as u64;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as u64;
    let at = entry.header_offset + 30 + name_len + extra_len + entry.compressed_size / 2;
    let mut byte = [0u8; 1];
    file.seek(SeekFrom::Start(at)).unwrap();
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();
    file.write_all(&[byte[0] ^ 0xFF]).unwrap();
}

fn first_arn(s: &Setup, id: i64) -> String {
    s.f.factum().container(id).unwrap().adds[0].files[0].arn.clone()
}

#[test]
fn close_rechecks_and_logs_it() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
    let close = s.f.factum().close_container(id).unwrap();
    let event = &s.events("container_closed")[0];
    assert_eq!(event["recheck"]["files"], 2);
    assert_eq!(event["recheck"]["bytes"], 3);
    #[cfg(target_os = "linux")]
    assert_eq!(event["recheck"]["uncached"], true);
    assert!(
        s.entry_text(close.entry_id).contains("re-checked"),
        "{}",
        s.entry_text(close.entry_id)
    );
}

#[test]
fn close_after_reopen_rechecks_only_new_files() {
    let s = Setup::new();
    let id = s.create();
    let factum = s.f.factum();
    s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
    factum.close_container(id).unwrap();
    factum.reopen_container(id).unwrap();
    s.add(id, &[s.file("c.txt")]);
    factum.close_container(id).unwrap();
    assert_eq!(s.events("container_closed")[1]["recheck"]["files"], 1);
}

#[test]
fn damaged_bytes_refuse_the_close() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("d.txt")]);
    damage_content(&s.container_path(), &first_arn(&s, id));
    let error = s.f.factum().close_container(id).unwrap_err();
    assert!(error.to_string().contains("doesn't match its hashes"), "{error}");
    assert!(s.events("container_closed").is_empty());
    assert!(s.f.factum().container(id).unwrap().summary.open);
}

#[test]
fn recheck_reports_the_damaged_file() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("d.txt")]);
    damage_content(&s.container_path(), &first_arn(&s, id));
    let input = s.f.factum().recheck_input(id).unwrap();
    assert_eq!(input.records.len(), 2);
    let result = factum::container::volume::recheck(
        &input.path,
        input.end,
        &input.records,
        &AddProgress::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(result.mismatches.len(), 1);
    assert_eq!(result.mismatches[0].arn, first_arn(&s, id));
}

#[test]
fn close_with_missing_file_fails_cleanly() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    std::fs::remove_file(s.container_path()).unwrap();
    assert!(s.f.factum().close_container(id).is_err());
    assert!(s.events("container_closed").is_empty());
    assert!(s.f.factum().container(id).unwrap().summary.open);
}

/// Damages the first file of a fresh container with two files; returns the container id and the re-check.
fn damaged(s: &Setup) -> (i64, factum::container::volume::Recheck) {
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("d.txt")]);
    damage_content(&s.container_path(), &first_arn(s, id));
    let recheck = s.f.factum().recheck_container(id).unwrap();
    assert_eq!(recheck.mismatches.len(), 1);
    (id, recheck)
}

/// Adds the failed files again as `add_again_plan` says.
fn add_again(s: &Setup, id: i64, recheck: &factum::container::volume::Recheck) -> i64 {
    let factum = s.f.factum();
    let mut entry = 0;
    for (sources, options) in factum.add_again_plan(id, &recheck.mismatches).unwrap() {
        let mut volume = factum.open_container_for_add(id).unwrap();
        let staged = volume
            .stage_add(&sources, &options, &AddProgress::default(), &AtomicBool::new(false))
            .unwrap();
        entry = factum.commit_container_add(id, &mut volume, staged).unwrap();
    }
    entry
}

#[test]
fn a_crc_field_on_a_replaced_copy_is_reported_as_what_it_is() {
    use factum::container::zip64::read_archive;
    use std::io::{Seek, SeekFrom, Write};
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    let arn = first_arn(&s, id);
    add_again(&s, id, &recheck);
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    let path = s.container_path();
    // the content as it was before it was damaged, and only the CRC field different
    damage_content(&path, &arn);
    let mut file = std::fs::File::open(&path).unwrap();
    let len = file.metadata().unwrap().len();
    let entry = read_archive(&mut file, len).unwrap().get_arn(&arn).unwrap().clone();
    let good = std::fs::read(&path).unwrap();
    let name = [entry.name.as_slice(), &[1, 0, 24, 0]].concat();
    let at = good.windows(name.len()).rposition(|w| w == name).unwrap() as u64;
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(at - 46 + 16)).unwrap();
    file.write_all(&(entry.crc32 ^ 1).to_le_bytes()).unwrap();
    let report = factum
        .verify_container_file(&path, &factum.gpgsm(), &|_, _| {}, &AtomicBool::new(false))
        .unwrap();
    let stream: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.code == "stream_hash" || f.code == "replaced_copy")
        .map(|f| f.message.as_str())
        .collect();
    assert_eq!(stream.len(), 1, "{stream:?}");
    assert!(stream[0].contains("CRC-32 differs"), "{stream:?}");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "stream_hash" && f.level == factum::verifier::Level::Fail),
        "{:?}",
        report.findings
    );
}

#[test]
fn damaged_close_logs_and_writes_nothing() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    let length = std::fs::metadata(s.container_path()).unwrap().len();
    let factum = s.f.factum();
    let entry = factum.close_container_damaged(id, &recheck).unwrap();
    let event = &s.events("container_closed")[0];
    assert_eq!(event["damaged"], serde_json::json!([recheck.mismatches[0].path]));
    assert!(event.get("signatures").is_none());
    assert!(
        s.entry_text(entry).contains("closed as damaged"),
        "{}",
        s.entry_text(entry)
    );
    assert_eq!(std::fs::metadata(s.container_path()).unwrap().len(), length);
    let summary = &factum.list_containers(s.case_id).unwrap()[0];
    assert!(summary.damaged && !summary.open && !summary.signed);
    assert_eq!(factum.container(id).unwrap().damaged_closes.len(), 1);
    let (signed, _) = factum.sign_unsigned_containers(s.case_id).unwrap();
    assert_eq!(signed, 0);
}

#[test]
fn reopen_after_damaged_close_rechecks_again() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    let factum = s.f.factum();
    factum.close_container_damaged(id, &recheck).unwrap();
    factum.reopen_container(id).unwrap();
    let input = factum.recheck_input(id).unwrap();
    assert!(input.records.iter().any(|r| r.arn == recheck.mismatches[0].arn));
}

#[test]
fn add_again_replaces_and_closes_signed() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    let factum = s.f.factum();
    let plan = factum.add_again_plan(id, &recheck.mismatches).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].0, vec![s.file("a.txt")]);
    assert_eq!(plan[0].1.base, s.source);
    add_again(&s, id, &recheck);
    let added = s.events("container_files_added");
    assert_eq!(added[1]["replaces"][0]["arn"], recheck.mismatches[0].arn);
    // plain paths need no raw form: their log payload is what it always was
    assert!(added[0].get("base_path_raw").is_none());
    assert!(added[0]["files"][0].get("source_raw").is_none());
    factum.close_container(id).unwrap();
    let report = factum
        .verify_container_file(
            &s.container_path(),
            &factum.gpgsm(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
    assert_eq!(codes.iter().filter(|c| **c == "replaced_copy").count(), 1, "{codes:?}");
    assert!(!codes.contains(&"stream_hash"), "{:?}", report.findings);
    assert!(!codes.contains(&"log_mismatch"), "{:?}", report.findings);
}

/// A container with two files whose names both show as `a\u{fffd}`, in a folder that is not UTF-8 either: its id, the
/// folder and the two paths.
#[cfg(target_os = "linux")]
fn added_from_a_path_that_is_not_unicode(s: &Setup) -> (i64, PathBuf, PathBuf, PathBuf) {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let base = s.f.path().join(OsStr::from_bytes(b"caf\xe9"));
    std::fs::create_dir(&base).unwrap();
    let (first, second) = (
        base.join(OsStr::from_bytes(b"a\xe9")),
        base.join(OsStr::from_bytes(b"a\xff")),
    );
    std::fs::write(&first, "one").unwrap();
    std::fs::write(&second, "two").unwrap();
    let id = s.create();
    let factum = s.f.factum();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let options = AddOptions {
        base: base.clone(),
        keep_path: true,
        ..Default::default()
    };
    let staged = volume
        .stage_add(
            &[first.clone(), second.clone()],
            &options,
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    factum.commit_container_add(id, &mut volume, staged).unwrap();
    (id, base, first, second)
}

#[cfg(target_os = "linux")]
#[test]
fn add_again_finds_a_source_that_is_not_unicode() {
    let s = Setup::new();
    let (id, base, first, _) = added_from_a_path_that_is_not_unicode(&s);
    let factum = s.f.factum();
    let added = &s.events("container_files_added")[0];
    assert!(added["base_path_raw"].is_string());
    assert!(added["base_path"].as_str().unwrap().ends_with("caf\u{fffd}"));
    assert!(added["files"][0]["source_raw"].is_string());

    let arn = first_arn(&s, id);
    damage_content(&s.container_path(), &arn);
    let recheck = factum.recheck_container(id).unwrap();
    assert_eq!(recheck.mismatches.len(), 1);
    let plan = factum.add_again_plan(id, &recheck.mismatches).unwrap();
    assert_eq!(plan[0].0, vec![first]);
    assert_eq!(plan[0].1.base, base);
    add_again(&s, id, &recheck);
    let added = s.events("container_files_added");
    assert_eq!(added[1]["replaces"][0]["arn"], arn.as_str());
    assert_eq!(added[1]["files"].as_array().unwrap().len(), 1);
    // the log and the container agree on the raw forms too
    let report = factum
        .verify_container_file(
            &s.container_path(),
            &factum.gpgsm(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
    assert!(
        !report.findings.iter().any(|f| f.code == "log_mismatch"),
        "{:?}",
        report.findings
    );
}

/// A log entry whose raw form names the other file, though both show alike as text.
#[cfg(target_os = "linux")]
#[test]
fn a_tampered_source_raw_is_refused() {
    let s = Setup::new();
    let (id, _, _, second) = added_from_a_path_that_is_not_unicode(&s);
    let factum = s.f.factum();
    let added = &s.events("container_files_added")[0];
    let raw = |n: usize| added["files"][n]["source_raw"].as_str().unwrap().to_string();
    s.f.exec(&format!(
        "UPDATE entries SET payload_json = replace(payload_json, '{}', '{}')",
        raw(0),
        raw(1)
    ));
    // verifying finds the log and the container apart
    let report = factum
        .verify_container_file(
            &s.container_path(),
            &factum.gpgsm(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
    let mismatch = report
        .findings
        .iter()
        .find(|f| f.code == "log_mismatch")
        .expect("a mismatch");
    assert!(
        mismatch
            .message
            .contains("differs between the container and the case log"),
        "{}",
        mismatch.message
    );
    // Add Again would read what the log names; nothing is added to a container that differs from its log
    let arn = first_arn(&s, id);
    damage_content(&s.container_path(), &arn);
    let recheck = factum.recheck_container(id).unwrap();
    let plan = factum.add_again_plan(id, &recheck.mismatches).unwrap();
    assert_eq!(plan[0].0, vec![second]);
    let error = factum.open_container_for_add(id).err().expect("refused");
    assert!(error.to_string().contains("differs from the case log"), "{error}");
    assert_eq!(s.events("container_files_added").len(), 1);
}

#[test]
fn add_again_needs_a_recorded_source() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    let mut unknown = recheck.mismatches.clone();
    unknown[0].source = None;
    let error = s.f.factum().add_again_plan(id, &unknown).unwrap_err();
    assert!(error.to_string().contains("its source is not recorded"), "{error}");
}

// --- review fixes

/// Adds `subject predicate <object>` to the container's current state, as a forger with write access would.
fn add_triple(path: &Path, subject: &str, predicate: &str, object: &str) {
    use factum::container::turtle::{self, Term};
    let mut graph = turtle::parse(&String::from_utf8(member(path, TURTLE).unwrap()).unwrap()).unwrap();
    graph.add(subject, predicate, Term::Iri(object.to_string()));
    write_turtle(path, &turtle::write(&graph, &turtle::factum_prefixes()));
}

/// Writes members after the newest state and a new directory; `omit` leaves members out of it.
fn rewrite(path: &Path, members: &[(&str, &[u8])], omit: &[&str]) {
    use factum::container::zip64::{Appender, read_archive};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let mut app = Appender::new(file, len, archive.entries).unwrap();
    for (name, data) in members {
        app.add_bytes(name, 0, data).unwrap();
    }
    app.finish(omit, &archive.comment).unwrap();
}

/// What makes a container factum's, to take out of one: what is left has no sign of who wrote it.
fn without_layout(path: &Path, also: &[&str]) {
    use factum::container::volume::SIGNATURE_MEMBERS;
    let mut file = std::fs::File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let names: Vec<String> = factum::container::zip64::read_archive(&mut file, len)
        .unwrap()
        .entries
        .iter()
        .map(|e| e.name_lossy())
        .filter(|n| n.starts_with("factum/") || n == "verify_container.py")
        .collect();
    let omit: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .chain(SIGNATURE_MEMBERS)
        .chain(also.iter().copied())
        .collect();
    rewrite(path, &[], &omit);
}

/// Writes `text` as the container's new root metadata, with matching hashes and no signatures.
fn write_turtle(path: &Path, text: &str) {
    use factum::container::AFF4_NS;
    use factum::container::turtle::{self, Term};
    use factum::container::zip64::{Appender, read_archive};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let uuid = String::from_utf8(member(path, "container.description").unwrap()).unwrap();
    let mut hashes = turtle::Graph::default();
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
    app.add_bytes(TURTLE, 8, text.as_bytes()).unwrap();
    app.add_bytes(HASHES, 0, turtle::write(&hashes, &[("aff4", AFF4_NS)]).as_bytes())
        .unwrap();
    app.finish(&[SIG_GPG, "information.turtle.pubkey.asc"], &archive.comment)
        .unwrap();
}

#[test]
fn verify_after_damaged_close_names_it() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    let factum = s.f.factum();
    let entry = factum.close_container_damaged(id, &recheck).unwrap();
    let report = factum
        .verify_container_file(
            &s.container_path(),
            &factum.gpgsm(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
    let messages: Vec<&str> = report.findings.iter().map(|f| f.message.as_str()).collect();
    assert!(!messages.iter().any(|m| m.contains("earlier state")), "{messages:?}");
    assert!(
        messages
            .iter()
            .any(|m| m.contains("as damaged") && m.contains(&format!("#{entry}"))),
        "{messages:?}"
    );
}

#[test]
fn add_again_with_changed_source_is_not_a_replacement() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    std::fs::write(s.file("a.txt"), "changed since").unwrap();
    add_again(&s, id, &recheck);
    let added = s.events("container_files_added");
    assert!(added[1].get("replaces").is_none(), "{}", added[1]);
    // the damaged copy is still unreplaced: closing fails again
    assert!(s.f.factum().close_container(id).is_err());
}

#[test]
fn replacement_with_other_content_fails_verification() {
    let s = Setup::new();
    let (id, _) = damaged(&s);
    let detail = s.f.factum().container(id).unwrap();
    let (damaged_arn, other_arn) = (detail.adds[0].files[0].arn.clone(), detail.adds[0].files[1].arn.clone());
    add_triple(
        &s.container_path(),
        &damaged_arn,
        &format!("{}replacedBy", factum::container::FACTUM_NS),
        &other_arn,
    );
    let report = factum::container::verify::verify_file(
        &s.container_path(),
        &FakeSigner::new(false),
        &s.f.factum().gpgsm(),
        &|_, _| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
    assert!(!codes.contains(&"replaced_copy"), "{:?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "stream_hash" && f.message.contains("different content")),
        "{:?}",
        report.findings
    );
}

/// A re-check that found `record` damaged.
fn damage_of(record: &factum::container::volume::FileRecord) -> factum::container::volume::Recheck {
    factum::container::volume::Recheck {
        mismatches: vec![record.clone()],
        ..Default::default()
    }
}

/// Changes the CRC-32 the directory has for one member; its content stays as it was.
fn flip_directory_crc(path: &Path, entry: &factum::container::zip64::CdEntry) {
    use std::io::{Seek, SeekFrom, Write};
    let bytes = std::fs::read(path).unwrap();
    // the name as the directory has it: followed by the ZIP64 extra
    let name = [entry.name.as_slice(), &[1, 0, 24, 0]].concat();
    let at = bytes.windows(name.len()).rposition(|w| w == name).unwrap() as u64;
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(at - 46 + 16)).unwrap();
    file.write_all(&(entry.crc32 ^ 1).to_le_bytes()).unwrap();
}

fn directory_entry(
    path: &Path,
    find: impl Fn(&factum::container::zip64::Archive) -> Option<&factum::container::zip64::CdEntry>,
) -> factum::container::zip64::CdEntry {
    let mut file = std::fs::File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = factum::container::zip64::read_archive(&mut file, len).unwrap();
    find(&archive).unwrap().clone()
}

#[test]
fn close_refuses_a_recheck_of_another_state() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let recheck = factum.recheck_container(id).unwrap();
    // another process adds a file after the re-check
    s.add(id, &[s.file("b.txt")]);
    let error = factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap_err();
    assert!(
        error.to_string().contains("changed since the re-check; re-check again"),
        "{error}"
    );
    assert!(s.events("container_closed").is_empty());
    // nothing was re-checked at all
    let error = factum
        .close_container_with(id, &factum.gpgsm(), &Default::default())
        .unwrap_err();
    assert!(error.to_string().contains("re-check again"), "{error}");
    // nothing changed: a re-check stays good, however long ago it was
    let recheck = factum.recheck_container(id).unwrap();
    factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap();
}

#[test]
fn close_refuses_a_recheck_once_a_late_signature_moved_the_end() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    factum.reopen_container(id).unwrap();
    let recheck = factum.recheck_container(id).unwrap();
    s.f.signer.set_active(true);
    assert_eq!(factum.sign_unsigned_containers(s.case_id).unwrap().0, 1);
    let error = factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap_err();
    assert!(error.to_string().contains("re-check again"), "{error}");
}

#[test]
fn a_recheck_before_a_crashed_addition_still_closes() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let recheck = factum.recheck_container(id).unwrap();
    // written, but the process died before its log entry: the state the re-check read is still what is closed
    let (mut volume, _) = Volume::open(&s.container_path(), None).unwrap();
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
    factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap();
}

#[test]
fn an_addition_is_refused_once_the_container_was_closed() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let mut volume = factum.open_container_for_add(id).unwrap();
    let staged = volume
        .stage_add(
            &[s.file("b.txt")],
            &s.options(),
            &AddProgress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
    // the file went away while it was being added to, and was closed without it
    let aside = s.f.path().join("aside");
    std::fs::rename(s.container_path(), &aside).unwrap();
    factum.close_container_without_file(id).unwrap();
    std::fs::rename(&aside, s.container_path()).unwrap();
    let error = factum.commit_container_add(id, &mut volume, staged).unwrap_err();
    assert!(error.to_string().contains("closed meanwhile"), "{error}");
    drop(volume);
    assert_eq!(s.events("container_files_added").len(), 1);
    assert_eq!(factum.container(id).unwrap().summary.file_count, 1);
    assert!(
        factum
            .compare_with_log(id, &Volume::open(&s.container_path(), None).unwrap().0)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn log_only_steps_wait_for_no_writer_and_need_no_file() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let record = factum.container(id).unwrap().adds[0].files[0].clone();
    let writer = Volume::open(&s.container_path(), None).unwrap();
    let error = factum.close_container_damaged(id, &damage_of(&record)).unwrap_err();
    assert!(error.to_string().contains("in use"), "{error}");
    assert!(s.events("container_closed").is_empty());
    drop(writer);
    factum.close_container_damaged(id, &damage_of(&record)).unwrap();

    let writer = Volume::open(&s.container_path(), None).unwrap();
    let error = factum.reopen_container(id).unwrap_err();
    assert!(error.to_string().contains("in use"), "{error}");
    assert!(s.events("container_reopened").is_empty());
    drop(writer);
    // without a file there is nothing to lock
    let aside = s.f.path().join("aside");
    std::fs::rename(s.container_path(), &aside).unwrap();
    factum.reopen_container(id).unwrap();
    factum.close_container_without_file(id).unwrap();
}

#[test]
fn a_replacement_the_log_does_not_record_fails() {
    let s = Setup::new();
    let id = s.create();
    let twin = s.file("twin.txt");
    std::fs::write(&twin, "a").unwrap();
    s.add(id, &[s.file("a.txt"), twin]);
    let files = s.f.factum().container(id).unwrap().adds[0].files.clone();
    let path = s.container_path();
    damage_content(&path, &files[0].arn);
    add_triple(
        &path,
        &files[0].arn,
        &format!("{}replacedBy", factum::container::FACTUM_NS),
        &files[1].arn,
    );
    // a recipient without the log sees a replaced copy, as before
    let factum = s.f.factum();
    let alone = factum::container::verify::verify_file(
        &path,
        &FakeSigner::new(false),
        &factum.gpgsm(),
        &|_, _| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        alone.findings.iter().any(|f| f.code == "replaced_copy"),
        "{:?}",
        alone.findings
    );
    assert!(!alone.findings.iter().any(|f| f.code == "log_mismatch"));
    let report = factum
        .verify_container_file(&path, &factum.gpgsm(), &|_, _| {}, &AtomicBool::new(false))
        .unwrap();
    assert!(
        report.findings.iter().any(|f| f.code == "log_mismatch"
            && f.level == factum::verifier::Level::Fail
            && f.message.contains("marks")),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_replacement_is_compared_with_the_log_both_ways() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    add_again(&s, id, &recheck);
    let factum = s.f.factum();
    let mut detail = factum.container(id).unwrap();
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    assert_eq!(detail.adds[1].replaces.len(), 1);
    assert!(factum::containers::compare_records(&detail, volume.graph(), i64::MAX).is_empty());
    // the log records one the container does not list
    detail.adds[1].replaces.push(("aff4://old".into(), "aff4://new".into()));
    let findings = factum::containers::compare_records(&detail, volume.graph(), i64::MAX);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].entry_id, Some(detail.adds[1].entry_id));
    // not as of a state before the addition that recorded it
    assert!(
        factum::containers::compare_records(&detail, volume.graph(), detail.adds[0].entry_id)
            .iter()
            .all(|f| !f.message.contains("aff4://new"))
    );
}

#[test]
fn folders_are_compared_with_the_log_both_ways() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.source.join("Users")]);
    let factum = s.f.factum();
    let mut detail = factum.container(id).unwrap();
    assert_eq!(detail.adds[0].folders.len(), 2);
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    assert!(factum::containers::compare_records(&detail, volume.graph(), i64::MAX).is_empty());
    detail.adds[0].folders[0].path += "x";
    let messages: Vec<String> = factum::containers::compare_records(&detail, volume.graph(), i64::MAX)
        .into_iter()
        .map(|f| f.message)
        .collect();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert!(messages[0].contains("in the case log but not in the container"));
    assert!(messages[1].contains("in no addition"));
}

/// Logs a `container_signed` entry, as an older version or another process may have left it.
fn log_signed(s: &Setup, uuid: &str, close: Option<u32>, sha: Option<&str>) {
    let mut payload = serde_json::json!({"event": "container_signed", "case_id": s.case_id, "container_id": uuid,
                                         "signatures": {"gpg": "F00", "x509": null}, "signed_utc": "x"});
    if let Some(close) = close {
        payload["close"] = close.into();
    }
    if let Some(sha) = sha {
        payload["turtle_sha256"] = sha.into();
    }
    let append = factum::log_service::Append {
        payload: Some(payload),
        allow_archived: true,
        ..Default::default()
    };
    s.f.factum().append(s.case_id, "system", "signed", append).unwrap();
}

#[test]
fn list_and_detail_agree_on_which_close_is_signed() {
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let agree = |signed: bool, damaged: bool| {
        let detail = factum.container(id).unwrap();
        assert_eq!(factum.list_containers(s.case_id).unwrap()[0], detail.summary);
        assert_eq!((detail.summary.signed, detail.summary.damaged), (signed, damaged));
    };
    let first = factum.close_container(id).unwrap();
    let uuid = factum.container(id).unwrap().summary.uuid;
    factum.reopen_container(id).unwrap();
    s.add(id, &[s.file("b.txt")]);
    let second = factum.close_container(id).unwrap();
    assert_ne!(first.turtle_sha256, second.turtle_sha256);
    agree(false, false);
    // an event that does not tell which close it signed proves nothing
    log_signed(&s, &uuid, None, None);
    agree(false, false);
    log_signed(&s, &uuid, Some(2), None);
    agree(false, false);
    // late signing signs the older close only: the newest decides
    log_signed(&s, &uuid, Some(1), Some(&first.turtle_sha256));
    agree(false, false);
    // a number that names the wrong close: the hash finds the right one
    log_signed(&s, &uuid, Some(1), Some(&second.turtle_sha256));
    agree(true, false);
    // a close as damaged after it is the newest
    factum.reopen_container(id).unwrap();
    agree(true, false);
    let record = factum.container(id).unwrap().adds[0].files[0].clone();
    factum.close_container_damaged(id, &damage_of(&record)).unwrap();
    agree(false, true);
    factum.reopen_container(id).unwrap();
    let aside = s.f.path().join("aside");
    std::fs::rename(s.container_path(), &aside).unwrap();
    factum.close_container_without_file(id).unwrap();
    agree(false, false);
}

#[test]
fn evidence_with_container_leaves_nothing_when_it_fails() {
    let s = Setup::new();
    let factum = s.f.factum();
    let entries = || {
        s.f.count(&format!("SELECT COUNT(*) FROM entries WHERE case_id = {}", s.case_id))
    };
    let evidence = || {
        s.f.count(&format!("SELECT COUNT(*) FROM evidence WHERE case_id = {}", s.case_id))
    };
    let (entries_before, evidence_before) = (entries(), evidence());
    let unchanged = || assert_eq!((entries(), evidence()), (entries_before, evidence_before));
    let create = |path: &Path| factum.create_evidence_with_container(s.case_id, "disk 2", "", "seized", path, "");

    // the file cannot be created
    let existing = s.f.path().join("taken.aff4l");
    std::fs::write(&existing, "something else").unwrap();
    assert!(create(&existing).is_err());
    assert_eq!(std::fs::read(&existing).unwrap(), b"something else");
    assert!(create(&s.f.path().join("no/such/folder/c.aff4l")).is_err());
    unchanged();
    // an evidence name it cannot be created with
    let path = s.container_path();
    assert!(
        factum
            .create_evidence_with_container(s.case_id, " ", "", "", &path, "")
            .is_err()
    );
    unchanged();
    // the second of the two entries cannot be signed: the first goes with it, and so does the file
    s.f.signer.fail_text_after.set(Some(1));
    assert!(create(&path).is_err());
    assert!(!path.exists());
    unchanged();
    // the name is free again and the retry leaves one of each
    let (evidence_id, id) = create(&path).unwrap();
    assert_eq!((entries(), evidence()), (entries_before + 2, evidence_before + 1));
    let detail = factum.container(id).unwrap();
    assert_eq!(detail.evidence_id, Some(evidence_id));
    let (volume, _) = Volume::open(&path, None).unwrap();
    let arn = volume.arn();
    assert_eq!(
        volume
            .graph()
            .first_value(&arn, &format!("{}evidenceId", factum::container::FACTUM_NS)),
        Some(evidence_id.to_string().as_str())
    );
    drop(volume);
    let report = factum.verify_case(s.case_id, None).unwrap();
    assert!(
        !report.findings.iter().any(|f| f.level == factum::verifier::Level::Fail),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_close_signs_the_stored_bytes() {
    use factum::verifier::Level;
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let path = s.container_path();
    // what an older serializer left: the same graph in other bytes
    let stored = String::from_utf8(member(&path, TURTLE).unwrap()).unwrap();
    write_turtle(&path, &format!("# written by an older factum\n{stored}"));
    let stored = member(&path, TURTLE).unwrap();
    let factum = s.f.factum();
    let close = factum.close_container(id).unwrap();
    assert_eq!(member(&path, TURTLE).unwrap(), stored);
    assert_eq!(member(&path, &history_member(1, TURTLE)).unwrap(), stored);
    assert_eq!(close.turtle_sha256, hex::encode(sha2::Sha256::digest(&stored)));
    // the state is the current one, so a late signature goes to the root as well
    s.f.signer.set_active(true);
    assert_eq!(factum.sign_unsigned_containers(s.case_id).unwrap().0, 1);
    assert!(member(&path, SIG_GPG).is_some());
    let report = factum
        .verify_container_file(&path, &factum.gpgsm(), &|_, _| {}, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(report.states.len(), 1, "{:?}", report.states);
    assert!(report.states[0].current);
    assert!(
        !report.findings.iter().any(|f| f.level == Level::Fail),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_closed_state_numbered_zero_is_a_failure() {
    use factum::container::zip64::{Appender, read_archive};
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    let path = s.container_path();
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let mut app = Appender::new(file, len, archive.entries).unwrap();
    app.add_bytes(&history_member(0, TURTLE), 8, b"# nothing").unwrap();
    app.finish(&[], &archive.comment).unwrap();
    drop(app);
    let report = factum
        .verify_container_file(&path, &factum.gpgsm(), &|_, _| {}, &AtomicBool::new(false))
        .unwrap();
    assert!(
        report.findings.iter().any(|f| f.code == "history"
            && f.level == factum::verifier::Level::Fail
            && f.message.contains("numbered 0")),
        "{:?}",
        report.findings
    );
    assert!(report.states.iter().all(|state| state.close != Some(0)));
}

#[test]
fn a_directory_fault_of_the_metadata_can_only_be_closed_as_damaged() {
    for member_name in ["version.txt", "container.description", TURTLE, HASHES] {
        let s = Setup::new();
        let id = s.create();
        s.add(id, &[s.file("a.txt")]);
        let path = s.container_path();
        flip_directory_crc(&path, &directory_entry(&path, |archive| archive.get(member_name)));
        let length = std::fs::metadata(&path).unwrap().len();
        let factum = s.f.factum();

        // neither appended to
        if member_name != HASHES {
            let error = factum.open_container_for_add(id).err().unwrap();
            assert!(error.is(ErrorKind::ContainerCrc), "{error}");
        }
        // nor signed
        let recheck = factum.recheck_container(id).unwrap();
        assert_eq!(recheck.directory_faults, [member_name]);
        assert!(recheck.mismatches.is_empty());
        let error = factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap_err();
        assert!(error.is(ErrorKind::ContainerCrc), "{error}");
        assert!(error.to_string().contains(member_name), "{error}");
        assert!(error.to_string().contains("closed as damaged"), "{error}");
        assert!(s.events("container_closed").is_empty());

        // the way out: nothing written, and the log says what the reason was
        let entry = factum.close_container_damaged(id, &recheck).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        let event = &s.events("container_closed")[0];
        assert_eq!(event["damaged"], serde_json::json!([]));
        assert_eq!(event["directory_fault"], serde_json::json!([member_name]));
        assert!(event.get("unchecked_files").is_none());
        let text = s.entry_text(entry);
        assert!(text.contains("1 directory fault, no file found damaged"), "{text}");
        assert!(!text.contains("match"), "{text}");
        let detail = factum.container(id).unwrap();
        assert!(detail.summary.damaged && !detail.summary.open && !detail.summary.signed);
        assert_eq!(detail.damaged_closes[0].3, [member_name]);
        assert_eq!(factum.list_containers(s.case_id).unwrap()[0], detail.summary);
        // the case can be archived now
        factum.reopen_container(id).unwrap();
        factum.close_container_damaged(id, &recheck).unwrap();
        factum.archive_case(s.case_id).unwrap();
    }
}

#[test]
fn metadata_that_differs_from_its_crc_and_cannot_be_read_is_a_directory_fault() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let path = s.container_path();
    write_turtle(&path, "@this is no turtle");
    flip_directory_crc(&path, &directory_entry(&path, |archive| archive.get(TURTLE)));
    let recheck = s.f.factum().recheck_container(id).unwrap();
    assert_eq!(recheck.directory_faults, [TURTLE]);
    assert_eq!(recheck.files, 0);
    let factum = s.f.factum();
    let entry = factum.close_container_damaged(id, &recheck).unwrap();
    // nobody looked at the file, so nothing is claimed about it
    let text = s.entry_text(entry);
    assert!(text.contains("1 directory fault, files not checked"), "{text}");
    assert!(!text.contains("no file found damaged"), "{text}");
    assert_eq!(s.events("container_closed")[0]["unchecked_files"], 1);
}

#[test]
fn a_content_crc_fault_stops_the_signature_and_names_the_member() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt"), s.file("b.txt")]);
    let arn = first_arn(&s, id);
    let path = s.container_path();
    let entry = directory_entry(&path, |archive| archive.get_arn(&arn));
    flip_directory_crc(&path, &entry);
    let factum = s.f.factum();
    // an addition does not read the content, so it does not stop for this
    drop(factum.open_container_for_add(id).unwrap());
    let recheck = factum.recheck_container(id).unwrap();
    assert!(recheck.mismatches.is_empty(), "the hashes matched");
    assert_eq!(recheck.directory_faults.len(), 1);
    let member = entry.name_lossy().to_string();
    assert!(
        recheck.directory_faults[0].contains(&member),
        "{:?}",
        recheck.directory_faults
    );
    let error = factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap_err();
    assert!(error.is(ErrorKind::ContainerCrc), "{error}");
    assert!(error.to_string().contains(&member), "{error}");
    assert!(s.events("container_closed").is_empty());
    let entry = factum.close_container_damaged(id, &recheck).unwrap();
    assert!(
        s.entry_text(entry).contains("no file found damaged"),
        "{}",
        s.entry_text(entry)
    );
}

#[test]
fn content_that_differs_from_its_hashes_is_damage_not_a_directory_fault() {
    let s = Setup::new();
    let (id, recheck) = damaged(&s);
    assert!(recheck.directory_faults.is_empty(), "{:?}", recheck.directory_faults);
    let entry = s.f.factum().close_container_damaged(id, &recheck).unwrap();
    assert!(s.events("container_closed")[0].get("directory_fault").is_none());
    assert!(
        s.entry_text(entry).contains("1 file doesn't match"),
        "{}",
        s.entry_text(entry)
    );
}

#[test]
fn a_close_as_damaged_needs_a_reason() {
    let s = Setup::new();
    let id = s.create();
    assert!(s.f.factum().close_container_damaged(id, &Default::default()).is_err());
    assert!(s.events("container_closed").is_empty());
}

#[test]
fn both_entries_of_a_new_evidence_container_are_signed_outside_the_write_lock() {
    use std::cell::Cell;
    use std::rc::Rc;
    let s = Setup::new();
    let db_path = s.f.path().join("factum.db");
    let signatures = Rc::new(Cell::new(0));
    let counted = signatures.clone();
    *s.f.signer.before_sign.borrow_mut() = Some(Box::new(move || {
        counted.set(counted.get() + 1);
        // another process can take the write lock at every signature: no prompt holds it up
        let other = rusqlite::Connection::open(&db_path).unwrap();
        other.busy_timeout(std::time::Duration::ZERO).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        other.execute_batch("ROLLBACK").unwrap();
    }));
    let factum = s.f.factum();
    let before = factum.leaf_hashes(s.case_id).unwrap().len();
    let path = s.container_path();
    factum
        .create_evidence_with_container(s.case_id, "disk 2", "", "seized", &path, "")
        .unwrap();
    assert_eq!(signatures.get(), 2);
    assert_eq!(factum.leaf_hashes(s.case_id).unwrap().len(), before + 2);
    let report = factum.verify_case(s.case_id, None).unwrap();
    assert!(
        report.findings.iter().all(|f| f.code == "not_sealed"),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_new_evidence_container_retries_both_entries_when_the_log_moved() {
    use std::cell::Cell;
    use std::rc::Rc;
    let s = Setup::new();
    let db_path = s.f.path().join("factum.db");
    let case_id = s.case_id;
    let once = Rc::new(Cell::new(true));
    *s.f.signer.before_sign.borrow_mut() = Some(Box::new(move || {
        // another process takes the predicted evidence id while the first entry is being signed
        if once.replace(false) {
            let other = rusqlite::Connection::open(&db_path).unwrap();
            other
                .execute(
                    "INSERT INTO evidence (case_id, description, evidence_hash, created_utc, details) \
                     VALUES (?, 'other', '', 'x', '')",
                    [case_id],
                )
                .unwrap();
        }
    }));
    let factum = s.f.factum();
    let path = s.container_path();
    let (evidence_id, id) = factum
        .create_evidence_with_container(s.case_id, "disk 2", "", "seized", &path, "")
        .unwrap();
    assert_eq!(factum.container(id).unwrap().evidence_id, Some(evidence_id));
    assert_eq!(factum.get_evidence(evidence_id).unwrap().unwrap().description, "disk 2");
    assert_eq!(s.events("container_created").len(), 1);
    let (volume, _) = Volume::open(&path, None).unwrap();
    let arn = volume.arn();
    assert_eq!(
        volume
            .graph()
            .first_value(&arn, &format!("{}evidenceId", factum::container::FACTUM_NS)),
        Some(evidence_id.to_string().as_str())
    );
}

#[cfg(unix)]
#[test]
fn a_file_that_cannot_be_reached_does_not_stop_the_log_only_steps() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |path: &Path, mode| std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    let s = Setup::new();
    let folder = s.f.path().join("mount");
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("c.aff4l");
    let factum = s.f.factum();
    let id = factum
        .create_container(s.case_id, "dead", s.evidence_id, &path, "")
        .unwrap();
    // a folder without permissions, as a dead mount: is_file says no, without the file being gone
    mode(&folder, 0o000);
    let reachable = path.is_file();
    let closed = (!reachable).then(|| factum.close_container_without_file(id));
    let reopened = (!reachable).then(|| factum.reopen_container(id));
    mode(&folder, 0o755);
    if reachable {
        return; // root reads everything
    }
    closed.unwrap().unwrap();
    reopened.unwrap().unwrap();
    // a file it may not open: close as damaged goes through all the same
    let record = factum::container::volume::FileRecord {
        arn: "aff4://x".into(),
        path: "x".into(),
        size: 0,
        md5: String::new(),
        sha1: String::new(),
        sha256: String::new(),
        metadata_only: false,
        excerpt: None,
        link: None,
        source: None,
        source_raw: None,
    };
    mode(&path, 0o000);
    let closed = factum.close_container_damaged(id, &damage_of(&record));
    mode(&path, 0o644);
    closed.unwrap();
}

#[test]
fn a_late_signature_keeps_what_was_logged_while_it_waited_for_the_lock() {
    use factum::container::x509::Gpgsm;
    let s = Setup::with_signer(FakeSigner::new(false));
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    factum.reopen_container(id).unwrap();
    s.f.signer.set_active(true);
    let (ready, go) = std::sync::mpsc::channel();
    let db_path = s.f.path().join("factum.db");
    let (source, options) = (s.file("b.txt"), s.options());
    let other = std::thread::spawn(move || {
        // another process, in the middle of an addition: it holds the lock until its log entry is committed
        let db = factum::Db::open(&db_path).unwrap();
        let signer = FakeSigner::new(true);
        let other = factum::Factum::with_seal_dir(&db, &signer, None);
        let mut volume = other.open_container_for_add(id).unwrap();
        let staged = volume
            .stage_add(&[source], &options, &AddProgress::default(), &AtomicBool::new(false))
            .unwrap();
        ready.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        other.commit_container_add(id, &mut volume, staged).unwrap();
    });
    go.recv().unwrap();
    // reads the log, then waits for the lock
    assert_eq!(factum.sign_unsigned_containers(s.case_id).unwrap(), (1, vec![]));
    other.join().unwrap();
    let (volume, _) = Volume::open(&s.container_path(), None).unwrap();
    assert!(factum.compare_with_log(id, &volume).unwrap().is_empty());
    assert_eq!(factum::container::volume::file_records(volume.graph()).len(), 2);
    drop(volume);
    s.add(id, &[s.file("c.txt")]);
    let close = factum.close_container(id).unwrap();
    assert_eq!(close.file_count, 3);
    let report = factum
        .verify_container_file(
            &s.container_path(),
            &Gpgsm::unavailable(),
            &|_, _| {},
            &AtomicBool::new(false),
        )
        .unwrap();
    assert!(
        !report.findings.iter().any(|f| f.code == "log_mismatch"),
        "{:?}",
        report.findings
    );
}

#[test]
fn closed_states_a_crafted_number_claims_are_one_finding() {
    use factum::container::zip64::{Appender, read_archive};
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    let path = s.container_path();
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let len = file.metadata().unwrap().len();
    let archive = read_archive(&mut file, len).unwrap();
    let mut app = Appender::new(file, len, archive.entries).unwrap();
    app.add_bytes(&history_member(u32::MAX, TURTLE), 8, b"# nothing")
        .unwrap();
    app.finish(&[], &archive.comment).unwrap();
    drop(app);
    let report = factum::container::verify::verify_file(
        &path,
        &FakeSigner::new(true),
        &factum.gpgsm(),
        &|_, _| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    let gaps: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.message.contains("are missing from the container"))
        .map(|f| f.message.as_str())
        .collect();
    assert_eq!(
        gaps,
        ["The closed states of closes 2 to 4294967294 are missing from the container."]
    );
}

#[test]
fn a_close_as_damaged_that_lands_during_a_close_stops_it() {
    use std::cell::Cell;
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    let recheck = factum.recheck_container(id).unwrap();
    let (db_path, path, aside) = (
        s.f.path().join("factum.db"),
        s.container_path(),
        s.f.path().join("aside"),
    );
    let once = Cell::new(true);
    *s.f.signer.before_sign.borrow_mut() = Some(Box::new(move || {
        // while this close signs its entry, another process closes the container without its lock: it found no file
        if once.replace(false) {
            let db = factum::Db::open(&db_path).unwrap();
            let signer = FakeSigner::new(true);
            let other = factum::Factum::with_seal_dir(&db, &signer, None);
            std::fs::rename(&path, &aside).unwrap();
            other.close_container_without_file(id).unwrap();
            std::fs::rename(&aside, &path).unwrap();
        }
    }));
    let length = std::fs::metadata(s.container_path()).unwrap().len();
    let error = factum.close_container_with(id, &factum.gpgsm(), &recheck).unwrap_err();
    assert!(
        error.to_string().contains("closed meanwhile; nothing was signed"),
        "{error}"
    );
    let closes = s.events("container_closed");
    assert_eq!(closes.len(), 1, "{closes:?}");
    assert_eq!(closes[0]["file_missing"], true);
    assert_eq!(std::fs::metadata(s.container_path()).unwrap().len(), length);
    assert!(member(&s.container_path(), &history_member(1, TURTLE)).is_none());
}

#[test]
fn a_recheck_that_ended_early_says_so_with_nothing_due_as_well() {
    let s = Setup::new();
    let id = s.create();
    s.add(id, &[s.file("a.txt")]);
    let factum = s.f.factum();
    factum.close_container(id).unwrap();
    factum.reopen_container(id).unwrap();
    let path = s.container_path();
    write_turtle(&path, "@this is no turtle");
    flip_directory_crc(&path, &directory_entry(&path, |archive| archive.get(TURTLE)));
    let recheck = factum.recheck_container(id).unwrap();
    assert!(recheck.arns.is_empty(), "nothing was added since the close");
    assert!(recheck.ended_early);
    let entry = factum.close_container_damaged(id, &recheck).unwrap();
    let text = s.entry_text(entry);
    assert!(text.contains("1 directory fault, files not checked"), "{text}");
    assert!(!text.contains("no file found damaged"), "{text}");
    assert_eq!(s.events("container_closed")[1]["unchecked_files"], 0);
}
