//! Writes the public sample container (samples/container/sample.aff4l), signed with GPG and X.509: two files, a
//! close, a reopen, one more file, a second close. Run by `scripts/sample-container.sh`, which makes the throwaway
//! keys: `cargo run --example sample_container -- <out.aff4l> <gnupg home> <X.509 fingerprint> <source folder>`

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use factum::container::volume::{AddOptions, AddProgress};
use factum::container::x509::X509_CERT_SETTING;
use factum::signer::{GnupgSigner, Signer as _};
use factum::{Db, Factum};

fn main() -> factum::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [out, home, x509, source] = args.as_slice() else {
        eprintln!("usage: sample_container <out.aff4l> <gnupg home> <X.509 fingerprint> <source folder>");
        std::process::exit(2);
    };
    let (home, source) = (PathBuf::from(home), PathBuf::from(source));
    let work = tempfile::tempdir()?;
    let db = Db::open(&work.path().join("sample.db"))?;
    let signer = GnupgSigner::new(&db, Some(home));
    let key = signer
        .list_keys()
        .first()
        .map(|k| k.keyid.clone())
        .expect("a GPG key in the home");
    assert!(signer.set_active_key(&db, &key), "the GPG key cannot be used");
    db.set_setting(X509_CERT_SETTING, x509)?;
    let factum = Factum::with_seal_dir(&db, &signer, Some(work.path().to_path_buf()));
    let case_id = factum.create_case("SAMPLE", "factum sample container (test only)", "")?;
    let (_, id) = factum.create_evidence_with_container(
        case_id,
        "Sample evidence",
        "",
        "A throwaway sample for checking other AFF4-L tools against factum's signatures.",
        &PathBuf::from(out),
        &source.display().to_string(),
    )?;
    let add = |files: &[&str]| -> factum::Result<()> {
        let options = AddOptions {
            base: source.clone(),
            keep_path: true,
            ..Default::default()
        };
        let sources: Vec<PathBuf> = files.iter().map(|f| source.join(f)).collect();
        let mut volume = factum.open_container_for_add(id)?;
        let staged = volume.stage_add(&sources, &options, &AddProgress::default(), &AtomicBool::new(false))?;
        factum.commit_container_add(id, &mut volume, staged)?;
        Ok(())
    };
    add(&["hello.txt", "docs/readme.md"])?;
    let first = factum.close_container(id)?;
    factum.reopen_container(id)?;
    add(&["later.txt"])?;
    let second = factum.close_container(id)?;
    for close in [&first, &second] {
        if close.gpg.is_none() || close.x509.is_none() {
            eprintln!("not signed with both GPG and X.509: {:?}", close.x509_refused);
            std::process::exit(1);
        }
    }
    println!("{out}: two closes, signed with GPG {key} and X.509 {x509}");
    Ok(())
}
