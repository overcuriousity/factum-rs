//! The public sample container (samples/container/, made by scripts/sample-container.sh) still verifies: its content
//! and both closed states. Its signatures are checked by CI with verify_container.py and the published keys.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use factum::container::verify::verify_file;
use factum::container::x509::Gpgsm;
use factum::signer::FakeSigner;
use factum::verifier::Level;

#[test]
fn sample_verifies() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/container/sample.aff4l");
    let gpgsm = Gpgsm::new(Some(tempfile::tempdir().unwrap().path().to_path_buf()));
    let report = verify_file(
        &path,
        &FakeSigner::new(false),
        &gpgsm,
        &|_, _| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    let broken: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.level == Level::Fail && ["stream_hash", "turtle_hash", "history"].contains(&f.code))
        .collect();
    assert!(broken.is_empty(), "{broken:?}");
    assert_eq!(report.states.iter().filter(|s| s.close.is_some()).count(), 2);
    assert_eq!(report.checked_files, 3);
}
