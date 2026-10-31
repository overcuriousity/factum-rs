//! The public sample container (samples/container/, made by scripts/sample-container.sh) still verifies: its content
//! and both closed states. Its signatures are checked by CI with verify_container.py and the published keys.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use factum::container::verify::verify_file;
use factum::container::x509::Gpgsm;
use factum::container::zip64::{member_bytes, read_archive};
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
    // both closes were signed by the certificate the container stores
    assert!(
        !report.findings.iter().any(|f| f.code == "x509_mismatch"),
        "{:?}",
        report.findings
    );
    if gpgsm.available() {
        let signers = report
            .states
            .iter()
            .filter_map(|s| s.x509.as_ref()?.fingerprint.as_ref());
        assert_eq!(signers.count(), 2);
    }
    assert_eq!(report.states.iter().filter(|s| s.close.is_some()).count(), 2);
    assert_eq!(report.checked_files, 3);
}

/// Every state in the file, not only the newest: its directory reads to its end and its members to theirs.
#[test]
fn every_state_of_the_sample_reads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/container/sample.aff4l");
    let bytes = std::fs::read(&path).unwrap();
    let ends: Vec<u64> = bytes
        .windows(22)
        .enumerate()
        .filter(|(_, w)| w.starts_with(b"PK\x05\x06"))
        .map(|(at, w)| (at + 22 + u16::from_le_bytes([w[20], w[21]]) as usize) as u64)
        .collect();
    assert!(ends.len() > 2, "{ends:?}");
    assert_eq!(ends.last(), Some(&(bytes.len() as u64)));
    let mut file = std::fs::File::open(&path).unwrap();
    for end in ends {
        let archive = read_archive(&mut file, end).unwrap();
        for entry in &archive.entries {
            member_bytes(&mut file, entry).unwrap();
        }
    }
}
