//! The public sample container (samples/container/, made by scripts/sample-container.sh) still verifies: its content
//! and both closed states. Its signatures are checked by CI with verify_container.py and the published keys.

use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use factum::container::verify::verify_file;
use factum::container::volume::VERIFY_CONTAINER_PY;
use factum::container::x509::Gpgsm;
use factum::container::zip64::{member_bytes, read_archive};
use factum::signer::FakeSigner;
use factum::verifier::Level;

/// Whether `program` is an MSYS build, as Git for Windows brings: it takes a native `--homedir` for a relative path, so
/// nothing can be done with one. Its `--version` gives its home in POSIX form. factum goes by native builds (Gpg4win).
fn msys_build(program: &str) -> bool {
    cfg!(windows)
        && Command::new(program).arg("--version").output().is_ok_and(|output| {
            let text = String::from_utf8_lossy(&output.stdout);
            text.lines().any(|line| line.starts_with("Home: /"))
        })
}

#[test]
fn sample_verifies() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/container/sample.aff4l");
    let home = tempfile::tempdir().unwrap();
    let gpgsm = Gpgsm::new(Some(home.path().to_path_buf()));
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
    if gpgsm.available() && !msys_build("gpgsm") {
        let signers = report
            .states
            .iter()
            .filter_map(|s| s.x509.as_ref()?.fingerprint.as_ref());
        assert_eq!(signers.count(), 2);
    }
    assert_eq!(report.states.iter().filter(|s| s.close.is_some()).count(), 2);
    assert_eq!(report.checked_files, 3);
}

/// The script of this build, as CI runs the one the sample carries. Signatures that cannot be checked for want of gpg or
/// openssl are warnings, so it passes without them as well.
#[test]
fn this_build_of_the_script_passes_the_sample() {
    let Ok(python) = which::which("python3") else {
        eprintln!("skipped: python3 is not installed");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("verify_container.py");
    std::fs::write(&script, VERIFY_CONTAINER_PY).unwrap();
    let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/container");
    let mut command = Command::new(python);
    command
        .args(["-I", "-X", "utf8"])
        .arg(&script)
        .arg(samples.join("sample.aff4l"))
        .arg("--ca")
        .arg(samples.join("root.pem"))
        .arg("--use-carried-key");
    // an MSYS gpg cannot use the script's temporary home: without it the signatures are warnings, and openssl stays
    let without_gpg = msys_build("gpg");
    if without_gpg {
        let gpg = format!("gpg{}", std::env::consts::EXE_SUFFIX);
        let path = std::env::var_os("PATH").unwrap_or_default();
        let folders = std::env::split_paths(&path).filter(|folder| !folder.join(&gpg).exists());
        command.env("PATH", std::env::join_paths(folders).unwrap());
    }
    let output = command.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{text}");
    assert!(!without_gpg || !text.contains("openssl is not installed"), "{text}");
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
