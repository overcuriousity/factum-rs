//! The public sample container (samples/container/, made by scripts/sample-container.sh) still verifies: its content
//! and both closed states. Its signatures are checked by CI with verify_container.py and the published keys.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use factum::container::verify::verify_file;
use factum::container::volume::VERIFY_CONTAINER_PY;
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
    let output = std::process::Command::new(python)
        .args(["-I", "-X", "utf8"])
        .arg(&script)
        .arg(samples.join("sample.aff4l"))
        .arg("--ca")
        .arg(samples.join("root.pem"))
        .arg("--use-carried-key")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
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

/// Temporary: what gpg and gpgsm do with the sample on the Windows runner. Always panics, so its output is in the log.
#[cfg(windows)]
#[test]
fn diag_windows_gpg_temporary() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn run(label: &str, program: &Path, args: &[&str], input: &[u8]) {
        println!("=== {label}: {} {args:?}", program.display());
        let started = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match started {
            Ok(child) => child,
            Err(e) => return println!("could not start: {e}"),
        };
        let mut stdin = child.stdin.take().unwrap();
        let data = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
        let output = child.wait_with_output();
        let _ = writer.join();
        match output {
            Ok(output) => println!(
                "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(e) => println!("could not wait: {e}"),
        }
    }

    /// `C:\Users\x` as `/c/Users/x`.
    fn msys(path: &Path) -> String {
        let text = path.display().to_string().replace('\\', "/");
        match text.as_bytes() {
            [drive, b':', ..] => format!("/{}{}", (*drive as char).to_ascii_lowercase(), &text[2..]),
            _ => text,
        }
    }

    fn home(prefix: &str) -> tempfile::TempDir {
        tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
    }

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/container/sample.aff4l");
    let length = std::fs::metadata(&path).unwrap().len();
    let mut file = std::fs::File::open(&path).unwrap();
    let archive = read_archive(&mut file, length).unwrap();
    let mut member = |name: &str| member_bytes(&mut file, archive.get(name).unwrap()).unwrap();
    let (turtle, gpg_signature) = (member("information.turtle"), member("information.turtle.asc"));
    let (key, x509_signature) = (
        member("information.turtle.pubkey.asc"),
        member("information.turtle.factum.sig"),
    );
    let chain = member("information.turtle.factum.cer");

    println!("=== tools");
    for name in ["gpg", "gpgsm", "gpgconf", "gpg-agent", "openssl", "python3"] {
        println!("{name}: {:?}", which::which(name));
    }
    println!("temp dir: {}", std::env::temp_dir().display());
    let gpg = which::which("gpg").unwrap();
    let gpgsm = which::which("gpgsm").unwrap();
    let gpgconf = which::which("gpgconf");
    run("gpg version", &gpg, &["--version"], b"");
    run("gpgsm version", &gpgsm, &["--version"], b"");
    if let Ok(gpgconf) = &gpgconf {
        run("gpgconf dirs", gpgconf, &["--list-dirs"], b"");
    }

    // gpg, as verify_container.py runs it with --use-carried-key: a new home each, so the two forms can be compared
    let work = home("fc-");
    let signature = work.path().join("signature.asc");
    std::fs::write(&signature, &gpg_signature).unwrap();
    let signature = signature.display().to_string();
    for form in ["native", "msys"] {
        let dir = home("fc-");
        let given = if form == "native" {
            dir.path().display().to_string()
        } else {
            msys(dir.path())
        };
        let base = [
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "error",
            "--status-fd",
            "2",
            "--homedir",
            &given,
        ];
        let with = |rest: &[&'static str]| {
            let mut args = base.to_vec();
            args.extend_from_slice(rest);
            args
        };
        run(&format!("gpg {form}: home it uses"), &gpg, &with(&["--version"]), b"");
        run(&format!("gpg {form}: import"), &gpg, &with(&["--import"]), &key);
        run(
            &format!("gpg {form}: list keys"),
            &gpg,
            &with(&["--list-keys", "--with-colons", "--fixed-list-mode"]),
            b"",
        );
        let mut verify = base.to_vec();
        verify.extend(["--verify", signature.as_str(), "-"]);
        run(&format!("gpg {form}: verify"), &gpg, &verify, &turtle);
        println!("--- files in the home: {:?}", file_names(dir.path()));
        if let Ok(gpgconf) = &gpgconf {
            run(
                &format!("gpgconf {form}: kill"),
                gpgconf,
                &["--homedir", &given, "--kill", "all"],
                b"",
            );
        }
    }

    // gpgsm, as src/container/x509.rs runs it
    for form in ["native", "msys"] {
        let dir = home("fx-");
        std::fs::write(dir.path().join("gpg-agent.conf"), "no-allow-mark-trusted\n").unwrap();
        std::fs::write(dir.path().join("trustlist.txt"), "").unwrap();
        let (signature_file, data_file) = (dir.path().join("signature.pem"), dir.path().join("data"));
        std::fs::write(&signature_file, &x509_signature).unwrap();
        std::fs::write(&data_file, &turtle).unwrap();
        let (signature_arg, data_arg) = (signature_file.display().to_string(), data_file.display().to_string());
        let given = if form == "native" {
            dir.path().display().to_string()
        } else {
            msys(dir.path())
        };
        let base = ["--batch", "--no-tty", "--status-fd", "2", "--homedir", &given];
        let mut import = base.to_vec();
        import.push("--import");
        run(&format!("gpgsm {form}: import"), &gpgsm, &import, &chain);
        let mut verify = base.to_vec();
        verify.extend([
            "--disable-crl-checks",
            "--disable-ocsp",
            "--verify",
            &signature_arg,
            &data_arg,
        ]);
        run(&format!("gpgsm {form}: verify"), &gpgsm, &verify, b"");
        let mut list = base.to_vec();
        list.extend(["--with-colons", "--list-keys"]);
        run(&format!("gpgsm {form}: list keys"), &gpgsm, &list, b"");
        println!("--- files in the home: {:?}", file_names(dir.path()));
        if let Ok(gpgconf) = &gpgconf {
            run(
                &format!("gpgconf {form}: kill"),
                gpgconf,
                &["--homedir", &given, "--kill", "all"],
                b"",
            );
        }
    }

    // what the failing test calls
    let text = String::from_utf8_lossy(&x509_signature).into_owned();
    let existing = home("fx-");
    let check = Gpgsm::new(Some(existing.path().to_path_buf())).verify_detached(&text, &turtle);
    println!("=== Gpgsm::verify_detached, home exists\n{check:?}");
    let gone = Gpgsm::new(Some(tempfile::tempdir().unwrap().path().to_path_buf()));
    println!(
        "=== Gpgsm::verify_detached, home gone\n{:?}",
        gone.verify_detached(&text, &turtle)
    );

    panic!("diagnostic only: read the output above");
}

/// Temporary, for `diag_windows_gpg_temporary`.
#[cfg(windows)]
fn file_names(folder: &Path) -> Vec<String> {
    std::fs::read_dir(folder)
        .map(|names| {
            names
                .flatten()
                .map(|name| name.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}
