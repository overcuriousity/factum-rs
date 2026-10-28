//! The container's ZIP64 output as other readers see it: the zip crate, Python's zipfile, and a later append.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use factum::container::zip64::{Appender, read_archive};

fn write_two_states(path: &Path) -> (u64, u64) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    let mut app = Appender::new(file, 0, Vec::new()).unwrap();
    app.add_bytes("version.txt", 0, b"major=2\nminor=1\ntool=factum\n")
        .unwrap();
    app.add_bytes("aff4://0b4c6f2e-1a2b-4c3d-8e9f-001122334455", 8, &[42u8; 100_000])
        .unwrap();
    let end1 = app.finish(&[], b"aff4://v").unwrap();
    let mut file = app.into_file();
    let entries = read_archive(&mut file, end1).unwrap().entries;
    let mut app = Appender::new(file, end1, entries).unwrap();
    app.add_bytes("information.turtle", 8, "ünïcode name test".as_bytes())
        .unwrap();
    app.add_bytes("factum/history/1/information.turtle", 0, b"h").unwrap();
    let end2 = app.finish(&[], b"aff4://v").unwrap();
    (end1, end2)
}

#[test]
fn zip_crate_reads_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.aff4l");
    write_two_states(&path);
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
    let mut names: Vec<String> = archive.file_names().map(|name| name.unwrap().to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "aff4://0b4c6f2e-1a2b-4c3d-8e9f-001122334455",
            "factum/history/1/information.turtle",
            "information.turtle",
            "version.txt"
        ]
    );
    let mut text = String::new();
    archive
        .by_name("information.turtle")
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "ünïcode name test");
    let mut data = Vec::new();
    archive
        .by_name("aff4://0b4c6f2e-1a2b-4c3d-8e9f-001122334455")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, vec![42u8; 100_000]);
}

#[test]
fn python_zipfile_reads_output() {
    let Ok(python) = which::which("python3") else {
        eprintln!("python3 not installed, skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.aff4l");
    write_two_states(&path);
    let output = std::process::Command::new(python)
        .args([
            "-I",
            "-c",
            "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None; \
             assert z.comment == b'aff4://v'; print(len(z.namelist()))",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "4");
}

#[test]
fn append_keeps_earlier_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.aff4l");
    let (end1, end2) = write_two_states(&path);
    // the first state, as a copy handed over after the first finish, is a prefix of the file
    let all = std::fs::read(&path).unwrap();
    assert_eq!(all.len() as u64, end2);
    let mut file = std::fs::File::open(&path).unwrap();
    let first = read_archive(&mut file, end1).unwrap();
    assert_eq!(first.entries.len(), 2);
    let copy = dir.path().join("copy.aff4l");
    std::fs::write(&copy, &all[..end1 as usize]).unwrap();
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&copy).unwrap()).unwrap();
    assert_eq!(archive.len(), 2);
    let mut version = String::new();
    archive
        .by_name("version.txt")
        .unwrap()
        .read_to_string(&mut version)
        .unwrap();
    assert!(version.starts_with("major=2"));
}

#[test]
fn unzip_tests_output() {
    let Ok(unzip) = which::which("unzip") else {
        eprintln!("unzip not installed, skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.aff4l");
    write_two_states(&path);
    let output = std::process::Command::new(unzip).arg("-t").arg(&path).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("No errors detected"), "{text}");
}
