//! Differential fuzz of factum's verifier and verify_container.py. Scratch: copied to tests/ for a run, never committed.
//! FUZZ_COUNT mutants, FUZZ_SEED, FUZZ_OUT for the report and the mutants that disagree.
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use factum::container::verify::{ContainerFormat, verify_file};
use factum::container::volume::{AddOptions, AddProgress, HASHES, TURTLE, VERIFY_CONTAINER_PY};
use factum::container::x509::Gpgsm;
use factum::container::zip64::{Appender, read_archive};
use factum::signer::{GnupgSigner, Signer as _};
use factum::verifier::Level;
use factum::{Db, Factum};

fn hashes_bytes(uuid: &str, text: &[u8]) -> Vec<u8> {
    use factum::container::AFF4_NS;
    use factum::container::turtle::{self, Term};
    use sha2::Digest;
    let mut hashes = turtle::Graph::default();
    for (name, value) in [
        ("SHA256", hex::encode(sha2::Sha256::digest(text))),
        ("SHA512", hex::encode(sha2::Sha512::digest(text))),
    ] {
        let term = Term::Literal { value, datatype: Some(format!("{AFF4_NS}{name}")) };
        hashes.add(&format!("aff4://{uuid}/{TURTLE}"), &format!("{AFF4_NS}hash"), term);
    }
    turtle::write(&hashes, &[("aff4", AFF4_NS)]).into_bytes()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn base(dir: &Path, home: &common::GpgHome, open: bool) -> PathBuf {
    let db = Db::open(&dir.join("factum.db")).unwrap();
    let signer = GnupgSigner::new(&db, Some(home.path()));
    let key = signer.list_keys()[0].keyid.clone();
    assert!(signer.set_active_key(&db, &key));
    let factum = Factum::with_seal_dir(&db, &signer, Some(dir.to_path_buf()));
    let case_id = factum.create_case("C-1", "Case", "").unwrap();
    let source = dir.join("mnt");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("small.txt"), b"small").unwrap();
    std::fs::write(source.join("third.txt"), b"third file").unwrap();
    std::fs::write(source.join("big.bin"), (0..200_000u32).map(|i| (i % 249) as u8).collect::<Vec<_>>()).unwrap();
    let path = dir.join("c.aff4l");
    let id = factum
        .create_container(case_id, "C", factum.create_evidence(case_id, "disk", "", "").unwrap(), &path, &source.display().to_string())
        .unwrap();
    let options = AddOptions { base: source.clone(), keep_path: true, metadata_only: false, excerpt: None, replaces: Vec::new() };
    let names: &[&str] = if open { &["small.txt", "big.bin", "third.txt"] } else { &["small.txt", "big.bin"] };
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            factum.reopen_container(id).unwrap();
        }
        let mut volume = factum.open_container_for_add(id).unwrap();
        volume.segment_limit = 100_000;
        let staged = volume.stage_add(&[source.join(name)], &options, &AddProgress::default(), &AtomicBool::new(false)).unwrap();
        factum.commit_container_add(id, &mut volume, staged).unwrap();
        drop(volume);
        if index + 1 < names.len() || !open {
            factum.close_container(id).unwrap();
        }
    }
    path
}

const KINDS: [&str; 16] = [
    "bit anywhere", "bit in directory", "bit in end records", "bit in local header", "bit in metadata", "directory field",
    "truncate", "append", "splice", "omit members", "add member", "replace member", "turtle edit", "method", "swap offsets", "version line",
];

fn add_and_omit(path: &Path, add: &[(String, Vec<u8>)], omit: &[String]) {
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let Ok(archive) = read_archive(&mut file, len) else { return };
    let mut app = Appender::new(file, len, archive.entries).unwrap();
    for (name, data) in add {
        app.add_bytes(name, 0, data).unwrap();
    }
    let omit: Vec<&str> = omit.iter().map(String::as_str).collect();
    app.finish(&omit, &archive.comment).unwrap();
}

fn mutate(rng: &mut Rng, kind: usize, base: &[u8], path: &Path) {
    let mut file = std::fs::File::open(path).unwrap();
    let archive = read_archive(&mut file, base.len() as u64).unwrap();
    drop(file);
    let names: Vec<String> = archive.entries.iter().map(|e| e.name_lossy()).collect();
    let cd = base.windows(4).position(|w| w == b"PK\x01\x02").map(|_| {
        // the newest directory: after the last member
        archive.entries.iter().map(|e| e.header_offset + 30 + e.name.len() as u64 + 20 + e.compressed_size).max().unwrap() as usize
    }).unwrap();
    let entry = rng.pick(&archive.entries).clone();
    let mut bytes = base.to_vec();
    let flip = |bytes: &mut Vec<u8>, rng: &mut Rng, from: usize, to: usize| {
        let at = from + rng.below(to.saturating_sub(from).min(bytes.len() - from));
        bytes[at] ^= 1 << rng.below(8);
    };
    let directory_at = |bytes: &[u8], name: &[u8]| {
        let listed = [name, &[1, 0, 24, 0]].concat();
        bytes.windows(listed.len()).rposition(|w| w == listed).map(|at| at - 46)
    };
    match kind {
        0 => flip(&mut bytes, rng, 0, base.len()),
        1 => flip(&mut bytes, rng, cd, base.len()),
        2 => flip(&mut bytes, rng, base.len() - 160, base.len()),
        3 => {
            let at = entry.header_offset as usize;
            flip(&mut bytes, rng, at, at + 30 + entry.name.len());
        }
        4 => {
            let metadata: Vec<_> = archive.entries.iter().filter(|e| e.name_lossy().contains("information.turtle")).collect();
            let e = *rng.pick(&metadata);
            std::fs::write(path.with_extension("name"), e.name_lossy()).unwrap();
            let at = e.header_offset as usize + 30 + e.name.len() + 20;
            flip(&mut bytes, rng, at, at + e.compressed_size.max(1) as usize);
        }
        5 => {
            if let Some(at) = directory_at(&bytes, &entry.name) {
                let name_len = entry.name.len();
                // (offset, width) of the fields of an entry and its ZIP64 extra
                let (field, width) = *rng.pick(&[(8usize, 2usize), (10, 2), (16, 4), (20, 4), (24, 4), (28, 2), (30, 2), (32, 2), (42, 4),
                    (46 + name_len + 4, 8), (46 + name_len + 12, 8), (46 + name_len + 20, 8)]);
                let values: [u64; 8] = [0, 1, 0xFFFF, 0xFFFF_FFFF, u64::MAX, base.len() as u64, entry.compressed_size + 1, entry.size + 1];
                let value = *rng.pick(&values);
                bytes[at + field..at + field + width].copy_from_slice(&value.to_le_bytes()[..width]);
            }
        }
        6 => {
            let keep = if rng.below(2) == 0 { base.len() - 1 - rng.below(600) } else { rng.below(base.len()) };
            bytes.truncate(keep);
        }
        7 => {
            let tail: Vec<u8> = match rng.below(5) {
                0 => vec![rng.next() as u8; 1 + rng.below(70_000)],
                1 => (0..rng.below(3000)).map(|_| rng.next() as u8).collect(),
                2 => b"PK\x05\x06".repeat(1 + rng.below(4000)),
                3 => base[base.len() - rng.below(2000)..].to_vec(),
                _ => b"PK\x03\x04".repeat(1 + rng.below(40)),
            };
            bytes.extend(tail);
        }
        8 => {
            let length = 1 + rng.below(400);
            let (from, to) = (rng.below(base.len() - length), rng.below(base.len() - length));
            let piece = base[from..from + length].to_vec();
            bytes[to..to + length].copy_from_slice(&piece);
        }
        9 | 10 | 11 | 12 | 15 => {}
        13 => {
            if let Some(at) = directory_at(&bytes, &entry.name) {
                let method = *rng.pick(&[0u8, 8, 9, 12, 99]);
                bytes[at + 10] = method;
                if rng.below(4) > 0 {
                    bytes[entry.header_offset as usize + 8] = method;
                }
            }
        }
        14 => {
            let other = rng.pick(&archive.entries).clone();
            if let (Some(a), Some(b)) = (directory_at(&bytes, &entry.name), directory_at(&bytes, &other.name)) {
                let (at_a, at_b) = (a + 46 + entry.name.len() + 20, b + 46 + other.name.len() + 20);
                bytes[at_a..at_a + 8].copy_from_slice(&other.header_offset.to_le_bytes());
                bytes[at_b..at_b + 8].copy_from_slice(&entry.header_offset.to_le_bytes());
            }
        }
        _ => unreachable!(),
    }
    std::fs::write(path, &bytes).unwrap();
    let close = |rng: &mut Rng| *rng.pick(&["1", "2", "3", "0", "01", "x", "4294967295", "4294967296", "+1"]);
    match kind {
        9 => {
            let omit: Vec<String> = (0..1 + rng.below(3)).map(|_| rng.pick(&names).clone()).collect();
            add_and_omit(path, &[], &omit);
        }
        10 => {
            let number = close(rng);
            let leaf = *rng.pick(&["information.turtle", "information.turtle.hashes", "information.turtle.asc", "extra", ""]);
            let name = match rng.below(4) {
                0 => format!("factum/history/{number}/{leaf}"),
                1 => "information.hdt".to_string(),
                2 => (*rng.pick(&["information.turtle.asc", "information.turtle.factum.sig", "information.turtle.factum.cer", "information.turtle.pubkey.asc"])).to_string(),
                _ => format!("factum/history/{number}"),
            };
            add_and_omit(path, &[(name, b"added".to_vec())], &[]);
        }
        11 => {
            let name = rng.pick(&names).clone();
            let data = rng.pick(&[&b""[..], b"x", b"# nothing\n", b"x> .", b"major=2\nminor=1\n", b"-----BEGIN CERTIFICATE-----\n", b"aff4://11111111-2222-4333-8444-555555555555"]).to_vec();
            add_and_omit(path, &[(name, data)], &[]);
        }
        12 => {
            let member_of = |name: &str| {
                let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
                let mut member = archive.by_name(name).unwrap();
                let mut text = String::new();
                std::io::Read::read_to_string(&mut member, &mut text).unwrap();
                text
            };
            let mut text = member_of(TURTLE);
            let uuid = member_of("container.description");
            let lines: Vec<&str> = text.lines().collect();
            let line = lines[rng.below(lines.len())].to_string();
            let imports = format!("<aff4://x/{}> <http://aff4.org/Schema#x> \"y\" .", rng.below(9));
            let edited = match rng.below(19) {
                12 => line.replace(" ;", ",x ;"),
                13 => line.replace(" ;", "#x ;"),
                14 => line.replace(" ;", "(x) ;"),
                15 => line.replace(" ;", ". ;"),
                16 => line.replace(" .", " ;"),
                17 => format!("@prefix x: <y:> .\n{line}"),
                18 => line.replace("aff4://", "aff4:\\u002F/"),
                0 => line.replace(" ;", " , aff4:Other ;"),
                1 => format!("# {line}"),
                2 => line.replace("aff4:", "nope:"),
                3 => line.replacen('a', "\\u0061", 1),
                4 => line.replace('"', "'"),
                5 => format!("{line}  "),
                6 => line.replace("<", "< "),
                7 => line.replace('"', "\"\\q"),
                8 => imports,
                9 => line.replace(" .", " ;"),
                10 => format!("    aff4l:imports <{uuid}/missing> ;\n{line}"),
                _ => String::new(),
            };
            text = text.replacen(&line, &edited, 1);
            let keep_signatures = rng.below(3) == 0;
            let omit: Vec<String> = if keep_signatures { Vec::new() } else {
                ["information.turtle.asc", "information.turtle.pubkey.asc"].map(str::to_string).to_vec()
            };
            let uuid = uuid.trim_start_matches("aff4://").to_string();
            add_and_omit(path, &[(TURTLE.to_string(), text.as_bytes().to_vec()), (HASHES.to_string(), hashes_bytes(&uuid, text.as_bytes()))], &omit);
        }
        15 => {
            let line = *rng.pick(&[&b"major=2\nminor=1\ntool=other 1\n"[..], b"major=2\nminor=1\n", b"major=1\nminor=0\ntool=factum\n", b"major=21\nminor=1\n", b"minor=1\nmajor=2\r\n", b"major= 2 \nminor=1\n"]);
            add_and_omit(path, &[("version.txt".to_string(), line.to_vec())], &[]);
        }
        _ => {}
    }
}

fn python_verdict(script: &Path, path: &Path, home: &Path) -> (String, Vec<String>, String) {
    let output = Command::new("timeout")
        .args(["60", "python3", "-I", "-X", "utf8"])
        .arg(script)
        .arg(path)
        .env("GNUPGHOME", home)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let code = output.status.code().unwrap_or(-1);
    let level = if text.contains("Traceback") || !(code == 0 || code == 1) {
        format!("CRASH{code}")
    } else if code == 1 {
        "Fail".to_string()
    } else if text.contains(", 0 warning(s)") {
        "Ok".to_string()
    } else {
        "Warn".to_string()
    };
    let codes = text
        .lines()
        .filter(|l| !l.starts_with('\u{2713}'))
        .filter_map(|l| l.strip_suffix(']')?.rsplit_once('[').map(|(_, c)| c.to_string()))
        .collect();
    (level, codes, text)
}

#[test]
fn fuzz() {
    let count: usize = std::env::var("FUZZ_COUNT").unwrap().parse().unwrap();
    let seed: u64 = std::env::var("FUZZ_SEED").unwrap().parse().unwrap();
    let out = PathBuf::from(std::env::var("FUZZ_OUT").unwrap());
    std::fs::create_dir_all(&out).unwrap();
    let home = common::GpgHome::new("Factum Test <test@factum.invalid>").unwrap();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let bases = [base(dirs[0].path(), &home, false), base(dirs[1].path(), &home, true)];
    let contents = bases.each_ref().map(|p| std::fs::read(p).unwrap());
    let scripts = tempfile::tempdir().unwrap();
    let script = scripts.path().join("verify_container.py");
    std::fs::write(&script, VERIFY_CONTAINER_PY).unwrap();
    let next = AtomicUsize::new(0);
    let tally = Mutex::new(BTreeMap::<String, usize>::new());
    let lines = Mutex::new(Vec::<String>::new());
    let gnupg = home.path();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let (next, tally, lines, script, contents, out, gnupg, bases) = (&next, &tally, &lines, &script, &contents, &out, &gnupg, &bases);
            scope.spawn(move || {
                let work = tempfile::tempdir().unwrap();
                let db = Db::open(&work.path().join("f.db")).unwrap();
                let signer = GnupgSigner::new(&db, Some(gnupg.clone()));
                let gpgsm = Gpgsm::unavailable();
                let path = work.path().join(format!("m{worker}.aff4l"));
                loop {
                    let n = next.fetch_add(1, Ordering::Relaxed);
                    if n >= count {
                        return;
                    }
                    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(n as u64 * 2 + 1) | 1);
                    for _ in 0..8 { rng.next(); }
                    let kind = n % KINDS.len();
                    let which = rng.below(2);
                    std::fs::write(&path, &contents[which]).unwrap();
                    mutate(&mut rng, kind, &contents[which], &path);
                    let started = std::time::Instant::now();
                    let rust = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        verify_file(&path, &signer, &gpgsm, &|_, _| {}, &AtomicBool::new(false))
                    }));
                    let (rust_level, format, rust_codes) = match rust {
                        Err(_) => ("PANIC".to_string(), None, Vec::new()),
                        Ok(Err(e)) => (format!("Error({e})").chars().take(60).collect(), None, Vec::new()),
                        Ok(Ok(r)) => (format!("{:?}", r.overall()), Some(r.format), r.findings.iter().map(|f| f.code.to_string()).collect::<Vec<_>>()),
                    };
                    let rust_time = started.elapsed().as_secs_f32();
                    let (python_level, python_codes, text) = python_verdict(script, &path, gnupg);
                    // an error stops factum's check where the script reports a failure
                    let rust_verdict = if rust_level.starts_with("Error") { "Fail" } else { rust_level.as_str() };
                    let agree = rust_verdict == python_level;
                    let foreign = !matches!(format, Some(ContainerFormat::Factum));
                    let class = if rust_level == "PANIC" || python_level.starts_with("CRASH") {
                        "crash"
                    } else if agree {
                        "agree"
                    } else if foreign && python_level == "Fail" {
                        "declared: script stricter on a file without factum's layout"
                    } else if rust_verdict == "Warn" && python_level == "Fail"
                        && text.lines().any(|l| l.starts_with('\u{2717}') && l.contains("information.turtle cannot be read"))
                        && text.lines().filter(|l| l.starts_with('\u{2717}')).count() == 1
                    {
                        "declared: valid Turtle outside factum's layout"
                    } else {
                        "DISAGREE"
                    };
                    *tally.lock().unwrap().entry(class.to_string()).or_default() += 1;
                    *tally.lock().unwrap().entry(format!("kind {:02} {}", kind, KINDS[kind])).or_default() += 1;
                    *tally.lock().unwrap().entry(format!("verdict rust={} python={}", rust_verdict.split('(').next().unwrap(), python_level)).or_default() += 1;
                    if rust_time > 20.0 {
                        lines.lock().unwrap().push(format!("SLOW {n} {} {rust_time}s", KINDS[kind]));
                    }
                    if rust_level == "Ok" && python_level == "Ok" {
                        // what both pass: the metadata must be what it was
                        let root = |p: &Path| zip::ZipArchive::new(std::fs::File::open(p).unwrap()).ok().and_then(|mut a| {
                            let mut text = Vec::new();
                            std::io::Read::read_to_end(&mut a.by_name(TURTLE).ok()?, &mut text).ok()?;
                            Some(text)
                        });
                        let same = root(&path) == root(&bases[which]);
                        let touched = if kind == 4 { std::fs::read_to_string(path.with_extension("name")).unwrap() } else { String::new() };
                        lines.lock().unwrap().push(format!("OKOK\t{}\tsame metadata {same}\t{touched}", KINDS[kind]));
                        if !same {
                            std::fs::copy(&path, out.join(format!("ok{n}.aff4l"))).unwrap();
                        }
                    }
                    if class != "agree" {
                        std::fs::copy(&path, out.join(format!("{n}.aff4l"))).unwrap();
                        std::fs::write(out.join(format!("{n}.txt")), &text).unwrap();
                        lines.lock().unwrap().push(format!(
                            "{class}\t{n}\t{}\tbase{which}\trust={rust_level} {format:?} {rust_codes:?}\tpython={python_level} {python_codes:?}",
                            KINDS[kind]
                        ));
                    }
                }
            });
        }
    });
    let mut report = String::new();
    for (key, value) in tally.lock().unwrap().iter() {
        report.push_str(&format!("{value:6} {key}\n"));
    }
    report.push('\n');
    for line in lines.lock().unwrap().iter() {
        report.push_str(line);
        report.push('\n');
    }
    std::fs::write(out.join("report.txt"), &report).unwrap();
}
