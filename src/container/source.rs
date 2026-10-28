//! The files and folders that go into a container: walking them without following links, their metadata as the
//! platform shows it, and their names in the AFF4-L encoding (section 5).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use base64::Engine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    File,
    Folder,
    /// a symbolic link and its target; recorded, never followed
    Link(PathBuf),
    /// devices, sockets, FIFOs: skipped
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMeta {
    pub kind: SourceKind,
    pub size: u64,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    /// the inode change time (Unix)
    pub changed: Option<String>,
    pub birth: Option<String>,
    /// the Unix file mode
    pub mode: Option<u32>,
}

/// An xsd:dateTime in UTC; the fraction of a second only as long as it needs to be.
pub fn xsd_time(time: SystemTime) -> String {
    let time: chrono::DateTime<chrono::Utc> = time.into();
    let mut text = time.format("%Y-%m-%dT%H:%M:%S%.9f").to_string();
    while text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    text + "Z"
}

pub fn read_meta(path: &Path) -> io::Result<SourceMeta> {
    let metadata = std::fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        SourceKind::Link(std::fs::read_link(path)?)
    } else if file_type.is_dir() {
        SourceKind::Folder
    } else if file_type.is_file() {
        SourceKind::File
    } else {
        SourceKind::Special
    };
    #[cfg(unix)]
    let (changed, mode) = {
        use std::os::unix::fs::MetadataExt;
        let changed = std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(
            metadata.ctime().max(0) as u64,
            metadata.ctime_nsec().clamp(0, 999_999_999) as u32,
        ));
        (changed.map(xsd_time), Some(metadata.mode()))
    };
    #[cfg(not(unix))]
    let (changed, mode) = (None, None);
    Ok(SourceMeta {
        size: if kind == SourceKind::File { metadata.len() } else { 0 },
        kind,
        modified: metadata.modified().ok().map(xsd_time),
        accessed: metadata.accessed().ok().map(xsd_time),
        changed,
        birth: metadata.created().ok().map(xsd_time),
        mode,
    })
}

/// Opens a source read-only; on Linux without updating its access time, where the file's owner allows that.
pub fn open_source(path: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOATIME)
            .open(path)
        {
            // O_NOATIME is only allowed to the file's owner
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
            other => return other,
        }
    }
    File::open(path)
}

/// A file or path name as AFF4-L stores it, and its raw bytes when the name cannot be stored as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedName {
    pub text: String,
    /// Base64 of the bytes as read from disk (`fileNameRaw` / `originalPathNameRaw`)
    pub raw_b64: Option<String>,
}

/// AFF4-L v1.0, section 5: valid UTF-8 without control characters is stored as it is; anything else is stored
/// Base64-encoded as raw, and as text with 0x00–0x1F, '%' and 0x80–0xFF written as %XX.
pub fn encode_name(bytes: &[u8]) -> EncodedName {
    match std::str::from_utf8(bytes) {
        Ok(text) if !bytes.iter().any(|b| *b < 0x20) => EncodedName {
            text: text.to_string(),
            raw_b64: None,
        },
        _ => {
            let mut text = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                if *byte < 0x20 || *byte == b'%' || *byte >= 0x80 {
                    text.push_str(&format!("%{byte:02X}"));
                } else {
                    text.push(*byte as char);
                }
            }
            EncodedName {
                text,
                raw_b64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            }
        }
    }
}

/// The bytes of a name as the operating system gives them (Windows: its UTF-16 converted to UTF-8).
pub fn os_bytes(name: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().into_owned().into_bytes()
    }
}

/// The path stored for a source: below `base`, joined with the platform's separator, or only the file name.
/// The base itself has an empty path (it is the root of the acquisition).
pub fn stored_path(path: &Path, base: &Path, keep_path: bool) -> Result<Vec<u8>, String> {
    if base.as_os_str().is_empty() {
        return Ok(if keep_path {
            full_path(path)
        } else {
            path.file_name().map(os_bytes).unwrap_or_default()
        });
    }
    let relative = path.strip_prefix(base).map_err(|_| {
        format!(
            "{} is not below the base path {}. Choose a base path that contains every source.",
            path.display(),
            base.display()
        )
    })?;
    if !keep_path {
        return Ok(path.file_name().map(os_bytes).unwrap_or_default());
    }
    let mut out = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(format!("{} has an unexpected path component", path.display()));
        };
        if !out.is_empty() {
            out.extend(std::path::MAIN_SEPARATOR_STR.as_bytes());
        }
        out.extend(os_bytes(name));
    }
    Ok(out)
}

/// A full path as stored without a base path: on Unix without the leading separator, on Windows starting with
/// the drive or share (`C:\Users\x`, `\\server\share\x`).
fn full_path(path: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for component in path.components() {
        let part = match component {
            Component::Prefix(prefix) => prefix.as_os_str(),
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::Normal(name) => name,
        };
        if !out.is_empty() {
            out.extend(std::path::MAIN_SEPARATOR_STR.as_bytes());
        }
        out.extend(os_bytes(part));
    }
    out
}

/// Every source and, for folders, everything below them: depth-first, a folder before its contents, the entries
/// of a folder sorted by name. Links are listed, not followed; a path reached twice is listed once.
pub fn walk(roots: &[PathBuf]) -> Vec<Walked> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        walk_one(root, &mut seen, &mut out);
    }
    out
}

/// A source with its metadata, or the path that could not be read and why.
pub type Walked = Result<(PathBuf, SourceMeta), (PathBuf, io::Error)>;

fn walk_one(path: &Path, seen: &mut HashSet<PathBuf>, out: &mut Vec<Walked>) {
    if !seen.insert(path.to_path_buf()) {
        return;
    }
    let meta = match read_meta(path) {
        Ok(meta) => meta,
        Err(e) => {
            out.push(Err((path.to_path_buf(), e)));
            return;
        }
    };
    let folder = meta.kind == SourceKind::Folder;
    out.push(Ok((path.to_path_buf(), meta)));
    if !folder {
        return;
    }
    let mut children = match std::fs::read_dir(path) {
        Ok(entries) => readable_entries(path, entries.map(|e| e.map(|e| e.path())), out),
        Err(e) => {
            out.push(Err((path.to_path_buf(), e)));
            return;
        }
    };
    children.sort_by_key(|child| child.file_name().map(os_bytes));
    for child in children {
        walk_one(&child, seen, out);
    }
}

/// The entries of `folder` that could be listed; one that could not is an error of the folder, never dropped.
fn readable_entries(
    folder: &Path,
    entries: impl Iterator<Item = io::Result<PathBuf>>,
    out: &mut Vec<Walked>,
) -> Vec<PathBuf> {
    let mut children = Vec::new();
    for entry in entries {
        match entry {
            Ok(child) => children.push(child),
            Err(e) => out.push(Err((
                folder.to_path_buf(),
                io::Error::new(
                    e.kind(),
                    format!("an entry of this folder cannot be read ({e}); it was not added"),
                ),
            ))),
        }
    }
    children
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Read;

    #[test]
    fn an_unreadable_folder_entry_is_an_error() {
        let folder = Path::new("/mnt/share");
        let mut out = Vec::new();
        let entries = vec![
            Ok(folder.join("a")),
            Err(io::Error::other("stale handle")),
            Ok(folder.join("b")),
        ];
        let children = readable_entries(folder, entries.into_iter(), &mut out);
        assert_eq!(children, vec![folder.join("a"), folder.join("b")]);
        assert_eq!(out.len(), 1);
        let (path, error) = out[0].as_ref().unwrap_err();
        assert_eq!(path, folder);
        assert!(error.to_string().contains("stale handle"), "{error}");
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn encode_name_follows_standard_section_5() {
        let name = b"\t\rmalware.exe\x08\x08\x08txt";
        let encoded = encode_name(name);
        assert_eq!(encoded.text, "%09%0Dmalware.exe%08%08%08txt");
        assert_eq!(encoded.raw_b64, Some(b64(name)));
        let encoded = encode_name(b"caf\xe9");
        assert_eq!(encoded.text, "caf%E9");
        assert_eq!(encoded.raw_b64, Some(b64(b"caf\xe9")));
        // rule 2 also escapes '%', but only when rule 2 applies
        assert_eq!(encode_name(b"100%\x01").text, "100%25%01");
        let encoded = encode_name("100%.txt".as_bytes());
        assert_eq!((encoded.text.as_str(), encoded.raw_b64), ("100%.txt", None));
        let encoded = encode_name("Jürgen ネコ.txt".as_bytes());
        assert_eq!((encoded.text.as_str(), encoded.raw_b64), ("Jürgen ネコ.txt", None));
    }

    #[test]
    fn source_outside_base_is_refused() {
        let error = stored_path(Path::new("/mnt/b/x"), Path::new("/mnt/a"), true).unwrap_err();
        assert!(error.contains("/mnt/b/x"), "{error}");
        // a name that only starts like the base is not below it
        assert!(stored_path(Path::new("/mnt/ab/x"), Path::new("/mnt/a"), true).is_err());
    }

    #[test]
    fn stored_path_without_base_keeps_full_path() {
        #[cfg(unix)]
        assert_eq!(
            stored_path(Path::new("/mnt/x/a.txt"), Path::new(""), true).unwrap(),
            b"mnt/x/a.txt".to_vec()
        );
        #[cfg(windows)]
        {
            assert_eq!(
                stored_path(Path::new(r"C:\Users\x\a.txt"), Path::new(""), true).unwrap(),
                br"C:\Users\x\a.txt".to_vec()
            );
            assert_eq!(
                stored_path(Path::new(r"\\server\share\x\a.txt"), Path::new(""), true).unwrap(),
                br"\\server\share\x\a.txt".to_vec()
            );
        }
    }

    #[test]
    fn stored_path_keeps_or_drops_the_path() {
        let path = Path::new("/mnt/fs01/Users/x/evil.exe");
        let base = Path::new("/mnt/fs01");
        let separator = std::path::MAIN_SEPARATOR.to_string();
        assert_eq!(
            stored_path(path, base, true).unwrap(),
            ["Users", "x", "evil.exe"].join(&separator).into_bytes()
        );
        assert_eq!(stored_path(path, base, false).unwrap(), b"evil.exe".to_vec());
        // the base itself is the root of the acquisition: no path of its own
        assert_eq!(stored_path(base, base, true).unwrap(), Vec::<u8>::new());
    }

    #[cfg(unix)]
    #[test]
    fn walk_records_links_and_skips_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("b.txt"), b"bee").unwrap();
        std::fs::write(root.join("sub/a.txt"), b"a").unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"not walked").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let fifo = std::process::Command::new("mkfifo")
            .arg(root.join("pipe"))
            .status()
            .is_ok_and(|s| s.success());
        let roots = vec![root.clone(), root.join("b.txt")];
        let walked: Vec<(PathBuf, SourceMeta)> = walk(&roots).into_iter().map(Result::unwrap).collect();
        let names: Vec<String> = walked
            .iter()
            .map(|(p, _)| p.strip_prefix(dir.path()).unwrap().display().to_string())
            .collect();
        let mut expected = vec!["root", "root/b.txt", "root/link"];
        if fifo {
            expected.push("root/pipe");
        }
        expected.extend(["root/sub", "root/sub/a.txt"]);
        assert_eq!(names, expected);
        let kind = |name: &str| &walked[names.iter().position(|n| n == name).unwrap()].1.kind;
        assert_eq!(kind("root"), &SourceKind::Folder);
        assert_eq!(kind("root/b.txt"), &SourceKind::File);
        assert_eq!(kind("root/link"), &SourceKind::Link(outside.clone()));
        if fifo {
            assert_eq!(kind("root/pipe"), &SourceKind::Special);
        }
        assert_eq!(walked[names.iter().position(|n| n == "root/b.txt").unwrap()].1.size, 3);
        assert_eq!(walk(&roots).len(), walked.len());
    }

    #[test]
    fn meta_has_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let meta = read_meta(&path).unwrap();
        let modified = meta.modified.unwrap();
        assert_eq!(
            modified,
            xsd_time(std::fs::metadata(&path).unwrap().modified().unwrap())
        );
        let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d*[1-9])?Z$").unwrap();
        assert!(re.is_match(&modified), "{modified}");
        assert!(meta.accessed.is_some());
        #[cfg(unix)]
        assert!(meta.changed.is_some() && meta.mode.is_some_and(|m| m & 0o170000 == 0o100000));
    }

    #[test]
    fn xsd_time_trims_the_fraction() {
        let at = |secs: u64, nanos: u32| std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos);
        assert_eq!(xsd_time(at(1_599_435_382, 0)), "2020-09-06T23:36:22Z");
        assert_eq!(xsd_time(at(1_599_435_382, 120_000_000)), "2020-09-06T23:36:22.12Z");
        // 100 ns: the finest a Windows file time holds
        assert_eq!(xsd_time(at(1_599_435_382, 100)), "2020-09-06T23:36:22.0000001Z");
    }

    #[test]
    fn open_source_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"content").unwrap();
        let mut text = String::new();
        open_source(&path).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "content");
    }
}
