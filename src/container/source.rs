//! The files and folders that go into a container: walking them without following links, their metadata as the
//! platform shows it, and their names in the AFF4-L encoding (section 5).

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
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
    /// which file this is: device and inode on Unix, volume serial and file index of a regular file on Windows
    pub id: Option<(u64, u64)>,
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

/// The time `seconds` and `nanos` after the epoch; a time before 1970 has negative seconds and positive nanoseconds.
#[cfg_attr(not(unix), allow(dead_code))]
fn unix_time(seconds: i64, nanos: i64) -> Option<SystemTime> {
    chrono::DateTime::from_timestamp(seconds, nanos.clamp(0, 999_999_999) as u32).map(SystemTime::from)
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
    let (changed, mode, id) = {
        use std::os::unix::fs::MetadataExt;
        (
            unix_time(metadata.ctime(), metadata.ctime_nsec()).map(xsd_time),
            Some(metadata.mode()),
            Some((metadata.dev(), metadata.ino())),
        )
    };
    #[cfg(windows)]
    let (changed, mode, id) = {
        // a path's metadata does not hold the file index; the file has to be opened, regular files only
        let id = (kind == SourceKind::File)
            .then(|| open_not_following(path).and_then(|file| file_id(&file)).ok())
            .flatten();
        (None, None, id)
    };
    Ok(SourceMeta {
        size: if kind == SourceKind::File { metadata.len() } else { 0 },
        kind,
        modified: metadata.modified().ok().map(xsd_time),
        accessed: metadata.accessed().ok().map(xsd_time),
        changed,
        birth: metadata.created().ok().map(xsd_time),
        mode,
        id,
    })
}

/// Whether two ids are the same file; an inode of 0 says nothing.
fn same_id(a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Option<bool> {
    match (a, b) {
        (Some(a), Some(b)) if a.1 != 0 && b.1 != 0 => Some(a == b),
        _ => None,
    }
}

/// Whether a walked item is the file `own` with the real path `own_real`: never a symbolic link to it, which is
/// recorded as a link, and only a file of its size. The ids decide; where they do not (an inode of 0, a file system
/// that numbers its files anew), the real path does.
pub fn is_same_file(own: &SourceMeta, own_real: &Path, path: &Path, meta: &SourceMeta) -> bool {
    meta.kind == SourceKind::File
        && meta.size == own.size
        && (same_id(own.id, meta.id) == Some(true) || std::fs::canonicalize(path).is_ok_and(|real| real == own_real))
}

/// Opens without following a link and without waiting for the other end of a FIFO. On Linux without updating the
/// access time, where the file's owner allows that.
#[cfg(unix)]
fn open_not_following(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let open = |flags: i32| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | flags)
            .open(path)
    };
    #[cfg(target_os = "linux")]
    match open(libc::O_NOATIME) {
        // O_NOATIME is only allowed to the file's owner
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
        other => return other,
    }
    open(0)
}

/// Opens the link or other reparse point itself (FILE_FLAG_OPEN_REPARSE_POINT), to look at it: no access to its
/// content is asked for.
#[cfg(windows)]
fn open_not_following(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(0x0020_0000)
        .open(path)
}

#[cfg(unix)]
fn file_id(file: &File) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Volume serial and file index. std has them only on nightly.
#[cfg(windows)]
fn file_id(file: &File) -> io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    // SAFETY: an all-zero value is valid for this plain struct
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle lives as long as `file`, and `info` is a valid struct to fill
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok((u64::from(info.dwVolumeSerialNumber), index))
}

/// Reads block again: only the open must not wait.
#[cfg(unix)]
fn blocking(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: fd is open for as long as `file` lives; these calls touch only its status flags
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens a walked file read-only, and only that file: whatever lies at the path by now (a link, a FIFO, another file)
/// is an error. `SourceMeta::size` is what may be read from it.
pub fn open_source(path: &Path, meta: &SourceMeta) -> io::Result<File> {
    let changed = || io::Error::other("changed after it was listed; not added");
    // a link where a file was walked
    #[cfg(unix)]
    let file = open_not_following(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            changed()
        } else {
            e
        }
    })?;
    // not with FILE_FLAG_OPEN_REPARSE_POINT: that bypasses the filter of a deduplicated or cloud file, which would
    // read as its stub. A link swapped in leads to another file index, and that is found below.
    #[cfg(windows)]
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    // vfat, exfat, CIFS with noserverino and FUSE without use_ino may number a file anew between walk and open: that
    // too reads as changed. Left so on purpose: a failure that says so, never a file taken on trust.
    if !metadata.is_file() || metadata.len() != meta.size || same_id(file_id(&file).ok(), meta.id) == Some(false) {
        return Err(changed());
    }
    #[cfg(unix)]
    blocking(&file)?;
    Ok(file)
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

/// The bytes of a name as the operating system gives them (Windows: its UTF-16 as WTF-8, which is UTF-8 for any name
/// that is valid Unicode).
pub fn os_bytes(name: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        wtf8(name.encode_wide())
    }
}

/// A name back from `os_bytes`.
pub fn os_string(bytes: Vec<u8>) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&utf16_of_wtf8(&bytes))
    }
}

/// UTF-16 as WTF-8: an unpaired surrogate becomes the three bytes UTF-8 would give it. They are not valid UTF-8, so
/// such a name gets a raw form like any other that is not.
#[cfg(any(windows, test))]
fn wtf8(units: impl Iterator<Item = u16>) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in char::decode_utf16(units) {
        match unit {
            Ok(c) => out.extend(c.encode_utf8(&mut [0; 4]).as_bytes()),
            Err(e) => {
                let unit = e.unpaired_surrogate();
                out.extend([
                    0xE0 | (unit >> 12) as u8,
                    0x80 | ((unit >> 6) & 0x3F) as u8,
                    0x80 | (unit & 0x3F) as u8,
                ]);
            }
        }
    }
    out
}

/// The UTF-16 of `wtf8`'s bytes; bytes it does not write give some other name, never a panic.
#[cfg(any(windows, test))]
fn utf16_of_wtf8(bytes: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let (len, first) = match bytes[at] {
            byte @ 0..=0xBF => (1, u32::from(byte)),
            byte @ 0xC0..=0xDF => (2, u32::from(byte & 0x1F)),
            byte @ 0xE0..=0xEF => (3, u32::from(byte & 0x0F)),
            byte => (4, u32::from(byte & 0x07)),
        };
        let rest = &bytes[(at + 1).min(bytes.len())..(at + len).min(bytes.len())];
        let code = rest.iter().fold(first, |code, byte| code << 6 | u32::from(byte & 0x3F));
        match code.checked_sub(0x1_0000) {
            None => units.push(code as u16),
            Some(code) => units.extend([0xD800 | ((code >> 10) & 0x3FF) as u16, 0xDC00 | (code & 0x3FF) as u16]),
        }
        at += len;
    }
    units
}

/// Base64 of a path's bytes, when its text cannot stand in for them.
pub fn raw_path(path: &Path) -> Option<String> {
    encode_name(&os_bytes(path.as_os_str())).raw_b64
}

/// The path a recorded text and raw form (from `raw_path`) stand for; without a raw form, the text.
pub fn exact_path(text: &str, raw_b64: Option<&str>) -> PathBuf {
    raw_b64
        .and_then(|raw| base64::engine::general_purpose::STANDARD.decode(raw).ok())
        .map_or_else(|| PathBuf::from(text), |bytes| PathBuf::from(os_string(bytes)))
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
        let meta = read_meta(&path).unwrap();
        let mut text = String::new();
        open_source(&path, &meta).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "content");
    }

    #[cfg(unix)]
    fn assert_changed(path: &Path, meta: &SourceMeta) {
        let error = open_source(path, meta).unwrap_err();
        assert!(error.to_string().contains("changed after it was listed"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn open_source_refuses_what_was_swapped_in() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"content").unwrap();
        let meta = read_meta(&path).unwrap();
        // a link to a file of the same size
        let other = dir.path().join("other");
        std::fs::write(&other, b"CONTENT").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert_changed(&path, &meta);
        // another file of the same size at the path
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&other, &path).unwrap();
        assert_changed(&path, &meta);
        // a FIFO nobody writes to: without O_NONBLOCK this open never returns
        std::fs::remove_file(&path).unwrap();
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        assert!(made.is_ok_and(|s| s.success()));
        assert_changed(&path, &meta);
    }

    #[cfg(unix)]
    #[test]
    fn open_source_refuses_another_size_and_reads_block_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"content").unwrap();
        let meta = read_meta(&path).unwrap();
        let file = open_source(&path, &meta).unwrap();
        use std::os::fd::AsRawFd;
        // SAFETY: only reads the flags of an open descriptor
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0);
        std::fs::write(&path, b"content and more").unwrap();
        assert_changed(&path, &meta);
    }

    #[test]
    fn the_container_is_found_by_its_id_or_else_by_its_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let own_path = dir.path().join("c.aff4l");
        let same_size = dir.path().join("other");
        std::fs::write(&own_path, b"container").unwrap();
        std::fs::write(&same_size, b"same size").unwrap();
        let own_real = std::fs::canonicalize(&own_path).unwrap();
        let own = read_meta(&own_real).unwrap();
        assert!(is_same_file(&own, &own_real, &own_path, &own));
        // a hard link is the same file; on Windows the index must be readable to know that
        let hard = dir.path().join("hard");
        std::fs::hard_link(&own_path, &hard).unwrap();
        assert!(is_same_file(&own, &own_real, &hard, &read_meta(&hard).unwrap()));
        assert!(!is_same_file(
            &own,
            &own_real,
            &same_size,
            &read_meta(&same_size).unwrap()
        ));
        // the same id with another size: not the file that was measured
        let other_size = SourceMeta {
            size: own.size + 1,
            ..own.clone()
        };
        assert!(!is_same_file(&own, &own_real, &own_path, &other_size));
        // an inode of 0 says nothing, nor do ids that differ on a file system that numbers files anew
        for (own_id, walked_id) in [((1, 0), (1, 0)), (own.id.unwrap(), (1, 0)), (own.id.unwrap(), (9, 9))] {
            let own = SourceMeta {
                id: Some(own_id),
                ..own.clone()
            };
            let walked = SourceMeta {
                id: Some(walked_id),
                ..own.clone()
            };
            assert!(is_same_file(&own, &own_real, &own_path, &walked));
            assert!(!is_same_file(&own, &own_real, &same_size, &walked));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_never_the_container() {
        let dir = tempfile::tempdir().unwrap();
        let own_path = dir.path().join("c.aff4l");
        std::fs::write(&own_path, b"container").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&own_path, &link).unwrap();
        let own_real = std::fs::canonicalize(&own_path).unwrap();
        let own = read_meta(&own_real).unwrap();
        assert!(!is_same_file(&own, &own_real, &link, &read_meta(&link).unwrap()));
    }

    #[test]
    fn times_before_1970_keep_their_sign() {
        assert_eq!(xsd_time(unix_time(-1, 500_000_000).unwrap()), "1969-12-31T23:59:59.5Z");
        assert_eq!(xsd_time(unix_time(-86_400, 0).unwrap()), "1969-12-31T00:00:00Z");
        assert_eq!(
            xsd_time(unix_time(1_599_435_382, 100).unwrap()),
            "2020-09-06T23:36:22.0000001Z"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_modified_time_before_1970_is_read_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        let time = std::time::UNIX_EPOCH - std::time::Duration::new(86_400, 0);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(time).unwrap();
        assert_eq!(
            read_meta(&path).unwrap().modified.as_deref(),
            Some("1969-12-31T00:00:00Z")
        );
    }

    #[test]
    fn unpaired_surrogates_keep_a_raw_form() {
        let name = wtf8([0x61, 0xD83D, 0x62, 0xDC00].into_iter());
        assert_eq!(name, b"a\xED\xA0\xBDb\xED\xB0\x80");
        let encoded = encode_name(&name);
        assert_eq!(encoded.text, "a%ED%A0%BDb%ED%B0%80");
        assert_eq!(encoded.raw_b64, Some(b64(&name)));
        assert_eq!(utf16_of_wtf8(&name), vec![0x61, 0xD83D, 0x62, 0xDC00]);
    }

    #[test]
    fn valid_utf16_is_plain_utf8_and_comes_back() {
        let text = "Jürgen ネコ 😀.txt";
        let units: Vec<u16> = text.encode_utf16().collect();
        let name = wtf8(units.iter().copied());
        assert_eq!(name, text.as_bytes());
        assert_eq!(encode_name(&name).raw_b64, None);
        assert_eq!(utf16_of_wtf8(&name), units);
        // what wtf8 never writes is no panic
        utf16_of_wtf8(b"\xF0\x9F");
        utf16_of_wtf8(b"\xE0");
    }

    #[cfg(unix)]
    #[test]
    fn a_path_comes_back_from_its_raw_form() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(OsStr::from_bytes(b"/mnt/caf\xe9/x"));
        let raw = raw_path(path).unwrap();
        assert_eq!(exact_path(&path.display().to_string(), Some(&raw)), path);
        assert_eq!(raw_path(Path::new("/mnt/plain")), None);
        assert_eq!(exact_path("/mnt/plain", None), Path::new("/mnt/plain"));
    }
}
