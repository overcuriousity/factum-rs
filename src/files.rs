//! File helpers shared by seals, the configuration and exports: names that every file system accepts and writes
//! that never leave a half-written file.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

static UNSAFE_CHARACTERS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^\w.-]+").unwrap());

/// case file numbers like "2026/04 Müller" must not create folders or escape the target folder
pub fn safe_filename(text: &str) -> String {
    let replaced = UNSAFE_CHARACTERS.replace_all(text, "-");
    let trimmed = replaced.trim_matches(|c| c == '.' || c == '-');
    if trimmed.is_empty() {
        "case".into()
    } else {
        trimmed.into()
    }
}

/// safe_filename, at most `max_bytes` long (UTF-8; at least 16): a longer name is cut at a character boundary
/// and ends in 8 hex digits of the SHA-256 of `text`, so names cut to the same start stay distinct. Names that
/// fit are returned unchanged.
pub fn safe_filename_capped(text: &str, max_bytes: usize) -> String {
    let name = safe_filename(text);
    if name.len() <= max_bytes {
        return name;
    }
    let suffix = format!("-{}", &hex::encode(Sha256::digest(text.as_bytes()))[..8]);
    let mut end = max_bytes.saturating_sub(suffix.len());
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", name[..end].trim_end_matches(['.', '-']))
}

/// Writes a file that is afterwards complete or not there: a temporary file in the same folder, synced, renamed
/// over `path`, then the folder synced (not possible on Windows). An existing file keeps its permissions.
pub fn write_atomically(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let folder = parent_of(path);
    let mut builder = tempfile::Builder::new();
    builder.prefix(".factum-").suffix(".tmp");
    #[cfg(unix)]
    let permissions = std::fs::metadata(path).map(|m| m.permissions()).unwrap_or_else(|_| {
        // like fs::write: what the umask leaves of rw-rw-rw-
        std::os::unix::fs::PermissionsExt::from_mode(0o666)
    });
    #[cfg(unix)]
    builder.permissions(permissions);
    let mut file = builder.tempfile_in(&folder)?;
    file.write_all(content)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    if let Ok(folder) = std::fs::File::open(&folder) {
        let _ = folder.sync_all();
    }
    Ok(())
}

/// Python's Path.parent: "." for a bare file name.
pub fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filenames() {
        assert_eq!(safe_filename("2026/04 Müller"), "2026-04-Müller");
        assert_eq!(safe_filename("../x"), "x");
        assert_eq!(safe_filename("///"), "case");
    }

    #[test]
    fn capped_filenames_cut_at_a_character_boundary_and_stay_distinct() {
        assert_eq!(safe_filename_capped("2026/04 Müller", 100), "2026-04-Müller");
        let long = "案".repeat(80);
        let capped = safe_filename_capped(&long, 100);
        assert!(capped.len() <= 100, "{}", capped.len());
        // 91 bytes for the text: 30 three-byte characters, then "-" and 8 hex digits
        assert_eq!(capped, format!("{}-{}", "案".repeat(30), &capped[capped.len() - 8..]));
        let other = safe_filename_capped(&format!("{long}2"), 100);
        assert_eq!(other.len(), capped.len());
        assert_ne!(other, capped);
        // the cut does not leave a separator before the hash
        assert!(!safe_filename_capped(&format!("{}/{}", "a".repeat(90), "b".repeat(20)), 100).contains("--"));
    }

    #[test]
    fn atomic_writes_replace_and_leave_no_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seal.asc");
        write_atomically(&path, b"one").unwrap();
        write_atomically(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(write_atomically(&dir.path().join("missing").join("x"), b"x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_keep_the_permissions_of_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_atomically(&path, b"y").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
