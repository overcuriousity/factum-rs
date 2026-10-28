//! Where the sources of an Add operation were read from: the mount (Linux) or volume (Windows) below each source,
//! so the log and the container say through which device, file system and options the files were read.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

/// One mount, as recorded with an Add operation. An empty `mount_point` with nothing else known is "mount unknown".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mount {
    pub mount_point: String,
    pub device: Option<String>,
    pub fs_type: Option<String>,
    pub options: Option<String>,
    pub read_only: Option<bool>,
    /// the image file behind a loop device
    pub image: Option<String>,
    pub volume_serial: Option<String>,
    pub volume_label: Option<String>,
    pub volume_guid: Option<String>,
    /// the mount the image file lies on, when that is a FUSE mount (xmount and similar)
    pub backing: Option<Box<Mount>>,
    /// the sources below this mount
    pub paths: Vec<String>,
}

impl Mount {
    pub fn is_unknown(&self) -> bool {
        self.mount_point.is_empty() && self.device.is_none() && self.fs_type.is_none()
    }

    pub fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("mount_point".into(), json!(self.mount_point));
        for (key, value) in [
            ("device", &self.device),
            ("fs_type", &self.fs_type),
            ("options", &self.options),
            ("image", &self.image),
            ("volume_serial", &self.volume_serial),
            ("volume_label", &self.volume_label),
            ("volume_guid", &self.volume_guid),
        ] {
            if let Some(value) = value {
                map.insert(key.into(), json!(value));
            }
        }
        if let Some(read_only) = self.read_only {
            map.insert("read_only".into(), json!(read_only));
        }
        if let Some(backing) = &self.backing {
            map.insert("backing".into(), backing.to_json());
        }
        if !self.paths.is_empty() {
            map.insert("paths".into(), json!(self.paths));
        }
        Value::Object(map)
    }

    pub fn from_json(value: &Value) -> Option<Mount> {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        Some(Mount {
            mount_point: text("mount_point")?,
            device: text("device"),
            fs_type: text("fs_type"),
            options: text("options"),
            read_only: value.get("read_only").and_then(Value::as_bool),
            image: text("image"),
            volume_serial: text("volume_serial"),
            volume_label: text("volume_label"),
            volume_guid: text("volume_guid"),
            backing: value.get("backing").and_then(Mount::from_json).map(Box::new),
            paths: value
                .get("paths")
                .and_then(Value::as_array)
                .map(|paths| paths.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default(),
        })
    }
}

/// The mount as one line: `/mnt/disk · /dev/loop0 · ntfs3 · ro,noatime · image /cases/disk.raw`.
pub fn mount_line(m: &Mount) -> String {
    if m.is_unknown() {
        return "mount unknown".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    for part in [&Some(m.mount_point.clone()), &m.device, &m.fs_type] {
        // a pseudo file system names its source like its type (tmpfs, proc): once is enough
        if let Some(part) = part.as_ref().filter(|p| !p.is_empty() && !parts.contains(p)) {
            parts.push(part.clone());
        }
    }
    match (&m.options, m.read_only) {
        (Some(options), _) => parts.push(options.clone()),
        (None, Some(true)) => parts.push("ro".into()),
        (None, Some(false)) => parts.push("rw".into()),
        (None, None) => {}
    }
    if let Some(serial) = &m.volume_serial {
        parts.push(format!("serial {serial}"));
    }
    if let Some(label) = m.volume_label.as_ref().filter(|l| !l.is_empty()) {
        parts.push(format!("label {label}"));
    }
    if let Some(image) = &m.image {
        parts.push(format!("image {image}"));
    }
    if let Some(backing) = &m.backing {
        let via = [
            Some(backing.mount_point.clone()),
            backing.fs_type.clone(),
            backing.device.clone(),
        ]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
        parts.push(format!("on {via}"));
    }
    parts.join(" · ")
}

/// The mounts the sources, and everything walked below them, were read from: one per mount. Each lists the sources
/// below it or, for a mount reached only by walking into it (a partition mounted inside an added folder), its mount
/// point. The mount table is read once.
pub fn mounts_for(sources: &[PathBuf], walked: &[PathBuf]) -> Vec<Mount> {
    let canonical = |p: &Path| plain(std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()));
    // a source is looked up by its real path (macOS' /var is /private/var) and listed as it was added
    let sources: Vec<(PathBuf, PathBuf)> = sources.iter().map(|s| (s.clone(), canonical(s))).collect();
    // a walked item's folder is resolved once; the item itself is not followed (a link is read where it lies)
    let mut folders: HashMap<PathBuf, PathBuf> = HashMap::new();
    let walked: Vec<PathBuf> = walked
        .iter()
        .map(|p| match (p.parent(), p.file_name()) {
            (Some(parent), Some(name)) => folders
                .entry(parent.to_path_buf())
                .or_insert_with(|| canonical(parent))
                .join(name),
            _ => canonical(p),
        })
        .collect();
    platform::mounts_for(&sources, &walked)
}

/// Groups paths by the mount `resolve` finds for them (unknown when it finds none). Sources are (as added, real
/// path) pairs.
fn group(
    sources: &[(PathBuf, PathBuf)],
    walked: &[PathBuf],
    resolve: &mut dyn FnMut(&Path) -> Option<Mount>,
) -> Vec<Mount> {
    let mut mounts: Vec<Mount> = Vec::new();
    for (given, path, is_source) in sources
        .iter()
        .map(|(given, real)| (given, real, true))
        .chain(walked.iter().map(|p| (p, p, false)))
    {
        let mount = resolve(path).unwrap_or_default();
        let index = match mounts
            .iter()
            .position(|m| m.mount_point == mount.mount_point && m.device == mount.device)
        {
            Some(index) => index,
            None => {
                mounts.push(mount);
                mounts.len() - 1
            }
        };
        let known = &mut mounts[index];
        let label = if is_source || known.mount_point.is_empty() {
            given.display().to_string()
        } else {
            known.mount_point.clone()
        };
        if (is_source || known.paths.is_empty()) && !known.paths.contains(&label) {
            known.paths.push(label);
        }
    }
    mounts
}

/// The mounts of `entries` the paths lie on, as `group` lists them; `to_mount` turns an entry into a mount.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn assign(
    entries: &[MountEntry],
    sources: &[(PathBuf, PathBuf)],
    walked: &[PathBuf],
    to_mount: &dyn Fn(&MountEntry) -> Mount,
) -> Vec<Mount> {
    group(sources, walked, &mut |path| containing(entries, path).map(to_mount))
}

/// The mount a path lies on; None when the platform does not say.
pub fn mount_of(path: &Path) -> Option<Mount> {
    mounts_for(&[path.to_path_buf()], &[])
        .into_iter()
        .next()
        .filter(|m| !m.is_unknown())
}

/// A path without Windows' verbatim prefix (`\\?\C:\x` is `C:\x`, `\\?\UNC\server\share` is `\\server\share`), as
/// canonicalize returns it there and as people know it.
fn plain(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\")
            && rest.as_bytes().get(1) == Some(&b':')
        {
            return PathBuf::from(rest);
        }
    }
    path
}

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct MountEntry {
    pub mount_point: String,
    pub device: String,
    pub fs_type: String,
    pub options: String,
}

/// `\040` and the other octal escapes of mountinfo, decoded.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b)) {
            let value =
                (bytes[i + 1] - b'0') as u32 * 64 + (bytes[i + 2] - b'0') as u32 * 8 + (bytes[i + 3] - b'0') as u32;
            out.push(value as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mounts of `/proc/self/mountinfo` (proc(5)): mount point and per-mount options from the first part, file
/// system type and source after the `-` separator.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let separator = fields.iter().position(|f| *f == "-")?;
            Some(MountEntry {
                mount_point: unescape(fields.get(4)?),
                options: fields.get(5)?.to_string(),
                fs_type: fields.get(separator + 1)?.to_string(),
                device: unescape(fields.get(separator + 2)?),
            })
        })
        .collect()
}

/// The mount a path lies on: the longest mount point it starts with (a later mount over the same point wins).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn containing<'a>(entries: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    entries
        .iter()
        .filter(|e| path.starts_with(&e.mount_point))
        .fold(None, |best: Option<&MountEntry>, e| match best {
            Some(b)
                if Path::new(&b.mount_point).components().count() > Path::new(&e.mount_point).components().count() =>
            {
                Some(b)
            }
            _ => Some(e),
        })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_only(options: &str) -> bool {
    options.split(',').any(|o| o == "ro")
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    fn entries() -> Option<Vec<MountEntry>> {
        Some(parse_mountinfo(&std::fs::read_to_string("/proc/self/mountinfo").ok()?))
    }

    fn to_mount(entry: &MountEntry) -> Mount {
        Mount {
            mount_point: entry.mount_point.clone(),
            device: Some(entry.device.clone()),
            fs_type: Some(entry.fs_type.clone()),
            options: Some(entry.options.clone()),
            read_only: Some(read_only(&entry.options)),
            ..Default::default()
        }
    }

    pub fn mounts_for(sources: &[(PathBuf, PathBuf)], walked: &[PathBuf]) -> Vec<Mount> {
        let entries = entries().unwrap_or_default();
        // a loop device: the image file behind it, and the FUSE mount that file lies on (xmount and similar)
        let with_backing = |entry: &MountEntry| {
            let mut mount = to_mount(entry);
            if let Some(loop_name) = entry.device.strip_prefix("/dev/").filter(|d| d.starts_with("loop")) {
                let backing = std::fs::read_to_string(format!("/sys/block/{loop_name}/loop/backing_file")).ok();
                if let Some(image) = backing.map(|b| b.trim_end().to_string()).filter(|b| !b.is_empty()) {
                    mount.backing = containing(&entries, Path::new(&image))
                        .filter(|e| e.fs_type.starts_with("fuse"))
                        .map(|e| Box::new(to_mount(e)));
                    mount.image = Some(image);
                }
            }
            mount
        };
        assign(&entries, sources, walked, &with_backing)
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Storage::FileSystem::{
        GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    };

    const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn text(buffer: &[u16]) -> String {
        let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
        std::ffi::OsString::from_wide(&buffer[..end])
            .to_string_lossy()
            .into_owned()
    }

    pub fn mounts_for(sources: &[(PathBuf, PathBuf)], walked: &[PathBuf]) -> Vec<Mount> {
        // one volume lookup per folder, not per file
        let mut by_folder: HashMap<PathBuf, Option<Mount>> = HashMap::new();
        group(sources, walked, &mut |path| {
            let folder = path.parent().unwrap_or(path).to_path_buf();
            by_folder.entry(folder).or_insert_with(|| volume_of(path)).clone()
        })
    }

    fn volume_of(path: &Path) -> Option<Mount> {
        let mut root = vec![0u16; 1024];
        // SAFETY: the buffers are valid for the lengths given; the strings are NUL-terminated
        if unsafe { GetVolumePathNameW(wide(path).as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
            return None;
        }
        let root_text = text(&root);
        let root_wide = wide(Path::new(&root_text));
        let mut label = vec![0u16; 261];
        let mut fs_name = vec![0u16; 261];
        let (mut serial, mut max_len, mut flags) = (0u32, 0u32, 0u32);
        // SAFETY: as above
        let info = unsafe {
            GetVolumeInformationW(
                root_wide.as_ptr(),
                label.as_mut_ptr(),
                label.len() as u32,
                &mut serial,
                &mut max_len,
                &mut flags,
                fs_name.as_mut_ptr(),
                fs_name.len() as u32,
            )
        } != 0;
        let mut guid = vec![0u16; 64];
        // SAFETY: as above
        let has_guid =
            unsafe { GetVolumeNameForVolumeMountPointW(root_wide.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) } != 0;
        Some(Mount {
            mount_point: root_text,
            fs_type: info.then(|| text(&fs_name)),
            read_only: info.then_some(flags & FILE_READ_ONLY_VOLUME != 0),
            volume_serial: info.then(|| format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF)),
            volume_label: info.then(|| text(&label)),
            volume_guid: has_guid.then(|| text(&guid)),
            ..Default::default()
        })
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;

    /// macOS and others: not recorded (optional, spec 5.1)
    pub fn mounts_for(sources: &[(PathBuf, PathBuf)], walked: &[PathBuf]) -> Vec<Mount> {
        group(sources, walked, &mut |_| None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
40 22 7:0 / /mnt/my\\040disk ro,noatime shared:20 - ntfs3 /dev/loop0 ro,uid=0
41 22 0:50 / /mnt/xmount rw,nosuid,nodev,relatime shared:21 - fuse.xmount xmount rw,user_id=0
";

    #[test]
    fn parse_mountinfo_decodes_and_matches() {
        let entries = parse_mountinfo(MOUNTINFO);
        assert_eq!(entries.len(), 3);
        let disk = containing(&entries, Path::new("/mnt/my disk/Users/a")).unwrap();
        assert_eq!(disk.mount_point, "/mnt/my disk");
        assert_eq!((disk.device.as_str(), disk.fs_type.as_str()), ("/dev/loop0", "ntfs3"));
        assert_eq!(containing(&entries, Path::new("/home/x")).unwrap().mount_point, "/");
        // a mount point is matched by whole components
        assert_eq!(
            containing(&entries, Path::new("/mnt/xmountain")).unwrap().mount_point,
            "/"
        );
    }

    #[test]
    fn nested_mounts_below_a_source_are_recorded() {
        let entries = parse_mountinfo(MOUNTINFO);
        let mounts = assign(
            &entries,
            &[(PathBuf::from("/mnt"), PathBuf::from("/mnt"))],
            &[PathBuf::from("/mnt/x.txt"), PathBuf::from("/mnt/my disk/Users/a")],
            &|e| Mount {
                mount_point: e.mount_point.clone(),
                device: Some(e.device.clone()),
                ..Default::default()
            },
        );
        let points: Vec<(&str, &[String])> = mounts
            .iter()
            .map(|m| (m.mount_point.as_str(), m.paths.as_slice()))
            .collect();
        assert_eq!(
            points,
            vec![
                ("/", &["/mnt".to_string()][..]),
                ("/mnt/my disk", &["/mnt/my disk".to_string()][..])
            ]
        );
    }

    #[test]
    fn read_only_from_options() {
        assert!(read_only("ro,noatime"));
        assert!(!read_only("rw,relatime"));
        assert!(!read_only("rw,errors=remount-ro"));
    }

    #[test]
    fn mount_line_formats() {
        let mount = Mount {
            mount_point: "/mnt/disk".into(),
            device: Some("/dev/loop0".into()),
            fs_type: Some("ntfs3".into()),
            options: Some("ro,noatime".into()),
            read_only: Some(true),
            image: Some("/mnt/xmount/disk.dd".into()),
            backing: Some(Box::new(Mount {
                mount_point: "/mnt/xmount".into(),
                device: Some("xmount".into()),
                fs_type: Some("fuse.xmount".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert_eq!(
            mount_line(&mount),
            "/mnt/disk · /dev/loop0 · ntfs3 · ro,noatime · image /mnt/xmount/disk.dd · on /mnt/xmount fuse.xmount xmount"
        );
        assert_eq!(mount_line(&Mount::default()), "mount unknown");
        let tmpfs = Mount {
            mount_point: "/tmp".into(),
            device: Some("tmpfs".into()),
            fs_type: Some("tmpfs".into()),
            ..Default::default()
        };
        assert_eq!(mount_line(&tmpfs), "/tmp · tmpfs");
        assert_eq!(Mount::from_json(&mount.to_json()), Some(mount));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mounts_for_temp_dir_is_known() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = mounts_for(
            &[dir.path().to_path_buf(), dir.path().join("x")],
            &[dir.path().join("y")],
        );
        assert_eq!(mounts.len(), 1);
        assert!(!mounts[0].mount_point.is_empty());
        assert!(mounts[0].fs_type.is_some());
        assert_eq!(mounts[0].paths.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn sources_are_listed_as_given() {
        // a link in the path (as /var is on macOS): the mount is found through the real path, the source is named
        // the way it was added
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        let source = dir.path().join("link/a.txt");
        std::fs::write(&source, "a").unwrap();
        let mounts = mounts_for(std::slice::from_ref(&source), &[]);
        assert_eq!(mounts[0].paths, vec![source.display().to_string()]);
    }

    #[cfg(windows)]
    #[test]
    fn mounts_for_temp_dir_has_volume() {
        let dir = tempfile::tempdir().unwrap();
        let mounts = mounts_for(&[dir.path().to_path_buf()], &[]);
        assert_eq!(mounts.len(), 1);
        assert!(!mounts[0].mount_point.starts_with(r"\\?\"), "{}", mounts[0].mount_point);
        assert!(mounts[0].fs_type.is_some());
        assert!(mounts[0].volume_serial.is_some());
        assert!(mounts[0].volume_guid.is_some());
    }
}
