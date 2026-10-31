//! Where the sources of an Add operation were read from: the mount (Linux) or volume (Windows) below each source,
//! so the log and the container say through which device, file system and options the files were read.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_json::{Map, Value, json};

use super::source::os_string;

/// One mount, as recorded with an Add operation. An empty `mount_point` with nothing else known is "mount unknown".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mount {
    pub mount_point: String,
    /// Base64 of the mount point's bytes, when `mount_point` cannot hold them
    pub mount_point_raw: Option<String>,
    pub device: Option<String>,
    pub fs_type: Option<String>,
    /// the mount's own options
    pub options: Option<String>,
    /// the options of the file system below it (norecovery, errors=...)
    pub super_options: Option<String>,
    /// by the mount's or the file system's options
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
            ("mount_point_raw", &self.mount_point_raw),
            ("device", &self.device),
            ("fs_type", &self.fs_type),
            ("options", &self.options),
            ("super_options", &self.super_options),
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
            mount_point_raw: text("mount_point_raw"),
            device: text("device"),
            fs_type: text("fs_type"),
            options: text("options"),
            super_options: text("super_options"),
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

/// The mount as one line: `/mnt/disk · /dev/loop0 · ntfs3 · rw,noatime · super ro,norecovery · image /cases/disk.raw`.
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
    if let Some(options) = &m.super_options {
        parts.push(format!("super {options}"));
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
    resolve: &mut dyn FnMut(&Path) -> Option<Rc<Mount>>,
) -> Vec<Mount> {
    let mut mounts: Vec<Mount> = Vec::new();
    for (given, path, is_source) in sources
        .iter()
        .map(|(given, real)| (given, real, true))
        .chain(walked.iter().map(|p| (p, p, false)))
    {
        let mount = resolve(path).unwrap_or_default();
        let index = match mounts.iter().position(|m| {
            m.mount_point == mount.mount_point && m.mount_point_raw == mount.mount_point_raw && m.device == mount.device
        }) {
            Some(index) => index,
            None => {
                mounts.push(Mount::clone(&mount));
                mounts.len() - 1
            }
        };
        let known = &mut mounts[index];
        if !is_source && !known.paths.is_empty() {
            continue;
        }
        let label = if is_source || known.mount_point.is_empty() {
            given.display().to_string()
        } else {
            known.mount_point.clone()
        };
        if !known.paths.contains(&label) {
            known.paths.push(label);
        }
    }
    mounts
}

/// The mounts of `entries` the paths lie on, as `group` lists them; `to_mount` turns an entry into a mount, once for
/// each entry however many paths lie on it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn assign(
    entries: &[MountEntry],
    sources: &[(PathBuf, PathBuf)],
    walked: &[PathBuf],
    to_mount: &dyn Fn(&MountEntry) -> Mount,
) -> Vec<Mount> {
    let mut resolved: HashMap<u64, Rc<Mount>> = HashMap::new();
    group(sources, walked, &mut |path| {
        let entry = containing(entries, path)?;
        Some(
            resolved
                .entry(entry.id)
                .or_insert_with(|| Rc::new(to_mount(entry)))
                .clone(),
        )
    })
}

/// The volume a path lies on, looked up once per folder: with the folder itself, as a child may be another volume's
/// mount folder, and with the path when it is such a folder (or has no parent).
#[cfg_attr(not(windows), allow(dead_code))]
fn volume_by_folder(
    cache: &mut HashMap<PathBuf, Option<Rc<Mount>>>,
    path: &Path,
    is_mount_folder: &dyn Fn(&Path) -> bool,
    lookup: &dyn Fn(&Path) -> Option<Mount>,
) -> Option<Rc<Mount>> {
    let folder = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty() && !is_mount_folder(path))
        .unwrap_or(path);
    cache
        .entry(folder.to_path_buf())
        .or_insert_with(|| lookup(folder).map(Rc::new))
        .clone()
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
    pub id: u64,
    pub parent: u64,
    pub mount_point: OsString,
    pub device: String,
    pub fs_type: String,
    pub options: String,
    pub super_options: String,
}

/// `\040` and the other octal escapes of mountinfo, decoded.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unescape(bytes: &[u8]) -> Vec<u8> {
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
    out
}

/// The mounts of `/proc/self/mountinfo` (proc(5)) that can be reached: ids, mount point and per-mount options from
/// the first part, file system type, source and superblock options after the `-` separator. The file is bytes: the
/// kernel escapes only blanks and backslashes, so a mount point that is not UTF-8 stands in it as it is.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_mountinfo(content: impl AsRef<[u8]>) -> Vec<MountEntry> {
    let text = |field: &[u8]| String::from_utf8_lossy(field).into_owned();
    let number = |field: &[u8]| text(field).parse::<u64>().ok();
    let entries = content
        .as_ref()
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
            let separator = fields.iter().position(|f| *f == b"-")?;
            Some(MountEntry {
                id: number(fields.first()?)?,
                parent: number(fields.get(1)?)?,
                mount_point: os_string(unescape(fields.get(4)?)),
                options: text(fields.get(5)?),
                fs_type: text(fields.get(separator + 1)?),
                device: text(&unescape(fields.get(separator + 2)?)),
                super_options: fields.get(separator + 3).map(|f| text(f)).unwrap_or_default(),
            })
        })
        .collect();
    reachable(entries)
}

/// Without the mounts nothing reaches any more: one with a mount on top of it (which hangs from the one it covers),
/// and one below a folder that was mounted over later (that mount hangs from one of its ancestors, not below it).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn reachable(entries: Vec<MountEntry>) -> Vec<MountEntry> {
    let parents: HashMap<u64, u64> = entries.iter().map(|e| (e.id, e.parent)).collect();
    let ancestors = |entry: &MountEntry| {
        let mut found = vec![entry.parent];
        while let Some(parent) = parents.get(&found[found.len() - 1]).filter(|p| !found.contains(p)) {
            found.push(*parent);
        }
        found
    };
    let hidden = |entry: &MountEntry| {
        let ancestors = ancestors(entry);
        entries.iter().any(|other| {
            if other.mount_point == entry.mount_point {
                other.parent == entry.id && other.id != entry.id
            } else {
                Path::new(&entry.mount_point).starts_with(&other.mount_point)
                    && !ancestors.contains(&other.id)
                    && ancestors.contains(&other.parent)
            }
        })
    };
    let keep: Vec<bool> = entries.iter().map(|e| !hidden(e)).collect();
    entries
        .into_iter()
        .zip(keep)
        .filter_map(|(entry, keep)| keep.then_some(entry))
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
    use crate::container::source::{encode_name, os_bytes};

    fn entries() -> Option<Vec<MountEntry>> {
        Some(parse_mountinfo(std::fs::read("/proc/self/mountinfo").ok()?))
    }

    pub(super) fn to_mount(entry: &MountEntry) -> Mount {
        Mount {
            mount_point: entry.mount_point.to_string_lossy().into_owned(),
            mount_point_raw: encode_name(&os_bytes(&entry.mount_point)).raw_b64,
            device: Some(entry.device.clone()),
            fs_type: Some(entry.fs_type.clone()),
            options: Some(entry.options.clone()),
            super_options: Some(entry.super_options.clone()).filter(|o| !o.is_empty()),
            read_only: Some(read_only(&entry.options) || read_only(&entry.super_options)),
            ..Default::default()
        }
    }

    /// The image file behind a loop device. A partition (`loop0p1`) has no `loop/` of its own: its sysfs folder lies
    /// inside the whole device's.
    pub(super) fn loop_image(class_block: &Path, name: &str) -> Option<OsString> {
        let device = class_block.join(name);
        let device = if device.join("partition").exists() {
            device.join("..")
        } else {
            device
        };
        let backing = std::fs::read(device.join("loop/backing_file")).ok()?;
        let end = backing.iter().rposition(|byte| *byte != b'\n')? + 1;
        Some(os_string(backing[..end].to_vec()))
    }

    pub fn mounts_for(sources: &[(PathBuf, PathBuf)], walked: &[PathBuf]) -> Vec<Mount> {
        let entries = entries().unwrap_or_default();
        // a loop device: the image file behind it, and the FUSE mount that file lies on (xmount and similar)
        let with_backing = |entry: &MountEntry| {
            let mut mount = to_mount(entry);
            let loop_name = entry.device.strip_prefix("/dev/").filter(|d| d.starts_with("loop"));
            if let Some(image) = loop_name.and_then(|name| loop_image(Path::new("/sys/class/block"), name)) {
                mount.backing = containing(&entries, Path::new(&image))
                    .filter(|e| e.fs_type.starts_with("fuse"))
                    .map(|e| Box::new(to_mount(e)));
                mount.image = Some(image.to_string_lossy().into_owned());
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
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

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
        let mut by_folder: HashMap<PathBuf, Option<Rc<Mount>>> = HashMap::new();
        group(sources, walked, &mut |path| {
            volume_by_folder(&mut by_folder, path, &is_mount_folder, &volume_of)
        })
    }

    /// A folder with a reparse point: a mount folder (or a junction, whose volume is looked up the same way).
    fn is_mount_folder(path: &Path) -> bool {
        use std::os::windows::fs::MetadataExt;
        std::fs::symlink_metadata(path).is_ok_and(|m| {
            let attributes = m.file_attributes();
            attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
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
        assert_eq!(
            (disk.options.as_str(), disk.super_options.as_str()),
            ("ro,noatime", "ro,uid=0")
        );
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
                mount_point: e.mount_point.to_string_lossy().into_owned(),
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
    fn each_entry_is_turned_into_a_mount_once() {
        let entries = parse_mountinfo(MOUNTINFO);
        let walked: Vec<PathBuf> = (0..100).map(|n| PathBuf::from(format!("/mnt/xmount/{n}"))).collect();
        let calls = std::cell::Cell::new(0);
        let mounts = assign(&entries, &[], &walked, &|e| {
            calls.set(calls.get() + 1);
            Mount {
                mount_point: e.mount_point.to_string_lossy().into_owned(),
                ..Default::default()
            }
        });
        assert_eq!(mounts.len(), 1);
        assert_eq!(calls.get(), 1);
    }

    fn points(entries: &[MountEntry]) -> Vec<(u64, &str)> {
        entries
            .iter()
            .map(|e| (e.id, e.mount_point.to_str().unwrap()))
            .collect()
    }

    #[test]
    fn a_mount_with_another_on_top_is_dropped() {
        // 30 on top of 22, 31 on top of 30, whatever order the kernel lists them in
        let entries = parse_mountinfo(
            "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
             31 30 8:4 / /mnt/x rw - ext4 /dev/sdd1 rw\n\
             22 20 8:2 / /mnt/x rw - ext4 /dev/sdb1 rw\n\
             30 22 8:3 / /mnt/x rw - ext4 /dev/sdc1 rw\n",
        );
        assert_eq!(points(&entries), vec![(20, "/"), (31, "/mnt/x")]);
        assert_eq!(containing(&entries, Path::new("/mnt/x/a")).unwrap().device, "/dev/sdd1");
    }

    #[test]
    fn a_mount_below_a_folder_mounted_over_later_is_dropped() {
        // 22 hangs from the root's /mnt/x/y; 30 then covers /mnt/x; 31 was mounted inside 30
        let entries = parse_mountinfo(
            "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
             22 20 8:2 / /mnt/x/y rw - ext4 /dev/sdb1 rw\n\
             30 20 8:3 / /mnt/x rw - ext4 /dev/sdc1 rw\n\
             31 30 8:4 / /mnt/x/z rw - ext4 /dev/sdd1 rw\n",
        );
        assert_eq!(points(&entries), vec![(20, "/"), (30, "/mnt/x"), (31, "/mnt/x/z")]);
    }

    #[test]
    fn a_mount_inside_a_covered_mount_is_dropped_and_one_inside_the_cover_kept() {
        let entries = parse_mountinfo(
            "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
             22 20 8:2 / /mnt rw - ext4 /dev/sdb1 rw\n\
             23 22 8:3 / /mnt/y rw - ext4 /dev/sdc1 rw\n\
             30 22 8:4 / /mnt rw - ext4 /dev/sdd1 rw\n\
             31 30 8:5 / /mnt/y rw - ext4 /dev/sde1 rw\n",
        );
        assert_eq!(points(&entries), vec![(20, "/"), (30, "/mnt"), (31, "/mnt/y")]);
    }

    #[test]
    fn a_parent_id_loop_is_no_hang() {
        let entries = parse_mountinfo("2 3 8:1 / /a rw - ext4 /dev/a rw\n3 2 8:2 / /a/b rw - ext4 /dev/b rw\n");
        assert_eq!(entries.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_mount_point_that_is_not_utf8_matches_by_its_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        // the kernel leaves such bytes as they are and writes a blank as \\040
        let entries = parse_mountinfo(
            b"20 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
              21 20 8:2 / /mnt/caf\xe9\\040x ro - ext4 /dev/sdb1 ro\n\
              22 20 8:3 / /mnt/caf\xff\\040x ro - ext4 /dev/sdc1 ro\n",
        );
        assert_eq!(entries.len(), 3);
        let path = OsStr::from_bytes(b"/mnt/caf\xe9 x/a");
        assert_eq!(containing(&entries, Path::new(path)).unwrap().device, "/dev/sdb1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_mount_point_that_is_not_utf8_is_recorded_with_its_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let entries = parse_mountinfo(
            b"21 20 8:2 / /mnt/caf\xe9 ro - ext4 /dev/sdb1 ro\n22 20 8:3 / /mnt/caf\xff ro - ext4 /dev/sdb1 ro\n",
        );
        let walked: Vec<PathBuf> = [&b"/mnt/caf\xe9/a"[..], &b"/mnt/caf\xff/a"[..]]
            .iter()
            .map(|p| PathBuf::from(OsStr::from_bytes(p)))
            .collect();
        // the same text and device, two mounts all the same
        let mounts = assign(&entries, &[], &walked, &platform::to_mount);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].mount_point, "/mnt/caf\u{fffd}");
        assert_eq!(mounts[0].mount_point_raw.as_deref(), Some("L21udC9jYWbp"));
        assert_eq!(Mount::from_json(&mounts[0].to_json()).as_ref(), Some(&mounts[0]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn superblock_options_are_recorded_and_can_make_a_mount_read_only() {
        let entries = parse_mountinfo("40 22 7:0 / /mnt/disk rw,noatime - ext4 /dev/sdb1 ro,norecovery\n");
        let mount = platform::to_mount(&entries[0]);
        assert_eq!(mount.options.as_deref(), Some("rw,noatime"));
        assert_eq!(mount.super_options.as_deref(), Some("ro,norecovery"));
        assert_eq!(mount.read_only, Some(true));
        assert_eq!(
            mount_line(&mount),
            "/mnt/disk · /dev/sdb1 · ext4 · rw,noatime · super ro,norecovery"
        );
        assert_eq!(Mount::from_json(&mount.to_json()), Some(mount));
        let entries = parse_mountinfo("40 22 7:0 / /mnt/disk ro - ext4 /dev/sdb1 rw\n");
        assert_eq!(platform::to_mount(&entries[0]).read_only, Some(true));
        let entries = parse_mountinfo("40 22 7:0 / /mnt/disk rw - ext4 /dev/sdb1 rw,errors=remount-ro\n");
        assert_eq!(platform::to_mount(&entries[0]).read_only, Some(false));
        // a log entry from before this has the mount's options only
        let old = serde_json::json!({"mount_point": "/mnt/disk", "options": "ro"});
        assert_eq!(Mount::from_json(&old).unwrap().super_options, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_image_behind_a_loop_partition_is_found_through_its_device() {
        // as sysfs has it: /sys/class/block/<name> links into the device's folder, a partition's lies inside it
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("devices/loop0");
        let partition = device.join("loop0p1");
        std::fs::create_dir_all(device.join("loop")).unwrap();
        std::fs::create_dir_all(&partition).unwrap();
        std::fs::write(device.join("loop/backing_file"), "/cases/disk.raw\n").unwrap();
        std::fs::write(partition.join("partition"), "1\n").unwrap();
        let class = dir.path().join("class");
        std::fs::create_dir(&class).unwrap();
        std::os::unix::fs::symlink(&device, class.join("loop0")).unwrap();
        std::os::unix::fs::symlink(&partition, class.join("loop0p1")).unwrap();
        let expected = Some(OsString::from("/cases/disk.raw"));
        assert_eq!(platform::loop_image(&class, "loop0"), expected);
        assert_eq!(platform::loop_image(&class, "loop0p1"), expected);
        assert_eq!(platform::loop_image(&class, "loop1"), None);
    }

    #[test]
    fn a_mount_folder_does_not_decide_its_siblings_volume() {
        let lookup = |path: &Path| {
            Some(Mount {
                mount_point: if path.starts_with("/vol/mounted") {
                    "mounted"
                } else {
                    "vol"
                }
                .into(),
                ..Default::default()
            })
        };
        let is_mount_folder = |path: &Path| path == Path::new("/vol/mounted");
        let mut cache = HashMap::new();
        // the mount folder comes first and is its own volume; its siblings lie on the folder's
        for (path, volume) in [
            ("/vol/mounted", "mounted"),
            ("/vol/a.txt", "vol"),
            ("/vol/b.txt", "vol"),
            ("/vol/mounted/x.txt", "mounted"),
        ] {
            let found = volume_by_folder(&mut cache, Path::new(path), &is_mount_folder, &lookup);
            assert_eq!(found.unwrap().mount_point, volume, "{path}");
        }
        assert_eq!(cache.len(), 2);
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
