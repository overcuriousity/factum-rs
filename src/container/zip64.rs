//! An append-only ZIP64 writer and a reader. New members and a new central directory are written after the last
//! end-of-central-directory record, so the bytes of an earlier state never move.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const EOCD64_SIG: u32 = 0x0606_4b50;
const LOCATOR_SIG: u32 = 0x0706_4b50;
const ZIP64_EXTRA: u16 = 0x0001;
const VERSION: u16 = 45; // ZIP64
const FLAG_UTF8: u16 = 1 << 11;
const EOCD_LEN: u64 = 22;
const LOCATOR_LEN: u64 = 20;
const EOCD64_LEN: u64 = 56;
const BUFFER: usize = 1 << 20;

/// One member as the central directory lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdEntry {
    pub name: Vec<u8>,
    /// 0 stored, 8 deflated
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    pub header_offset: u64,
}

impl CdEntry {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// A central directory: the members of one state of the file.
#[derive(Debug, Clone)]
pub struct Archive {
    pub entries: Vec<CdEntry>,
    pub comment: Vec<u8>,
    /// the byte after the end-of-central-directory record
    pub end: u64,
    /// name -> index of its last entry
    index: std::collections::HashMap<Vec<u8>, usize>,
}

impl PartialEq for Archive {
    fn eq(&self, other: &Self) -> bool {
        (&self.entries, &self.comment, self.end) == (&other.entries, &other.comment, other.end)
    }
}

impl Eq for Archive {}

impl Archive {
    pub fn new(entries: Vec<CdEntry>, comment: Vec<u8>, end: u64) -> Self {
        let index = entries.iter().enumerate().map(|(i, e)| (e.name.clone(), i)).collect();
        Self {
            entries,
            comment,
            end,
            index,
        }
    }

    /// The member of that name; of several, the last, as Python's zipfile reads it.
    pub fn get(&self, name: &str) -> Option<&CdEntry> {
        self.index.get(name.as_bytes()).map(|&i| &self.entries[i])
    }

    /// Names listed more than once: ZIP readers disagree on which one they read.
    pub fn duplicates(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut duplicates: Vec<String> = self
            .entries
            .iter()
            .filter(|e| !seen.insert(e.name.as_slice()))
            .map(CdEntry::name_lossy)
            .collect();
        duplicates.dedup();
        duplicates
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn read_at(file: &mut File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; len];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Reads the central directory whose end-of-central-directory record ends exactly at `end`.
pub fn read_archive(file: &mut File, end: u64) -> io::Result<Archive> {
    if end < EOCD_LEN {
        return Err(invalid("not a ZIP file"));
    }
    // the record is followed by a comment of up to 65535 bytes
    let window = (EOCD_LEN + 0xFFFF).min(end);
    let tail = read_at(file, end - window, window as usize)?;
    let mut found = None;
    for at in (0..=tail.len() - EOCD_LEN as usize).rev() {
        if u32_at(&tail, at) == EOCD_SIG && at + EOCD_LEN as usize + u16_at(&tail, at + 20) as usize == tail.len() {
            found = Some(at);
            break;
        }
    }
    let at = found.ok_or_else(|| invalid("no end-of-central-directory record"))?;
    let eocd_offset = end - window + at as u64;
    let comment = tail[at + EOCD_LEN as usize..].to_vec();
    let (mut count, mut cd_size, mut cd_offset) = (
        u16_at(&tail, at + 10) as u64,
        u32_at(&tail, at + 12) as u64,
        u32_at(&tail, at + 16) as u64,
    );
    // where the central directory has to end: at the ZIP64 record, or at the classic one
    let mut cd_end = eocd_offset;
    if eocd_offset >= LOCATOR_LEN {
        let locator = read_at(file, eocd_offset - LOCATOR_LEN, LOCATOR_LEN as usize)?;
        if u32_at(&locator, 0) == LOCATOR_SIG {
            let record_offset = u64_at(&locator, 8);
            if record_offset + EOCD64_LEN > eocd_offset - LOCATOR_LEN {
                return Err(invalid("bad ZIP64 locator"));
            }
            let record = read_at(file, record_offset, EOCD64_LEN as usize)?;
            if u32_at(&record, 0) != EOCD64_SIG {
                return Err(invalid("bad ZIP64 end-of-central-directory record"));
            }
            count = u64_at(&record, 32);
            cd_size = u64_at(&record, 40);
            cd_offset = u64_at(&record, 48);
            cd_end = record_offset;
        }
    }
    if cd_offset.checked_add(cd_size) != Some(cd_end) {
        return Err(invalid(
            "the central directory does not end where the end records begin",
        ));
    }
    if cd_size > 1 << 32 {
        return Err(invalid("central directory too large"));
    }
    let directory = read_at(file, cd_offset, cd_size as usize)?;
    let mut entries = Vec::with_capacity(count.min(1 << 20) as usize);
    let mut at = 0usize;
    for _ in 0..count {
        if at + 46 > directory.len() || u32_at(&directory, at) != CENTRAL_SIG {
            return Err(invalid("bad central directory entry"));
        }
        let name_len = u16_at(&directory, at + 28) as usize;
        let extra_len = u16_at(&directory, at + 30) as usize;
        let comment_len = u16_at(&directory, at + 32) as usize;
        let next = at + 46 + name_len + extra_len + comment_len;
        if next > directory.len() {
            return Err(invalid("bad central directory entry"));
        }
        let mut entry = CdEntry {
            name: directory[at + 46..at + 46 + name_len].to_vec(),
            method: u16_at(&directory, at + 10),
            crc32: u32_at(&directory, at + 16),
            compressed_size: u32_at(&directory, at + 20) as u64,
            size: u32_at(&directory, at + 24) as u64,
            header_offset: u32_at(&directory, at + 42) as u64,
        };
        let extra = &directory[at + 46 + name_len..at + 46 + name_len + extra_len];
        apply_zip64_extra(&mut entry, extra);
        if entry.header_offset >= cd_offset {
            return Err(invalid("a member lies behind the central directory"));
        }
        entries.push(entry);
        at = next;
    }
    Ok(Archive::new(entries, comment, end))
}

/// Replaces the 0xFFFFFFFF fields of a central directory entry with the values of its ZIP64 extra field.
fn apply_zip64_extra(entry: &mut CdEntry, extra: &[u8]) {
    let mut at = 0;
    while at + 4 <= extra.len() {
        let (id, len) = (u16_at(extra, at), u16_at(extra, at + 2) as usize);
        let body = &extra[at + 4..(at + 4 + len).min(extra.len())];
        if id == ZIP64_EXTRA {
            let mut field = 0;
            let mut next = |value: &mut u64| {
                if *value == 0xFFFF_FFFF && field + 8 <= body.len() {
                    *value = u64_at(body, field);
                    field += 8;
                }
            };
            next(&mut entry.size);
            next(&mut entry.compressed_size);
            next(&mut entry.header_offset);
        }
        at += 4 + len;
    }
}

/// The end of the newest complete state: the file's length if it ends with one, else `hint`, else the nearest
/// end-of-central-directory record before the end whose central directory reads (an interrupted append).
pub fn find_last_end(file: &mut File, hint: Option<u64>) -> io::Result<Option<u64>> {
    let len = file.seek(SeekFrom::End(0))?;
    if read_archive(file, len).is_ok() {
        return Ok(Some(len));
    }
    if let Some(hint) = hint.filter(|h| *h <= len)
        && read_archive(file, hint).is_ok()
    {
        return Ok(Some(hint));
    }
    // backwards in blocks that overlap by 3 bytes, so a signature across a block boundary is found
    let mut block_end = len;
    while block_end >= EOCD_LEN {
        let start = block_end.saturating_sub(BUFFER as u64);
        let block = read_at(file, start, (block_end - start) as usize)?;
        for at in (0..block.len().saturating_sub(3)).rev() {
            if u32_at(&block, at) != EOCD_SIG {
                continue;
            }
            let offset = start + at as u64;
            let comment_len = read_at(file, offset + 20, 2).map(|b| u16_at(&b, 0) as u64);
            let Ok(comment_len) = comment_len else { continue };
            let candidate = offset + EOCD_LEN + comment_len;
            if candidate <= len && read_archive(file, candidate).is_ok() {
                return Ok(Some(candidate));
            }
        }
        if start == 0 {
            break;
        }
        block_end = start + 3;
    }
    Ok(None)
}

/// The uncompressed content of a member.
pub fn member_reader<'f>(file: &'f mut File, entry: &CdEntry) -> io::Result<Box<dyn Read + 'f>> {
    let header = read_at(file, entry.header_offset, 30)?;
    if u32_at(&header, 0) != LOCAL_SIG {
        return Err(invalid(format!("no local header for {}", entry.name_lossy())));
    }
    let data = entry.header_offset + 30 + u16_at(&header, 26) as u64 + u16_at(&header, 28) as u64;
    file.seek(SeekFrom::Start(data))?;
    let raw = Read::take(file, entry.compressed_size);
    match entry.method {
        0 => Ok(Box::new(raw)),
        // no more than the size the directory gives, whatever the data inflates to
        8 => Ok(Box::new(flate2::read::DeflateDecoder::new(raw).take(entry.size))),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("compression method {other} of {}", entry.name_lossy()),
        )),
    }
}

/// The most of one member read into memory (metadata, signatures, a bevy of an ImageStream): a crafted container
/// cannot make factum hold more, whatever its directory claims or its data inflates to.
pub const MAX_IN_MEMORY: u64 = 1 << 30;

/// A member's content in memory; refused when it is larger than MAX_IN_MEMORY.
pub fn member_bytes(file: &mut File, entry: &CdEntry) -> io::Result<Vec<u8>> {
    member_bytes_up_to(file, entry, MAX_IN_MEMORY)
}

fn member_bytes_up_to(file: &mut File, entry: &CdEntry, limit: u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(entry.size.min(limit).min(1 << 24) as usize);
    member_reader(file, entry)?.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(invalid(format!("{} is larger than {limit} bytes", entry.name_lossy())));
    }
    Ok(data)
}

/// A member's content as UTF-8 text (see `member_bytes`).
pub fn member_text(file: &mut File, entry: &CdEntry) -> io::Result<String> {
    String::from_utf8(member_bytes(file, entry)?)
        .map_err(|_| invalid(format!("{} is not UTF-8 text", entry.name_lossy())))
}

/// The current time as MS-DOS time and date (UTC).
fn dos_now() -> (u16, u16) {
    use chrono::{Datelike, Timelike};
    let now = chrono::Utc::now();
    let time = ((now.hour() << 11) | (now.minute() << 5) | (now.second() / 2)) as u16;
    let date = ((((now.year() - 1980).max(0) as u32) << 9) | (now.month() << 5) | now.day()) as u16;
    (time, date)
}

/// Counts what goes through it.
struct Counting<'w, W: Write> {
    inner: &'w mut W,
    count: u64,
}

impl<W: Write> Write for Counting<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.count += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes members after `start` and, on `finish`, a central directory listing the earlier members and the new ones.
pub struct Appender {
    out: BufWriter<File>,
    position: u64,
    entries: Vec<CdEntry>,
}

impl Appender {
    /// Truncates the file at `start` (everything after it is discarded) and writes from there. `existing` are the
    /// members of the state that ends at `start`.
    pub fn new(file: File, start: u64, existing: Vec<CdEntry>) -> io::Result<Appender> {
        file.set_len(start)?;
        let mut out = BufWriter::with_capacity(BUFFER, file);
        out.seek(SeekFrom::Start(start))?;
        Ok(Appender {
            out,
            position: start,
            entries: existing,
        })
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    /// The file, for reading members; the next write seeks back to where the appender is.
    pub fn file_mut(&mut self) -> io::Result<&mut File> {
        self.out.flush()?;
        Ok(self.out.get_mut())
    }

    /// Adds a member; `observe` sees the uncompressed bytes as they are read.
    pub fn add_member(
        &mut self,
        name: &str,
        method: u16,
        data: &mut dyn Read,
        observe: &mut dyn FnMut(&[u8]),
    ) -> io::Result<CdEntry> {
        if method != 0 && method != 8 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only stored or deflated members",
            ));
        }
        let header_offset = self.position;
        self.out.seek(SeekFrom::Start(header_offset))?;
        let (time, date) = dos_now();
        let name_bytes = name.as_bytes();
        let mut header = Vec::with_capacity(30 + name_bytes.len() + 20);
        header.extend(LOCAL_SIG.to_le_bytes());
        header.extend(VERSION.to_le_bytes());
        header.extend(FLAG_UTF8.to_le_bytes());
        header.extend(method.to_le_bytes());
        header.extend(time.to_le_bytes());
        header.extend(date.to_le_bytes());
        header.extend(0u32.to_le_bytes()); // crc, patched
        header.extend(0xFFFF_FFFFu32.to_le_bytes());
        header.extend(0xFFFF_FFFFu32.to_le_bytes());
        header.extend((name_bytes.len() as u16).to_le_bytes());
        header.extend(20u16.to_le_bytes());
        header.extend(name_bytes);
        header.extend(ZIP64_EXTRA.to_le_bytes());
        header.extend(16u16.to_le_bytes());
        header.extend([0u8; 16]); // sizes, patched
        self.out.write_all(&header)?;
        let mut crc = crc32fast::Hasher::new();
        let mut size = 0u64;
        let mut buffer = vec![0; BUFFER];
        let compressed_size = {
            let mut counting = Counting {
                inner: &mut self.out,
                count: 0,
            };
            {
                let mut sink: Box<dyn Write + '_> = if method == 8 {
                    Box::new(flate2::write::DeflateEncoder::new(
                        &mut counting,
                        flate2::Compression::fast(),
                    ))
                } else {
                    Box::new(&mut counting)
                };
                loop {
                    let read = match data.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(e) => return Err(e),
                    };
                    let chunk = &buffer[..read];
                    observe(chunk);
                    crc.update(chunk);
                    size += read as u64;
                    sink.write_all(chunk)?;
                }
                sink.flush()?;
            }
            counting.count
        };
        let crc32 = crc.finalize();
        let data_end = header_offset + header.len() as u64 + compressed_size;
        self.out.flush()?;
        let file = self.out.get_mut();
        file.seek(SeekFrom::Start(header_offset + 14))?;
        file.write_all(&crc32.to_le_bytes())?;
        file.seek(SeekFrom::Start(header_offset + 30 + name_bytes.len() as u64 + 4))?;
        file.write_all(&size.to_le_bytes())?;
        file.write_all(&compressed_size.to_le_bytes())?;
        file.seek(SeekFrom::Start(data_end))?;
        self.position = data_end;
        let entry = CdEntry {
            name: name_bytes.to_vec(),
            method,
            crc32,
            compressed_size,
            size,
            header_offset,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn add_bytes(&mut self, name: &str, method: u16, bytes: &[u8]) -> io::Result<CdEntry> {
        self.add_member(name, method, &mut &bytes[..], &mut |_| {})
    }

    /// Forgets everything written at or after `pos` (a member that failed half-way).
    pub fn rewind_to(&mut self, pos: u64) -> io::Result<()> {
        self.out.flush()?;
        self.entries.retain(|e| e.header_offset < pos);
        let file = self.out.get_mut();
        file.set_len(pos)?;
        file.seek(SeekFrom::Start(pos))?;
        self.position = pos;
        Ok(())
    }

    /// The members the next `finish` lists (the newest of each name).
    pub fn entries(&self) -> Vec<CdEntry> {
        let last: std::collections::HashMap<&[u8], usize> = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.name.as_slice(), index))
            .collect();
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, entry)| last[entry.name.as_slice()] == *index)
            .map(|(_, entry)| entry.clone())
            .collect()
    }

    /// Writes the central directory (the newest member of each name, without `omit`) and the end records, and
    /// syncs the file. Returns the new end; further members go after it.
    pub fn finish(&mut self, omit: &[&str], comment: &[u8]) -> io::Result<u64> {
        let entries: Vec<CdEntry> = self
            .entries()
            .into_iter()
            .filter(|e| !omit.iter().any(|name| e.name == name.as_bytes()))
            .collect();
        let (time, date) = dos_now();
        let cd_offset = self.position;
        self.out.seek(SeekFrom::Start(cd_offset))?;
        let mut directory = Vec::new();
        for entry in &entries {
            directory.extend(CENTRAL_SIG.to_le_bytes());
            directory.extend(VERSION.to_le_bytes()); // made by
            directory.extend(VERSION.to_le_bytes()); // needed
            directory.extend(FLAG_UTF8.to_le_bytes());
            directory.extend(entry.method.to_le_bytes());
            directory.extend(time.to_le_bytes());
            directory.extend(date.to_le_bytes());
            directory.extend(entry.crc32.to_le_bytes());
            directory.extend(0xFFFF_FFFFu32.to_le_bytes());
            directory.extend(0xFFFF_FFFFu32.to_le_bytes());
            directory.extend((entry.name.len() as u16).to_le_bytes());
            directory.extend(28u16.to_le_bytes());
            directory.extend(0u16.to_le_bytes()); // comment
            directory.extend(0u16.to_le_bytes()); // disk
            directory.extend(0u16.to_le_bytes()); // internal attributes
            directory.extend(0u32.to_le_bytes()); // external attributes
            directory.extend(0xFFFF_FFFFu32.to_le_bytes());
            directory.extend(&entry.name);
            directory.extend(ZIP64_EXTRA.to_le_bytes());
            directory.extend(24u16.to_le_bytes());
            directory.extend(entry.size.to_le_bytes());
            directory.extend(entry.compressed_size.to_le_bytes());
            directory.extend(entry.header_offset.to_le_bytes());
        }
        let record_offset = cd_offset + directory.len() as u64;
        let count = entries.len() as u64;
        let mut tail = Vec::new();
        tail.extend(EOCD64_SIG.to_le_bytes());
        tail.extend((EOCD64_LEN - 12).to_le_bytes());
        tail.extend(VERSION.to_le_bytes());
        tail.extend(VERSION.to_le_bytes());
        tail.extend(0u32.to_le_bytes());
        tail.extend(0u32.to_le_bytes());
        tail.extend(count.to_le_bytes());
        tail.extend(count.to_le_bytes());
        tail.extend((directory.len() as u64).to_le_bytes());
        tail.extend(cd_offset.to_le_bytes());
        tail.extend(LOCATOR_SIG.to_le_bytes());
        tail.extend(0u32.to_le_bytes());
        tail.extend(record_offset.to_le_bytes());
        tail.extend(1u32.to_le_bytes());
        tail.extend(EOCD_SIG.to_le_bytes());
        tail.extend(0u16.to_le_bytes());
        tail.extend(0u16.to_le_bytes());
        tail.extend(0xFFFFu16.to_le_bytes());
        tail.extend(0xFFFFu16.to_le_bytes());
        tail.extend(0xFFFF_FFFFu32.to_le_bytes());
        tail.extend(0xFFFF_FFFFu32.to_le_bytes());
        tail.extend((comment.len().min(0xFFFF) as u16).to_le_bytes());
        tail.extend(&comment[..comment.len().min(0xFFFF)]);
        self.out.write_all(&directory)?;
        self.out.write_all(&tail)?;
        self.out.flush()?;
        self.out.get_ref().sync_all()?;
        self.position = record_offset + tail.len() as u64;
        self.entries = entries;
        Ok(self.position)
    }

    pub fn into_file(self) -> File {
        self.out
            .into_inner()
            .map_err(|e| e.into_error())
            .expect("flushed by finish")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};

    fn new_file(dir: &tempfile::TempDir) -> std::fs::File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("c.aff4l"))
            .unwrap()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn content(file: &mut std::fs::File, archive: &Archive, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        member_reader(file, archive.get(name).unwrap())
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn round_trip_stored_and_deflated() {
        let dir = tempfile::tempdir().unwrap();
        let big = pattern(3 << 20);
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("empty", 0, b"").unwrap();
        app.add_bytes("abc", 8, b"abc").unwrap();
        let mut seen = 0usize;
        app.add_member("big", 8, &mut big.as_slice(), &mut |bytes| seen += bytes.len())
            .unwrap();
        assert_eq!(seen, big.len());
        let end = app.finish(&[], b"aff4://x").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        assert_eq!(archive.comment, b"aff4://x");
        assert_eq!(archive.end, end);
        assert_eq!(content(&mut file, &archive, "empty"), b"");
        assert_eq!(content(&mut file, &archive, "abc"), b"abc");
        assert_eq!(content(&mut file, &archive, "big"), big);
        assert!(archive.get("big").unwrap().compressed_size < big.len() as u64);
    }

    #[test]
    fn newest_member_of_a_name_wins_and_omit_removes() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("information.turtle", 0, b"one").unwrap();
        app.add_bytes("x.asc", 0, b"sig").unwrap();
        let end1 = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let first = read_archive(&mut file, end1).unwrap();
        let mut app = Appender::new(file, end1, first.entries).unwrap();
        app.add_bytes("information.turtle", 0, b"two").unwrap();
        let end2 = app.finish(&["x.asc"], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end2).unwrap();
        let names: Vec<&[u8]> = archive.entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(names, vec![b"information.turtle".as_slice()]);
        assert_eq!(content(&mut file, &archive, "information.turtle"), b"two");
    }

    #[test]
    fn interrupted_append_finds_previous_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first state").unwrap();
        let end1 = app.finish(&[], b"aff4://x").unwrap();
        let mut file = app.into_file();
        let entries = read_archive(&mut file, end1).unwrap().entries;
        let mut app = Appender::new(file, end1, entries).unwrap();
        let mut junk = pattern(200 << 10);
        junk[1000..1004].copy_from_slice(b"PK\x05\x06");
        app.add_bytes("b", 0, &junk).unwrap();
        drop(app); // no finish: as if the process died
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("c.aff4l"))
            .unwrap();
        let len = file.seek(SeekFrom::End(0)).unwrap();
        assert!(len > end1);
        assert!(read_archive(&mut file, len).is_err());
        assert_eq!(find_last_end(&mut file, None).unwrap(), Some(end1));
        assert_eq!(find_last_end(&mut file, Some(end1)).unwrap(), Some(end1));
        // a wrong hint falls back to the scan
        assert_eq!(find_last_end(&mut file, Some(end1 + 1)).unwrap(), Some(end1));
    }

    /// Renames the central directory entry of `from` to `to` (same length): a crafted duplicate name.
    pub(crate) fn rename_in_directory(path: &std::path::Path, from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let mut bytes = std::fs::read(path).unwrap();
        let at = bytes.windows(from.len()).rposition(|w| w == from.as_bytes()).unwrap();
        bytes[at..at + to.len()].copy_from_slice(to.as_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn duplicate_names_are_reported_and_the_last_wins() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("aaaa", 0, b"first").unwrap();
        app.add_bytes("bbbb", 0, b"second").unwrap();
        let end = app.finish(&[], b"").unwrap();
        drop(app);
        rename_in_directory(&dir.path().join("c.aff4l"), "bbbb", "aaaa");
        let mut file = std::fs::File::open(dir.path().join("c.aff4l")).unwrap();
        let archive = read_archive(&mut file, end).unwrap();
        assert_eq!(archive.duplicates(), vec!["aaaa".to_string()]);
        // like Python's zipfile: the last entry of a name is the one read
        assert_eq!(content(&mut file, &archive, "aaaa"), b"second");
    }

    #[test]
    fn lookups_stay_fast_with_many_members() {
        let entries: Vec<CdEntry> = (0..50_000)
            .map(|i| CdEntry {
                name: format!("aff4://{i:036}").into_bytes(),
                method: 0,
                crc32: 0,
                compressed_size: 0,
                size: 0,
                header_offset: i,
            })
            .collect();
        let archive = Archive::new(entries, Vec::new(), 0);
        let started = std::time::Instant::now();
        for i in 0..50_000 {
            assert!(archive.get(&format!("aff4://{i:036}")).is_some());
        }
        assert!(started.elapsed().as_millis() < 1000, "{:?}", started.elapsed());
    }

    #[test]
    fn a_member_inflating_beyond_the_limit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        let bomb = app.add_bytes("bomb", 8, &vec![0u8; 4 << 20]).unwrap();
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let mut entry = read_archive(&mut file, end).unwrap().get("bomb").unwrap().clone();
        assert!(bomb.compressed_size < 64 << 10);
        // a directory claiming far more than the data: only the limit is ever read
        entry.size = 1 << 40;
        let error = member_bytes_up_to(&mut file, &entry, 1 << 20).unwrap_err();
        assert!(error.to_string().contains("larger than"), "{error}");
        entry.size = 4 << 20;
        assert_eq!(member_bytes_up_to(&mut file, &entry, 4 << 20).unwrap().len(), 4 << 20);
    }

    #[test]
    fn rewind_drops_what_was_written_after() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("keep", 0, b"k").unwrap();
        let mark = app.position();
        app.add_bytes("drop", 0, b"d").unwrap();
        app.rewind_to(mark).unwrap();
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        assert!(archive.get("keep").is_some() && archive.get("drop").is_none());
        assert_eq!(file.metadata().unwrap().len(), end);
    }
}
